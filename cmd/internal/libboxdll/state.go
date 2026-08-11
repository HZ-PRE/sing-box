package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
)

var app = newAppState()

type appState struct {
	// operationMu serializes lifecycle and one-shot command operations. In
	// particular, Stop must not close HistoryStorage while URLTest workers use it.
	operationMu    sync.Mutex
	mu             sync.Mutex
	service        *libbox.BoxService
	statusPort     int64
	commandServer  *libbox.CommandServer
	commandClients map[int32]*commandClientState
}

type commandClientState struct {
	client *libbox.CommandClient
}

func newAppState() *appState {
	return &appState{commandClients: make(map[int32]*commandClientState)}
}

func (a *appState) setup(basePath, workingPath, tempPath string, statusPort int64, debug bool) string {
	if err := dllLogger.configure(workingPath); err != nil {
		tracef("setup", "configure log file failed workingPath=%q: %v", workingPath, err)
	} else {
		tracef("setup", "log file configured path=%q", dllLogger.currentPath())
	}
	tracef("setup", "begin base=%q working=%q temp=%q statusPort=%d debug=%t", basePath, workingPath, tempPath, statusPort, debug)
	tracef("setup", "waiting for operation lock")
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("setup", "operation lock acquired; waiting for state lock")
	a.mu.Lock()
	defer a.mu.Unlock()
	tracef("setup", "state lock acquired")

	if a.service != nil {
		tracef("setup", "rejected: service is running")
		return "error: cannot setup while service is running"
	}

	options := &libbox.SetupOptions{
		BasePath:    basePath,
		WorkingPath: workingPath,
		TempPath:    tempPath,
		// The command transport has no Windows named-pipe implementation.
		IsTVOS: runtime.GOOS == "windows",
	}
	tracef("setup", "calling libbox.Setup tcpCommandTransport=%t", options.IsTVOS)
	if err := libbox.Setup(options); err != nil {
		tracef("setup", "libbox.Setup failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("setup", "libbox.Setup completed")

	if a.commandServer != nil {
		tracef("setup", "closing previous command server")
		if err := a.commandServer.Close(); err != nil {
			tracef("setup", "previous command server close failed: %v", err)
		} else {
			tracef("setup", "previous command server closed")
		}
	}
	tracef("setup", "creating command server maxLines=400")
	server := libbox.NewCommandServer(noopCommandServerHandler{}, 400)
	tracef("setup", "starting command server")
	if err := server.Start(); err != nil {
		tracef("setup", "command server start failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("setup", "command server started")
	a.commandServer = server
	a.statusPort = statusPort
	tracef("setup", "state stored; posting Stopped")
	postStatus(statusPort, "Stopped")
	tracef("setup", "completed successfully")
	return ""
}

func (a *appState) start(configPath string, debug bool) string {
	tracef("start", "begin configPath=%q debug=%t; waiting for operation lock", configPath, debug)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("start", "operation lock acquired")
	return traceResult("start", a.startUnlocked(configPath))
}

func (a *appState) startUnlocked(configPath string) string {
	tracef("start", "reading config path=%q", configPath)
	content, err := os.ReadFile(configPath)
	if err != nil {
		tracef("start", "read config failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("start", "config read bytes=%d; checking traffic entry points", len(content))
	var entryPoints struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err = json.Unmarshal(content, &entryPoints); err != nil {
		tracef("start", "entry-point inspection failed: %v", err)
		return "error: invalid config JSON: " + err.Error()
	}
	if len(entryPoints.Inbounds) == 0 {
		tracef("start", "rejected: configuration has no inbounds; service would start but cannot proxy traffic")
		return "error: configuration has no inbounds; add a mixed or tun inbound"
	}
	tracef("start", "traffic entry points found inbounds=%d; validating", len(entryPoints.Inbounds))
	if err = libbox.CheckConfig(string(content)); err != nil {
		tracef("start", "config validation failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("start", "config validation succeeded")

	tracef("start", "checking current state")
	a.mu.Lock()
	if a.service != nil {
		a.mu.Unlock()
		tracef("start", "rejected: service already started")
		return "error: already started"
	}
	if a.commandServer == nil {
		a.mu.Unlock()
		tracef("start", "rejected: setup has not created command server")
		return "error: setup must be called before start"
	}
	server := a.commandServer
	statusPort := a.statusPort
	a.mu.Unlock()

	tracef("start", "creating libbox service")
	serviceInstance, err := libbox.NewService(string(content), noopPlatformInterface{})
	if err != nil {
		tracef("start", "NewService failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("start", "libbox service created")
	postStatus(statusPort, "Starting")
	tracef("start", "starting libbox service")
	if err = serviceInstance.Start(); err != nil {
		tracef("start", "service start failed: %v; closing partial service", err)
		if closeErr := serviceInstance.Close(); closeErr != nil {
			tracef("start", "partial service close failed: %v", closeErr)
		}
		postStatus(statusPort, "Stopped")
		return "error: " + err.Error()
	}
	tracef("start", "libbox service started; committing state")

	a.mu.Lock()
	if a.service != nil || a.commandServer != server {
		a.mu.Unlock()
		tracef("start", "state changed while starting; closing newly started service")
		if closeErr := serviceInstance.Close(); closeErr != nil {
			tracef("start", "new service close after state change failed: %v", closeErr)
		}
		postStatus(statusPort, "Stopped")
		return "error: service state changed while starting"
	}
	a.service = serviceInstance
	tracef("start", "attaching service to command server")
	server.SetService(serviceInstance)
	a.mu.Unlock()

	postStatus(statusPort, "Started")
	tracef("start", "service state committed and Started posted")
	return ""
}

func (a *appState) stop() string {
	tracef("stop", "begin; waiting for operation lock")
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("stop", "operation lock acquired")
	return traceResult("stop", a.stopUnlocked())
}

func (a *appState) stopUnlocked() string {
	tracef("stop", "snapshotting state and detaching service")
	a.mu.Lock()
	clients := a.commandClients
	a.commandClients = make(map[int32]*commandClientState)
	server := a.commandServer
	serviceInstance := a.service
	a.service = nil
	statusPort := a.statusPort
	if server != nil {
		tracef("stop", "detaching service from command server")
		server.SetService(nil)
	}
	a.mu.Unlock()

	tracef("stop", "disconnecting command clients count=%d", len(clients))
	for command, state := range clients {
		if state != nil {
			tracef("stop", "disconnecting command client command=%d", command)
			if err := state.client.Disconnect(); err != nil {
				tracef("stop", "command client disconnect failed command=%d: %v", command, err)
			} else {
				tracef("stop", "command client disconnected command=%d", command)
			}
		}
	}
	if serviceInstance == nil {
		tracef("stop", "service is already nil")
		postStatus(statusPort, "Stopped")
		return ""
	}

	postStatus(statusPort, "Stopping")
	tracef("stop", "closing libbox service")
	err := serviceInstance.Close()
	postStatus(statusPort, "Stopped")
	if err != nil {
		tracef("stop", "libbox service close failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("stop", "libbox service closed")
	return ""
}

func (a *appState) restart(configPath string, debug bool) string {
	tracef("restart", "begin configPath=%q debug=%t; waiting for operation lock", configPath, debug)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("restart", "operation lock acquired; stopping current service")
	if value := a.stopUnlocked(); value != "" {
		tracef("restart", "stop phase failed: %s", value)
		return value
	}
	tracef("restart", "stop phase completed; starting service")
	return traceResult("restart", a.startUnlocked(configPath))
}

func (a *appState) close() error {
	tracef("close", "begin; waiting for operation lock")
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("close", "operation lock acquired; stopping state")
	if value := a.stopUnlocked(); value != "" {
		tracef("close", "stop phase failed: %s", value)
		return errors.New(value)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.commandServer == nil {
		tracef("close", "command server already nil; completed")
		return nil
	}
	tracef("close", "closing command server")
	err := a.commandServer.Close()
	a.commandServer = nil
	if err != nil {
		tracef("close", "command server close failed: %v", err)
	} else {
		tracef("close", "completed successfully")
	}
	return err
}

// changeConfigOptions validates the mobile-only options blob for ABI parity.
// This desktop bridge starts the already-generated runtime config directly, so
// retaining options here would be dead state and must not imply they are applied.
func (a *appState) changeConfigOptions(options string) string {
	tracef("configOptions", "validation begin bytes=%d", len(options))
	if options == "" {
		tracef("configOptions", "empty payload normalized to empty object")
		options = "{}"
	}
	var value any
	if err := json.Unmarshal([]byte(options), &value); err != nil {
		tracef("configOptions", "JSON decode failed: %v", err)
		return "error: invalid config options: " + err.Error()
	}
	if _, ok := value.(map[string]any); !ok {
		tracef("configOptions", "rejected: root type is %T", value)
		return "error: config options must be a JSON object"
	}
	tracef("configOptions", "validation succeeded")
	return ""
}

func (a *appState) selectOutbound(groupTag, outboundTag string) string {
	tracef("selectOutbound", "begin group=%q outbound=%q; waiting for operation lock", groupTag, outboundTag)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("selectOutbound", "operation lock acquired")
	if groupTag == "" || outboundTag == "" {
		tracef("selectOutbound", "rejected: empty tag")
		return "error: group and outbound tags must not be empty"
	}
	tracef("selectOutbound", "creating standalone command client")
	client := libbox.NewStandaloneCommandClient()
	tracef("selectOutbound", "sending selection command")
	if err := client.SelectOutbound(groupTag, outboundTag); err != nil {
		tracef("selectOutbound", "command failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("selectOutbound", "selection completed")
	return ""
}

// URLTest blocks until libbox has finished testing the group. Updated delays
// are then delivered by the group command stream through HistoryStorage's hook.
func (a *appState) urlTest(groupTag string) string {
	tracef("urlTest", "begin group=%q; waiting for operation lock", groupTag)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	tracef("urlTest", "operation lock acquired")
	if groupTag == "" {
		tracef("urlTest", "rejected: empty group tag")
		return "error: group tag must not be empty"
	}
	tracef("urlTest", "creating standalone command client")
	client := libbox.NewStandaloneCommandClient()
	startedAt := time.Now()
	tracef("urlTest", "sending synchronous URL-test command group=%q", groupTag)
	if err := client.URLTest(groupTag); err != nil {
		tracef("urlTest", "command failed after %s: %v", time.Since(startedAt), err)
		return "error: " + err.Error()
	}
	tracef("urlTest", "command completed group=%q duration=%s", groupTag, time.Since(startedAt))
	return ""
}

func (a *appState) startCommandClient(command int32, port int64) string {
	tracef("startCommandClient", "begin command=%d port=%d", command, port)
	if command != commandStatus && command != commandGroup {
		tracef("startCommandClient", "rejected unsupported command=%d", command)
		return fmt.Sprintf("error: unsupported command client: %d", command)
	}
	if port == 0 {
		tracef("startCommandClient", "rejected zero Dart port")
		return "error: Dart port must not be zero"
	}

	tracef("startCommandClient", "waiting for state lock")
	a.mu.Lock()
	defer a.mu.Unlock()
	tracef("startCommandClient", "state lock acquired")
	if a.commandServer == nil {
		tracef("startCommandClient", "rejected: command server is nil")
		return "error: setup must be called before starting command clients"
	}
	if existing := a.commandClients[command]; existing != nil {
		tracef("startCommandClient", "replacing existing client command=%d", command)
		if err := existing.client.Disconnect(); err != nil {
			tracef("startCommandClient", "existing client disconnect failed command=%d: %v", command, err)
		}
		delete(a.commandClients, command)
	}

	tracef("startCommandClient", "creating command client interval=%s", 500*time.Millisecond)
	client := libbox.NewCommandClient(&dartCommandClientHandler{command: command, port: port}, &libbox.CommandClientOptions{
		Command:        command,
		StatusInterval: int64(500 * time.Millisecond),
	})
	tracef("startCommandClient", "connecting command client command=%d", command)
	if err := client.Connect(); err != nil {
		tracef("startCommandClient", "connect failed command=%d: %v", command, err)
		return "error: " + err.Error()
	}
	a.commandClients[command] = &commandClientState{client: client}
	tracef("startCommandClient", "client connected and stored command=%d", command)
	return ""
}

func (a *appState) stopCommandClient(command int32) string {
	tracef("stopCommandClient", "begin command=%d; waiting for state lock", command)
	a.mu.Lock()
	defer a.mu.Unlock()
	tracef("stopCommandClient", "state lock acquired")
	state := a.commandClients[command]
	if state == nil {
		tracef("stopCommandClient", "no client registered command=%d", command)
		return ""
	}
	delete(a.commandClients, command)
	tracef("stopCommandClient", "client removed from state; disconnecting command=%d", command)
	if err := state.client.Disconnect(); err != nil {
		tracef("stopCommandClient", "disconnect failed command=%d: %v", command, err)
		return "error: " + err.Error()
	}
	tracef("stopCommandClient", "client disconnected command=%d", command)
	return ""
}
