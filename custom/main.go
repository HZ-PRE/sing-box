package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"os"
	"sync"
	"unsafe"

	"github.com/HZ-PRE/sing-box/experimental/libbox"
)

var (
	setupOnce sync.Once
	app       = newAppState()
)

//export setupOnce
func setupOnce(api unsafe.Pointer) {
	setupOnce.Do(func() {
		// 预留给桌面/Flutter embedder 的一次性初始化。
		// 当前骨架先保持空实现，确保 FFI 符号存在。
	})
}

//export setup
func setup(basePath, workingPath, tempPath *C.char, statusPort C.int64_t, debug C.uchar) *C.char {
	return toCString(app.Setup(cString(basePath), cString(workingPath), cString(tempPath), int64(statusPort), debug != 0))
}

//export start
func start(configPath *C.char, _ C.uchar) *C.char {
	return toCString(app.Start(cString(configPath)))
}

//export stop
func stop() *C.char {
	return toCString(app.Stop())
}

//export restart
func restart(configPath *C.char, _ C.uchar) *C.char {
	return toCString(app.Restart(cString(configPath)))
}

//export parse
func parse(configPath, _tempPath *C.char, _debug C.uchar) *C.char {
	return toCString(app.Parse(cString(configPath)))
}

//export generateConfig
func generateConfig(configPath *C.char) *C.char {
	return toCStringValue(app.GenerateConfig(cString(configPath)))
}

//export generateWarpConfig
func generateWarpConfig(licenseKey, previousAccountID, previousAccessToken *C.char) *C.char {
	return toCStringValue(app.GenerateWarpConfig(cString(licenseKey), cString(previousAccountID), cString(previousAccessToken)))
}

//export selectOutbound
func selectOutbound(groupTag, outboundTag *C.char) *C.char {
	return toCString(app.SelectOutbound(cString(groupTag), cString(outboundTag)))
}

//export urlTest
func urlTest(groupTag *C.char) *C.char {
	return toCString(app.URLTest(cString(groupTag)))
}

//export startCommandClient
func startCommandClient(command C.int32_t, port C.int64_t) *C.char {
	return toCString(app.StartCommandClient(int32(command), int64(port)))
}

//export stopCommandClient
func stopCommandClient(command C.int32_t) *C.char {
	return toCString(app.StopCommandClient(int32(command)))
}

//export changeConfigOptions
func changeConfigOptions(jsonOptions *C.char) *C.char {
	return toCString(app.ChangeConfigOptions(cString(jsonOptions)))
}

func main() {}

func cString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

func toCString(err error) *C.char {
	if err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

func toCStringValue(value string, err error) *C.char {
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString(value)
}

type appState struct {
	mu            sync.Mutex
	basePath      string
	workingPath   string
	tempPath      string
	statusPort    int64
	debug         bool
	configOptions string
	service       *libbox.BoxService
	commandServer *libbox.CommandServer
	clients       map[int32]*ffiCommandClient
}

func newAppState() *appState {
	return &appState{clients: make(map[int32]*ffiCommandClient)}
}

func (a *appState) Setup(basePath, workingPath, tempPath string, statusPort int64, debug bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.basePath = basePath
	a.workingPath = workingPath
	a.tempPath = tempPath
	a.statusPort = statusPort
	a.debug = debug

	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(workingPath, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(tempPath, 0o755); err != nil {
		return err
	}

	return libbox.Setup(&libbox.SetupOptions{
		BasePath:    basePath,
		WorkingPath: workingPath,
		TempPath:    tempPath,
	})
}

func (a *appState) Start(configPath string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.stopLocked(); err != nil {
		return err
	}
	return a.startLocked(configPath)
}

func (a *appState) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopLocked()
}

func (a *appState) Restart(configPath string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.stopLocked(); err != nil {
		return err
	}
	return a.startLocked(configPath)
}

func (a *appState) Parse(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	return libbox.CheckConfig(string(content))
}

func (a *appState) GenerateConfig(configPath string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	formatted, err := libbox.FormatConfig(string(content))
	if err != nil {
		return "", err
	}
	if formatted == nil {
		return "", nil
	}
	return formatted.String(), nil
}

func (a *appState) GenerateWarpConfig(licenseKey, previousAccountID, previousAccessToken string) (string, error) {
	payload := map[string]string{
		"licenseKey":          licenseKey,
		"previousAccountId":   previousAccountID,
		"previousAccessToken": previousAccessToken,
	}
	bytes, err := json.Marshal(map[string]any{
		"unsupported": true,
		"message":     "generateWarpConfig skeleton not implemented yet",
		"input":       payload,
	})
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (a *appState) SelectOutbound(groupTag, outboundTag string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	client, err := a.ensureCommandClientLocked(libbox.CommandSelectOutbound)
	if err != nil {
		return err
	}
	return client.client.SelectOutbound(groupTag, outboundTag)
}

func (a *appState) URLTest(groupTag string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	client, err := a.ensureCommandClientLocked(libbox.CommandURLTest)
	if err != nil {
		return err
	}
	return client.client.URLTest(groupTag)
}

func (a *appState) StartCommandClient(command int32, port int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.clients[command]; exists {
		return nil
	}
	fc := newFFICommandClient(command, port)
	if err := fc.client.Connect(); err != nil {
		return err
	}
	a.clients[command] = fc
	return nil
}

func (a *appState) StopCommandClient(command int32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopCommandClientLocked(command)
}

func (a *appState) ChangeConfigOptions(jsonOptions string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.configOptions = jsonOptions
	return nil
}

func (a *appState) startLocked(configPath string) error {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	service, err := libbox.NewService(string(content), &desktopPlatformStub{})
	if err != nil {
		return err
	}
	if err = service.Start(); err != nil {
		return err
	}
	commandServer := libbox.NewCommandServer(&desktopCommandServerHandler{}, 256)
	commandServer.SetService(service)
	if err = commandServer.Start(); err != nil {
		_ = service.Close()
		return err
	}
	a.service = service
	a.commandServer = commandServer
	return nil
}

func (a *appState) stopLocked() error {
	for command := range a.clients {
		if err := a.stopCommandClientLocked(command); err != nil {
			return err
		}
	}
	if a.commandServer != nil {
		if err := a.commandServer.Close(); err != nil {
			return err
		}
		a.commandServer = nil
	}
	if a.service != nil {
		if err := a.service.Close(); err != nil {
			return err
		}
		a.service = nil
	}
	return nil
}

func (a *appState) stopCommandClientLocked(command int32) error {
	fc, exists := a.clients[command]
	if !exists {
		return nil
	}
	delete(a.clients, command)
	return fc.client.Disconnect()
}

func (a *appState) ensureCommandClientLocked(command int32) (*ffiCommandClient, error) {
	if fc, exists := a.clients[command]; exists {
		return fc, nil
	}
	fc := newFFICommandClient(command, 0)
	a.clients[command] = fc
	return fc, nil
}
