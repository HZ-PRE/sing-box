package main

/*
#cgo CFLAGS: -I${SRCDIR}/dart_api
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "dart_api_dl.h"

static bool bridgeDartPostString(int64_t port, const char* value) {
	Dart_CObject result;
	result.type = Dart_CObject_kString;
	result.value.as_string = (char*)value;
	return Dart_PostCObject_DL((Dart_Port_DL)port, &result);
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"unsafe"

	"github.com/sagernet/sing-box/experimental/libbox"
)

const (
	commandStatus = int32(libbox.CommandStatus)
	commandGroup  = int32(libbox.CommandGroup)
)

var setupOnceGuard sync.Once

// Every exported function returning *C.char transfers ownership to Dart.
// The caller must invoke freeString after converting the result.

//export setupOnce
func setupOnce(api unsafe.Pointer) {
	tracef("ffi.setupOnce", "called apiPresent=%t", api != nil)
	setupOnceGuard.Do(func() {
		if api == nil {
			tracef("ffi.setupOnce", "skipped: API pointer is nil")
			return
		}
		result := C.Dart_InitializeApiDL(api)
		tracef("ffi.setupOnce", "Dart_InitializeApiDL result=%d", int64(result))
	})
}

//export setup
func setup(basePath, workingPath, tempPath *C.char, statusPort C.int64_t, debug C.uchar) *C.char {
	base, working, temp := cString(basePath), cString(workingPath), cString(tempPath)
	tracef("ffi.setup", "called base=%q working=%q temp=%q statusPort=%d debug=%t", base, working, temp, int64(statusPort), debug != 0)
	return toCString(traceResult("ffi.setup", app.setup(base, working, temp, int64(statusPort), debug != 0)))
}

//export start
func start(configPath *C.char, debug C.uchar) *C.char {
	path := cString(configPath)
	tracef("ffi.start", "called configPath=%q debug=%t", path, debug != 0)
	return toCString(traceResult("ffi.start", app.start(path, debug != 0)))
}

//export stop
func stop() *C.char {
	tracef("ffi.stop", "called")
	return toCString(traceResult("ffi.stop", app.stop()))
}

//export restart
func restart(configPath *C.char, debug C.uchar) *C.char {
	path := cString(configPath)
	tracef("ffi.restart", "called configPath=%q debug=%t", path, debug != 0)
	return toCString(traceResult("ffi.restart", app.restart(path, debug != 0)))
}

// parse validates the configuration file at configPath. tempPath is retained in
// the ABI for parity with the mobile implementation; libbox.Setup owns it.
//
//export parse
func parse(configPath, tempPath *C.char, debug C.uchar) *C.char {
	path, temp := cString(configPath), cString(tempPath)
	tracef("ffi.parse", "called configPath=%q tempPath=%q debug=%t", path, temp, debug != 0)
	return toCString(traceResult("ffi.parse", validateConfigFile(path, temp, debug != 0)))
}

// generateConfig returns the validated, normalized JSON configuration.
//
//export generateConfig
func generateConfig(path *C.char) *C.char {
	configPath := cString(path)
	tracef("ffi.generateConfig", "called path=%q", configPath)
	value, err := normalizedConfigFile(configPath)
	response := result(value, err)
	if err == nil {
		tracef("ffi.generateConfig", "completed successfully bytes=%d", len(value))
	} else {
		tracef("ffi.generateConfig", "failed: %v", err)
	}
	return toCString(response)
}

// WARP account registration belongs to the platform integration and is not an
// API offered by experimental/libbox. Keep the ABI explicit instead of
// returning a successful-looking empty result.
//
//export generateWarpConfig
func generateWarpConfig(licenseKey, previousAccountID, previousAccessToken *C.char) *C.char {
	// Never log credential values; only record whether optional inputs exist.
	tracef("ffi.generateWarpConfig", "called licensePresent=%t previousAccountPresent=%t previousTokenPresent=%t", cString(licenseKey) != "", cString(previousAccountID) != "", cString(previousAccessToken) != "")
	response := "error: WARP configuration generation is unsupported by this desktop core"
	tracef("ffi.generateWarpConfig", "completed with result: %s", response)
	return C.CString(response)
}

//export selectOutbound
func selectOutbound(groupTag, outboundTag *C.char) *C.char {
	group, outbound := cString(groupTag), cString(outboundTag)
	tracef("ffi.selectOutbound", "called group=%q outbound=%q", group, outbound)
	return toCString(traceResult("ffi.selectOutbound", app.selectOutbound(group, outbound)))
}

//export urlTest
func urlTest(groupTag *C.char) *C.char {
	group := cString(groupTag)
	tracef("ffi.urlTest", "called group=%q", group)
	return toCString(traceResult("ffi.urlTest", app.urlTest(group)))
}

//export changeConfigOptions
func changeConfigOptions(options *C.char) *C.char {
	value := cString(options)
	tracef("ffi.changeConfigOptions", "called bytes=%d", len(value))
	return toCString(traceResult("ffi.changeConfigOptions", app.changeConfigOptions(value)))
}

//export startCommandClient
func startCommandClient(command C.int32_t, port C.int64_t) *C.char {
	tracef("ffi.startCommandClient", "called command=%d port=%d", int32(command), int64(port))
	return toCString(traceResult("ffi.startCommandClient", app.startCommandClient(int32(command), int64(port))))
}

//export stopCommandClient
func stopCommandClient(command C.int32_t) *C.char {
	tracef("ffi.stopCommandClient", "called command=%d", int32(command))
	return toCString(traceResult("ffi.stopCommandClient", app.stopCommandClient(int32(command))))
}

//export freeString
func freeString(value *C.char) {
	tracef("ffi.freeString", "called pointerPresent=%t", value != nil)
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}

func cString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

func toCString(value string) *C.char { return C.CString(value) }

func result(value string, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return value
}

func validateConfigFile(configPath, tempPath string, debug bool) string {
	tracef("config.validate", "read path=%q tempPath=%q debug=%t", configPath, tempPath, debug)
	content, err := os.ReadFile(configPath)
	if err != nil {
		tracef("config.validate", "read failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("config.validate", "read completed bytes=%d", len(content))
	if err = libbox.CheckConfig(string(content)); err != nil {
		tracef("config.validate", "validation failed: %v", err)
		return "error: " + err.Error()
	}
	tracef("config.validate", "validation succeeded")
	return ""
}

func normalizedConfigFile(path string) (string, error) {
	tracef("config.normalize", "read path=%q", path)
	content, err := os.ReadFile(path)
	if err != nil {
		tracef("config.normalize", "read failed: %v", err)
		return "", err
	}
	tracef("config.normalize", "formatting bytes=%d", len(content))
	formatted, err := libbox.FormatConfig(string(content))
	if err != nil {
		tracef("config.normalize", "format failed: %v", err)
		return "", err
	}
	tracef("config.normalize", "format succeeded outputBytes=%d", len(formatted.Value))
	return formatted.Value, nil
}

func postStatus(port int64, status string) {
	tracef("dart.status", "post status=%q port=%d", status, port)
	postJSON(port, map[string]any{"status": status})
}

func postJSON(port int64, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		tracef("dart.postJSON", "marshal failed port=%d: %v", port, err)
		return
	}
	tracef("dart.postJSON", "marshaled port=%d bytes=%d", port, len(payload))
	postString(port, string(payload))
}

func postString(port int64, value string) {
	if port == 0 || value == "" {
		tracef("dart.postString", "skipped port=%d bytes=%d", port, len(value))
		return
	}
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	posted := bool(C.bridgeDartPostString(C.int64_t(port), cValue))
	tracef("dart.postString", "posted=%t port=%d bytes=%d", posted, port, len(value))
}

type dartCommandClientHandler struct {
	command int32
	port    int64
}

func (h *dartCommandClientHandler) Connected() {
	tracef("commandClient", "connected command=%d port=%d", h.command, h.port)
}

func (h *dartCommandClientHandler) Disconnected(message string) {
	// A disconnect is transport state, not a JSON payload. Posting it to the
	// data stream would make Dart's jsonDecode fail.
	tracef("commandClient", "disconnected command=%d port=%d message=%q", h.command, h.port, message)
}

func (h *dartCommandClientHandler) ClearLogs() {
	tracef("commandClient", "clear logs requested command=%d port=%d", h.command, h.port)
}

func (h *dartCommandClientHandler) WriteLogs(messages libbox.StringIterator) {
	var values []string
	for messages != nil && messages.HasNext() {
		values = append(values, messages.Next())
	}
	tracef("commandClient.logs", "received command=%d port=%d count=%d", h.command, h.port, len(values))
	postJSON(h.port, values)
}

func (h *dartCommandClientHandler) WriteStatus(message *libbox.StatusMessage) {
	if message == nil {
		tracef("commandClient.status", "ignored nil message command=%d port=%d", h.command, h.port)
		return
	}
	tracef("commandClient.status", "received command=%d port=%d down=%d up=%d downTotal=%d upTotal=%d memory=%d connectionsIn=%d connectionsOut=%d traffic=%t", h.command, h.port, message.Downlink, message.Uplink, message.DownlinkTotal, message.UplinkTotal, message.Memory, message.ConnectionsIn, message.ConnectionsOut, message.TrafficAvailable)
	postJSON(h.port, map[string]any{
		"downloadSpeed":      message.Downlink,
		"uploadSpeed":        message.Uplink,
		"downloadTotal":      message.DownlinkTotal,
		"uploadTotal":        message.UplinkTotal,
		"memoryUsage":        message.Memory,
		"activeConnections":  message.ConnectionsOut,
		"connectionNum":      message.ConnectionsOut,
		"connectionNumIn":    message.ConnectionsIn,
		"connectionNumOut":   message.ConnectionsOut,
		"isTrafficAvailable": message.TrafficAvailable,
	})
}

func (h *dartCommandClientHandler) WriteGroups(message libbox.OutboundGroupIterator) {
	tracef("commandClient.groups", "snapshot begin command=%d port=%d", h.command, h.port)
	groups := make([]map[string]any, 0)
	for message != nil && message.HasNext() {
		group := message.Next()
		if group == nil {
			continue
		}
		items := make([]map[string]any, 0)
		for iterator := group.GetItems(); iterator != nil && iterator.HasNext(); {
			item := iterator.Next()
			if item != nil {
				items = append(items, map[string]any{
					"tag": item.Tag, "type": item.Type,
					"urlTestTime": item.URLTestTime, "urlTestDelay": item.URLTestDelay,
				})
			}
		}
		tracef("commandClient.groups", "group tag=%q type=%q selected=%q selectable=%t items=%d", group.Tag, group.Type, group.Selected, group.Selectable, len(items))
		groups = append(groups, map[string]any{
			"tag": group.Tag, "type": group.Type, "selectable": group.Selectable,
			"selected": group.Selected, "isExpand": group.IsExpand, "itemList": items,
		})
	}
	tracef("commandClient.groups", "snapshot completed command=%d port=%d groups=%d", h.command, h.port, len(groups))
	postJSON(h.port, groups)
}

func (h *dartCommandClientHandler) InitializeClashMode(_ libbox.StringIterator, current string) {
	tracef("commandClient.clashMode", "initialized command=%d port=%d current=%q", h.command, h.port, current)
}
func (h *dartCommandClientHandler) UpdateClashMode(mode string) {
	tracef("commandClient.clashMode", "updated command=%d port=%d mode=%q", h.command, h.port, mode)
}
func (h *dartCommandClientHandler) WriteConnections(message *libbox.Connections) {
	tracef("commandClient.connections", "received command=%d port=%d messagePresent=%t", h.command, h.port, message != nil)
}

type noopCommandServerHandler struct{}

func (noopCommandServerHandler) ServiceReload() error {
	tracef("commandServer", "service reload requested")
	return nil
}
func (noopCommandServerHandler) PostServiceClose() {
	tracef("commandServer", "post service close callback")
}
func (noopCommandServerHandler) GetSystemProxyStatus() *libbox.SystemProxyStatus {
	tracef("commandServer", "system proxy status requested; unsupported")
	return nil
}
func (noopCommandServerHandler) SetSystemProxyEnabled(enabled bool) error {
	tracef("commandServer", "set system proxy requested enabled=%t; ignored", enabled)
	return nil
}

type noopPlatformInterface struct{}

func (noopPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (noopPlatformInterface) AutoDetectInterfaceControl(int32) error      { return nil }
func (noopPlatformInterface) OpenTun(libbox.TunOptions) (int32, error) {
	err := errors.New("TUN is unsupported by the desktop FFI platform bridge")
	tracef("platform.OpenTun", "failed: %v", err)
	return 0, err
}
func (noopPlatformInterface) WriteLog(message string) {
	tracef("sing-box", "%s", message)
}
func (noopPlatformInterface) UseProcFS() bool { return false }
func (noopPlatformInterface) FindConnectionOwner(protocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (int32, error) {
	err := errors.New("connection owner lookup is unsupported")
	tracef("platform.FindConnectionOwner", "failed protocol=%d source=%s:%d destination=%s:%d: %v", protocol, sourceAddress, sourcePort, destinationAddress, destinationPort, err)
	return 0, err
}
func (noopPlatformInterface) PackageNameByUid(uid int32) (string, error) {
	err := errors.New("package lookup is unsupported")
	tracef("platform.PackageNameByUid", "failed uid=%d: %v", uid, err)
	return "", err
}
func (noopPlatformInterface) UIDByPackageName(packageName string) (int32, error) {
	err := errors.New("package lookup is unsupported")
	tracef("platform.UIDByPackageName", "failed package=%q: %v", packageName, err)
	return 0, err
}
func (noopPlatformInterface) StartDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error {
	return nil
}
func (noopPlatformInterface) CloseDefaultInterfaceMonitor(libbox.InterfaceUpdateListener) error {
	return nil
}
func (noopPlatformInterface) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return emptyNetworkInterfaceIterator{}, nil
}
func (noopPlatformInterface) UnderNetworkExtension() bool { return false }
func (noopPlatformInterface) IncludeAllNetworks() bool    { return false }
func (noopPlatformInterface) ReadWIFIState() *libbox.WIFIState {
	return nil
}
func (noopPlatformInterface) ClearDNSCache()                              {}
func (noopPlatformInterface) SendNotification(*libbox.Notification) error { return nil }

type emptyNetworkInterfaceIterator struct{}

func (emptyNetworkInterfaceIterator) Next() *libbox.NetworkInterface { return nil }
func (emptyNetworkInterfaceIterator) HasNext() bool                  { return false }

func main() {}
