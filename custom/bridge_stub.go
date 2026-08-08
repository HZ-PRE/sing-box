package main

import (
	"context"
	"encoding/json"
	"net/netip"

	"github.com/HZ-PRE/sing-box/adapter"
	libbox "github.com/HZ-PRE/sing-box/experimental/libbox"
	platform "github.com/HZ-PRE/sing-box/experimental/libbox/platform"
	"github.com/HZ-PRE/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
)

type desktopPlatformStub struct{}

func (d *desktopPlatformStub) Initialize(networkManager adapter.NetworkManager) error {
	return nil
}

func (d *desktopPlatformStub) UsePlatformAutoDetectInterfaceControl() bool {
	return true
}

func (d *desktopPlatformStub) AutoDetectInterfaceControl(fd int) error {
	return nil
}

func (d *desktopPlatformStub) OpenTun(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	return nil, nil
}

func (d *desktopPlatformStub) CreateDefaultInterfaceMonitor(log logger.Logger) tun.DefaultInterfaceMonitor {
	return desktopDefaultInterfaceMonitor{}
}

func (d *desktopPlatformStub) Interfaces() ([]adapter.NetworkInterface, error) {
	return nil, nil
}

func (d *desktopPlatformStub) UnderNetworkExtension() bool {
	return false
}

func (d *desktopPlatformStub) IncludeAllNetworks() bool {
	return false
}

func (d *desktopPlatformStub) ClearDNSCache() {}

func (d *desktopPlatformStub) ReadWIFIState() adapter.WIFIState {
	return adapter.WIFIState{}
}

func (d *desktopPlatformStub) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ProcessInfo, error) {
	return nil, nil
}

func (d *desktopPlatformStub) SendNotification(notification *platform.Notification) error {
	return nil
}

type desktopDefaultInterfaceMonitor struct{}

func (d desktopDefaultInterfaceMonitor) Start() error                     { return nil }
func (d desktopDefaultInterfaceMonitor) Close() error                     { return nil }
func (d desktopDefaultInterfaceMonitor) DefaultInterface() *tun.Interface { return nil }
func (d desktopDefaultInterfaceMonitor) OverrideAndroidVPN() bool         { return false }
func (d desktopDefaultInterfaceMonitor) AndroidVPNEnabled() bool          { return false }
func (d desktopDefaultInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) any {
	return nil
}
func (d desktopDefaultInterfaceMonitor) UnregisterCallback(element any) {}

type desktopCommandServerHandler struct{}

func (d *desktopCommandServerHandler) ServiceReload() error { return nil }
func (d *desktopCommandServerHandler) PostServiceClose()    {}
func (d *desktopCommandServerHandler) GetSystemProxyStatus() *libbox.SystemProxyStatus {
	return nil
}
func (d *desktopCommandServerHandler) SetSystemProxyEnabled(isEnabled bool) error {
	return nil
}

type ffiCommandClient struct {
	client *libbox.CommandClient
}

func newFFICommandClient(command int32, _port int64) *ffiCommandClient {
	handler := &ffiCommandClientHandler{}
	return &ffiCommandClient{
		client: libbox.NewCommandClient(handler, &libbox.CommandClientOptions{
			Command:        command,
			StatusInterval: 1000000000,
		}),
	}
}

type ffiCommandClientHandler struct{}

func (h *ffiCommandClientHandler) Connected()                                  {}
func (h *ffiCommandClientHandler) Disconnected(message string)                 {}
func (h *ffiCommandClientHandler) ClearLogs()                                  {}
func (h *ffiCommandClientHandler) WriteLogs(messageList libbox.StringIterator) {}
func (h *ffiCommandClientHandler) InitializeClashMode(modeList libbox.StringIterator, currentMode string) {
}
func (h *ffiCommandClientHandler) UpdateClashMode(newMode string)                   {}
func (h *ffiCommandClientHandler) WriteConnections(message *libbox.Connections)     {}
func (h *ffiCommandClientHandler) WriteStatus(message *libbox.StatusMessage)        {}
func (h *ffiCommandClientHandler) WriteGroups(message libbox.OutboundGroupIterator) {}

func jsonString(v any) string {
	bytes, _ := json.Marshal(v)
	return string(bytes)
}
