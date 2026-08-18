package main

import (
	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing-box/experimental/libbox"
)

type CommandServerHandler struct {
	logger log.Logger
}

// PostServiceClose implements libbox.CommandServerHandler.
func (csh *CommandServerHandler) PostServiceClose() {
	panic("unimplemented")
}

var commandServer *libbox.CommandServer

func (csh *CommandServerHandler) ServiceReload() error {

	if commandServer != nil {
		commandServer.SetService(nil)
		commandServer = nil
	}
	// if box != nil {
	// 	box.Close()
	// 	box = nil
	// }
	return nil
}

func (csh *CommandServerHandler) GetSystemProxyStatus() *libbox.SystemProxyStatus {
	return &libbox.SystemProxyStatus{Available: true, Enabled: false}
}

func (csh *CommandServerHandler) SetSystemProxyEnabled(isEnabled bool) error {
	return csh.ServiceReload()
}
