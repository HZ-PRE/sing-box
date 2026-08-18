package houtbound

// import (
// 	"context"
// 	"net"

// 	"github.com/sagernet/sing-box/adapter"
// 	E "github.com/sagernet/sing/common/exceptions"
// 	M "github.com/sagernet/sing/common/metadata"
// 	N "github.com/sagernet/sing/common/network"
// )

// type PluginConstructor func(ctx context.Context, pluginArgs map[string][]string, router adapter.Router, dialer N.Dialer, serverAddr M.Socksaddr) (Plugin, error)

// type Plugin interface {
// 	DialContext(ctx context.Context) (net.Conn, error)
// }

// var plugins map[string]PluginConstructor

// func RegisterPlugin(name string, constructor PluginConstructor) {
// 	if plugins == nil {
// 		plugins = make(map[string]PluginConstructor)
// 	}
// 	plugins[name] = constructor
// }

// func CreatePlugin(ctx context.Context, name string, pluginArgs map[string][]string, router adapter.Router, dialer N.Dialer, serverAddr M.Socksaddr) (Plugin, error) {

// 	constructor, loaded := plugins[name]
// 	if !loaded {
// 		return nil, E.New("plugin not found: ", name)
// 	}
// 	return constructor(ctx, pluginArgs, router, dialer, serverAddr)
// }
