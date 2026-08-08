//go:build with_wireguard

package include

import (
	"github.com/HZ-PRE/sing-box/adapter/endpoint"
	"github.com/HZ-PRE/sing-box/adapter/outbound"
	"github.com/HZ-PRE/sing-box/protocol/wireguard"
)

func registerWireGuardOutbound(registry *outbound.Registry) {
	wireguard.RegisterOutbound(registry)
}

func registerWireGuardEndpoint(registry *endpoint.Registry) {
	wireguard.RegisterEndpoint(registry)
}
