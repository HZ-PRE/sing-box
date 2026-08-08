//go:build with_quic

package include

import (
	"github.com/HZ-PRE/sing-box/adapter/inbound"
	"github.com/HZ-PRE/sing-box/adapter/outbound"
	"github.com/HZ-PRE/sing-box/protocol/hysteria"
	"github.com/HZ-PRE/sing-box/protocol/hysteria2"
	_ "github.com/HZ-PRE/sing-box/protocol/naive/quic"
	"github.com/HZ-PRE/sing-box/protocol/tuic"
	_ "github.com/HZ-PRE/sing-box/transport/v2rayquic"
	_ "github.com/sagernet/sing-dns/quic"
)

func registerQUICInbounds(registry *inbound.Registry) {
	hysteria.RegisterInbound(registry)
	tuic.RegisterInbound(registry)
	hysteria2.RegisterInbound(registry)
}

func registerQUICOutbounds(registry *outbound.Registry) {
	hysteria.RegisterOutbound(registry)
	tuic.RegisterOutbound(registry)
	hysteria2.RegisterOutbound(registry)
}
