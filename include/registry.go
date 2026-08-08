package include

import (
	"context"

	"github.com/HZ-PRE/sing-box/adapter"
	"github.com/HZ-PRE/sing-box/adapter/endpoint"
	"github.com/HZ-PRE/sing-box/adapter/inbound"
	"github.com/HZ-PRE/sing-box/adapter/outbound"
	C "github.com/HZ-PRE/sing-box/constant"
	"github.com/HZ-PRE/sing-box/log"
	"github.com/HZ-PRE/sing-box/option"
	"github.com/HZ-PRE/sing-box/protocol/block"
	"github.com/HZ-PRE/sing-box/protocol/direct"
	"github.com/HZ-PRE/sing-box/protocol/dns"
	"github.com/HZ-PRE/sing-box/protocol/group"
	"github.com/HZ-PRE/sing-box/protocol/http"
	"github.com/HZ-PRE/sing-box/protocol/mixed"
	"github.com/HZ-PRE/sing-box/protocol/naive"
	"github.com/HZ-PRE/sing-box/protocol/redirect"
	"github.com/HZ-PRE/sing-box/protocol/shadowsocks"
	"github.com/HZ-PRE/sing-box/protocol/shadowtls"
	"github.com/HZ-PRE/sing-box/protocol/socks"
	"github.com/HZ-PRE/sing-box/protocol/ssh"
	"github.com/HZ-PRE/sing-box/protocol/tor"
	"github.com/HZ-PRE/sing-box/protocol/trojan"
	"github.com/HZ-PRE/sing-box/protocol/tun"
	"github.com/HZ-PRE/sing-box/protocol/vless"
	"github.com/HZ-PRE/sing-box/protocol/vmess"
	E "github.com/sagernet/sing/common/exceptions"
)

func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	tun.RegisterInbound(registry)
	redirect.RegisterRedirect(registry)
	redirect.RegisterTProxy(registry)
	direct.RegisterInbound(registry)

	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	mixed.RegisterInbound(registry)

	shadowsocks.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	shadowtls.RegisterInbound(registry)
	vless.RegisterInbound(registry)

	registerQUICInbounds(registry)
	registerStubForRemovedInbounds(registry)

	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)

	block.RegisterOutbound(registry)
	dns.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	socks.RegisterOutbound(registry)
	http.RegisterOutbound(registry)
	shadowsocks.RegisterOutbound(registry)
	vmess.RegisterOutbound(registry)
	trojan.RegisterOutbound(registry)
	tor.RegisterOutbound(registry)
	ssh.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)

	registerQUICOutbounds(registry)
	registerWireGuardOutbound(registry)
	registerStubForRemovedOutbounds(registry)

	return registry
}

func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()

	registerWireGuardEndpoint(registry)

	return registry
}

func registerStubForRemovedInbounds(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
}

func registerStubForRemovedOutbounds(registry *outbound.Registry) {
	outbound.Register[option.ShadowsocksROutboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksROutboundOptions) (adapter.Outbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
}
