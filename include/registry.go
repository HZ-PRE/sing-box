package include

import (
	"context"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/dns/transport/multi"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/group/balancer"

	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/redirect"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	originca "github.com/sagernet/sing-box/service/origin_ca"
	"github.com/sagernet/sing-box/service/resolved"
	smartdnspool "github.com/sagernet/sing-box/service/smart_dns_pool"
	"github.com/sagernet/sing-box/service/ssmapi"
)

func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

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
	vless.RegisterInbound(registry)

	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)

	block.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)
	shadowsocks.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	balancer.RegisterLoadBalance(registry)

	return registry
}

func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()

	return registry
}

func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	transport.RegisterSDNS(registry)

	multi.RegisterTransport(registry) //H
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	fakeip.RegisterTransport(registry)
	resolved.RegisterTransport(registry)

	registerQUICTransports(registry)
	registerDHCPTransport(registry)
	registerTailscaleTransport(registry)

	return registry
}

func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	resolved.RegisterService(registry)
	ssmapi.RegisterService(registry)
	smartdnspool.RegisterService(registry) //H

	registerDERPService(registry)
	registerCCMService(registry)
	registerOCMService(registry)
	registerOOMKillerService(registry)

	return registry
}

func CertificateProviderRegistry() *certificate.Registry {
	registry := certificate.NewRegistry()

	registerACMECertificateProvider(registry)
	registerTailscaleCertificateProvider(registry)
	originca.RegisterCertificateProvider(registry)

	return registry
}
