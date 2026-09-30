package include_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
)

func TestOnlyRetainedProxyProtocolsRegistered(t *testing.T) {
	registry := include.OutboundRegistry()
	for _, kind := range []string{"ssplus", "vless", "direct", "block", "selector", "urltest", "balancer", "local-socks"} {
		if _, ok := registry.CreateOptions(kind); !ok {
			t.Errorf("missing retained outbound %s", kind)
		}
	}
	ctx := include.Context(context.Background())
	for _, kind := range []string{"shadowsocks", "shadowsocksr", "vmess", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "warp", "awg", "tailscale", "anytls", "naive", "ssh", "tor", "mieru", "shadowtls", "snell", "masque", "xray", "psiphon", "dnstt", "gooserelay", "http", "socks", "tunnel_client", "tunnel_server"} {
		t.Run(kind, func(t *testing.T) {
			if _, ok := registry.CreateOptions(kind); ok {
				t.Fatal("removed outbound is registered")
			}
			var config option.Options
			if err := config.UnmarshalJSONContext(ctx, []byte(`{"outbounds":[{"type":"`+kind+`"}]}`)); err == nil {
				t.Fatal("removed outbound accepted by JSON parser")
			}
			if _, ok := include.EndpointRegistry().CreateOptions(kind); ok {
				t.Fatal("removed endpoint is registered")
			}
			if kind != "http" && kind != "socks" {
				if _, ok := include.InboundRegistry().CreateOptions(kind); ok {
					t.Fatal("removed inbound is registered")
				}
			}
		})
	}
}

func TestLocalTUNBridgeRejectsRemoteServersAndDetours(t *testing.T) {
	for _, opts := range []option.LocalSOCKSBridgeOptions{
		{ServerOptions: option.ServerOptions{Server: "proxy.example", ServerPort: 1080}},
		{ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 1080}},
		{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080}, DialerOptions: option.DialerOptions{Detour: "proxy"}},
	} {
		if _, err := socks.NewOutbound(context.Background(), nil, nil, "bridge", opts); err == nil {
			t.Fatal("local bridge accepted a remote server or detour")
		}
	}
}
