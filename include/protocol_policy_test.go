package include

import (
	"context"
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// Run with both the production tags and historical optional protocol tags.
// No build flag may restore a removed protocol through a registration stub.
func TestRemovedProtocolsHaveNoRegistryEntries(t *testing.T) {
	ctx := Context(context.Background())
	for _, protocol := range []string{"vmess", "trojan", "hysteria", "hysteria2", "tuic", "wireguard", "warp", "awg", "tailscale", "anytls", "shadowtls", "snell", "mieru", "masque", "naive", "psiphon", "tor", "ssh", "shadowsocksr", "cloudflared", "xray", "dnstt", "gooserelay", "tunnel_client", "tunnel_server"} {
		for _, section := range []string{"inbounds", "outbounds", "endpoints"} {
			t.Run(section+"/"+protocol, func(t *testing.T) {
				var options option.Options
				if err := options.UnmarshalJSONContext(ctx, []byte(fmt.Sprintf(`{"%s":[{"type":%q}]}`, section, protocol))); err == nil {
					t.Fatal("removed protocol was registered")
				}
			})
		}
	}
}
