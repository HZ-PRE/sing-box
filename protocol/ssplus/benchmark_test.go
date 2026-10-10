package ssplus

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// End-to-end localhost echo, including both endpoints in the measured process.
// Build this unchanged harness against both revisions before comparing native.
// This measures synchronous round trips, not maximum pipelined WAN throughput.
func BenchmarkUDPPolicy(b *testing.B) {
	for _, mode := range []string{"native", "uot1", "uot2"} {
		for _, size := range []int{64, 1200} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
				port := dualPort(b)
				logger := log.NewNOPFactory().Logger()
				router := &echoRouter{routed: make(chan adapter.InboundContext, 8)}
				in, err := NewInbound(context.Background(), router, logger, "bench", option.SSPlusInboundOptions{
					IVKey: key, Method: "chacha20-ietf-poly1305", Protocol: "auth_aes128_md5", Obfs: "tls1.2_ticket_auth",
					Users: []option.SSPlusUser{{UserID: 1, Key: key}}, ListenOptions: option.ListenOptions{ListenPort: uint16(port)},
				})
				if err != nil {
					b.Fatal(err)
				}
				defer in.Close()
				if err = in.Start(adapter.StartStateStart); err != nil {
					b.Fatal(err)
				}
				registry := outbound.NewRegistry()
				RegisterOutbound(registry)
				ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)
				udp := "false"
				if mode == "uot1" {
					udp = `{"enabled":true,"version":1}`
				}
				if mode == "uot2" {
					udp = "true"
				}
				var opts option.Outbound
				err = opts.UnmarshalJSONContext(ctx, []byte(fmt.Sprintf(`{"type":"ssplus","server":"127.0.0.1","server_port":%d,"iv_key":%q,"key":%q,"user_id":1,"method":"chacha20-ietf-poly1305","protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","udp_over_tcp":%s}`, port, key, key, udp)))
				if err != nil {
					b.Fatal(err)
				}
				out, err := NewOutbound(ctx, nil, logger, "bench", *opts.Options.(*option.SSPlusOutboundOptions))
				if err != nil {
					b.Fatal(err)
				}
				target := M.ParseSocksaddr("example.com:53")
				conn, err := out.ListenPacket(ctx, target)
				if err != nil {
					b.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Minute))
				payload, reply := bytes.Repeat([]byte{0x42}, size), make([]byte, size)
				roundtrip := func() {
					if _, err := conn.WriteTo(payload, target); err != nil {
						b.Fatal(err)
					}
					n, _, err := conn.ReadFrom(reply)
					if err != nil || n != size || !bytes.Equal(reply, payload) {
						b.Fatalf("roundtrip: %d %v", n, err)
					}
				}
				roundtrip() // Warm the connection and its buffers outside timing.
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					roundtrip()
				}
				b.StopTimer()
			})
		}
	}
}
