package ssplus

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/ssplus"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type echoRouter struct {
	adapter.Router
	routed chan adapter.InboundContext
}

func (r *echoRouter) RouteConnectionEx(_ context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- metadata
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (r *echoRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed <- metadata
	go func() {
		defer conn.Close()
		for {
			buffer := buf.NewPacket()
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				if onClose != nil {
					onClose(err)
				}
				return
			}
			if err = conn.WritePacket(buffer, destination); err != nil {
				if onClose != nil {
					onClose(err)
				}
				return
			}
		}
	}()
}

func TestRegisteredLoopbackTCPAndUDPPolicies(t *testing.T) {
	inRegistry, outRegistry := inbound.NewRegistry(), outbound.NewRegistry()
	RegisterInbound(inRegistry)
	RegisterOutbound(outRegistry)
	ctx := service.ContextWith[option.InboundOptionsRegistry](context.Background(), inRegistry)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outRegistry)
	logger := log.NewNOPFactory().Logger()
	router := &echoRouter{routed: make(chan adapter.InboundContext, 8)}
	ivKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	userKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	var inOptions option.Inbound
	err := inOptions.UnmarshalJSONContext(ctx, []byte(fmt.Sprintf(`{"type":"ssplus","tag":"ssplus-in","native_udp":false,"listen":"127.0.0.1","listen_port":%d,"protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","iv_key":%q,"users":[{"user_id":7,"name":"alice","key":%q}]}`, dualPort(t), ivKey, userKey)))
	if err != nil {
		t.Fatal(err)
	}
	encodedInbound, err := inOptions.MarshalJSONContext(ctx)
	if err != nil || bytes.Contains(encodedInbound, []byte("native_udp")) {
		t.Fatal("retired inbound UDP option was persisted", err)
	}
	in, err := inRegistry.Create(ctx, router, logger, inOptions.Tag, inOptions.Type, inOptions.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err = in.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	port := in.(*Inbound).listener.TCPListener().Addr().(*net.TCPAddr).Port
	for index, legacy := range []string{"", `,"udp_over_tcp":true`, `,"udp_over_tcp":{"enabled":true,"version":1}`, `,"udp_over_tcp":false`, `,"udp_mode":"uot","udp_over_tcp":false`} {
		var outOptions option.Outbound
		err = outOptions.UnmarshalJSONContext(ctx, []byte(fmt.Sprintf(`{"type":"ssplus","tag":"ssplus-out","server":"127.0.0.1","server_port":%d,"protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","iv_key":%q,"user_id":7,"key":%q%s}`, port, ivKey, userKey, legacy)))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := outOptions.MarshalJSONContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("udp_mode")) {
			t.Fatal("retired UDP options were persisted")
		}
		var restored option.Outbound
		if err = restored.UnmarshalJSONContext(ctx, encoded); err != nil {
			t.Fatal(err)
		}
		parsed := restored.Options.(*option.SSPlusOutboundOptions).UDPOverTCP
		if index == 0 && parsed != nil || index != 0 && (parsed == nil || parsed.Enabled != (index == 1 || index == 2)) {
			t.Fatal("UDP policy lost during configuration roundtrip")
		}
		if index == 2 && parsed.Version != 1 {
			t.Fatal("UoT v1 lost during configuration roundtrip")
		}
		out, err := outRegistry.CreateOutbound(ctx, router, logger, outOptions.Tag, outOptions.Type, outOptions.Options)
		if err != nil {
			t.Fatal(err)
		}
		for _, network := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("v%d/%s", index, network), func(t *testing.T) {
				destination := M.ParseSocksaddr("example.com:443")
				conn, err := out.DialContext(ctx, network, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				if n, err := conn.Write([]byte("ping")); err != nil || n != 4 {
					t.Fatalf("Write returned %d, %v", n, err)
				}
				reply := make([]byte, 4)
				if _, err = io.ReadFull(conn, reply); err != nil {
					t.Fatal(err)
				}
				if string(reply) != "ping" {
					t.Fatalf("reply %q", reply)
				}
				metadata := <-router.routed
				if metadata.User != "alice" || metadata.InboundType != "ssplus" || metadata.Inbound != "ssplus-in" {
					t.Fatalf("incorrect routing metadata: %+v", metadata)
				}
				if network == "tcp" && metadata.Destination != destination {
					t.Fatal("incorrect TCP destination")
				}
			})
		}
		t.Run(fmt.Sprintf("v%d/ListenPacket", index), func(t *testing.T) {
			packets, err := out.ListenPacket(ctx, M.ParseSocksaddr("1.1.1.1:53"))
			if err != nil {
				t.Fatal(err)
			}
			defer packets.Close()
			packets.SetDeadline(time.Now().Add(5 * time.Second))
			for _, address := range []string{"1.1.1.1:53", "[2001:db8::1]:5353", "example.com:1234"} {
				destination := M.ParseSocksaddr(address)
				if n, err := packets.WriteTo([]byte("packet"), destination); err != nil || n != 6 {
					t.Fatalf("WriteTo returned %d, %v", n, err)
				}
				buffer := make([]byte, 64)
				n, addr, err := packets.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				if string(buffer[:n]) != "packet" || M.SocksaddrFromNet(addr).Unwrap() != destination.Unwrap() {
					t.Fatalf("incorrect reply %q from %#v, want %#v", buffer[:n], M.SocksaddrFromNet(addr), destination)
				}
			}
			destination := M.ParseSocksaddr("1.1.1.1:53")
			if _, err = packets.WriteTo(make([]byte, 65536), destination); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatal("oversized datagram accepted")
			}
			if _, err = packets.WriteTo([]byte("truncate"), destination); err != nil {
				t.Fatal(err)
			}
			if _, _, err = packets.ReadFrom(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("truncated read: %v", err)
			}
			if _, err = packets.WriteTo([]byte("ok"), destination); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 2)
			if n, _, err := packets.ReadFrom(reply); err != nil || n != 2 || string(reply) != "ok" {
				t.Fatalf("framing lost after truncated read: %q, %v", reply, err)
			}
			if metadata := <-router.routed; metadata.User != "alice" {
				t.Fatal("missing native UDP user")
			}
		})
	}
}

func TestOutboundNetworks(t *testing.T) {
	opts := option.SSPlusOutboundOptions{IVKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Key: base64.StdEncoding.EncodeToString(make([]byte, 32)), UserID: 1}
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if networks := out.Network(); len(networks) != 2 {
		t.Fatal("default must support TCP and native UDP")
	}
	opts.Network = "invalid"
	if _, err = NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", opts); err == nil {
		t.Fatal("accepted invalid network")
	}
}

func TestNativeOutboundFallbackAndCooldown(t *testing.T) {
	for _, mode := range []string{"native", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			logger := log.NewNOPFactory().Logger()
			router := &echoRouter{routed: make(chan adapter.InboundContext, 8)}
			key := base64.StdEncoding.EncodeToString(make([]byte, 32))
			port := dualPort(t)
			opts := option.SSPlusInboundOptions{IVKey: key, Users: []option.SSPlusUser{{UserID: 1, Key: key}}, ListenOptions: option.ListenOptions{ListenPort: uint16(port)}}
			in, err := NewInbound(ctx, router, logger, "native", opts)
			if err != nil {
				t.Fatal(err)
			}
			if err = in.Start(adapter.StartStateStart); err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			if mode == "blocked" {
				in.(*Inbound).listener.UDPConn().Close()
			}
			out, err := NewOutbound(ctx, nil, logger, "native", option.SSPlusOutboundOptions{IVKey: key, Key: key, UserID: 1, ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(port)}})
			if err != nil {
				t.Fatal(err)
			}
			h := out.(*Outbound)
			dials := &policyDialer{Dialer: h.dialer}
			h.dialer = dials
			for attempt := 0; attempt < 2; attempt++ {
				conn, err := out.ListenPacket(ctx, M.ParseSocksaddr("1.1.1.1:53"))

				if err != nil {
					t.Fatal(err)
				}
				_, native := conn.(*ssplus.NativeConn)
				if native != (mode == "native") {
					t.Fatal("wrong UDP transport")
				}
				if mode == "blocked" && (dials.udp.Load() != 1 || h.nativeRetry.Load() == 0) {
					t.Fatal("missing cooldown")
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte("test"), 1000)
				if _, err = conn.WriteTo(payload, M.ParseSocksaddr("example.com:53")); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, 8000)
				n, addr, err := conn.ReadFrom(response)
				conn.Close()
				if err != nil || !bytes.Equal(response[:n], payload) || addr.String() != "example.com:53" {
					t.Fatalf("roundtrip: %d %v", n, err)
				}
				<-router.routed
			}

			if mode == "blocked" {
				h.nativeRetry.Store(time.Now().Add(-time.Second).UnixNano())
				conn, err := out.ListenPacket(ctx, M.ParseSocksaddr("1.1.1.1:53"))
				if err != nil {
					t.Fatal(err)
				}
				conn.Close()
				if dials.udp.Load() != 2 {
					t.Fatal("native was not retried after cooldown")
				}
			}
		})
	}
}

func TestNativePaddingOptions(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, limit := range []int{-1, 0, 15, 31, 32} {
		opts := option.SSPlusOutboundOptions{UDPPadding: &limit, IVKey: key, Key: key, UserID: 1, ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 12345}}
		_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "padding", opts)
		valid := limit >= 0 && limit <= 31
		if (err == nil) != valid {
			t.Fatalf("outbound padding %d: %v", limit, err)
		}
		in, err := NewInbound(context.Background(), &echoRouter{}, log.NewNOPFactory().Logger(), "padding", option.SSPlusInboundOptions{UDPPadding: &limit, IVKey: key, Users: []option.SSPlusUser{{UserID: 1, Key: key}}})
		if (err == nil) != valid {
			t.Fatalf("inbound padding %d: %v", limit, err)
		}
		if err == nil {
			in.Close()
		}
	}
}

func dualPort(t testing.TB) int {
	t.Helper()
	for i := 0; i < 100; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		tcp.Close()
		if err == nil {
			udp.Close()
			return port
		}
	}
	t.Fatal("no available TCP/UDP port")
	return 0
}
