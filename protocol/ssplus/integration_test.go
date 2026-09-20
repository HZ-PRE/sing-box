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

func TestRegisteredLoopbackTCPAndUOT(t *testing.T) {
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
	err := inOptions.UnmarshalJSONContext(ctx, []byte(fmt.Sprintf(`{"type":"ssplus","tag":"ssplus-in","listen":"127.0.0.1","listen_port":0,"protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","iv_key":%q,"users":[{"user_id":7,"name":"alice","key":%q}]}`, ivKey, userKey)))
	if err != nil {
		t.Fatal(err)
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
	for _, version := range []uint8{1, 2} {
		var outOptions option.Outbound
		err = outOptions.UnmarshalJSONContext(ctx, []byte(fmt.Sprintf(`{"type":"ssplus","tag":"ssplus-out","server":"127.0.0.1","server_port":%d,"protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","iv_key":%q,"user_id":7,"key":%q,"udp_over_tcp":{"enabled":true,"version":%d}}`, port, ivKey, userKey, version)))
		if err != nil {
			t.Fatal(err)
		}
		out, err := outRegistry.CreateOutbound(ctx, router, logger, outOptions.Tag, outOptions.Type, outOptions.Options)
		if err != nil {
			t.Fatal(err)
		}
		for _, network := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("v%d/%s", version, network), func(t *testing.T) {
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
		t.Run(fmt.Sprintf("v%d/ListenPacket", version), func(t *testing.T) {
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
				t.Fatal("missing UoT user")
			}
		})
	}
}

func TestOutboundRejectsInvalidUOT(t *testing.T) {
	opts := option.SSPlusOutboundOptions{IVKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Key: base64.StdEncoding.EncodeToString(make([]byte, 32)), UserID: 1}
	opts.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true, Version: 3}
	if _, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", opts); err == nil {
		t.Fatal("accepted unknown UoT version")
	}
	opts.UDPOverTCP.Enabled = false
	opts.UDPOverTCP.Version = 2
	opts.Network = "udp"
	if _, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", opts); err == nil {
		t.Fatal("accepted native UDP")
	}
	opts.Network = ""
	out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "", opts)
	if err != nil {
		t.Fatal(err)
	}
	if networks := out.Network(); len(networks) != 1 || networks[0] != "tcp" {
		t.Fatal("TCP-only outbound advertised UDP")
	}
	if _, err = out.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53")); err == nil {
		t.Fatal("ListenPacket accepted disabled UoT")
	}
}
