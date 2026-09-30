package include_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func TestRetainedProxyTCPAndUDP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp.WriteTo(buffer[:n], addr)
		}
	}()
	for _, kind := range []string{"ssplus", "vless", "vless-xudp", "vless-packetaddr", "local-socks"} {
		t.Run(kind, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			protocol := "vless"
			inbound := `"users":[{"uuid":"00000000-0000-4000-8000-000000000001"}]`
			outbound := `"uuid":"00000000-0000-4000-8000-000000000001","packet_encoding":""`
			if kind == "ssplus" {
				protocol = "ssplus"
				common := `"method":"aes-256-gcm","protocol":"auth_sha1_v4","iv_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
				inbound = common + `,"users":[{"user_id":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}]`
				outbound = common + `,"user_id":1,"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="`
			} else if kind == "vless-xudp" {
				outbound = `"uuid":"00000000-0000-4000-8000-000000000001","packet_encoding":"xudp"`
			} else if kind == "vless-packetaddr" {
				outbound = `"uuid":"00000000-0000-4000-8000-000000000001","packet_encoding":"packetaddr"`
			}
			serverProtocol := protocol
			if kind == "local-socks" {
				protocol = "local-socks"
				serverProtocol = "socks"
				inbound = `"users":[]`
				outbound = `"version":"5"`
			}
			ctx, cancel := context.WithTimeout(include.Context(context.Background()), 15*time.Second)
			defer cancel()
			start := func(raw string) *box.Box {
				var config option.Options
				if err := config.UnmarshalJSONContext(ctx, []byte(raw)); err != nil {
					t.Fatal(err)
				}
				instance, err := box.New(box.Options{Context: ctx, Options: config})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { instance.Close() })
				if err := instance.Start(); err != nil {
					t.Fatal(err)
				}
				return instance
			}
			start(fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":%q,"listen":"127.0.0.1","listen_port":%d,%s}],"outbounds":[{"type":"direct"}]}`, serverProtocol, port, inbound))
			client := start(fmt.Sprintf(`{"log":{"disabled":true},"outbounds":[{"type":%q,"tag":"proxy","server":"127.0.0.1","server_port":%d,%s}]}`, protocol, port, outbound))
			proxy, ok := client.Outbound().Outbound("proxy")
			if !ok {
				t.Fatal("proxy missing")
			}
			for cycle := 0; cycle < 3; cycle++ {
				conn, err := proxy.DialContext(ctx, "tcp", M.ParseSocksaddr(tcp.Addr().String()))
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := []byte("retained-protocol-tcp")
				if _, err = conn.Write(payload); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				_, err = io.ReadFull(conn, got)
				conn.Close()
				if err != nil || string(got) != string(payload) {
					t.Fatalf("TCP echo: %q %v", got, err)
				}
				destination := M.ParseSocksaddr(udp.LocalAddr().String())
				pc, err := proxy.ListenPacket(ctx, destination)
				if err != nil {
					t.Fatal(err)
				}
				pc.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err = pc.WriteTo(payload, destination.UDPAddr()); err != nil {
					pc.Close()
					t.Fatal(err)
				}
				got = make([]byte, 128)
				n, _, err := pc.ReadFrom(got)
				pc.Close()
				if err != nil || string(got[:n]) != string(payload) {
					t.Fatalf("UDP echo: %q %v", got[:n], err)
				}
			}
		})
	}
}
