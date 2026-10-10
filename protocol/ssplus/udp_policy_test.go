package ssplus

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/ssplus"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type policyDialer struct {
	N.Dialer
	udp   atomic.Int32
	tcp   atomic.Int32
	onUDP func() error
}

func TestUnknownNativeProbeCoalesced(t *testing.T) {
	ctx := context.Background()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	logger := log.NewNOPFactory().Logger()
	port := uint16(dualPort(t))
	in, err := NewInbound(ctx, &echoRouter{routed: make(chan adapter.InboundContext, 32)}, logger, "probe", option.SSPlusInboundOptions{IVKey: key, Users: []option.SSPlusUser{{UserID: 1, Key: key}}, ListenOptions: option.ListenOptions{ListenPort: port}})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err = in.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	out, err := NewOutbound(ctx, nil, logger, "probe", option.SSPlusOutboundOptions{IVKey: key, Key: key, UserID: 1, ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port}})
	if err != nil {
		t.Fatal(err)
	}
	h := out.(*Outbound)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	d := &policyDialer{Dialer: h.dialer, onUDP: func() error { once.Do(func() { close(entered) }); <-release; return errors.New("blocked") }}
	h.dialer = d
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	first := make(chan error, 1)
	go func() {
		conn, err := h.ListenPacket(ctx, M.ParseSocksaddr("example.com:53"))
		if conn != nil {
			conn.Close()
		}
		first <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for i := 0; i < 8; i++ {
		conn, err := h.ListenPacket(ctx, M.ParseSocksaddr("example.com:53"))
		if err != nil {
			close(release)
			t.Fatal(err)
		}
		conn.Close()
	}
	close(release)
	if err = <-first; err != nil {
		t.Fatal(err)
	}
	if d.udp.Load() != 1 {
		t.Fatalf("duplicate probes: %d", d.udp.Load())
	}
	h.InterfaceUpdated()
	if h.nativeRetry.Load() != 0 || h.nativeKnown.Load() {
		t.Fatal("network change retained capability state")
	}
}

func (d *policyDialer) DialContext(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		d.udp.Add(1)
		if d.onUDP != nil {
			return nil, d.onUDP()
		}
	} else {
		d.tcp.Add(1)
	}
	return d.Dialer.DialContext(ctx, network, target)
}

func TestForcedUOTAndCancellation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	router := &echoRouter{routed: make(chan adapter.InboundContext, 8)}
	port := uint16(dualPort(t))
	in, err := NewInbound(ctx, router, logger, "policy", option.SSPlusInboundOptions{IVKey: key, Users: []option.SSPlusUser{{UserID: 1, Key: key}}, ListenOptions: option.ListenOptions{ListenPort: port}})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err = in.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint8{1, 2} {
		for _, forced := range []bool{false, true} {
			opts := option.SSPlusOutboundOptions{IVKey: key, Key: key, UserID: 1, ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port}, UDPOverTCP: &option.UDPOverTCPOptions{Enabled: forced, Version: version}}
			out, err := NewOutbound(ctx, nil, logger, "policy", opts)
			if err != nil {
				t.Fatal(err)
			}
			h := out.(*Outbound)
			d := &policyDialer{Dialer: h.dialer}
			h.dialer = d
			// Simulate native network failure without consuming application payload.
			d.onUDP = func() error { return errors.New("UDP blocked") }
			target := M.ParseSocksaddr("example.com:53")
			conn, err := out.ListenPacket(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err = conn.WriteTo([]byte("policy"), target); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 16)
			n, addr, err := conn.ReadFrom(got)
			conn.Close()
			if err != nil || string(got[:n]) != "policy" || addr.String() != target.String() {
				t.Fatal("UoT echo failed", err)
			}
			if forced && (d.udp.Load() != 0 || d.tcp.Load() != 1 || h.nativeRetry.Load() != 0) {
				t.Fatal("forced UoT attempted native")
			}
			if !forced && (d.udp.Load() != 1 || d.tcp.Load() != 2 || h.nativeRetry.Load() == 0) {
				t.Fatal("fallback not attempted")
			}
			if !forced {
				// A recovered UDP path is tried after the cooldown expires.
				d.onUDP = nil
				h.nativeRetry.Store(time.Now().Add(-time.Second).UnixNano())
				recovered, err := out.ListenPacket(ctx, target)
				if err != nil {
					t.Fatal(err)
				}
				_, native := recovered.(*ssplus.NativeConn)
				recovered.Close()
				if !native || d.udp.Load() != 2 {
					t.Fatal("recovered UDP path not selected")
				}
			}
		}
	}
	for _, version := range []uint8{3, 255} {
		_, err := NewOutbound(ctx, nil, logger, "invalid", option.SSPlusOutboundOptions{IVKey: key, Key: key, UserID: 1, UDPOverTCP: &option.UDPOverTCPOptions{Version: version}})
		if err == nil {
			t.Fatal("invalid version accepted")
		}
	}
	out, err := NewOutbound(ctx, nil, logger, "cancel", option.SSPlusOutboundOptions{IVKey: key, Key: key, UserID: 1, ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: port}})
	if err != nil {
		t.Fatal(err)
	}
	h := out.(*Outbound)
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d := &policyDialer{Dialer: h.dialer, onUDP: func() error { cancel(); return context.Canceled }}
	h.dialer = d
	if conn, err := out.ListenPacket(cancelCtx, M.ParseSocksaddr("example.com:53")); !errors.Is(err, context.Canceled) {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("cancellation lost", err)
	}
	if d.tcp.Load() != 1 || h.nativeRetry.Load() != 0 {
		t.Fatal("cancellation triggered fallback or cooldown")
	}
}

func TestUOTConcurrentDatagrams(t *testing.T) {
	for _, version := range []uint8{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(5 * time.Second))
			right.SetDeadline(time.Now().Add(5 * time.Second))
			target := M.ParseSocksaddr("example.com:53")
			conn, err := (&uot.Client{Version: version}).DialEarlyConn(left, false, target)
			if err != nil {
				t.Fatal(err)
			}
			packets := &packetConn{Conn: conn}
			const count = 32
			writes := make(chan error, count)
			for i := 0; i < count; i++ {
				go func(i int) {
					_, err := packets.WriteTo(bytes.Repeat([]byte{byte(i)}, 1200), target)
					writes <- err
				}(i)
			}
			request := uot.Request{}
			if version == 2 {
				parsed, err := uot.ReadRequest(right)
				if err != nil {
					t.Fatal(err)
				}
				request = *parsed
			}
			server := &packetConn{Conn: uot.NewConn(right, request)}
			seen := make(map[byte]bool)
			for i := 0; i < count; i++ {
				payload := make([]byte, 1200)
				n, addr, err := server.ReadFrom(payload)
				if err != nil || n != len(payload) || addr.String() != target.String() {
					t.Fatal("invalid concurrent frame", n, addr, err)
				}
				id := payload[0]
				if seen[id] || id >= count || !bytes.Equal(payload, bytes.Repeat([]byte{id}, 1200)) {
					t.Fatal("datagram frames interleaved")
				}
				seen[id] = true
			}
			for i := 0; i < count; i++ {
				if err := <-writes; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
