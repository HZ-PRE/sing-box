package ssplus

import (
	"bytes"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"testing"
	"time"
)

func TestCompactDatagramPacketCount(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		config := nativeTestConfig(t, "aes-256-gcm")
		a, b := net.Pipe()
		tx := newNativeConn(config, a, make([]byte, 48), true, &nativeBudget{limit: 512 * 1024})
		rx := newNativeConn(config, b, make([]byte, 48), false, &nativeBudget{limit: 512 * 1024})
		if enabled {
			tx.pathMTU.Store(nativeMaxMTU)
			rx.pathMTU.Store(nativeMaxMTU)
		}
		packets := 0
		tx.reply = func(packet []byte) error { packets++; rx.receive(packet, "", nil); return nil }
		payload := bytes.Repeat([]byte{7}, 1200)
		if _, err := tx.WriteTo(payload, M.ParseSocksaddr("1.1.1.1:443")); err != nil {
			t.Fatal(err)
		}
		rx.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, 1200)
		n, _, err := rx.ReadFrom(got)
		if err != nil || n != len(payload) || !bytes.Equal(got, payload) {
			t.Fatal(n, err)
		}
		want := 2
		if enabled {
			want = 1
		}
		if packets != want {
			t.Fatalf("compact=%v packets=%d want=%d", enabled, packets, want)
		}
		if rx.assembly.budget.used.Load() != 0 {
			t.Fatal("budget leak")
		}
		tx.Close()
		rx.Close()
	}
}

func TestNativeMTUNegotiationAndFallback(t *testing.T) {
	for _, limit := range []int{nativeMTU, nativeMaxMTU} {
		client, server, _ := nativePairLimit(t, "chacha20-ietf-poly1305", limit)
		deadline := time.Now().Add(time.Second)
		if limit == nativeMaxMTU {
			for client.pathMTU.Load() != nativeMaxMTU && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if client.pathMTU.Load() != nativeMaxMTU || server.pathMTU.Load() != nativeMaxMTU {
				t.Fatal("MTU not validated")
			}
		} else if client.pathMTU.Load() == nativeMaxMTU {
			t.Fatal("unverified large path")
		}
		payload := bytes.Repeat([]byte{5}, 1200)
		if _, err := client.WriteTo(payload, M.ParseSocksaddr("example.com:443")); err != nil {
			t.Fatal(err)
		}
		server.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, 1200)
		n, _, err := server.ReadFrom(got)
		if err != nil || n != 1200 || !bytes.Equal(got, payload) {
			t.Fatal(n, err)
		}
	}
}
