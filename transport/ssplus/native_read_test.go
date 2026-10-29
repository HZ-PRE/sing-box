package ssplus

import (
	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"
)

func TestNativeReadPacketReleasesShortBuffer(t *testing.T) {
	a, z := net.Pipe()
	defer z.Close()
	budget := &nativeBudget{limit: 128}
	c := newNativeConn(nativeTestConfig(t, "aes-256-gcm"), a, make([]byte, 48), true, budget)
	defer c.Close()
	budget.take(3)
	c.queue <- nativeMessage{data: []byte("abc"), address: M.ParseSocksaddr("1.1.1.1:53")}
	b := B.NewSize(1)
	defer b.Release()
	if _, err := c.ReadPacket(b); err != io.ErrShortBuffer {
		t.Fatal(err)
	}
	if budget.used.Load() != 0 {
		t.Fatal("queue reservation leaked")
	}
}

func BenchmarkNativeReadPacket(b *testing.B) {
	for _, deadline := range []bool{false, true} {
		name := "no-deadline"
		if deadline {
			name = "deadline"
		}
		b.Run(name, func(b *testing.B) {
			a, z := net.Pipe()
			defer z.Close()
			budget := &nativeBudget{limit: 128}
			c := newNativeConn(nativeTestConfig(b, "aes-256-gcm"), a, make([]byte, 48), true, budget)
			defer c.Close()
			if deadline {
				c.SetReadDeadline(time.Now().Add(time.Hour))
			}
			packet := B.NewSize(128)
			defer packet.Release()
			message := nativeMessage{data: make([]byte, 64), address: M.ParseSocksaddr("1.1.1.1:53")}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				budget.take(64)
				c.queue <- message
				packet.Reset()
				if _, err := c.ReadPacket(packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
