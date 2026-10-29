package ssplus_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/sagernet/sing-box/transport/ssplus"
	M "github.com/sagernet/sing/common/metadata"
)

func compareKey(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
func compareConfig(b testing.TB, method, padding string) *wire.Config {
	c, e := wire.NewConfig(method, compareKey(1))
	if e != nil {
		b.Fatal(e)
	}
	if e = c.SetPadding(padding, 1024); e != nil {
		b.Fatal(e)
	}
	c.EnableFixedObfuscation()
	return c
}

type compareCountConn struct {
	net.Conn
	written atomic.Int64
}

func (c *compareCountConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, e
}
func comparePair(b testing.TB, c *wire.Client, s *wire.Server) (net.Conn, net.Conn, *compareCountConn, *compareCountConn) {
	a, z := net.Pipe()
	ac, zc := &compareCountConn{Conn: a}, &compareCountConn{Conn: z}
	a.SetDeadline(time.Now().Add(time.Minute))
	z.SetDeadline(time.Now().Add(time.Minute))
	type result struct {
		c net.Conn
		e error
	}
	done := make(chan result, 1)
	go func() { c, _, _, e := s.Accept(zc); done <- result{c, e} }()
	client, e := c.DialConn(ac, M.ParseSocksaddr("example.com:443"))
	if e != nil {
		a.Close()
		z.Close()
		b.Fatal(e)
	}
	r := <-done
	if r.e != nil {
		a.Close()
		z.Close()
		b.Fatal(r.e)
	}
	return client, r.c, ac, zc
}
func BenchmarkV2CompareHandshake(b *testing.B) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, padding := range []string{"initial", "off"} {
			b.Run(method+"/"+padding, func(b *testing.B) {
				cfg := compareConfig(b, method, padding)
				u := wire.User{ID: 1, Key: compareKey(2)}
				client, e := wire.NewClient(cfg, u)
				if e != nil {
					b.Fatal(e)
				}
				server, e := wire.NewServer(cfg, []wire.User{u})
				if e != nil {
					b.Fatal(e)
				}
				var size int64
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					a, z, ac, zc := comparePair(b, client, server)
					size += ac.written.Load() + zc.written.Load()
					a.Close()
					z.Close()
				}
				b.StopTimer()
				b.ReportMetric(float64(size)/float64(b.N), "wire-B/handshake")
			})
		}
	}
}
func BenchmarkV2CompareStream(b *testing.B) {
	for _, size := range []int{64, 1200, 32768} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			cfg := compareConfig(b, "aes-256-gcm", "initial")
			u := wire.User{ID: 1, Key: compareKey(2)}
			client, _ := wire.NewClient(cfg, u)
			server, _ := wire.NewServer(cfg, []wire.User{u})
			a, z, ac, zc := comparePair(b, client, server)
			defer a.Close()
			defer z.Close()
			echo := make(chan error, 1)
			go func() { _, e := io.Copy(z, z); echo <- e }()
			payload, reply := make([]byte, size), make([]byte, size)
			// Start traffic after the optional initial padding budget is exhausted.
			warm := make(chan error, 1)
			go func() {
				for i := 0; i < 16; i++ {
					if _, e := a.Write(payload); e != nil {
						warm <- e
						return
					}
				}
				warm <- nil
			}()
			for i := 0; i < 16; i++ {
				if _, e := io.ReadFull(a, reply); e != nil {
					b.Fatal(e)
				}
			}
			if e := <-warm; e != nil {
				b.Fatal(e)
			}
			start := ac.written.Load() + zc.written.Load()
			done := make(chan error, 1)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			go func() {
				for i := 0; i < b.N; i++ {
					if _, e := a.Write(payload); e != nil {
						done <- e
						return
					}
				}
				done <- nil
			}()
			for i := 0; i < b.N; i++ {
				if _, e := io.ReadFull(a, reply); e != nil {
					b.Fatal(e)
				}
			}
			if e := <-done; e != nil {
				b.Fatal(e)
			}
			b.StopTimer()
			b.ReportMetric(float64(ac.written.Load()+zc.written.Load()-start)/float64(b.N), "wire-B/roundtrip")
			a.Close()
			z.Close()
			<-echo
		})
	}
}
