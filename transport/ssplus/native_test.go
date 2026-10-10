package ssplus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func nativeTestConfig(t testing.TB, method string) *Config {
	t.Helper()
	c, err := NewConfig(method, "origin", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func nativeTestCiphers(t testing.TB, method string) (nativeCipher, nativeCipher) {
	c := nativeTestConfig(t, method)
	var id [16]byte
	id[0] = 42
	seed := make([]byte, 48)
	copy(seed, id[:])
	return newNativeCipher(c, seed, "request"), newNativeCipher(c, seed, "request")
}

func TestNativeCipherAuthenticationReplay(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			tx, rx := nativeTestCiphers(t, method)
			packets := make([][]byte, 1100)
			for i := range packets {
				p, err := tx.seal(make([]byte, 0, nativeMTU), []byte("payload"))
				if err != nil {
					t.Fatal(err)
				}
				packets[i] = p
			}
			for _, index := range []int{100, 0, 99, 50, 1099, 1000} {
				bad := bytes.Clone(packets[index])
				bad[len(bad)-1] ^= 1
				if _, _, err := rx.open(nil, bad); err == nil {
					t.Fatal("tampering accepted")
				}
				p, _, err := rx.open(nil, packets[index])
				if err != nil || string(p) != "payload" {
					t.Fatal(err)
				}
				if _, _, err = rx.open(nil, packets[index]); err == nil {
					t.Fatal("replay accepted")
				}
			}
			if _, _, err := rx.open(nil, packets[1]); err == nil {
				t.Fatal("stale packet accepted")
			}
			bad := bytes.Clone(packets[1098])
			bad[nativeCIDOffset] ^= 1
			if _, _, err := rx.open(nil, bad); err == nil {
				t.Fatal("wrong session accepted")
			}
			tx.seq = math.MaxUint64
			if _, err := tx.seal(make([]byte, 0, nativeMTU), []byte{1}); err == nil {
				t.Fatal("nonce wrapped")
			}
		})
	}
}

func nativeFragments(data []byte, id uint64) [][]byte {
	var packets [][]byte
	for offset, index := 0, 0; offset < len(data); index++ {
		n := min(nativeFragment, len(data)-offset)
		p := make([]byte, max(32, 14+n))
		p[0] = nativeData
		binary.BigEndian.PutUint64(p[1:], id)
		binary.BigEndian.PutUint32(p[9:], uint32(len(data)))
		p[13] = byte(index)
		copy(p[14:], data[offset:])
		packets = append(packets, p)
		offset += n
	}
	return packets
}
func TestNativeReassemblyLossReorderLimits(t *testing.T) {
	now := time.Now()
	budget := &nativeBudget{limit: 512 * 1024}
	a := nativeAssembler{budget: budget}
	data := bytes.Repeat([]byte{37}, 65507)
	packets := nativeFragments(data, 10)
	for i := len(packets) - 1; i >= 0; i-- {
		result := a.feed(packets[i], 10+uint64(i), now)
		if i > 0 && result != nil {
			t.Fatal("partial message delivered")
		}
		if i == 0 {
			if !bytes.Equal(result, data) {
				t.Fatal("reassembly mismatch")
			}
			budget.release(len(result))
		}
	}
	if budget.used.Load() != 0 {
		t.Fatal("budget leak")
	}
	for id := uint64(100); id < 1000; id += 100 {
		a.feed(nativeFragments(data, id)[0], id, now)
	}
	if a.bytes > 256*1024 || len(a.partial) > 8 {
		t.Fatal("unbounded reassembly")
	}
	// A lost large datagram never blocks a later independent message.
	small := []byte("small")
	result := a.feed(nativeFragments(small, 2000)[0], 2000, now)
	if !bytes.Equal(result, small) {
		t.Fatal("head of line blocking")
	}
	budget.release(len(result))
	a.expire(now.Add(nativeFragmentTTL))
	if budget.used.Load() != 0 {
		t.Fatal("expiry leak")
	}
	p := nativeFragments(data, 3000)[0]
	binary.BigEndian.PutUint32(p[9:], math.MaxUint32)
	if a.feed(p, 3000, now) != nil || budget.used.Load() != 0 {
		t.Fatal("oversize accepted")
	}
}

// Uses real UDP sockets; the control pipe represents the authenticated stream.
func nativePair(t *testing.T, method string) (*NativeConn, *NativeConn, *NativeService) {
	return nativePairLimit(t, method, nativeMaxMTU)
}

func nativePairLimit(t *testing.T, method string, maxPacket int) (*NativeConn, *NativeConn, *NativeService) {
	t.Helper()
	config := nativeTestConfig(t, method)
	s := (&Server{config: config}).NewNativeService()
	t.Cleanup(func() { s.Close() })
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	if err := udp.(*net.UDPConn).SetReadBuffer(256 * 1024); err != nil {
		t.Fatal(err)
	}
	go func() {
		var p [nativeMaxMTU + 1]byte
		for {
			n, addr, err := udp.ReadFrom(p[:])
			if err != nil {
				return
			}
			if n > maxPacket {
				continue
			}
			s.Receive(p[:n], addr.String(), func(b []byte) error { _, err := udp.WriteTo(b, addr); return err })
		}
	}()
	raw, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	accepted := make(chan *NativeConn, 1)
	go func() {
		p, err := s.Accept(b)
		if err == nil {
			accepted <- p
		}
	}()
	client := &Client{config: config}
	p, err := client.OpenNative(context.Background(), a, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, <-accepted, s
}
func TestNativeSocketRoundtripAndCleanup(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			client, server, hub := nativePair(t, method)
			client.SetDeadline(time.Now().Add(5 * time.Second))
			server.SetDeadline(time.Now().Add(5 * time.Second))
			for _, size := range []int{0, 1, 1000, 1200, 4096, 65507} {
				payload := bytes.Repeat([]byte{byte(size)}, size)
				target := M.ParseSocksaddr("example.com:53")
				if n, err := client.WriteTo(payload, target); err != nil || n != size {
					t.Fatalf("write %d: %d %v", size, n, err)
				}
				buffer := make([]byte, 65535)
				n, address, err := server.ReadFrom(buffer)
				if err != nil || n != size || !bytes.Equal(buffer[:n], payload) {
					t.Fatalf("server read %d: %d %v", size, n, err)
				}
				if address.String() != target.String() {
					t.Fatal("target mismatch")
				}
				if _, err = server.WriteTo(buffer[:n], address); err != nil {
					t.Fatal(err)
				}
				n, _, err = client.ReadFrom(buffer)
				if err != nil || n != size || !bytes.Equal(buffer[:n], payload) {
					t.Fatalf("client read %d: %d %v", size, n, err)
				}
			}
			if _, err := client.WriteTo(make([]byte, 65508), M.ParseSocksaddr("1.1.1.1:53")); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			if _, _, err := client.ReadFrom(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
			client.SetReadDeadline(time.Time{})
			done := make(chan error, 1)
			go func() { _, _, err := client.ReadFrom(make([]byte, 8)); done <- err }()
			client.Close()
			select {
			case err := <-done:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked close")
			}
			hub.Close()
			if hub.budget.used.Load() != 0 {
				t.Fatal("retained packet memory")
			}
		})
	}
}

func TestNativePathValidationAndMigration(t *testing.T) {
	config := nativeTestConfig(t, "aes-256-gcm")
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	seed := make([]byte, 48)
	seed[0] = 7
	s := newNativeConn(config, b, seed, false, &nativeBudget{limit: 512 * 1024})
	s.hub = &NativeService{sessions: make(map[[16]byte]*NativeConn)}
	defer s.Close()
	c := newNativeConn(config, a, seed, true, &nativeBudget{limit: 512 * 1024})
	var response []byte
	reply := func(p []byte) error { response = bytes.Clone(p); return nil }
	send := func(packet []byte, source string) {
		response = nil
		s.receive(packet, source, reply)
		if len(response) > len(packet) {
			t.Fatal("path validation amplified packet")
		}
	}
	makeControl := func(kind byte, token []byte) []byte {
		p := make([]byte, 32)
		p[0] = kind
		copy(p[1:], token)
		wire, err := c.tx.seal(make([]byte, 0, nativeMTU), p)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	send(makeControl(nativeProbe, nil), "old")
	plain, _, err := c.rx.open(nil, response)
	if err != nil || plain[0] != nativeChallenge {
		t.Fatal("missing challenge", err)
	}
	if s.source != "" {
		t.Fatal("unvalidated path bound")
	}
	send(makeControl(nativeConfirm, plain[1:17]), "old")
	if s.source != "old" {
		t.Fatal("not bound")
	}
	send(makeControl(nativeProbe, nil), "new")
	plain, _, err = c.rx.open(nil, response)
	if err != nil {
		t.Fatal(err)
	}
	send(makeControl(nativeConfirm, make([]byte, 16)), "new")
	if s.source != "old" {
		t.Fatal("invalid token migrated")
	}
	send(makeControl(nativeConfirm, plain[1:17]), "new")
	if s.source != "new" {
		t.Fatal("valid migration rejected")
	}
}

func TestNativeConcurrentCloseAndDeadlines(t *testing.T) {
	c, s, h := nativePair(t, "aes-256-gcm")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c.SetReadDeadline(time.Now())
				c.WriteTo([]byte("x"), M.ParseSocksaddr("1.1.1.1:53"))
				s.ReadFrom(make([]byte, 8))
				s.SetReadDeadline(time.Now())
			}
		}()
	}
	s.SetReadDeadline(time.Now())
	c.Close()
	s.Close()
	h.Close()
	wg.Wait()
}

func FuzzNativeDatagram(f *testing.F) {
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, nativeMTU))
	tx, _ := nativeTestCiphers(f, "aes-256-gcm")
	packet, err := tx.seal(nil, nativeFragments([]byte("seed"), 1)[0])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(packet)
	f.Fuzz(func(t *testing.T, p []byte) {
		_, rx := nativeTestCiphers(t, "aes-256-gcm")
		rx.open(nil, p)
		a := nativeAssembler{budget: &nativeBudget{limit: 256 * 1024}}
		if data := a.feed(p, 1, time.Now()); data != nil {
			a.budget.release(len(data))
		}
		a.clear()
		if a.budget.used.Load() != 0 {
			t.Fatal("budget leak")
		}
	})
}

func BenchmarkNativeWrite(b *testing.B) {
	for _, size := range []int{64, 1200, 65507} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			config := nativeTestConfig(b, "chacha20-ietf-poly1305")
			a, z := net.Pipe()
			defer a.Close()
			defer z.Close()
			c := newNativeConn(config, a, make([]byte, 48), true, &nativeBudget{limit: 512 * 1024})
			defer c.Close()
			c.reply = func([]byte) error { return nil }
			payload := make([]byte, size)
			target := M.ParseSocksaddr("1.1.1.1:53")
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.WriteTo(payload, target); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
