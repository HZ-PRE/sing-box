package ssplus

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func shapedConfig(t testing.TB, method string) *Config {
	c := configFor(t, method)
	c.EnableFixedObfuscation()
	return c
}

func shapedFlight(t testing.TB, c *Config, user User) []byte {
	first, _ := firstFlight(t, c, user)
	raw := &memoryConn{}
	w := &tlsShapeConn{Conn: raw, client: true}
	if _, err := w.Write(first); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(raw.output.Bytes())
}

func TestTLSShapeRoundTrip(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, padding := range []string{"initial", "light", "off"} {
			t.Run(method+"/"+padding, func(t *testing.T) {
				cfg := shapedConfig(t, method)
				_ = cfg.SetPadding(padding, 1024)
				u := User{ID: 1, Key: testKey(2)}
				client, _ := NewClient(cfg, u)
				server, _ := NewServer(cfg, []User{u})
				a, b := peerPair(t, client, server)
				done := make(chan error, 1)
				go func() { _, err := io.Copy(b, b); done <- err }()
				for _, n := range []int{1, 64, 1200, 16382, 16384, 65536} {
					p, reply := bytes.Repeat([]byte{byte(n)}, n), make([]byte, n)
					written := make(chan error, 1)
					go func() { _, err := a.Write(p); written <- err }()
					if _, err := io.ReadFull(a, reply); err != nil || !bytes.Equal(p, reply) {
						t.Fatal("roundtrip", err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
				}
				a.Close()
				b.Close()
				<-done
			})
		}
	}
}

func TestTLSShapeSilentFailuresReplayAndDowngrade(t *testing.T) {
	c := shapedConfig(t, "")
	s, _ := NewServer(c, []User{{ID: 1, Key: testKey(2)}})
	check := func(p []byte, response bool) {
		t.Helper()
		raw := &memoryConn{input: bytes.NewReader(p)}
		conn, dest, user, err := s.Accept(raw)
		if err == nil || conn != nil || dest.IsValid() || user.ID != 0 {
			t.Fatal("unauthenticated destination escaped")
		}
		if (raw.output.Len() > 0) != response {
			t.Fatal("unexpected external behavior")
		}
		if len(s.pending) != 0 {
			t.Fatal("admission slot leaked")
		}
	}
	for _, u := range []User{{ID: 1, Key: testKey(9)}, {ID: 99, Key: testKey(2)}, {ID: 1, Key: testKey(2), KeyID: 77}} {
		check(shapedFlight(t, c, u), false)
	}
	first := shapedFlight(t, c, User{ID: 1, Key: testKey(2)})
	for _, n := range []int{0, 1, 4, 5, 43, 75, len(first) - 1} {
		check(first[:n], false)
	}
	bad := bytes.Clone(first)
	bad[len(bad)-1] ^= 1
	check(bad, false)
	bad = bytes.Clone(first)
	bad[3], bad[4] = 255, 255
	check(bad, false)
	check(first, true)  // A valid first flight still cannot release a destination.
	check(first, false) // Replay is silent.
	plain := configFor(t, "")
	flight, _ := firstFlight(t, plain, User{ID: 1, Key: testKey(2)})
	check(flight, false)
	// Rewrapping a plain-mode handshake cannot cross the Noise domain boundary.
	raw := &memoryConn{}
	_, _ = (&tlsShapeConn{Conn: raw, client: true}).Write(flight)
	check(raw.output.Bytes(), false)
	ps, _ := NewServer(plain, []User{{ID: 1, Key: testKey(2)}})
	raw = &memoryConn{input: bytes.NewReader(first)}
	if _, _, _, err := ps.Accept(raw); err == nil || raw.output.Len() != 0 {
		t.Fatal("TLS to plain downgrade")
	}
}

func TestTLSShapeRotation(t *testing.T) {
	c := shapedConfig(t, "")
	u := User{ID: 1, Key: testKey(3), PreviousKey: testKey(2), PreviousValidUntil: time.Now().Add(time.Minute).Unix()}
	s, _ := NewServer(c, []User{u})
	for _, key := range []string{u.Key, u.PreviousKey} {
		client, _ := NewClient(c, User{ID: 1, Key: key})
		a, b := peerPair(t, client, s)
		a.Close()
		b.Close()
	}
	u.PreviousValidUntil = time.Now().Unix()
	if err := s.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	p := shapedFlight(t, c, User{ID: 1, Key: testKey(2)})
	raw := &memoryConn{input: bytes.NewReader(p)}
	if _, _, _, err := s.Accept(raw); err == nil || raw.output.Len() != 0 {
		t.Fatal("expired key accepted")
	}
}

func TestTLSShapeRecordBoundsAndPoison(t *testing.T) {
	for _, header := range [][]byte{{23, 3, 3, 0, 0}, {23, 3, 3, 255, 255}, {22, 3, 3, 0, 1}, {23, 3, 1, 0, 1}} {
		raw := &memoryConn{input: bytes.NewReader(append(header, 0))}
		c := &tlsShapeConn{Conn: raw, readStep: 2}
		var p [1]byte
		if _, err := c.Read(p[:]); err == nil {
			t.Fatal("bad record accepted")
		}
		raw.input = bytes.NewReader([]byte{23, 3, 3, 0, 1, 42})
		if _, err := c.Read(p[:]); err == nil {
			t.Fatal("failed stream revived")
		}
	}
	// TLS record fragmentation/coalescing must preserve the SSPlus byte stream.
	p := bytes.Repeat([]byte{42}, 65536)
	raw := &memoryConn{}
	w := &tlsShapeConn{Conn: raw, writeStep: 2}
	if n, err := w.Write(p); err != nil || n != len(p) {
		t.Fatal(err)
	}
	r := &tlsShapeConn{Conn: &memoryConn{input: bytes.NewReader(raw.output.Bytes())}, readStep: 2}
	got := make([]byte, len(p))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(p, got) {
		t.Fatal(err)
	}
}

func TestTLSShapeStandardParserAndActiveProbe(t *testing.T) {
	c := shapedConfig(t, "")
	first := shapedFlight(t, c, User{ID: 1, Key: testKey(2)})
	// Independent Go TLS parser must recognize the complete ClientHello grammar.
	parsed := false
	stop := errors.New("parsed hello; stop before certificate selection")
	raw := &memoryConn{input: bytes.NewReader(first)}
	_ = tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			parsed = len(hello.CipherSuites) == 4 && len(hello.SupportedCurves) == 2
			return nil, stop
		}}).Handshake()
	if !parsed {
		t.Fatal("standard TLS parser did not recognize ClientHello")
	}
	// A real TLS client cannot complete TLS with this service. It is a carrier,
	// not HTTPS; a scanner can distinguish the silent close from a real website.
	s, _ := NewServer(c, []User{{ID: 1, Key: testKey(2)}})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, _, _, err := s.Accept(b); done <- err }()
	err := tls.Client(a, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}).HandshakeContext(context.Background())
	if err == nil || <-done == nil {
		t.Fatal("unexpected real TLS acceptance")
	}
	t.Log("Go TLS ClientHello parser: recognized; real TLS handshake: rejected (expected limitation)")
	if dir := os.Getenv("SSPLUS_OBFS_EVIDENCE"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "clienthello.bin"), first, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTLSShapeHelloDiversity(t *testing.T) {
	c := shapedConfig(t, "")
	lengths := map[int]bool{}
	sessions := map[string]bool{}
	for i := 0; i < 128; i++ {
		// Use real client handshake padding, not a synthetic fixed-size ticket.
		pad, err := c.helloPadding(c.newPaddingAllowance())
		if err != nil {
			t.Fatal(err)
		}
		p, err := shapeHello(1, bytes.Repeat([]byte{byte(i)}, 32), make([]byte, IVSize+48+len(pad)))
		if err != nil {
			t.Fatal(err)
		}
		sid, _, err := parseShapeHello(p[5:], 1)
		if err != nil {
			t.Fatal(err)
		}
		lengths[len(p)] = true
		sessions[string(sid)] = true
	}
	if len(lengths) < 3 || len(sessions) != 128 {
		t.Fatal("fixed hello length/session")
	}
}

func FuzzTLSShapeHello(f *testing.F) {
	p, _ := shapeHello(1, make([]byte, 32), make([]byte, IVSize+48))
	f.Add(p)
	f.Add([]byte{22, 3, 1, 255, 255})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 4096 {
			return
		}
		if len(p) >= 5 {
			_, _, _ = parseShapeHello(p[5:], 1)
			_, _, _ = parseShapeHello(p[5:], 2)
		}
		c := &tlsShapeConn{Conn: &memoryConn{input: bytes.NewReader(p)}}
		var b [1024]byte
		_, _ = c.Read(b[:])
		if c.readErr == nil && len(c.pending) > IVSize+2+maxNoiseMessage {
			t.Fatal("unbounded pending")
		}
	})
}

func TestTLSShapeHandshakeLengths(t *testing.T) {
	p, _ := shapeHello(1, make([]byte, 32), make([]byte, IVSize+48))
	if int(binary.BigEndian.Uint16(p[3:])) != len(p)-5 {
		t.Fatal("outer length")
	}
	if int(binary.BigEndian.Uint16(p[7:])) != len(p)-9 {
		t.Fatal("handshake length")
	}
}
