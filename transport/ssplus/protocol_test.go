package ssplus

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	M "github.com/sagernet/sing/common/metadata"
)

func testKey(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
func configFor(t testing.TB, method string) *Config {
	t.Helper()
	c, err := NewConfig(method, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type fragmentedConn struct{ net.Conn }

func (c fragmentedConn) Read(p []byte) (int, error)  { return c.Conn.Read(p[:min(len(p), 13)]) }
func (c fragmentedConn) Write(p []byte) (int, error) { return c.Conn.Write(p[:min(len(p), 17)]) }
func peerPair(t testing.TB, c *Client, s *Server) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, dest, user, err := s.Accept(fragmentedConn{b})
		if err == nil && (dest.String() != "example.com:443" || user.ID != 1 || user.Key != "" || user.PreviousKey != "") {
			err = errors.New("identity or destination mismatch")
		}
		done <- result{conn, err}
	}()
	client, err := c.DialConn(fragmentedConn{a}, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	return client, r.conn
}
func TestV2RoundTrip(t *testing.T) {
	for _, method := range []string{"aes-256-gcm", "chacha20-ietf-poly1305"} {
		for _, mode := range []string{"initial", "light", "off"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				cfg := configFor(t, method)
				_ = cfg.SetPadding(mode, 1024)
				c, _ := NewClient(cfg, User{ID: 1, Key: testKey(2)})
				s, _ := NewServer(cfg, []User{{ID: 1, Key: testKey(2)}})
				client, server := peerPair(t, c, s)
				done := make(chan error, 1)
				go func() {
					_, err := server.Write([]byte("ready"))
					if err == nil {
						_, err = io.Copy(server, server)
					}
					done <- err
				}()
				greeting := make([]byte, 5)
				if _, err := io.ReadFull(client, greeting); err != nil || string(greeting) != "ready" {
					t.Fatal(err)
				}
				for _, size := range []int{1, 64, 1200, 1201, 16382, 65536} {
					p := bytes.Repeat([]byte{byte(size)}, size)
					written := make(chan error, 1)
					go func() { _, err := client.Write(p); written <- err }()
					reply := make([]byte, size)
					if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(p, reply) {
						t.Fatal("payload mismatch", err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
				}
				client.Close()
				<-done
			})
		}
	}
}
func firstFlight(t testing.TB, cfg *Config, user User) ([]byte, *noise.HandshakeState) {
	t.Helper()
	u, err := parseUser(user)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := cfg.makeIV(u.ID, u.KeyID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	hs, err := cfg.handshake(u.key, iv, true)
	if err != nil {
		t.Fatal(err)
	}
	message, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = writeNoise(&out, iv, message); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(hs.LocalEphemeral().Private) })
	return out.Bytes(), hs
}

type memoryConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *memoryConn) Read(p []byte) (int, error)       { return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error)      { return c.output.Write(p) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }
func TestV2SilentFailuresAndBounds(t *testing.T) {
	cfg := configFor(t, "")
	s, _ := NewServer(cfg, []User{{ID: 1, Key: testKey(2)}})
	for _, user := range []User{{ID: 1, Key: testKey(9)}, {ID: 99, Key: testKey(2)}, {ID: 1, KeyID: 77, Key: testKey(2)}} {
		first, _ := firstFlight(t, cfg, user)
		conn := &memoryConn{input: bytes.NewReader(first)}
		if accepted, _, _, err := s.Accept(conn); accepted != nil || !errors.Is(err, ErrAuthentication) || conn.output.Len() != 0 {
			t.Fatal("credential probe answered", err)
		}
	}
	first, _ := firstFlight(t, cfg, User{ID: 1, Key: testKey(2)})
	for _, n := range []int{0, 15, 47, 48, 49, len(first) - 1} {
		conn := &memoryConn{input: bytes.NewReader(first[:n])}
		if _, _, _, err := s.Accept(conn); err == nil || conn.output.Len() != 0 {
			t.Fatal("truncation accepted")
		}
	}
	bad := bytes.Clone(first)
	binary.BigEndian.PutUint16(bad[IVSize:], 65535)
	conn := &memoryConn{input: bytes.NewReader(bad)}
	if _, _, _, err := s.Accept(conn); err == nil || conn.output.Len() != 0 {
		t.Fatal("oversize hello")
	}
	if len(s.pending) != 0 {
		t.Fatal("pending slot leaked")
	}
	// Old protocol version, even correctly node-authenticated, cannot downgrade.
	iv, _ := cfg.makeIV(1, 1, time.Now())
	a := cfg.identityCipher(iv[:16])
	plain, _ := a.Open(nil, make([]byte, 12), iv[16:], iv[:16])
	plain[0] = 1
	a.Seal(iv[16:16], make([]byte, 12), plain, iv[:16])
	if _, _, err := cfg.parseIV(iv, time.Now()); err == nil {
		t.Fatal("v1 accepted")
	}
}
func TestV2ReplayRequiresFreshConfirmation(t *testing.T) {
	cfg := configFor(t, "")
	first, hs := firstFlight(t, cfg, User{ID: 1, Key: testKey(2)})
	s, _ := NewServer(cfg, []User{{ID: 1, Key: testKey(2)}})
	captured := &memoryConn{input: bytes.NewReader(first)}
	if conn, _, _, err := s.Accept(captured); err == nil || conn != nil {
		t.Fatal("first flight admitted without confirmation")
	}
	response, err := readNoise(bytes.NewReader(captured.output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	_, tx, rx, err := hs.ReadMessage(nil, response)
	if err != nil {
		t.Fatal(err)
	}
	outbound := &memoryConn{}
	stream := newStream(outbound, tx, rx, cfg, cfg.newPaddingAllowance())
	var addr bytes.Buffer
	_ = M.SocksaddrSerializer.WriteAddrPort(&addr, M.ParseSocksaddr("example.com:443"))
	_, _ = stream.Write(addr.Bytes())
	replay := append(bytes.Clone(first), outbound.output.Bytes()...)
	// A restarted server has an empty replay cache but a new ephemeral secret.
	fresh, _ := NewServer(cfg, []User{{ID: 1, Key: testKey(2)}})
	if conn, _, _, err := fresh.Accept(&memoryConn{input: bytes.NewReader(replay)}); err == nil || conn != nil {
		t.Fatal("captured transport confirmed a fresh handshake")
	}
	duplicate := &memoryConn{input: bytes.NewReader(first)}
	if _, _, _, err := s.Accept(duplicate); err == nil || duplicate.output.Len() != 0 {
		t.Fatal("cached first flight replay answered")
	}
}
func TestV2Rotation(t *testing.T) {
	cfg := configFor(t, "")
	current := User{ID: 1, Key: testKey(3), PreviousKey: testKey(2), PreviousValidUntil: time.Now().Add(time.Minute).Unix()}
	s, err := NewServer(cfg, []User{current})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{testKey(2), testKey(3)} {
		c, _ := NewClient(cfg, User{ID: 1, Key: key})
		a, b := peerPair(t, c, s)
		a.Close()
		b.Close()
	}
	current.PreviousValidUntil = time.Now().Unix()
	if err = s.UpdateUser(current); err != nil {
		t.Fatal(err)
	}
	first, _ := firstFlight(t, cfg, User{ID: 1, Key: testKey(2)})
	conn := &memoryConn{input: bytes.NewReader(first)}
	if _, _, _, err = s.Accept(conn); err == nil || conn.output.Len() != 0 {
		t.Fatal("expired key admitted")
	}
	c, _ := NewClient(cfg, User{ID: 1, Key: testKey(3)})
	a, b := peerPair(t, c, s)
	a.Close()
	b.Close()
	s.RemoveUser(1)
	first, _ = firstFlight(t, cfg, User{ID: 1, Key: testKey(3)})
	if _, _, _, err = s.Accept(&memoryConn{input: bytes.NewReader(first)}); err == nil {
		t.Fatal("revoked user admitted")
	}
}
func TestV2CredentialValidation(t *testing.T) {
	for _, u := range []User{{ID: 0, Key: testKey(2)}, {ID: 1, Key: "password"}, {ID: 1, Key: testKey(2), PreviousKey: testKey(3)}, {ID: 1, Key: testKey(2), PreviousKey: testKey(2), PreviousValidUntil: 1}, {ID: 1, KeyID: 1, Key: testKey(2), PreviousKeyID: 1, PreviousKey: testKey(3), PreviousValidUntil: 1}} {
		if ValidateUser(u) == nil {
			t.Fatal("invalid key ring", u.ID)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		key, id, err := GenerateKey()
		if err != nil || id == 0 || seen[key] {
			t.Fatal("key generation", err)
		}
		seen[key] = true
		if err = ValidateUser(User{ID: 1, Key: key, KeyID: id}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestV2HandshakeLimits(t *testing.T) {
	cfg := configFor(t, "")
	s, _ := NewServer(cfg, []User{{ID: 1, Key: testKey(2)}})
	for i := 0; i < maxPendingHandshakes; i++ {
		s.pending <- struct{}{}
	}
	if _, _, _, err := s.Accept(&memoryConn{input: bytes.NewReader(nil)}); err == nil {
		t.Fatal("admission limit")
	}
	for i := 0; i < maxPendingHandshakes; i++ {
		<-s.pending
	}
	m := &memoryConn{input: bytes.NewReader(make([]byte, maxHandshakeBytes+1))}
	g := newHandshakeGuard(m, time.Second)
	_, err := io.Copy(io.Discard, g)
	g.finish()
	if !errors.Is(err, errHandshakeLimit) || m.input.Len() != 1 {
		t.Fatal("read cap", err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	g = newHandshakeGuard(b, 10*time.Millisecond)
	if _, err = g.Read(make([]byte, 1)); err == nil || g.finish() {
		t.Fatal("deadline not enforced")
	}
}
func TestV2ConcurrentRotation(t *testing.T) {
	cfg := configFor(t, "")
	s, _ := NewServer(cfg, []User{{ID: 1, Key: testKey(2)}})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				_ = s.UpdateUser(User{ID: 1, Key: testKey(2)})
				s.usersMutex.RLock()
				u := s.users[1]
				_, _ = u.selectKey(u.KeyID, time.Now())
				s.usersMutex.RUnlock()
			}
		}()
	}
	wg.Wait()
}
func FuzzV2IdentityAndHello(f *testing.F) {
	c, _ := NewConfig("", testKey(1))
	iv, _ := c.makeIV(1, 1, time.Now())
	f.Add(iv)
	f.Add([]byte{0, 1})
	f.Fuzz(func(t *testing.T, p []byte) { c.parseIV(p, time.Now()); readNoise(bytes.NewReader(p)) })
}
