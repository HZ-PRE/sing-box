// Package ssplus implements SSPlus v2: Noise NNpsk0 with X25519.
package ssplus

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	IVSize           = 48
	clockWindow      = 2 * time.Minute
	maxReplayEntries = 65536
	maxNoiseMessage  = 512
)

var ErrAuthentication = errors.New("ssplus: authentication failed")

type Config struct {
	tlsShape      bool
	paddingMode   string
	paddingBudget int
	nativePadding int
	method        byte
	ivKey         []byte
	suite         noise.CipherSuite
}

func NewConfig(method, ivKey string) (*Config, error) {
	c := &Config{nativePadding: nativePaddingMax, paddingMode: "initial", paddingBudget: 1024}
	switch method {
	case "", "aes-256-gcm":
		c.method = 1
	case "chacha20-ietf-poly1305":
		c.method = 2
	default:
		return nil, fmt.Errorf("ssplus: unsupported method %q", method)
	}
	var err error
	c.ivKey, err = decodeKey(ivKey)
	if err != nil {
		return nil, fmt.Errorf("ssplus iv_key: %w", err)
	}
	c.suite = noise.NewCipherSuite(noise.DH25519, noiseAEADFunc{c.method}, noise.HashSHA256)
	return c, nil
}

func deriveKey(key, salt []byte, label string) []byte {
	out := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, key, salt, []byte("ssplus/v2/"+label)), out)
	return out
}
func (c *Config) identityCipher(random []byte) cipher.AEAD {
	key := deriveKey(c.ivKey, random, "identity")
	block, _ := aes.NewCipher(key)
	clear(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

// Native UDP uses independent directional secrets delivered inside the PFS stream.
func (c *Config) payloadCipher(key, salt []byte, direction string) cipher.AEAD {
	subkey := deriveKey(key, salt, direction)
	defer clear(subkey)
	if c.method == 2 {
		a, _ := chacha20poly1305.New(subkey)
		return a
	}
	block, _ := aes.NewCipher(subkey)
	a, _ := cipher.NewGCM(block)
	return a
}
func (c *Config) makeIV(id, keyID uint32, now time.Time) ([]byte, error) {
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv[:16]); err != nil {
		return nil, err
	}
	var plain [16]byte
	plain[0], plain[1] = 2, c.method
	binary.BigEndian.PutUint32(plain[4:8], id)
	binary.BigEndian.PutUint32(plain[8:12], keyID)
	if now.Unix() < 0 || now.Unix() > int64(^uint32(0)) {
		return nil, ErrAuthentication
	}
	binary.BigEndian.PutUint32(plain[12:], uint32(now.Unix()))
	a := c.identityCipher(iv[:16])
	a.Seal(iv[16:16], make([]byte, a.NonceSize()), plain[:], iv[:16])
	return iv, nil
}
func (c *Config) parseIV(iv []byte, now time.Time) (uint32, uint32, error) {
	if len(iv) != IVSize {
		return 0, 0, ErrAuthentication
	}
	a := c.identityCipher(iv[:16])
	p, err := a.Open(nil, make([]byte, a.NonceSize()), iv[16:], iv[:16])
	if err != nil || len(p) != 16 || p[0] != 2 || p[1] != c.method || p[2] != 0 || p[3] != 0 {
		return 0, 0, ErrAuthentication
	}
	ts := int64(binary.BigEndian.Uint32(p[12:]))
	id, kid := binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint32(p[8:])
	if id == 0 || kid == 0 || ts < now.Add(-clockWindow).Unix() || ts > now.Add(clockWindow).Unix() {
		return 0, 0, ErrAuthentication
	}
	return id, kid, nil
}
func (c *Config) handshake(key, iv []byte, client bool) (*noise.HandshakeState, error) {
	// Bind the complete identity envelope, including version, cipher and key ID.
	prologue := append([]byte("SSPlus/v2/Noise/"), iv...)
	if c.tlsShape {
		prologue = append(prologue, []byte("/tls-ticket/v1")...)
	}
	return noise.NewHandshakeState(noise.Config{CipherSuite: c.suite, Pattern: noise.HandshakeNN,
		Initiator: client, PresharedKey: key, PresharedKeyPlacement: 0, Prologue: prologue})
}
func readNoise(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 48 || n > maxNoiseMessage {
		return nil, ErrAuthentication
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}
func writeNoise(w io.Writer, prefix, message []byte) error {
	if len(message) > maxNoiseMessage {
		return ErrAuthentication
	}
	packet := make([]byte, 0, len(prefix)+2+len(message))
	packet = append(packet, prefix...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(message)))
	packet = append(packet, message...)
	return writeFull(w, packet)
}
func (c *Config) helloPadding(b *paddingAllowance) ([]byte, error) {
	state := c.paddingState(b)
	n, err := state.next(0, 127)
	if err != nil {
		return nil, err
	}
	// Encrypted payload is only padding: application data waits for fresh ECDH.
	return make([]byte, n), nil
}

type Client struct {
	config *Config
	user   credential
}

func NewClient(config *Config, user User) (*Client, error) {
	u, err := parseUser(user)
	if err != nil {
		return nil, err
	}
	return &Client{config: config, user: u}, nil
}

// DialConn completes Noise and sends the encrypted destination. Caller owns conn.
func (c *Client) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	if c.config.tlsShape {
		conn = &tlsShapeConn{Conn: conn, client: true}
	}
	var address bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&address, destination); err != nil {
		return nil, err
	}
	iv, err := c.config.makeIV(c.user.ID, c.user.KeyID, time.Now())
	if err != nil {
		return nil, err
	}
	hs, err := c.config.handshake(c.user.key, iv, true)
	if err != nil {
		return nil, err
	}
	defer func() { clear(hs.LocalEphemeral().Private) }()
	budget := c.config.newPaddingAllowance()
	pad, err := c.config.helloPadding(budget)
	if err != nil {
		return nil, err
	}
	first, _, _, err := hs.WriteMessage(nil, pad)
	if err != nil {
		return nil, err
	}
	if err = writeNoise(conn, iv, first); err != nil {
		return nil, err
	}
	second, err := readNoise(conn)
	if err != nil {
		return nil, err
	}
	hello, tx, rx, err := hs.ReadMessage(nil, second)
	if err != nil {
		return nil, ErrAuthentication
	}
	if len(hello) > 127 || tx == nil || rx == nil {
		return nil, ErrAuthentication
	}
	stream := newStream(conn, tx, rx, c.config, budget)
	// This first transport message also proves receipt of the fresh responder key.
	if err = writeFull(stream, address.Bytes()); err != nil {
		return nil, err
	}
	return stream, nil
}

type Server struct {
	config     *Config
	users      map[uint32]*credential
	usersMutex sync.RWMutex
	pending    chan struct{}
	dummy      [32]byte
	replay     replayCache
}

func NewServer(config *Config, users []User) (*Server, error) {
	if len(users) == 0 {
		return nil, errors.New("ssplus: at least one user is required")
	}
	return NewManagedServer(config, users)
}
func NewManagedServer(config *Config, users []User) (*Server, error) {
	s := &Server{config: config, users: make(map[uint32]*credential), pending: make(chan struct{}, maxPendingHandshakes)}
	if _, err := rand.Read(s.dummy[:]); err != nil {
		return nil, err
	}
	for _, user := range users {
		if err := s.AddUser(user); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Server) AddUser(user User) error {
	u, err := parseUser(user)
	if err != nil {
		return err
	}
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()
	if _, ok := s.users[u.ID]; ok {
		return fmt.Errorf("ssplus: duplicate user_id %d", u.ID)
	}
	s.users[u.ID] = &u
	return nil
}

// UpdateUser atomically replaces a complete, bounded key ring. In-flight
// handshakes against the previous snapshot are rejected; established streams live on.
func (s *Server) UpdateUser(user User) error {
	u, err := parseUser(user)
	if err != nil {
		return err
	}
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()
	if s.users[u.ID] == nil {
		return fmt.Errorf("ssplus: unknown user_id %d", u.ID)
	}
	s.users[u.ID] = &u
	return nil
}
func (s *Server) RemoveUser(id uint32) {
	s.usersMutex.Lock()
	delete(s.users, id)
	s.usersMutex.Unlock()
}
func (s *Server) remember(iv []byte, now time.Time) bool { return s.replay.remember(iv, now) }

// Accept does not release a routable destination until the first transport
// record confirms the fresh handshake. Captured first flights cannot dial targets.
func (s *Server) Accept(conn net.Conn) (net.Conn, M.Socksaddr, User, error) {
	fail := func(err error) (net.Conn, M.Socksaddr, User, error) {
		return nil, M.Socksaddr{}, User{}, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	select {
	case s.pending <- struct{}{}:
	default:
		_ = conn.Close()
		return fail(errHandshakeLimit)
	}
	defer func() { <-s.pending }()
	guard := newHandshakeGuard(conn, maxHandshakeDuration)
	admitted := false
	defer func() {
		guard.finish()
		if !admitted {
			_ = guard.Close()
		}
	}()
	conn = guard
	if s.config.tlsShape {
		conn = &tlsShapeConn{Conn: conn}
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(conn, iv); err != nil {
		return fail(err)
	}
	id, kid, err := s.config.parseIV(iv, time.Now())
	if err != nil {
		return fail(err)
	}
	s.usersMutex.RLock()
	u := s.users[id]
	s.usersMutex.RUnlock()
	key := s.dummy[:]
	valid := false
	if u != nil {
		if selected, ok := u.selectKey(kid, time.Now()); ok {
			key = selected
			valid = true
		}
	}
	first, err := readNoise(conn)
	if err != nil {
		return fail(err)
	}
	hs, err := s.config.handshake(key, iv, false)
	if err != nil {
		return fail(err)
	}
	defer func() { clear(hs.LocalEphemeral().Private) }()
	hello, _, _, err := hs.ReadMessage(nil, first)
	if err != nil || len(hello) > 127 {
		return fail(ErrAuthentication)
	}
	if !valid || !s.remember(iv, time.Now()) {
		return fail(ErrAuthentication)
	}
	budget := s.config.newPaddingAllowance()
	pad, err := s.config.helloPadding(budget)
	if err != nil {
		return fail(err)
	}
	second, rx, tx, err := hs.WriteMessage(nil, pad)
	if err != nil {
		return fail(err)
	}
	if rx == nil || tx == nil {
		return fail(ErrAuthentication)
	}
	if err = writeNoise(conn, nil, second); err != nil {
		return fail(err)
	}
	stream := newStream(conn, tx, rx, s.config, budget)
	destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
	if err != nil {
		return fail(err)
	}
	if _, _, err = s.config.parseIV(iv, time.Now()); err != nil {
		return fail(err)
	}
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()
	if s.users[id] != u {
		return fail(ErrAuthentication)
	}
	if _, ok := u.selectKey(kid, time.Now()); !ok {
		return fail(ErrAuthentication)
	}
	if !guard.finish() {
		return fail(errHandshakeLimit)
	}
	admitted = true
	return stream, destination, User{ID: u.ID, KeyID: kid, Name: u.Name, Level: u.Level}, nil
}
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
