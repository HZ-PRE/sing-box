// Package ssplus implements the SS+ v1 transport. See docs/manual/proxy-protocol/ssplus.md.
package ssplus

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	IVSize           = 48
	clockWindow      = 2 * time.Minute
	maxReplayEntries = 65536
)

var ErrAuthentication = errors.New("ssplus: authentication failed")

type User struct {
	ID    uint32
	Name  string
	Key   string
	Level uint32
}

type credential struct {
	User
	key []byte
}

type Config struct {
	method   byte
	plugin   byte
	ivKey    []byte
	obfs     bool
	obfsHost string
}

// NewConfig accepts only authenticated ciphers and explicit, shared plugin settings.
func NewConfig(method, plugin, ivKey string) (*Config, error) {
	return NewConfigWithObfs(method, plugin, ivKey, "plain", "")
}

func NewConfigWithObfs(method, plugin, ivKey, obfs, host string) (*Config, error) {
	c := new(Config)
	switch obfs {
	case "", "plain":
		if host != "" {
			return nil, fmt.Errorf("ssplus: obfs_param requires tls1.2_ticket_auth")
		}
	case "tls1.2_ticket_auth":
		c.obfs = true
		if len(host) > 253 || strings.ContainsAny(host, "\r\n\x00 ,/:") {
			return nil, fmt.Errorf("ssplus: invalid obfs host")
		}
		c.obfsHost = host
	default:
		return nil, fmt.Errorf("ssplus: unsupported obfs %q", obfs)
	}
	switch method {
	case "", "aes-256-gcm":
		c.method = 1
	case "chacha20-ietf-poly1305":
		c.method = 2
	default:
		return nil, fmt.Errorf("ssplus: unsupported method %q", method)
	}
	switch plugin {
	case "", "auth_sha1_v4":
		c.plugin = 1
	case "origin":
		c.plugin = 0
	case "auth_aes128_md5":
		c.plugin = 2
	default:
		return nil, fmt.Errorf("ssplus: unsupported SSR protocol %q", plugin)
	}
	var err error
	c.ivKey, err = decodeKey(ivKey)
	if err != nil {
		return nil, fmt.Errorf("ssplus iv_key: %w", err)
	}
	return c, nil
}

func decodeKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, errors.New("expected a base64-encoded 32-byte key")
	}
	return key, nil
}

func parseUser(user User) (credential, error) {
	if user.ID == 0 {
		return credential{}, errors.New("ssplus: user_id must be nonzero")
	}
	key, err := decodeKey(user.Key)
	if err != nil {
		return credential{}, fmt.Errorf("ssplus user %d key: %w", user.ID, err)
	}
	return credential{User: user, key: key}, nil
}

func deriveKey(key, salt []byte, label string) []byte {
	out := make([]byte, 32)
	// HKDF with a fixed output length cannot fail here.
	_, _ = io.ReadFull(hkdf.New(sha256.New, key, salt, []byte("ssplus/v1/"+label)), out)
	return out
}

func (c *Config) identityCipher(random []byte) cipher.AEAD {
	block, _ := aes.NewCipher(deriveKey(c.ivKey, random, "identity"))
	aead, _ := cipher.NewGCM(block)
	return aead
}

func (c *Config) payloadCipher(key, salt []byte, direction string) cipher.AEAD {
	key = deriveKey(key, salt, direction)
	if c.method == 2 {
		aead, _ := chacha20poly1305.New(key)
		return aead
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

func (c *Config) makeIV(id uint32, now time.Time) ([]byte, error) {
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv[:16]); err != nil {
		return nil, err
	}
	plain := make([]byte, 16)
	plain[0], plain[1], plain[2] = 1, c.method, c.plugin
	binary.BigEndian.PutUint32(plain[4:8], id)
	binary.BigEndian.PutUint64(plain[8:], uint64(now.Unix()))
	aead := c.identityCipher(iv[:16])
	aead.Seal(iv[16:16], make([]byte, aead.NonceSize()), plain, iv[:16])
	return iv, nil
}

func (c *Config) parseIV(iv []byte, now time.Time) (uint32, error) {
	if len(iv) != IVSize {
		return 0, ErrAuthentication
	}
	aead := c.identityCipher(iv[:16])
	p, err := aead.Open(nil, make([]byte, aead.NonceSize()), iv[16:], iv[:16])
	if err != nil || p[0] != 1 || p[1] != c.method || p[2] != c.plugin || p[3] != 0 {
		return 0, ErrAuthentication
	}
	ts := binary.BigEndian.Uint64(p[8:])
	if ts < uint64(now.Add(-clockWindow).Unix()) || ts > uint64(now.Add(clockWindow).Unix()) {
		return 0, ErrAuthentication
	}
	return binary.BigEndian.Uint32(p[4:8]), nil
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
	return &Client{config, u}, nil
}

// DialConn sends the destination immediately, including for server-first TCP protocols.
// The caller owns conn and must close it on error and impose a handshake deadline.
func (c *Client) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	if c.config.obfs {
		var err error
		conn, err = clientTicketHandshake(conn, c.config.ivKey, c.config.obfsHost)
		if err != nil {
			return nil, err
		}
	}
	var address bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&address, destination); err != nil {
		return nil, err
	}
	iv, err := c.config.makeIV(c.user.ID, time.Now())
	if err != nil {
		return nil, err
	}
	if err = writeFull(conn, iv); err != nil {
		return nil, err
	}
	stream := &streamConn{Conn: conn, config: c.config, key: c.user.key, iv: iv}
	stream.writer = shadowaead.NewWriter(fullWriter{conn}, c.config.payloadCipher(c.user.key, iv, "request"), shadowaead.MaxPacketSize)
	var result net.Conn = stream
	if c.config.plugin == 1 {
		result = newSSRConn(stream, c.user.key, iv, true)
	} else if c.config.plugin == 2 {
		result = newAESMD5Conn(stream, c.user.key, iv, true)
	}
	if err = writeFull(result, address.Bytes()); err != nil {
		return nil, err
	}
	return result, nil
}

type Server struct {
	config     *Config
	users      map[uint32]*credential
	usersMutex sync.RWMutex
	mutex      sync.Mutex
	replays    map[[IVSize]byte]time.Time
	lastSweep  time.Time
}

func NewServer(config *Config, users []User) (*Server, error) {
	if len(users) == 0 {
		return nil, errors.New("ssplus: at least one user is required")
	}
	return NewManagedServer(config, users)
}

// NewManagedServer permits an empty user list, which denies all connections until AddUser.
func NewManagedServer(config *Config, users []User) (*Server, error) {
	s := &Server{config: config, users: make(map[uint32]*credential), replays: make(map[[IVSize]byte]time.Time)}
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
	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("ssplus: duplicate user_id %d", user.ID)
	}
	s.users[user.ID] = &u
	return nil
}

func (s *Server) RemoveUser(id uint32) {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()
	delete(s.users, id)
}

// Accept authenticates the user and destination before recording the IV or routing traffic.
func (s *Server) Accept(conn net.Conn) (net.Conn, M.Socksaddr, User, error) {
	fail := func(err error) (net.Conn, M.Socksaddr, User, error) { return nil, M.Socksaddr{}, User{}, err }
	if s.config.obfs {
		var err error
		conn, err = s.serverTicketHandshake(conn)
		if err != nil {
			return fail(err)
		}
	}
	iv := make([]byte, IVSize)
	if _, err := io.ReadFull(conn, iv); err != nil {
		return fail(err)
	}
	id, err := s.config.parseIV(iv, time.Now())
	if err != nil {
		return fail(err)
	}
	s.usersMutex.RLock()
	u, ok := s.users[id]
	s.usersMutex.RUnlock()
	if !ok {
		return fail(ErrAuthentication)
	}
	stream := &streamConn{Conn: conn, config: s.config, key: u.key, iv: iv}
	stream.reader = shadowaead.NewReader(conn, s.config.payloadCipher(u.key, iv, "request"), shadowaead.MaxPacketSize)
	var result net.Conn = stream
	if s.config.plugin == 1 {
		result = newSSRConn(stream, u.key, iv, false)
	} else if s.config.plugin == 2 {
		result = newAESMD5Conn(stream, u.key, iv, false)
	}
	destination, err := M.SocksaddrSerializer.ReadAddrPort(result)
	if err != nil {
		return fail(ErrAuthentication)
	}
	// Recheck freshness after potentially slow reads. A header cannot outlive the replay cache.
	if _, err = s.config.parseIV(iv, time.Now()); err != nil {
		return fail(err)
	}
	// Do not admit a handshake if its credential was removed or replaced during reads.
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()
	if s.users[id] != u || !s.remember(iv, time.Now()) {
		return fail(ErrAuthentication)
	}
	return result, destination, User{ID: u.ID, Name: u.Name, Level: u.Level}, nil
}

func (s *Server) remember(iv []byte, now time.Time) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if now.Sub(s.lastSweep) >= time.Second {
		for token, expiry := range s.replays {
			if !now.Before(expiry) {
				delete(s.replays, token)
			}
		}
		s.lastSweep = now
	}
	token := [IVSize]byte(iv)
	if _, exists := s.replays[token]; exists {
		return false
	}
	// Fail closed when full: never evict a live entry and reopen its replay window.
	if len(s.replays) >= maxReplayEntries {
		return false
	}
	s.replays[token] = now.Add(2*clockWindow + time.Second)
	return true
}

type streamConn struct {
	net.Conn
	config                *Config
	key, iv               []byte
	reader                *shadowaead.Reader
	writer                *shadowaead.Writer
	readMutex, writeMutex sync.Mutex
	readErr, writeErr     error
}

func (c *streamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.reader == nil {
		salt := make([]byte, 32)
		if _, c.readErr = io.ReadFull(c.Conn, salt); c.readErr != nil {
			return 0, c.readErr
		}
		binding := append(append([]byte(nil), c.iv...), salt...)
		c.reader = shadowaead.NewReader(c.Conn, c.config.payloadCipher(c.key, binding, "response"), shadowaead.MaxPacketSize)
	}
	n, err := c.reader.Read(p)
	if err != nil {
		c.readErr = err
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writer == nil {
		salt := make([]byte, 32)
		if _, c.writeErr = rand.Read(salt); c.writeErr != nil {
			return 0, c.writeErr
		}
		if c.writeErr = writeFull(c.Conn, salt); c.writeErr != nil {
			return 0, c.writeErr
		}
		binding := append(append([]byte(nil), c.iv...), salt...)
		c.writer = shadowaead.NewWriter(fullWriter{c.Conn}, c.config.payloadCipher(c.key, binding, "response"), shadowaead.MaxPacketSize)
	}
	n, err := c.writer.Write(p)
	if err != nil {
		c.writeErr = err
	}
	return n, err
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

type fullWriter struct{ io.Writer }

func (w fullWriter) Write(p []byte) (int, error) {
	if err := writeFull(w.Writer, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
