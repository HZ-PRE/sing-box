package ssplus

// This is a bounded TLS 1.2 session-ticket-shaped carrier, NOT TLS. All user
// authentication and confidentiality belong to Noise. In particular there is
// no certificate, TLS Finished verification or interoperability with browsers.
import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const (
	tlsShapeHelloLimit  = 2048
	tlsShapeRecordLimit = 16384 + 2048 // TLS 1.2 ciphertext limit.
)

// EnableFixedObfuscation selects the only production SSPlus v2 carrier.
// It is deliberately not negotiated or exposed as a user setting.
func (c *Config) EnableFixedObfuscation() { c.tlsShape = true }

type tlsShapeConn struct {
	net.Conn
	client               bool
	session              [32]byte // Set during the synchronous Noise handshake, then immutable.
	readMu, writeMu      sync.Mutex
	readStep, writeStep  uint8
	readErr, writeErr    error
	pending, writeBuffer []byte
	remaining            int
	header               [5]byte
}

func shapeRecord(dst []byte, kind byte, version uint16, p []byte) []byte {
	dst = append(dst, kind, byte(version>>8), byte(version))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(p)))
	return append(dst, p...)
}

func shapeHello(kind byte, session []byte, ticket []byte) ([]byte, error) {
	body := make([]byte, 2+32, 128+len(ticket))
	body[0], body[1] = 3, 3
	if _, err := rand.Read(body[2:]); err != nil {
		return nil, err
	}
	body = append(body, 32)
	body = append(body, session...)
	var ext []byte
	version := uint16(0x0303)
	if kind == 1 {
		version = 0x0301
		body = append(body, 0, 8, 0xc0, 0x2f, 0xc0, 0x30, 0xcc, 0xa8, 0xcc, 0xa9, 1, 0)
		// Supported groups, point formats, signature algorithms, extended master secret.
		ext = []byte{0, 10, 0, 6, 0, 4, 0, 29, 0, 23, 0, 11, 0, 2, 1, 0,
			0, 13, 0, 6, 0, 4, 4, 1, 4, 3, 0, 23, 0, 0}
	} else {
		body = append(body, 0xc0, 0x2f, 0)
		ext = []byte{0, 23, 0, 0}
	}
	ext = append(ext, 0, 35)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(ticket)))
	ext = append(ext, ticket...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	handshake := []byte{kind, 0, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	return shapeRecord(nil, 22, version, handshake), nil
}

// Parse the complete hello, including all vector boundaries. Never search for
// magic byte patterns or trust a length before checking the containing vector.
func parseShapeHello(p []byte, kind byte) (session, ticket []byte, err error) {
	bad := func() ([]byte, []byte, error) { return nil, nil, ErrAuthentication }
	if len(p) < 71 || len(p) > tlsShapeHelloLimit || p[0] != kind || p[1] != 0 ||
		int(binary.BigEndian.Uint16(p[2:])) != len(p)-4 || p[4] != 3 || p[5] != 3 || p[38] != 32 {
		return bad()
	}
	session = p[39:71]
	p = p[71:]
	if kind == 1 {
		if len(p) < 2 {
			return bad()
		}
		n := int(binary.BigEndian.Uint16(p))
		p = p[2:]
		if n < 2 || n%2 != 0 || n > len(p) {
			return bad()
		}
		found := false
		for i := 0; i < n; i += 2 {
			if p[i] == 0xc0 && p[i+1] == 0x2f {
				found = true
			}
		}
		p = p[n:]
		if !found || len(p) < 2 || p[0] != 1 || p[1] != 0 {
			return bad()
		}
		p = p[2:]
	} else {
		if len(p) < 3 || !bytes.Equal(p[:3], []byte{0xc0, 0x2f, 0}) {
			return bad()
		}
		p = p[3:]
	}
	if len(p) < 2 || int(binary.BigEndian.Uint16(p)) != len(p)-2 {
		return bad()
	}
	p = p[2:]
	// Small bounded extension list; reject duplicates without a heap map.
	var seen [32]uint16
	count := 0
	for len(p) > 0 {
		if len(p) < 4 || count == len(seen) {
			return bad()
		}
		id, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if n > len(p) {
			return bad()
		}
		for _, old := range seen[:count] {
			if old == id {
				return bad()
			}
		}
		seen[count] = id
		count++
		if id == 35 {
			ticket = p[:n]
		}
		p = p[n:]
	}
	if ticket == nil {
		return bad()
	}
	if kind == 1 && (len(ticket) < IVSize+48 || len(ticket) > IVSize+maxNoiseMessage) {
		return bad()
	}
	if kind == 2 && len(ticket) != 0 {
		return bad()
	}
	return session, ticket, nil
}

func (c *tlsShapeConn) recordHeader(kind byte, version uint16, limit int) (int, error) {
	if _, err := io.ReadFull(c.Conn, c.header[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(c.header[3:]))
	if c.header[0] != kind || binary.BigEndian.Uint16(c.header[1:]) != version || n == 0 || n > limit {
		return 0, ErrAuthentication
	}
	return n, nil
}

func (c *tlsShapeConn) record(kind byte, version uint16, limit int) ([]byte, error) {
	n, err := c.recordHeader(kind, version, limit)
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(c.Conn, p)
	return p, err
}

func (c *tlsShapeConn) changeCipherSpec() error {
	n, err := c.recordHeader(20, 0x0303, 1)
	if err != nil {
		return err
	}
	var p [1]byte
	if _, err = io.ReadFull(c.Conn, p[:n]); err != nil {
		return err
	}
	if p[0] != 1 {
		return ErrAuthentication
	}
	return nil
}

func (c *tlsShapeConn) readHello() error {
	kind, version := byte(1), uint16(0x0301)
	if c.client {
		kind, version = 2, 0x0303
	}
	p, err := c.record(22, version, tlsShapeHelloLimit)
	if err != nil {
		return err
	}
	session, ticket, err := parseShapeHello(p, kind)
	if err != nil {
		return err
	}
	if c.client {
		if !bytes.Equal(c.session[:], session) {
			return ErrAuthentication
		}
		if err = c.changeCipherSpec(); err != nil {
			return err
		}
		p, err = c.record(22, 0x0303, maxNoiseMessage)
		if err != nil {
			return err
		}
		if len(p) < 48 {
			return ErrAuthentication
		}
		c.pending = binary.BigEndian.AppendUint16(nil, uint16(len(p)))
		c.pending = append(c.pending, p...)
		c.readStep = 2
	} else {
		copy(c.session[:], session)
		c.pending = append([]byte(nil), ticket[:IVSize]...)
		c.pending = binary.BigEndian.AppendUint16(c.pending, uint16(len(ticket)-IVSize))
		c.pending = append(c.pending, ticket[IVSize:]...)
		c.readStep = 1
	}
	return nil
}

func (c *tlsShapeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.readStep == 0 {
		if c.readErr = c.readHello(); c.readErr != nil {
			return 0, c.readErr
		}
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		if len(c.pending) == 0 {
			c.pending = nil
		}
		return n, nil
	}
	if c.remaining == 0 {
		kind, limit := byte(23), tlsShapeRecordLimit
		if c.readStep == 1 {
			if c.readErr = c.changeCipherSpec(); c.readErr != nil {
				return 0, c.readErr
			}
			kind, limit = 22, tlsShapeHelloLimit
			c.readStep = 2
		}
		c.remaining, c.readErr = c.recordHeader(kind, 0x0303, limit)
		if c.readErr != nil {
			return 0, c.readErr
		}
	}
	n, err := c.Conn.Read(p[:min(len(p), c.remaining)])
	c.remaining -= n
	if err != nil {
		c.readErr = err
	}
	return n, err
}

func (c *tlsShapeConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writeStep == 0 {
		var packet []byte
		if c.client {
			if len(p) < IVSize+2+48 || len(p) > IVSize+2+maxNoiseMessage || int(binary.BigEndian.Uint16(p[IVSize:])) != len(p)-IVSize-2 {
				c.writeErr = ErrAuthentication
				return 0, c.writeErr
			}
			if _, c.writeErr = rand.Read(c.session[:]); c.writeErr != nil {
				return 0, c.writeErr
			}
			ticket := append([]byte(nil), p[:IVSize]...)
			ticket = append(ticket, p[IVSize+2:]...)
			packet, c.writeErr = shapeHello(1, c.session[:], ticket)
			c.writeStep = 1
		} else {
			if len(p) < 50 || len(p) > maxNoiseMessage+2 || int(binary.BigEndian.Uint16(p)) != len(p)-2 {
				c.writeErr = ErrAuthentication
				return 0, c.writeErr
			}
			packet, c.writeErr = shapeHello(2, c.session[:], nil)
			packet = append(packet, 20, 3, 3, 0, 1, 1)
			packet = shapeRecord(packet, 22, 0x0303, p[2:])
			c.writeStep = 2
		}
		if c.writeErr == nil {
			c.writeErr = writeFull(c.Conn, packet)
		}
		if c.writeErr != nil {
			return 0, c.writeErr
		}
		return len(p), nil
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), tlsShapeRecordLimit)
		kind := byte(23)
		prefix := 0
		if c.writeStep == 1 {
			if len(p) > tlsShapeHelloLimit {
				c.writeErr = ErrAuthentication
				return total, c.writeErr
			}
			kind, prefix, c.writeStep = 22, 6, 2
		}
		need := prefix + 5 + n
		if cap(c.writeBuffer) < need {
			c.writeBuffer = make([]byte, 0, min(tlsShapeRecordLimit+11, max(512, need)))
		}
		c.writeBuffer = c.writeBuffer[:0]
		if prefix != 0 {
			c.writeBuffer = append(c.writeBuffer, 20, 3, 3, 0, 1, 1)
		}
		c.writeBuffer = shapeRecord(c.writeBuffer, kind, 0x0303, p[:n])
		if c.writeErr = writeFull(c.Conn, c.writeBuffer); c.writeErr != nil {
			return total, c.writeErr
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
