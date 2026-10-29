package ssplus

import (
	"encoding/binary"
	"github.com/flynn/noise"
	"io"
	"net"
	"sync"
)

const maxRecord = 16384

// Each record has a Noise-encrypted uint16 length, followed by a separately
// encrypted payload: uint16 data length | application bytes | optional padding.
// Independent CipherStates own nonces. Authentication failure is terminal.
type streamConn struct {
	net.Conn
	tx, rx                           *noise.CipherState
	padding                          *paddingAllowance
	policy                           paddingState
	readMu, writeMu                  sync.Mutex
	readErr, writeErr                error
	readBuffer, writeBuffer, pending []byte
	readHeader                       [18]byte
}

func newStream(conn net.Conn, tx, rx *noise.CipherState, c *Config, b *paddingAllowance) *streamConn {
	return &streamConn{Conn: conn, tx: tx, rx: rx, padding: b, policy: c.paddingState(b)}
}
func grow(buffer []byte, n int) []byte {
	if cap(buffer) < n {
		buffer = make([]byte, min(maxRecord+34, max(512, n*2)))
	}
	return buffer[:n]
}
func (c *streamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.pending) == 0 {
		header := c.readHeader[:]
		if _, c.readErr = io.ReadFull(c.Conn, header[:]); c.readErr != nil {
			return 0, c.readErr
		}
		var length []byte
		length, c.readErr = c.rx.Decrypt(header[:0], nil, header[:])
		if c.readErr != nil {
			return 0, c.readErr
		}
		n := int(binary.BigEndian.Uint16(length))
		if n < 3 || n > maxRecord {
			c.readErr = ErrAuthentication
			return 0, c.readErr
		}
		c.readBuffer = grow(c.readBuffer, n+16)
		if _, c.readErr = io.ReadFull(c.Conn, c.readBuffer); c.readErr != nil {
			return 0, c.readErr
		}
		var plain []byte
		plain, c.readErr = c.rx.Decrypt(c.readBuffer[:0], nil, c.readBuffer)
		if c.readErr != nil {
			return 0, c.readErr
		}
		dataLen := int(binary.BigEndian.Uint16(plain[:2]))
		if dataLen == 0 || dataLen > len(plain)-2 || len(plain)-2-dataLen > 127 {
			c.readErr = ErrAuthentication
			return 0, c.readErr
		}
		c.pending = plain[2 : 2+dataLen]
		if c.rx.Nonce()%(1<<17) == 0 {
			c.rx.Rekey()
		}
	}
	n := copy(p, c.pending)
	// Do not retain consumed bootstrap secrets or application plaintext.
	clear(c.pending[:n])
	c.pending = c.pending[n:]
	return n, nil
}
func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), maxRecord-2)
		padding, err := c.policy.next(n, min(127, maxRecord-2-n))
		if err != nil {
			c.writeErr = err
			return total, err
		}
		length := 2 + n + padding
		c.writeBuffer = grow(c.writeBuffer, 18+length+16)
		binary.BigEndian.PutUint16(c.writeBuffer[:2], uint16(length))
		if _, err = c.tx.Encrypt(c.writeBuffer[:0], nil, c.writeBuffer[:2]); err != nil {
			c.writeErr = err
			return total, err
		}
		body := c.writeBuffer[18 : 18+length]
		binary.BigEndian.PutUint16(body[:2], uint16(n))
		copy(body[2:], p[:n])
		clear(body[2+n:])
		if _, err = c.tx.Encrypt(c.writeBuffer[18:18], nil, body); err != nil {
			c.writeErr = err
			return total, err
		}
		if err = writeFull(c.Conn, c.writeBuffer); err != nil {
			c.writeErr = err
			return total, err
		}
		if c.tx.Nonce()%(1<<17) == 0 {
			c.tx.Rekey()
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
