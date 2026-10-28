package ssplus

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/adler32"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"time"
)

// SSR auth_sha1_v4 framing runs on the plaintext side of the SS AEAD stream.
// Only the client sends an auth frame; all subsequent frames use CRC32/Adler32.
// These checksums are framing checks, not substitutes for the outer AEAD.
const ssrMaxPayload = 8100

var errSSRFrame = errors.New("ssplus: invalid auth_sha1_v4 frame")

type ssrConn struct {
	padding paddingState
	net.Conn
	key, iv               []byte
	readAuth, writeAuth   bool
	pending               []byte
	readMutex, writeMutex sync.Mutex
	readErr, writeErr     error
}

func newSSRConn(conn net.Conn, key, iv []byte, client bool, policy ...paddingState) *ssrConn {
	c := &ssrConn{Conn: conn, key: key, iv: iv, readAuth: !client, writeAuth: client}
	if len(policy) > 0 {
		c.padding = policy[0]
	}
	return c
}

func authCRC(length []byte, key []byte) uint32 {
	h := crc32.NewIEEE()
	h.Write(length)
	h.Write([]byte("auth_sha1_v4"))
	h.Write(key)
	return h.Sum32()
}

func authMAC(frame, key, iv []byte) []byte {
	macKey := append(append([]byte(nil), iv...), key...)
	h := hmac.New(sha1.New, macKey)
	h.Write(frame)
	return h.Sum(nil)[:10]
}

func encodeSSR(payload, key, iv []byte, auth bool, now time.Time) ([]byte, error) {
	var random [1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	padding := int(random[0] & 63)
	if len(payload) > 1200 {
		padding = 0
	}
	return encodeSSRPadding(payload, key, iv, auth, now, padding)
}

func encodeSSRPadding(payload, key, iv []byte, auth bool, now time.Time, padding int) ([]byte, error) {
	if padding < 0 || padding > 127 || len(payload) > ssrMaxPayload {
		return nil, errSSRFrame
	}
	prefix, suffix, authLen := 4, 4, 0
	if auth {
		prefix, suffix, authLen = 6, 10, 12
	}
	if prefix+1+padding+authLen+len(payload)+suffix >= 8192 {
		return nil, errSSRFrame
	}
	frame := make([]byte, prefix+1+padding+authLen+len(payload)+suffix)
	binary.BigEndian.PutUint16(frame, uint16(len(frame)))
	if auth {
		binary.LittleEndian.PutUint32(frame[2:], authCRC(frame[:2], key))
	} else {
		binary.LittleEndian.PutUint16(frame[2:], uint16(crc32.ChecksumIEEE(frame[:2])))
	}
	frame[prefix] = byte(padding + 1)
	if _, err := rand.Read(frame[prefix+1 : prefix+1+padding]); err != nil {
		return nil, err
	}
	pos := prefix + 1 + padding
	if auth {
		binary.LittleEndian.PutUint32(frame[pos:], uint32(now.Unix()))
		if _, err := rand.Read(frame[pos+4 : pos+12]); err != nil {
			return nil, err
		}
		pos += 12
	}
	copy(frame[pos:], payload)
	if auth {
		copy(frame[len(frame)-suffix:], authMAC(frame[:len(frame)-suffix], key, iv))
	} else {
		binary.LittleEndian.PutUint32(frame[len(frame)-suffix:], adler32.Checksum(frame[:len(frame)-suffix]))
	}
	return frame, nil
}

func readSSR(r io.Reader, key, iv []byte, auth bool, now time.Time) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	prefix, suffix, authLen := 4, 4, 0
	if auth {
		prefix, suffix, authLen = 6, 10, 12
	}
	if length < prefix+1+authLen+suffix || length >= 8192 {
		return nil, errSSRFrame
	}
	frame := make([]byte, length)
	copy(frame, size[:])
	if _, err := io.ReadFull(r, frame[2:]); err != nil {
		return nil, err
	}
	end := length - suffix
	if auth {
		if binary.LittleEndian.Uint32(frame[2:6]) != authCRC(frame[:2], key) || !hmac.Equal(frame[end:], authMAC(frame[:end], key, iv)) {
			return nil, errSSRFrame
		}
	} else {
		if binary.LittleEndian.Uint16(frame[2:4]) != uint16(crc32.ChecksumIEEE(frame[:2])) || binary.LittleEndian.Uint32(frame[end:]) != adler32.Checksum(frame[:end]) {
			return nil, errSSRFrame
		}
	}
	padding := int(frame[prefix])
	if padding == 255 {
		if prefix+3 > end {
			return nil, errSSRFrame
		}
		padding = int(binary.BigEndian.Uint16(frame[prefix+1 : prefix+3]))
		if padding < 3 {
			return nil, errSSRFrame
		}
	} else if padding == 0 {
		return nil, errSSRFrame
	}
	pos := prefix + padding
	if pos+authLen > end {
		return nil, errSSRFrame
	}
	if auth {
		ts := int64(binary.LittleEndian.Uint32(frame[pos : pos+4]))
		if ts < now.Add(-clockWindow).Unix() || ts > now.Add(clockWindow).Unix() {
			return nil, ErrAuthentication
		}
		pos += authLen
	}
	return frame[pos:end], nil
}

func (c *ssrConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	for len(c.pending) == 0 {
		c.pending, c.readErr = readSSR(c.Conn, c.key, c.iv, c.readAuth, time.Now())
		if c.readErr != nil {
			return 0, c.readErr
		}
		c.readAuth = false
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ssrConn) Write(p []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(p) > 0 {
		size := min(len(p), ssrMaxPayload)
		padding, err := c.padding.next(size, 127)
		var frame []byte
		if err == nil {
			frame, err = encodeSSRPadding(p[:size], c.key, c.iv, c.writeAuth, time.Now(), padding)
		}
		if err == nil {
			err = writeFull(c.Conn, frame)
		}
		if err != nil {
			c.writeErr = err
			return total, err
		}
		c.writeAuth = false
		total += size
		p = p[size:]
	}
	return total, nil
}
