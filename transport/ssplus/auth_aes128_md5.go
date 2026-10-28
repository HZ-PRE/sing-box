package ssplus

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Implements SSR auth_aes128_md5's single-user framing. SS+ selects the user
// before decoding this layer, so its Key is the selected user's 32-byte key.
// The plugin's opaque UID is not used for SS+ account selection.
var errAESFrame = errors.New("ssplus: invalid auth_aes128_md5 frame")

func md5MAC(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func aesAuthBlock(key []byte) []byte {
	// SSR EVP_BytesToKey for a single AES-128 block: MD5(base64(key) + salt).
	sum := md5.Sum([]byte(base64.StdEncoding.EncodeToString(key) + "auth_aes128_md5"))
	return sum[:]
}

func encodeAESAuth(payload, key, iv []byte, now time.Time) ([]byte, error) {
	var random [1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	return encodeAESAuthPadding(payload, key, iv, now, int(random[0]))
}

func encodeAESAuthPadding(payload, key, iv []byte, now time.Time, padding int) ([]byte, error) {
	if padding < 0 || padding > 255 {
		return nil, errAESFrame
	}
	frame := make([]byte, 35+padding+len(payload))
	if len(frame) >= 8192 {
		return nil, errAESFrame
	}
	if _, err := rand.Read(frame); err != nil {
		return nil, err
	}
	macKey := append(append([]byte(nil), iv...), key...)
	copy(frame[1:7], md5MAC(macKey, frame[:1])[:6])
	plain := make([]byte, 16)
	binary.LittleEndian.PutUint32(plain, uint32(now.Unix()))
	if _, err := rand.Read(plain[4:12]); err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(plain[12:], uint16(len(frame)))
	binary.LittleEndian.PutUint16(plain[14:], uint16(padding))
	block, _ := aes.NewCipher(aesAuthBlock(key))
	// One CBC block with an all-zero IV is identical to block encryption.
	block.Encrypt(frame[11:27], plain)
	copy(frame[27:31], md5MAC(macKey, frame[7:27])[:4])
	copy(frame[31+padding:], payload)
	copy(frame[len(frame)-4:], md5MAC(key, frame[:len(frame)-4])[:4])
	return frame, nil
}

func readAESAuth(r io.Reader, key, iv []byte, now time.Time) ([]byte, error) {
	header := make([]byte, 31)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	macKey := append(append([]byte(nil), iv...), key...)
	if !hmac.Equal(header[1:7], md5MAC(macKey, header[:1])[:6]) ||
		!hmac.Equal(header[27:31], md5MAC(macKey, header[7:27])[:4]) {
		return nil, errAESFrame
	}
	plain := make([]byte, 16)
	block, _ := aes.NewCipher(aesAuthBlock(key))
	block.Decrypt(plain, header[11:27])
	length := int(binary.LittleEndian.Uint16(plain[12:]))
	padding := int(binary.LittleEndian.Uint16(plain[14:]))
	ts := int64(binary.LittleEndian.Uint32(plain))
	if length < 35 || length >= 8192 || padding > length-35 ||
		ts < now.Add(-clockWindow).Unix() || ts > now.Add(clockWindow).Unix() {
		return nil, errAESFrame
	}
	frame := make([]byte, length)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[31:]); err != nil {
		return nil, err
	}
	if !hmac.Equal(frame[length-4:], md5MAC(key, frame[:length-4])[:4]) {
		return nil, errAESFrame
	}
	return frame[31+padding : length-4], nil
}

func aesFrameKey(key []byte, sequence uint32) []byte {
	result := make([]byte, len(key)+4)
	copy(result, key)
	binary.LittleEndian.PutUint32(result[len(key):], sequence)
	return result
}

func encodeAESData(payload, key []byte, sequence uint32) ([]byte, error) {
	return new(aesDataCodec).encode(payload, key, sequence)
}

type aesDataCodec struct {
	buffer []byte
	key    []byte
	sum    [md5.Size]byte
}

func (c *aesDataCodec) frameKey(key []byte, sequence uint32) []byte {
	if len(c.key) != len(key)+4 {
		c.key = make([]byte, len(key)+4)
		copy(c.key, key)
	}
	binary.LittleEndian.PutUint32(c.key[len(key):], sequence)
	return c.key
}

func (c *aesDataCodec) frame(size int) []byte {
	if cap(c.buffer) < size {
		c.buffer = make([]byte, min(8192, max(256, size*2)))
	}
	return c.buffer[:size]
}

func (c *aesDataCodec) encode(payload, key []byte, sequence uint32) ([]byte, error) {
	if sequence == 0 || len(payload) > ssrMaxPayload {
		return nil, errAESFrame
	}
	var random [1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	return c.encodePadding(payload, key, sequence, int(random[0]&31))
}

func (c *aesDataCodec) encodePadding(payload, key []byte, sequence uint32, extra int) ([]byte, error) {
	if sequence == 0 || len(payload) > ssrMaxPayload || extra < 0 || extra > 127 || 9+extra+len(payload) >= 8192 {
		return nil, errAESFrame
	}
	padding := extra + 1
	frame := c.frame(8 + padding + len(payload))
	binary.LittleEndian.PutUint16(frame, uint16(len(frame)))
	mac := hmac.New(md5.New, c.frameKey(key, sequence))
	mac.Write(frame[:2])
	copy(frame[2:4], mac.Sum(c.sum[:0])[:2])
	frame[4] = byte(padding)
	if _, err := rand.Read(frame[5 : 4+padding]); err != nil {
		return nil, err
	}
	copy(frame[4+padding:], payload)
	mac.Reset()
	mac.Write(frame[:len(frame)-4])
	copy(frame[len(frame)-4:], mac.Sum(c.sum[:0])[:4])
	return frame, nil
}

func readAESData(r io.Reader, key []byte, sequence uint32) ([]byte, error) {
	return new(aesDataCodec).read(r, key, sequence)
}

func (c *aesDataCodec) read(r io.Reader, key []byte, sequence uint32) ([]byte, error) {
	if sequence == 0 {
		return nil, errAESFrame
	}
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	mac := hmac.New(md5.New, c.frameKey(key, sequence))
	mac.Write(header[:2])
	if !hmac.Equal(header[2:], mac.Sum(c.sum[:0])[:2]) {
		return nil, errAESFrame
	}
	length := int(binary.LittleEndian.Uint16(header[:2]))
	if length < 9 || length >= 8192 {
		return nil, errAESFrame
	}
	frame := c.frame(length)
	copy(frame, header[:])
	if _, err := io.ReadFull(r, frame[4:]); err != nil {
		return nil, err
	}
	mac.Reset()
	mac.Write(frame[:length-4])
	if !hmac.Equal(frame[length-4:], mac.Sum(c.sum[:0])[:4]) {
		return nil, errAESFrame
	}
	padding := int(frame[4])
	if padding == 255 {
		if length < 11 {
			return nil, errAESFrame
		}
		padding = int(binary.LittleEndian.Uint16(frame[5:7]))
		if padding < 3 {
			return nil, errAESFrame
		}
	}
	if padding < 1 || padding > length-8 {
		return nil, errAESFrame
	}
	return frame[4+padding : length-4], nil
}

type aesMD5Conn struct {
	padding paddingState
	net.Conn
	key, iv                     []byte
	readAuth, writeAuth         bool
	readSequence, writeSequence uint32
	pending                     []byte
	readMutex, writeMutex       sync.Mutex
	readErr, writeErr           error
	decoder, encoder            aesDataCodec
}

func newAESMD5Conn(conn net.Conn, key, iv []byte, client bool, policy ...paddingState) net.Conn {
	c := &aesMD5Conn{Conn: conn, key: key, iv: iv, readAuth: !client, writeAuth: client, readSequence: 1, writeSequence: 1}
	if len(policy) > 0 {
		c.padding = policy[0]
	}
	return c
}

func (c *aesMD5Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	for len(c.pending) == 0 {
		if c.readAuth {
			c.pending, c.readErr = readAESAuth(c.Conn, c.key, c.iv, time.Now())
			c.readAuth = false
		} else {
			c.pending, c.readErr = c.decoder.read(c.Conn, c.key, c.readSequence)
			c.readSequence++
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *aesMD5Conn) Write(p []byte) (int, error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	total := 0
	for len(p) > 0 {
		size := min(len(p), ssrMaxPayload)
		if c.writeAuth {
			size = min(size, 1200)
		}
		padding, err := c.padding.next(size, 127)
		if err != nil {
			c.writeErr = err
			return total, err
		}
		var frame []byte
		if c.writeAuth {
			frame, err = encodeAESAuthPadding(p[:size], c.key, c.iv, time.Now(), padding)
			c.writeAuth = false
		} else {
			frame, err = c.encoder.encodePadding(p[:size], c.key, c.writeSequence, padding)
			c.writeSequence++
		}
		if err == nil {
			err = writeFull(c.Conn, frame)
		}
		if err != nil {
			c.writeErr = err
			return total, err
		}
		total += size
		p = p[size:]
	}
	return total, nil
}
