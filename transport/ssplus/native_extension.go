package ssplus

import (
	"encoding/binary"
	"io"
)

// The optional MTU1 extension retains v3 keys, sequence numbers and the legacy
// fragmentation geometry. Only an authenticated 1360-byte round trip enables
// single-datagram compact frames. Never amplify an unvalidated source.
func isLargeControl(p []byte, wireSize int) bool {
	return wireSize == nativeMaxMTU && len(p) == nativeMaxMTU-nativeHeader-nativeEnvelope-16 &&
		p[0] >= nativeProbe && p[0] <= nativeReady && string(p[17:21]) == "MTU1"
}

func (c *NativeConn) largePlain() []byte {
	if c.largeBuffer == nil {
		c.largeBuffer = make([]byte, nativeMaxMTU)
	}
	return c.largeBuffer
}

func (c *NativeConn) sendLargeControl(kind byte, token []byte, reply func([]byte) error) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	plain := c.largePlain()[:nativeMaxMTU-nativeHeader-nativeEnvelope-16]
	clear(plain)
	plain[0] = kind
	copy(plain[1:17], token)
	copy(plain[17:21], "MTU1")
	packet, err := c.tx.sealLimit(c.writeBuffer[:0], plain, nativeMaxMTU)
	if err != nil {
		return err
	}
	return reply(packet)
}

func (c *NativeConn) respondControl(kind byte, token []byte, reply func([]byte) error, limit int) error {
	if limit == nativeMaxMTU {
		return c.sendLargeControl(kind, token, reply)
	}
	return c.sendControl(kind, token, reply, min(limit, nativeMTU))
}

// Called with writeMu held; returns false if legacy fragments are required.
func (c *NativeConn) writeCompact(address, payload []byte, reply func([]byte) error) (bool, error) {
	size := len(address) + len(payload)
	if c.pathMTU.Load() != nativeMaxMTU ||
		size+3+nativeHeader+nativeEnvelope+16+nativePaddingMax > nativeMaxMTU {
		return false, nil
	}
	plain := c.largePlain()[:max(32, size+3)]
	clear(plain)
	plain[0] = nativeCompact
	binary.BigEndian.PutUint16(plain[1:3], uint16(size))
	copy(plain[3:], address)
	copy(plain[3+len(address):], payload)
	packet, err := c.tx.sealLimit(c.writeBuffer[:0], plain, nativeMaxMTU)
	if err != nil {
		return true, err
	}
	if len(packet) > nativeMaxMTU {
		return true, io.ErrShortBuffer
	}
	return true, reply(packet)
}
