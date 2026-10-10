package ssplus

import (
	"bytes"
	"net"
)

// Buffer only synchronous handshake writes. Reads flush immediately; returning
// DialConn always flushes, including server-first application protocols.
type handshakeBuffer struct {
	net.Conn
	buffer bytes.Buffer
	active bool
}

func (c *handshakeBuffer) Write(p []byte) (int, error) {
	if !c.active {
		return c.Conn.Write(p)
	}
	if c.buffer.Len()+len(p) > 32768 {
		if err := c.flush(); err != nil {
			return 0, err
		}
		return c.Conn.Write(p)
	}
	return c.buffer.Write(p)
}

func (c *handshakeBuffer) flush() error {
	if c.buffer.Len() == 0 {
		return nil
	}
	err := writeFull(c.Conn, c.buffer.Bytes())
	c.buffer.Reset()
	return err
}

func (c *handshakeBuffer) Read(p []byte) (int, error) {
	if c.active {
		if err := c.flush(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}
