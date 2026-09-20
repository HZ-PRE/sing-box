package ssplus

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/uot"
)

// Adapt the existing UoT codec to net.PacketConn: preserve domain destinations,
// report payload byte counts, and consume truncated datagrams without losing framing.
type packetConn struct {
	*uot.Conn
	readMutex sync.Mutex
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	buffer := buf.NewSize(65535)
	defer buffer.Release()
	destination, err := c.Conn.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	var addr net.Addr = destination
	if !destination.IsFqdn() {
		addr = destination.UDPAddr()
	}
	n := copy(p, buffer.Bytes())
	if n < buffer.Len() {
		return n, addr, io.ErrShortBuffer
	}
	return n, addr, nil
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, io.ErrShortBuffer
	}
	if _, err := c.Conn.WriteTo(p, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}
