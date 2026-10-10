package ssplus

import (
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/uot"
)

// Consume the complete frame on short reads and preserve domain destinations.
// Return the pooled buffer after each read instead of keeping it on the conn.
// A pending ReadFrom still owns its buffer until it completes or is canceled.
type packetConn struct {
	*uot.Conn
	readMutex  sync.Mutex
	writeMutex sync.Mutex
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
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if _, err := c.Conn.WriteTo(p, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}
