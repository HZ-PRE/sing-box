package xhttp

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/xray/signal/done"
)

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
	closeOnce  sync.Once
	closeErr   error
}

// HTTP/2 CloseIdleConnections does not close active streams. Track the sockets
// beneath TLS so transport shutdown also releases connections in that state.
type clientSockets struct {
	mu          sync.Mutex
	closed      bool
	connections map[*clientSocket]struct{}
}

type clientSocket struct {
	net.Conn
	owner *clientSockets
	once  sync.Once
	err   error
}

func (s *clientSockets) add(conn net.Conn) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	if s.connections == nil {
		s.connections = make(map[*clientSocket]struct{})
	}
	tracked := &clientSocket{Conn: conn, owner: s}
	s.connections[tracked] = struct{}{}
	return tracked, nil
}

func (c *clientSocket) Close() error {
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		c.err = c.Conn.Close()
	})
	return c.err
}

func (s *clientSockets) close() {
	s.mu.Lock()
	s.closed = true
	connections := make([]*clientSocket, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
}

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *splitConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *splitConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		err := c.writer.Close()
		var err2 error
		if c.reader != nil {
			err2 = c.reader.Close()
		}
		if err != nil {
			c.closeErr = err
		} else {
			c.closeErr = err2
		}
	})
	return c.closeErr
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	// TODO cannot do anything useful
	return nil
}

type httpServerConn struct {
	sync.Mutex
	*done.Instance
	io.Reader // no need to Close request.Body
	http.ResponseWriter
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	if c.Done() {
		return 0, io.ErrClosedPipe
	}
	n, err := c.ResponseWriter.Write(b)
	if err == nil {
		c.ResponseWriter.(http.Flusher).Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.Lock()
	defer c.Unlock()
	return c.Instance.Close()
}
