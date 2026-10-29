package ssplus

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type nativeMessage struct {
	data    []byte
	address M.Socksaddr
	offset  int
}

// NativeConn owns the authenticated TCP control connection and a bounded UDP
// receive queue. Closing either transport terminates the entire session.
type NativeConn struct {
	control                     net.Conn
	udp                         net.Conn
	hub                         *NativeService
	tx                          nativeCipher
	rx                          nativeCipher
	writeMu                     sync.Mutex
	writeBuffer                 [nativeMaxMTU]byte
	plainBuffer                 [14 + nativeFragment]byte
	addressBuffer               *B.Buffer
	readBuffer                  [nativeMaxMTU]byte
	largeBuffer                 []byte
	pathMTU                     atomic.Int32
	mu                          sync.Mutex
	assembly                    nativeAssembler
	queue                       chan nativeMessage
	done                        chan struct{}
	ready                       chan struct{}
	readyOnce                   sync.Once
	once                        sync.Once
	changed                     chan struct{}
	readDeadline, writeDeadline time.Time
	last                        time.Time
	source, pending             string
	token                       [16]byte
	pendingUntil                time.Time
	reply                       func([]byte) error
}

func newNativeConn(config *Config, control net.Conn, seed []byte, client bool, budget *nativeBudget) *NativeConn {
	c := &NativeConn{control: control, queue: make(chan nativeMessage, 8), done: make(chan struct{}), ready: make(chan struct{}), changed: make(chan struct{}), last: time.Now()}
	tx, rx := "response", "request"
	if client {
		tx, rx = rx, tx
	}
	c.tx = newNativeCipher(config, seed, tx)
	c.tx.policy.allowance = sharedPadding(control, config)
	c.rx = newNativeCipher(config, seed, rx)
	c.assembly.budget = budget
	// The address shares the first fragment's storage; writes hold writeMu.
	c.addressBuffer = B.With(c.plainBuffer[14:])
	return c
}

func (c *NativeConn) watchControl() {
	var b [1]byte
	// No business payload is allowed on the control stream after bootstrap.
	_, _ = c.control.Read(b[:])
	c.Close()
}

// OpenNative reads bootstrap over an already authenticated SS+ TCP stream.
// The UDP connection must use the same routing dialer and the same server.
// No application datagram is sent until bidirectional reachability is proven.
func (c *Client) OpenNative(ctx context.Context, control, udp net.Conn) (*NativeConn, error) {
	// A maximum-size datagram needs up to 60 wire packets. Avoid overflowing
	// the small Windows default socket buffer during scheduler/race pauses.
	if socket, ok := udp.(interface{ SetReadBuffer(int) error }); ok {
		_ = socket.SetReadBuffer(256 * 1024)
	}
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	stop := context.AfterFunc(ctx, func() { control.Close(); udp.Close() })
	defer stop()
	if err := control.SetDeadline(deadline); err != nil {
		control.Close()
		udp.Close()
		return nil, err
	}
	var bootstrap [56]byte
	defer clear(bootstrap[:])
	if _, err := io.ReadFull(control, bootstrap[:]); err != nil {
		control.Close()
		udp.Close()
		return nil, err
	}
	if string(bootstrap[:8]) != "SSPUDP04" {
		control.Close()
		udp.Close()
		return nil, errNativePacket
	}
	p := newNativeConn(c.config, control, bootstrap[8:], true, &nativeBudget{limit: 512 * 1024})
	p.udp = udp
	p.reply = func(b []byte) error {
		n, err := udp.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		return err
	}
	go func() {
		defer p.Close()
		var packet [nativeMaxMTU + 1]byte
		for {
			n, err := udp.Read(packet[:])
			if err != nil {
				return
			}
			p.receive(packet[:n], "", nil)
		}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	retry := time.NewTicker(300 * time.Millisecond)
	defer retry.Stop()
	// The authenticated large probe proves both directions before enabling the
	// optional compact frame; ordinary probes also validate the base MTU.
	if string(bootstrap[8:16]) == "SSPMTU1!" {
		if err := p.sendLargeControl(nativeProbe, nil, p.reply); err != nil {
			p.Close()
			return nil, err
		}
	}
	for {
		if err := p.sendControl(nativeProbe, nil, p.reply, nativeMTU); err != nil {
			p.Close()
			return nil, err
		}
		select {
		case <-p.ready:
			if ctx.Err() != nil {
				p.Close()
				return nil, ctx.Err()
			}
			if err := control.SetDeadline(time.Time{}); err != nil {
				p.Close()
				return nil, err
			}
			go p.watchControl()
			return p, nil
		case <-ctx.Done():
			p.Close()
			return nil, ctx.Err()
		case <-p.done:
			return nil, net.ErrClosed
		case <-timer.C:
			p.Close()
			return nil, os.ErrDeadlineExceeded
		case <-retry.C:
		}
	}
}

func (c *NativeConn) sendControl(kind byte, token []byte, reply func([]byte) error, limit int) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	plain := c.plainBuffer[:32]
	clear(plain)
	plain[0] = kind
	copy(plain[1:17], token)
	packet, err := c.tx.sealLimit(c.writeBuffer[:0], plain, limit)
	if err != nil {
		return err
	}
	return reply(packet)
}

func (c *NativeConn) receive(packet []byte, source string, reply func([]byte) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return
	default:
	}
	p, seq, err := c.rx.open(c.readBuffer[:0], packet)
	if err != nil {
		return
	}
	now := time.Now()
	if isLargeControl(p, len(packet)) {
		p = p[:32]
	}
	if c.hub != nil {
		if p[0] == nativeConfirm && len(p) == 32 && (source == c.pending || source == c.source) && now.Before(c.pendingUntil) && bytes.Equal(p[1:17], c.token[:]) {
			c.source, c.reply = source, reply
			c.pending = ""
			c.last = now
			if len(packet) == nativeMaxMTU {
				c.pathMTU.Store(nativeMaxMTU)
			}
			_ = c.respondControl(nativeReady, nil, reply, len(packet))
			return
		}
		if source != c.source {
			if len(p) < 32 {
				return
			}
			if len(p) != 32 && p[0] != nativeData && p[0] != nativeCompact {
				return
			}
			if p[0] != nativeProbe && p[0] != nativeData && p[0] != nativeCompact {
				return
			}
			// Keep one outstanding challenge; a second source cannot churn it.
			if c.pending != "" && now.Before(c.pendingUntil) && source != c.pending {
				return
			}
			if c.pending != source || !now.Before(c.pendingUntil) {
				if _, err := rand.Read(c.token[:]); err != nil {
					return
				}
				c.pending, c.pendingUntil = source, now.Add(3*time.Second)
			}
			_ = c.respondControl(nativeChallenge, c.token[:], reply, len(packet))
			return
		}
		c.reply = reply
		if p[0] == nativeProbe && len(p) == 32 {
			c.last = now
			if len(packet) == nativeMaxMTU && c.pathMTU.Load() != nativeMaxMTU {
				if _, err := rand.Read(c.token[:]); err != nil {
					return
				}
				c.pending, c.pendingUntil = source, now.Add(3*time.Second)
				_ = c.respondControl(nativeChallenge, c.token[:], reply, len(packet))
				return
			}
			_ = c.respondControl(nativeReady, nil, reply, len(packet))
			return
		}
	} else {
		if p[0] == nativeChallenge && len(p) == 32 {
			_ = c.respondControl(nativeConfirm, p[1:17], c.reply, len(packet))
			return
		}
		if p[0] == nativeReady && len(p) == 32 {
			if len(packet) == nativeMaxMTU {
				c.pathMTU.Store(nativeMaxMTU)
			}
			c.readyOnce.Do(func() { close(c.ready) })
			return
		}
	}
	if p[0] != nativeData && p[0] != nativeCompact {
		return
	}
	c.last = now
	var data []byte
	if p[0] == nativeCompact {
		if c.pathMTU.Load() != nativeMaxMTU || len(p) < 7 {
			return
		}
		size := int(binary.BigEndian.Uint16(p[1:3]))
		if size < 4 || len(p) != max(32, size+3) || !c.assembly.budget.take(size) {
			return
		}
		data = append([]byte(nil), p[3:3+size]...)
	} else {
		data = c.assembly.feed(p, seq, now)
	}
	if data == nil {
		return
	}
	r := bytes.NewReader(data)
	address, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil || !address.IsValid() || address.Port == 0 || r.Len() > 65507 {
		c.assembly.budget.release(len(data))
		return
	}
	message := nativeMessage{data: data, address: address, offset: len(data) - r.Len()}
	select {
	case c.queue <- message:
	default:
		c.assembly.budget.release(len(data))
	}
}

func (c *NativeConn) readMessage() (nativeMessage, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.readDeadline, c.changed
		c.mu.Unlock()
		select {
		case <-c.done:
			return nativeMessage{}, net.ErrClosed
		default:
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nativeMessage{}, os.ErrDeadlineExceeded
		}
		// A queued message needs no timer or boxed net.Addr allocation.
		select {
		case message := <-c.queue:
			return message, nil
		default:
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case message := <-c.queue:
			if timer != nil {
				timer.Stop()
			}
			return message, nil
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return nativeMessage{}, net.ErrClosed
		case <-timeout:
			return nativeMessage{}, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}
func (c *NativeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	message, err := c.readMessage()
	if err != nil {
		return 0, nil, err
	}
	defer c.assembly.budget.release(len(message.data))
	n := copy(p, message.data[message.offset:])
	if n < len(message.data)-message.offset {
		return n, message.address, io.ErrShortBuffer
	}
	return n, message.address, nil
}
func (c *NativeConn) ReadPacket(buffer *B.Buffer) (M.Socksaddr, error) {
	message, err := c.readMessage()
	if err != nil {
		return M.Socksaddr{}, err
	}
	defer c.assembly.budget.release(len(message.data))
	n := copy(buffer.FreeBytes(), message.data[message.offset:])
	if n < len(message.data)-message.offset {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	buffer.Truncate(buffer.Len() + n)
	return message.address, nil
}
func (c *NativeConn) WritePacket(buffer *B.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), destination)
	return err
}
func (c *NativeConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	if len(payload) > 65507 {
		return 0, io.ErrShortBuffer
	}
	destination := M.SocksaddrFromNet(address)
	if !destination.IsValid() || destination.Port == 0 {
		return 0, errNativePacket
	}
	c.mu.Lock()
	c.last = time.Now()
	reply, deadline := c.reply, c.writeDeadline
	c.mu.Unlock()
	if reply == nil {
		return 0, errNativePacket
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	c.addressBuffer.Reset()
	if err := M.SocksaddrSerializer.WriteAddress(c.addressBuffer, destination); err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(c.addressBuffer.Extend(2), destination.Port)
	addressLen := c.addressBuffer.Len()
	if used, err := c.writeCompact(c.addressBuffer.Bytes(), payload, reply); used {
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}
	messageID := c.tx.seq + 1
	plain := c.plainBuffer[:]
	plain[0] = nativeData
	binary.BigEndian.PutUint64(plain[1:], messageID)
	binary.BigEndian.PutUint32(plain[9:], uint32(addressLen+len(payload)))
	// Copy directly into fragments instead of first copying the whole datagram.
	for index, offset := 0, 0; index == 0 || offset < len(payload); index++ {
		n := 0
		if index == 0 {
			n = addressLen
		}
		copied := copy(plain[14+n:], payload[offset:])
		n += copied
		plain[13] = byte(index)
		clear(plain[14+n : max(32, 14+n)])
		packet, err := c.tx.seal(c.writeBuffer[:0], plain[:max(32, 14+n)])
		if err != nil {
			return 0, err
		}
		if err = reply(packet); err != nil {
			return 0, err
		}
		offset += copied
	}
	return len(payload), nil
}
func (c *NativeConn) Close() error {
	c.once.Do(func() {
		c.control.Close()
		if c.udp != nil {
			c.udp.Close()
		}
		c.mu.Lock()
		close(c.done)
		c.assembly.clear()
		for {
			select {
			case m := <-c.queue:
				c.assembly.budget.release(len(m.data))
			default:
				c.mu.Unlock()
				if c.hub != nil {
					c.hub.remove(c)
				}
				return
			}
		}
	})
	return nil
}
func (c *NativeConn) LocalAddr() net.Addr {
	if c.udp != nil {
		return c.udp.LocalAddr()
	}
	return c.control.LocalAddr()
}
func (c *NativeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = t, t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	if c.udp != nil {
		return c.udp.SetWriteDeadline(t)
	}
	return nil
}
func (c *NativeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *NativeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	if c.udp != nil {
		return c.udp.SetWriteDeadline(t)
	}
	return nil
}

// NativeService is shared by every source endpoint of one SS+ inbound.
// Only authenticated TCP handshakes create sessions. Unknown UDP is discarded.
type NativeService struct {
	config   *Config
	mu       sync.Mutex
	sessions map[[16]byte]*NativeConn
	budget   nativeBudget
	done     chan struct{}
	started  bool
	closed   bool
}

func (s *Server) NewNativeService() *NativeService {
	return &NativeService{config: s.config, sessions: make(map[[16]byte]*NativeConn), budget: nativeBudget{limit: 16 * 1024 * 1024}, done: make(chan struct{})}
}
func (s *NativeService) Accept(control net.Conn) (*NativeConn, error) {
	var bootstrap [56]byte
	defer clear(bootstrap[:])
	copy(bootstrap[:8], "SSPUDP04")
	if _, err := rand.Read(bootstrap[8:]); err != nil {
		return nil, err
	}
	// Capability hint is authenticated by the TCP stream. The remaining
	// 40 random bytes retain the full 256-bit secret plus a random salt.
	copy(bootstrap[8:16], "SSPMTU1!")
	c := newNativeConn(s.config, control, bootstrap[8:], false, &s.budget)
	c.hub = s
	s.mu.Lock()
	if s.closed || len(s.sessions) >= 512 || s.sessions[c.rx.id] != nil {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.sessions[c.rx.id] = c
	if !s.started {
		s.started = true
		go s.sweep()
	}
	s.mu.Unlock()
	if err := writeFull(control, bootstrap[:]); err != nil {
		c.Close()
		return nil, err
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, err
	}
	go c.watchControl()
	return c, nil
}
func (s *NativeService) Receive(packet []byte, source string, reply func([]byte) error) {
	if len(packet) < nativeHeader+nativeEnvelope+17 || len(packet) > nativeMaxMTU || packet[0]&0xe0 != 0x40 {
		return
	}
	var id [16]byte
	copy(id[:], packet[nativeCIDOffset:nativePNOffset])
	s.mu.Lock()
	c := s.sessions[id]
	s.mu.Unlock()
	if c != nil {
		c.receive(packet, source, reply)
	}
}
func (s *NativeService) remove(c *NativeConn) {
	s.mu.Lock()
	delete(s.sessions, c.rx.id)
	s.mu.Unlock()
}
func (s *NativeService) snapshot() []*NativeConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]*NativeConn, 0, len(s.sessions))
	for _, c := range s.sessions {
		all = append(all, c)
	}
	return all
}
func (s *NativeService) sweep() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			for _, c := range s.snapshot() {
				c.mu.Lock()
				c.assembly.expire(now)
				idle := now.Sub(c.last) >= 60*time.Second
				c.mu.Unlock()
				if idle {
					c.Close()
				}
			}
		case <-s.done:
			return
		}
	}
}
func (s *NativeService) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	s.mu.Unlock()
	for _, c := range s.snapshot() {
		c.Close()
	}
	return nil
}
