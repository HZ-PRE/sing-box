package ssplus

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	maxHandshakeBytes    = 32 * 1024
	maxPendingHandshakes = 128
	maxHandshakeDuration = 10 * time.Second
)

var errHandshakeLimit = errors.New("ssplus: authentication resource limit")

// This wrapper is installed before ticket decoding, including its read-ahead.
// Once authentication succeeds it becomes a transparent connection wrapper.
type handshakeGuard struct {
	net.Conn
	remaining         int
	active            bool // accessed only by the synchronous handshake reader
	mu                sync.Mutex
	finished, expired bool
	timer             *time.Timer
}

func newHandshakeGuard(conn net.Conn, timeout time.Duration) *handshakeGuard {
	g := &handshakeGuard{Conn: conn, remaining: maxHandshakeBytes, active: true}
	// A close timer preserves a caller's shorter read/write deadlines.
	g.timer = time.AfterFunc(timeout, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !g.finished {
			g.expired = true
			_ = g.Conn.Close()
		}
	})
	return g
}

func (g *handshakeGuard) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !g.active {
		return g.Conn.Read(p)
	}
	if g.remaining == 0 {
		return 0, errHandshakeLimit
	}
	n, err := g.Conn.Read(p[:min(len(p), g.remaining)])
	g.remaining -= n
	return n, err
}

func (g *handshakeGuard) finish() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finished = true
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil // Do not retain the timer/closure for a long-lived proxy connection.
	}
	g.active = false
	return !g.expired
}
