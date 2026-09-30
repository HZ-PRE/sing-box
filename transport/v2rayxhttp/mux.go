package xhttp

import (
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
)

type XmuxConn interface {
	IsClosed() bool
	Close() error
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	OpenUsage    atomic.Int32
	sessions     int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
	manager      *XmuxManager
}

type XmuxManager struct {
	options     option.V2RayXHTTPXmuxOptions
	concurrency int32
	connections int32
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	mtx         sync.Mutex
	closed      bool
}

func NewXmuxManager(options option.V2RayXHTTPXmuxOptions, newConnFunc func() XmuxConn) *XmuxManager {
	return &XmuxManager{
		options:     options,
		concurrency: options.GetNormalizedMaxConcurrency().Rand(),
		connections: options.GetNormalizedMaxConnections().Rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
		manager:   m,
		sessions:  1,
	}
	if x := m.options.GetNormalizedCMaxReuseTimes().Rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.options.GetNormalizedHMaxRequestTimes().Rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.options.GetNormalizedHMaxReusableSecs().Rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	xmuxClient.OpenUsage.Store(1)
	return xmuxClient
}

func (c *XmuxClient) expired() bool {
	return c.XmuxConn.IsClosed() || c.leftUsage == 0 || c.LeftRequests.Load() <= 0 ||
		(!c.UnreusableAt.IsZero() && time.Now().After(c.UnreusableAt))
}

// Retain requires an existing lease. Each in-flight upload keeps its transport
// alive even when the session switches to a fresh multiplexed client.
func (c *XmuxClient) Retain() { c.OpenUsage.Add(1) }

func (c *XmuxClient) Release() {
	c.release(true)
}

func (c *XmuxClient) ReleaseReference() {
	c.release(false)
}

func (c *XmuxClient) release(session bool) {
	m := c.manager
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if session {
		c.sessions--
	}
	if c.OpenUsage.Add(-1) == 0 && c.expired() {
		for i, candidate := range m.xmuxClients {
			if candidate == c {
				m.remove(i)
				break
			}
		}
	}
}

func (m *XmuxManager) remove(i int) {
	m.xmuxClients[i].XmuxConn.Close()
	copy(m.xmuxClients[i:], m.xmuxClients[i+1:])
	m.xmuxClients[len(m.xmuxClients)-1] = nil
	m.xmuxClients = m.xmuxClients[:len(m.xmuxClients)-1]
}

func (m *XmuxManager) Close() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.closed = true
	for _, c := range m.xmuxClients {
		c.XmuxConn.Close()
	}
	m.xmuxClients = nil
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if m.closed || ctx.Err() != nil {
		return nil
	}
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.OpenUsage.Load() == 0 && xmuxClient.expired() {
			m.remove(i)
		} else {
			i++
		}
	}
	if len(m.xmuxClients) == 0 {
		return m.newXmuxClient()
	}
	if m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		return m.newXmuxClient()
	}
	// Reservoir sampling avoids allocating a temporary slice and crypto RNG
	// objects for non-security-sensitive connection scheduling.
	var selected *XmuxClient
	count := 0
	for _, c := range m.xmuxClients {
		if c.expired() || (m.concurrency > 0 && c.sessions >= m.concurrency) {
			continue
		}
		count++
		if rand.IntN(count) == 0 {
			selected = c
		}
	}
	if selected == nil {
		return m.newXmuxClient()
	}
	if selected.leftUsage > 0 {
		selected.leftUsage--
	}
	selected.OpenUsage.Add(1)
	selected.sessions++
	return selected
}
