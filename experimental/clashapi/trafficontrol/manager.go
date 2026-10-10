package trafficontrol

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/compatible"
	"github.com/sagernet/sing-box/common/memorystats"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/x/list"

	"github.com/gofrs/uuid/v5"
)

type ConnectionEventType int

const (
	ConnectionEventNew ConnectionEventType = iota
	ConnectionEventUpdate
	ConnectionEventClosed
)

type ConnectionEvent struct {
	Type          ConnectionEventType
	ID            uuid.UUID
	Metadata      *TrackerMetadata
	UplinkDelta   int64
	DownlinkDelta int64
	ClosedAt      time.Time
}

const closedConnectionsLimit = 1000

type Manager struct {
	uploadTotal             atomic.Int64
	downloadTotal           atomic.Int64
	outboundUploadTotal     sync.Map
	outboundDownloadTotal   sync.Map
	connections             compatible.Map[uuid.UUID, Tracker]
	closedConnectionsAccess sync.Mutex
	closedConnections       list.List[TrackerMetadata]
	closedLimit             int

	eventSubscriber *observable.Subscriber[ConnectionEvent]
}

func NewManager() *Manager {
	return &Manager{closedLimit: closedConnectionsLimit}
}

// SetClosedConnectionsLimit keeps the default when omitted; zero disables history.
func (m *Manager) SetClosedConnectionsLimit(limit int) {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	m.closedLimit = max(0, limit)
	for m.closedConnections.Len() > m.closedLimit {
		m.closedConnections.PopFront()
	}
}

func (m *Manager) SetEventHook(subscriber *observable.Subscriber[ConnectionEvent]) {
	m.eventSubscriber = subscriber
}

func (m *Manager) Join(c Tracker) {
	metadata := c.Metadata()
	m.connections.Store(metadata.ID, c)
	if m.eventSubscriber != nil {
		m.eventSubscriber.Emit(ConnectionEvent{
			Type:     ConnectionEventNew,
			ID:       metadata.ID,
			Metadata: metadata,
		})
	}
}

func (m *Manager) Leave(c Tracker) {
	metadata := c.Metadata()
	_, loaded := m.connections.LoadAndDelete(metadata.ID)
	if loaded {
		closedAt := time.Now()
		metadata.ClosedAt = closedAt
		metadataCopy := metadata.closedSnapshot()
		m.closedConnectionsAccess.Lock()
		if m.closedLimit > 0 && m.closedConnections.Len() >= m.closedLimit {
			m.closedConnections.PopFront()
		}
		if m.closedLimit > 0 {
			m.closedConnections.PushBack(metadataCopy)
		}
		m.closedConnectionsAccess.Unlock()
		if m.eventSubscriber != nil {
			m.eventSubscriber.Emit(ConnectionEvent{
				Type:     ConnectionEventClosed,
				ID:       metadata.ID,
				Metadata: &metadataCopy,
				ClosedAt: closedAt,
			})
		}
	}
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTotal.Add(size)
}

func (m *Manager) PushOutboundUploaded(outbound string, size int64) {
	loadCounter(&m.outboundUploadTotal, outbound).Add(size)
}

func (m *Manager) PushOutboundDownloaded(outbound string, size int64) {
	loadCounter(&m.outboundDownloadTotal, outbound).Add(size)
}

func loadCounter(counters *sync.Map, outbound string) *atomic.Int64 {
	if value, ok := counters.Load(outbound); ok {
		return value.(*atomic.Int64)
	}
	value, _ := counters.LoadOrStore(outbound, new(atomic.Int64))
	return value.(*atomic.Int64)
}

// Memory samples once per second, independently of connection-list subscribers.
// This reports Go-managed committed memory, not process RSS.
func (m *Manager) Memory() uint64 {
	return memorystats.Inuse()
}

func (m *Manager) Total() (up int64, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) OutboundUsage(outbound string) (up int64, down int64) {
	if vUp, ok := m.outboundUploadTotal.Load(outbound); ok {
		up = vUp.(*atomic.Int64).Load()
	}
	if vDown, ok := m.outboundDownloadTotal.Load(outbound); ok {
		down = vDown.(*atomic.Int64).Load()
	}
	return
}

func (m *Manager) ConnectionsLen() int {
	return m.connections.Len()
}

func (m *Manager) Connections() []*TrackerMetadata {
	var connections []*TrackerMetadata
	m.connections.Range(func(_ uuid.UUID, value Tracker) bool {
		connections = append(connections, value.Metadata())
		return true
	})
	return connections
}

func (m *Manager) ClosedConnections() []*TrackerMetadata {
	m.closedConnectionsAccess.Lock()
	values := m.closedConnections.Array()
	m.closedConnectionsAccess.Unlock()
	if len(values) == 0 {
		return nil
	}
	connections := make([]*TrackerMetadata, len(values))
	for i := range values {
		connections[i] = &values[i]
	}
	return connections
}

func (m *Manager) Connection(id uuid.UUID) Tracker {
	connection, loaded := m.connections.Load(id)
	if !loaded {
		return nil
	}
	return connection
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []Tracker
	m.connections.Range(func(_ uuid.UUID, value Tracker) bool {
		if value.Metadata().OutboundType != C.TypeDNS {
			connections = append(connections, value)
		}
		return true
	})

	return &Snapshot{
		Upload:      m.uploadTotal.Load(),
		Download:    m.downloadTotal.Load(),
		Connections: connections,
		Memory:      m.Memory(),
	}
}

func (m *Manager) ResetStatistic() {
	m.uploadTotal.Store(0)
	m.downloadTotal.Store(0)
	m.outboundUploadTotal.Range(func(key, value any) bool {
		value.(*atomic.Int64).Store(0)
		return true
	})
	m.outboundDownloadTotal.Range(func(key, value any) bool {
		value.(*atomic.Int64).Store(0)
		return true
	})
}

func (m *Manager) Clear() {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	m.closedConnections.Init()
}

type Snapshot struct {
	Download    int64
	Upload      int64
	Connections []Tracker
	Memory      uint64
}

func (s *Snapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"downloadTotal": s.Download,
		"uploadTotal":   s.Upload,
		"connections":   common.Map(s.Connections, func(t Tracker) *TrackerMetadata { return t.Metadata() }),
		"memory":        s.Memory,
	})
}
