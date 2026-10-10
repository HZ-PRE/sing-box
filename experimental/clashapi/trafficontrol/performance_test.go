package trafficontrol

import (
	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"sync"
	"testing"
)

func TestBoundCounterSurvivesReset(t *testing.T) {
	m := NewManager()
	counter := loadCounter(&m.outboundUploadTotal, "node")
	counter.Add(17)
	m.ResetStatistic()
	counter.Add(5)
	up, _ := m.OutboundUsage("node")
	if up != 5 {
		t.Fatalf("active connection lost after reset: %d", up)
	}
	if allocations := testing.AllocsPerRun(1000, func() { m.PushOutboundUploaded("node", 1) }); allocations != 0 {
		t.Fatalf("hot counter allocates: %v", allocations)
	}
}

type testTracker struct{ metadata TrackerMetadata }

func (t *testTracker) Metadata() *TrackerMetadata { return &t.metadata }
func (t *testTracker) Close() error               { return nil }

func TestClosedHistoryBoundAndWorkingState(t *testing.T) {
	m := NewManager()
	m.SetClosedConnectionsLimit(2)
	for i := 0; i < 4; i++ {
		tracker := &testTracker{TrackerMetadata{ID: uuid.Must(uuid.NewV4()), Metadata: adapter.InboundContext{Domain: "example.com", SniffContext: make([]byte, 65536)}}}
		m.Join(tracker)
		m.Leave(tracker)
	}
	history := m.ClosedConnections()
	if len(history) != 2 || history[0].Metadata.SniffContext != nil || history[0].Metadata.Domain != "example.com" {
		t.Fatal("history not compacted/bounded")
	}
	m.SetClosedConnectionsLimit(0)
	if len(m.ClosedConnections()) != 0 {
		t.Fatal("history not cleared")
	}
}

func TestConcurrentMemorySnapshot(t *testing.T) {
	m := NewManager()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if m.Memory() == 0 || m.Snapshot().Memory == 0 {
					t.Error("empty sample")
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkOutboundCounter(b *testing.B) {
	m := NewManager()
	counter := loadCounter(&m.outboundUploadTotal, "node")
	b.Run("lookup", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m.PushOutboundUploaded("node", 4096)
		}
	})
	b.Run("bound", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			counter.Add(4096)
		}
	})
}
