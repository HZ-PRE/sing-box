package trafficontrol

import (
	"sync"
	"testing"
)

func TestOutboundAccountingConcurrentAndReset(t *testing.T) {
	m := NewManager()
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 1000; j++ {
				m.PushOutboundUploaded("node", 7)
				m.PushOutboundDownloaded("node", 11)
			}
		}()
	}
	workers.Wait()
	if up, down := m.OutboundUsage("node"); up != 112000 || down != 176000 {
		t.Fatalf("lost concurrent traffic: %d/%d", up, down)
	}
	m.ResetStatistic()
	if up, down := m.OutboundUsage("node"); up != 0 || down != 0 {
		t.Fatal("reset retained traffic")
	}
	m.PushOutboundUploaded("node", 3)
	m.PushOutboundDownloaded("other", 5)
	if up, down := m.OutboundUsage("node"); up != 3 || down != 0 {
		t.Fatal("post-reset counter incorrect")
	}
	if up, down := m.OutboundUsage("other"); up != 0 || down != 5 {
		t.Fatal("outbound counters overlap")
	}
}

func BenchmarkOutboundAccounting(b *testing.B) {
	m := NewManager()
	m.PushOutboundUploaded("node", 0)
	m.PushOutboundDownloaded("node", 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.PushOutboundUploaded("node", 16384)
		m.PushOutboundDownloaded("node", 16384)
	}
}

func TestConcurrentSnapshots(t *testing.T) {
	m := NewManager()
	m.PushUploaded(7)
	m.PushDownloaded(11)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 10; j++ {
				snapshot := m.Snapshot()
				if snapshot.Upload != 7 || snapshot.Download != 11 || snapshot.Memory == 0 {
					t.Error("invalid concurrent snapshot")
				}
			}
		}()
	}
	workers.Wait()
}
