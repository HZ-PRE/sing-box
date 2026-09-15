package monitoring

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service/pause"
)

func newTestMonitor(t *testing.T) *OutboundMonitoring {
	t.Helper()
	m, err := NewOutboundMonitoring(pause.WithDefaultManager(context.Background()), log.NewNOPFactory().Logger(), option.MonitoringOptions{
		Workers: 1, Interval: badoption.Duration(10 * time.Millisecond), IdleTimeout: badoption.Duration(50 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestMonitoringConcurrentTouchAndClose(t *testing.T) {
	for range 100 {
		m := newTestMonitor(t)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 30 {
					m.Touch()
				}
			}()
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		m.Touch()
		m.access.Lock()
		stopped := !m.started && m.mainTicker == nil && !m.workersRunning.Load()
		m.access.Unlock()
		if !stopped {
			t.Fatal("closed monitoring restarted its scheduler")
		}
	}
}

func TestMonitoringIdleWake(t *testing.T) {
	m := newTestMonitor(t)
	for range 3 {
		deadline := time.Now().Add(3 * time.Second)
		for {
			m.access.Lock()
			idle := m.mainTicker == nil
			m.access.Unlock()
			if idle {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("scheduler did not stop while idle")
			}
			time.Sleep(time.Millisecond)
		}
		m.Touch()
		m.access.Lock()
		awake := m.mainTicker != nil && time.Since(m.lastActive.Load()) < m.idleTimeout
		m.access.Unlock()
		if !awake {
			t.Fatal("traffic did not wake and refresh the idle scheduler")
		}
	}
}
