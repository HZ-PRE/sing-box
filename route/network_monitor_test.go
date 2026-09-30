package route

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/x/list"
)

type queuedNetworkMonitor struct {
	callbacks list.List[tun.NetworkUpdateCallback]
}

func (*queuedNetworkMonitor) Start() error { return nil }
func (*queuedNetworkMonitor) Close() error { return nil }
func (m *queuedNetworkMonitor) RegisterCallback(cb tun.NetworkUpdateCallback) *list.Element[tun.NetworkUpdateCallback] {
	return m.callbacks.PushBack(cb)
}
func (m *queuedNetworkMonitor) UnregisterCallback(e *list.Element[tun.NetworkUpdateCallback]) {
	m.callbacks.Remove(e)
}

func TestNetworkNotificationsSerializedAndDiscardedAfterClose(t *testing.T) {
	upstream := &queuedNetworkMonitor{}
	m := serializeNetworkMonitor(upstream)
	var active, calls atomic.Int32
	element := m.RegisterCallback(func() {
		if active.Add(1) != 1 {
			t.Error("concurrent interface callback")
		}
		runtime.Gosched()
		calls.Add(1)
		active.Add(-1)
	})
	// Simulate the OS snapshotting a callback before dispatching it asynchronously.
	queued := upstream.callbacks.Array()[0]
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); queued() }()
	}
	wg.Wait()
	if calls.Load() != 64 {
		t.Fatal("network update lost")
	}
	m.UnregisterCallback(element)
	queued()
	if calls.Load() != 64 {
		t.Fatal("queued callback fired after unregister")
	}
	m.RegisterCallback(func() { calls.Add(1) })
	queued = upstream.callbacks.Array()[0]
	m.Close()
	queued()
	if calls.Load() != 64 {
		t.Fatal("queued callback fired after shutdown")
	}
}
