package monitoring

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/sdm/ipinfo"
	M "github.com/sagernet/sing/common/metadata"
)

type ipTestOutbound struct {
	outbound.Adapter
	address      string
	queries      atomic.Int32
	queryStarted chan struct{}
	testBlock    chan struct{}
}

func (o *ipTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if o.testBlock != nil {
		select {
		case o.queryStarted <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if destination.Fqdn == "latency.test" {
		return (&net.Dialer{}).DialContext(ctx, network, o.address)
	}
	o.queries.Add(1)
	if o.queryStarted != nil {
		select {
		case o.queryStarted <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, errors.New("IP provider unavailable in test")
}
func (o *ipTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func newIPTestMonitor(t *testing.T) (*OutboundMonitoring, *ipTestOutbound) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := &ipTestOutbound{Adapter: outbound.NewAdapter("test", "node", []string{"tcp"}, nil), address: server.Listener.Addr().String()}
	m := &OutboundMonitoring{ctx: ctx, cancel: cancel, history: urltest.NewHistoryStorage(), ipInfoQueue: make(chan ipInfoTask, 2), logger: log.NewNOPFactory().Logger(), urls: []string{"http://latency.test/"}, urlTestTimeout: time.Second,
		outbounds: map[string]*outboundState{"node": {outbound: out}}}
	return m, out
}

func TestNodeIPPermissionDoesNotDisableLatency(t *testing.T) {
	m, out := newIPTestMonitor(t)
	for _, enabled := range []bool{false, true, false} {
		m.SetNodeIPInfoEnabled(enabled)
		before := out.queries.Load()
		history, err := m.tester(m.ctx, "node")
		if err != nil || history.Delay >= TimeoutDelay {
			t.Fatalf("latency failed: %v", err)
		}
		if out.queries.Load() != before {
			t.Fatal("latency probe performed IP lookup")
		}
		m.queueIPInfo("node")
		if (len(m.ipInfoQueue) > 0) != enabled {
			t.Fatalf("IP permission ignored: %v", enabled)
		}
		if enabled {
			m.fetchIPInfo(<-m.ipInfoQueue)
		}
	}
}

func TestLatencyPublishesBeforeBlockedIPAndRevocationCancels(t *testing.T) {
	m, out := newIPTestMonitor(t)
	out.queryStarted = make(chan struct{}, 1)
	m.SetNodeIPInfoEnabled(true)
	m.workerWG.Add(1)
	go m.ipInfoWorkerLoop()
	t.Cleanup(func() { m.cancel(); m.workerWG.Wait() })
	done := make(chan struct{})
	go func() { m.executeTask(&testTask{outboundTag: "node"}); close(done) }()
	select {
	case <-out.queryStarted:
	case <-time.After(time.Second):
		t.Fatal("IP did not start")
	}
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("IP blocked latency result")
	}
	if m.OutboundHistory("node").Time.IsZero() {
		t.Fatal("latency not published")
	}
	for i := 0; i < 10; i++ {
		m.queueIPInfo("node")
	}
	if len(m.ipInfoQueue) != 0 {
		t.Fatal("duplicate IP requests queued")
	}
	m.SetNodeIPInfoEnabled(false)
	deadline := time.Now().Add(time.Second)
	for {
		state := m.outbounds["node"]
		state.mu.Lock()
		pending := state.ipPending
		state.mu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("IP not cancelled")
		}
		time.Sleep(time.Millisecond)
	}
	if m.OutboundHistory("node").Delay >= TimeoutDelay {
		t.Fatal("IP cancellation damaged latency")
	}
}

func TestStaleIPTaskDoesNotRunAfterNetworkChange(t *testing.T) {
	m, out := newIPTestMonitor(t)
	m.SetNodeIPInfoEnabled(true)
	m.queueIPInfo("node")
	task := <-m.ipInfoQueue
	m.invalidateCycleTargets()
	m.fetchIPInfo(task)
	if out.queries.Load() != 0 {
		t.Fatal("stale IP task issued network requests")
	}
}

func TestPriorityWorkerDoesNotWaitForNormalProbe(t *testing.T) {
	m, out := newIPTestMonitor(t)
	m.normalQueue = make(chan *testTask, 1)
	m.priorityQueue = make(chan *testTask, 1)
	slow := &ipTestOutbound{Adapter: outbound.NewAdapter("test", "slow", []string{"tcp"}, nil), queryStarted: make(chan struct{}, 1)}
	// A blocked node keeps the ordinary worker occupied until cancellation.
	m.outbounds["slow"] = &outboundState{outbound: slow}
	slow.testBlock = make(chan struct{})
	m.workerWG.Add(2)
	go m.workerLoop()
	go m.priorityWorkerLoop()
	t.Cleanup(func() { m.cancel(); m.workerWG.Wait() })
	m.normalQueue <- &testTask{outboundTag: "slow"}
	select {
	case <-slow.queryStarted:
	case <-time.After(time.Second):
		t.Fatal("normal probe not started")
	}
	results := make(chan testOutcome, 1)
	m.priorityQueue <- &testTask{outboundTag: "node", priority: true, resultCh: results}
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatal(r.err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("priority probe waited for normal probe")
	}
	if out.queries.Load() != 0 {
		t.Fatal("IP permission off")
	}
}

func TestIPMetadataCannotOverwriteLatencyOrSurviveInvalidation(t *testing.T) {
	m, _ := newIPTestMonitor(t)
	m.SetNodeIPInfoEnabled(true)
	state := m.outbounds["node"]
	state.history.Delay = 123
	state.history.Time = time.Now()
	state.ipRefresh = true
	stamp := state.history.Time
	task := ipInfoTask{tag: "node", permission: m.ipInfoContext}
	m.applyIPInfo(task, m.ctx, &ipinfo.IpInfo{IP: "192.0.2.1"})
	if state.history.Delay != 123 || !state.history.Time.Equal(stamp) || state.history.IpInfo.IP != "192.0.2.1" || state.ipRefresh {
		t.Fatal("metadata corrupted latency")
	}
	m.invalidateCycleTargets()
	m.applyIPInfo(task, m.ctx, &ipinfo.IpInfo{IP: "192.0.2.2"})
	if state.history.IpInfo.IP != "192.0.2.1" {
		t.Fatal("old network result accepted")
	}
	state.invalid = false
	task.version = state.ipVersion
	m.SetNodeIPInfoEnabled(false)
	m.applyIPInfo(task, m.ctx, &ipinfo.IpInfo{IP: "192.0.2.3"})
	if state.history.IpInfo.IP != "192.0.2.1" {
		t.Fatal("revoked permission result accepted")
	}
}

func TestRetryHistoryRejectsUnverifiedAndStaleNodes(t *testing.T) {
	m, _ := newIPTestMonitor(t)
	m.mainInterval = time.Minute
	state := m.outbounds["node"]
	state.history.Delay = 25
	state.history.Time = time.Now()
	if _, h := m.HealthyOutboundHistory("node"); h == nil {
		t.Fatal("healthy node rejected")
	}
	state.from_cache = true
	if _, h := m.HealthyOutboundHistory("node"); h != nil {
		t.Fatal("cached node accepted")
	}
	state.from_cache = false
	state.invalid = true
	if _, h := m.HealthyOutboundHistory("node"); h != nil {
		t.Fatal("invalid node accepted")
	}
	state.invalid = false
	state.history.Time = time.Now().Add(-2 * time.Minute)
	if _, h := m.HealthyOutboundHistory("node"); h != nil {
		t.Fatal("stale node accepted")
	}
}
