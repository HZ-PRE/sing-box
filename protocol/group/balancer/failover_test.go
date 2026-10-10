package balancer

import (
	stdbufio "bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type testNode struct {
	outbound.Adapter
	address       string
	delay         atomic.Int64
	failed        atomic.Bool
	businessDials atomic.Int32
	packetHealthy atomic.Bool
	packetDials   atomic.Int32
}

func (o *testNode) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.Port == 80 {
		o.businessDials.Add(1)
	}
	if o.failed.Load() {
		return nil, errors.New("node offline")
	}
	timer := time.NewTimer(time.Duration(o.delay.Load()) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	return (&net.Dialer{}).DialContext(ctx, network, o.address)
}
func (o *testNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	o.packetDials.Add(1)
	if o.packetHealthy.Load() {
		return net.ListenPacket("udp", "127.0.0.1:0")
	}
	return nil, errors.New("node UDP offline")
}

type testOutbounds struct {
	adapter.OutboundManager
	items []adapter.Outbound
}

func (m *testOutbounds) Outbounds() []adapter.Outbound { return m.items }
func (m *testOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	for _, o := range m.items {
		if o.Tag() == tag {
			return o, true
		}
	}
	return nil, false
}

type testEndpoints struct{ adapter.EndpointManager }

func (*testEndpoints) Endpoints() []adapter.Endpoint { return nil }

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("selection did not converge")
}

// Real monitoring workers, HTTP probes and connection manager, with controllable
// local dialers. No Internet/server credentials or ten-minute timer is required.
func newFailoverFixture(t *testing.T, intervals ...time.Duration) (context.Context, *monitoring.OutboundMonitoring, []*testNode, *Balancer, *Balancer) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager := &testOutbounds{}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &testEndpoints{})
	logger := log.NewNOPFactory().Logger()
	connections := route.NewConnectionManager(logger)
	ctx = service.ContextWith[adapter.ConnectionManager](ctx, connections)
	interval := time.Hour
	if len(intervals) > 0 {
		interval = intervals[0]
	}
	m, err := monitoring.NewOutboundMonitoring(ctx, logger, option.MonitoringOptions{
		URLs: []string{server.URL}, Interval: badoption.Duration(interval),
		URLTestTimeout: badoption.Duration(time.Second), DebounceWindow: badoption.Duration(time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx = service.ContextWithPtr(ctx, m)
	var nodes []*testNode
	for i, tag := range []string{"slow", "fast", "middle"} {
		node := &testNode{Adapter: outbound.NewAdapter("test", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), address: server.Listener.Addr().String()}
		node.delay.Store([]int64{220, 20, 100}[i])
		nodes = append(nodes, node)
		manager.items = append(manager.items, node)
	}
	makeGroup := func(tag string, members []string) *Balancer {
		o, err := NewLoadBalance(ctx, nil, logger, tag, option.BalancerOutboundOptions{Strategy: StrategyLowestDelay, Outbounds: members})
		if err != nil {
			t.Fatal(err)
		}
		b := o.(*Balancer)
		manager.items = append(manager.items, b)
		return b
	}
	child := makeGroup("region", []string{"slow", "fast"})
	parent := makeGroup("auto", []string{"middle", "region"})
	if err := m.Start(adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	for _, b := range []*Balancer{child, parent} {
		if err := b.Start(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Start(adapter.StartStatePostStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Close(); parent.Close(); m.Close(); connections.Close() })
	// Deliberately let all initial notifications finish before subscribing.
	eventually(t, func() bool {
		h := m.OutboundsHistory("")
		return h["slow"].Delay > 0 && h["fast"].Delay > 0 && h["middle"].Delay > 0
	})
	time.Sleep(10 * time.Millisecond)
	for _, b := range []*Balancer{child, parent} {
		if err := b.PostStart(); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, m, nodes, child, parent
}

func TestLowestDelayInitialSnapshotAndNestedUpdates(t *testing.T) {
	_, m, nodes, child, parent := newFailoverFixture(t)
	eventually(t, func() bool { return child.Now() == "fast" && parent.Now() == "region" })
	// Child remains on fast, but its new delay exceeds the other parent member.
	nodes[1].delay.Store(170)
	m.TestNow("fast")
	eventually(t, func() bool { return child.Now() == "fast" && parent.Now() == "middle" })
	nodes[1].delay.Store(10)
	m.TestNow("fast")
	eventually(t, func() bool { return parent.Now() == "region" })
}

func TestLowestDelayInboundFailureTriggersProbeAndRecovery(t *testing.T) {
	ctx, m, nodes, child, parent := newFailoverFixture(t)
	// Isolate traffic failure handling from the startup-snapshot regression.
	child.strategyFn.UpdateOutboundsInfo(m.OutboundsHistory(child.Tag()))
	parent.strategyFn.UpdateOutboundsInfo(m.OutboundsHistory(parent.Tag()))
	eventually(t, func() bool { return parent.Now() == "region" })
	nodes[1].failed.Store(true)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	closed := make(chan error, 1)
	parent.NewConnection(ctx, local, adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("127.0.0.1:80")}, func(err error) { closed <- err })
	remote.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := remote.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(stdbufio.NewReader(remote), nil)
	if err != nil {
		t.Fatalf("single connection did not recover via backup: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("HTTP status %d", response.StatusCode)
	}
	remote.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("recovered connection leaked")
	}
	// No manual test request here: the actual inbound failure must trigger it.
	eventually(t, func() bool { return child.Now() == "slow" && parent.Now() == "middle" })
	nodes[1].failed.Store(false)
	m.TestNow("fast")
	eventually(t, func() bool { return child.Now() == "fast" && parent.Now() == "region" })
}

func TestLowestDelayPacketFailureTriggersProbe(t *testing.T) {
	ctx, _, nodes, child, parent := newFailoverFixture(t)
	eventually(t, func() bool { return parent.Now() == "region" })
	nodes[1].failed.Store(true)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	closed := make(chan error, 1)
	parent.NewPacketConnection(ctx, bufio.NewPacketConn(conn), adapter.InboundContext{Network: N.NetworkUDP, Destination: M.ParseSocksaddr("127.0.0.1:53")}, func(err error) { closed <- err })
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("expected packet failure")
		}
	case <-time.After(time.Second):
		t.Fatal("packet connection did not finish")
	}
	eventually(t, func() bool { return child.Now() == "slow" && parent.Now() == "middle" })
}

func TestLowestDelayStableTiesAndTimeout(t *testing.T) {
	a := &testNode{Adapter: outbound.NewAdapter("test", "a", []string{N.NetworkTCP, N.NetworkUDP}, nil)}
	b := &testNode{Adapter: outbound.NewAdapter("test", "b", []string{N.NetworkTCP, N.NetworkUDP}, nil)}
	s := NewLowestDelay([]adapter.Outbound{a, b}, option.BalancerOutboundOptions{})
	s.UpdateOutboundsInfo(nil)
	if s.Now() != "a" {
		t.Fatal("untested nodes must keep configured order")
	}
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": {Delay: 100}, "b": {Delay: 20}})
	if s.Now() != "b" {
		t.Fatal("not lowest delay")
	}
	s.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": {Delay: 100}, "b": {Delay: monitoring.TimeoutDelay}})
	if s.Now() != "a" {
		t.Fatal("timeout node retained")
	}
}

func TestLowestDelayPeriodicFailureAndRecovery(t *testing.T) {
	_, _, nodes, child, parent := newFailoverFixture(t, 100*time.Millisecond)
	eventually(t, func() bool { return child.Now() == "fast" && parent.Now() == "region" })
	nodes[1].failed.Store(true)
	eventually(t, func() bool { return child.Now() == "slow" && parent.Now() == "middle" })
	nodes[1].failed.Store(false)
	eventually(t, func() bool { return child.Now() == "fast" && parent.Now() == "region" })
}

func TestLowestDelayInboundTrafficStillWorks(t *testing.T) {
	ctx, _, _, _, parent := newFailoverFixture(t)
	eventually(t, func() bool { return parent.Now() == "region" })
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(time.Second))
	closed := make(chan error, 1)
	parent.NewConnection(ctx, local, adapter.InboundContext{Network: N.NetworkTCP, Destination: M.ParseSocksaddr("127.0.0.1:80")}, func(err error) { closed <- err })
	if _, err := remote.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(stdbufio.NewReader(remote), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("HTTP status %d", response.StatusCode)
	}
	remote.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("traffic connection leaked")
	}
}

func TestNestedRetryBudgetAndCancellation(t *testing.T) {
	ctx, _, nodes, _, parent := newFailoverFixture(t)
	eventually(t, func() bool { return parent.Now() == "region" })
	for _, n := range nodes {
		n.failed.Store(true)
	}
	conn, err := parent.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:80"))
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("expected all nodes offline")
	}
	var attempts int32
	for _, n := range nodes {
		attempts += n.businessDials.Load()
	}
	if attempts != 2 {
		t.Fatalf("nested groups must share exactly one retry, got %d dials", attempts)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	parent.DialContext(cancelled, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:80"))
	var after int32
	for _, n := range nodes {
		after += n.businessDials.Load()
	}
	if after-attempts > 1 {
		t.Fatal("cancelled request retried")
	}
}

func TestLowestDelayOptionalTolerance(t *testing.T) {
	a := &testNode{Adapter: outbound.NewAdapter("test", "a", []string{N.NetworkTCP, N.NetworkUDP}, nil)}
	b := &testNode{Adapter: outbound.NewAdapter("test", "b", []string{N.NetworkTCP, N.NetworkUDP}, nil)}
	s := NewLowestDelay([]adapter.Outbound{a, b}, option.BalancerOutboundOptions{Tolerance: 20})
	h := map[string]*adapter.URLTestHistory{"a": {Delay: 100}, "b": {Delay: 90}}
	s.UpdateOutboundsInfo(h)
	if s.Now() != "a" {
		t.Fatal("small jitter switched node")
	}
	h["b"].Delay = 79
	s.UpdateOutboundsInfo(h)
	if s.Now() != "b" {
		t.Fatal("significant improvement ignored")
	}
	h["b"].Delay = monitoring.TimeoutDelay
	s.UpdateOutboundsInfo(h)
	if s.Now() != "a" {
		t.Fatal("tolerance retained failed node")
	}
	h["a"].IsFromCache = true
	h["b"].Delay = 105
	s.UpdateOutboundsInfo(h)
	if s.Now() != "b" {
		t.Fatal("tolerance retained cached node")
	}
	strict := NewLowestDelay([]adapter.Outbound{a, b}, option.BalancerOutboundOptions{})
	strict.UpdateOutboundsInfo(map[string]*adapter.URLTestHistory{"a": {Delay: 100}, "b": {Delay: 99}})
	if strict.Now() != "b" {
		t.Fatal("default must remain strict lowest delay")
	}
}

func TestPacketEstablishmentCanUseHealthyBackup(t *testing.T) {
	ctx, _, nodes, child, _ := newFailoverFixture(t)
	eventually(t, func() bool { return child.Now() == "fast" })
	nodes[0].packetHealthy.Store(true)
	conn, err := child.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if nodes[0].packetDials.Load() != 1 || nodes[1].packetDials.Load() != 1 {
		t.Fatal("expected one failed UDP setup and one backup setup")
	}
}
