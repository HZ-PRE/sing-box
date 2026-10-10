package balancer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterLoadBalance(registry *outbound.Registry) {
	outbound.Register[option.BalancerOutboundOptions](registry, C.TypeBalancer, NewLoadBalance)
}

var _ adapter.OutboundGroup = (*Balancer)(nil)

const (
	StrategyRoundRobin        = "round-robin"
	StrategyConsistentHashing = "consistent-hashing"
	StrategyStickySessions    = "sticky-sessions"
	StrategyLowestDelay       = "lowest-delay"
)

type Balancer struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
	logger                       log.ContextLogger
	tags                         []string
	strategyFn                   Strategy
	options                      option.BalancerOutboundOptions
	interruptExternalConnections bool

	monitor *monitoring.OutboundMonitoring

	close          chan struct{}
	closeOnce      sync.Once
	workerWG       sync.WaitGroup
	interruptGroup *interrupt.Group
}

func NewLoadBalance(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.BalancerOutboundOptions) (adapter.Outbound, error) {
	outbound := &Balancer{
		Adapter:                      outbound.NewAdapter(C.TypeBalancer, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		interruptExternalConnections: options.InterruptExistConnections,
		options:                      options,
		interruptGroup:               interrupt.NewGroup(),
		close:                        make(chan struct{}),
	}
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
	}

	return outbound, nil
}

func (s *Balancer) Strategy() string {
	return s.options.Strategy
}

func (s *Balancer) Start() error {
	s.monitor = monitoring.Get(s.ctx)
	s.logger.Info("starting load balance, monitoring enabled: ", s.monitor != nil)
	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		outbounds = append(outbounds, detour)
	}
	switch s.options.Strategy {
	case StrategyRoundRobin:
		s.strategyFn = NewRoundRobin(outbounds, s.options)
	case StrategyConsistentHashing:
		s.strategyFn = NewConsistentHashing(outbounds, s.options)
	case StrategyStickySessions:
		s.strategyFn = NewStickySession(outbounds, s.options)
	case StrategyLowestDelay:
		s.strategyFn = NewLowestDelay(outbounds, s.options)
	default:
		return E.New("unknown load balance strategy: ", s.options.Strategy)
	}

	return nil
}

func (s *Balancer) PostStart() error {
	if s.monitor == nil {
		return E.New("outbound monitoring unavailable")
	}
	observer, err := s.monitor.SubscribeGroup(s.Tag())
	if err != nil {
		return err
	}
	// Monitoring starts before legacy PostStart. Read its current snapshot
	// after subscribing so cached/fast probe results cannot be missed.
	s.updateOutbounds()
	s.workerWG.Add(1)
	go s.worker(observer)
	return nil
}

func (s *Balancer) updateOutbounds() {
	if s.strategyFn.UpdateOutboundsInfo(s.monitor.OutboundsHistory(s.Tag())) {
		s.interruptGroup.Interrupt(s.interruptExternalConnections)
	}
	// A parent's delay follows this group's current selection. Publish only
	// after updating it, even when just the selected node's delay changed.
	s.monitor.NotifyGroupHistory(s.Tag())
}

func (s *Balancer) worker(observer <-chan monitoring.GroupEvent) {
	defer s.workerWG.Done()
	defer s.monitor.UnsubscribeGroup(s.Tag(), observer)

	for {
		select {
		case <-s.close:
			return

		case <-s.ctx.Done():
			return
		case _, ok := <-observer:
			if !ok {
				return
			}
			s.updateOutbounds()

		}
	}
}
func (s *Balancer) Close() error {
	if s.close != nil {
		s.closeOnce.Do(func() { close(s.close) })
		s.workerWG.Wait()
	}
	return nil
}

func (s *Balancer) Now() string {
	if s.strategyFn == nil {
		return ""
	}
	return s.strategyFn.Now()
}

func (s *Balancer) All() []string {
	return s.tags
}

func (s *Balancer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx = withDialRetryBudget(ctx)
	s.monitor.Touch()
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		metadata = &adapter.InboundContext{}
	}
	outbound := s.strategyFn.Select(*metadata, network, true)
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	if metadata != nil {
		metadata.SetRealOutbound(outbound.Tag())
	}

	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	if ctx.Err() == nil {
		s.monitor.InvalidateTest(outbound.Tag())
		if next := s.retryOutbound(ctx, outbound, network); next != nil {
			metadata.SetRealOutbound(next.Tag())
			conn, err = next.DialContext(ctx, network, destination)
			if err == nil {
				return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
			}
			if ctx.Err() == nil {
				s.monitor.InvalidateTest(next.Tag())
			}
		}
	}

	return nil, err
}

func (s *Balancer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx = withDialRetryBudget(ctx)
	s.monitor.Touch()
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		metadata = &adapter.InboundContext{}
	}
	outbound := s.strategyFn.Select(*metadata, N.NetworkUDP, true)
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	if metadata != nil {
		metadata.SetRealOutbound(outbound.Tag())
	}

	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	if ctx.Err() == nil {
		s.monitor.InvalidateTest(outbound.Tag())
		if next := s.retryOutbound(ctx, outbound, N.NetworkUDP); next != nil {
			metadata.SetRealOutbound(next.Tag())
			conn, err = next.ListenPacket(ctx, destination)
			if err == nil {
				return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
			}
			if ctx.Err() == nil {
				s.monitor.InvalidateTest(next.Tag())
			}
		}
	}
	return nil, err
}

func (s *Balancer) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	// Route through our dialer so real inbound traffic gets the same failure
	// probes and connection interruption as DialContext callers.
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *Balancer) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *Balancer) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	selected := s.strategyFn.Select(metadata, metadata.Network, true)
	if selected == nil {
		return nil, E.New(metadata.Network, " is not supported by outbound: ")
	}
	metadata.SetRealOutbound(selected.Tag())
	return selected.(adapter.DirectRouteOutbound).NewDirectRouteConnection(metadata, routeContext, timeout)
}
