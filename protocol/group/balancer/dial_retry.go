package balancer

import (
	"context"
	"slices"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
)

type dialRetryKey struct{}

// Nested balancers share one retry, so group depth cannot multiply dial attempts.
func withDialRetryBudget(ctx context.Context) context.Context {
	if ctx.Value(dialRetryKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, dialRetryKey{}, new(atomic.Bool))
}

func (s *Balancer) retryOutbound(ctx context.Context, failed adapter.Outbound, network string) adapter.Outbound {
	budget, _ := ctx.Value(dialRetryKey{}).(*atomic.Bool)
	if ctx.Err() != nil || s.options.Strategy != StrategyLowestDelay || budget == nil || budget.Load() {
		return nil
	}
	failedLeaf, _ := s.monitor.HealthyOutboundHistory(failed.Tag())
	var best adapter.Outbound
	bestDelay := monitoring.TimeoutDelay
	for _, tag := range s.tags {
		if tag == failed.Tag() {
			continue
		}
		candidate, ok := s.outbound.Outbound(tag)
		if !ok || !slices.Contains(candidate.Network(), network) {
			continue
		}
		leaf, h := s.monitor.HealthyOutboundHistory(tag)
		if failedLeaf != "" && leaf == failedLeaf {
			continue
		}
		if h == nil || h.IsFromCache || h.Delay == 0 || h.Delay >= bestDelay {
			continue
		}
		best, bestDelay = candidate, h.Delay
	}
	if best != nil && budget.CompareAndSwap(false, true) {
		return best
	}
	return nil
}
