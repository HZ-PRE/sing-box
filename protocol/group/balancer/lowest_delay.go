package balancer

import (
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type LowestDelay struct {
	outbounds        map[string][]adapter.Outbound
	selectedOutbound map[string]adapter.Outbound
	tolerance        uint16

	mu sync.Mutex
}

func NewLowestDelay(outbounds []adapter.Outbound, options option.BalancerOutboundOptions) *LowestDelay {
	couts := convertOutbounds(outbounds)
	return &LowestDelay{
		outbounds: couts,
		tolerance: options.Tolerance,
		selectedOutbound: map[string]adapter.Outbound{
			N.NetworkUDP: couts[N.NetworkUDP][0],
			N.NetworkTCP: couts[N.NetworkTCP][0],
		},
	}
}

var _ Strategy = (*LowestDelay)(nil)

func (s *LowestDelay) Now() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.selectedOutbound[N.NetworkTCP].Tag()
}
func (s *LowestDelay) UpdateOutboundsInfo(history map[string]*adapter.URLTestHistory) bool {
	min, _ := getMinDelay(s.outbounds, history)

	s.mu.Lock()
	changed := false
	for net, out := range min {
		current := s.selectedOutbound[net]
		if s.tolerance > 0 && current != nil {
			h := history[current.Tag()]
			currentDelay, bestDelay := getTagDelay(current.Tag(), history), getTagDelay(out.Tag(), history)
			if h != nil && !h.IsFromCache && currentDelay < monitoring.TimeoutDelay &&
				int(currentDelay)-int(bestDelay) <= int(s.tolerance) {
				min[net] = current
				out = current
			}
		}
		changed = changed || out.Tag() != s.selectedOutbound[net].Tag()
	}
	s.selectedOutbound = min
	s.mu.Unlock()
	return changed
}
func (s *LowestDelay) Select(metadata adapter.InboundContext, net string, touch bool) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	if net != N.NetworkTCP && net != N.NetworkUDP {
		net = N.NetworkTCP
	}
	return s.selectedOutbound[net]

}
