package ssplus

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync/atomic"
)

// Padding affects only outgoing optional bytes, never the accepted wire format.
// Configure it before creating clients or servers. Empty mode means initial.
func (c *Config) SetPadding(mode string, budget int) error {
	if mode == "" {
		mode = "initial"
	}
	if mode != "initial" && mode != "light" && mode != "off" {
		return fmt.Errorf("ssplus: padding must be initial, light or off")
	}
	if budget < 0 || budget > 65536 {
		return fmt.Errorf("ssplus: padding_budget must be between 0 and 65536")
	}
	if budget == 0 {
		budget = 1024
	}
	c.paddingMode, c.paddingBudget = mode, budget
	return nil
}

// One allowance per outgoing connection, shared with its native UDP session.
// Framing bytes and the mandatory MTU reachability probe are not optional padding.
type paddingAllowance struct{ remaining atomic.Int64 }

func (c *Config) newPaddingAllowance() *paddingAllowance {
	p := new(paddingAllowance)
	if c.paddingMode != "off" {
		p.remaining.Store(int64(c.paddingBudget))
	}
	return p
}

func (p *paddingAllowance) take(n int) int {
	if p == nil || n <= 0 {
		return 0
	}
	for {
		old := p.remaining.Load()
		n = min(n, int(old))
		if n == 0 || p.remaining.CompareAndSwap(old, old-int64(n)) {
			return n
		}
	}
}

type paddingState struct {
	allowance *paddingAllowance
	light     bool
	records   uint8
	bulk      bool
}

func (c *Config) paddingState(p *paddingAllowance) paddingState {
	return paddingState{allowance: p, light: c.paddingMode == "light"}
}

// Stop permanently on a large record. After the first eight records, only
// explicitly enabled light mode pads payloads up to 256 bytes, by at most 31.
func (p *paddingState) next(payload, limit int) (int, error) {
	initial := p.records < 8
	if initial {
		p.records++
	}
	if payload > 1200 {
		p.bulk = true
	}
	if !initial && !p.light {
		return 0, nil
	}
	if p.bulk || p.allowance == nil || p.allowance.remaining.Load() == 0 || limit <= 0 {
		return 0, nil
	}
	if !initial {
		if !p.light || payload > 256 {
			return 0, nil
		}
		limit = min(limit, 31)
	}
	// Choose a band and then a length within it; do not force fixed-sized packets.
	var r [2]byte
	if _, err := rand.Read(r[:]); err != nil {
		return 0, err
	}
	low, width := 16, 16
	switch r[0] % 3 {
	case 1:
		low, width = 32, 32
	case 2:
		low, width = 64, 64
	}
	if limit < low {
		low, width = 0, limit+1
	} else {
		width = min(width, limit-low+1)
	}
	return p.allowance.take(low + int(r[1])%width), nil
}

type paddingOwner interface{ outgoingPadding() *paddingAllowance }

func sharedPadding(conn net.Conn, config *Config) *paddingAllowance {
	if owner, ok := conn.(paddingOwner); ok {
		return owner.outgoingPadding()
	}
	return config.newPaddingAllowance()
}

func (c *streamConn) outgoingPadding() *paddingAllowance { return c.padding }
