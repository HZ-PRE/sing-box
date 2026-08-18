//go:build !with_quic

package outbound

import (
	"context"

	"github.com/HZ-PRE/sing-box/adapter"
	C "github.com/HZ-PRE/sing-box/constant"
	"github.com/HZ-PRE/sing-box/log"
	"github.com/HZ-PRE/sing-box/option"
)

func NewTUIC(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
	return nil, C.ErrQUICNotIncluded
}
