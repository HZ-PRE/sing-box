package ssplus

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/diagnostics"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/ssplus"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SSPlusOutboundOptions](registry, C.TypeSSPlus, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	dialer      N.Dialer
	server      M.Socksaddr
	client      *ssplus.Client
	nativePin   bool
	forceUOT    bool
	uotVersion  uint8
	nativeRetry atomic.Int64
	nativeKnown atomic.Bool
	nativeProbe atomic.Bool
	nativeEpoch atomic.Uint64
	nativeState sync.Mutex
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSPlusOutboundOptions) (adapter.Outbound, error) {
	config, err := ssplus.NewConfigWithObfs(options.Method, options.Protocol, options.IVKey, options.Obfs, options.ObfsParam)
	if err != nil {
		return nil, err
	}
	if err = config.SetPadding(options.Padding, options.PaddingBudget); err != nil {
		return nil, err
	}
	if options.UDPPadding != nil {
		if err = config.SetNativePadding(*options.UDPPadding); err != nil {
			return nil, err
		}
	}
	key, err := ssplus.ResolveKey(options.Key, options.Password)
	if err != nil {
		return nil, err
	}
	client, err := ssplus.NewClient(config, ssplus.User{ID: options.UserID, Key: key})
	if err != nil {
		return nil, err
	}
	networks := options.Network.Build()
	uotOptions := option.UDPOverTCPOptions{Version: uot.Version}
	if options.UDPOverTCP != nil {
		uotOptions = *options.UDPOverTCP
	}
	if uotOptions.Version == 0 {
		uotOptions.Version = uot.Version
	}
	if uotOptions.Version != uot.Version && uotOptions.Version != uot.LegacyVersion {
		return nil, fmt.Errorf("ssplus: unsupported UoT version %d", uotOptions.Version)
	}
	for _, network := range networks {
		if network != N.NetworkTCP && network != N.NetworkUDP {
			return nil, fmt.Errorf("ssplus: unsupported network %q", network)
		}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	h := &Outbound{Adapter: outbound.NewAdapterWithDialerOptions(C.TypeSSPlus, tag, networks, options.DialerOptions), dialer: outboundDialer, server: options.ServerOptions.Build(), client: client}
	h.nativePin = options.Detour == ""
	h.forceUOT, h.uotVersion = uotOptions.Enabled, uotOptions.Version
	return h, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = h.Tag(), destination
	if N.NetworkName(network) == N.NetworkUDP {
		packets, err := h.listenPacket(ctx, destination, true)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packets, destination), nil
	}
	return h.dialTCP(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = h.Tag(), destination
	return h.listenPacket(ctx, destination, false)
}

const nativeRetryCooldown = 30 * time.Second

func (h *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr, connect bool) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !h.forceUOT && time.Now().UnixNano() >= h.nativeRetry.Load() {
		// Unknown/failed nodes have one capability probe at a time. Other
		// sessions use UoT immediately rather than sharing application sockets.
		known := h.nativeKnown.Load()
		if known || h.nativeProbe.CompareAndSwap(false, true) {
			if !known {
				defer h.nativeProbe.Store(false)
			}
			return h.racePacket(ctx, destination, connect)
		}
	}
	return h.listenUOT(ctx, destination, connect)
}

func (h *Outbound) listenUOT(ctx context.Context, destination M.Socksaddr, connect bool) (net.PacketConn, error) {
	conn, err := h.dialTCP(ctx, N.NetworkTCP, uot.RequestDestination(h.uotVersion))
	if err != nil {
		return nil, err
	}
	packets, err := (&uot.Client{Version: h.uotVersion}).DialEarlyConn(conn, connect, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &packetConn{Conn: packets}, nil
}

// Race only transport setup, never application datagrams. The losing transport
// is canceled and closed. All goroutines finish before this call returns.
func (h *Outbound) racePacket(ctx context.Context, destination M.Socksaddr, connect bool) (net.PacketConn, error) {
	epoch := h.nativeEpoch.Load()
	type result struct {
		conn   net.PacketConn
		err    error
		native bool
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, 2)
	diagnostics.Go(raceCtx, diagnostics.SSPlus, func(ctx context.Context) { c, err := h.listenNative(ctx); results <- result{c, err, true} })
	pending := 1
	uotStarted := false
	startUOT := func() {
		if uotStarted {
			return
		}
		uotStarted = true
		pending++
		diagnostics.Go(raceCtx, diagnostics.SSPlus, func(ctx context.Context) {
			c, err := h.listenUOT(ctx, destination, connect)
			results <- result{c, err, false}
		})
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	var lastErr error
	for pending > 0 {
		select {
		case <-ctx.Done():
			cancel()
			for ; pending > 0; pending-- {
				if r := <-results; r.conn != nil {
					r.conn.Close()
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
			startUOT()
		case r := <-results:
			pending--
			if r.err == nil {
				if ctx.Err() == nil {
					h.recordNative(epoch, r.native)
				}
				cancel()
				for ; pending > 0; pending-- {
					if other := <-results; other.conn != nil {
						other.conn.Close()
					}
				}
				if ctx.Err() != nil {
					r.conn.Close()
					return nil, ctx.Err()
				}
				return r.conn, nil
			}
			lastErr = r.err
			if r.native && ctx.Err() == nil {
				h.recordNative(epoch, false)
				startUOT()
			}
		}
	}
	return nil, lastErr
}

// A network switch invalidates negative capability results immediately.
func (h *Outbound) InterfaceUpdated() {
	h.nativeState.Lock()
	defer h.nativeState.Unlock()
	h.nativeEpoch.Add(1)
	h.nativeRetry.Store(0)
	h.nativeKnown.Store(false)
}

func (h *Outbound) recordNative(epoch uint64, success bool) {
	h.nativeState.Lock()
	defer h.nativeState.Unlock()
	if h.nativeEpoch.Load() != epoch {
		return
	}
	h.nativeKnown.Store(success)
	if success {
		h.nativeRetry.Store(0)
	} else {
		h.nativeRetry.Store(time.Now().Add(nativeRetryCooldown).UnixNano())
	}
}

func (h *Outbound) listenNative(ctx context.Context) (net.PacketConn, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	control, err := h.dialTCP(probeCtx, N.NetworkTCP, M.Socksaddr{Fqdn: ssplus.NativeUDPAddress})
	if err != nil {
		return nil, err
	}
	server := h.server
	// Pin UDP to the IP used by the TCP session when using a direct dialer.
	// A detour may expose the relay's address, so retain the configured target there.
	if h.nativePin {
		if remote := M.SocksaddrFromNet(control.RemoteAddr()); remote.Addr.IsValid() {
			server = remote
			server.Port = h.server.Port
		}
	}
	udp, err := h.dialer.DialContext(probeCtx, N.NetworkUDP, server)
	if err != nil {
		control.Close()
		return nil, err
	}
	packets, err := h.client.OpenNative(probeCtx, control, udp)
	if err != nil {
		return nil, err
	}
	return packets, nil
}

func (h *Outbound) dialTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, fmt.Errorf("ssplus: unsupported underlying network %q", network)
	}
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.server)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(canceled) })
	secured, err := h.client.DialConn(conn, destination)
	if !stop() {
		<-canceled
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return secured, nil
}
