package ssplus

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
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
	dialer N.Dialer
	server M.Socksaddr
	client *ssplus.Client
	uot    *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSPlusOutboundOptions) (adapter.Outbound, error) {
	config, err := ssplus.NewConfigWithObfs(options.Method, options.Protocol, options.IVKey, options.Obfs, options.ObfsParam)
	if err != nil {
		return nil, err
	}
	key, err := ssplus.ResolveKey(options.Key, options.Password)
	if err != nil {
		return nil, err
	}
	client, err := ssplus.NewClient(config, ssplus.User{ID: options.UserID, Key: key})
	if err != nil {
		return nil, err
	}
	uotOptions := option.UDPOverTCPOptions{Enabled: true, Version: uot.Version}
	if options.UDPOverTCP != nil {
		uotOptions = *options.UDPOverTCP
	}
	if uotOptions.Version != 0 && uotOptions.Version != uot.Version && uotOptions.Version != uot.LegacyVersion {
		return nil, fmt.Errorf("ssplus: unsupported UoT version %d", uotOptions.Version)
	}
	networks := options.Network.Build()
	if !uotOptions.Enabled {
		if len(options.Network) == 0 {
			networks = []string{N.NetworkTCP}
		}
		for _, network := range networks {
			if network != N.NetworkTCP {
				return nil, fmt.Errorf("ssplus: UDP requires udp_over_tcp")
			}
		}
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
	if uotOptions.Enabled {
		h.uot = &uot.Client{Dialer: (*tcpDialer)(h), Version: uotOptions.Version}
	}
	return h, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = h.Tag(), destination
	if N.NetworkName(network) == N.NetworkUDP {
		if h.uot == nil {
			return nil, fmt.Errorf("ssplus: UDP requires udp_over_tcp")
		}
		packets, err := h.listenPacket(ctx, destination, true)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(packets, destination), nil
	}
	return (*tcpDialer)(h).DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound, metadata.Destination = h.Tag(), destination
	if h.uot == nil {
		return nil, fmt.Errorf("ssplus: UDP requires udp_over_tcp")
	}
	return h.listenPacket(ctx, destination, false)
}

func (h *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr, connect bool) (*packetConn, error) {
	conn, err := (*tcpDialer)(h).DialContext(ctx, N.NetworkTCP, uot.RequestDestination(h.uot.Version))
	if err != nil {
		return nil, err
	}
	packets, err := h.uot.DialEarlyConn(conn, connect, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &packetConn{Conn: packets}, nil
}

type tcpDialer Outbound

func (h *tcpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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

func (h *tcpDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("ssplus: native UDP is not supported; use UoT")
}
