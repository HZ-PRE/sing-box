package outbound

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/HZ-PRE/sing-box/adapter"
	"github.com/HZ-PRE/sing-box/common/dialer"
	"github.com/HZ-PRE/sing-box/common/mux"
	C "github.com/HZ-PRE/sing-box/constant"
	"github.com/HZ-PRE/sing-box/log"
	"github.com/HZ-PRE/sing-box/option"
	"github.com/HZ-PRE/sing-box/transport/sip003"
	shadowsocks "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

var _ adapter.Outbound = (*Shadowsocks)(nil)

type Shadowsocks struct {
	myOutboundAdapter
	dialer          N.Dialer
	method          shadowsocks.Method
	userId          string
	serverAddr      M.Socksaddr
	plugin          sip003.Plugin
	uotClient       *uot.Client
	multiplexDialer *mux.Client
}

func NewShadowsocks(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksOutboundOptions) (*Shadowsocks, error) {
	method, err := shadowsocks.CreateMethod(ctx, options.Method, shadowsocks.MethodOptions{
		Password: options.Password,
	})
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &Shadowsocks{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeShadowsocks,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		dialer:     outboundDialer,
		method:     method,
		userId:     options.UserId,
		serverAddr: options.ServerOptions.Build(),
	}
	if options.Plugin != "" {
		outbound.plugin, err = sip003.CreatePlugin(ctx, options.Plugin, options.PluginOptions, router, outbound.dialer, outbound.serverAddr)
		if err != nil {
			return nil, err
		}
	}
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if !uotOptions.Enabled {
		outbound.multiplexDialer, err = mux.NewClientWithOptions((*shadowsocksDialer)(outbound), logger, common.PtrValueOrDefault(options.Multiplex))
		if err != nil {
			return nil, err
		}
	}
	if uotOptions.Enabled {
		outbound.uotClient = &uot.Client{
			Dialer:  (*shadowsocksDialer)(outbound),
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

type userIDPacketConn struct {
	net.PacketConn
	userId string
}

func buildUserIDHeader(userId string) ([]byte, error) {
	if userId == "" {
		return nil, nil
	}
	if len(userId) > 255 {
		return nil, fmt.Errorf("userId too long: %d", len(userId))
	}

	header := make([]byte, 2+len(userId))
	header[0] = 0xAA
	header[1] = byte(len(userId))
	copy(header[2:], userId)
	return header, nil
}

func writeAll(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (c *userIDPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	header, err := buildUserIDHeader(c.userId)
	if err != nil {
		return 0, err
	}
	if len(header) == 0 {
		return c.PacketConn.WriteTo(b, addr)
	}

	packet := make([]byte, len(header)+len(b))
	copy(packet, header)
	copy(packet[len(header):], b)

	n, err := c.PacketConn.WriteTo(packet, addr)
	if err != nil {
		return 0, err
	}
	if n < len(header) {
		return 0, io.ErrShortWrite
	}

	payloadN := n - len(header)
	if payloadN > len(b) {
		payloadN = len(b)
	}
	return payloadN, nil
}

func (h *Shadowsocks) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			if h.uotClient != nil {
				h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
				return h.uotClient.DialContext(ctx, network, destination)
			} else {
				h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
			}
		}
		return (*shadowsocksDialer)(h).DialContext(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *Shadowsocks) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	if h.multiplexDialer == nil {
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
			return h.uotClient.ListenPacket(ctx, destination)
		} else {
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*shadowsocksDialer)(h).ListenPacket(ctx, destination)
	} else {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *Shadowsocks) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *Shadowsocks) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

func (h *Shadowsocks) InterfaceUpdated() {
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
	return
}

func (h *Shadowsocks) Close() error {
	return common.Close(common.PtrOrNil(h.multiplexDialer))
}

var _ N.Dialer = (*shadowsocksDialer)(nil)

type shadowsocksDialer Shadowsocks

func (h *shadowsocksDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		var outConn net.Conn
		var err error
		if h.plugin != nil {
			outConn, err = h.plugin.DialContext(ctx)
		} else {
			outConn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		}
		if err != nil {
			return nil, err
		}
		header, err := buildUserIDHeader(h.userId)
		if err != nil {
			outConn.Close()
			return nil, err
		}

		// 当前语义：在 SS 流开始前明文写入 userId header
		if len(header) > 0 {
			err = writeAll(outConn, header)
			if err != nil {
				outConn.Close()
				return nil, err
			}
		}
		return h.method.DialEarlyConn(outConn, destination), nil
	case N.NetworkUDP:
		outConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		conn := h.method.DialPacketConn(outConn)
		return bufio.NewBindPacketConn(&userIDPacketConn{
			PacketConn: conn,
			userId:     h.userId,
		}, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *shadowsocksDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	outConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := h.method.DialPacketConn(outConn)
	return &userIDPacketConn{
		PacketConn: conn,
		userId:     h.userId,
	}, nil
}
