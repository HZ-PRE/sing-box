package ssplus

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/ssplus"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SSPlusInboundOptions](registry, C.TypeSSPlus, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router   adapter.ConnectionRouterEx
	logger   log.ContextLogger
	listener *listener.Listener
	server   *ssplus.Server
	native   *ssplus.NativeService
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSPlusInboundOptions) (adapter.Inbound, error) {
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
	users := make([]ssplus.User, len(options.Users))
	for i, user := range options.Users {
		key, err := ssplus.ResolveKey(user.Key, user.Password)
		if err != nil {
			return nil, err
		}
		users[i] = ssplus.User{ID: user.UserID, Name: user.Name, Key: key}
	}
	server, err := ssplus.NewServer(config, users)
	if err != nil {
		return nil, err
	}
	h := &Inbound{Adapter: inbound.NewAdapter(C.TypeSSPlus, tag), router: router, logger: logger, server: server}
	h.native = server.NewNativeService()
	h.listener = listener.New(listener.Options{
		Context: ctx, Logger: logger, Network: []string{N.NetworkTCP, N.NetworkUDP},
		Listen: options.ListenOptions, ConnectionHandler: h, PacketHandler: h,
	})
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStart {
		if err := h.listener.Start(); err != nil {
			return err
		}
		_ = h.listener.UDPConn().SetReadBuffer(256 * 1024)
		return nil
	}
	return nil
}

func (h *Inbound) Close() error {
	h.native.Close()
	return h.listener.Close()
}

func (h *Inbound) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	h.native.Receive(buffer.Bytes(), source.String(), func(packet []byte) error {
		_, err := h.listener.UDPConn().WriteToUDPAddrPort(packet, source.AddrPort())
		return err
	})
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	secured, destination, user, err := h.server.Accept(conn)
	if err == nil && destination.Fqdn != ssplus.NativeUDPAddress && destination.Fqdn != uot.MagicAddress {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.DebugContext(ctx, "ssplus handshake from ", metadata.Source, ": ", err)
		return
	}
	metadata.Inbound, metadata.InboundType = h.Tag(), h.Type()
	metadata.Destination = destination.Unwrap()
	metadata.User = user.Name
	if metadata.User == "" {
		metadata.User = strconv.FormatUint(uint64(user.ID), 10)
	}
	if destination.Fqdn == ssplus.NativeUDPAddress {
		if destination.Port != 0 {
			N.CloseOnHandshakeFailure(secured, onClose, ssplus.ErrAuthentication)
			return
		}
		packets, err := h.native.Accept(secured)
		if err != nil {
			N.CloseOnHandshakeFailure(secured, onClose, err)
			return
		}
		// Read the first target before routing the native UDP session.
		packets.SetReadDeadline(time.Now().Add(10 * time.Second))
		buffer := buf.NewSize(65535)
		target, err := packets.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			N.CloseOnHandshakeFailure(packets, onClose, err)
			return
		}
		packets.SetReadDeadline(time.Time{})
		metadata.Destination = target
		h.router.RoutePacketConnectionEx(ctx, bufio.NewCachedPacketConn(bufio.NewPacketConn(packets), buffer, target), metadata, onClose)
		return
	}
	if destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress {
		if destination.Port != 0 {
			N.CloseOnHandshakeFailure(secured, onClose, ssplus.ErrAuthentication)
			return
		}
		request := uot.Request{}
		if destination.Fqdn == uot.MagicAddress {
			parsed, readErr := uot.ReadRequest(secured)
			if readErr != nil {
				N.CloseOnHandshakeFailure(secured, onClose, readErr)
				return
			}
			request = *parsed
		}
		if err = conn.SetDeadline(time.Time{}); err != nil {
			N.CloseOnHandshakeFailure(secured, onClose, err)
			return
		}
		metadata.Domain = destination.Fqdn
		metadata.Destination = request.Destination
		if destination.Fqdn == uot.LegacyMagicAddress {
			metadata.Destination = M.ParseSocksaddr("0.0.0.0:0")
		}
		h.router.RoutePacketConnectionEx(ctx, uot.NewConn(secured, request), metadata, onClose)
		return
	}
	if destination.Port == 0 {
		N.CloseOnHandshakeFailure(secured, onClose, ssplus.ErrAuthentication)
		return
	}
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, secured, metadata, onClose)
}
