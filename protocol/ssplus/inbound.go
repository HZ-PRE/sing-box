package ssplus

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/ssplus"
	N "github.com/sagernet/sing/common/network"
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
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SSPlusInboundOptions) (adapter.Inbound, error) {
	config, err := ssplus.NewConfigWithObfs(options.Method, options.Protocol, options.IVKey, options.Obfs, options.ObfsParam)
	if err != nil {
		return nil, err
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
	h := &Inbound{Adapter: inbound.NewAdapter(C.TypeSSPlus, tag), router: uot.NewRouter(router, logger), logger: logger, server: server}
	h.listener = listener.New(listener.Options{
		Context: ctx, Logger: logger, Network: []string{N.NetworkTCP},
		Listen: options.ListenOptions, ConnectionHandler: h,
	})
	return h, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStart {
		return h.listener.Start()
	}
	return nil
}

func (h *Inbound) Close() error { return h.listener.Close() }

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	secured, destination, user, err := h.server.Accept(conn)
	if err == nil {
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
	h.logger.InfoContext(ctx, "[", metadata.User, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, secured, metadata, onClose)
}
