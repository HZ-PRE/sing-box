//go:build with_wireguard

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound/houtbound"
	"github.com/sagernet/sing-box/transport/wireguard"
	dns "github.com/sagernet/sing-dns"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
)

var (
	_ adapter.Outbound                = (*WireGuard)(nil)
	_ adapter.InterfaceUpdateListener = (*WireGuard)(nil)
)

type WireGuard struct {
	myOutboundAdapter
	ctx           context.Context
	workers       int
	peers         []wireguard.PeerConfig
	useStdNetBind bool
	listener      N.Dialer
	ipcConf       string

	pauseManager     pause.Manager
	pauseCallback    *list.Element[pause.Callback]
	bind             conn.Bind
	device           *device.Device
	tunDevice        wireguard.Device
	hforwarder       *houtbound.Forwarder
	fakePackets      []int
	fakePacketsSize  []int
	fakePacketsDelay []int
	fakePacketsMode  string
	lastUpdate       time.Time
}

func NewWireGuard(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardOutboundOptions) (*WireGuard, error) {
	hforwarder := houtbound.ApplyTurnRelay(houtbound.CommonTurnRelayOptions{ServerOptions: options.ServerOptions, TurnRelayOptions: options.TurnRelay})
	outbound := &WireGuard{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeWireGuard,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:          ctx,
		workers:      options.Workers,
		pauseManager: service.FromContext[pause.Manager](ctx),
		hforwarder:   hforwarder, //hiddify
	}
	outbound.fakePackets = []int{0, 0}
	outbound.fakePacketsSize = []int{0, 0}
	outbound.fakePacketsDelay = []int{0, 0}
	outbound.fakePacketsMode = options.FakePacketsMode
	if options.FakePackets != "" {
		var err error
		outbound.fakePackets, err = option.ParseIntRange(options.FakePackets)
		if err != nil {
			return nil, err
		}
		outbound.fakePacketsSize = []int{40, 100}
		outbound.fakePacketsDelay = []int{10, 50}

		if options.FakePacketsSize != "" {
			var err error
			outbound.fakePacketsSize, err = option.ParseIntRange(options.FakePacketsSize)
			if err != nil {
				return nil, err
			}
		}

		if options.FakePacketsDelay != "" {
			var err error
			outbound.fakePacketsDelay, err = option.ParseIntRange(options.FakePacketsDelay)
			if err != nil {
				return nil, err
			}
		}
	}

	peers, err := wireguard.ParsePeers(options)
	if err != nil {
		return nil, err
	}
	outbound.peers = peers
	if len(options.LocalAddress) == 0 {
		return nil, E.New("missing local address")
	}
	if options.GSO {
		if options.GSO && options.Detour != "" {
			return nil, E.New("gso is conflict with detour")
		}
		options.IsWireGuardListener = true
		outbound.useStdNetBind = true
	}
	listener, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound.listener = listener
	var privateKey string
	{
		bytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		privateKey = hex.EncodeToString(bytes)
	}
	outbound.ipcConf = "private_key=" + privateKey
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1408
	}
	var wireTunDevice wireguard.Device
	if !options.SystemInterface && tun.WithGVisor {
		wireTunDevice, err = wireguard.NewStackDevice(options.LocalAddress, mtu)
	} else {
		wireTunDevice, err = wireguard.NewSystemDevice(router, options.InterfaceName, options.LocalAddress, mtu, options.GSO)
	}
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	outbound.tunDevice = wireTunDevice
	return outbound, nil
}

func (w *WireGuard) Start() error {
	if common.Any(w.peers, func(peer wireguard.PeerConfig) bool {
		return !peer.Endpoint.IsValid()
	}) {
		// wait for all outbounds to be started and continue in PortStart
		return nil
	}
	return w.start()
}

func (w *WireGuard) PostStart() error {
	if common.All(w.peers, func(peer wireguard.PeerConfig) bool {
		return peer.Endpoint.IsValid()
	}) {
		return nil
	}
	return w.start()
}

func (w *WireGuard) start() error {
	err := wireguard.ResolvePeers(w.ctx, w.router, w.peers)
	if err != nil {
		return err
	}
	var bind conn.Bind
	if w.useStdNetBind {
		bind = conn.NewStdNetBind(w.listener.(dialer.WireGuardListener))
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
			reserved    [3]uint8
		)
		peerLen := len(w.peers)
		if peerLen == 1 {
			isConnect = true
			connectAddr = w.peers[0].Endpoint
			reserved = w.peers[0].Reserved
		}
		bind = wireguard.NewClientBind(w.ctx, w, w.listener, isConnect, connectAddr, reserved)
	}

	wgDevice := device.NewDevice(w.tunDevice, bind, &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			w.logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			w.logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}, w.workers)
	wgDevice.FakePackets = w.fakePackets
	wgDevice.FakePacketsSize = w.fakePacketsSize
	wgDevice.FakePacketsDelays = w.fakePacketsDelay
	mode := strings.ToLower(w.fakePacketsMode)
	if mode == "" || mode == "m1" {
		wgDevice.FakePacketsHeader = []byte{}
		wgDevice.FakePacketsNoModify = false
	} else if mode == "m2" {
		wgDevice.FakePacketsHeader = []byte{}
		wgDevice.FakePacketsNoModify = true
	} else if mode == "m3" {
		// clist := []byte{0xC0, 0xC2, 0xC3, 0xC4, 0xC9, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF}
		wgDevice.FakePacketsHeader = []byte{0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3}
		wgDevice.FakePacketsNoModify = false
	} else if mode == "m4" {
		wgDevice.FakePacketsHeader = []byte{0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3}
		wgDevice.FakePacketsNoModify = true
	} else if mode == "m5" {
		wgDevice.FakePacketsHeader = []byte{0xC0, 0xC2, 0xC3, 0xC4, 0xC9, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF}
		wgDevice.FakePacketsNoModify = false
	} else if mode == "m6" {
		wgDevice.FakePacketsHeader = []byte{0x40, 0x42, 0x43, 0x44, 0x49, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}
		wgDevice.FakePacketsNoModify = true
	} else if strings.HasPrefix(mode, "h") || strings.HasPrefix(mode, "g") {
		clist, err := hex.DecodeString(strings.ReplaceAll(mode[1:], "_", ""))
		if err != nil {
			return err
		}
		wgDevice.FakePacketsHeader = clist
		wgDevice.FakePacketsNoModify = strings.HasPrefix(mode, "h")
	} else {
		return fmt.Errorf("incorrect packet mode: %s", mode)
	}

	ipcConf := w.ipcConf
	for _, peer := range w.peers {
		ipcConf += peer.GenerateIpcLines()
	}
	err = wgDevice.IpcSet(ipcConf)
	if err != nil {
		return E.Cause(err, "setup wireguard: \n", ipcConf)
	}
	w.device = wgDevice
	w.pauseCallback = w.pauseManager.RegisterCallback(w.onPauseUpdated)

	return w.tunDevice.Start()
}

func (w *WireGuard) Close() error {
	if w.hforwarder != nil { //hiddify
		w.hforwarder.Close() //hiddify
	} //hiddify
	if w.device != nil {
		w.device.Close()
	}
	if w.pauseCallback != nil {
		w.pauseManager.UnregisterCallback(w.pauseCallback)
	}
	w.tunDevice.Close()
	return nil
}

func (w *WireGuard) InterfaceUpdated() {
	w.logger.Info("Hiddify! Wirguard! Interface updated!XXX")
	// <-time.After(10 * time.Millisecond)
	// if true {
	// 	return
	// }
	if w.pauseManager.IsNetworkPaused() {
		w.logger.Error("Hiddify! Network is paused!... returning")
		return
	}
	<-time.After(50 * time.Millisecond)
	err := w.device.BindUpdate()
	<-time.After(50 * time.Millisecond)
	// err := fmt.Errorf("Hiddify! downing wireguard interface failed")

	if err != nil {
		w.logger.Error("Hiddify! bind update failed", err)
	}
	// w.logger.Error("Hiddify! downing...")
	// e1 := w.device.Down()
	// if e1 != nil {
	// 	w.logger.Error("Hiddify! downing wireguard interface failed", e1)
	// } else {
	// 	w.logger.Warn("Hiddify! downing   Ok!")
	// }
	// for i := 0; i < 5; i++ {
	// 	if !w.pauseManager.IsNetworkPaused() {
	// 		break
	// 	}
	// 	if i == 4 {
	// 		w.logger.Error("No network is availble after 4 seconds, stopping wireguard.")
	// 		return
	// 	}
	// 	w.logger.Warn("Network is pause waiting ", i)
	// 	select {
	// 	case <-time.After(1 * time.Second):
	// 		// case <-w.conn.done:
	// 		// 	return
	// 	}
	// }
	// <-time.After(100 * time.Millisecond)
	// w.logger.Warn("Hiddify! uping.... wireguard interface")
	// e2 := w.device.Up()
	// if e2 != nil {
	// 	w.logger.Error("Hiddify! Uping wireguard interface failed", e2)
	// } else {
	// 	w.logger.Warn("Hiddify! OK!Updating wireguard interface")

	// }
	// } else {
	// 	w.logger.Warn("Hiddify! OK2!Updating wireguard interface")
	// }
	return
}

func (w *WireGuard) onPauseUpdated(event int) {
	w.logger.Info("Hiddify! Wirguard! on Pause updated! event=", event)
	// <-time.After(1000 * time.Millisecond)
	switch event {

	case pause.EventDevicePaused:
		w.device.Down()
	case pause.EventNetworkPause: //hiddify already handled in Interface Updated
		err := w.device.Down()
		w.logger.Info("Hiddify! Wirguard! downing net! err=", err)
		<-time.After(50 * time.Millisecond)
	case pause.EventDeviceWake:
		w.device.Up()
	case pause.EventNetworkWake: //hiddify already handled in Interface Updated
		err := w.device.Up()
		w.logger.Info("Hiddify! Wirguard! Uping net! err=", err)
		<-time.After(50 * time.Millisecond)
	}
}

func (w *WireGuard) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if r := recover(); r != nil {
		fmt.Println("SWireguard error!", r, string(debug.Stack()))
	}
	// if !w.device.IsUp() {
	// 	return nil, E.New("Interface is not ready yet")
	// }

	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := w.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.tunDevice, network, destination, destinationAddresses)
	}
	return w.tunDevice.DialContext(ctx, network, destination)
}

func (w *WireGuard) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if r := recover(); r != nil {
		fmt.Println("SWireguard error!", r, string(debug.Stack()))
	}
	// if !w.device.IsUp() {
	// 	return nil, E.New("Interface is not ready yet")
	// }
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := w.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, w.tunDevice, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, err
	}
	return w.tunDevice.ListenPacket(ctx, destination)
}

func (w *WireGuard) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewDirectConnection(ctx, w.router, w, conn, metadata, dns.DomainStrategyAsIS)
}

func (w *WireGuard) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewDirectPacketConnection(ctx, w.router, w, conn, metadata, dns.DomainStrategyAsIS)
}
