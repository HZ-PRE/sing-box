// Package vmess retains the upstream package name for VLESS/XUDP compatibility.
// Only common framing remains; VMess authentication and encryption are removed.
package vmess

import (
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
)

const (
	CommandTCP      = 1
	CommandUDP      = 2
	CommandMux      = 3
	StatusNew       = 1
	StatusKeep      = 2
	StatusEnd       = 3
	StatusKeepAlive = 4
	OptionData      = 1
	OptionError     = 2
	NetworkTCP      = 1
	NetworkUDP      = 2
)

var MuxDestination = M.Socksaddr{Fqdn: "v1.mux.cool", Port: 666}

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x03, M.AddressFamilyIPv6),
	M.AddressFamilyByte(0x02, M.AddressFamilyFqdn),
	M.PortThenAddress(),
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type PacketConn interface {
	net.Conn
	N.NetPacketConn
}
