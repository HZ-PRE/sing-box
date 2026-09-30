// Shared VLESS framing and XUDP/Mux constants. No VMess handshake implementation.
package vmess

import (
 "net"
 M "github.com/sagernet/sing/common/metadata"
 N "github.com/sagernet/sing/common/network"
)

type Handler interface { N.TCPConnectionHandlerEx; N.UDPConnectionHandlerEx }
type PacketConn interface { net.Conn; N.NetPacketConn }

const (
	CommandTCP = 1
	CommandUDP = 2
	CommandMux = 3
)
const (
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
var AddressSerializer = M.NewSerializer(M.AddressFamilyByte(0x01, M.AddressFamilyIPv4), M.AddressFamilyByte(0x03, M.AddressFamilyIPv6), M.AddressFamilyByte(0x02, M.AddressFamilyFqdn), M.PortThenAddress())
