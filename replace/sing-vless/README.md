# Retained VLESS and framing support

Derived from `github.com/starifly/sing-vmess` at `v0.2.7-mod.9`.
The upstream module and root package names remain for import compatibility.
Only VLESS/Vision, packetaddr, XUDP and multiplex framing are retained.
VMess clients, servers, authentication, KDF and chunk encryption are absent.
Retained implementation files are unchanged; shared declarations were extracted
into `protocol.go`. The upstream license is included.
