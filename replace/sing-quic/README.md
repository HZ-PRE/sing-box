# Retained QUIC transport support

Derived from `github.com/sagernet/sing-quic`
v0.6.2-0.20260525051024-9467ede27fb7. The original license is retained in
`LICENSE`.

Only the shared QUIC TLS helpers (`quic.go` and `quic_error.go`) remain, for
VLESS transports and DNS. Hysteria, Hysteria2 and TUIC implementations were
removed.
