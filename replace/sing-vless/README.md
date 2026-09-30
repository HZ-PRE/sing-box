# Retained VLESS support

Derived from `github.com/starifly/sing-vmess` v0.2.7-mod.9 (the project's
previous replacement for `github.com/sagernet/sing-vmess`). The original
license is retained in `LICENSE`.

Only VLESS, packetaddr, XUDP and the shared mux framing used by VLESS remain.
VMess clients, services, key derivation and protocol ciphers were removed.
The original module/package names remain to preserve the shared VLESS imports;
they do not enable VMess proxy support.
