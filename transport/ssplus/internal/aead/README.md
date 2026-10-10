AEAD stream framing retained from `github.com/sagernet/sing-shadowsocks` v0.2.8,
`shadowaead/aead.go`, under the accompanying GPL-3.0 license.

Only length-prefixed authenticated frame readers and writers are used by SS+.
Unused raw/vector/buffered APIs have been removed. The retained Read/Write paths
validate frame lengths, preserve v1 wire bytes, latch terminal errors, and grow
per-connection buffers only as needed. Callers serialize each direction.
Ordinary Shadowsocks client/server handshakes, password derivation, methods,
SS2022 and standalone Shadowsocks protocol registration are not included.
