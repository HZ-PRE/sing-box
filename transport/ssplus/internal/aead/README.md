AEAD stream framing retained from `github.com/sagernet/sing-shadowsocks` v0.2.8,
`shadowaead/aead.go`, under the accompanying GPL-3.0 license.

Only length-prefixed authenticated frame readers and writers are used by SS+.
Ordinary Shadowsocks client/server handshakes, password derivation, methods,
SS2022 and standalone Shadowsocks protocol registration are not included.
