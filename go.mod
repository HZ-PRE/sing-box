module github.com/sagernet/sing-box

go 1.25.6

require (
	github.com/anthropics/anthropic-sdk-go v1.26.0
	github.com/caddyserver/certmagic v0.25.2
	github.com/caddyserver/zerossl v0.1.5
	github.com/database64128/tfo-go/v2 v2.3.2
	github.com/go-chi/chi/v5 v5.2.5
	github.com/go-chi/render v1.0.3
	github.com/godbus/dbus/v5 v5.2.2
	github.com/gofrs/uuid/v5 v5.4.0
	github.com/insomniacslk/dhcp v0.0.0-20260220084031-5adc3eb26f91
	github.com/jsimonetti/rtnetlink v1.4.0
	github.com/keybase/go-keychain v0.0.1
	github.com/libdns/acmedns v0.5.0
	github.com/libdns/alidns v1.0.6
	github.com/libdns/cloudflare v0.2.2
	github.com/libdns/libdns v1.1.1
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mdlayher/netlink v1.9.0
	github.com/metacubex/utls v1.8.4
	github.com/mholt/acmez/v3 v3.1.6
	github.com/miekg/dns v1.1.72
	github.com/openai/openai-go/v3 v3.26.0
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/pires/go-proxyproto v0.8.1
	github.com/sagernet/asc-go v0.0.0-20241217030726-d563060fe4e1
	github.com/sagernet/bbolt v0.0.0-20231014093535-ea5cb2fe9f0a
	github.com/sagernet/cors v1.2.1
	github.com/sagernet/fswatch v0.1.1
	github.com/sagernet/gomobile v0.1.12
	github.com/sagernet/quic-go v0.59.0-sing-box-mod.4
	github.com/sagernet/sing v0.8.11-0.20260514110501-905ad103a4df
	github.com/sagernet/sing-mux v0.3.4
	github.com/sagernet/sing-quic v0.6.2-0.20260525051024-9467ede27fb7
	github.com/sagernet/sing-shadowsocks v0.2.8
	github.com/sagernet/sing-shadowsocks2 v0.2.1
	github.com/sagernet/sing-tun v0.8.10-0.20260519125758-eb58efc8915d
	github.com/sagernet/sing-vmess v0.2.8-0.20250909125414-3aed155119a1
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netns v0.0.5
	go.uber.org/zap v1.27.1
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.48.0
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93
	golang.org/x/mod v0.33.0
	golang.org/x/net v0.50.0
	golang.org/x/sys v0.41.0
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
	howett.net/plist v1.0.1
)

require (
	github.com/kr/pretty v0.3.1 // indirect
	github.com/sagernet/gvisor v0.0.0-20250811.0-sing-box-mod.1 // indirect
	github.com/sagernet/smux v1.5.50-sing-box-mod.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

require (
	github.com/AdguardTeam/golibs v0.32.7 // indirect
	github.com/ameshkov/dnscrypt/v2 v2.4.0
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/biter777/countries v1.7.5
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	golang.org/x/sync v0.19.0
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
)

//replace github.com/sagernet/sing => ../sing

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1 // indirect
	github.com/florianl/go-nfqueue/v2 v2.0.2 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-mod.2 // indirect
	github.com/sdm/hmrd_multi_resolver_dns v0.0.0-20260429114007-8d809dc33d0e
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.4.1
)

replace github.com/sagernet/sing-vmess => ./replace/sing-vless

replace github.com/sagernet/sing-dns => github.com/shtorm-7/sing-dns v0.4.6-extended-1.0.0

replace github.com/ameshkov/dnscrypt/v2 => github.com/shtorm-7/dnscrypt/v2 v2.4.0-extended-1.0.0

replace github.com/sagernet/sing-shadowsocks2 => ./replace/sing-shadowsocks2

replace github.com/sdm/hmrd_multi_resolver_dns => ../third_party/hmrd_multi_resolver_dns

replace github.com/sagernet/sing-quic => ./replace/sing-quic
