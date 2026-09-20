# SS+ v1：SS AEAD + SSR 插件 + 多用户 IV + UoT

配置类型为 `ssplus`，实现客户端与服务端。它是一套自定义协议：沿用 SS 地址编码和 AEAD 分帧、SSR 协议插件与混淆及 sing 的 UoT，使用新的多用户握手和密钥派生。本页示例为 `auth_aes128_md5` + `tls1.2_ticket_auth`。**完整连接不兼容普通 SS、SSR 或 SS2022 服务端；两端必须使用本实现。**

## 原有结构与接入位置

| 层 | 仓库现状 | SS+ 实现 |
| --- | --- | --- |
| 配置与注册 | `option`、`include/registry.go` | `SSPlusInboundOptions`、`SSPlusOutboundOptions`，独立类型 `ssplus` |
| SS | 出站 `sing-shadowsocks2`，入站 `sing-shadowsocks` | 复用 `sing-shadowsocks/shadowaead` 的 Reader/Writer |
| 用户扩展 | 现有 SS 出站的 `AA + uint8(len) + user_id` 是明文前缀，并非 IV | 48 字节随机化、认证加密的用户 IV；按 ID 查找独立用户密钥 |
| SSR | 现有 `shadowsocksr` 注册项只返回“已移除”错误 | 内置 `auth_aes128_md5` / `auth_sha1_v4` / `origin` 与 `tls1.2_ticket_auth` 混淆 |
| UDP | `sing/common/uot` 与 `common/uot.Router` | 默认 UoT v2，可选 v1；底层仅监听/连接 TCP |
| 应用校验 | `v2/config` 限制可用协议和加密方式 | 放行 `ssplus` 并验证密码套件、插件、密钥和用户 ID |

发送顺序：`目标地址 + TCP 数据或 UoT 数据 → SSR protocol → SS AEAD → SSR obfs → TCP`。未混淆的请求端先发送用户 IV，响应端先发送随机响应盐；启用 TLS ticket 时，先完成混淆握手，再用 ApplicationData 记录包装这些字节。

当前示例使用 `auth_aes128_md5` + `tls1.2_ticket_auth`；仍支持 `auth_sha1_v4`、`origin` 和 `plain` 混淆。不支持 `auth_chain_*`、`auth_aes128_sha1`、其他 SSR obfs、SIP003 外部插件及 multiplex；未知插件会在初始化时报错，不会自动降级。

## 配置

- `method`：`aes-256-gcm`（默认）或 `chacha20-ietf-poly1305`。
- `protocol`：本示例为 `auth_aes128_md5`；保留 `auth_sha1_v4`（旧默认）和 `origin`，两端必须相同。
- `obfs`：本示例为 `tls1.2_ticket_auth`；省略仍为 `plain`，两端必须相同。
- `obfs_param`：可选单个 SNI 域名，仅用于客户端 ClientHello，服务端不按 SNI 校验或路由。
- `iv_key`：服务端与其所有客户端共享的身份封装密钥，标准 Base64 编码的 32 随机字节。
- `user_id`：非零 uint32；同一入站不允许重复。
- `key`：该用户独立的 32 字节随机密钥，标准 Base64 编码。不是口令，不支持 SS 的 EVP_BytesToKey。
- `password`：可以用面板随机密码/UUID 代替 `key`（二选一），适用于入站用户及出站。按 UTF-8 原样计算 `Base64(HKDF-SHA256(password, salt=空, info="ssplus/v1/password", length=32))`；该映射不增加密码熵。已有 `key` 的线格式保持不变。
- 入站 `users[].name`：写入路由元数据 `User`；省略时使用十进制 ID。
- 出站 `udp_over_tcp`：省略时启用 v2；可用 `true`、`false` 或 `{"enabled":true,"version":1|2}`。禁用后默认仅声明 TCP；显式请求 UDP 会报错。
- 出站支持现有 `ServerOptions`、`DialerOptions` 和 `network`；入站支持现有 `ListenOptions`。应用层仍禁止代理链。

分别运行 `openssl rand -base64 32` 三次生成 IV 密钥、Alice 密钥和 Bob 密钥，替换以下所有占位符。不要将三项设置为同一个密钥。

服务端完整 JSON：

```json
{
  "inbounds": [{
    "type": "ssplus",
    "tag": "ssplus-in",
    "listen": "::",
    "listen_port": 8389,
    "method": "aes-256-gcm",
    "protocol": "auth_aes128_md5",
    "obfs": "tls1.2_ticket_auth",
    "iv_key": "<IV_KEY_BASE64>",
    "users": [
      {"name": "alice", "user_id": 1001, "key": "<ALICE_KEY_BASE64>"},
      {"name": "bob", "user_id": 1002, "key": "<BOB_KEY_BASE64>"}
    ]
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
```

客户端完整 JSON（替换服务器地址）：

```json
{
  "inbounds": [{
    "type": "mixed", "tag": "local",
    "listen": "127.0.0.1", "listen_port": 2080
  }],
  "outbounds": [{
    "type": "ssplus",
    "tag": "ssplus-out",
    "server": "203.0.113.10",
    "server_port": 8389,
    "method": "aes-256-gcm",
    "protocol": "auth_aes128_md5",
    "obfs": "tls1.2_ticket_auth",
    "iv_key": "<IV_KEY_BASE64>",
    "user_id": 1001,
    "key": "<ALICE_KEY_BASE64>",
    "udp_over_tcp": {"enabled": true, "version": 2}
  }],
  "route": {"final": "ssplus-out"}
}
```

当前通过原生 JSON 配置使用；没有新增 `ssplus://` 分享链接、Clash 配置转换或客户端 GUI 字段。应用的配置构建流程可能重建本地入站；上面的完整配置也可供内核直接使用。

## 线格式（所有未特别注明的整数为大端）

### 用户 IV：48 字节

```
random[16] | encrypted_identity[16] | GCM_tag[16]
```

`identity` 明文：

| 偏移 | 长度 | 内容 |
| --- | --- | --- |
| 0 | 1 | 版本 `1` |
| 1 | 1 | 密码套件：`1` AES-256-GCM，`2` ChaCha20-Poly1305 |
| 2 | 1 | 插件：`0` origin，`1` auth_sha1_v4，`2` auth_aes128_md5 |
| 3 | 1 | 保留，必须为 `0` |
| 4 | 4 | user_id |
| 8 | 8 | Unix 时间戳，秒 |

所有派生均为 HKDF-SHA256，输出 32 字节。身份封装密钥：`HKDF(iv_key, salt=random, info="ssplus/v1/identity")`。身份使用 AES-256-GCM，nonce 为 12 个零字节，AAD 为 `random[16]`。每次连接随机派生不同封装密钥，因此不能把 `random` 配置成固定值。

服务端验证身份 AEAD、版本、套件、插件和 ±120 秒时间窗口，随后通过 user_id 查找用户。持有共享 iv_key 只能封装身份，不能替代所选用户的 key 完成载荷认证。

### 请求与响应

请求密钥：`HKDF(user_key, salt=完整48字节用户IV, info="ssplus/v1/request")`。

请求线上结构：`用户IV[48] | AEAD记录...`。第一段解密且移除 SSR 帧后的字节为 SS/SOCKS 地址：`ATYP | ADDR | PORT`，后接数据。

响应线上结构：`随机响应盐[32] | AEAD记录...`。响应密钥：`HKDF(user_key, salt=请求IV[48] || 响应盐[32], info="ssplus/v1/response")`。这将响应绑定到请求，且两个方向使用不同密钥。

AEAD 记录沿用 SS：`AEAD(uint16(payload_length)) | AEAD(payload)`。每个方向独立从全零 nonce 开始，按 SS 的小端计数规则递增；长度块与数据块各消耗一个 nonce；单记录明文上限 `0x3fff`。使用所选密码套件，记录无附加 AAD。

### SSR 插件

`auth_aes128_md5` 的插件 Key 为已通过 SS+ IV 选择的用户密钥，插件 IV 为完整 48 字节请求 IV，使用 SSR 单用户模式，无需 `protocol_param`。插件内的随机 UID 不承担 SS+ 多用户选择。

- 首帧：随机字节 1 + HMAC-MD5 截断 6 + UID 4 + AES 密文 16 + HMAC 截断 4 + 随机 padding + payload + HMAC 截断 4。
- 16 字节认证明文为 timestamp 4、client_id 4、connection_id 4、总长度 2、padding 长度 2，整数均为小端。
- AES-128-CBC 使用零 IV、密钥 `MD5(Base64(user_key) || "auth_aes128_md5")`；单个认证块不添加 PKCS padding。
- 首两个 HMAC 的密钥为 `请求IV || user_key`；尾部 HMAC 密钥为 `user_key`。
- 数据帧：小端总长度 2 + 长度 HMAC 2 + padding 描述与随机字节 + payload + HMAC 4。HMAC 密钥为 `user_key || uint32LE(sequence)`，两个方向独立从 1 计数；认证首帧不占序号。溢出后关闭连接，避免复用序号。
- 帧长严格小于 8192，支持扩展 padding；错误的长度、MAC、padding 或时间戳会关闭连接。

`origin` 原样传递明文。`auth_sha1_v4` 使用原 SSR 的首帧与数据帧格式，插件 `Key=user_key`，插件 `IV=完整48字节请求IV`：

- 客户端首帧：`length[2] | CRC32[4,LE] | padding | timestamp[4,LE] | client_id[4] | connection_id[4] | payload | HMAC-SHA1[:10]`。
- 首帧 CRC32 输入为 `length || "auth_sha1_v4" || Key`；HMAC 密钥为 `IV || Key`，输入为帧中除 HMAC 外的全部字节。
- 后续请求帧和全部响应帧：`length[2] | CRC32(length)低16位[2,LE] | padding | payload | Adler32[4,LE]`。
- padding 以一字节总长度开头；首字节为 `255` 时，后面两字节存储包含三字节前缀的总 padding 长度。
- 所有帧长度小于 8192；本实现单次数据切片上限 8100。支持分片、粘包和扩展 padding；校验失败即报错，不切换为裸流。

CRC32、Adler32 和 SSR SHA1 均为继承的插件格式；传输完整性由外层 AEAD 提供。已用 Dreamacro/clash v1.18.0 `transport/ssr/protocol` 做双向数据帧互验，参考客户端帧保存在 `transport/ssplus/testdata/auth_sha1_v4_clash.json`。

### UoT

v2 使用目标 `sp.v2.udp-over-tcp.arpa:0`，其后为现有 UoT 请求头（connect 标志、目标地址）及 UDP 帧。v1 使用 `sp.udp-over-tcp.arpa:0`。帧编码全部复用 sing 的 UoT 实现，支持 connect 和多目标模式。UDP 与普通 TCP 一样经过 SSR 插件和 AEAD，不建立原生 UDP 隧道。

## 生命周期与限制

- 请求握手超时 10 秒，客户端同时响应 context 取消；成功后清除握手 deadline。
- 验证用户载荷和目标地址后，才记录 IV 并交给路由。并发重复请求只接受一次。
- 每个入站最多记录 65536 个活跃 IV，保留 241 秒；满载时拒绝新握手，不淘汰仍有效的记录。记录到期按需回收。
- 重放缓存为进程内状态，重启会清空；共享 iv_key 的多实例不共享缓存。需要跨重启/多实例重放保证时，必须另行实现共享持久化缓存，或为实例分配独立密钥。
- 两端需要时钟同步。本版没有前向保密、用户热更新、身份撤销 API 或外部安全审计。

## 验证

在 `sdm-sing-box` 目录执行：

```sh
go test ./transport/ssplus ./protocol/ssplus -count=1
go test -race ./transport/ssplus ./protocol/ssplus -count=1
go test ./transport/ssplus -run '^$' -fuzz FuzzSSRDecode -fuzztime=5s
```

测试覆盖双密码套件、双插件、多用户、碎片读写、大载荷、服务端先发数据、篡改和错误密钥、IV 时效和重放、跨请求响应拒绝、UoT v1/v2，以及真实 TCP 回环中的配置注册与路由用户信息。

## tls1.2_ticket_auth 混淆

混淆包裹在 SS+ IV 和 AEAD 流外层，服务端此时还不知道用户，因此使用共享 `iv_key` 作为原 SSR obfs 的 Key。每个连接随机生成 32 字节 session ID。ClientHello 和 ServerHello 的 random 是时间戳 4 字节（大端）+ 随机 18 字节 + HMAC-SHA1 截断 10 字节；HMAC 密钥为 `iv_key || session_id`。

流程：ClientHello → ServerHello / ChangeCipherSpec / Finished → 客户端 ChangeCipherSpec / Finished → 双向 ApplicationData。Finished 的 HMAC 覆盖相应方向的握手记录；客户端也验证服务端 random 与返回的 session ID。支持原 SSR 服务端可选 NewSessionTicket。ClientHello 可通过 `obfs_param` 设置单个 SNI 域名，不需要证书。

服务端验证 ±120 秒时间窗并缓存 ClientHello 防重放标记，缓存与 SS+ IV 共用 65536 个条目的上限，每个启用混淆的连接占用两个标记。账号同步不清空缓存。握手支持分片、粘包、短写，收发均受握手 deadline 约束。应用记录只接受 TLS 1.2 ApplicationData 形状，单记录最多 16384 字节。

这是 SSR 的 TLS 外形混淆，不是标准 TLS。它不进行证书验证，也不提供前向保密；业务流的机密性与完整性由 SS+ AEAD 提供。不要将普通 TLS 客户端或额外 TLS transport 配置到这个端口。

互通验证参考 Dreamacro/clash v1.18.0 的 `transport/ssr/protocol` 和 `transport/ssr/obfs`，以隔离的测试依赖运行两个原版 SSR 客户端与本实现的交互；参考依赖不进入产品二进制。报文布局同时核对了 shadowsocksrr/shadowsocksr 的 `obfsplugin/auth.py`、`obfsplugin/obfs_tls.py`。测试源位于配套 Xray 项目的 `testing/ssplusinterop/testdata/ssr_reference_test.go`。
