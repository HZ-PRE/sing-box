# SS+ v1：SS AEAD + SSR 插件 + 多用户 IV + 原生 UDP v3

配置类型为 `ssplus`，实现客户端与服务端。它是一套自定义协议：沿用 SS 地址编码和 AEAD 分帧、SSR 协议插件与混淆及原生 UDP v3，使用新的多用户握手和密钥派生。本页示例为 `auth_aes128_md5` + `tls1.2_ticket_auth`。**完整连接不兼容普通 SS、SSR 或 SS2022 服务端；两端必须使用本实现。**

## 原有结构与接入位置

| 层 | 仓库现状 | SS+ 实现 |
| --- | --- | --- |
| 配置与注册 | `option`、`include/registry.go` | `SSPlusInboundOptions`、`SSPlusOutboundOptions`，独立类型 `ssplus` |
| SS | 出站 `sing-shadowsocks2`，入站 `sing-shadowsocks` | 复用 `sing-shadowsocks/shadowaead` 的 Reader/Writer |
| 用户扩展 | 现有 SS 出站的 `AA + uint8(len) + user_id` 是明文前缀，并非 IV | 48 字节随机化、认证加密的用户 IV；按 ID 查找独立用户密钥 |
| SSR | 现有 `shadowsocksr` 注册项只返回“已移除”错误 | 内置 `auth_aes128_md5` / `auth_sha1_v4` / `origin` 与 `tls1.2_ticket_auth` 混淆 |
| UDP | `transport/ssplus/native_*` | 默认原生 UDP v3，失败回退 UoT；可强制 UoT v1/v2 |
| 应用校验 | `v2/config` 限制可用协议和加密方式 | 放行 `ssplus` 并验证密码套件、插件、密钥和用户 ID |

发送顺序：`目标地址 + TCP 数据或原生 UDP 控制数据 → SSR protocol → SS AEAD → SSR obfs → TCP`。未混淆的请求端先发送用户 IV，响应端先发送随机响应盐；启用 TLS ticket 时，先完成混淆握手，再用 ApplicationData 记录包装这些字节。

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
- `udp_padding`：原生 UDP 随机填充上限，默认 31，范围 0～31。仅影响原生 UDP，不影响 UoT。
- `udp_over_tcp`：默认 `false`，原生 UDP 失败时回退 UoT v2；`true` 强制 UoT v2。对象形式 `{ "enabled": true, "version": 1 }` 可指定 UoT v1；`enabled: false` 指定回退使用的版本。
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
    "udp_padding": 31
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

## 生命周期与限制

- AEAD 解密出的单记录长度统一限制为 `0x3fff`，超长、截断或认证错误后不再继续读写该方向。允许空记录，但单次读取连续遇到 100 个空记录时返回错误，避免已持有密钥的对端无限占用读取循环。
- AEAD 与 SSR 数据帧缓冲按连接、方向复用；足够大的调用方读取缓冲直接用于 AEAD 解密。TLS 外形混淆保持每条记录最多 4096 字节，最多四条已就绪记录合并一次底层写入。客户端握手写入在读取服务端响应前、以及返回连接前立即刷新，合并 Finished、IV 和地址，不引入定时等待，保持服务端先发数据的协议可用。
- 防重放缓存按时间桶回收，保留期不短于 241 秒，正常时间前进时最多向上取整 1 秒。只清理已过期条目，不扫描全部存活条目；没有额外常驻清理线程。缓存只属于当前入站实例，不提供跨进程或跨服务器的防重放状态共享。
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

测试覆盖双密码套件、双插件、多用户、碎片读写、大载荷、服务端先发数据、篡改和错误密钥、IV 时效和重放、跨请求响应拒绝、原生 UDP v3，以及真实 TCP 回环中的配置注册与路由用户信息。

## tls1.2_ticket_auth 混淆

混淆包裹在 SS+ IV 和 AEAD 流外层，服务端此时还不知道用户，因此使用共享 `iv_key` 作为原 SSR obfs 的 Key。每个连接随机生成 32 字节 session ID。ClientHello 和 ServerHello 的 random 是时间戳 4 字节（大端）+ 随机 18 字节 + HMAC-SHA1 截断 10 字节；HMAC 密钥为 `iv_key || session_id`。

流程：ClientHello → ServerHello / ChangeCipherSpec / Finished → 客户端 ChangeCipherSpec / Finished → 双向 ApplicationData。Finished 的 HMAC 覆盖相应方向的握手记录；客户端也验证服务端 random 与返回的 session ID。支持原 SSR 服务端可选 NewSessionTicket。ClientHello 可通过 `obfs_param` 设置单个 SNI 域名，不需要证书。

服务端验证 ±120 秒时间窗并缓存 ClientHello 防重放标记，缓存与 SS+ IV 共用 65536 个条目的上限，每个启用混淆的连接占用两个标记。账号同步不清空缓存。握手支持分片、粘包、短写，收发均受握手 deadline 约束。应用记录只接受 TLS 1.2 ApplicationData 形状，单记录最多 16384 字节。

这是 SSR 的 TLS 外形混淆，不是标准 TLS。它不进行证书验证，也不提供前向保密；业务流的机密性与完整性由 SS+ AEAD 提供。不要将普通 TLS 客户端或额外 TLS transport 配置到这个端口。

互通验证参考 Dreamacro/clash v1.18.0 的 `transport/ssr/protocol` 和 `transport/ssr/obfs`，以隔离的测试依赖运行两个原版 SSR 客户端与本实现的交互；参考依赖不进入产品二进制。报文布局同时核对了 shadowsocksrr/shadowsocksr 的 `obfsplugin/auth.py`、`obfsplugin/obfs_tls.py`。测试源位于配套 Xray 项目的 `testing/ssplusinterop/testdata/ssr_reference_test.go`。

## UDP 策略：原生 UDP v3 + UoT 回退

客户端 `udp_over_tcp` 省略或为 `false` 时，优先尝试新版 QUIC 短包头外形 UDP v3；建立失败、超时或原生版本不匹配时，自动回退 UoT。为 `true` 时，所有 UDP 请求直接使用 UoT，不探测原生 UDP。TCP 业务不受此选项影响。

UoT 默认 v2；对象配置 `{ "enabled": true, "version": 1 }` 强制 v1，`{ "enabled": false, "version": 1 }` 则在原生失败时回退 v1。版本 0/省略按 v2 处理，其他版本拒绝。服务端同时接受原生 v3 与 UoT v1/v2；不恢复原生 UDP v1/v2。

原生会话建立预算为 2 秒（调用方更短的 deadline 优先）。新版 SDM 客户端等待 250 ms 后并行建立备用 UoT，原生提前失败则立即启动备用连接；首个成功通道胜出，取消并关闭另一通道。业务报文只在选定后发送。原生失败或 UoT 胜出后进入 30 秒冷却；冷却结束再次尝试。未知节点同时只进行一次能力探测，其余会话直接使用 UoT；已确认可用的原生会话独立建立。网络接口变化清除能力缓存，旧网络上的结果不会覆盖新网络状态。没有后台探测定时器，调用方取消不记录失败。

回退发生在首个业务报文发送之前，不重放已发送请求。已建立原生会话在使用中丢包、目标不响应或中途断网，不会自动迁移到 UoT；后续新会话重新建立时应用上述策略。UoT 增加 TCP 队头阻塞风险，不能承诺弱网延迟低于原生 UDP。

配置保留 `udp_over_tcp` 和 `udp_padding`（默认 31，范围 0～31）。旧 `udp_mode`、`native_udp` 仍被忽略并在序列化时移除，策略只由 `udp_over_tcp` 控制。服务端需部署支持 UoT 的本次版本；原生路径仍需要放行节点相同端口的 TCP/UDP。

认证沿用已有 SS+ 加密 TCP 流，建立会话后 TCP 仅管理生命周期；UDP 使用随机会话密钥、HKDF 分方向派生、节点配置的 AES-256-GCM 或 ChaCha20-Poly1305，以及逐方向最大 62 位序号。1024 包滑动窗口拒绝重放并允许乱序，只有认证通过才更新窗口。不是标准 Shadowsocks/SSR UDP，必须使用配套实现。

基础线报文不超过 1200 字节；下述 MTU1 扩展验证通过后，紧凑单报文最多 1360 字节。超过单包容量仍使用原有分片，最多支持 65507 字节业务数据。每个会话最多 8 个重组任务、256 KiB 不完整报文；超时 5 秒丢弃，丢失报文不会阻塞后续独立报文。完成队列最多 8 包；客户端总报文预算 512 KiB，服务端每入站总报文预算 16 MiB、最多 512 个会话，超过上限丢包或拒绝新会话。预算不包含加密对象、socket 和路由自身内存。

会话初建和 NAT 地址变化通过加密 challenge/confirm 验证回程可达性。验证前控制响应不大于请求，不转发业务数据；迁移触发的业务包丢弃，不重传。TCP 关闭或服务端 60 秒无业务活动会回收会话。无后台保活包。接收 socket 尝试设置 256 KiB 缓冲，系统可能按自身限制调整。

本功能不添加真正 TLS、证书或前向保密。既有 SSR/TLS 外形混淆用于 TCP 流（TCP 业务、UoT 或原生 UDP 控制流），原生 UDP 是自定义加密报文，不承诺隐藏协议特征。原生 UDP 避免 TCP 队头阻塞，但弱网可能丢包，大包分片开销高于小包；应用的可靠传输需由 QUIC 等上层负责。

新增验证：`go test -race ./transport/ssplus/... ./protocol/ssplus -count=3`，`go test ./transport/ssplus -run '^$' -fuzz FuzzNativeDatagram -fuzztime=20s`。配套 Xray `testing/ssplusinterop/testdata/client_test.go` 覆盖真实跨进程 TCP、新版原生 UDP、双算法/三个认证组合/两用户、多目标路由和大包。

### 原生 UDP v3：QUIC 短包头外形混淆

当前客户端和服务端仅接受 `SSPUDP03` 引导标识；旧版 `SSPUDP01` / `SSPUDP02` 会被明确拒绝，可按客户端策略回退到 UoT。TCP 业务线格式不变。

- 线格式：QUIC 短包头标志（1 字节）+ 方向独立的目的连接 ID（16 字节）+ 受保护的截断包序号（4 字节）+ SS+ AEAD 密文。Header Form=0、Fixed Bit=1、Spin Bit=0，移除头保护后 Reserved/Key Phase=0，Packet Number Length=4。
- 头保护遵循 QUIC 短包头的布局：从 PN 偏移加 4 的位置取 16 字节密文样本，使用独立 AES-256 密钥生成掩码，保护首字节低 5 位和 4 字节包序号。它不是标准 QUIC 密钥协商或 QUIC 帧编码。
- 使用 RFC 9000 A.3 的四字节包序号还原算法。完整序号上限为 2^62-1；AEAD nonce 使用完整序号，不会在截断序号跨越 2^32 时重用。防重放窗口仍为 1024 包，只在认证及封装校验成功后更新。
- AEAD 方向标签是 `ssplus/v1/native-udp/v3/request` / `response`；头保护密钥追加 `/header`，连接 ID 追加 `/cid`，均由每会话随机材料独立派生。服务端按接收方向 CID 做 O(1) 查找，无逐会话试密钥。CID 在会话内固定，仍可关联流量。
- `udp_padding` 默认 31，允许整数 0～31，仅控制本端发送。0 关闭额外随机填充，仍保留短包头保护、长度封装和基础控制包长度；两个方向可独立设置。填充长度来自批量读取的系统密码学随机数，填充字节在加密前置零。
- 加密内容仍为实际长度（2 字节）+ 数据/控制内容 + 填充。基础 UDP 负载上限 1200 字节，预留最大填充后单片数据容量 1116 字节；该分片格式保持不变。MTU1 紧凑报文另见下文。最大业务数据报仍为 65507 字节。

### MTU1 可选紧凑报文扩展

认证 TCP 引导头仍为 `SSPUDP03`，后续 48 字节材料的前 8 字节可为 `SSPMTU1!`；其余 40 字节仍随机，包含完整 256 位会话秘密和随机盐。旧客户端将其作为普通派生材料使用；新客户端仅在收到该能力提示后发送较大探测包，连接旧服务端不会发送超出原上限的探测。

新客户端同时发送基础探测和 1360 字节加密探测。扩展控制明文长 1321 字节，沿用类型、16 字节 challenge token，并在偏移 17 写入 `MTU1`；其余字节置零。大包 challenge/confirm/ready 验证两个方向，响应不大于触发报文。任一方向不支持较大报文时，基础握手仍可完成，不增加等待较大探测的超时。

确认后可使用类型 6：`type[1] | 地址及载荷长度[2,BE] | SS地址 | UDP载荷`，不足 32 字节补零，再使用既有 AEAD、头保护、序号与防重放窗口封装。读写缓冲有界，接收数据仍计入报文预算。1200 字节业务载荷加常见 IPv4/IPv6/短域名地址可单包发送；过长域名和大数据报继续按 1116 字节分片。

这是每次会话建立时的固定大小路径探测，不是完整动态 PMTUD；已有会话中途路径 MTU 下降仍可能丢包，需要上层重建会话。升级服务端后才会启用扩展，普通 TCP 与 UoT 线格式不变。

路径验证响应的完整报文长度不超过触发请求，包括 NAT 迁移。没有定时伪装包、随机延迟、额外重传、新后台任务或额外运行时依赖；收发缓冲复用。

此功能仅模拟 QUIC 1-RTT 短包头外形：没有 QUIC Initial/Handshake、TLS 1.3、证书、ACK、拥塞控制或标准 QUIC DATAGRAM 帧，也不提供前向保密。普通 QUIC/HTTP3 客户端不能连接；抓包工具不保证将它识别为 QUIC，检测完整握手和流量行为仍可区分。不要宣称它是真正 QUIC 或无法识别。部署仍需放行节点同一端口的 TCP/UDP。
