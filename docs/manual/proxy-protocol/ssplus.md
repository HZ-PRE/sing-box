# SSPlus v2：随机 PSK、Noise/X25519 与密钥轮换

本次服务端与 sdm-core 必须一起更新。v1、SSR protocol、旧 `tls1.2_ticket_auth` 实现和 password 派生接口已删除，没有兼容或降级路径。v2 可选用重新实现的 `tls-ticket` 轻量外观层；它只承载 v2，不恢复旧认证或旧客户端兼容。

## 密钥与配置

每个用户使用独立的 **32 随机字节**，编码为带 `=` 的标准 Base64。节点的 `iv_key` 也独立随机生成，不与用户 key 混用。长度校验无法判断熵；禁止用人类密码、UUID、全零或重复字节填充。

在 XrayR 根目录构建和生成密钥：

```powershell
go build -trimpath -ldflags '-s -w' -o XrayR.exe .
./XrayR.exe ssplus-key
```

每次命令生成一份 `{ "key": "…", "key_id": … }`，通过现有受保护的订阅/管理通道分发。节点 iv_key 也可以单独运行一次命令生成，仅取 key。不要把输出写入公共日志。Linux 可使用 `openssl rand -base64 32`；省略 key_id 时两端从 SHA-256(key) 的前四字节大端整数推导，零映射为 1。key_id 只是公开选择器，不负责认证。

sdm-sing-box 出站：

```json
{
  "type": "ssplus", "tag": "ssplus-out",
  "server": "server.example", "server_port": 8389,
  "method": "aes-256-gcm",
  "iv_key": "<节点的32字节随机密钥Base64>",
  "user_id": 1001, "key": "<用户的32字节随机密钥Base64>",
  "padding": "initial", "padding_budget": 1024,
  "udp_over_tcp": {"enabled": false, "version": 2}
}
```

`method` 也支持 `chacha20-ietf-poly1305`。默认优先原生 UDP，失败回退 UoT；`udp_over_tcp.enabled=true` 强制 UoT，version 可为 1 或 2。原生 UDP 需开放同端口 UDP，TCP 始终需要开放。

sdm-sing-box 入站使用 `users` 数组，用户字段为 `user_id`、`key`、可选 `key_id`、`name` 以及下面的轮换字段。Xray 静态入站对应 `settings.clients`，用户名称字段为 `email`。配置类型仍为 `ssplus`。

## 用户密钥轮换

服务端用户可配置：

```json
{
  "user_id": 1001,
  "key": "<新随机key>", "key_id": 12,
  "previous_key": "<旧随机key>", "previous_key_id": 11,
  "previous_valid_until": 2000000000
}
```

上面时间仅为格式示例；实际应填写计划宽限期的 Unix 秒时间戳，且严格按 `now < previous_valid_until` 判断。当前与旧 key、key_id 必须分别不同。每用户最多两把密钥，查找 O(1)，不遍历所有用户试解密。

操作顺序：生成新 key → 服务端发布新 key 和旧 key 的短期宽限 → 客户端订阅切换至新 key → 宽限到期后从面板/配置删除旧 key。省略 key_id 时自动推导；若发生同一用户两代 ID 碰撞，显式指定不同的非零 ID。配置发布由面板或运维系统执行，代码不会擅自定时生成并分发新用户密钥。

账号更新原子替换密钥环。进行中的旧快照握手在最终确认时被拒绝；已建立的 TCP/UDP 会话继续使用会话密钥，直到结束或超时。删除用户同样阻止新会话，不强制踢断已认证连接。旧 key 到期立即不再用于认证，但配置、不可变快照中的旧 key 字符串须在下次更新/重载后才可被回收；不要把到期理解为立即内存擦除。

## XrayR 面板接入

`NodeType: Shadowsocks`，在 ControllerConfig 中设置：

```yaml
SSPlusConfig:
  Enabled: true
```

节点采用专用 TCP/UDP 入口，关闭外部 TLS/REALITY 与其他传输插件。TCP 固定使用 `tls-ticket` 轻量 TLS 1.2 session-ticket 外观，原生 UDP v4 固定使用 `quic-like` 外观；服务端和客户端都不提供选择字段，也不自动探测、降级为原始 v2 流量。节点 `iv_key`、`padding` 和 `padding_budget` 从面板节点信息读取，不在 SSPlusConfig 下填写。

NewXboard 节点接口 `/openapi/nodeserver/node` 的 data 提供 `method`、`outPort`、`ivKey`、`padding` 和 `padding_budget`，不再提供 `tcp_obfs` 或 `udp_obfs`。`padding` 可为 `initial`、`light`、`off`，预算范围0～65536；省略或填0时使用 `initial / 1024` 默认值。无效值会阻止节点入站启动。用户接口 `/openapi/nodeserver/users` 的 data 为数组，每项提供 `id`、`passwd`（现在必须是随机32字节key的Base64），可附 `key_id`、`previous_key`、`previous_key_id`、`previous_valid_until`。流式与普通解析都保留这些轮换字段，继续使用原流量统计、路由、限速和设备限制链路。

其他面板适配器仍可通过 Passwd 提供当前随机 key，但必须能提供节点 iv_key，完整轮换字段目前接入 NewXboard。原 UUID/password 订阅必须迁移；普通 ss:// 订阅不会自动转换为 v2。面板网站和 Flutter GUI 不在本次源码修改范围内，订阅生成端需输出上述 key 字段。

## 握手与记录格式

使用 `github.com/flynn/noise v1.1.0`：

- `Noise_NNpsk0_25519_AESGCM_SHA256` 或 `Noise_NNpsk0_25519_ChaChaPoly_SHA256`。
- 身份封装48字节：随机16字节 + AES-GCM加密的16字节身份字段 + 16字节tag。身份明文包含版本2、套件、保留位、user_id、key_id、Unix秒。随机值用于派生独立身份密钥；完整封装绑定进 Noise prologue。
- 第一、第二 Noise 消息均为 uint16BE长度 + Noise消息，消息最大512字节，解密的握手填充最多127字节。**第一消息没有目标地址或应用数据**。
- 客户端验证第二消息后，通过第一条传输记录发送目标地址；服务端认证这条记录后才允许路由、拨号。即使重启丢失重放缓存，旧确认记录也不能确认新服务端临时密钥。
- TCP传输：AEAD加密的2字节长度（含tag共18字节）+ AEAD加密的 `[uint16应用长度 | 应用数据 | 可选填充]`。单条明文最多16384字节，最大应用数据16382字节；每记录固定开销36字节，填充0～127字节。读写各自串行，缓冲按需增长并复用，认证/长度错误后连接状态不可继续使用。
- 标准AES-GCM/ChaCha20-Poly1305通过每CipherState独立的nonce缓冲区适配Noise，避免库默认适配层每次分配nonce切片。nonce编码、AEAD输出及最大nonce边界与上游实现逐字节对照，并覆盖固定Noise参考向量；握手状态机仍由库实现。
- 每方向65536条记录调用 Noise `Rekey`，不重置nonce，无额外轮换包。属于对称密钥演进，不是重新执行X25519，也不提供密钥泄漏后的自动恢复能力。

### TCP `tls-ticket` 外观层

客户端第一飞行固定放入可由标准 TLS 解析器读取的 TLS 1.2 ClientHello session-ticket 扩展；服务端用 ServerHello、ChangeCipherSpec 和加密 Finished 外观返回第二飞行。后续 SSPlus 密文包装为 TLS Application Data 风格记录，外层只增加5字节记录头，不重复加密。连接模式写入 Noise prologue，不接受无外观线路的降级或重放。

这不是 TLS：没有证书、TLS Finished 校验或浏览器互操作。真实 TLS 客户端无法完成握手，深度探测可据此识别。普通 HTTPS 请求会静默关闭，不会转交网站。

## 原生 UDP v4

通过上述 PFS TCP 流下发随机会话种子，控制地址 `sp.v2.native-udp.ssplus.arpa`、bootstrap标识 `SSPUDP04`。沿用逐目标路由、路径验证、反放大、MTU、分片预算和1024包重放窗口。

每方向每65536包，通过带域隔离的HKDF更新payload密钥；不重置62位包序号。接收端只在完整认证成功后提交新代，保留上一代AEAD以处理跨代乱序，同时丢弃旧派生secret；伪造新代包不能推进状态。连续丢失超过一整代的数据，需要重新建立会话。

线路包使用 QUIC v1 1-RTT 风格短包头：固定位、16字节方向独立CID、4字节截断包号，以及与 RFC 9001 相同位置的头部保护。它仍不是完整 QUIC，没有 Initial/TLS、ACK、拥塞控制、连接迁移协议或 HTTP/3；完整 QUIC 解码器可以识别差异。未认证的真实 QUIC Initial 和未知 CID 不产生响应或会话状态。

## 填充和主动探测边界

默认 initial，优先握手、目标地址及前8条应用记录，按多个长度区间随机填充。每方向每连接总预算默认1024字节，与原生UDP共享；大流量停止填充。light 可继续为<=256字节的小包提供最多31字节填充，仍受总预算限制。off 关闭可选填充。原生UDP `udp_padding` 上限默认31，范围0～31。MTU路径探测的必要字节不算可选填充。

认证前读取上限32KiB、时限10秒、每服务实例最多128个并发握手；用户/密钥未知和错误凭据均静默关闭，不返回SSPlus专属错误，不触发目标拨号。重放缓存最多65536条，保留约4分钟，满时拒绝新握手而不驱逐有效条目；这限制单实例短时间内的新建连接总量。错误原因只在本地处理/日志中可见，不声称所有失败路径严格等时。

这是专用TCP/UDP入口。轻量外观层只降低简单首字节、记录类型和固定包头规则的识别效果，不等同真实 HTTPS/QUIC，也不保证无法被流量分类器识别。需要抵抗完整握手验证时，应改用真实 TLS 1.3 + HTTP/WebSocket 或真实 QUIC DATAGRAM/HTTP3 承载。

## 安全审查范围与限制

采用公开规范和公开分析过的Noise模式，并检查本地封装、状态机、密钥方向、重放、轮换和资源边界；**没有声称本项目或所选Go库已经获得独立第三方审计**。

参考：[Noise规范](https://noiseprotocol.org/noise.html)、[NNpsk0分析](https://noiseexplorer.com/patterns/NNpsk0/)、[flynn/noise](https://github.com/flynn/noise/tree/v1.1.0)。第一飞行只具有PSK保护，因此不携带业务数据；业务数据等临时DH完成后发送。攻击者事后仅取得长期PSK，且临时/会话秘密已销毁时，不能据此还原历史业务流量。持有PSK的主动攻击者可冒充任一端；此方案不是证书身份系统，也不是后量子协议。

临时私钥、过渡派生字节尽力clear；Go GC、不可变字符串和库内部副本不提供可验证的全内存零化保证。业务进程被完全攻陷、密钥分发被攻陷或端点仍保存会话秘密时，以上历史保密条件不成立。

本地固定已知答案覆盖两种套件、双方飞行、双向split密钥、有无prologue和消息载荷；并测试重放、篡改、错误身份、轮换/撤销、跨代乱序、长度上限、超时与并发。验证结果与性能数据见服务端 `docs/SSPLUS-V2-RESULTS-2026-10-28.md`。
