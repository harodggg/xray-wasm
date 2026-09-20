# 浏览器指纹伪装 · 安全审计（task-4）

> 审计对象：ClientHello profile 引擎（task-1，`crates/xt-wasm-tls/src/fingerprint.rs`）与
> REALITY 接线（task-2，`reality.rs` / `lib.rs`）。
> 审计输出：本文件 + `crates/xt-wasm-tls/tests/fingerprint_security.rs`。
> 最后更新：T1 引擎已落地并导出（`lib.rs` 的 `pub mod fingerprint;`），§0 的 ②③ 两项缺陷已修并有
> 回归测试；`reality.rs` 的握手接线（T2）**尚未落地**，所以「线上 ClientHello 实际换成 chrome 形状」的
> 条目仍标「阻塞 task-2」。本文件里的线上测试全部走 `reality_handshake`，T2 落地后会自动改为审计 chrome
> 形状的真实字节，无需改测试。

## 状态标记

| 标记 | 含义 |
|---|---|
| ✅ 已验证 | 有可复现实验/测试输出，命令与结果都写在文中 |
| ⚠️ 代码审查 | 只读了实现，引擎当前未被 `lib.rs` 引用、没有运行证据 |
| ❌ 缺陷 | 已复现的、应当修的问题（已报 lead / 归 backend 或 lead） |
| ❔ 未验证 | 证据不足，明确写出「缺什么才能判定」，**不写成「安全」** |

---

## 0. 结论摘要

| # | 审计项 | 结论 | 状态 |
|---|---|---|---|
| 1 | REALITY 认证语义未被削弱 | 位置语义（random=6..38、sid_len=38、session_id=39..71）在线上字节里成立；认证绑定**整条** ClientHello（AAD），任何单字节篡改都不能再通过认证；服务端不回显 session_id 时客户端拒绝且不重试。 | ✅（plain 形状）；chrome 形状待 T2 后复跑 |
| 2 | 每次连接的随机性 | 8 条线上 ClientHello：random / 认证密文 / GCM tag 两两不同；引擎侧 GREASE 随 seed 变化、`groups` 与 `key_share` 的 GREASE 成对、`new_grease_seed()` 每次新值、ECH 长度与总长随 seed 变化。 | ✅（引擎）；线上 chrome 待 T2 复跑 |
| 3 | 不引入更强可识别特征 | **挖出 3 个真问题，均已修并各有回归测试**：<br>①「声明 11ec 却不发 key_share」→ 5/5 SNI 触发 HelloRetryRequest，连接直接失败（已按实测删掉 11ec，复核 5/5 正常）；<br>② 洗牌把首尾 GREASE 也洗了（真 Chrome 恒钉首尾）→ 已改成只洗中间 16 个；<br>③ ECH 填充长度写死 → ClientHello 总长跨连接恒定 → 已改成由 seed 在 4 档里取。 | ✅ ①②③（回归测试见 §5.3） |
| 4 | 不静默降级 | `profile_by_name` 精确匹配、未知名字返回 `None`（含大小写/空白变体）；配置错误必须由 `RealityTlsLayer::new` 抛出。远端无法诱导回退：profile 在构造期固定，运行期没有基于远端输入的分支；HRR/伪造 ServerHello 实验里客户端只报错、**不重发第二份 ClientHello**。 | ✅ 引擎侧 + 远端侧；未知 profile 的**配置错误**测试阻塞 task-2 |
| 5 | 不泄漏本地信息 | 指纹路径无时间戳/pid/固定盐；GREASE/ECH 字节由 `rand::random::<u64>()`（ChaCha12 CSPRNG，宿主经 getrandom 取 OS 熵）派生。REALITY 的 unix 时间戳在 AES-GCM 密文里，只有服务端能读，且是协议要求。 | ✅ 引擎侧（含 `grease_seed_is_fresh_per_call`）；wasm 运行期熵源 ❔ |
| 6 | 拒绝解析 | 官方夹包的**每一个前缀长度**、4000 次确定性变异、8 类结构性畸形都不 panic；引擎对超长 SNI / ALPN 返回 `FingerprintError`（边界值不误拒）。另发现一处**可达性外**的潜在 panic（手工构造 `ClientHello` 时 `aad()` 越界）。 | ✅（解析器 + 引擎错误路径）；潜在 panic ❌低危 |

**最重要的一条**：本特性最大的风险不是「装得不像」，而是**装到一半把连接弄坏、并留下一个比现在更强的标签**。

- 真 Chrome 的 `supported_groups` 声明 `X25519MLKEM768(0x11ec)` 并**确实提供** 1216 字节 key_share；我们做不出这份 share。只要在 `supported_groups` 里保留 11ec 而不给 share，按 RFC 8446 §4.1.1 服务端 **MUST** 回 HelloRetryRequest，而客户端（`reality.rs:946-956`）明确把 HRR 判为失败 → 连接死。
- 实测：声明 11ec 不发 share，cloudflare / google / example 等 **5/5 SNI 全部 HRR**；把 11ec 从 `supported_groups` 和 `key_share` 同时删掉，**5/5 恢复 ServerHello**。
- 决策（lead 拍板）：默认 `chrome` profile 删除 11ec，得到一个「**PQ 尚未默认开启时期的 Chrome**」形状。代价与残余风险见 §3、§6。

---

## 1. 威胁模型

### 1.1 三个观察者

**A. 被动旁路观察者**（ISP / 出口审计盒 / 有状态中间盒；只看不改）

能看到：
- ClientHello 的**全部明文**（TLS 1.3 只加密 ServerHello 之后的服务端消息）；
- 每条连接的 ClientHello **总字节长度**、record 分帧（我们只发一条 `22 03 01` handshake record）；
- 扩展集合、扩展顺序、GREASE 值、`supported_groups` 与 `key_share` 的**内容一致性**；
- 是否出现 HelloRetryRequest（额外一个 RTT、且方向/长度可辨），随后是否出现**第二份 ClientHello**；
- 时序、包长分布、SNI 明文、TCP 层特征；
- 跨连接聚合：JA3（含扩展顺序）/ JA4（排序、对顺序与 groups 不敏感）。

看不到：TLS 1.3 加密后的 EncryptedExtensions/Certificate/CertificateVerify/Finished、应用数据；
REALITY 认证语义（密文在 `session_id` 里，只见随机字节）。**注意 A 是唯一能跨连接做统计的观察者**
（§5 的 JA3 恒定性、CH 长度恒定、排列分布都主要给 A 看）。

**B. 主动探测者**（能连我们的 REALITY 服务端、能发任意字节、能改包、能重放我们的 CH）

能看到：A 的全部 + 服务端的响应（是否像真网站：ServerHello/证书链/行为）；
能做的实验：拿我们抓到的 ClientHello 重放给任意第三方；向我们的**客户端**注入任意 ServerHello
（HRR、不匹配的 session_id、畸形记录）观察它是否重试/回退。目标是把「代理」与「真网站」分开。

已有对抗性证据（本任务测试）：
- 服务端回显被改过的 `session_id` → 客户端拒绝，且**不再发任何字节**；
- 服务端发 HRR → 客户端报「HelloRetryRequest is not supported」，同样**不重发第二份 CH**；
- 因此 B 无法通过注入消息让我们切 profile / 回落 plain（§2.4）。

**C. 真实对端站点**（REALITY 的 `dest`，例如 Cloudflare；官方 Xray 服务端会把 CH 原样转发给它）

能看到：ClientHello 全文（含没被我们实现的字段）、`supported_groups` 与 `key_share` 的不一致；
能据此决定 **HRR**、选哪个组；能记录 JA3/JA4、做反爬/风控；但看不到 REALITY 认证（`session_id` 对它是随机字节）。
本仓库当前的 wasm 服务端是自己伪造 ServerHello、**不联系 dest**，所以内部 e2e 永远看不到 HRR —— 只有
T3 的「真机 » dest」路径才会暴露（见 §4）。

**D. 本地/实现层**：CSPRNG 熵源、依赖、panic（崩溃特征是独立一类可识别性）、配置错误导致静默降级。

### 1.2 信任边界与不得破坏的语义

- REALITY 认证依赖三处字节位置：`random` = `hello[6..38]`（HKDF salt 取 `6..26`，AES-GCM nonce 取 `26..38`）、
  `session_id` 长度字节 = `hello[38]`、`session_id` = `hello[39..71]`（前 16 字节密文 + 16 字节 GCM tag）。
  服务端还会校验自己回显的 `session_id` 与 `client_hello[39..71]` 一致。
- 指纹引擎只负责「按 profile 拼字节」，`session_id` 必须**原样**写入、不清零不随机化；
  拼装顺序固定为 legacy_version / random / sid_len / session_id / ciphers / compression / extensions。
- 认证的 AAD 是**整条 ClientHello**（session_id 置零）。这既是指纹自由度为零的原因，也是「任何改动都必须同步
  让认证仍然成立」的原因。

---

## 2. 逐条结论

### 2.1 REALITY 认证语义未被削弱 ✅

证据（`tests/fingerprint_security.rs`，全部用**线上真实字节**：经 `reality_handshake` 对内存 duplex 跑真实握手，
在服务端侧截第一条 record，不 mock `build_*`）：

- `wire_client_hello_keeps_reality_auth_layout`：`hello[38]==32`、`parse_client_hello().session_id_offset==39`、
  `random == hello[6..38]`、`session_id == hello[39..71]`、`authenticate()` 通过、`short_id`/`client_version` 正确还原。
- `tampering_reality_critical_fields_breaks_authentication`：分别篡改 random 的 salt 段 / nonce 段 /
  认证密文 / X25519 公钥 → 认证**必须**失败（四条全过）。
- `no_single_byte_tamper_outside_session_id_can_authenticate`：对整条消息**逐字节**翻转一位，
  只要还能解析出来，认证就**必须**失败 → 证明认证绑定整条消息，指纹引擎没有留下
  「改了也不影响认证」的自由字节。
- `official_fixture_keeps_positions_and_authenticates`：带 GREASE、16 个真实扩展、三份 key_share 的官方夹包，
  位置仍是 39，且能被我们的服务端认证。
- `server_that_does_not_echo_session_id_is_rejected_without_a_retry`：回显不符 → 客户端拒绝，且不再发字节。

**待复跑**：以上断言全部走 `reality_handshake`，T2 接线后默认 profile 变成 `chrome`，这些用例会自动
改为审计 chrome 形状的线上字节。届时若有一条变红，就是认证语义被破坏，**不许放宽断言**。

### 2.2 每次连接的随机性 ✅（plain）/ 待 chrome 复跑

- `per_connection_randomness_on_the_wire`：连续 8 条连接的 `random`、`session_id[0..16]`、`session_id[16..32]`
  两两不同。
- `grease_values_are_per_connection_when_present`：若线上出现 GREASE 扩展值，则不同连接不得复用。
  （plain 无 GREASE 时该断言自动跳过；T2 后 chrome 生效。）
- T1 侧（✅ 引擎级已测）：`new_grease_seed() = rand::random::<u64>()`（`grease_seed_is_fresh_per_call`，
  64 次取种子互不相同）；GREASE 5 个槽位由 seed 对 16 个 GREASE 值 Fisher–Yates 后取前 5，**没有写死常量**
  （`engine_grease_is_seed_dependent_and_paired`：64 个 seed 产生 50+ 种组合，`groups` 与 `key_share` 的
  GREASE 值必须相等）；`key_share` 的 GREASE 组与 `supported_groups` 的 GREASE 组必须成对。
- ❌→✅ 但「随机」不等于「分布像 Chrome」：ECH 填充长度曾写死（§5.3，已修），所以**总长度**也必须由 seed
  驱动（`chrome_ech_padding_length_varies_across_seeds_in_observed_set` 同时断言总长跨 seed 变化）。

### 2.3 不引入新的、更强的可识别特征 ❌（三处，其一已修）

见 §3 不一致点清单与 §4 HRR 专题、§5 跨连接可识别性。要点：

1. **声明 11ec 不给 share** → MUST HRR → 连接失败 + 新的失败特征。已按实测砍掉，复核通过。
2. **洗牌把首尾 GREASE 也洗了**（❌→✅ 已修）：真 Chrome 恒钉首尾（12/12）。backend 已改成只对中间 16 个做
   Fisher–Yates、首尾 GREASE 钉住；回归测试 `chrome_shuffle_pins_grease_first_and_last_across_seeds`
   （256 个 seed：首尾位置恒为 GREASE、中间恒 16 个非 GREASE、且排列确实在变 >200 种）。
3. **ECH 填充长度写死 208**（❌→✅ 已修）：真 Chrome 的 ECH 扩展长度在 {186,218,250,282}
   （payload {144,176,208,240}，32B 步长）间变化。backend 已改成由 seed 在 4 档里取；回归测试
   `chrome_ech_padding_length_varies_across_seeds_in_observed_set`（256 个 seed：取值 ⊆ 观测集合、
   覆盖全部 4 档、ClientHello 总长也随 seed 变化）。

### 2.4 不静默降级 ⚠️（阻塞 task-2）/ 远端侧 ✅

- 引擎不静默降级 ✅：`profile_by_name` 是**大小写敏感精确匹配**，`"chrome"` / `"plain"`，其余（含 `"Chrome"`、
  `"chrome "`、`""`）返回 `None`；`None`/`""` → 默认 profile 由调用方决定，T1 不兜底
  （`engine_rejects_unknown_profile_names_instead_of_downgrading`、`profile_names()` 含两个可用名字）。
  但**最终判据在 T2**：`RealityTlsLayer::new(&TlsConfig)` 遇到未知名字必须返回 `TransportError::Config`
  并在错误里列出 `fingerprint::profile_names()`。T2 落地后本文件会补上集成测试（构造 `TlsConfig`，
  期望 `Err`，并断言错误文本包含可用名字列表）。
- 远端不能诱导回退 ✅：profile 是构造期决定的 `&'static Profile`，运行期握手路径**没有任何**基于 ServerHello
  内容切换 profile 的分支；`hello_retry_request_is_fatal_and_produces_no_second_client_hello` 与
  `server_that_does_not_echo_session_id_is_rejected_without_a_retry` 证明：服务端注入 HRR/坏回显后，
  客户端只报错，线上**不再出现第二个 ClientHello**（用 500 ms 超时读服务端侧，读到 EOF 而非数据）。
  即：远端既不能让我们换 profile，也不能让我们多发一次握手暴露第二种形状。

### 2.5 不泄漏本地信息 ⚠️ 代码审查 / ❔ 运行期熵源

- 指纹路径（T1）逐行审查：没有 `SystemTime`、没有 `process::id`、没有固定盐；所有「本来就随机」的字节
  （GREASE 值、扩展顺序、ECH 的 config_id/enc/payload/填充长度）都由调用方传入的 `grease_seed` 经 SplitMix64 派生。
  SplitMix64 不是密码学 PRNG，但它的用途只是把 64 位 CSPRNG 种子展开成公开可见的字节；唯一要求是
  **每连接种子新**，由 `new_grease_seed()` 保证（`grease_seed_is_fresh_per_call`），调用方必须每连接调用一次 ——
  接线正确性由 §2.2 的线上测试兜住。
- 种子来源：`rand = "0.8"` 的 `rand::random::<u64>()` = thread_rng（ChaCha12）→ `getrandom 0.2.17` → 宿主 OS 熵。
  ❔ **未验证**：wasip2 运行时熵源端到端（没有跑 wasm 目标下的熵源测试）。需要的证据：在
  `wasm32-wasip2` 下连续取 `new_grease_seed()` 并检查分布在统计上正常，以及确认 `wasi:random` 被真正调用。
- REALITY 的 unix 时间戳：位于 AES-GCM **密文**内的认证载荷（`session_id[0..16]`），被动观察者不可见，
  只有持有长期私钥的服务端能解；它是协议要求（时钟窗口反重放），不是本特性引入的泄漏。
- `random` / `session_id` 由 T2 的调用方用 `rand::random` 生成；`session_id[16..32]` 是 GCM tag（由密文决定）。

### 2.6 拒绝解析 ✅（解析器）/ ⚠️（引擎错误路径）

- `parser_never_panics_on_any_truncation_of_the_official_fixture`：1787 字节夹具的**每一个**前缀都喂进
  `parse_client_hello`，无 panic。
- `parser_never_panics_on_mutated_fixture`：4000 次确定性伪随机多字节变异，无 panic。
- `parser_rejects_structural_malformations_without_panicking`：8 类结构性畸形（长度撒谎、扩展块越界、
  session_id 长度 0/33、cipher 长度越界…）全部返回 `Err`。
- ❌ 潜在 panic（低危，**当前不可达**）：`ClientHello` 是 `pub` 结构体、字段 `pub`，`aad()` 直接
  `aad[offset..offset+32]` 不做边界检查。`parse_client_hello` 恒定产出 39，所以生产路径安全；但下游若手工构造
  `ClientHello { session_id_offset: 9999, .. }` 再调 `authenticate` 会 panic。
  `hand_built_client_hello_with_bogus_offset_is_a_latent_panic` 把这个缺口钉住（断言它**确实**会 panic，
  即缺口仍在）。建议：字段收窄为私有，或 `aad()` 返回 `Result`；修好后删除该测试。
- T1 引擎错误路径（✅ 引擎级已测）：`engine_returns_errors_for_oversized_sni_and_alpn` 覆盖超长 SNI（70 000 B）、
  单个 ALPN id > 255、ALPN 列表总长 > 65535 —— 全部返回 `Err` 且不 panic；边界值（200 B 的 ALPN id）
  不被误拒。`FingerprintError` 变体见 `fingerprint.rs`。

---

## 3. 与真 Chrome 的不一致点清单（逐项：对谁可见）

参考系：`src/testdata/xray-clienthello*.hex`，共 **12 份**官方 Xray `fingerprint: chrome` 抓包
（含仓库原有 1 份 + `scripts/capture-clienthello.sh` 新抓的 11 份）。

### 3.1 结构性不一致（我们与真 Chrome 的本质差异）

| # | 不一致点 | 具体表现 | 被动旁路 | 主动探测 | 真实对端 | 现状 |
|---|---|---|---|---|---|---|
| 1 | **无 X25519MLKEM768 key_share** | 真 Chrome：`supported_groups=[GREASE,11ec,001d,0017,0018]` 且 `key_share` 含 11ec 的 1216B；我们：`supported_groups=[GREASE,001d,0017,0018]`，`key_share` 只有 GREASE+001d | 可见：静态解析 `groups ∩ shares`；且 CH 总长只有 **501–597B** vs 真 Chrome 1723–1819B（尺寸模型由 `chrome_client_hello_size_reflects_the_missing_pq_share` 钉住） | 可见：可主动诱导 HRR 实验区分（真 Chrome 不会 HRR 到 11ec） | 可见：**曾会发 HRR**（现已不触发）；也会注意到 CH 体积小、无 PQ 组 | ✅ 已按实测砍掉 11ec；体量与版本年代问题见 §6 |
| 2 | **无真实 ECH** | 只发结构合法的 GREASE ECH 占位（type/kdf/aead 固定，config/enc/payload 随机） | 单看一条连接无法与真 ECH 区分（ECH 内容本就随机） | 可比较「我们总是带 65037」与「真 Chrome 只有拿到 DNS ECHConfig 时才带」——需要对照组，❔未验证 | 若真 ECH 是硬要求会失败；一般服务端忽略 | ⚠️ 有意取舍，代价照写 |
| 3 | **扩展排列的 GREASE 位置** | 真 Chrome 恒钉「首扩展=GREASE、尾扩展=GREASE」（12/12）；T1 的 Fisher–Yates 作用在整个扩展向量上，会把 GREASE 洗到中间 | 深度解析扩展顺序即可见 | 同左 | 同左 | ❌ 缺陷（`fingerprint.rs:456-462`），已报 lead/backend |
| 4 | **ECH 填充长度恒定** | 真 Chrome 的 ECH 扩展长度 {186,218,250,282}（=42+payload，payload∈{144,176,208,240}，32B 步长）；T1 写死 `ECH_PAYLOAD_LEN=208` → 每条连接 250 | 可见：跨连接的 CH 总长恒定（真 Chrome 在 1723/1755/1787/1819 间波动） | 同左 | 同左 | ❌ 缺陷（`fingerprint.rs:112`），已报 lead/backend |
| 5 | **排列分布是否与 uTLS 一致** | 若两边都是「16 个真实扩展均匀随机排列」，统计上不可分；若 uTLS 有偏而我们均匀（或反之）可被 N 条连接区分 | 可见：排列统计 | 同左 | 同左 | ❔ 未验证（12 条样本功效不足，§5.4） |
| 6 | **版本年代** | 砍掉 11ec 后形状 ≈「PQ 尚未默认开启的 Chrome（≤123，2024-03 之前）」 | 可见：DPI 可用时间线推断 | 同左 | 可见：风控可能对「声称 Chrome 却无 PQ 组」降级 | ❔ 未验证（没有 Chrome ≤123 的夹包可比其余字段） |
| 7 | **JA3 必然不同** | 去掉 11ec 改变 `EllipticCurves` 段 → JA3 哈希与真 Chrome 不同（实测 `6ea7fca2…` → `ddd81626…`） | 可见（若用 JA3） | 同左 | 同左 | ✅ 已复现；**JA4 不受影响**（§5.5） |
| 8 | **实际密钥交换强度更低** | 我们只做 X25519；真 Chrome 做 X25519MLKEM768 混合（抗「先存后解」） | 可见（groups） | 同左 | 同左 | ⚠️ **这是真实的密码学降级，不只是外观**：今天的流量可被录下、等未来量子计算解密。文档必须说清 |

### 3.2 其他可见差异（由 profile 之外造成，属于能力边界）

| # | 差异 | 对谁可见 |
|---|---|---|
| 9 | ClientHello 只有一条 record、大小 ~565B | 被动（包长/时序）、对端 |
| 10 | TCP + TLS 1.3，无 QUIC/HTTP3 | 被动（真 Chrome 访问很多站点走 QUIC/UDP 443）、对端 |
| 11 | 无 TLS 会话恢复（PSK/0-RTT）：真 Chrome 会 `pre_shared_key` 恢复 | 被动（真 Chrome 的后续连接 CH 形状不同）、对端 |
| 12 | 证书链是 REALITY 伪造的（每连接临时 ed25519 + HMAC 签名） | 对端/主动探测：不做 CA 校验的客户端才接受；这是 REALITY 机制本身，不是本特性引入 |
| 13 | 应用层指纹（HTTP/2 SETTINGS、header 顺序、ALPS 行为）未对齐 | 对端 |

---

## 4. HRR 专题（本特性最重要的结论）

### 4.1 实测（✅ 已复现）

脚本（完整源码见 §8.2）对 5 个真实 SNI 发 4 种形状的 ClientHello，读第一条响应：

```
## cloudflare.com
  PLAIN_TODAY: ServerHello (122B, handshake_type=2)
  OLD_plan   : HELLO_RETRY_REQUEST (88B) requests ['key_share=0x11ec']
  NEW_plan   : ServerHello (122B, handshake_type=2)
## www.cloudflare.com
  PLAIN_TODAY: ServerHello (122B, handshake_type=2)
  OLD_plan   : HELLO_RETRY_REQUEST (88B) requests ['key_share=0x11ec']
  NEW_plan   : ServerHello (122B, handshake_type=2)
  FIXTURE    : ServerHello (1210B, handshake_type=2)
## google.com / www.google.com / example.com
  同上：PLAIN_TODAY ServerHello，OLD_plan HRR(请求 0x11ec)，NEW_plan ServerHello
```

其中：
- `FIXTURE` = 仓库里官方 Xray `fingerprint:chrome` 夹包原样重放（含真 11ec 1216B share）；
- `OLD_plan` = **只从夹包里删掉 11ec 那条 key_share**（supported_groups 保留 11ec），其余字节不变；
- `NEW_plan` = supported_groups 与 key_share **都**去掉 11ec（lead 拍板后的实现）；
- `PLAIN_TODAY` = 当前 `reality.rs` 手写的最小形状。

**决定性差分**：同一个夹包，**只删掉 11ec 那条 key_share**、其余字节逐字节不变，就从 `ServerHello` 变成
`HELLO_RETRY_REQUEST`，且 HRR 明确请求 `0x11ec`。也就是说：「我们与真 Chrome 的唯一不可弥补差异」正好就是
触发 HRR 的那一处。而把 11ec 从两处都删掉后，5/5 SNI 全部恢复正常握手。

### 4.2 协议依据（RFC 8446）

- §4.1.1：「If the server selects an (EC)DHE group and the client did not offer a compatible `key_share`
  extension in the initial ClientHello, the server **MUST** respond with a HelloRetryRequest.」
- §4.1.2：客户端第二份 ClientHello 必须是「the same ClientHello without modification, except as follows」，
  允许的变化只有：替换 `key_share` 为被请求组的那一条、移除 `early_data`、加入 `cookie`、更新 `pre_shared_key`、
  改 `padding`。**`random` 与 `session_id` 不在允许变化之列。**
- §4.2.2：服务端可在 HRR 带 `cookie`，客户端必须在第二份 CH 里原样带回。

我们的客户端当前对 HRR 的处理：`reality.rs:946-956` 检测到 HRR 哨兵 random 直接返回
`"Reality TLS: HelloRetryRequest is not supported"`（测试 `hello_retry_request_is_fatal_and_produces_no_second_client_hello` 钉住）。

### 4.3 REALITY × HRR 的协议层别扭（推理，**部分未验证**）

以下推理基于代码与 RFC，**没有**用官方 Xray 服务端验证过（标 ❔）：

- 客户端第一份 CH 里：HKDF 输入 = `random[0..20]`，GCM nonce = `random[20..32]`，
  认证密文 = `session_id[0..16]`，AAD = 整条 CH（session_id 置零）。
- 按 §4.1.2，第二份 CH 的 `random` 与 `session_id` 必须**逐字节不变**；但允许变的 `key_share` 是整条 AAD 的一部分。
- 于是出现两难：
  - 若保持 `session_id` 不变 → 第二份 CH 的 AAD 变了，服务端按「收到的 CH 重建 AAD」解不开（认证失败/回退）；
  - 若重新加密 `session_id` 以适配新 AAD → `session_id` 变了，违反 §4.1.2 的「不变」，且破坏
    `client_hello[39..71]` 的回显校验语义。
- 结论（推理）：**REALITY 的认证嵌位与 HRR 天然不兼容**；将来谁想做「HRR 后自动降级重试」，
  必须走**新连接**（新 random / 新 session_id / 新 GREASE），而不是在同一条连接里发第二份 CH。
- ❔ 未验证项：官方 Xray 服务端在「转发 CH 给 dest、dest 回 HRR」时的实际行为（它是否会认证第一份 CH、
  是否把 HRR 回传给客户端、是否在新连接上重试）。需要的证据：官方服务端 + 一个必然触发 HRR 的 dest 的
  抓包或日志。**本条会直接影响任何 HRR 降级方案的设计**，所以单列。

### 4.4 净判断（收益 vs 新增暴露）

- 采纳「声明但不提供 11ec」时：对 PQ 首选站点 100%（5/5）从「能连」变「连不上」；同时旁观者看到
  「CH 声明 11ec → 服务端 HRR → 连接中断」，这是**比现在 plain 的 JA3 不像 Chrome 稀有得多**的特征，
  且伴随可用性回归。**净判断：明确为负**。
- 采纳「两头都删 11ec」后（当前决策）：连接恢复正常；代价是 JA3 的 EllipticCurves 段与真 Chrome 不同
  （JA4 不受影响），并接受「等价于 PQ 之前的 Chrome」这一版本年代假设（§6 残余风险 3/4）。
- 备选（未采纳，列为非目标）：实现真正的 ML-KEM key share（重依赖 + wasm 体积）、或 HRR 后新连接降级重试。

---

## 5. 跨连接可识别性（能看多次连接的观察者）

### 5.1 真实参考的实测统计（分析时 12 份官方 Xray chrome 抓包）

> 仓库里的抓包份数会随 testing 增删（分析时 12 份，之后被清理到 5 份）；下表数值来自 12 份那一次，
> §8.3 给了可重跑的复算脚本，结论以重跑为准。

| 特征 | 实测 |
|---|---|
| 扩展**集合** | 16 个真实扩展的集合 12/12 完全相同；另有 2 个 GREASE 扩展恒在首尾，其**类型值**每连接不同 |
| 扩展**顺序** | 12/12 互不相同（16 个真实扩展被随机排列） |
| GREASE 扩展位置 | 12/12 恒为「第一个」和「最后一个」 |
| GREASE 值 | 每连接不同（cipher 首位、首尾扩展类型、groups/key_share 首位、supported_versions 首位） |
| ECH(65037) 扩展长度 | {186, 218, 250, 282}（payload {144,176,208,240}，32B 步长） |
| ClientHello 总长度 | {1723, 1755, 1787, 1819}（差异来自 ECH 填充；SNI 长度在本组样本内恒为 23） |
| JA4 | 12/12 相同 = `t13d1516h2_8daaf6152771_d8a2da3f94cd`（testing 的独立实现） |

复算命令见 §8.3。

### 5.2 固定扩展顺序暴露多少？

- JA3 的 Extension 段**保留顺序**（只剔除 GREASE 值）。真 Chrome 每连接重排 → 它的 JA3 是**一组**值；
  若我们固定排列 → 我们的 JA3 是**单点**。
- 影响面：出口侧被动监听、目标站、有状态中间盒都能在**极少连接数**（2 条）内发现「恒定」而不是分布；
  更重要的是这个恒定值本身是一个**稳定标签**，可跨连接、跨会话关联我们这一侧客户端，作用接近 cookie，
  远强于单次指纹。
- 结论：**必须洗牌**（backend 已实现）。但洗牌只能解决「JA3 恒定」；下面是残余。

### 5.3 洗牌后的残余可识别性（两个缺陷：已修 + 回归测试）

1. **GREASE 未钉首尾**（已修）。真 Chrome 12/12 钉首尾；原实现洗了整个向量（含 `GreaseEmpty` /
   `GreaseTrailing`）。现改为 `partition` 出 GREASE 后只洗中间 16 个、再把首尾放回。
   回归测试：`chrome_shuffle_pins_grease_first_and_last_across_seeds`。
2. **CH 总长恒定**（已修）。ECH 填充长度写死 208 → 每条连接 ECH 都是 250B。现改为由 seed 在
   {144,176,208,240} 中取，使总长也随连接变化（与真 Chrome 的 1723/1755/1787/1819 对应）。
   回归测试：`chrome_ech_padding_length_varies_across_seeds_in_observed_set`。
3. 线上字节层面还有两条**条件式**测试：线上出现 GREASE 时必须钉首尾、出现 ECH 时长度必须跨连接变化 ——
   T2 把默认 profile 换成 chrome 后，这两条会从「plain 跳过」变成真正生效的审计
   （`wire_client_hello_pins_grease_first_and_last_when_present`、
   `wire_client_hello_ech_length_varies_across_connections_when_present`）。
   注意这两个缺陷都不影响 JA3/JA4 的**哈希值**（GREASE 被剔除、长度不进哈希），所以 T3 的对拍测试**抓不到**，
   只有跨连接的统计才能发现 —— 这正是安全审计要独立做的原因。

### 5.4 我们的排列分布 vs uTLS 的分布（❔ 未验证）

- 现有 12 条：集合相同、顺序全不同、每个扩展出现在各位置的范围几乎铺满 0..15 —— **与「均匀随机排列」一致**。
- 但 12 条样本**功效不足**，不能证明 uTLS 严格均匀。需要的统计量与样本量：
  - 统计量：对每一对扩展 (A,B) 统计 P(A 在 B 前)；均匀零假设下 = 0.5。
    检出偏差 δ（α=0.05，功效 0.8）约需 **N ≈ (z+0.84)² · 0.25 / δ²**：
    δ=0.20 → ~196 条；δ=0.10 → ~784 条；δ=0.05 → ~3136 条。
    120 个扩展对做 Bonferroni 校正后：δ=0.10 → ~480 条，δ=0.05 → ~1900 条。
  - 补充统计量：各扩展的位置分布 χ²（16 格）。
  - 廉价判据：**碰撞率**。均匀 16! ≈ 2.09e13 种排列，几百条连接不会重复；若我们的实现退化成固定/轮转/少量
    排列，几百条内必现重复 —— 这一条不需要区分 uTLS 分布就有判据价值。
- 需要的输入：**500–2000 条** fresh 抓包（`scripts/capture-clienthello.sh` 可重复抓）+ testing 的「扩展位置表」。
  12 条只能排除 50% 量级的偏差。

### 5.5 JA3 vs JA4：主判据必须是 JA4 ✅

实测（同一份夹包 vs 只删 11ec 的 NEW_plan，JA3/JA4 各按定义计算）：

```
JA3 fixt: 6ea7fca2518150a2939b8ba64620c0af
         771,4865-…-53,16-18-65281-23-0-5-27-51-13-45-43-65037-35-11-10-17613,4588-29-23-24,0
JA3 new : ddd81626fa673b92bc01edb0dcf9c32d
         771,4865-…-53,16-18-65281-23-0-5-27-51-13-45-43-65037-35-11-10-17613,29-23-24,0
JA3 same: False        # 差异只在 EllipticCurves 段
JA4 fixt: t13d1514h2_8daaf6152771_9a55b862dad6
JA4 new : t13d1514h2_8daaf6152771_9a55b862dad6
JA4 same: True         # supported_groups 不进 JA4；JA4 把扩展排序，顺序也不进
```

- JA4 设计上就**排序扩展**（FoxIO README 的 Q&A 明确说：Chromium 2023 年起随机化扩展顺序，
  JA4 用排序 + 签名算法来保持唯一性），且**不含 supported_groups**。因此：
  - 去掉 11ec 后 JA3 必然不再等于真 Chrome，但 **JA4 仍然相同**；
  - 洗牌扩展顺序**不会**改变 JA4（只改变 JA3 的恒定性）。
- 给 design 的结论：**JA4 负责「像不像」；JA3 只能做「别恒定」的卫生检查，不能当匹配目标**
  （真 Chrome 自己的 JA3 每连接都变，用 JA3 做等值匹配本身就无意义）。
- 引用：JA4 排序扩展的理由见 [FoxIO JA4+ README](https://github.com/FoxIO-LLC/ja4/blob/main/README.md)
  的 Q&A（"Why are you sorting the extensions?"）。

---

## 6. 已知残余风险清单

| # | 风险 | 严重度 | 现状 / 归属 |
|---|---|---|---|
| 1 | 「声明 11ec 不给 share」触发 HRR → 连接失败 + 新的失败特征 | 高 | ✅ 已修（删 11ec）；回归测试 `chrome_profile_never_declares_x25519mlkem768`、`wire_client_hello_never_declares_11ec_without_its_share`；T3 真机判据必须保留 |
| 2 | 洗牌把 GREASE 洗离首尾 → 与真 Chrome 不一致 | 中 | ✅ 已修 + 回归测试 `chrome_shuffle_pins_grease_first_and_last_across_seeds` |
| 3 | ECH 填充长度写死 → CH 总长跨连接恒定 | 中 | ✅ 已修 + 回归测试 `chrome_ech_padding_length_varies_across_seeds_in_observed_set` |
| 4 | 排列分布是否与 uTLS 一致 | 中 | ❔ 未验证；需要 500–2000 条抓包（§5.4） |
| 5 | 版本年代假设（形状 ≈ Chrome ≤123）无夹包可比 | 中 | ❔ 未验证；需要一份 Chrome ≤123 的 ClientHello 夹具（或用旧版 uTLS 模板生成） |
| 6 | 随 Chrome 124+ 普及，老版本 Chrome 自然消亡 → 「无 PQ 组的 Chrome」越来越像伪装客户端 | 中 | 长期风险，随 §6.3 的填充一起评估；文档已如实写明 |
| 7 | CH 体量 ~565B vs 真 Chrome 1723–1819B | 中 | 由 §3.1 #1 决定，无法在不实现 PQ 的前提下消除 |
| 8 | 无 PQ 混合密钥交换 → 缺少「先存后解」防护（真实密码学降级） | 中 | 明确列为非目标；文档必须写 |
| 9 | 无 QUIC/HTTP3、无会话恢复、无 0-RTT | 中 | 本特性不解决（§7）；跨层差异大于 CH 细节 |
| 10 | GREASE ECH 是假的（不是真 ECH） | 低-中 | 有意取舍；若未来 ECH 成硬要求会失败 |
| 11 | `ClientHello` 字段 pub + `aad()` 无边界检查 → 手工构造可 panic | 低 | ❌ 低危、当前不可达；测试已钉住 |
| 12 | 官方 Xray 服务端在 HRR 下的行为未验证 | 低（当前不触发 HRR） | ❔ 未验证；影响未来任何 HRR 降级方案设计 |
| 13 | wasm 运行期 CSPRNG 熵源未做端到端验证 | 低 | ❔ 未验证（依赖栈：rand 0.8 → getrandom 0.2.17 → OS） |
| 14 | 调用方忘调 `new_grease_seed()`（或复用一个 seed）→ GREASE/顺序/长度全部重复 | 中 | 由线上测试兜住（`grease_values_are_per_connection_when_present`）；T2 接线后必须保持绿 |

---

## 7. 本特性不解决什么（能力边界，别当卖点）

- **不改 TLS 之外的特征**：流量时序、包长分布、方向、TCP/IP 层指纹（JA4T/TCP options）、IP 归属。
- **不隐藏 SNI**：SNI 仍明文（除非用真实 ECH，我们只有 GREASE 占位）。
- **不解决 DNS**：DNS 查询仍可被观察；也不提供 ECH 所需的 HTTPS/SVCB 解析。
- **不改 TLS 版本/证书链行为**：仍是 TCP + 伪造证书的 REALITY 路径；不做 CA 校验（REALITY 机制）。
- **不做 PQ 密钥交换**：只声明/发送 X25519，缺少 X25519MLKEM768 的抗「先存后解」保护。
- **不做 QUIC/HTTP3、不做 0-RTT、不做会话恢复**：真 Chrome 访问大量站点时走 QUIC 且会恢复会话，
  这些跨层差异比 ClientHello 细节更容易区分客户端。
- **不做应用层伪装**：HTTP/2 SETTINGS、header 顺序、ALPS 实际行为、HTTP/3 都未对齐。
- **不改变认证**：指纹只改外观；REALITY 的认证强度、抗主动探测语义保持原样（§2.1）。
- **不保证「像某个版本的 Chrome」**：只保证「可观测字段与某一份真实夹包一致，除显式列出的偏差外」，
  并且这份夹包对应的 Chrome 版本会随真实浏览器更新而过期（§6 #5/#6）。

---

## 8. 复现命令与脚本

### 8.1 测试（本任务的可执行证据）

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh
CARGO_TARGET_DIR=$PWD/target cargo test -p xt-wasm-tls --test fingerprint_security -- --nocapture
CARGO_TARGET_DIR=$PWD/target cargo test -p xt-wasm-tls
```

`tests/fingerprint_security.rs` 当前 **26 个用例**，全部通过（T2 落地后线上一组会自动改为审计 chrome 形状的
线上字节；引擎级一组不依赖 T2）。最近一次输出：

```
running 26 tests
test engine_rejects_unknown_profile_names_instead_of_downgrading ... ok
test engine_returns_errors_for_oversized_sni_and_alpn ... ok
test engine_preserves_reality_critical_positions_verbatim ... ok
test engine_grease_is_seed_dependent_and_paired ... ok
test grease_seed_is_fresh_per_call ... ok
test chrome_client_hello_size_reflects_the_missing_pq_share ... ok
test chrome_profile_never_declares_x25519mlkem768 ... ok
test chrome_shuffle_pins_grease_first_and_last_across_seeds ... ok
test chrome_ech_padding_length_varies_across_seeds_in_observed_set ... ok
test wire_client_hello_keeps_reality_auth_layout ... ok
test wire_client_hello_never_declares_11ec_without_its_share ... ok
test wire_client_hello_pins_grease_first_and_last_when_present ... ok
test wire_client_hello_ech_length_varies_across_connections_when_present ... ok
test per_connection_randomness_on_the_wire ... ok
test grease_values_are_per_connection_when_present ... ok
test tampering_reality_critical_fields_breaks_authentication ... ok
test no_single_byte_tamper_outside_session_id_can_authenticate ... ok
test official_fixture_keeps_positions_and_authenticates ... ok
test official_fixture_declares_and_shares_x25519mlkem768 ... ok
test declaring_x25519mlkem768_without_its_key_share_is_statically_identifiable ... ok
test hello_retry_request_is_fatal_and_produces_no_second_client_hello ... ok
test server_that_does_not_echo_session_id_is_rejected_without_a_retry ... ok
test parser_never_panics_on_any_truncation_of_the_official_fixture ... ok
test parser_never_panics_on_mutated_fixture ... ok
test parser_rejects_structural_malformations_without_panicking ... ok
test hand_built_client_hello_with_bogus_offset_is_a_latent_panic ... ok

test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 8.2 HRR 真机探针（§4.1 的证据，**仅用标准库**）

把下面内容存成 `fp_hrr_probe.py`，然后：

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
python3 fp_hrr_probe.py                    # 默认 5 个 SNI
python3 fp_hrr_probe.py "" cloudflare.com  # 只测一个 SNI（第一个参数是夹具路径，空用默认）
```

> ⚠️ 这会真的向外网 443 发包；只在允许的机器上运行。

```python
#!/usr/bin/env python3
# T4 指纹安全审计 —— HelloRetryRequest 真机探针（可重复运行，仅用标准库）
#
# 用法：
#   python3 fp_hrr_probe.py [fixture.hex] [sni ...]
# 默认读取 crates/xt-wasm-tls/src/testdata/xray-clienthello.hex，
# 默认对 cloudflare.com www.cloudflare.com google.com www.google.com example.com 做探测。
#
# 它做三件事：
#   1. 把仓库里的官方 Xray fingerprint:chrome 夹包解析成「类型 -> 原始字节」，
#      这样所有变体都是**同一份真实字节**的精确差分，不是手搓近似；
#   2. 构造 4 种形状并真的发到目标网站 443：
#        FIXTURE_verbatim           官方夹包原样（含真 11ec 1216B share）
#        OLD_plan                   T1 原计划：supported_groups 保留 11ec，key_share 不发
#        NEW_plan                   lead 拍板后：supported_groups/key_share 都去掉 11ec
#        PLAIN_TODAY                当前 reality.rs 手写的最小形状
#   3. 打印 ServerHello / HELLO_RETRY_REQUEST（并解析 HRR 请求的 group）/ ALERT。

import os, socket, struct, sys

HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
DEFAULT_FIXTURE = "crates/xt-wasm-tls/src/testdata/xray-clienthello.hex"
DEFAULT_SNIS = ["cloudflare.com", "www.cloudflare.com", "google.com",
                "www.google.com", "example.com"]


def ext(t, d):
    return struct.pack(">HH", t, len(d)) + d


def parse_client_hello(msg):
    """返回 (header_body_prefix, cipher_bytes, compression, [(type, data)])。"""
    assert msg[0] == 1, "不是 ClientHello"
    body_len = int.from_bytes(msg[1:4], "big")
    assert body_len + 4 == len(msg), "长度字段不符"
    b = msg[4:]
    p = 34  # legacy_version(2) + random(32)
    sid_len = b[p]
    p += 1 + sid_len
    cs_len = int.from_bytes(b[p:p + 2], "big")
    ciphers = b[p + 2:p + 2 + cs_len]
    p += 2 + cs_len
    comp_len = b[p]
    comp = b[p + 1:p + 1 + comp_len]
    p += 1 + comp_len
    ext_total = int.from_bytes(b[p:p + 2], "big")
    p += 2
    exts = []
    q = 0
    raw = b[p:p + ext_total]
    while q < len(raw):
        t = int.from_bytes(raw[q:q + 2], "big")
        l = int.from_bytes(raw[q + 2:q + 4], "big")
        exts.append((t, raw[q + 4:q + 4 + l]))
        q += 4 + l
    return b[:p], ciphers, comp, exts


def build(sni, ciphers, comp, exts, sid=None, random32=None):
    """按给定的扩展列表重新组装 ClientHello（长度全部重算）。"""
    b = b"\x03\x03" + (random32 or os.urandom(32))
    b += b"\x20" + (sid or os.urandom(32))
    b += struct.pack(">H", len(ciphers)) + ciphers
    b += bytes([len(comp)]) + comp
    blob = b"".join(ext(t, d) for t, d in exts)
    b += struct.pack(">H", len(blob)) + blob
    return b"\x01" + len(b).to_bytes(3, "big") + b


def sni_ext(sni):
    h = sni.encode()
    name = b"\x00" + struct.pack(">H", len(h)) + h
    return struct.pack(">H", len(name)) + name


def drop_from_u16_list(data, value):
    n = int.from_bytes(data[0:2], "big")
    items = [data[2 + i * 2:4 + i * 2] for i in range(n // 2)]
    items = [i for i in items if int.from_bytes(i, "big") != value]
    return struct.pack(">H", len(items) * 2) + b"".join(items)


def drop_from_key_share(data, group):
    total = int.from_bytes(data[0:2], "big")
    keep, r = b"", 2
    while r < 2 + total:
        g = int.from_bytes(data[r:r + 2], "big")
        l = int.from_bytes(data[r + 2:r + 4], "big")
        if g != group:
            keep += data[r:r + 4 + l]
        r += 4 + l
    return struct.pack(">H", len(keep)) + keep


def fixture_shapes(fixture_hex):
    msg = bytes.fromhex(open(fixture_hex).read().strip())
    _, ciphers, comp, exts = parse_client_hello(msg)

    def with_sni(sni):
        return [(t, sni_ext(sni) if t == 0 else d) for t, d in exts]

    def old_plan(sni):  # 声明 11ec，不发它的 share
        return build(sni, ciphers, comp, [
            (t, drop_from_key_share(d, 0x11ec) if t == 51 else d)
            for t, d in with_sni(sni)])

    def new_plan(sni):  # groups 与 key_share 都去掉 11ec
        out = []
        for t, d in with_sni(sni):
            if t == 10:
                d = drop_from_u16_list(d, 0x11ec)
            if t == 51:
                d = drop_from_key_share(d, 0x11ec)
            out.append((t, d))
        return build(sni, ciphers, comp, out)

    verbatim = build("www.cloudflare.com", ciphers, comp, with_sni("www.cloudflare.com"))
    return verbatim, old_plan, new_plan


def plain_today(sni):
    """当前 reality.rs 的手写形状：1 个 cipher、无 GREASE、扩展顺序照代码。"""
    groups = b"".join(struct.pack(">H", g) for g in (0x001d, 0x0017, 0x0018))
    sigalgs = b"".join(struct.pack(">H", s) for s in (0x0807, 0x0403, 0x0804, 0x0805))
    kexts = [
        (0, sni_ext(sni)),
        (10, struct.pack(">H", len(groups)) + groups),
        (11, b"\x01\x00"),
        (13, struct.pack(">H", len(sigalgs)) + sigalgs),
        (35, b""),
        (43, b"\x04\x03\x04\x03\x03"),
        (45, b"\x01\x01"),
        (51, struct.pack(">H", 36) + struct.pack(">HH", 0x001d, 32) + os.urandom(32)),
    ]
    exts = kexts
    return build(sni, struct.pack(">H", 0x1301), b"\x00", exts)


def probe(name, raw_hs, sni, port=443, timeout=8):
    rec = b"\x16\x03\x01" + struct.pack(">H", len(raw_hs)) + raw_hs
    try:
        s = socket.create_connection((sni, port), timeout=timeout)
        s.sendall(rec)
        hdr = s.recv(5)
        if len(hdr) < 5:
            return f"{name}: EOF/短响应 {hdr.hex()}"
        rlen = struct.unpack(">H", hdr[3:5])[0]
        data = b""
        while len(data) < rlen:
            c = s.recv(rlen - len(data))
            if not c:
                break
            data += c
        s.close()
    except Exception as e:
        return f"{name}: ERROR {type(e).__name__}: {e}"
    if hdr[0] == 0x15:
        return f"{name}: ALERT level={data[0]} desc=0x{data[1]:02x}"
    if data[0] == 2 and data[6:38] == HRR_RANDOM:
        p = 4 + 2 + 32
        sid = data[p]
        p += 1 + sid + 2 + 1
        elen = struct.unpack(">H", data[p:p + 2])[0]
        p += 2
        end = p + elen
        req = []
        while p < end:
            et = struct.unpack(">H", data[p:p + 2])[0]
            l = struct.unpack(">H", data[p + 2:p + 4])[0]
            d = data[p + 4:p + 4 + l]
            if et == 51:
                req.append("key_share=0x%04x" % struct.unpack(">H", d[0:2])[0])
            elif et == 44:
                req.append("cookie(%dB)" % l)
            p += 4 + l
        return f"{name}: HELLO_RETRY_REQUEST ({rlen}B) requests {req}"
    return f"{name}: ServerHello ({rlen}B, handshake_type={data[0]})"


def main():
    args = sys.argv[1:]
    fixture = args[0] if args else DEFAULT_FIXTURE
    snis = args[1:] if len(args) > 1 else DEFAULT_SNIS
    verbatim, old_plan, new_plan = fixture_shapes(fixture)
    print(f"# fixture = {fixture}")
    print(f"# 4 种形状 × {len(snis)} 个 SNI\n")
    for sni in snis:
        print(f"## {sni}")
        print("  " + probe("PLAIN_TODAY", plain_today(sni), sni))
        print("  " + probe("OLD_plan   ", old_plan(sni), sni))
        print("  " + probe("NEW_plan   ", new_plan(sni), sni))
        if sni == "www.cloudflare.com":
            print("  " + probe("FIXTURE    ", verbatim, sni))
        print()


if __name__ == "__main__":
    main()
```

### 8.3 跨连接统计复算（§5.1 的表）

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
python3 - <<'PY'
import glob, collections
# 复用 8.2 的解析函数
exec(open('fp_hrr_probe.py').read().split('def build(')[0])
files = sorted(glob.glob('crates/xt-wasm-tls/src/testdata/xray-clienthello*.hex'))
def gr(t): return t & 0x0f0f == 0x0a0a and (t >> 8) == (t & 0xff)
orders, lens, ech = [], [], []
for f in files:
    raw = bytes.fromhex(open(f).read().strip())
    _, _, _, exts = parse_client_hello(raw)
    order = [t for t, _ in exts]
    orders.append(tuple(order)); lens.append(len(raw))
    ech.append({t: len(d) for t, d in exts}.get(65037))
real = lambda o: frozenset(t for t in o if not gr(t))
print("captures:", len(files), "(仓库里的份数会随 testing 增删；结论以重跑为准)")
print("real extension set identical:", len({real(o) for o in orders}) == 1)
print("distinct orders:", len(set(orders)))
print("GREASE pinned first+last:", all(gr(o[0]) and gr(o[-1]) for o in orders))
print("ECH lengths:", sorted(set(ech)))
print("total lengths:", sorted(set(lens)))
PY
```

### 8.4 JA3 / JA4 差分复算（§5.5）

见「§5.5 实测」一节：JA3 用 `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats` 拼接后 MD5（剔 GREASE），
JA4 按 FoxIO 规范（ciphers 排序、extensions 去 SNI/ALPN 并排序、拼 sigalgs 后 SHA-256 截断 12 hex）。
testing 的 `tests/fingerprint_differential.rs` 里有一份带 FoxIO 官方哈希向量的 Rust 实现，可直接复跑。

---

## 9. 证据索引

| 证据 | 位置 |
|---|---|
| 位置语义 / 篡改不可认证 / 官方夹包认证 / 随机性 / HRR 致命 / 回显校验 / 解析健壮性 / 潜在 panic | `crates/xt-wasm-tls/tests/fingerprint_security.rs`（26 用例） |
| 引擎级：11ec 缺席、GREASE 钉首尾 + 随 seed 变化、ECH 长度 4 档、CH 体量模型、未知 profile 拒绝、超长 SNI/ALPN、位置原样保留 | 同上（`chrome_*` / `engine_*` / `grease_seed_*` 用例） |
| JA3/JA4 对拍、逐字段差分、12 份抓包 | `crates/xt-wasm-tls/tests/fingerprint_differential.rs`（task-3） |
| 真机 HRR 探针 | 本文 §8.2 |
| 12 份官方夹包 | `crates/xt-wasm-tls/src/testdata/xray-clienthello*.hex` |
| 抓包脚本 | `scripts/capture-clienthello.sh`（task-3） |
| RFC 依据 | [RFC 8446 §4.1.1/§4.1.2/§4.2.2](https://www.rfc-editor.org/rfc/rfc8446) |
| JA4 排序扩展的理由 | [FoxIO JA4+ README](https://github.com/FoxIO-LLC/ja4/blob/main/README.md) |
| Chrome 124 起默认启用 PQ KEM | [Chrome Enterprise release notes](https://support.google.com/chrome/a/answer/10314655) |
