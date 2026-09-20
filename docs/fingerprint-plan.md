# 浏览器指纹伪装（ClientHello profile）—— 方案、配置面与能力边界

> **状态：配置面、引擎、接线与本文均已落地；涉及「像不像 / 会不会握手失败」的结论一律引用实测。**
> 本文里没有实测支撑的位置**不写结论**，只写「未验证」或「待收尾」，并注明由谁验证。
> 判据来源：T3 = `crates/xt-wasm-tls/tests/fingerprint_differential.rs`；
> T4 = `crates/xt-wasm-tls/tests/fingerprint_security.rs` + `docs/fingerprint-security.md`。
> （T3/T4 的执行者在收尾前中断，二者产物已落盘并通过验收，由 lead 复核收尾。）

---

## 0. 一句话

客户端默认组装一个**有版本年代的 Chrome 形状的 ClientHello** —— 等价于
「**PQ 尚未默认开启的 Chrome（约 Chrome 114）**」，而**不是**「当前最新 Chrome」。
这**只改 TLS 外观，不改 REALITY 认证**。我们**不声称**「实现了 Chrome 指纹」
——见 §3 的能力边界。

---

## 1. 目标（我们打算做到什么程度）

| 目标 | 说明 | 状态 |
|---|---|---|
| 消掉当前最强的那个指纹 | 现在发的是手写最小形状：**1 个 cipher、无 GREASE**，这在 JA3/JA4 层面极易识别 | 见 §1.1 状态表 |
| 在**可观测字段**上与真 Chrome 一致 | cipher 列表、扩展集合（顺序每连接随机打乱）、`supported_groups`、`ec_point_formats`、ALPN、`signature_algorithms`、GREASE 模式 | 对拍判据由 T3 给 |
| 用户可配、可自检、不静默降级 | `--fingerprint <name>` / `XT_FINGERPRINT`，默认 `chrome`；未知名字**启动即失败** | ✅ 本文 §5 |
| 保留一个「不想伪装」的选项 | `plain`：旧的精简形状，同时是回归基准 | 见 §4 |

### 1.1 当前状态（只写有证据的）

| 部分 | 状态 | 证据 |
|---|---|---|
| profile 引擎（`fingerprint.rs`） | ✅ 已落地 | `cargo test -p xt-wasm-tls`（50 单测全绿）；`profile_names()` = `["chrome","plain"]` |
| 接进 REALITY 握手（`reality.rs` / `lib.rs`） | ✅ 已落地（T2） | 新增 `resolve_profile()` + `build_reality_client_hello_with_profile()`；`cargo test --workspace` 191 passed |
| 配置面 / 默认值 / 帮助文本 / 自检 / 本文 | ✅ 已落地 | `--fingerprint`、`XT_FINGERPRINT`、`XT_CHECK=1` 输出；本文 §5 |
| 默认 profile **不声明 11ec** 这一取舍 | ✅ **已实测**（T4） | 声明 11ec 而不给其 key_share ⇒ 5 个 SNI **5/5 触发 HelloRetryRequest**；见 §3.2 与 `docs/fingerprint-security.md` §4.1 |
| **JA4 与官方 chrome 全等** | ✅ **已实测**（T3） | `cargo test -p xt-wasm-tls --test fingerprint_differential`（20 passed）；双方 JA4 = `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| 逐字段差分：仅 4 处差异，全在有意清单内 | ✅ **已实测**（T3） | 同上：扩展顺序（有意打乱）/ `supported_groups` 少 11ec / `key_share` 少 11ec / ECH 载荷档 |
| ECH GREASE 占位的可见性 | ⚠️ T4：**单条连接**不可与真 ECH 区分；主动探测需对照组，**未验证** | `docs/fingerprint-security.md` §3.1 #2 |
| 「无 PQ 混合」是**真实的密码学降级**（不只是外观） | ✅ 已明确列为代价（T4） | `docs/fingerprint-security.md` §3.1 #8、§7 |
| 线上 chrome 握手能被本工程服务端认证 | ✅ 已落地 | T2 的 `chrome_client_hello_authenticates_against_our_server`（`parse_client_hello` + `authenticate` 通过）；`scripts/e2e-wasm-to-wasm-test.sh` **5/5**、`scripts/e2e-vision-test.sh` **4/4** |
| chrome × 真实站点（example.com / www.cloudflare.com）HTTP 码矩阵 | ⏳ T3 收尾由 lead 补跑 | — |

> 本表随实测更新。任何一格从 ⏳ 变 ✅ 的唯一条件是：对应任务给出可复现命令与原始输出。
> ⚠️ 归因说明：T3/T4 的执行者在收尾前中断，上表引用的是**他们已落盘并通过验收的产物**
> （`tests/fingerprint_differential.rs` 20 绿、`tests/fingerprint_security.rs` 26 绿、
> `docs/fingerprint-security.md`），由 lead 复核收尾。

---

## 2. 非目标（明确不做，不留给读者猜）

1. **不做真实 ECH。** 真 Chrome 的 `encrypted_client_hello`(65037) 需要一份真实的
   ECHConfigList 与 HPKE 封装；我们没有，也不打算在本次做（只发 GREASE 占位，见 §3.2）。
2. **不做 X25519MLKEM768 的 key_share（也不声明它）。** 那要一份后量子密钥与对应
   依赖；更关键的是：**声明 11ec 却不给它的 key_share 会触发 HelloRetryRequest**
   （T4 实测 5/5，见 §3.2），而我们既不支持 HRR、也没有 ML-KEM ⇒ **握手直接失败**。
3. **不做 HRR 降级重试。** REALITY 认证把 `random` 与 `session_id` 绑进了第一份
   ClientHello（HKDF salt 与认证密文），HRR 会改变第二份 ClientHello 的这些字段，
   协议上与认证冲突 —— 详见 `docs/fingerprint-security.md`。
4. **不伪装 TLS 之外的特征**：流量时序、包长分布、TLS 版本、证书链、SNI、DNS 都不改。
5. **不做服务端侧指纹伪装。** 本次只改客户端出站 ClientHello；服务端的握手形状仍按
   REALITY 的需求构造（见 README「服务端的已知限制」）。
6. **不承诺追平 Chrome 版本演进。** 我们只对齐**一份固定的夹包**（见 §9），
   Chrome 改版后需要人工重抓、重新对拍。
7. **不做 profile 自动协商 / 自动探测对端喜好。** profile 是本地静态选择。

---

## 3. 能力边界（**最重要的一节**）

### 3.1 我们对外只能说这一句

> 「ClientHello 在**可观测字段**上与一个**有版本年代的 Chrome 形状**一致：
> legacy_version / cipher 列表 / 扩展集合 / ec_point_formats / ALPN /
> signature_algorithms / GREASE 模式 / compression（扩展**顺序每连接随机打乱**，
> 与真 Chrome 的做法相同）。在字段集合与取值上，它与当前最新 Chrome 的差异只有一处：
> 我们**不声明 X25519MLKEM768(11ec)**（1222 字节的长度差是这一处的直接后果）；
> 另外 ECH 只发 GREASE 占位。」

**不能**说、也不要在 issue / 文档 / commit message 里写：

| 禁止措辞 | 为什么 |
|---|---|
| 「实现了 Chrome 指纹」 / 「uTLS 全套」 | 我们只对齐可观测字段，且与当前最新 Chrome 存在已知差异（§3.2） |
| 「与**当前最新** Chrome 一致 / 无差别 / 无法区分」 | 当前 Chrome 会声明 11ec + 发它的 key_share；我们的形状对应**约 Chrome 114**（PQ 尚未默认开启） |
| 「我们的 JA3 是 XXXXX」 | **真 Chrome（uTLS）自己的 JA3 每次连接都不同**（§3.4）；单次 JA3 相等不是判据，稳定的判据是 JA4 |
| 「和官方客户端 `fingerprint: chrome` 完全一样」 | 官方客户端 26.3.27 **声明并发送** 11ec 的 key_share，我们刻意不发（§3.2） |

### 3.2 与真 Chrome 的差异，以及为什么这样取舍

| 真 Chrome（当前版本）会发 | 我们发什么 | 为什么 | 代价 / 证据 |
|---|---|---|---|
| `supported_groups` 声明 `X25519MLKEM768`(0x11ec) **且** `key_share` 里带它的 **1216 字节** share | **两者都不发**（`supported_groups` 与 `key_share` 里都没有 11ec） | **T4 实测**：声明 11ec 却不给它的 key_share ⇒ RFC 8446 §4.1.1 要求对端发 **HelloRetryRequest**；对 5 个 SNI 实测 **5/5 命中 HRR**，而我们**不支持 HRR、也没有 ML-KEM** ⇒ 握手直接失败。反向验证：把夹包**只删掉那 1216 字节的 11ec share、其余字节不变**，同一站点立刻从正常 ServerHello 变成 HRR | 这是**刻意的、不可弥补**的差异。JA3 的 EllipticCurves 段因此与**当前** Chrome 不同（与约 Chrome 114 的形状一致）；具体 JA3/JA4 值以 T3 实测为准。详见 `docs/fingerprint-security.md` |
| 真实 **ECH**（65037，可解密） | 结构合法的 **GREASE ECH 占位**：`type=0x00 / kdf=0x0001 / aead=0x0001 / 随机 config_id / enc=32B 随机 / payload=144·176·208·240B 随机`（4 档、由每连接的 seed 决定，扩展长度因此为 186/218/250/282B —— 与官方抓包观察到的**同一组**长度一致） | 没有 ECHConfigList / HPKE，**无法发出可解密的真 ECH** | T4 结论（`docs/fingerprint-security.md` §3.1 #2）：单看一条连接**无法**与真 ECH 区分（ECH 内容本就随机）；主动探测要拿「有/无 ECHConfig 的对照组」才可能分辨，**未验证**；若对端把真 ECH 当硬要求会失败（推理，未验证） |
| MLKEM 混合共享密钥 | 纯 X25519（且 11ec 已不在 `supported_groups` 里） | 见上一行；且已实测服务端接受纯 X25519（V7） | 内层密钥交换与真 Chrome 不同，但**这不在 ClientHello 的可观测字段里** |

> 两条差异（无 11ec、无真 ECH）都是**有意的取舍**，不是过渡状态、也不是待办 bug。
> 谁想把它们「修掉」，等价于引入后量子依赖 + 支持 HRR + 实现 ECH，
> 而且 HRR 会与 REALITY 的认证语义冲突（§6）——那是另一个决策，不在本次范围。

### 3.3 我们不保证什么

* 不保证能骗过**主动探测**（对端主动重放 / 修改 ClientHello 做行为探测）。
* 不保证我们的输出与真 Chrome 的 **JA3** 相等 —— 它**必然不同**（我们少了 11ec，
  且真 Chrome 自己的 JA3 每次都变），只有 **JA4 全等**是实测成立的（§3.4）。
* 不保证在 Chrome 之外的浏览器（Safari/Firefox）上像——本次只有 Chrome 一个伪装 profile。

### 3.4 判据是 JA4，不是 JA3（T3 实测，反直觉但必须先知道）

testing 抓了 **9 份**（后扩到 12 份）同一个官方 xray（26.3.27，`fingerprint: chrome`）的
ClientHello，实测：

| 指标 | 结果 |
|---|---|
| **JA4** | **9/9 完全相同** = `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| **JA3** | **9/9 互不相同**（`6ea7fca2…` / `df84da9d…` / `43128e69…` …） |
| 扩展**集合**（排序后） | 9/9 完全相同 |
| 扩展**顺序** | 每连接随机打乱（但**首尾恒为 GREASE**，12/12） |
| ClientHello 总长 | 1723…1819 字节（ECH GREASE 载荷长度随机） |

因此：

* **判据 = JA4 全等**（JA4 把 cipher 与扩展列表排序后哈希，且不含 `supported_groups`，
  对我们「不发 11ec」这个已知取舍免疫）。
* **不能**拿单次 JA3 相等当判据：那会因为扩展顺序的随机排列而随机成功或失败，
  得出错误结论。要比 JA3 就必须把 `Extensions` 段**排序后**再比。
* 我们的实现**同样按每次连接随机化扩展顺序**，并**把首尾 GREASE 钉住**（T4 曾发现
  第一版把 GREASE 也洗到中间，与真 Chrome 不符，已修 + 回归测试）。
* ✅ **我们的 chrome 输出与官方夹包的 JA4 全等**（T3 实测，本文引用其测试）：
  `cargo test -p xt-wasm-tls --test fingerprint_differential`
  → `differential_ja4_equals_official_chrome` 通过；双方 JA4_a/b/c 三段逐段相等，
  值均为 `t13d1516h2_8daaf6152771_d8a2da3f94cd`。
* 我们与真值的**逐字段差异只有 4 处**，且全部落在有意清单里：
  扩展顺序（有意打乱）/ `supported_groups` 少 11ec / `key_share` 少 11ec /
  ECH 载荷档位。出现第 5 处差异时 T3 的差分测试会打印首个不一致偏移与两侧 hex。

### 3.5 这不是纯外观问题：我们真的降级了密钥交换

必须写清楚（T4 的结论，见 `docs/fingerprint-security.md` §3.1 #8）：

* 真 Chrome 用 **X25519MLKEM768 混合**交换，具备抗「先存后解」（harvest-now,
  decrypt-later）的后量子保护；
* 我们只做**纯 X25519**。也就是说，**今天的流量可以被录下来，等未来量子计算机成熟后解密**。
* 这不是「伪装得像不像」的问题，而是一条**真实的密码学强度差异**。我们选择接受它，
  是因为引入 PQ 依赖 + 支持 HRR 会与 REALITY 的认证语义冲突（§6）且远超本次范围。
  它是**明确的非目标**，不是待办 bug —— 但文档与 release note 都不许把它藏起来。

> JA3/JA4 定义与可独立复核的 MD5/SHA-256 向量都在
> `crates/xt-wasm-tls/tests/fingerprint_differential.rs` 里；JA4 定义依据
> <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>。

---

## 4. profile 清单

| 名字 | 含义 | 默认 | 状态 |
|---|---|---|---|
| `chrome` | 对齐 `crates/xt-wasm-tls/src/testdata/xray-clienthello.hex`（官方 Xray 客户端 `fingerprint: chrome` 的真实抓包，1787 字节），**但刻意去掉 11ec**（`supported_groups` 与 `key_share` 里都没有它）——即「**PQ 尚未默认开启时期的 Chrome**」的形状（本工程用「约 Chrome 114」作代表；T4 记为 ≤123，具体版本边界**未验证**，没有旧版夹包可比），而非当前最新 Chrome。理由与实测见 §3.2 | ✅ 默认 | 引擎已落地（T1） |
| `plain` | 旧的精简形状（1 个 cipher、无 GREASE），「不想伪装」与回归基准 | | 引擎实现见 T1 |

### 4.1 每个 profile 的固定属性（**「我们到底伪装成什么」的唯一权威表**）

| 属性 | `chrome`（默认） | `plain` |
|---|---|---|
| 默认 **ALPN** | `h2, http/1.1`（**用户显式配置 ALPN 时以用户为准**） | **不注入**默认（空 → 不发 ALPN 扩展） |
| 扩展**顺序** | 每连接**随机打乱**（与真 Chrome 一致；否则「JA3 恒定」会成为真 Chrome 没有的跨连接标签） | 固定（旧形状） |
| **GREASE** | 有（cipher / 扩展 / groups / supported_versions / key_share / 末尾，均由每次连接的 CSPRNG 种子决定） | 无 |
| `supported_groups` 含 **11ec** | **否**（有意；声明而不给 key_share 会触发 HRR，见 §3.2） | 否 |
| ClientHello 总长 | **501 / 533 / 565 / 597** 字节（由 ECH 占位的 4 档载荷 144/176/208/240 决定；夹包同档 208 时为 565） | 固定 **177** 字节 |
| cipher 数量 | 16（含 1 个 GREASE 占位） | 1 |
| ECH(65037) | GREASE 占位（扩展长 186/218/250/282B 四档，不可解密） | 不发 |
| 用途 | 默认伪装；≈ **Chrome 114**（T4 记为 ≤123；具体版本边界未验证） | 「不想伪装」/ 回归基准 |

> 这张表的实现来源是 `crates/xt-wasm-tls/src/fingerprint.rs` 里的 `CHROME` / `PLAIN`
> 两个 `Profile` 常量；CLI 与本文档都不复制这些常量，只引用名字与属性。
> ALPN 属于 **profile 的一部分**（真 Chrome 一定带 ALPN，不带 ALPN 的浏览器形状
> 本身是稀有组合；而且 JA4 的 ALPN 标记位直接取决于它，空 ALPN 会让 JA4 与真 Chrome 不等），
> 所以不是可选装饰。

补充约定（已由 T1 确认，与 `fingerprint.rs` 同源）：

* **可选项清单与代码同源。** `--help` 与「未知名字」报错里的列表都从
  `xt_wasm_tls::fingerprint::profile_names()` 生成，不在 CLI 里手写第二份（防漂移）。
  该函数当前返回 `["chrome", "plain"]`，顺序稳定、无重复、含 `DEFAULT_PROFILE_NAME`。
* **名字大小写敏感、没有同义名。** `profile_by_name` 做精确匹配：`Chrome` / `CHROME`
  都算未知名字（启动即失败），没有 `none` / `raw` 之类的别名。
* **默认值是 `chrome`**（`DEFAULT_PROFILE_NAME`）；`None` / `""` → 由调用方映射到它，
  引擎自己**不兜底**（`profile_by_name("")` 与未知名字一样返回 `None`）。

---

## 5. 配置面（用户看到的样子）

| 参数 | 环境变量 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `--fingerprint <name>` | `XT_FINGERPRINT` | | `chrome` | ClientHello 指纹 profile。未知名字**启动即失败**（非 0 退出），错误里列出可用名字 |

语义定稿（`TlsConfig.fingerprint: Option<String>`，crates/xt-wasm-tls/src/config.rs）：

1. `None` 或 `""`（k8s 里没填的字段常是空串）→ 用 `DEFAULT_PROFILE_NAME`（`chrome`）。
2. 未知名字 → **配置错误，启动即失败**。**不静默回退**到 `plain`：
   静默回退会让用户以为在伪装、其实没有。
3. 优先级沿用本工程既有习惯：**环境变量打底，命令行覆盖**（`--fingerprint` > `XT_FINGERPRINT`）。
4. 与 `--no-flow` 一样，参数面在配置自检里可见（便于 k8s 排障）：
   `XT_CHECK=1` 把**生效的 fingerprint 与 ALPN 一起打印**（排障时这两者是一组），
   未知名字以非 0 退出。
5. **ALPN**：命令行目前**没有**独立的 `--alpn` 参数；`chrome` profile 自带默认
   `h2, http/1.1`（§4.1），所以默认发出的就是它。接口层语义是「用户显式给 alpn →
   用户优先；没给 → 用 profile 默认」。

> wasmtime 会把 guest 的退出码塌缩成 0 / 非 0（见 README「两个平台层面的坑」），
> 所以脚本里**不要断言 `== 2`**。

---

## 6. 与 REALITY 认证的关系（一句话 + 三条不变量）

**指纹只改 ClientHello 的外观，不改 REALITY 的认证语义：认证仍由
`random` 字段（HKDF salt）与 `session_id[0..16]`（认证密文）承载。**

三条不变量（T4 会逐条钉住）：

1. HKDF 的输入仍是 ClientHello 的 `random` 字段（握手消息偏移 6..26）；
2. REALITY 认证密文仍写在 `session_id[0..16]`，AAD 仍是「`session_id` 字段置零」的完整握手消息；
3. 服务端回显 `session_id` 的校验不变（`parsed_server_hello.session_id == client_hello[39..71]`）。

profile 引擎只负责「按 profile 拼其余字节」，不碰上面两处的位置语义。

---

## 7. 已知不一致点与代价

| # | 不一致点 | 对谁可见 | 结论 |
|---|---|---|---|
| 1 | **当前最新 Chrome 声明 11ec（且发它的 key_share），我们不声明** —— 我们模仿的是「PQ 之前」的 Chrome 形状 | 被动旁路观察者 / 真实对端站点 | ✅ **已实测（T4）**：跟随最新 Chrome 去声明 11ec 会让 5 个 SNI **5/5 触发 HelloRetryRequest**，而本工程不支持 HRR ⇒ 握手直接失败。因此**故意不声明**；这是唯一影响连通的差异，也是「不可弥补」的那一处 |
| 2 | ECH 是 GREASE 占位，不是真 ECH | 主动探测者 / 真实对端站点 | ✅ T4：**单条连接**不可与真 ECH 区分（ECH 内容本就随机）；主动探测需要「有/无 ECHConfig」的对照组，**未验证**；对端若把真 ECH 当硬要求会失败（推理，未验证） |
| 3 | ClientHello 总长 **501–597 字节**（4 档），官方抓包 **1723–1819 字节**（夹包 1787）；差 1222 字节 = 11ec 在 `supported_groups`(2B) + `key_share`(1220B) | 被动观察者（包长分布） | ✅ 数值已实测（T3 差分 + T1 的定长公式）；**包长分布是否构成可识别特征**：T4 列为残余风险（中），未做进一步分离实验 |
| 4 | 逐字段未对齐清单 | 被动观察者 | ✅ T3 实测：**只有 4 处** —— 扩展顺序（有意打乱）/ `supported_groups` 少 11ec / `key_share` 少 11ec / ECH 载荷档位。第 5 处一旦出现，差分测试会打印首个不一致偏移与两侧 hex |
| 5 | **JA4** 是否全等；以及 JA3 的 `EllipticCurves` 段与**当前** Chrome 不同（少了 11ec） | 被动观察者 | ✅ T3 实测：**JA4 全等**（双方 `t13d1516h2_8daaf6152771_d8a2da3f94cd`）；**JA3 必然不同**。注意真 Chrome 自己的 JA3 每次连接都不同（§3.4），所以「我们的 JA3」不是一个应当固定的值；只有把扩展段排序后的 JA3 才可与真值比较 |
| 6 | **密钥交换是纯 X25519**，无后量子混合 → 缺少抗「先存后解」保护 | 被动观察者（groups）/ 未来解密者 | ✅ **真实的密码学降级**，不是外观问题（§3.5，T4 §3.1 #8）。明确列为非目标，必须如实告知 |
| 7 | 「PQ 之前的 Chrome」这一版本年代假设（约 Chrome 114；T4 记为 ≤123） | 被动观察者（可用时间线推断） | ❔ **未验证**：没有旧版 Chrome/uTLS 的夹包可比其余字段（T4 残余风险 #5/#6）。长期看老版本 Chrome 会自然消亡，这一形状会越来越像伪装客户端 |
| 8 | 若对端**只接受 MLKEM key_share**，或**强制要求真实 ECH**（ECH required），我们可能直接握不上 | 真实对端站点 | **待验证**。⚠️ 这一条目前只是**推理**，没有实测 —— 不许当成已确认结论引用 |

> ⚠️ 本节是本文最容易写错的地方。上一轮排查被一句过时描述误导了好几轮，
> 所以这里的每一格**只有 T3/T4 的实测输出**能填写，推理、类比、直觉都不算。
> 本节中 #1 能写成结论，是因为 T4 给出了可复现的反向验证
> （把夹包只删掉 1216 字节的 11ec share，同一站点从正常 ServerHello 变成 HRR）；
> #4/#5 能写成结论，是因为 T3 的差分测试在我这边**实际跑过并全绿**
> （`cargo test -p xt-wasm-tls --test fingerprint_differential`，20 passed）。
> 完整的威胁模型与残余风险清单见 `docs/fingerprint-security.md` §3/§6。

---

## 8. 如何验证

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh

# 全部单测
CARGO_TARGET_DIR=$PWD/target cargo test --workspace

# wasm 构建（产品形态）
CARGO_TARGET_DIR=$PWD/target cargo build -p xt-wasm-cli --release --target wasm32-wasip2

# 本地 = CI 的全部检查（必须 9/9）
XW_CARGO_HOME=$PWD/target/cargo XW_TARGET_DIR=$PWD/target ./scripts/check.sh

# 指纹专项：JA3/JA4 计算 + 逐字段差分（T3 的集成测试，自带 MD5/SHA-256 权威向量）
# 会打印官方夹包的 JA3 五段串/值、JA4 值，以及字段级差异
CARGO_TARGET_DIR=$PWD/target cargo test -p xt-wasm-tls --test fingerprint_differential -- --nocapture

# 重抓一份官方客户端（fingerprint: chrome）的 ClientHello 夹包（脚本可重复运行，
# 产物写入 crates/xt-wasm-tls/src/testdata/，不覆盖已有夹具）
./scripts/capture-clienthello.sh

# 指纹专项：安全审计与对抗性测试（T4 写的）
CARGO_TARGET_DIR=$PWD/target cargo test -p xt-wasm-tls --test fingerprint_security

# 配置自检：打印生效 fingerprint（不监听端口）
XT_CHECK=1 XT_SERVER=127.0.0.1:8443 XT_PBK=<公钥> XT_SID=<sid> XT_SNI=<域名> \
  ./scripts/run-local.sh
# 未知名字必须失败并列出可用名字：
XT_FINGERPRINT=definitely-not-a-profile ... ./scripts/run-local.sh

# 端到端不回归（真的走新 ClientHello）
./scripts/e2e-wasm-to-wasm-test.sh
./scripts/e2e-vision-test.sh
```

---

## 9. Chrome 改版后怎么更新（维护手册）

Chrome 的 ClientHello 会随版本漂移。更新流程固定为「重抓 → 对拍 → 更新常量 → 重跑验收」：

1. **重抓夹包**：`scripts/capture-clienthello.sh`（T3 写）起一个裸 TCP 监听，让官方
   xray 客户端（`fingerprint: chrome`）连过去，抓第一条 record 并去掉 5 字节 record 头，
   把产物写成 `crates/xt-wasm-tls/src/testdata/` 下的**新文件**（如 `xray-clienthello-2026-09.hex`）。
   已有夹具 `xray-clienthello.hex` 是 `reality_server.rs` 的对拍依据，**不要覆盖它**。
2. **确认这是权威对照**：夹包的抓法要写进脚本注释（客户端版本、配置、抓取命令），
   否则半年后没人知道它对齐的是哪个 Chrome。
3. **改常量**：所有需要随之调整的常量都集中在 `crates/xt-wasm-tls/src/fingerprint.rs`：
   cipher 列表、扩展集合（顺序由实现每连接随机打乱）、各扩展的内容取值、
   `supported_groups`、ALPN、`signature_algorithms`、GREASE 模式。CLI 与本文档
   **不含**这些常量（只引用名字）。
   ⚠️ **新夹包里如果出现 11ec，必须先把它去掉再对齐** —— 照抄会让对端发 HRR、
   握手直接失败（§3.2 的实测）。这条不是「暂未实现」，是设计约束。
4. **跑对拍**：`cargo test -p xt-wasm-tls --test fingerprint_differential -- --nocapture`。
   判据是 **JA4 全等** + 逐字段差分；差分清单只允许包含 §3.2 那两条有意差异，
   加上本来就随机的窗口（GREASE / `random` / `session_id[16..32]` / x25519 公钥 /
   ECH 载荷 / 扩展顺序）。出现清单之外的差异必须解释清楚，**不要**放宽窗口掩盖它。
5. **重跑全部验收**：`cargo test --workspace` + `./scripts/check.sh`（9/9）+ 两条 e2e。
6. **更新本文**：把 §1.1 状态表与 §7 的结论按新实测刷新。

**两条禁止的「修绿」手法**（写了就是错）：
* 为了让对拍变绿而**把 11ec 加回 `supported_groups`**（去「对齐」当前 Chrome）—— 那会
  让对端发 HRR、握手直接失败（§3.2），是把连通性换成纸面相似度；
* 为了掩盖差异而**放宽差分窗口**（把非随机字节也算成「随机」）—— 窗口只能包含真随机的字节。

---

## 10. 证据索引

| 内容 | 位置 |
|---|---|
| 真 Chrome 形状的权威对照（官方客户端抓包） | `crates/xt-wasm-tls/src/testdata/xray-clienthello.hex`（抓法：V18） |
| 服务端接受纯 X25519（不需要 ML-KEM） | `docs/verification-log.md` V7 |
| 官方客户端 ClientHello 的结构与跨实现认证 | `docs/verification-log.md` V18 |
| 对拍判据（JA3 / JA4 / 逐字段差分） | T3 产物：`crates/xt-wasm-tls/tests/fingerprint_differential.rs`（20 绿，lead 复核收尾） |
| 安全审计与残余风险 | T4 产物：`docs/fingerprint-security.md` + `crates/xt-wasm-tls/tests/fingerprint_security.rs`（26 绿，lead 复核收尾） |
| 引擎实现（profile 常量 / GREASE / 洗牌 / ECH 占位） | T1：`crates/xt-wasm-tls/src/fingerprint.rs` |
| 接线与「chrome 握手可被本工程服务端认证」 | T2：`crates/xt-wasm-tls/src/reality.rs` 的 `resolve_profile` / `build_reality_client_hello_with_profile`，测试 `chrome_client_hello_authenticates_against_our_server` |
| 配置面 / 默认值 | 本文 §5 + `crates/xt-wasm-cli/src/main.rs` |
