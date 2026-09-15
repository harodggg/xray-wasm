# xray-wasm · 可行性结论与实施方案

> 目标：把 Xray 当前最强协议栈 **VLESS + XTLS-Vision + REALITY** 的**客户端**用 Rust 实现，
> 编译为 **wasm32-wasip2**，在 **wasmtime** 下运行真实的 TCP 代理。
>
> 本文所有"已验证"结论都有可复现的实验证据，不是推断。

---

## 1. 可行性结论（全部已实测）

| # | 关键问题 | 结论 | 证据 |
|---|---|---|---|
| 1 | WASI preview1 能否发出站 TCP？ | ❌ **不能** | Rust std `sys/pal/wasi/net.rs:64` 里 `TcpStream::connect` 直接 `unsupported()`；实测报 `kind=Unsupported` |
| 2 | WASI preview2 能否发出站 TCP？ | ✅ **能** | 实测 `wasmtime run -S tcp=y -S inherit-network=y` → 真实 connect/write/read 成功（收到 `pong`） |
| 3 | 纯 Rust 密码学在 wasip2 可用？ | ✅ **能** | X25519 ECDH 双方一致、HKDF-SHA256、AES-256-GCM 往返、`getrandom` 全部实跑通过 |
| 4 | async 代码能否在 wasip2 跑？ | ✅ **能** | wasip2 无 tokio reactor；用**阻塞 socket 包装成 `AsyncRead`/`AsyncWrite` + `futures::executor::block_on`** 驱动，实测收发成功 |
| 5 | 有没有现成的纯 Rust REALITY 客户端？ | ✅ **有** | meow-rs 的 `reality_tls.rs`（2203 行）**零 `boring` 依赖**，自实现 TLS 1.3 记录层/握手/密钥调度，session_id 封装语义与 Xray 官方逐字节一致 |
| 6 | VLESS + XTLS-Vision 能否复用？ | ✅ **能** | meow-rs 的 `vless/vision.rs`、`vless/header.rs` 均 **0 个 boring、0 个 `tokio::net`**，只依赖 `tokio::io` trait |
| 7 | 服务端是否接受**纯 X25519** 的 REALITY ClientHello？ | ✅ **接受** | 官方客户端用 `fingerprint: ios/edge/random` 时服务端日志为 `is using X25519MLKEM768: false` + `handshake() err: <nil>` + `isHandshakeComplete: true` + `received request for tcp:...`。**因此移植不需要 ML-KEM** |

**结论：方案成立。** 关键路径上已无未知风险。

> 第 7 项是开工前最重要的一个验证。现代 Chrome 指纹会带后量子混合密钥交换
> X25519MLKEM768（官方客户端 `fingerprint: chrome` 实测就是 `true`），
> 而移植的实现是纯 X25519。如果服务端只认 MLKEM，整个方案就要额外背上 ML-KEM 依赖。
> 实测确认服务端对纯 X25519 一视同仁——**这条岔路被排除**。

### 1.1 复现命令（全部在 wasmtime 48.0.2 + stable 1.98.1 上跑过）

```sh
# wasip1：失败，且是语言标准库层面的失败
rustc --target wasm32-wasip1 probe.rs -o p1.wasm
wasmtime run p1.wasm 127.0.0.1:18080          # → operation not supported (kind=Unsupported)

# wasip2：成功
rustc --target wasm32-wasip2 probe.rs -o p2.wasm
wasmtime run -S tcp=y -S inherit-network=y p2.wasm 127.0.0.1:18080   # → OK: read 5 bytes "pong\n"
# 注意：只给 tcp=y 而漏了 inherit-network=y，会得到 PermissionDenied（os error 2），
# 这个报错极易被误读成「网络被墙」。
```

---

## 2. 三条被排除的路线（记录下来，避免以后重走）

1. **wasm32-wasip1** —— 出站 TCP 在语言标准库层面就不存在，无论换什么运行时都救不了。**必须用 wasip2。**
2. **沿用 meow-rs 的 BoringSSL 后端** —— `boring` 是 C++（BoringSSL），编译到 wasm 需要 wasi-sdk 工具链且改动面极大。**REALITY 逻辑本身不依赖它**，所以直接绕开。
3. **`rustls`** —— 不暴露 ClientHello 的字节级控制（扩展顺序、GREASE、session_id），而 REALITY 的认证**就藏在 session_id 里**。这是 meow 当初手写 TLS 的原因，我们沿用同一判断。

---

## 3. REALITY 客户端认证算法（据 Xray 官方 `transport/internet/reality/reality.go` 核实）

```
1. 构造 ClientHello，其中 session_id 预留 32 字节全 0，记下此时完整字节 raw
2. session_id[0..3] = 版本号(x,y,z);  [3] = 0
   session_id[4..8] = BE32(unix 时间戳)
   session_id[8..]  = shortId
3. ecdhe   = ClientHello 里 key_share 的临时私钥（就是真 TLS 用的那把）
   AuthKey = ECDH(ecdhe_priv, server_public_key)          // 32 字节
   AuthKey = HKDF-SHA256(ikm=AuthKey, salt=ClientHello.random[:20], info="REALITY")
4. 密文 = AES-256-GCM(AuthKey).Seal(
        nonce      = ClientHello.random[20:32],
        plaintext  = session_id[:16],                     // 16 字节 → 密文16 + tag16 = 32
        aad        = raw)                                 // ← 注意：AAD 是 session_id 全 0 时的 ClientHello
5. 把 32 字节密文写回 ClientHello 的 session_id 字段（偏移 39..71）
6. 服务端证书校验不走 CA：服务端用临时 ed25519 证书，
   其 Signature 字段 == HMAC-SHA512(AuthKey, 证书公钥)  → 以此证明对方持有 REALITY 私钥
```

**第 4 步的 AAD 细节是易错点**，meow 的实现里已有对应注释与单测（`reality_client_hello_session_id_decrypts_to_auth_payload`），移植时要保留。

---

## 4. 架构

```
xray-wasm/
  Cargo.toml               # workspace
  crates/
    xt-wasm-tls/           # 移植 meow reality_tls.rs：TLS1.3 + REALITY 客户端（纯 Rust）
    xt-wasm-vless/         # 移植 meow vless/{header,vision}.rs：VLESS 请求头 + XTLS-Vision 流控
    xt-wasm-runtime/       # wasip2 运行时桥接：阻塞 socket ↔ AsyncRead/AsyncWrite + executor
    xt-wasm-cli/           # 产物：wasm32-wasip2 可执行文件（本地 TCP 监听 → 隧转发）
  docs/
  scripts/run-local.sh     # 封装 wasmtime 的 -S tcp=y -S inherit-network=y
  tests/                   # 端到端测试（见 §6）
```

**数据流**

```
本地 TCP 连接
   └─▶ xt-wasm-vless   VLESS 请求头 + Vision 填充
         └─▶ xt-wasm-tls   REALITY 认证 → TLS1.3 记录层加密
               └─▶ wasip2 阻塞 TcpStream ──▶ wasmtime 宿主 TCP ──▶ 服务端
```

**移植时需要改的只有两处**
- `reality_tls.rs:130` 的 `tokio::time::timeout` → 换成不依赖 runtime 的超时（或直接用 socket SO_RCVTIMEO）
- 依赖的 `meow_common::{ProxyConn, Metadata}` 小 trait/类型 → 本地精简实现

---

## 5. 里程碑

| # | 内容 | 完成判据 | 状态 |
|---|---|---|---|
| M0 | 骨架 + 运行时桥接 | 阻塞/非阻塞 socket 桥接与 executor 在 wasip2 上跑通 | ✅ **完成**（V4/V5/V9） |
| M1 | 移植 `reality_tls.rs`，剥离 tokio runtime | wasm 内完成一次到**真实 Xray REALITY 服务端**的 TLS1.3 握手，且服务端确认 `isHandshakeComplete=true` | ✅ **完成**（V11 修复 + V12，226ms） |
| M2 | 移植 VLESS 头 + Vision | 能将一个 TCP 流经隧道送到目标并回传 | ✅ **完成**（V13，服务端日志 `received request for tcp:example.com:443`） |
| M3 | CLI + 本地端到端 | 经 wasm 隧道拿到真实网页 | ✅ **完成**（V13，`curl --proxy socks5h://…` → HTTP 200） |
| M4 | 硬化 | 超时/错误路径、无 `unwrap` panic、与 stock Xray 客户端对拍线格式 | 🟡 **部分完成**：对拍见 V14（`ServerHello` 127 字节与官方一致），并修复了 `ClientVer` 互通缺陷；错误路径与 panic 审计仍待做 |

**验收现状**：`cargo test --workspace` → 59 passed / 0 failed；
`./scripts/e2e-test.sh` → 端到端通过。详见 `docs/verification-log.md` V13/V15。

### 尚未完成的事项（诚实列出）

1. **TLS 指纹仍是手写形状**，未实现 uTLS 的 Chrome 伪装（见 §7 风险表）。
   功能可用，但抗 JA3/JA4 与主动探测能力弱于官方客户端。
2. **未实现 XTLS-Vision 的 DIRECT splice 性能优化**（功能正确，仅性能差异）。
3. **未做 UDP / Mux / 后量子（ML-KEM、ML-DSA-65）**，均在范围内明确排除。

> 并发与调度已不再是限制：
> * v0.2 起改为**非阻塞并发**，一条长连接不再独占进程（V16，A/B 实测）；
> * v0.3 起 socket 换成 **`wasi:sockets` 直连**，建连不再阻塞事件循环，
>   等待由 pollable 真就绪通知完成，空闲 CPU 降低约 17 倍（V17）。

---

## 6. 测试策略（关键：不依赖远程 VPS）

在**同一台机器**上完成真实验证：
1. 下载官方 Xray-core 的 macOS 二进制到工作区；
2. 用 `xray x25519` 生成密钥对，手写一份 REALITY 服务端配置（`dest` 指向真实 TLS1.3 站点）；
3. 本地起服务端（127.0.0.1:8443）；
4. 把 wasm 客户端指向它，验证端到端连通；
5. **对拍**：同一配置下用官方 xray 客户端跑一遍，比对线上字节（至少比对 ClientHello 结构与 session_id 语义）。

> 工作区已有的 `xray-deploy/install-xray.sh` 是 Linux/systemd 的服务端一键脚本，
> 不能直接在 macOS 跑，但它是**服务端配置字段的权威参考**（VLESS+Vision+REALITY、X25519、shortId、spiderX）。

---

## 7. 风险登记

| 风险 | 影响 | 处置 |
|---|---|---|
| wasmtime 的 `-S inherit-network=y` 是实验性开关，未来语义可能变 | 运行方式需调整 | 在 `scripts/run-local.sh` 里集中封装；必要时改用宿主内嵌 wasmtime（Rust 侧控制 socket 注入） |
| 移植的 meow 代码与上游 Xray 后续版本漂移 | 握手失败 | 保留 §3 的算法文档与对拍测试 |
| 浏览器场景完全不可用（无裸 TCP） | 不能用于 Chrome 扩展 | 已与用户确认目标为 wasi/wasmtime；浏览器需另走 XHTTP/WSS 路线 |
| meow-rs 为 MIT，但需保留版权声明 | 合规 | 移植文件头部保留出处与 LICENSE 声明 |
| **客户端 TLS 指纹不是浏览器形状**（移植实现手写 ClientHello，不含 uTLS 伪装；`TlsConfig::fingerprint` 保留了字段但未生效） | **功能可用，但削弱 REALITY 的核心价值**：能连通（§1 第 7 项已证），却更容易被 JA3/JA4 或主动探测识别 | v1 接受；后续若要恢复伪装需按 Chrome 的扩展顺序/GREASE/ALPN 逐字节构造 ClientHello，并与真实 Chrome 抓包对拍 |
| 与 Vision 的 `direct splice` 性能优化未实现 | 仅性能，不影响连通 | M2 先做功能正确，性能留待 M4 |

---

## 8. 未决事项

- **是否移植 meow-rs 代码**（MIT）还是干净重写 —— 影响工期与合规，待确认。
- 项目位置（顶层 `xray-wasm/` vs 并入 `xray-tun`）—— 待确认。
