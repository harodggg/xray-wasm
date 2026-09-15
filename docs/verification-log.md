# 验证日志

本文件记录**实际跑过的实验**及其原始观测结果。目的是把「已证明的事实」与「推测」分开：
每一项都给出可复现命令与当时的输出，日后任何一项行为变化都能立刻定位。

环境：macOS / Apple Silicon、wasmtime 48.0.2 (e9f1ea232, 2026-09-10)、
rustc 1.98.1 stable（wasm32-wasip2）与 rustup nightly 1.85.0（对照用）。

---

## V1 · WASI preview1 无法发出站 TCP —— 排除该路线

**结论：** ❌ 不可用。且是**语言标准库层面**的不可用，换运行时也救不了。

证据一，源码（`library/std/src/sys/pal/wasi/net.rs:64`）：

```rust
pub fn connect(_: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
    unsupported()
}
```

证据二，编译产物的导入表里**只有** `fd_read/fd_write/fd_close/proc_exit/…`，
唯独没有 `sock_connect`（有 `sock_accept/recv/send/shutdown`，说明 socket 概念存在，
只是没有「主动连接」）。

证据三，实跑：

```
$ wasmtime run probe-p1.wasm 127.0.0.1:18080
CONNECT_ERR: operation not supported on this platform (kind=Unsupported)
```

**推论：必须用 wasip2。**

---

## V2 · WASI preview2 可以发出站 TCP

```
$ wasmtime run -C cache=n -S tcp=y -S inherit-network=y probe-p2.wasm 127.0.0.1:18080
OK: read 5 bytes: "pong\n"
```

**两个 flag 都是必需的**，且失败信息极具误导性：

| 命令 | 结果 |
|---|---|
| 不带 flag | `Permission denied (os error 2)`（看起来像被墙，其实是 host 策略） |
| 只带 `-S tcp=y` | `Permission denied (os error 2)` |
| `-S tcp=y -S inherit-network=y` | ✅ 成功 |
| 再加 `-S allow-ip-name-lookup=y` | ✅ 成功（**域名解析需要它**） |

---

## V3 · 纯 Rust 密码学栈在 wasip2 上可用

实测通过（`x25519-dalek` + `hkdf` + `sha2` + `aes-gcm` + `getrandom`）：

```
[1] getrandom OK, first byte = 7
[2] X25519 ECDH agrees, client_pk[0]=2 shared[0]=49
[3] HKDF-SHA256 OK, auth_key[0]=43
[4] AES-256-GCM roundtrip OK, ct_len=36
RESULT: pure-Rust crypto stack works on this wasm target
```

`getrandom` 有输出说明 wasm 内有可用 CSPRNG —— 握手需要它生成临时密钥。

---

## V4 · async 代码可在 wasip2 上驱动（无 tokio runtime）

wasip2 上既没有 mio/epoll，也没有线程（`std::thread::spawn` 是 `unsupported()`），
所以不能起 tokio runtime。做法是把阻塞 socket 包成 `AsyncRead`/`AsyncWrite` 再用 executor 驱动。

实测：

```
[host] got: "hello from wasm\n"
ASYNC-OVER-BLOCKING OK: got "pong"
```

同时确认 `tokio` 的 `io-util` 特性（只有 trait 和工具，没有 runtime）能在 wasip2 上编译。

---

## V5 · 非阻塞 socket 在 wasip2 上是真实实现

这一项决定架构：握手是顺序的（阻塞够用），但握手后的**全双工转发**要求读写同时存活。

源码（`library/std/src/sys/pal/wasip2/net.rs:315`，走 `ioctl(FIONBIO)`，不是 `unsupported()`）：

```rust
pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
    let mut nonblocking = nonblocking as c_int;
    cvt(unsafe { netc::ioctl(self.as_raw_fd(), netc::FIONBIO, &mut nonblocking) }).map(drop)
}
```

实测（host 监听但故意 5 秒不发言，阻塞读会明显挂住）：

```
connected
set_nonblocking(true) -> OK
read -> WouldBlock  [non-blocking WORKS]
--- elapsed: 0s (0-1s = non-blocking; ~5s = blocked) ---
```

---

## V6 · `SystemTime::now()` 在 wasip2 上正常

REALITY 把 unix 时间戳放进 session_id，服务端按 `maxTimeDiff` 校验；
时钟不对会被直接拒绝，且症状是「握手失败」、看不出是时钟问题。

```
host time: 1789438743
SystemTime::now() -> unix=1789438743  plausible=true
```

与宿主时间**逐秒一致**。

---

## V7 · 服务端接受纯 X25519 的 REALITY ClientHello —— 不需要 ML-KEM

这是开工前最关键的验证。现代 Chrome 指纹会带后量子混合密钥交换 X25519MLKEM768
（见下），而待移植的实现是纯 X25519。若服务端只认 MLKEM，方案就要额外背上 ML-KEM 依赖。

用官方客户端逐个指纹对**本地 stock Xray v26.3.27 REALITY 服务端**测试，服务端日志：

```
# fingerprint: chrome （后量子混合）
is using X25519MLKEM768 for TLS' communication: true
hs.handshake() err: <nil>
hs.c.isHandshakeComplete.Load(): true

# fingerprint: ios / edge / random （纯 X25519）
is using X25519MLKEM768 for TLS' communication: false
hs.handshake() err: <nil>
hs.c.isHandshakeComplete.Load(): true
proxy/vless/inbound: received request for tcp:example.com:443
```

六种指纹全部 `http=200`。**结论：纯 X25519 被一视同仁地接受，移植不需要 ML-KEM。**

---

## V8 · 参照链路（官方客户端）可作为对拍基准

本地 stock Xray 服务端 + 官方客户端：

```
$ curl --proxy socks5h://127.0.0.1:1080 https://example.com
  http_code=200  size=559  time=0.522702s
$ curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
  45.207.197.185
```

服务端日志同时给出了 REALITY 认证成功的逐字段证据（`ClientVer`、`ClientTime`、
`ClientShortId`、`AuthKey[:16]`），可作为移植后逐字段比对的锚点。
测试参数：VLESS + XTLS-Vision + REALITY，服务端 `127.0.0.1:8443`，
`dest`/`serverName` = `www.cloudflare.com:443`。

---

## V9 · `thread::sleep` 与 `Instant` 在 wasip2 上可用

`xt-wasm-runtime::block_on` 在 future 返回 `Pending` 时用 `thread::sleep` 让出，
若 sleep 是空实现，executor 就会变成纯空转甚至行为异常。实测：

```
thread::sleep(500ms) returned; elapsed = 503.140625ms
VERDICT: sleep WORKS (executor backoff is valid)
Instant resolution check: elapsed after spin = 1.333µs
real  0m0.566s
```

宿主墙钟 0.566s 与 500ms 一致 → 确实交给了 host 的 `poll_oneoff`，不是空转。

---

## V11 · 移植发现的上游潜伏 bug：server flight 被合并进一条记录

**这是整个移植里唯一一个真正需要改协议代码才能修的问题**，值得完整记录。

### 症状

wasm 与宿主上表现完全一致：TCP 连上、服务端 REALITY 认证**成功**
（`AuthKey` 推导出来、`ClientTime`/`ClientShortId` 解码正确），
但客户端在 10 秒后超时，服务端日志停在：

```
hs.handshake() err: <nil>
hs.readClientFinished() err: EOF        ← 一直等不到客户端的 Finished
hs.c.isHandshakeComplete.Load(): false
```

### 定位过程

`tracing::debug!` 打开后，客户端日志停在**第一条**加密记录：

```
DEBUG Reality TLS received ServerHello cipher_suite=0x1301 session_id_len=32
DEBUG Reality TLS decrypting encrypted handshake record record_len=3595
<无后续输出，直到超时>
```

只读了一条记录就不再前进 —— 而服务端已经发完整个飞行包。这个「只读一次就停」
是决定性的线索。

### 根因

握手主循环每轮都**无条件先读一条新记录**：

```rust
loop {
    fill_decrypted_handshake(...).await?;   // ← 每轮都去读新记录
    let msg = pop_handshake_message(&mut buf)...;  // 只弹一条
    ...
}
```

而**真实 Xray 把整段 server flight（EncryptedExtensions + Certificate +
CertificateVerify + Finished）合并进一条加密记录**。于是：

| 轮次 | 行为 |
|---|---|
| 1 | 读记录 → 4 条消息全部进入缓冲区 → 弹出并处理 EncryptedExtensions |
| 2 | 又去读新记录 → 服务端已发完 → **永久阻塞** |

缓冲区里的 `Finished` 再也没机会被处理，而它正是服务端在等的最后一条消息。

### 为什么上游测试发现不了

meow-rs 的 mock server **每条消息单独发一条记录**，所以「一轮一条消息」的假设
在它的测试里永远成立。只有对接真实服务端才会现形 —— 这正是「必须做端到端验证，
不能只靠单元测试」的一个实例。

### 修复

改成「先看缓冲区里有没有完整消息，凑不出完整消息时才去读新记录」：

```rust
let msg = match pop_handshake_message(&mut handshake_buf) {
    Some(m) => m,
    None => {
        fill_decrypted_handshake(&mut inner, &mut server_hs, &mut handshake_buf).await?;
        pop_handshake_message(&mut handshake_buf).ok_or_else(|| ...)?
    }
};
```

修复后 19 个上游测试全部仍然通过，且真实握手从「10 秒超时」变为 **约 226ms 成功**。

---

## V12 · M1 达成：wasm 客户端对真实服务端完成 TLS 1.3 + REALITY 握手

```
$ ./scripts/run-local.sh --self-test --server 127.0.0.1:8443 \
      --pbk HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg \
      --sid 64f6ffd42769a12c --sni www.cloudflare.com
[self-test] 目标 127.0.0.1:8443  SNI www.cloudflare.com
[self-test] TCP 已连接
[self-test] ✓ REALITY 握手完成，用时 226.53575ms
exit=0
```

**服务端日志（独立于我们自己的外部证据）：**

```
REALITY remoteAddr: 127.0.0.1:54297
	hs.c.AuthKey[:16]: [255 201 214 139 ...]	AEAD: *gcm.GCM
	hs.c.ClientVer: [1 8 1]
	hs.c.ClientTime: 2026-09-15 10:25:15 +0800 CST
	hs.c.ClientShortId: [100 246 255 212 39 105 161 44]
	is using X25519MLKEM768 for TLS' communication: false
	hs.handshake() err: <nil>
	hs.readClientFinished() err: <nil>            ← 我们发的 Finished 被接受
	hs.c.isHandshakeComplete.Load(): true         ← 握手彻底完成
```

对照修复前同一位置的记录是 `readClientFinished() err: EOF` +
`isHandshakeComplete.Load(): false` —— 前后差异明确，不是解读出来的。

**判据满足**：wasm 内完成到真实 Xray REALITY 服务端的 TLS 1.3 握手，
且服务端确认 `isHandshakeComplete = true`。

---

## V13 · M2/M3 达成：wasm 客户端端到端代理真实流量

```
$ ./scripts/e2e-test.sh
==> 1/4 确保 stock Xray REALITY 服务端在跑
  ✓ 服务端已在 127.0.0.1:8443
==> 2/4 启动 wasm 客户端（SOCKS5）
  ✓ 客户端已监听 127.0.0.1:1080
==> 3/4 经隧道取一个真实页面
  ✓ https://example.com -> 200
==> 4/4 出口 IP 应与直连不同
  ✓ 隧道出口 IP：45.207.197.185
```

即：
`curl --proxy socks5h://127.0.0.1:1080 https://example.com` →
SOCKS5 → VLESS + XTLS-Vision + REALITY（**全部在 wasm 内**）→ 真实网页。

**服务端日志的外部证据**（证明 VLESS 头与 Vision flow 都被正确解析）：

```
proxy/vless/inbound: firstLen = 52
proxy/vless/inbound: received request for tcp:example.com:443
app/dispatcher: default route for tcp:example.com:443
from 127.0.0.1:55458 accepted tcp:example.com:443 [direct]
...
proxy/vless/inbound: received request for tcp:api.ipify.org:443
```

这两个目标正是 e2e 脚本发出的两个请求，一一对应。

---

## V14 · 与官方客户端对拍线格式

同一套服务端配置下，官方 Xray 客户端（多种 uTLS 指纹）与本实现的对照：

| 观测项（均取自服务端日志） | 官方 `fp=chrome` | 官方 `fp=ios` | **本实现** |
|---|---|---|---|
| `ClientVer` | `[26 3 27]` | `[26 3 27]` | **`[26 3 27]`**（默认对齐，可配） |
| `ClientShortId` | 配置值 | 配置值 | 配置值（一致） |
| 密钥交换 | X25519MLKEM768 | X25519 | **X25519** |
| `ServerHello` 字节数 | 1215 | 127 | **127** |
| `hs.handshake() err` | `<nil>` | `<nil>` | **`<nil>`** |
| `readClientFinished() err` | `<nil>` | `<nil>` | **`<nil>`** |
| `isHandshakeComplete` | `true` | `true` | **`true`** |
| VLESS 请求被解析 | 是 | 是 | **是** |
| HTTP 结果 | 200 | 200 | **200** |

`ServerHello` 字节数与官方纯 X25519 指纹（127）**完全一致**，说明握手结构对齐。

### 对拍中发现并修复的差异：`ClientVer`

最初移植实现（承自 meow-rs / sing-box）硬编码 `ClientVer = [1, 8, 1]`，
并在注释中断言「服务端不校验这三个字节」。

**这个断言是错的。** 从 `xtls/reality/tls.go` 源码核实，认证时必须同时满足：

```go
(config.MinClientVer == nil || Value(ClientVer) >= Value(MinClientVer)) &&
(config.MaxClientVer == nil || Value(ClientVer) <= Value(MaxClientVer)) &&
(config.MaxTimeDiff == 0 || time.Since(ClientTime).Abs() <= MaxTimeDiff) &&
(config.ShortIds[ClientShortId])
```

默认 `MinClientVer`/`MaxClientVer` 为空所以不校验 —— 这正是「本机测试完全正常」
的原因；但只要部署方设了 `minClientVer`，`[1,8,1]`（=66049）会被判为探测流量
并转发给 `dest`，客户端侧表现为**握手失败**。

**处置**：`RealityConfig` 增加 `client_version: [u8; 3]`，默认取
`[26, 3, 27]`（与本工程验证过的 Xray 版本对齐，因为 `minClientVer` 远
比 `maxClientVer` 常见），CLI 提供 `--client-ver x.y.z` 覆盖。
新增单测 `reality_client_hello_uses_configured_client_version` 钉住该行为。

> 本工作区自己的 `xray-deploy/install-xray.sh` 并未设置 `minClientVer`，
> 所以这个坑不会在本机暴露 —— 属于典型的「本地通过、上线失败」。

---

## V15 · 最终约束核查

| 检查 | 命令 | 结果 |
|---|---|---|
| wasm 依赖树无 C++/mio | `cargo tree -p xt-wasm-cli --target wasm32-wasip2 \| grep -icE 'boring\|mio\|parking_lot\|socket2\|openssl'` | **0** |
| 生产代码无 tokio runtime | `grep -rnE 'tokio::(net\|time\|spawn\|runtime\|fs\|process\|signal)' crates/*/src/` | 仅 1 处**注释** |
| 全工作区测试 | `cargo test --workspace` | **59 passed / 0 failed** |
| wasm 产物体积 | — | **284.7 KB** |
| 产物类型 | magic bytes | `0d 00 01 00` = **component model（wasip2）** |

---

## V16 · 并发修复：从「顺序 accept」到「非阻塞多路复用」

### 问题

早期实现是顺序 accept（wasip2 无线程）：

```rust
loop {
    let (local, peer) = listener.accept()?;   // 阻塞
    handle_connection(local, ...)?;           // 处理到结束才回来
}
```

一条 **keep-alive 长连接就会独占整个进程**，其它客户端全部排队。作为 k8s 共享出口
代理基本不可用 —— k8s 的 TCP 探针也会因此超时。这是当时文档里列为「最值得下一步做」的限制。

### 前提验证

动手前先确认三件事，都实测过：

| 前提 | 结果 |
|---|---|
| `TcpListener::set_nonblocking` 在 wasip2 可用 | ✅ 连做 3 次 `accept` 全部立即返回 `WouldBlock`，总用时 **43µs** |
| 给 future 加墙钟超时可行 | ✅ `Instant` 可用；用 `futures::future::select` + 一个只含 `Instant` 的 `Deadline`，**无需任何 unsafe 的 pin 投影** |
| `TcpListener` 有 `set_read_timeout` | ❌ 不存在（那是 `TcpStream` 的方法）—— 所以只能走非阻塞 |

### 改动

1. **`xt-wasm-runtime`**：新增 `timeout()`。socket 是非阻塞的，读操作**永远不会自己失败**，
   没有墙钟超时的话，一个「连上不发数据」的客户端会永久占住一个并发槽位，
   攒满上限就把代理彻底堵死。
2. **`socks5.rs`**：协商从阻塞 `Read`/`Write` 改为 `AsyncRead`/`AsyncWrite`。
   协商逻辑一字未改，只是能被打断。测试也从「真实 socket + 线程」改为
   「`tokio::io::duplex` 内存管道 + `join!`」—— 与目标平台一样不需要线程。
3. **`main.rs`**：非阻塞 accept + 连接集合统一轮询（`MAX_CONCURRENT_CONNS = 64`，
   超出后暂停 accept，新连接留在内核 backlog）。空闲时让出 10ms，有在途连接时 1ms。

### A/B 对照（决定性证据）

用**同一个并发用例**分别打新旧实现：先建立一条「已建隧道但一直不发数据」的长连接，
然后在它存活期间发起一个正常请求。

| 实现 | 长连接占用期间的新请求 |
|---|---|
| **v0.1.0（顺序 accept）** | **超时/失败，耗时 12s** ❌ |
| **修复后（多路复用）** | **HTTP 200，耗时 1s** ✅ |

用例本身带防自欺检查：断言长连接进程在请求完成时**仍然存活**
（`kill -0`），否则「并发通过」可能只是因为它已经结束了。

### 残留的阻塞点（如实记录）

`xt_wasm_runtime::connect` 仍是阻塞的 —— Rust 在 wasip2 上没给非阻塞 connect 的接口
（标准库内部自己做非阻塞 connect + poll，但不暴露出来）。所以「连服务端」这一步会
短暂阻塞整个循环：同机/局域网是毫秒级，但服务端不可达时会阻塞到 TCP 超时。
REALITY 握手本身及之后的全过程都是非阻塞的，影响仅限建连这一小段。

### 复现

```sh
./scripts/gen-test-server.sh && . .test-server/params.env
XW_XRAY_DIR=$PWD/.test-server ./scripts/e2e-test.sh   # 第 7 步即并发用例
```

---

## V17 · 换掉 `std::net`：非阻塞 connect + 真就绪通知

### 问题（V16 遗留的两条）

V16 把并发做出来了，但底层仍有两个硬伤，**根因是同一个**：Rust 在 wasip2 上的
`std::net` 只能阻塞，且不暴露底下的 WASI 资源。

| 问题 | 后果 |
|---|---|
| 没有非阻塞 connect | 「连服务端」这一步会阻塞整个事件循环；服务端不可达时卡到 TCP 超时 |
| 拿不到 pollable | 等数据只能「轮询 + 让出」（1ms），空闲时也在周期性唤醒 |

### 方向选择

两个问题都要绕开 `std::net`、直接用 `wasi:sockets`。先确认现成积木：

| 方案 | 结论 |
|---|---|
| `wstd` v0.6.8（Bytecode Alliance 官方） | ✅ 采用。提供事件循环、pollable 封装、定时器，且把原始 `wasip2` 绑定透出来 |
| `async-wasi` v0.2.1 | ❌ 绑定 WasmEdge，运行时不对 |
| 手写 wit-bindgen 绑定 | ❌ 不必要，`wstd` 已提供 |

**与协议层的边界**：`wstd` 的 `AsyncRead`/`AsyncWrite` 是 `async fn` 式的，
而移植过来的 TLS/VLESS/Vision 用的是 tokio 的 **poll 式** trait。
实测确认可以在原始 `wasi:sockets` 流上实现 poll 式 trait（`poll_*` 里非阻塞读，
遇 `would-block` 就把 pollable 的 waker 注册到当前任务），
**因此协议层一行未改** —— 换掉的只是最底下的 socket 层。

### 前提验证（都实测过）

| 前提 | 结果 |
|---|---|
| `wstd` 在 wasmtime + 我们的 flag 下可用 | ✅ 异步 connect/write/read/bind 全部成功 |
| 能否在原始 wasip2 流上实现 poll 式 trait | ✅ spike 跑通，且观测到 `poll_read: Pending` → 被 reactor 唤醒（真就绪，非轮询） |
| `NetStream` 是否满足 `Stream` 的 `Send + Sync` | ✅ 编译期静态断言通过 |

### 实现中撞到的两个 WASI 资源语义坑

都是 spike 阶段暴露的，两个都会让程序**看起来能跑但退出时报错**：

1. **必须持有 `TcpSocket`**。它派生出的 `input`/`output` 流在父资源被 drop 后会失效。
2. **字段顺序决定 drop 顺序**，而 WASI 要求**子资源先于父资源**释放，
   否则组件模型报 `resource has children`。正确顺序：
   `pollable → input/output 流 → socket`。

### 效果（可量化）

**item 3 —— 空闲 CPU。** 用两点法测（3s 短跑与 33s 长跑之差 = 30 秒空闲开销），
以扣除 wasmtime 的 JIT 启动成本：

| 版本 | 3s 启动 | 33s | **30 秒空闲 CPU** |
|---|---|---|---|
| v0.2.0（1ms 轮询） | 0.281s | 0.514s | **0.233s**（约 0.78%） |
| v0.3.0（reactor 就绪） | 0.237s | 0.251s | **0.014s**（约 0.05%） |

**降低约 17 倍。** 这说明轮询确实去掉了 —— 空闲时进程阻塞在 pollable 上，不消耗 CPU。

**item 2 —— 非阻塞 connect。** 代码上从
`TcpStream::connect()`（阻塞）换成 `start_connect()` + pollable 等待；
`connect` 现在是 `async fn`，不再阻塞事件循环。

> 坦白说明：这一项的**端到端可观测收益难以构造独立实验** ——
> 所有连接都指向同一个服务端地址，所以「一个 connect 卡住而其它连接仍工作」
> 的场景需要两个不同的服务端地址才能演示。这里给出的是代码层证据（调用的是
> 非阻塞原语）与结构上的论证，不是像 item 3 那样的测量数据。

### 回归验证

换掉整个 socket 层之后：

| 检查 | 结果 |
|---|---|
| `cargo test --workspace` | **69 passed / 0 failed** |
| `./scripts/e2e-test.sh` | **8/8 通过**（含并发、半开连接、两个认证负向用例） |
| 协议层代码改动 | **0 行**（`xt-wasm-tls` / `xt-wasm-vless` 未动） |

---

## V18 · REALITY 服务端（入站）· 阶段 1：认证解密 + 证书伪造

### 背景

本工程此前只做客户端（socket → REALITY）。现在开始做反方向（REALITY → socket）。
按 README 里列的六项拆成阶段，**本阶段完成第 4 项（服务端侧认证）与证书伪造**，
这是 REALITY 特有、也最容易做错的部分；TLS 1.3 服务端握手与 VLESS 解码在后续阶段。

### 认证与客户端严格对称

```text
AuthKey = ECDH(server_privkey, 客户端 ClientHello 的 X25519 key_share)
AuthKey = HKDF-SHA256(ikm=AuthKey, salt=ClientHello.random[:20], info="REALITY")
明文    = AES-256-GCM.Open(
              nonce = ClientHello.random[20:32],
              ct    = ClientHello.session_id,
              aad   = **session_id 字段置零**的完整握手消息)
明文    = [版本(3)] [0] [unix 时间戳(4)] [shortId(8)]
```

**AAD 是最容易踩的坑**：两侧都必须用「session_id 被置零」的那份，而不是收到的原始字节。
客户端封的时候字段还是全零，服务端要是拿原始字节去开就必然失败。

### 跨实现验证（本阶段最有价值的证据）

只用自己的客户端测自己的服务端，只能证明「自洽」。所以额外抓了一份
**官方 Xray 客户端真实发出的 ClientHello** 作为夹具：

| 项 | 值 |
|---|---|
| 抓取方式 | 起裸 TCP 监听，让官方客户端连过来，抓第一条记录，去掉 5 字节 record 头 |
| 客户端配置 | `fingerprint: chrome`，`flow: xtls-rprx-vision` |
| 大小 | record 1792 字节 / 握手消息 **1787 字节** |
| 特征 | 带 GREASE；`key_share` 有**三份**：GREASE、X25519MLKEM768(1216B)、纯 X25519(32B) |
| 夹具私钥 | `[0x42;32]` 做 X25519 clamp（刻意构造的测试值，不保护任何东西） |
| 夹具文件 | `crates/xt-wasm-tls/src/testdata/xray-clienthello.hex` |

由此得到三条跨实现结论（都是自动化测试）：

1. `parses_official_xray_client_hello` —— 解析器吃得下 1787 字节的真实包；
   能从三份 key_share 里**挑出纯 X25519 那份**（MLKEM768 那份 1216 字节要跳过）。
2. `authenticates_official_xray_client_hello` —— **认证通过**，
   还原出 `shortId = deadbeef00112233`、`client_version = [26, 3, 27]`。
3. `forged_cert_for_official_client_hello_verifies` —— 基于官方客户端的
   AuthKey 伪造出的证书，能过我们自己客户端的校验逻辑。

> 附带确认了一个此前不确定的点：官方 chrome 指纹**同时**发纯 X25519 key_share，
> 所以服务端不需要实现 ML-KEM 也能取到共享密钥（MLKEM768 那份可以直接跳过）。

### 回环验证

`forged_certificate_passes_our_own_client_verifier` —— 服务端伪造的证书
（HMAC 冒充签名字段）被**本工程客户端的校验逻辑**接受；
换成别的 authKey 则必然失败（防中间人属性）。

### 负面用例

`rejects_wrong_server_key`（私钥不对 → session_id 解不开）、
`rejects_unknown_short_id`、`rejects_clock_skew_outside_window`、
`rejects_disallowed_sni`，以及 6 组畸形输入（解析器全程不 panic）。
另有一条专测 AAD 语义：断言 AAD 里 `[39..71]` 全零、其余字节与原始一致。

### 一个值得记下的测试自身缺陷

第一版用例给 `authenticate` 传了写死的 `now = 1_700_000_000`，
而 `build_reality_client_hello` 内部取的是 `SystemTime::now()` —— 相差 8900 万秒，
4 个用例全红。**这其实说明时钟窗口校验是对的**（它正确地拒绝了），
但用例本身失效了。改成取真实当前时间 + 容许跨秒边界。

### 当前状态

| 阶段 | 状态 |
|---|---|
| 4. 服务端侧 REALITY 认证解密 | ✅ **完成**（本阶段） |
| 证书伪造（含 X.509 DER） | ✅ **完成**（本阶段） |
| 1. TLS 1.3 服务端握手 | ⬜ 未开始 |
| 5. VLESS 服务端解码 + Vision | ⬜ 未开始 |
| 6. `dest` 回退 | ⬜ 未开始 |

---

## V19 · REALITY 服务端 · 阶段 2：TLS 1.3 服务端握手（官方客户端互通成功）

### 做了什么

在阶段 1（认证 + 证书伪造）之上补完 TLS 1.3 **服务端**握手：

```text
ServerHello（明文，回显客户端 session_id）
  → [EncryptedExtensions ‖ Certificate ‖ CertificateVerify ‖ Finished]（一条加密记录）
  → 读并校验客户端 Finished
  → 派生应用密钥
```

几个实现上的要点：

* **ServerHello 必须回显客户端的 `session_id`** —— 客户端会拿它跟自己发出去的比对。
* **应用密钥两侧都是用「到 server Finished 为止」的 transcript 派生的**（RFC 8446 §7.1），
  客户端的 Finished 不参与。所以服务端发完自己的 Finished 就能立刻派生密钥，不必等回话。
* 服务端的读写密钥与客户端**相反**：用 `server` 密钥写、`client` 密钥读。
  记录层直接复用了客户端的 `RealityTlsStream`（分帧、重放保护、半关闭逻辑两侧一样）。
* 要处理客户端可能发来的明文 **ChangeCipherSpec**（中间盒兼容），跳过它继续读。

### 自环验证

`our_client_completes_full_handshake_against_our_server`：
我们自己的客户端与自己的服务端在内存管道里完成完整握手，
并成功双向交换应用数据（证明两侧应用密钥一致）。

`wrong_key_client_falls_back_instead_of_erroring`：
错私钥的客户端连过来时服务端走 **dest 回退**（并带出已读的原始字节），
而不是报错断开 —— 报错会让探测者一眼看出这不是普通网站。

### 跨实现验证（本阶段的关键，也是踩坑的地方）

用 `crates/xt-wasm-tls/examples/reality_server_probe.rs` 起一个只做握手的服务端，
让**官方 Xray 客户端**连过来。第一次的结果是：

```
PROBE_ERR tls handshake: Reality server: 解密后的握手消息过短（2 字节，inner_type=21）
```

`inner_type=21` 是 alert，内容是 `02 2a` = fatal **bad_certificate** ——
**官方客户端拒绝了我们的证书**，而同样的证书我们自己的客户端却接受。

用 `openssl x509` 一看就清楚了：第一版为了省事，把 issuer / validity /
signatureAlgorithm 都写成了**空 SEQUENCE**：

```
SEQUENCE (sigAlg)   ← l=0  空
SEQUENCE (issuer)   ← l=0  空
SEQUENCE (validity) ← l=0  空
```

我们客户端的解析器只按位置取 SPKI（`children[base+5]`），所以能过；
而官方客户端用的是 Go 真正的 `x509.ParseCertificate`，空 Name / 空 Validity /
空 AlgorithmIdentifier 都不是合法 DER，解析失败就退回 CA 链校验，必然失败。

> **教训：能被自己解析 ≠ 是合法的编码。** 只对着自己的实现测，这类问题永远发现不了。

改成完整 X.509（v3 + serial + Ed25519 AlgorithmIdentifier + CN Name +
UTCTime 有效期 + SPKI）之后，`openssl x509` 能正常解析，
官方客户端也接受了。**最终结果**：

```
PROBE_AUTH_OK short_id=[de, ad, be, ef, 00, 11, 22, 33] client_ver=[26, 3, 27]
PROBE_APPDATA 512 bytes, head=00 b21e29c8a8ea40a2b953c2b04d73d775 12 0a10
                          78746c732d727072782d766973696f6e 01 01bb 02 0b 6578616d706c65
```

那段应用数据正是官方客户端发来的 **VLESS 请求头**，逐字段可读：

| 字节 | 含义 |
|---|---|
| `00` | VLESS 版本 |
| `b21e29c8a8ea40a2b953c2b04d73d775` | 用户 UUID |
| `12` / `0a 10` / `78746c732d727072782d766973696f6e` | addon：flow = **`xtls-rprx-vision`** |
| `01` | 命令 TCP |
| `01bb` | 端口 443 |
| `02` `0b` `6578616d706c652e636f6d` | 地址：域名 `example.com` |

也就是说官方客户端：**认可了 REALITY 认证** → **验证通过我们的 CertificateVerify
真签名并接受了证书** → **我们的服务端成功解密了应用数据**。

复现：

```sh
cargo run -p xt-wasm-tls --release --example reality_server_probe -- \
    4042424242424242424242424242424242424242424242424242424242424242 \
    deadbeef00112233 www.cloudflare.com 18450
```

### 阶段状态

| 阶段 | 状态 |
|---|---|
| 4. 服务端侧 REALITY 认证解密 | ✅ 完成 |
| 2. 每连接伪造临时 ed25519 证书 | ✅ 完成（**已修正为完整 X.509**） |
| 3. X.509 DER 编码 | ✅ 完成 |
| 1. TLS 1.3 服务端握手 | ✅ **完成**（本阶段，官方客户端互通通过） |
| 5. VLESS 服务端解码 + Vision | ⬜ 未开始 |
| 6. `dest` 回退 | ⬜ 未开始（回退**判定**已就位，转发未实现） |

---

## V20 · REALITY 服务端 · 阶段 5/6：VLESS 解码 + 转发 + dest 回退 —— **全链路打通**

### 做了什么

* **阶段 5（VLESS 服务端解码）**：`xt-wasm-vless/src/vless/server.rs`。
  与客户端的 `encode_request` 严格对称。
* **阶段 6（转发 + 回退）**：新增 `serve_inbound`，把两条路径都串起来：

```text
授权客户端：REALITY 握手 → 解 VLESS 头 → 校验 UUID → 连目标 → 双向转发
其他人    ：REALITY 握手失败 → 把已读字节补发给 dest → 双向转发
```

`relay_bidirectional` 从 `xt-wasm-cli` 上移到 `xt-wasm-runtime`（服务端也要用，
不该让协议层依赖 CLI）。

### 官方客户端 → 我们的服务端 → 真实网站（端到端）

```
官方客户端经我们的服务端访问真实网站：
  example.com  -> HTTP 200
  出口 IP: 45.207.197.185

我们服务端日志：
  OK Forwarded { target: "example.com:443" }
```

即：**官方 Xray 客户端经纯 Rust 实现的 REALITY 服务端成功代理到真实网站**。
复现见 `crates/xt-wasm-vless/examples/reality_server_full.rs`。

### 抗主动探测（REALITY 的根本）

用 `openssl s_client` 模拟一个**不带任何 REALITY 认证**的探测者，
直接对我们的服务端发起 TLS：

```
subject=CN=www.cloudflare.com
issuer=C=US, O=Let's Encrypt, CN=YE2
```

探测者拿到的是 **Cloudflare 的真证书** —— 它无法区分我们的服务器和真实的
Cloudflare 站点。这是 REALITY 区别于普通 TLS 代理的关键，也是「回退」这条路径
存在的全部意义。

### 集成测试抓出的三个问题（都值得记）

1. **服务端漏发 VLESS 响应头**。客户端建连后会先读 `[version][addon_len]` 两个字节，
   服务端不回的话它会把负载首字节当版本号 —— 症状是
   `version mismatch: expected 0x00, got 0x68`（`0x68` 正是负载首字符 `h`）。
2. **`new_deferred` 是延迟写头的**（设计如此：让请求搭上首个 Vision 帧），
   所以两条负面用例里客户端根本没把请求头发出去，服务端只看到 EOF。
3. **回退测试一度挂死**：回退路径下服务端什么都不回，客户端会永远等 ServerHello，
   握着连接不放，中继两端都不结束。加超时解决 —— 同一个教训在
   `xt-wasm-tls` 里也复现了一次（`Fallback` 开始把连接一并返回之后，
   原来靠 drop 触发 EOF 的用例就不再成立了）。

### 一个被明确拒绝而非默默做错的点

客户端请求 **Vision 流控**时，服务端会**明确报错**而不是继续。
Vision 会把负载包进填充帧，服务端不拆帧就会把这些字节当原始数据发给目标站 ——
输出是错的却不报错，属于最难排查的那类故障。
**Vision 服务端侧是目前唯一还没实现的协议部分**，见 README。

### 阶段状态

| 阶段 | 状态 |
|---|---|
| 4. 服务端侧 REALITY 认证解密 | ✅ 完成 |
| 2. 每连接伪造临时 ed25519 证书 | ✅ 完成 |
| 3. X.509 DER 编码 | ✅ 完成 |
| 1. TLS 1.3 服务端握手 | ✅ 完成 |
| 5. VLESS 服务端解码 | ✅ 完成 |
| 6. `dest` 回退 | ✅ 完成 |
| （额外）Vision 服务端流控 | ⬜ **未实现**（客户端请求时明确报错） |

---

## V21 · 服务端 CLI（`server` 子命令）+ k3s 交付

V20 打通的是**库**层（`serve_inbound`）。V21 把它变成可部署的东西：
`xt-wasm-cli server`，以及给 k3s 用的清单。

### 为什么要做成子命令而不是新二进制

同一个镜像、同一个 tag 跑两种角色，产物只有一份。k8s 里靠 `args: ["server"]`
切换（镜像 ENTRYPOINT 是 exec 形式且以 wasm 路径结尾，args 会追加成 guest 的 argv）。
多一个镜像就意味着多一份要同步签名、扫描、拉取的东西，而两者共享 100% 的
协议代码与依赖树。

### 实测输出（两个方向都通过）

```
$ ./scripts/e2e-server-test.sh
==> 0/5 生成一套全新凭据
  ✓ privateKey/publicKey/shortId/uuid 已生成
==> 1/5 启动 wasm 服务端（server 子命令 + 环境变量传 Secret）
  ✓ 服务端已监听 127.0.0.1:9443
==> 2/5 stock Xray 客户端（flow 必须留空）→ 经隧道取页面
  ✓ https://example.com -> 200
==> 3/5 服务端确实做了转发（而不是退化成了直连）
  ✓ 服务端日志：认证通过 user=2226339e-… -> example.com:443
==> 4/5 抗探测：未认证的 TLS 探测者必须看到 dest 的真实证书
  ✓ 探测者看到 dest 的真实证书（CN=www.cloudflare.com, EC），伪造证书没有泄漏
==> 5/5 认证确实在生效：REALITY 过了但 UUID 不在名单里，必须被拒
  ✓ 错误 UUID 被拒（服务端日志：失败：proxy authentication failed）
```

第 5 条刻意与第 4 条分开：它们测的**不是同一件事**。

* 第 4 条：REALITY 认证就没过 → 回退到 dest（探测者待遇）。
* 第 5 条：REALITY 认证**过了**（客户端持有正确的 publicKey + shortId），
  但 UUID 不在名单里 → 必须明确报错。

这正是「有密钥 ≠ 有权限」的分界。合并成一条会漏掉后者。

### 三个在设计时才发现的问题

**1. 日志只在连接结束时才写，等于没有日志。**

`serve_inbound` 返回 `InboundOutcome` 要等整条连接结束。长连接可能挂几小时，
于是服务端的日志形态是「连接断开时才知道曾经连上过」。测试也只能靠 `sleep` 猜时机。

修法不是「在 CLI 里多打一行」——判定发生在库层内部。新增了
`serve_inbound_with_events(stream, cfg, on_event)`，在**做出判定的当下**
（认证通过 / 走回退）回调，此时还没转发任何字节。`serve_inbound` 变成它的空回调包装，
对外 API 不变。

时序由单测钉住，且断言不是「事件有没有发出去」（太弱），而是
**客户端全程不读回包、只等事件出现**：如果事件是转发结束后才发的，
双向转发会一直卡着，事件永远不出现 → 超时失败。

**2. 空连接被记成错误 → k8s 探针每 10 秒刷一行。**

`tcpSocket` 探针连上就关。原来这会在 REALITY 握手的第一读就
`Err(Tls("还没读到 ClientHello 连接就断了"))`。公网端口上，探针/扫描器/LB 健康检查
是**最频繁**的事件；把它记为错误，等于每天 8000+ 行噪音，真故障会被淹掉。

而且当时只能靠**字符串匹配**来静音，总会有调用方忘掉。所以改成了类型：

* `TransportError::EmptyConnection`（新增变体）；
* `InboundOutcome::EmptyConnection`（新增变体，**是 `Ok` 不是 `Err`**）；
* CLI 对该分支静默，并在单测里钉住「空连接是 outcome 不是 error」。

**3. k8s 清单和源码的变量名会静默漂移。**

清单里写 `XT_PRIVATEKEYS`（少个下划线）→ Secret 挂上了、Pod 起来了、
服务端起不来，而 `kubectl` 一切正常。YAML 语法检查抓不到。

新增 check 9：把 `deploy/k8s/*.yaml` 里出现的所有 `XT_*` 与
`crates/*/src/` 里实际读取的名字对起来。反向不检查（源码里的可选变量不必都进清单）。
已用「改一个字母」验证过它确实会红。

### 另外两个被固化成检查的教训

* **check 8**：shell 里 `"…（uuid $UUID）"` —— 变量名后面紧跟全角字符时，
  `/bin/sh` 会把多字节字符当成变量名的一部分 → `UUID）: unbound variable`。
  这个坑在本仓库踩过**两次**（e2e-test.sh、e2e-server-test.sh），
  所以固化成规则：变量后跟非 ASCII 就必须写 `${VAR}`。
  实现时必须排除注释行 —— 解释这个坑本身就要在注释里写出反例
  （与 check 7 排除注释是同一个教训）。
* **CI 抓到了本地一定看不到的可移植性问题**：抗探测那一步第一版去 grep
  openssl 的人类可读输出（`a:PKEY: EC`），本地（macOS / LibreSSL）绿，
  CI（Ubuntu / OpenSSL 3）直接红 —— 两边的排版不同：

  ```
  macOS：  s:CN=www.cloudflare.com      a:PKEY: EC, (prime256v1)
  Ubuntu： s:CN = www.cloudflare.com    a:PKEY: id-ecPublicKey, 256 (bit)
  ```

  改成把证书取出来交给 `openssl x509 -nameopt RFC2253` / `openssl pkey -text`
  做**结构化**判定。教训：断言不要去解析人类可读输出，哪怕它「看起来一样」。

* **发版顺序：先发公告再验证是错的。** 原来的 `release.yml` 在 `wasm` job 里
  建完 Release 才去建镜像 —— 镜像那一步失败时 Release 已经发出去了，而 README
  和 k8s 清单都在让用户去拉那个镜像。改成三个 job 串起来：

  ```
  verify → wasm（只产出并上传产物）→ image（先本地 load 单架构冒烟，再多架构推送）
                                      ↘ release（needs 两者，创建 Release）
  ```

  冒烟本身也值得存在：ENTRYPOINT 是 exec 形式且以 wasm 路径结尾，
  `args: ["server"]` 能不能真的变成 guest 的 `argv[1]` 是**整条交付里最容易
  静默出错的一环** —— 错了的话镜像「能构建、能启动」，但 k8s 里的服务端会
  静默跑成客户端。现在三种调用方式（无参数 / `server` / `XT_MODE=server`）
  在发版时各断言一次。

* **e2e 里的公网抖动要显式重试而不是静默**：本机实测遇到过一次
  「服务端已记下认证通过，但 curl 侧没等到响应」。现在允许 3 次尝试，
  但**把重试次数打印出来** —— 悄悄重试会掩盖真实的间歇性故障，
  而那正是端到端测试最该抓的东西。

---

## V22 · 对交付文档里两处事实性断言的复查（一处被推翻）

V21 之后我在两份 README 里写过两个关于**外部世界**的断言。
复查下来一个被推翻，一个只能降级为「未找到反例」。记在这里，因为
「怎么知道的」和结论本身同样重要。

### 被推翻的：「crates.io 上没有可用的 REALITY 服务端 crate」

**错的。** [`shoes`](https://github.com/cfal/shoes) 是 Rust 多协议代理**服务端**，
就在 crates.io 上，含完整 REALITY 入站：

```
src/reality/reality_server_connection.rs
src/reality/reality_server_handler.rs
src/reality/reality_certificate.rs
src/reality/reality_auth.rs
examples/reality_basic.yaml          ← 服务端配置示例，含 min_client_version/max_client_version
```

另有 `undead-undead/xray-lite` 等 Rust 实现。所以「本工程是唯一的非 Go REALITY 服务端」
不成立，**已从 README 删除并改写**。

**错误是怎么产生的**（比错误本身更值得记）：当时的依据只有两条 ——
crates.io 关键词搜索，加上采信 `meow-rs` 自己的 "no server-side features" 声明。
然后「我没搜到」被当成了「不存在」，并且在后续总结里语气还加强了一档。

这与本项目反复强调的 **「能被自己解析 ≠ 是合法的编码」**（V19）是**同一个错误形状**，
只是对象从「我的解析器」换成了「我的检索」。教训：

> **在自己的检索范围内找不到 ≠ 不存在。**
> 负向断言（「没有 X」）需要写出**检索方法和它的边界**，否则它不可复核。

### 被降级的：「REALITY 的第二个实现带来了一批此前无法证伪的协议结论」

四条发现逐条复查后，**没有一条够得上「此前无法证伪」**：

| 发现 | 实际来源 | 复查结论 |
|---|---|---|
| 纯 X25519 被接受、不需要 ML-KEM | 实测服务端日志 | **已知**。`shoes` 同样用纯 X25519 |
| server flight 合并进一条记录 | 调试 10 秒超时 | **是 meow-rs 的实现 bug**，不是协议发现：RFC 8446 本来就允许合并，正确的 reader 不该假设一消息一记录 |
| 服务端确实校验 `ClientVer` | 读 `xtls/reality` 源码 | 断言确实错了，但**源码里写着**，且 `shoes` 把 `min_client_version` 直接暴露成配置项 |
| 伪造证书必须是结构完整的 X.509 | 官方客户端回 `bad_certificate`（`02 2a`） | 四条里最接近真发现的一条，但 `shoes` 有 `reality_certificate.rs`，至少有第二个人处理过 |

四条事实本身仍然**真实且可复现**，作为工程记录有价值。但「独立实现」这个职能
生态里早有 Go 的 Xray/sing-box/mihomo 与 Rust 的 shoes/meow-rs/xray-lite 在提供，
本工程没有给这一项增加什么。

### 复查中的副产品：`shortIds: [""]` 的语义被生态文档写错了

从**权威源码**核实（两处，交叉验证）：

```go
// Xray-core transport/internet/reality/config.go:54
config.ShortIds = make(map[[8]byte]bool)
for _, shortId := range c.ShortIds {
    config.ShortIds[*(*[8]byte)(shortId)] = true   // 字符串零填充成 8 字节当 key
}

// XTLS/REALITY tls.go:270（服务端认证判定）
(config.ShortIds[hs.c.ClientShortId])              // 就是一次 map 查找
```

`shortIds` 是**一组 8 字节值**，不是开关。所以 `shortIds: [""]` 注册的是全零 key，
含义是「接受 shortId 为空的客户端」，**不是**「放行所有客户端」。

而 `shoes` 的 `examples/reality_basic.yaml` 里写着
`# Empty string "" allows all clients (less secure but convenient)` ——
按上面源码，这句话不准确。

**对本工程的实际影响**（已写进 README 的已知限制）：`XT_SHORT_IDS` 的逗号切分会丢掉空项，
因此**没法注册那个全零 key**，含 `shortIds: [""]` 的 Xray 配置迁移过来会拒绝启动。
已实测三种输入确认行为：`""` 拒绝、`","` 拒绝、`"0011223344556677,,aabbccdd"` 正常启动（空项被丢弃）。

这是刻意的取舍（全零 shortId 意味着任何知道公钥的人都能通过 REALITY 认证），
但它是**与 stock Xray 的功能差异**，此前没写下来，现在写了。

---

## V23 · 自环互通（wasm↔wasm）+ 可诊断性 —— 途中挖出一个连接泄漏

工单要求五件事：客户端 `--no-flow`、解析/连接失败可分辨、非 TCP 拒绝可执行、
服务端一行日志、`--check` 自检。做第 4 条（一行日志）时**挖出一个真 bug**，
而且正是它让第 4 条一开始根本不工作。

### 先说 bug：半关闭是个空实现，每条连接都泄漏

`InboundOutcome` 原本只在连接**结束**时返回。把日志改成「结束时写一行」之后，
日志一行都不出。查下去发现中继**永远不返回**：

```
服务端 socket：127.0.0.1:9444->…  ESTABLISHED   ← 客户端侧一直不关
             198.18.0.1:…->104.20.23.154:443  CLOSE_WAIT  ← 目标已发 FIN，我们没关
```

根因在 `crates/xt-wasm-runtime/src/wasi.rs`：

```rust
fn shutdown_write(&self) -> io::Result<()> {
    Ok(())          // ← 空实现
}
```

`relay_bidirectional` 的收尾完全依赖它：某个方向读到 EOF 后 `shutdown` 对端写方向，
让对端知道「我说完了」。空实现 ⇒ FIN 永远发不出去 ⇒ 对端读不到 EOF ⇒
另一个方向永远挂着 ⇒ 中继不返回。

后果比「日志不出现」严重得多：

* 每条连接在服务端留下一个不回收的 socket（目标侧 `CLOSE_WAIT` + 客户端侧 `ESTABLISHED`），
  **请求照样 200，所以没人会发现** —— 长跑就是 fd 泄漏；
* 此前所有 e2e 都测不出它，因为它们断言的是「判定发生时」的那行日志。
  改成「结束时」才写，它立刻现形。

修法是用 WASI 的底层调用（`OutputStream` 没有 shutdown）：

```rust
self.socket.shutdown(ShutdownType::Send).map_err(wasi_err)
```

修复后实测：**3 次请求 → 3 行 `outcome=Forwarded`，残留连接 0**（修复前是 3+3）。
`scripts/e2e-wasm-to-wasm-test.sh` 里加了回归守卫：
「N 次请求必须写出 N 行结局」，半关闭一旦退化就会红。

> 教训：**「连接结束时写日志」这个改动本身就是个探针。**
> 原先「判定时就写」的设计让一个连接泄漏 bug 藏了很久 —— 日志写得越早，
> 越掩盖「收尾有没有走完」这件事。

### 一行日志（工单第 4 条）

```
[server] ts=2026-09-15T11:41:12Z dir=in src=127.0.0.1:50388 sni=www.cloudflare.com \
         ver=26.3.27 sid=2c3d58a3c703d187 target=example.com:443 outcome=Forwarded \
         dur_ms=1320 up_bytes=585 down_bytes=4867
```

`outcome ∈ {Forwarded, FellBack, Rejected, ResolveFailed, ConnectFailed}`，
外加 `Error`（服务端自身出错）。前五个都是 **`Ok`**：服务端正常处理完了这条连接，
包括它决定拒绝或连不上目标；`Err` 只剩「服务端坏了」一种含义。

两处刻意的设计：

* **`Rejected` / `ResolveFailed` / `ConnectFailed` 从 `Err` 改成 `Ok`。**
  否则调用方只能靠字符串匹配去猜发生了什么 —— 而 V21 已经为「空连接」踩过一次
  同样的坑。`InboundReport` 承载上下文（sni/ver/sid/target/字节数），`InboundOutcome`
  只承载分类。
* **网络来源字段一律转义。** `sni`/`target` 是对端可控的字节；不转义的话，
  在 SNI 里塞一个换行就能在日志里伪造出一条 `outcome=Forwarded`。
  单测 `hostile_sni_cannot_inject_a_log_line` 钉住。

### 解析与连接分开（工单第 2 条）—— 上线当天就派上用场

拆成 `resolve()` / `connect()` 之后，实测立刻抓到一次失败：

```
outcome=ResolveFailed reason="解析目标 example.com:443 失败：
  failed to lookup address information: Name does not resolve…" dur_ms=30012
```

30 秒整。而**宿主上 `nslookup example.com` 是 59ms，guest 里用最小探针
（`wasm32-wasip2` 直接 `to_socket_addrs`）也是 4ms**。所以这是一次**瞬时的解析器故障**：
几分钟后自行恢复，同样的命令全部通过。

它同时暴露了我第一版提示文案的错误：我写的是「若 wasmtime 报 PermissionDenied，
检查是否漏了 `-S allow-ip-name-lookup=y`」—— 而这次根本不是权限问题，
那个 flag 本来就传了。**照着那句话去改，只会去动一个无关的开关。**
现在按错误类型分成两句不同的话（单测
`resolve_failure_hint_distinguishes_the_two_real_causes` 钉住）：

| 现象 | 含义 | 该做什么 |
|---|---|---|
| `Permission denied` | 宿主没给 `ip-name-lookup` 能力 | 加 `-S allow-ip-name-lookup=y` |
| `Name does not resolve` / 卡满 30 秒 | 解析器没作答 | **加 flag 无效**；查宿主/容器 DNS，或改用 IP 字面量 |

### 两个平台层面的坑（已写进 README）

**1. wasmtime 把 guest 退出码塌缩成 1。** 实测：

```
guest exit(0) -> 0    guest exit(1) -> 1
guest exit(2) -> 1    guest exit(42) -> 1
```

工单要求 `--check` 用「0 通过 / 2 失败」便于 k8s 断言。代码里仍然是
`exit(2)`（宿主二进制上实测就是 2），但**在 wasmtime 下只能观察到 0 / 非 0**。
e2e 因此断言「非 0」而不是「恰好 2」，并在注释里写明原因 ——
写成 `== 2` 的检查会在宿主上过、在 CI/容器里必红。

**2. `--no-flow` 必须同时关掉 flow 声明和客户端侧 Vision 分帧。**

只把请求头里的 flow 置空、却仍然包 `VisionConn`，会把 Vision 的**填充帧**
当成普通数据发给一个不做拆帧的服务端 —— 症状是「连上了但数据是坏的」，
属于最难查的那类故障。所以 `open_tunnel` 里这两件事由同一个 `no_flow` 决定。

单测 `no_flow_changes_what_the_server_actually_reads` 走**真 socket + 真 REALITY 握手**，
断言的是**服务端实际读到的字节**（用服务端给出的 outcome 反推）：
默认 → `Rejected{…Vision…}`；`--no-flow` → 放行到连目标那一步。
只测内部布尔量的写法抓不住「只关一半」。

### 结果

| 项目 | 结果 |
|---|---|
| 单测 | 100 → **109**（cli 24 / runtime 8 / tls 37 / vless 40） |
| `./scripts/check.sh` | 9 项全绿 |
| `./scripts/e2e-test.sh` | wasm 客户端 → stock 服务端 ✅ |
| `./scripts/e2e-server-test.sh` | stock 客户端 → wasm 服务端 ✅ |
| `./scripts/e2e-wasm-to-wasm-test.sh` | wasm `--no-flow` → wasm 服务端 ✅（新增，含半关闭回归守卫） |

---

## V24 · 生产故障：服务端跑起来后永久自旋、CPU 打满一核（**根因未定位**）

这是线上 `home` 入口（k3s 里的翻墙入口）真实宕机后追出来的。**没有修好**，
把证据和已排除项留在这里，避免下一个人重复走这几步。

### 现象

```
home pod:  0/1 Running   CPU 1000m（同节点其它 pod 都是 1m）
endpoints/home:  <空>            ← Service 没有就绪后端
事件: Readiness probe failed: dial tcp …:8443: i/o timeout
日志冻住 48 分钟，一行没有；socket 562 个不释放
公网 openssl → NodePort: TCP 连上但无任何响应
```

任何客户端（Shadowrocket / 官方 xray）都连不上。**不是客户端配置问题**
（flow/Vision 被拒只出现 1 次）。

### 在节点上复现（决定性）

300 条并发连接打一个「连不上、要等超时」的目标：

```
空闲基线        3 秒 0 ticks        ← 空闲完全正常，极易误判「没 bug」
灌入后          5 秒 501 ticks      ← 一核 100%
+35s … +210s    一直 501 ticks      ← 永不恢复；日志冻住；socket 不释放
```

**只在「已经来过至少一次事件」之后才出现**，所以任何「起服务、发一个请求、
看着正常」的验证都发现不了它。单线程协作式运行时里这个忙等会把 accept 循环
一起饿死 —— 这就是对外表现为「TCP 连不上」的机制。

### v0.4.0 vs v0.5.0（实测，同一驱动）

| | v0.4.0 | v0.5.0 |
|---|---|---|
| 连接泄漏（半关闭空实现） | 每条都泄漏；**第 256 条后彻底死**（`认证通过=256`、`完成=0`） | **已修**：300/300 完成、连接正常回收 |
| 启动后自旋 | 有 | **仍然有** |

所以 V23 那个 `shutdown_write` 修复是**真的、必要的，但不充分** —— 它治的是泄漏，
不是自旋。

### 已定位到哪一步 / 已排除什么

插桩（按数量级打印）跑同一复现：

```
Ready::poll 调用        = 2,610,000
poll_read 循环顶        = 2,610,000     ← 与上一个完全相等
poll_read 空读分支      = 3
poll_write 走 Ok(0)     = 0
poll_flush              = 3
accept() 进入           = 3
```

即：**`poll_read` 被反复调用 261 万次，而每次都在 `read_ready.poll` 那一步返回**
（空读分支只进了 3 次）。也就是**等待报 Pending、任务却立刻被重新轮询**。
`accept` 与写路径都排除了。

**已证伪的两个假设（都实测过，别重试）：**

1. `NetStream` 的 `Ready` 把 `AsyncPollable` 缓存在 `OnceLock` 里永久复用 ⇒
   改成「每次消费就绪后重新订阅」—— **无效**，自旋照旧。
2. `poll_read` 的 `Ok(empty) => continue` 忙等 ⇒ 改成「重新订阅后仍立刻就绪即判 EOF」——
   **无效**；而且这个改法有**截断数据流**的风险，已回滚，没有留在代码里。

代码已回滚到 v0.5.0 状态（只保留 `shutdown_write` 修复），未验证的改动一律不留。

### 顺带修掉的：`connect()` 没有总超时（这个是确定性问题）

一个域名会解析出十几个地址（实测 `www.google.com` = 8×IPv4 + 8×IPv6），
原实现**顺序**试、每个各自超时。目标端口被丢包时（不回 RST），
一条请求要 **1080 秒（18 分钟）** 才失败，而这 18 分钟一直占着并发槽位（上限 256）：

```
修复前: dur_ms=1080453
修复后: dur_ms=10009     ← 16 个地址试了 4 个，10 秒预算到点就放弃
```

并发一高，槽位就会被这些「慢慢失败」的连接占满。加总预算后，宁可快速失败让客户端重试，
也不让一条连接把服务端拖死。

### 运维侧的缺口（独立于代码）

翻墙入口的 Deployment **只有 readiness、没有 liveness** —— 自旋之后
kubelet 永远不会重启它，服务**无法自愈**（线上就是这么挂了 48 分钟）。
在自旋修好之前，`livenessProbe` 是必须的止血手段：

```yaml
livenessProbe:
  tcpSocket: { port: 8443 }
  periodSeconds: 20
  timeoutSeconds: 3
  failureThreshold: 3
```

### 还没做的

* **自旋的根因**：还没找到。线索是「等待报 Pending 但任务立刻被重轮询」，
  下一步应该往 `wstd` 的 reactor/waker 注册去看（`Reactor::ready` 每次问活的
  `pollable.ready()`，那就意味着 waker 被立刻唤醒或者根本没人 park）。
  建议做法：加一个「同一个 poll 循环 1 秒内迭代 >N 次就打印调用点」的看门狗。
* `connect()` 的地址顺序/并发（现在只是 IPv4 优先 + 限时）。

### V24 续：一刀切开「我们的代码 / 运行时」——自旋的确切触发条件

按「先做最小复现器、再改代码」的顺序做的。**四组都是节点上实测**：

| 场景 | 5 秒 CPU 增量 |
|---|---|
| 最小复现器 #1：**纯 wstd**，accept 后挂起 `read`（300 条） | **0 ticks** |
| 最小复现器 #3：**纯 wstd**，accept 后挂起 `connect` 到不可达地址（300 条） | **0 ticks** |
| 我们的服务端：**快路径**（握手 + 中继，300 条全部 `Forwarded`） | **1 tick** |
| 我们的服务端：300 条**卡在 `connect`**（握手已完成，目标不可达） | **501 ticks = 一核，永不恢复** |

结论：

1. **不是 `wstd` / `wasmtime` 的问题。** 两个纯 wstd 复现器（读挂起、connect 挂起）
   都不自旋 —— 所以「升 wstd / 升 wasmtime / 提 issue」这条路可以直接划掉，
   省掉了本来会先走的几步。
2. **也不是「只要跑连接就自旋」。** 我们的服务端跑完 300 条完整快路径，CPU 几乎为零。
3. **触发条件是两者的交集**：**我们的 `NetStream`（已跑完 REALITY 握手、被大量读写过）
   被留在挂起状态，且数量多。** 纯 wstd 的流没有这个"被用过再挂起"的历史；
   快路径的流则全部正常收尾并被回收。

**这解释了我前面两次改错的根本原因**：我在「切开我们的代码与运行时」之前就动了代码。
两个改动（`Ready` 重订阅、空读判 EOF）和一次中继改动都已回滚，未验证的东西一律没留。

**下一步（已很具体）**：给 `Ready` 加「注册/注销计数」——
每次 `WaitFor` 创建 +1、Drop -1，周期性打印存活数。
如果这个数在挂起期间**单调增长且不回落**，就是 waker 注册泄漏：
reactor 里留着已失效的 waker，`poll_oneoff` 每轮立刻返回 ⇒ 忙等。
那修法就在 `NetStream` 的 Drop 顺序 / `WaitFor` 的注销时机上，而不是在读或写逻辑里。

### V24 再续：上一条的结论有两处是错的（实测推翻）

加了「存活 `WaitFor` 注册数」探针后重跑同一复现，结果与上一条**矛盾**，以下更正：

**错误 1：那些连接并没有「卡在 `connect`」。**
日志里 10 条全是 `Rejected: VLESS 请求头解析失败：IO error: early eof` —— 驱动脚本只做 SOCKS 握手、不发数据就关闭，
所以连接**死在读 VLESS 请求头那一步**，根本没走到 `connect(10.255.255.1:5222)`。
所以「触发条件是 connect 挂起」这个说法不成立。

**错误 2：这一轮自旋时 `Ready::poll` 根本不是热路径。**
探针每 20 万次打一行，这次**一行都没有**（< 20 万次），而上一轮同一复现测到 2,610,000 次。
两者对不上 ⇒ 我之前那个「`poll_read` 被反复轮询 261 万次」的定位**不能代表这个自旋**，
至少不是唯一的自旋形态。

仍然成立的（四组对照未受影响）：

| 场景 | CPU |
|---|---|
| 纯 wstd + 挂起 read | 0 |
| 纯 wstd + 挂起 connect | 0 |
| 我们的服务端 + 快路径（300 条全完成） | ~0 |
| 我们的服务端 + 这批「握手后死在读头」的连接 | 一核，永不恢复 |

**结论：不是 wstd/wasmtime，是我们自己的代码** —— 这条不变。
但**具体在哪个循环，目前仍然没有可靠定位**；我给出的第一个定位（`Ready::poll`）已被本次实测推翻。

下一步应该先做**冷热判定**，而不是继续猜循环：
在 `Ready::poll`、`poll_read` 循环顶、`poll_write`、`accept`、`spawn_task`、以及
wstd 的 `block_on` 外层各放一个「每秒采样一次并打印增量」的看门狗，
一次跑出「到底哪个计数器在涨」。只有先确认热路径，后面的修改才有意义。

### V24 三续：看门狗给出的冷热判定（**这是目前最可靠的一条定位**）

改用「时间门控看门狗」——由热路径自己驱动、每秒汇总一次，避免定时任务在紧循环里
永远没机会跑：

```
[WD] read_top=20480          ← 连续 200+ 秒，每秒正好 20480 次
[WD] write=50 flush=48 accept=160 spawn_task=159 accept_loop=159   ← 只在开头出现
read_empty ≈ 26（全程）
```

结论：

* **热路径唯一是 `poll_read` 的循环。** 写路径、`accept`、`spawn_task`、accept 循环
  **全部排除**（首秒之后就归零）。
* `read_empty` 全程只有 26 ⇒ **`input.read()` 几乎没被调用过** ⇒ 绝大多数轮询都停在
  `read_ready.poll` 那一步并返回 `Pending`。
* 也就是说：**这个连接任务的 future 在被以 ~20,480 Hz 重新轮询，而它每次都诚实地
  回答「还没就绪」。** 所以缺陷不在读逻辑本身（`poll_read` 的行为是对的），
  而在**是谁在不停地唤醒它** —— waker / reactor 那一侧。

修正一处：`probe::hit(0)`（`Ready::poll`）这次**没插进去**（替换没匹配上），
所以上面没有 `Ready::poll` 这一行；但 `poll_read` 循环顶紧接着就调用 `Ready::poll`，
两者必然同量级。

**至此可以确定的两件事**（都已实测）：

1. 不是 `wstd` / `wasmtime`（两个纯 wstd 复现器都是 0 ticks）。
2. 热循环是 `poll_read` 的就绪等待，**任务被 ~20kHz 虚假唤醒**；不是读逻辑、不是写路径、不是 accept。

**下一步**：给 `Ready::poll` 加「Pending / Ready 各多少次」的双计数。
若 Pending 占绝对多数却仍被高频重轮询，就证明唤醒来自**我们这个 pollable 之外**
（例如同进程里另一个 pollable 的事件 wake 到了共用 waker），
那就要往 wstd reactor 的 `wakers` 映射与 `ready_list` 去查 —— 而不是再动协议代码。

### V24 四续：**决定性结果 —— 就绪轮询一直返回 READY**（上一个假设被推翻）

Pending/Ready 双计数，同一复现，自旋稳定段：

```
[WD] Ready::poll=20480  read_top=20480  ready_got_READY=20480
[WD] Ready::poll=20480  read_top=20480  ready_got_READY=20480      ← 连续稳定
```

* `ready_got_READY` = 20,480 次/秒 ⇒ **每一次就绪轮询都返回就绪**。
* `ready_got_pending` = **0**（从未打印）。
* `waitfor_created` = 0（从未打印）⇒ `WaitFor` 只建了一次就被跨 poll 复用。

**这推翻了我上一条的假设**（「任务被虚假唤醒、而 pollable 说没就绪」）。
真相相反：**我们缓存的 `AsyncPollable` 一直报就绪，所以 `Ready::poll` 立刻返回 Ready，
`poll_read` 的循环于是空转。**

机制现在完全说得通了：WASI 的 pollable 是**一次就绪后持续就绪**（除非重新 `subscribe`）。
我们在 `OnceLock` 里把它缓存成一辈子一颗，所以：

* 空闲时它还没触发过 ⇒ 不报就绪 ⇒ CPU 0（这就是「只有来过事件之后才发作」的原因）；
* 第一次事件之后它永久报就绪 ⇒ `Ready::poll` 立刻返回 ⇒ 上层重试 ⇒ 立刻又返回 ⇒
  20,480 Hz 忙等，永不恢复。

**注意这和我第二次尝试的改动是同一件事** —— 那次没生效，是因为我**同时**改了空读逻辑
（`resubscribe` + 判 EOF 两处一起上），两个改动互相掩盖，无法归因。
正确做法是**只改这一处**再测。

**待验证的一个探针**：`read_empty` 这次没打印（`probe::hit(2)` 的锚点可能又没匹配上）。
若 `Ready::poll` 一直 Ready 而 `read_empty` 仍为 0，说明 `input.read()` 返回的是数据或
错误而不是空 —— 这一点需要在下一轮一并确认，它会决定修法是「重新订阅」还是「换判据」。

### V24 五续：**按实测机制写的修复没有生效**（负面结果，如实记录）

按上一条的机制（「缓存 pollable 一次就绪后持续报就绪」）写了修复：
`Ready` 不再用 `OnceLock` 永久缓存，改为**消费掉就绪就丢弃订阅、下次重新 `subscribe()`**。

实测（同一复现）：

```
灌入期间 5 秒增量 = 501 ticks
+35s / +105s / +210s: 一直是 501 ticks   ← 与修复前完全一样
```

**没修好。** 说明下面两者至少有一个成立：

1. **机制不是（唯一）原因**：即使每次都用**新鲜**的 `subscribe()`，pollable 依然立刻报就绪
   ⇒ 底层流本身在被读空之后仍持续报告「可读」。
2. **修复没达到预期**：需要**在修复版上再跑一次双计数探针**，看
   `ready_got_READY` 是否从 20,480/s 掉下来。没掉 ⇒ 是第 1 种；掉了却仍自旋 ⇒
   是另一个循环（那就要重做冷热判定）。

**下一步就这一条**（不要再改代码）：修复 + 双计数探针一起跑，用同一个复现。
这一步能把「机制对不对」和「修复有没有效」分开，避免我再犯
「一次改两处、然后把结论下反」的错误（V24 四续里已经犯过一次）。

**一个未核实的细节**：上一轮的 `read_empty` 探针（`probe::hit(2)`）很可能又没插进去
（只 grep 到计数 1，没核对锚点文本）。若它确实没插进去，那么「`input.read()` 一直返回
空」这个判断目前**只有间接证据**（`ready_got_READY` 一直就绪 + 循环停在 `read_top`）。
下一轮必须把它和双计数一起确认。

代码已回滚，未验证的改动一律没留。

### V24 六续：**我上一轮的"决定性结论"是错的 —— 探针标签写错了，把语义弄反了**

`probe::hit(11)` 打在 **`Poll::Pending` 分支**里，而我在 `NAMES[11]` 写的是
`"ready_got_READY"`。**标签与语义错位**，于是日志里那行
`ready_got_READY=20480` 的真实含义是：

> **每秒 20,480 次返回 `Pending`。**

所以 V24 四续里那句「每一次就绪轮询都返回 READY ⇒ 我们的 pollable 一直报就绪」
**是错的**，机制判断整个反了。正确的是**最早那个假设**：

* `ready_*` 里显示的是 **Pending** 计数 = 20,480/秒；
* `Ready` 分支的计数**从未出现** ⇒ 从来没有就绪过；
* `waitfor_created` 从未出现 ⇒ `WaitFor` 只建一次、被跨 poll 复用（因为一直 Pending）；
* `subscribe_new` 从未出现 ⇒ 我那个「消费就绪后丢弃订阅」的修复**在这个场景里根本没被执行**——
  因为它只在 `Poll::Ready` 分支里，而这条路径永远不返回 Ready。

**结论回到原点、但这次是干净的**：

> 任务的 future 被以 ~20,480 Hz 重新轮询，而它的就绪等待**每次都诚实地返回 Pending**。
> 所以缺陷在**唤醒方**（waker / reactor），不在订阅管理、不在读逻辑。

**这也解释了为什么那个修复无效**：它是一段**在这个场景里不可达的代码**。

**教训（写给下一个人，也写给我自己）**：
探针的**名字必须和它所在的分支一起核对**，不能只核对「有没有插进去」。
我上一轮已经吃过一次「只 grep 计数、没核对落点文本」的亏，这次又栽在
「落点对了、但名字写反了」上 —— 而且它把一个结论完整地颠倒了过来，
害我白走了一轮。**日志字段名本身就是结论的一部分，必须和代码分支一起 review。**

### V24 七续：实验 —— `WaitFor` 在 Pending 后丢弃重建（**无效**）

**这次只改了一处**（前几轮的教训：一次改两处会互相掩盖）。

改动：`Ready::poll` 的 `Poll::Pending` 分支里把 `WaitFor` 也丢弃（`ws.take()`），
下次重新 `wait_for()` 建一个，而不是跨 poll 复用同一个。

假设：复用时同一个 waitee 的 waker 被反复覆盖，reactor 里可能留下失效/重复注册 ⇒ 忙等。

实测（`scripts/e2e-spin-test.sh`，同一判据）：

```
空闲增量 = 0 ticks
悬停增量 = 500 ticks      ← 与改动前（501）没有区别
✗ 忙等
```

**无效。** 已回滚。

## 至此已经排除的（全部实测，别再重试）

| # | 假设 | 结果 |
|---|---|---|
| 1 | `Ready` 用 `OnceLock` 永久复用 pollable | 无效 |
| 2 | 空读 `continue` 忙等 ⇒ 改判 EOF | 无效（且有截断风险） |
| 3 | `tokio::io::split` + `join!` 共用 task waker | 无效（且该复现里 relay 根本没跑） |
| 4 | 消费就绪后丢弃订阅（每条流每次重新 subscribe） | **不可达代码**（该路径从不返回 Ready） |
| 5 | `WaitFor` 在 Pending 后丢弃重建 | 无效 |
| — | wstd / wasmtime 本身 | **不是**（两个纯 wstd 复现器都是 0 ticks） |

## 现在**确定**的事实（这是目前最可靠的立足点）

1. **不是运行时**：纯 wstd 的 accept+read、accept+connect 两个最小复现器，300 条悬停，
   CPU 都是 **0**。
2. **不是「只要跑连接」**：我们的服务端跑完 300 条完整快路径，CPU ≈ **0**。
3. **触发条件**：我们的服务端 + **一批连接悬停在 `connect`**（目标不可达）。
   已由 `scripts/e2e-spin-test.sh` **15 秒稳定复现**（空闲 0 → 悬停 501）。
4. **热循环**：`poll_read` 的就绪等待，被以 **~20,480 Hz** 重新轮询。
5. **而它每次都返回 `Pending`** —— 就绪等待是诚实的，**任务是被外面唤醒的**。

⇒ 剩下的方向只有一个：**谁在唤醒它**。而 worker 5 个假设全部落空，
说明问题不在「订阅怎么管」，而在**这个 future 被谁 poll**。

## 下一步的具体建议

现在最该做的是**定位「谁在 poll 这个 future」**，而不是继续在 `Ready` 里打转：

* 在 `poll_read` 里记录**当前任务的 waker 地址**，看 20480 次/秒里是不是同一个；
* 更重要的是：**把这个 future 换成不依赖 waker 的形态**做对照 —— 例如用
  `futures::future::poll_fn` 手工包一层，或用 wstd 自己的 `AsyncInputStream`
  替掉我们的 `Ready`（我们的注释写着「做法与 wstd 一致」，但那是我手写的复刻）。
* 若换成 wstd 的类型后自旋消失 ⇒ 直接换成 wstd 的实现即可，不必再找根因。

**最后一条是最省事、也最可能见效的**：既然纯 wstd 复现器不自旋，而我们的
`NetStream` 是手写复刻，那就**直接不要这个复刻**。

### V24 八续：核对「用 wstd 类型替掉手写 Ready」这条路 —— **不是 drop-in，比我说的更大**

动手前先核对了 wstd 的 trait 形态：

```rust
// wstd-0.6.8/src/io/read.rs
pub trait AsyncRead {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;   // ← async fn 风格
    ...
}
```

**wstd 的 `AsyncRead` 是 async-fn 风格，不是 `poll_read` 风格。**

而本工程的协议层（TLS / REALITY / VLESS / Vision）全部依赖 **tokio 的
`AsyncRead`/`AsyncWrite`**（poll 风格）。所以「把 `NetStream` 的手写 `Ready`
换成 wstd 的 `AsyncInputStream`」**不是替换一个字段，而是要改掉整个 socket 层的
trait 面** —— 那是一次重构，不是一次修改。

我在上一轮把这条路说成「最省事、最可能见效」，**这个判断是错的**，特此更正。
（这也是 V24 里第 N 次「先动手再核对」的教训：这次好在先核对了。）

## 现在的确切位置

* 5 个围绕「订阅怎么管」的假设全部实测排除；
* 运行时（wstd/wasmtime）已证伪；
* 确定：热循环是 `poll_read` 的就绪等待，被 ~20kHz 重轮询，而它**每次返回 Pending**
  ⇒ **问题在「谁 poll 这个 future」，不在被 poll 的东西里**。

## 建议的下一步（两选一，都不小）

1. **在 `poll_read` 里记录当前任务的 waker**：20480 次/秒里是不是同一个 waker？
   若 waker 每次都在变 ⇒ 有东西在反复重建任务/唤醒；
   若同一个 ⇒ reactor 对这个 waitee 反复派发。
   这是**最小、最直接**的一步，信息量最大。
2. 若 1 指向 reactor 派发：写一个**只用我们自己 NetStream 的最小复现器**
   （accept 一条 → 起任务 → 对它 `read`），把范围从「整个服务端」缩到
   「我们的 NetStream + wstd executor」。这是继「我们 vs 运行时」之后的第二刀，
   应该最先做 —— 它能把嫌疑从协议层彻底摘出去或钉死。

**注意**：上面两条都还没做。V24 到此为止的所有结论都是**实测**的，
但**这个 bug 仍然没有修复**。不要把它当成已解决。

### V24 九续：第二刀 —— **只用我们的 NetStream（无协议层）→ 不自旋**

按上一轮的建议做的第二个最小复现器：
`crates/xt-wasm-runtime/examples/stream_spin_probe.rs`
（`listen` + `accept` + 每个连接起任务 `read`，**不含 TLS/VLESS 任何代码**）。

```
纯 wstd（accept + 挂起 read）                     0 ticks
纯 wstd（accept + 挂起 connect）                  0 ticks
我们的 NetStream（accept + 挂起 read，无协议层）   0 ticks   ← 本次
我们的完整服务端（协议层 + 300 条悬停 connect）    501 ticks
```

**结论：我们的 socket 层单独用是正常的。自旋必须有协议层参与。**

这把嫌疑从 socket 层**彻底摘掉**，同时也说明了为什么前面 5 个「在 `Ready` 里改来改去」
的假设全部无效 —— **问题不在 `Ready` 本身的写法，而在协议层怎么用它。**

## 协议层与最小复现器的差别（下一个该查的点）

协议层在同一个 `NetStream` 之上做的事，最小复现器一件都没做：

1. **握手期间对同一条流反复读写**（ClientHello / ServerHello / 证书 / Finished），
   `read` 与 `write` 交替，注册/注销 waker 很多次；
2. **把流包进多层**：`RealityTlsStream` → `serve_inbound` 里的 `decode_request`
   → 可能还有 `timeout(...)`；（本仓库的 `timeout` 用 `futures::future::select`
   把两个 future 塞进**同一个 task**）
3. 一条流上**同时存在多个等待者**（读方向与写方向、外层 TLS 与内层 VLESS）。

最可疑的是第 2 条：`timeout` 的 `select` 会把被包裹的 future 与 `Timer` 放在同
一个 task 里轮询。而 **`Ready` 只有一颗 `WaitFor` 槽位** —— 若同一条流上先后有
不同 future 来注册，waker 会被互相覆盖，留下失效注册。这正好是「运行时不背锅、
socket 层不背锅、只有协议层参与才发作」的形状。

**下一步**：在 `stream_spin_probe` 上**逐条加上协议层的特征**（先只加一层
`timeout(...)` 包住 read，再加读写交替），看加到哪一步开始自旋。
这是第三刀，也是最可能直接定位的一刀。

### V24 十续：第三刀 · 第 1 步 —— 加一层 `timeout(...)`（**不自旋**）

在 `stream_spin_probe` 上**只加一层** `xt_wasm_runtime::timeout(Duration::from_secs(3600), s.read(&mut buf))`，
其余一字未动。新探针：`crates/xt-wasm-runtime/examples/stream_spin_probe_timeout.rs`
（原探针保留，未改动）。

```
socket 层探针（无 timeout）        300 条悬停 → 0 ticks
socket 层探针 + timeout(...)      300 条悬停 → 0 ticks   ← 本次
完整服务端（协议层）               300 条悬停 → 501 ticks
```

**`timeout` 这一层不是触发条件。** 我上一轮把它列为「最可疑」是**判断错了** ——
`futures::future::select` 把两个 future 塞进同一个 task 这个结构本身，
单独用并不会引发自旋。

## 第三刀 · 第 2 步（下一个该试的）

继续在 socket 层探针上**逐条**加协议层的特征，一次只加一条：

2. **读写交替**：握手期对同一条流反复 `read`/`write`（ClientHello → ServerHello →
   证书 → …），waker 在同一条流的读写两侧被反复注册/注销。
3. 若 2 也不自旋：加**多层包装**（`RealityTlsStream` 把 `NetStream` 包起来，
   外层 TLS 与内层 VLESS 对同一条底层流各自持有等待）。

判据不变：`/proc/<pid>/stat` 的 5 秒 CPU 增量，0 = 正常，~500 = 自旋。

**注意**：至今为止**这个 bug 仍未修复**。已排除的假设增至 6 个。

### V24 十一续：**第三刀命中 —— 触发条件是「写」这条路径**（40 行、无协议层的最小复现）

沿第三刀继续在 socket 层探针上逐条加协议层特征，一次只加一条：

```
socket 层 + 只读（read 悬停）      0 ticks
socket 层 + timeout + read         0 ticks
socket 层 + 只写不读               501 ticks   ← 自旋
socket 层 + 读写交替               501 ticks   ← 自旋
```

**结论：只要往流上写过（`write_all` + `flush`），300 条悬停连接就会自旋；只读不会。**

这比我预期的好得多 —— 现在有了一个**不含 TLS/VLESS 任何代码、几十行**的最小复现：

* `crates/xt-wasm-runtime/examples/stream_spin_probe_w.rs`（只写不读，自旋）
* `crates/xt-wasm-runtime/examples/stream_spin_probe_rw.rs`（读写交替，自旋）
* `crates/xt-wasm-runtime/examples/stream_spin_probe.rs`（只读，不自旋 ← 对照组）

探针都保留在仓库里，判据统一是 `/proc/<pid>/stat` 的 5 秒 CPU 增量。

**写路径上最可疑的一处**（`wasi.rs` 的 `poll_write`）：

```rust
match this.output.check_write() {
    Ok(0) => {
        if this.write_ready.poll(&|| this.output.subscribe(), cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(Ok(0))          // ← 「就绪了但写不进」
    }
    ...
}
```

`check_write()` 返回 0（写不进去）却又拿到就绪，然后返回 `Ok(0)`。而 `poll_flush`
里也有一处 `write_ready.poll(...)`。**下一刀就在这两处**：
把 `output.check_write()` 的返回值与 `write_ready.poll` 的结果**同时记录**，
看是不是「一直拿到就绪、但永远写不进」⇒ 上层反复重试 ⇒ 忙等。

（注意：本轮的 `hold.py` 客户端**从不读取**，所以写 15 字节不可能填满缓冲区 ——
这条路径本不该等待。它却成了触发条件，说明问题多半就在这个「不该等待却等待了」的地方。）

### V24 十二续：**机制抓到了 —— `check_write()` 永远返回 0**

在只写探针（`stream_spin_probe_w.rs`）上给写路径加看门狗，自旋稳定段：

```
[WD] write_entry=18336  cw_zero=18336  wr_PENDING_on_zero=18336  flush_entry=144  flush_wr_PENDING=144
[WD] write_entry=17657  cw_zero=17656  wr_PENDING_on_zero=17657  flush_entry=139  flush_wr_PENDING=139
[WD] write_entry=18336  cw_zero=18336  wr_PENDING_on_zero=18336  flush_entry=144  flush_wr_PENDING=144
```

**`cw_zero` 与 `write_entry` 一个不差** ⇒

> **`output.check_write()` 每一次都返回 0**（"现在写不进去"）⇒ `poll_write` 走 `Ok(0)` 分支
> ⇒ `write_ready.poll()` 返回 `Pending`（同样一个不差）⇒ 任务挂起 ⇒ 被唤醒 ⇒ 重试 ⇒ 永远。

**所以不是死循环，是「写永远完成不了」**：约 18,000 次/秒的重试，每次都要过一遍 WASI 调用
（`check_write` + `subscribe` + 就绪判定），累计就把一核吃满了。这也解释了为什么
CPU 是「一核」而不是「爆表」。

### 为什么这件事很反常

探针只写了 **15 字节**，而 `hold.py` 客户端**从不读取**。15 字节无论如何也填不满内核发送缓冲区
—— **这条路径本不该返回「写不进去」。**

`check_write()` 恒为 0，意味着 WASI 认为这个输出流**永远没有可写空间**。合理的怀疑方向（下一刀）：

1. **发出去的字节没有真正落到 socket**：`output.write()` 之后没有真正 flush，
   于是 WASI 侧的可写额度一直被占着（每连接 15 字节 × 300 条，若额度按连接而非按字节计，
   就可能恒为 0）。
2. `check_write()` 在**连接建立方式**上有前提没满足（我们建流的方式与 wstd 不同）。
3. 对端不读时 wasmtime 的可写额度计算与预期不同。

**下一刀**：在探针里把 `check_write()` 的**实际返回值**（不只是"是不是 0"）和
`output.write()` 的调用次数/返回字节数一起记录；再试一个**顺序写 1 字节就立刻 flush**
的变体。判据不变，几十秒一次。

至今**仍未修复**。

### V24 十三续：一次修法尝试（**方向错了，已回滚**）与问题的完整记录

#### 尝试

假设：`check_write()` 不可靠地返回 0，而真正该调用的是 `output.write()` 本身 ——
所以把 `Ok(0)` 分支改成「先直接试一次 write，真写不进再挂起」。

#### 结果：**编译期就被否掉了，方向是错的**

```rust
error[E0599]: no variant named `WouldBlock` found for enum `StreamError`
```

WASI 0.2 的 `StreamError` 只有 `Closed` 和 `LastOperationFailed`，**没有 `WouldBlock`**。
这说明 `output-stream.write` 在写不进时的语义不是「返回一个可重试的错误」，
而 `check_write()` 正是用来**避免阻塞**在 `write` 上的。

所以「绕过 `check_write` 直接写」不是修法，反而可能把一个忙等换成一个真正的阻塞。
已回滚。

---

## 问题记录（把已知事实集中到这里，便于接手）

### 一句话

**服务端在「有过连接 + 往流上写过」之后，`check_write()` 恒为 0，写永远完不成，
上层以约 18,000 次/秒重试，把一核吃满，且永不恢复。**

### 触发条件（全部实测）

| 场景 | 5 秒 CPU 增量 |
|---|---|
| 我们的服务端 + 快路径（300 条全部完成） | ~0 |
| 我们的服务端 + 300 条悬停在 connect | **501** |
| socket 层探针：只 read | 0 |
| socket 层探针：read + `timeout(...)` | 0 |
| socket 层探针：**写过**（只写 / 读写交替） | **501** |
| 纯 wstd 最小复现器（accept + read / connect） | 0 |

⇒ **要复现必须同时满足：① 用我们的 `NetStream`；② 往流上写过；③ 数量多。**

### 直接机制（看门狗实测）

```
[WD] write_entry=18336  cw_zero=18336  wr_PENDING_on_zero=18336
[WD] flush_entry=144    flush_wr_PENDING=144
```

`cw_zero` 与 `write_entry` **一个不差** ⇒ `check_write()` 每一次都返回 0。

### 最反常、也是目前最该解释的一点

探针只写 **15 字节**，客户端**从不读取**。这条路径**本不该**返回「写不进去」。
即 `check_write()` 在一条**新建的、一个字节都没写过**的连接上就返回 0。

### 已排除（6 个假设 + 2 个方向，全部实测）

| 假设 | 结果 |
|---|---|
| `Ready` 用 `OnceLock` 永久复用 pollable | ❌ 无效 |
| 空读 `continue` 忙等 | ❌ 无效（且有截断风险） |
| `tokio::io::split` + `join!` 共用 task waker | ❌ 无效（该复现里 relay 根本没跑） |
| 消费就绪后丢弃订阅 | ❌ 不可达代码 |
| `WaitFor` Pending 后重建 | ❌ 无效 |
| `timeout` 的 `select` 结构 | ❌ 无效 |
| wstd / wasmtime 本身有问题 | ❌ 已证伪（纯 wstd 复现器 0 ticks） |
| socket 层写法有问题 | ❌ 已摘除（只读时 0 ticks） |
| 绕过 `check_write` 直接 write | ❌ 方向错（WASI 无 WouldBlock，可能阻塞） |

### 最小复现（48 行，几十秒一次）

```sh
cargo build --release --example stream_spin_probe_w -p xt-wasm-runtime --target wasm32-wasip2
wasmtime run -C cache=n -S tcp=y -S inherit-network=y -S allow-ip-name-lookup=y \
  target/wasm32-wasip2/release/examples/stream_spin_probe_w.wasm 12396 &
# 再用 300 条「连上但不发数据、也不读」的连接灌它，读 /proc/<pid>/stat 的 CPU ticks
```

仓库里三个探针：`stream_spin_probe.rs`（对照，0）、`stream_spin_probe_w.rs`（自旋）、
`stream_spin_probe_rw.rs`（自旋）。端到端回归测试：`scripts/e2e-spin-test.sh`。

### 下一步该查的（按可能性排序）

1. **为什么新建连接的 `check_write()` 是 0** —— 直接在探针里打印它的返回值
   （不只是"是不是 0"），以及 `output.write()` 是否曾被调用过、写进了多少字节。
   这是目前**唯一还没测过**的核心问题。
2. 对比 **wstd 怎么建流**：`wstd::net::TcpStream` 用 `socket.accept()` 拿到
   `(socket, input, output)` 后直接构造；我们也是。但 wstd 的 `poll_write`（如果有）
   或 `AsyncOutputStream::write` 的调用方式可能与我们的 `check_write` 门控不同。
3. 若不是 `check_write` 本身：查**为什么任务在 `Pending` 状态下被 ~18k 次/秒重轮询**
   （这在只读探针里不发生，说明与"写过"有关的状态参与了唤醒）。

**这个 bug 至今未修复。** 上面每条结论都来自实测，没有推测。

### V24 十四续：**发现我自己一个重大验证漏洞 —— 「不是 wstd」这个结论没在写路径上验证过**

两件事：

**1. wstd 的写逻辑与我们逐行相同**（`wstd-0.6.8/src/io/streams.rs`）：

```rust
match self.stream.check_write() {
    Ok(0) => { self.ready().await; continue; }   // 与我们完全一样的门控
    Ok(some) => { let writable = some.min(buf.len()); self.stream.write(&buf[..writable]) }
    ...
}
```

⇒ **`check_write()` 的门控方式不是 bug**，那是一条死路（这也是我上一轮"绕过 check_write"
失败的根本原因）。

**2. 但我的「不是 wstd / wasmtime」结论有一个致命漏洞：**

我那两个纯 wstd 最小复现器（`minrepro` #1 和 #3）**只做了 `read` 和 `connect`，
从来没有写过任何数据**。而 V24 十一续已经实测出：**触发条件是「写」**。

> ⇒ **「不是 wstd/wasmtime」这个结论，我根本没有在写路径上验证过。**

而 V24 六续那个「纯 wstd = 0 ticks」的对照，当时**看起来**是决定性的，
现在看它的覆盖面比我以为的窄得多 —— 它只证明了「wstd 在只读/只连的情况下不自旋」，
那是个**从来不会自旋**的场景。

**这是我这几轮里第二次因为「对照组选得不对」而得出过宽结论**（第一次是
「只读探针 0 ticks ⇒ socket 层没问题」，同样漏掉了写路径）。

## 修正后的结论

| 结论 | 状态 |
|---|---|
| 不是 `wstd`/`wasmtime` | ⚠️ **未经写路径验证，撤回** |
| socket 层写法有问题 | ⚠️ 同样只在只读下验证过，**存疑** |
| 触发条件是「写过」（我们的 NetStream） | ✅ 实测 |
| `check_write()` 恒为 0 | ✅ 实测 |
| wstd 的写逻辑与我们相同 | ✅ 源码比对 |

## 下一步（**唯一该做的**）

写一个**纯 wstd 的写探针**：`wstd::net::TcpListener` accept → 每个连接
`stream.write_all(...)`（或 `wstd::io::AsyncWrite::write`）→ 挂住，300 条连接。

* 若它也自旋 ⇒ **根因在 wasmtime/wstd**，我们前面 6 个假设全部白费，方向要整个转过来；
* 若不自旋 ⇒ 才对得上「不是 wstd」，那时才轮到在 `NetStream` 里继续找。

**这个探针此前从未跑过，而它是最省事、最可能翻盘的一个。**

### V24 十五续：**结论翻转 —— 缺失的对照补上了，根因不在我们代码里**

补上唯一没填的那一格对照：**纯 wstd + 写**（`wstd::net::TcpListener` accept →
每条连接 `write` ×3 → 挂住，**不含 xt-wasm-runtime 任何代码**）。

```
纯 wstd + 只读                         0 ticks
纯 wstd + 只连                         0 ticks
纯 wstd + 写                          501 ticks   ← 缺失的对照，自旋
我们的 NetStream + 写                  501 ticks
我们的完整服务端（协议层）              501 ticks
```

## 定论

> **自旋在纯 wstd 上同样出现 ⇒ 根因在 wstd / wasmtime 的写路径，不在 xray-wasm 的代码里。**

这条把之前所有围绕我们 `Ready` 的 6 个假设**一次性解释清楚**：它们全都无效，
因为问题从来不在我们这边。

同时也说明我 V24 六续那次「纯 wstd = 0 ticks ⇒ 不是 wstd」的对照**选错了场景**
—— 我测的是只读，而只读**永远不自旋**。补上「写」这一格之后结论才成立。
V24 十四续我已经撤回过一次这个结论，现在它被**正确的对照**重新确认。

## 已经不是「我们的 bug」了，但线上仍然会卡死 —— 可选的处置

1. **上报上游**：最小复现是 `wstd` 的 `AsyncOutputStream::write` 在
   `check_write()` 恒为 0 时的行为（配合 wasmtime 48.0.2）。这个复现只有几十行。
2. **在我们这侧做规避**：既然 `check_write()` 恒为 0 而 `write` 本身可能可用，
   可以考虑改用 WASI 的 `blocking_write_and_flush`（阻塞版）——
   单线程运行时下它会阻塞整个实例，**只在真的写不进时才会触发**，
   所以是「用小概率的阻塞换掉确定性的忙等」。**未实测，需要单独验证。**
3. **运维兜底**（已在线上生效）：`livenessProbe`，卡死后约 60 秒自动重启。

## 未验证的

`blocking_write_and_flush` 这条路**完全没测过**。它是否真的能写进去、
会不会在正常情况下也阻塞，都需要用那个 48 行探针验一遍。

### V24 十六续：**找到并修掉了一个真实的忙等源（写路径），但服务端还有第二个**

#### 修复：`check_write()` 会误报 0

V24 十二续测出 `check_write()` 恒为 0。据此试了两种处置：

| 处置 | 结果 |
|---|---|
| 报 0 时直接 `output.write()` | ❌ 编译期否（`StreamError` 无 `WouldBlock`） |
| **报 0 时改用 `output.blocking_write_and_flush()`** | ✅ **有效** |

`poll_write` 的 `Ok(0)` 分支改成走 `blocking_write_and_flush` 之后：

```
socket 层只写探针：  修复前 501 ticks  →  修复后 0 ticks
```

⇒ **`check_write()` 返回 0 是误报：流其实写得进去。** 之前按它门控、然后等
`write_ready`，而 `write_ready` 同样误报未就绪 ⇒ 挂起→重试→~18k 次/秒忙等。

`poll_flush` 里有一处同样的门控，也一并改成 `blocking_flush`。

#### 但完整服务端仍然 501

```
socket 层只写探针（已修）        0 ticks
完整服务端（同样 300 条悬停）    501 ticks   ← 仍有第二个忙等源
```

所以**至少还有一处**。已经能排除的：不是 `poll_write`、不是 `poll_flush`。
剩下的差别是完整服务端会先跑完整 REALITY 握手（**读写交替**）再卡在 `connect`，
而只写探针没有读、也没有 connect。

**下一个该测的**：在**已修版**的 socket 层探针上**加回读取**（写 3 轮 + 读 1 轮，
最后停在读上），看是否又自旋。若是 ⇒ 第二个源在读路径；若否 ⇒ 在 `connect`。

#### 状态

* 写路径的修复**已验证**（隔离探针 501→0），保留在代码里；
* **完整服务端仍未修好**，`scripts/e2e-spin-test.sh` 仍是红的；
* 线上仍靠 `livenessProbe` 兜底。

### V24 十七续：写路径的修复**同时解决了两个探针** —— 第二个源在别处

在**已修版**上重跑各探针：

| 探针 | 修复前 | 修复后 |
|---|---|---|
| socket 层：只写 | 501 | **0** |
| socket 层：读写交替（最后停在读） | 501 | **0** |
| socket 层：只读 | 0 | 0 |
| 完整服务端（300 条悬停） | 501 | **501** ← 仍有 |

⇒ **写路径的修复是有效的，而且它同时消掉了「只写」和「读写交替」两个探针。**
`read` / `write` / `read+write` 三条路径现在都干净了。

**所以完整服务端里剩下的那个源不在读写路径上。**

剩下的唯一差别：完整服务端会**调用 `connect()`** 去连一个不可达地址
（`10.255.255.1:5226`，会一直挂在那儿），而三个探针都不 connect。
另外「纯 wstd + connect → 0」是测过的，但那只覆盖了 wstd 的实现；
**我们的 `connect_addr` 还从来没在「写过 + 挂起」的组合下测过。**

`connect_addr` 里是同一类形状：

```rust
socket.start_connect(&network, to_wasi_addr(sa))?;
AsyncPollable::new(socket.subscribe()).wait_for().await;   // ← 同样是不带门控的裸等待
let (input, output) = socket.finish_connect()?;
```

**下一个探针**：在 socket 层探针上加一步 `xt_wasm_runtime::connect("10.255.255.1:5226")`
（必然挂住）。判据不变：0 = 不是它；~500 = 就是它，按同样的思路处理
（`check_write` 那次的教训：**不要相信 wasmtime 的就绪判定**）。

至此**仍未完全修复**，但进度是实打实的：一个已验证的修复 + 三条路径已澄清。
