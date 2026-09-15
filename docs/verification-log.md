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
