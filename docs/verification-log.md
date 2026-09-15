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
