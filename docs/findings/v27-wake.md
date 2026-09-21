# V27-A（唤醒/就绪线）：结论 —— 不是唤醒缺陷，`wasi.rs` 无需修改

> 任务：`task-7`（v27-wake）。写者：`v27-wake`。
> 判据要求：命令 + 原始输出；阴性结果同样贴出。
> 本文所有输出均为本机实测（macOS，官方 Xray 26.3.27 d2758a0，wstd 0.6.8，wasmtime 48.0.2）。

## 0. 一句话结论

**三个候选机制（waker 注册丢失 / `block_on` 调度饥饿 / socket 就绪语义）全部不成立。**

* 卡住期间 **socket 上根本没有数据**：长期订阅和**全新订阅**两种 `input-stream.subscribe()` 都报 not-ready，
  连续 16s 如此（§3.3）。数据真的到达时，任务 **立刻**被唤醒并读走（§2、§3.2）。
* reactor 在卡住期间**一直活着**：心跳任务每 500ms 准点触发，`poll_read` 计数纹丝不动（§3.2）。
  所以既不是 `block_on` 饥饿，也不是整个 guest 卡在宿主调用里。
* at 最小延迟对端（裸 TCP，accept→sleep 1.5s→回 TLS record 头）上**不卡**（§2）；
  先做 2 次「连上就被 RST」的前序连接，再连延迟对端，**也不卡**（§2.3）。

**V27 的真实形态**：客户端首次 REALITY 握手在跟 **10s 死线**赛跑。当服务端首个飞行包晚于 10s 时必然失败。
本机在 **17:37–17:46 这一个时间窗** 里，官方服务端首个飞行包要 **17.1–19.3s** 才出现（后来恢复到 0.2–0.4s，§5），
所以同一套代码「有时绿有时红」。这不是冷启动属性（纯净回放：全新服务端 **0.43s**，§5.3）。

**在 `wasi.rs` 里没有可修的缺陷** —— 本文件最终保持 HEAD 不变（见 §7 决策点）。
真正值得修的是两处别人范围的东西：`reality.rs` 的死线要**定时器驱动**（§6），`main.rs` 的 `open_tunnel` 超时后**重试一次**（§7）。

---

## 1. 交付的工具：`scripts/v27-delayed-peer.py`

一个裸 TCP 对端，把「服务端慢 / 服务端脏 / 服务端根本不说话」这些变量从官方 Xray 里彻底剥掉。

| 模式 | 行为 | 用途 |
|---|---|---|
| `header0`（默认） | accept →（可选）读掉 ClientHello → sleep `--delay` → 发 `16 03 03 00 00` → 保持连接 | 延迟对端；判据是「卡在 10s 超时」vs「~delay 秒后立刻报 `unexpected plaintext handshake`」 |
| `bogus-serverhello` | 同上，但回「头 + 长度自称 1 的 ServerHello」 | 比 header0 多证明一步：客户端把 5 字节头解析成了记录 |
| `split-header` | 先 2 字节、0.3s 后 3 字节 | 测部分读之后的重注册 |
| `reject` / `--pre-reject N` | 立刻 RST 关闭 | 造「前序连接」 |
| `forward` | 透明代理到 `--upstream`，双向记录字节与时间 | 切开 client / server 两侧 |
| `capture` | 把客户端首批字节存盘 | 给 replay 用 |
| `replay` | 合成客户端：直接连 `--upstream`，发存盘的 ClientHello，测「首字节延迟」 | 纯服务端冷/热测量（不经过我们任何一行代码） |

**注意脚本刻意不关连接**：如果 accept 后立刻 close，客户端会收到 FIN，pollable 同样就绪，
那会把「唤醒失败」洗成「读到 EOF」，判据就废了；所以回包后要 `--hold` 住。

---

## 2. 最小复现（不依赖官方 Xray）：**三条阴性结果**

### 2.1 干净客户端 → 延迟对端（1.5s）：不卡

```sh
python3 scripts/v27-delayed-peer.py --port 18447 --delay 1.5 --mode header0 --accept 1 --hold 5
./scripts/run-local.sh --server 127.0.0.1:18447 --pbk HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg \
    --sid 64f6ffd42769a12c --sni www.cloudflare.com \
    --uuid b21e29c8-a8ea-40a2-b953-c2b04d73d775 --listen 127.0.0.1:1094
curl -sS -m 12 --proxy socks5h://127.0.0.1:1094 -o /dev/null https://example.com
```

对端日志（`/tmp/v27a/final/delayed-clean-peer.log`）：

```
[peer 17:55:12 t+   0.006] 监听 127.0.0.1:18447  delay=1.5s mode=header0 accept=1 hold=5.0s
[peer 17:55:14 t+   1.920] #1 accept 来自 127.0.0.1:61617
[peer 17:55:14 t+   2.073] #1 收到客户端首包 570 字节，距 accept 0.153s
[peer 17:55:14 t+   2.073] #1 静默等待 1.5s（模拟冷启动服务端取证书的飞行时间）
[peer 17:55:16 t+   3.576] 回包 mode=header0 len=5：1603030000
```

客户端日志：

```
[socks5] 127.0.0.1:61616 失败：REALITY 握手失败：tls handshake: Reality TLS: unexpected plaintext handshake
```

**回包后客户端立刻读到了这 5 个字节并报协议层错误**（不是 10s 超时）⇒ 唤醒路径是健康的。
（对端 `--accept 1` 退出后 curl 又重试了两条连接，拿到 `connection-refused` / `LastOperationFailed`，
那是脚本只收一条的副作用，与唤醒无关。）

### 2.2 同形态、不同 mode：也都正常

```
== bogus-serverhello ==   收到: 16030300050200000100
== split-header ==        收到: 1603030000   （第一段 1603 → 0.3s → 030000）
```
（`--delay 0.3`；原始输出见 `/tmp/v27a/smoke-*.log`。）

### 2.3 Lead 要求的决定性实验：**前序 RST 连接不污染**（阴性）

同一个客户端进程内，(a) 干净地连延迟对端；(b) 先被对端 RST 两条，再连延迟对端。

对端日志（`/tmp/v27a/final/delayed-after2rst-peer.log`）：

```
[peer 17:55:21 t+   0.013] 监听 127.0.0.1:18447  delay=1.5s mode=header0 accept=3 hold=5.0s
[peer 17:55:23 t+   1.967] #1 前序连接 → 立刻 RST（pre-reject）
[peer 17:55:23 t+   1.980] #2 前序连接 → 立刻 RST（pre-reject）
[peer 17:55:23 t+   1.996] #3 accept 来自 127.0.0.1:61810
[peer 17:55:24 t+   2.152] #3 收到客户端首包 602 字节，距 accept 0.156s
[peer 17:55:25 t+   3.657] 回包 mode=header0 len=5：1603030000
```

客户端日志：

```
[socks5] 127.0.0.1:61806 失败：REALITY 握手失败：io: StreamError::LastOperationFailed(Error { handle: Resource { handle: 16 } })
[socks5] 127.0.0.1:61809 失败：REALITY 握手失败：tls handshake: Reality TLS: unexpected plaintext handshake
```

**第 3 条（延迟 1.5s 的那条）照常被唤醒**，报 `unexpected plaintext handshake`。
⇒ 「前序连接留下的状态污染」（`Ready` 的 OnceLock / pollable 注册 / `block_on` 残留任务）**没有证据支持**。

---

## 3. 真实现场卡住时，逐帧发生了什么

### 3.1 埋点方式

在 `wasi.rs` 里加了一段**只在 `XT_DIAG=1` 时才输出**的诊断（跑完已回滚，补丁见 §9）：

* `poll_read` 进入 / `Pending` / 读到数据的时刻与 `remaining`；
* `Ready::poll` 每次进出、是否新建 `WaitFor`、结果；
* 一个 500ms 心跳任务（时间门控，避免被紧循环饿死）；
* 用原始 WASI import 每拍探一次 socket 就绪：`[method]input-stream.subscribe` + `[method]pollable.ready`，
  同时持有**首次建好的订阅**和**每拍新建的订阅**做对照。

### 3.2 一次完整 stall 的原始输出（`/tmp/v27a/client-e3.log`）

```
[v27] read_top#11 t+0.002s remaining=5
[v27] new AsyncPollable #4, t+0.002s
[v27] read PENDING#0 t+0.002s remaining=5
...（中间 18 秒：心跳每 500ms 一行，read_polls 恒为 12，read_pending 恒为 1）...
[v27wd t+ 18.094s] heartbeat #36 read_polls=12 read_pending=1 read_data=11
[v27] ready-poll#15 t+17.997s created_waitfor=true => Ready(())
[socks5] 127.0.0.1:51383 失败：REALITY 握手失败：tls handshake: Reality TLS: handshake did not complete within 10s
```

三条读数：

1. **reactor 活着**：心跳 500ms 一行、连响 204 次（`t+102s`），说明 `poll_oneoff` 正常返回、
   任务调度正常 ⇒ 排除「`block_on` 调度饥饿」和「整个 guest 卡在宿主调用」。
2. **任务没被重轮询，直到 data 到**：`read_polls` 停在 12 整整 18s，`ready-poll#15` 一返回 Ready
   就立刻继续、并立刻报出 10s 超时 ⇒ 唤醒本身是**即时**的，唤醒没有丢。
3. **`Ready` 的等待是诚实的**（这条在 V24 的日志里被探针标签写反过一次，这次标签与分支一起核对过）：
   它返回 `Pending` 是因为底层 pollable 没就绪，不是因为 waker 注册失败。

### 3.3 决定性读数：卡住期间 socket 上**没有数据**（`/tmp/v27a/client-d2.log`）

（同一场景，加了 §3.1 的原始 import 探针）

```
[v27wd t+  0.507s] heartbeat #1  | stream#114ef4 old_sub_ready=true  fresh_sub_ready=true;
                                    stream#1140c0 old_sub_ready=false fresh_sub_ready=false;
[v27wd t+  1.009s] heartbeat #2  | ... 同上 ...
...
[v27wd t+ 16.593s] heartbeat #33 | ... 同上 ...
```

* `stream#114ef4` = 客户端那条 SOCKS 连接（已经读空；注意它的 pollable **一直报就绪**，这本身也说明就绪语义没问题）。
* `stream#1140c0` = 卡住的那条隧道连接：**长期订阅和每拍新建的全新订阅都报 not-ready**，连续 16s。
  ⇒ 不是「我们缓存的订阅失效了」，是**对端一个字节都没发过来**。

### 3.4 夹在中间的透明代理：服务端确实晚发（`/tmp/v27a/fwd.log`，`--mode forward`）

```
[peer 17:42:11 t+   2.496] #1 c2s 首批 538 字节 （accept 后 0.000s）hex=1603010215010002110303e4
[peer 17:42:28 t+  19.641] #1 s2c 首批 2181 字节 （accept 后 17.144s）hex=160303007a0200007603033f
[peer 17:42:28 t+  19.641] #1 c2s 总计 538 字节，持续 17.145s
```

代理把客户端的 ClientHello 在 accept 后 0.000s 就转给了服务端；服务端的第一个 s2c 字节在 **17.14s** 后才到代理。
⇒ 卡点在**客户端之外**。

---

## 4. 机制判定表（三选一 → 都不是）

| 候选机制 | 判定 | 判据 |
|---|---|---|
| waker 注册丢失 | **否** | 延迟对端 1.5s 后**照常唤醒**（§2.1）；前序 RST 后照常唤醒（§2.3）；真实现场 data 一到就 `ready-poll => Ready`（§3.2） |
| `block_on` 调度饥饿 | **否** | 卡住全程心跳 500ms 准点、共 204 拍（§3.2）；`read_polls` 不变说明只是**没人该唤醒它**，不是调度器不转 |
| socket 就绪语义 | **否** | 长期订阅 + 全新订阅两种探针都 not-ready 16s（§3.3）；数据到达即读走（§2.1） |
| 「数据到了但没醒」（V27 原描述） | **前提不成立** | 数据没到；到达即醒。原埋点 `fresh_ready=false` 其实已经说明了这一点，只是被读成了「已注册却没醒」 |

**结论**：`wasi.rs` 的 `Ready` / `NetStream::poll_read` 在这条线上**没有缺陷**。

---

## 5. 那次 17–19s 是什么：**瞬态链路延迟，不是冷启动属性**

### 5.1 官方 xray 客户端走同一个代理（`/tmp/v27a/fwd-e1.log`）

同一台冷启动服务端、同一个代理，连续 3 条连接：

```
#1 s2c 首批 3270 字节 （accept 后 19.289s）    ← 冷（进程刚起）
#2 s2c 首批 3270 字节 （accept 后 0.211s）    ← 热
#3 s2c 首批 3270 字节 （accept 后 0.220s）    ← 热
```

curl：`#1 http=200 total=29.63s`，`#2 http=200 total=0.50s`，`#3 http=200 total=0.52s`。

**官方客户端不设 10s 上限，所以它愿意等 19.3s 并成功**；我们的客户端 10s 就放弃 ⇒ 必红。

### 5.2 纯净服务端回放：冷启动 **没有**惩罚（§1 的 `replay` 模式）

同一份抓下来的 ClientHello（570B，来自我们的 wasm 客户端）、**每次都是全新服务端进程**、直连：

| case | ClientHello→首字节 |
|---|---|
| 无前序探测 | **0.406s**（2183B） |
| 前序 1 次 connect-only 探测 | **0.445s** |
| 前序 2 次 connect-only 探测 | **0.393s** |
| 再各跑一轮 | **0.437s** / **0.397s** / **0.434s** |

⇒ (a) 官方 REALITY 服务端冷启动**没有**慢路径（与 `v27-cold-warm` 的 276/286/299ms 一致）；
(b) `nc -z` / k8s `tcpSocket` 这类 **connect-only 探测不会污染**后续 REALITY 握手。

### 5.3 结论

17.1–19.3s 那批数字出现在 **17:37–17:46** 这个窗口，之后（17:49 起）同一命令稳定 0.4s。
这是本机出口/dest 路径的**瞬态**，不是服务端冷启动属性。
它精确解释了 V27 的「flaky」与「预热后 8/8」：**能不能过，取决于那一次首个飞行包是否落在 10s 内。**

---

## 6. 顺手抓到的真缺陷：10s 死线**只在被 poll 时评估**

`reality.rs::handshake_with_deadline` 用 `poll_fn` 每次 poll 时比 `SystemTime::now()`：

```rust
std::future::poll_fn(move |cx| {
    if SystemTime::now() >= deadline { return Poll::Ready(Err(...did not complete within 10s...)) }
    handshake.as_mut().poll(cx)
})
```

它只在**任务被轮询**时才评估。而这条读路径是纯 waker 驱动、没有定时器，所以：

```
[v27] read PENDING#0 t+0.002s remaining=5
...
[v27] ready-poll#15 t+17.997s => Ready(())
[socks5] ... 失败：REALITY 握手失败：... did not complete within 10s
```

**「10s 超时」的消息在 18.0s 才打印。** 用户看到的时刻与它自称的死线不一致，
排障时会把「服务端 18s 才回包」误读成「客户端 10s 没醒」。
`wasi.rs` 里已经有**定时器驱动**的 `timeout()`（SOCKS 协商用的就是它，实测准点），
所以修法很直接（在 `reality.rs`，不在我的写范围）：

```rust
// crates/xt-wasm-tls/src/reality.rs, RealityTlsLayer::connect
let stream = xt_wasm_runtime::timeout(
    REALITY_HANDSHAKE_TIMEOUT,
    reality_handshake_with_profile(inner, &self.server_name, &self.alpn, &self.reality, self.profile),
).await
 .map_err(|_| TransportError::Tls(format!(
     "Reality TLS: handshake did not complete within {REALITY_HANDSHAKE_TIMEOUT:?}")))??
```

**注意**：这只让失败**准时**（10s 就报），**不解决**「服务端飞行包 >10s」这个失败本身。

---

## 7. 修复建议与决策点（`wasi.rs` 不需要改）

| 优先级 | 改哪 | 做什么 | 证据 / 预期 |
|---|---|---|---|
| **P0** | `crates/xt-wasm-cli/src/main.rs`（`open_tunnel`） | REALITY 握手超时后**重试一次** | 首个飞行包晚于 10s 时，第 2 条连接实测 **0.211–0.220s** 就回包（§5.1）；重试即可让冷启动首连可用，不必改 `e2e-test.sh` 的任何断言 |
| **P0** | 部署 / 运维 | 服务端启动后**自预热**（或客户端启动时先打一条自检握手），别让线上第一次真实用户的握手去撞冷启动 | §5.1／§5.3 |
| **P1** | `crates/xt-wasm-tls/src/reality.rs` | 死线改成 `xt_wasm_runtime::timeout()`（定时器驱动） | §6；让「10s」名副其实 |
| — | `crates/xt-wasm-runtime/src/wasi.rs` | **不改**。所有证据都表明唤醒/就绪路径正确 | §2、§3、§4 |
| — | `scripts/e2e-test.sh` | 不要为了绿而放宽断言 | 铁律 2 |

**需要谁决定什么**：
* 重试（P0）是产品语义决定（超时是 10s 还是 30s？重试一次还是两次？）→ 需要 lead / 客户端负责人拍板；
* 部署预热（P0）是运维决定；
* 死线实现（P1）是 `xt-wasm-tls` 负责人。

---

## 8. 复现命令清单

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh
CARGO_TARGET_DIR=$PWD/target cargo build -p xt-wasm-cli --release --target wasm32-wasip2

# (1) 延迟对端：期望「不卡」（~1.5s 后报 unexpected plaintext handshake）
python3 scripts/v27-delayed-peer.py --port 18447 --delay 1.5 --mode header0 --accept 1 --hold 5 &
./scripts/run-local.sh --server 127.0.0.1:18447 --pbk HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg \
    --sid 64f6ffd42769a12c --sni www.cloudflare.com \
    --uuid b21e29c8-a8ea-40a2-b953-c2b04d73d775 --listen 127.0.0.1:1094 &
curl -sS -m 12 --proxy socks5h://127.0.0.1:1094 -o /dev/null https://example.com

# (2) 前序 RST ×2 再连延迟对端：期望「仍然不卡」
#     （对端加到 --accept 3 --pre-reject 2，前面先走两条会被 RST 的 curl）

# (3) 纯服务端冷启动测量：期望 ~0.4s（先 capture 一份 ClientHello）
python3 scripts/v27-delayed-peer.py --port 18445 --mode capture --accept 1   # 客户端连它 → 存盘
python3 scripts/v27-delayed-peer.py --mode replay --upstream 127.0.0.1:8443 \
    --hello-file /tmp/v27a/clienthello.bin --hold 20

# (4) 真实现场（把 --listen 换成 1090+，不要用 1080）
#     官方服务端：$XW_WS/.scratch/xray-server/xray run -c .../server.json
#     客户端 + 2 次错误凭据 curl + 1 次正确凭据 curl
```

**V27 目前复现不出来的实测（同样是结论的一部分）** —— 8 轮、每轮**全新**官方服务端，
交替「干净」与「先做两次认证失败」：

```
round 1 pre=clean      curl=200 6.059439
round 2 pre=pre-authfail curl=200 7.165271
round 3 pre=clean      curl=200 6.113062
round 4 pre=pre-authfail curl=200 6.114472
round 5 pre=clean      curl=200 6.046303
round 6 pre=pre-authfail curl=200 6.120104
round 7 pre=clean      curl=200 6.879204
round 8 pre=pre-authfail curl=200 7.399805
```

**8/8 绿**，`pre-authfail` 不是触发条件。⇒ 判据不能建立在「冷启动慢」上（它不稳定）；
稳定的判据见 §1／§2（延迟对端）与 §7 的重试。

---

## 9. 附：诊断埋点补丁（已回滚，供下次复用）

`wasi.rs` 最终保持 HEAD。要重放本次证据，加下面这段（`XT_DIAG=1` 才生效，默认零输出）：

* `poll_read` 循环顶 / `Pending` 分支 / 读到数据时各 `eprintln!` 一行，
  带 `t+{diag_t0().elapsed()}`、`buf.remaining()`、`READ_POLLS`/`READ_PENDING`/`READ_DATA` 计数；
* `Ready::poll` 在 `wait.as_mut().poll(cx)` 前后打印 `created_waitfor` 与结果；
* `spawn_task` 一个 500ms 心跳打印上面几个计数。

**踩过的坑（值得记住）**：我第一次还加了一个「每拍 `subscribe()` 探 socket 就绪」的探针，
它把子 pollable 存在 thread_local 里活过了 `NetStream`，于是 drop 顺序被破坏，
组件模型直接 trap：

```
2: resource has children
```

带探针的两次运行都 trap（`client-e2.log` / `client-d3.log`），去掉探针的 `client-e3.log` **没有** trap
（`grep -c "resource has children"` = 0）。
⇒ `wasi.rs` 现有的字段顺序（`read_ready`/`write_ready` → `input`/`output` → `socket`）是对的；
**任何诊断用的子 pollable 必须在父流之前 drop**。

---

## 10. 未验证 / 开放

1. **本机现在拿不到稳定红**（§8 的 8/8）。V27 的 red 需要一个「首个飞行包 >10s」的条件，
   而那个条件在本机是瞬态的；要固化回归判据，建议用延迟对端（正向/负向都能造）而不是真服务端。
2. Lead 观测到的「外层 ClientHello +3.08s → 服务端收到 VLESS 头 +10.0s」那个 ~7s 缺口，
   我没有抓到现场。按我已有的数据（§3.3、§3.4、§5.2），更像同一次瞬态里**服务端/链路晚发**，
   而不是客户端内部延迟；但这一条**未验证**，需要一次带 `XT_DIAG` 埋点的现场才能定论。
3. 「服务端首个飞行包偶尔 17–19s」的**根因**（本机出口/dest 路径）没有继续追 ——
   它不在本工程代码范围内；如果要追，用 `--mode forward` 夹代理 + 抓 `route`/dest 直连对照。
4. `e2e-test.sh` 保持红，未改（铁律 2）。
