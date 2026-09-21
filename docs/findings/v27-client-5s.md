# V27-E：那「精确 5.000s」**不在客户端任何一步**（在官方服务端、且与客户端实现无关）

> 任务：`task-22`。写者：`v24-integrator`（接受 lead 转派）。复现：`./scripts/v27-client-5s.sh`。
> 口径：只写实测到的；没测到的写「未验证」。

## 0. 一句话结论

**5s 不在 wasm 客户端里。** 客户端在收到 curl 首包后**立刻**把它写进隧道（实测 +0.27s，
回环代理实测字节 **0.3ms 内上线**），然后干等 ~5.0s 才从隧道读到第一个回应。
而这 5s 在**官方 Xray 服务端**上，并且是「**服务端进程启动之后第一条连接**」的一次性代价：

* **官方 Xray 客户端**打同一个服务端，第 1 个请求也是 **5.26s**，第 2/3 个 0.23–0.31s；
* **`--no-flow` + 空 flow 服务端**（wasm 客户端）仍是 **5.26s**；
* **官方客户端 + 空 flow** 仍是 **5.25s**；
* 用**纯本地目标**（127.0.0.1:18080，无 DNS、无公网）也一样；
* 回环代理上，服务端发出的第一个记录出现在客户端应用记录上线之后 **+5.002s**。

⇒ **与 Vision 无关**（我们的 Vision 客户端路径被官方客户端/`--no-flow` 双向对照排除），
**与客户端实现无关**。V27-E 原来「停顿在客户端内部」的前提，被本次实测推翻。

---

## 1. 客户端内部时间戳（wasm，`XT_DIAG=1`）

源码树复制到 `$WORK/src`（**仓库 `crates/**` 只读**），在 `serve_inner` / `open_tunnel` /
`relay_bidirectional` 两个方向，以及 `wasi.rs` 的读写就绪侧打点后编译（埋点 sha256
`f0427a51…`，483706 B）。一次典型请求（回环代理那组，`--server` 指向代理）：

```
[XDIAG] cli conn_start            t=+0.000
[XDIAG] cli socks_request_read    t=+0.580
[XDIAG] cli open_tunnel_begin     t=+0.580
[XDIAG] cli outbound_tcp_connected t=+0.581
[XDIAG] cli reality_handshake_done t=+0.582      ← 握手完成（服务端同毫秒读 Finished）
[XDIAG] cli vless_header_queued   t=+0.582
[XDIAG] cli tunnel_ready          t=+0.582
[XDIAG] cli socks_granted         t=+0.582      ← SOCKS 放行
[XDIAG] cli relay_begin           t=+0.582
[XDIAG] client:a2b task_start     t=+0.582
[XDIAG] client:a2b first_read     t=+0.582  n=78   ← 入站首包读到了
[XDIAG] client:a2b first_write    t=+0.582  n=78   ← 已经写进隧道（无停顿！）
[XDIAG] client:b2a task_start     t=+0.583
[XDIAG] wasi read_pending         t=+0.583
   ……（客户端在这里干净地等待）……
[XDIAG] client:b2a first_read     t=+5.586  n=113  ← 5.0s 后才等到隧道回应
[XDIAG] client:b2a first_write    t=+5.586  n=113  ← 立刻交给 SOCKS 侧
```

判据对应的三个量：`socks_granted → a2b first_write` = **0.000s**；
`a2b first_write → b2a first_read` = **5.004s**；`b2a first_read → b2a first_write` = **0.000s**。

**所以「入站读没被唤醒」也被排除**：入站首包在 +0.582 就被读走了（`a2b first_read`），
而且立刻写进了隧道。停顿发生在「写完 → 等隧道回应」之间，是**对端**的时间。

写侧就绪计数（lead 提示的 `check_write>` 快路径）同样干净：首连的
`wasi write_enter` / `write_fast_path` / `flush_enter` 都紧挨着出现，
**没有** `write_check_write_zero` / `write_pending_on_zero` 的堆积。

## 2. 回环 TCP 代理：字节什么时候真的上线

客户端 `--server 127.0.0.1:8644`（代理）→ 官方服务端 `:8643`。代理给每个方向的字节打绝对时间戳：

```
1789904093.035950 c2s #1 538B  gap=0.000          ← ClientHello
1789904093.291353 s2c #1 2182B gap=0.255          ← 服务端 ServerHello + 飞行包
1789904093.291973 c2s #2 58B   gap=0.256          ← 客户端 Finished
1789904093.292293 c2s #3 420B  gap=0.000          ← 应用记录（VLESS 头 + 请求）：**立刻上线**
1789904098.293371 s2c #2 450B  gap=5.002          ← 服务端第一个回应：**+5.002s**
1789904098.293724 s2c #3 62B   gap=0.000
1789904098.295372 s2c #4 294B  gap=0.002
```

客户端的应用记录在**握手完成后 0.3ms**就上了线；服务端的第一个回应晚了 **5.002s**。

## 3. 对照矩阵：把「客户端实现」「Vision」「DNS/公网」三个变量都去掉

每次**冷启动服务端**，目标是**本机 127.0.0.1:18080** 的 HTTP 服务（无 DNS、无公网）：

| 用例 | 客户端 | flow | req1 ttfb | req2 | req3 |
|---|---|---|---|---|---|
| A | wasm（本工程） | vision | **5.327** | 0.230 | 0.288 |
| B | **官方 Xray 26.3.27** | vision | **5.256** | 0.313 | 0.230 |
| C | wasm | `--no-flow`（服务端 flow 空） | **5.259** | 0.260 | 0.226 |
| D | **官方 Xray** | flow 空 | **5.252** | 0.250 | 0.219 |

另一次带外网目标（`https://example.com`）的官方客户端：req1 **5.662**、req2 0.572。

四个用例的第 1 个请求全部 ~5.25s，第 2/3 个全部 <0.35s —— 而用例 B/D 的运行**完全不含本工程
的任何代码**。所以这 5s 既不是我们的客户端，也不是 Vision flow。

## 4. 服务端侧：一次性的，不是「冷客户端」

* 服务端进程**同一个**、客户端已经预热（用例 A 的 req2/req3）时，请求是 0.23s；
* 反过来说，**每换一次服务端进程**，第一个请求必然 ~5.25s（A/B/C/D 四次独立冷启动全部如此）；
* 把服务端 `dest` 换成**本机 TLS 服务**（`openssl s_server`，去掉「拨号远程 dest」）后：
  req1 **6.79s**、req2 0.0037s、req3 0.0037s —— **dest 拨号不是唯一原因**，一次性代价仍在；
* 服务端日志里 `proxy/vless/inbound: firstLen = …` 的**行时刻**比客户端字节上线晚 5.002s，
  说明是服务端**读到/处理**这条记录晚，而不是客户端发得晚。

**已排除**：客户端任意一步（§1）、Vision flow（§3 C/D）、出网/目标 DNS（§3 本地目标）、
「dest 是远程站点」单独作为充分原因（§4）。
**未定位**：官方 Xray 服务端内部**具体哪一步**吃掉这 5s（手上只有二进制，没有 Xray 源码）。
最像的形状是 REALITY 的 post-handshake 记录读取：服务端日志显示它在握手后读
`postHandshakeRecord`（450/62 字节），而客户端把「Finished + 首个应用记录」**合并在同一
TCP 突发**里发出（代理 §2：`#2 58B` 与 `#3 420B` 相隔 0.3ms）；若服务端只对「之后新到达
的字节」收通知，就会等一个 5s 级的兜底。**这条只是最像，未验证。**

## 5. 对 V27 的直接影响（给公告板的更正）

* `docs/findings/v27-five-second.md`（V27-D）把「服务端 `readClientFinished` → `firstLen`
  间隔 5.001s」读成「客户端 5s 后才把应用记录发出去」。**本次回环代理实测证明那是误读**：
  客户端的应用记录在握手完成后 0.3ms 就上了线，5s 是**服务端处理**的间隔。
* V27-B 里「官方 Xray 客户端 → 冷启动官方服务端 ✅」只断言了**握手成功**，没有测 **TTFB**；
  本次补测（§3 B/D）说明官方客户端同样吃这 5s。所以「冷/热」与「客户端实现」都不是这条
  现象的解释变量，**服务端进程的一次性初始化**才是。
* `e2e-test.sh` 的 10s 握手死线与此无关（那是握手层的），这 5s 发生在握手**之后**。

## 6. 未验证 / 边界

* 服务端内部的具体步骤：**未验证**（没有 Xray 源码；只做到「不是客户端、不是 Vision、
  不是目标 DNS、不是单纯的 dest 拨号」）。
* 本轮源码快照取自**当前工作树**（含队友未提交改动：`main.rs`/`server.rs`/`reality.rs`），
  git HEAD `14ba709`；埋点产物 sha256 `f0427a51…`。仓库 `crates/**` **未被修改**。
* 「把 Finished 与首个应用记录错开发送是否能避开 5s」**未验证** —— 这会是验证 §4 那个
  形状假设的最小实验（如果成立，规避手段在客户端一行；否则只能在服务端修）。

## 7. 复现

```sh
./scripts/v27-client-5s.sh              # 复制源码→打埋点→编译→四组对照+回环代理
V27E_SKIP_BUILD=1 ./scripts/v27-client-5s.sh   # 复用已编好的带埋点产物
```

端口：服务端 8643 / wasm SOCKS 1091 / 官方客户端 SOCKS 1092 / 本地目标 18080 / 代理 8644。
产物与日志在 `/tmp/v27e`（`log/A..D.*`、`log/P.proxy`、`frozen/client.bin`）。
