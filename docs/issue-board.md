# 问题公告板（V24 / V27 / 指纹特性）

> **写者：只有 lead。** 调查者各自写 `docs/findings/<slug>.md`（一人一文件，不冲突），
> 再把结论 `send_message` 给 lead 合并到这里。
> **合并门槛**：每条结论必须带可复现命令 + 原始输出；没跑过的写「未验证」，不许写成结论。
> **这块板的存在意义**：让**至少一个后端**（`v24-integrator`）能只读这一页就知道
> 「哪些假设已被排除、哪些已复现、现在该修什么」，不必重走前八轮。

---

## 0. 今日（v0.7.0 现场）新确认的两条事实

| # | 事实 | 证据 |
|---|---|---|
| F1 | **V24 的原判据在本机跑不了**：`scripts/e2e-spin-test.sh` 读 Linux `/proc/<pid>/stat`；本机是 macOS（无 `/proc`，沙箱禁 `ps`/`top`），且 `docker info` 无 daemon（`docker` 二进制在但跑不起来） | `ls /proc/self/stat` → 无；`docker info` → 不可用 |
| F2 | **V24 的替代判据已可用**：`scripts/v24-cpu-probe.py` 用 `os.wait4()` 的 rusage 测被测进程 CPU。已排除两条错路：`proc_pid_rusage()`（忙进程只报 0.068s/3s，不可信）、`/usr/bin/time -l` 包装（kill `time` 不杀子进程 → 管道不关挂死）。**⚠️ 本机绝对值偏低：2.0s 纯忙循环只报 1.09s（55%）**，所以判据必须用「同命令 idle vs hover 的比值」，不能用绝对 80% 阈值 | `scripts/v24-cpu-probe.py` 文件头校准说明 + 实测输出 |

**推论（重要，影响 10 个人的分工）**：在拿到可信判据之前，任何「修好了 V24」的说法都是不可证伪的。
所以 V24 这条线的**第一优先级是把判据做实**（用真实现场跑出触发/不触发两组数字），
第二优先级才是根因假设。

## 1. V24 · 服务端自旋（CPU 打满一核、accept 被饿死）

* **症状**：有过连接 + 往流上写过 + 一批连接悬停 → 跑满一核且不恢复；单线程运行时下 accept 被饿死。
* **权威复现脚本**：`scripts/e2e-spin-test.sh`（wasm 服务端 + 官方 Xray 客户端 + N 条 CONNECT 到不可达目标 10.255.255.1:5226 悬停）。
* **本机今日实测（用替代判据，最小探针）**：
  * `stream_spin_probe`（只读）idle → 1.1%
  * `stream_spin_probe_rw`（读写交替）idle 1.1% / hover(8 连接) 2.3%
  * ⇒ **最小探针形状在本机不复现自旋**。自旋可能需要完整协议现场（含真实握手写入），
    或只在特定时序/连接数下出现 —— 这本身是一条待证事实。
* **已排除/已撤回**（详见 `docs/verification-log.md` V24 全节，八轮）：见该节列出的 6 个已排除假设、
  3 次被撤回的过宽结论、以及「按机制写的修复无效」「Pending 后丢弃重建 WaitFor 无效」
  「用 wstd 类型替掉手写 Ready 不是 drop-in」三条负面结果。
* **状态**：`未修`。线上靠 `livenessProbe` 约 60 秒重启兜底。

## 2. V27 · 首个隧道连接 TTFB ≈5.2s（**三次归因被逐步推翻，最终定位在官方 Xray 服务端**）

### 最终结论（`v24-integrator`，task-22，四组对照 + 回环代理）

**这 5s 是「官方 Xray 服务端进程启动后的第一条连接」的一次性代价，与我们客户端实现和 flow 都无关。**

| 组 | 客户端 | 服务端 | req1 | req2 | req3 |
|---|---|---|---|---|---|
| A | wasm + vision | 官方 | **5.327s** | 0.230 | 0.288 |
| B | **官方 Xray 客户端** + vision | 官方 | **5.256s** | 0.313 | 0.230 |
| C | wasm `--no-flow` | 官方（空 flow） | **5.259s** | 0.260 | 0.226 |
| D | 官方客户端 | 官方（空 flow） | **5.252s** | 0.250 | 0.219 |

客户端埋点（`XT_DIAG`，源码副本 /tmp，仓库 `crates/**` 未改）：
`socks_granted +0.582 → first_read +0.582 → first_write +0.582`（**0.000s**）→ `b2a first_read +5.586`。
回环 TCP 代理复核：客户端应用记录在**握手完成后 0.3ms 就上线**；服务端第一个回应晚 **+5.002s**。
写侧就绪计数干净（无 `write_check_zero` 堆积）。

**⇒ V27-D 的读法被推翻**：官方服务端日志里的 `firstLen` 是它**处理**该记录的时刻，不是字节到达的时刻；
所以「服务端 5s 后才收到 VLESS 头」应读作「服务端 5s 后才**处理**它」。
**V27-B 的「官方客户端 ✅」也只断言了握手成功、未测 TTFB** —— 补测显示官方客户端同样吃这 5s。

**未验证**：官方服务端内部具体哪一步（无 Xray 源码）。最像的形状是 REALITY post-handshake 读：
客户端把 Finished 与首条应用记录合并在同一突发（相隔 0.3ms），若服务端只对**新到达**字节收通知，
就可能等一个 5s 级兜底。**最小验证实验**：让客户端把首条应用记录与 Finished 错开一点发送，看 5s 是否消失。

### 这条线上一路被推翻的归因（留档，避免重走）

1. ~~「冷服务端 TLS 握手慢」~~ —— 冷首连 ClientHello→ServerHello 仅 276–299ms（直连 dest 对照 231/235ms）。
2. ~~「客户端唤醒/就绪缺陷」~~ —— 原始 WASI `subscribe().ready()` 全程 false ⇒ 当时 socket 上确实没数据；
   心跳 204 拍准点；前序 RST / 前置认证失败都无影响。
3. ~~「5s 在客户端或运行时」~~ —— 本轮四组对照 + 客户端埋点 + 回环代理推翻。

**判据现状**：`e2e-test.sh` 的 flaky 由此解释（官方服务端首连 5s × 客户端 10s 死线）。
已发布的 P0 重试（task-20）正是对它的可用性兜底；**它不是我们代码的缺陷**。

## 3. 指纹特性## 3. 指纹特性（v0.7.0 已发布）· 不是 bug，但边界要知道

`crates/xt-wasm-tls/src/fingerprint.rs`（chrome/plain）。完整边界见 `docs/fingerprint-plan.md`
与 `docs/fingerprint-security.md`，要点：不发 X25519MLKEM768（会触发 HRR 直接握手失败）⇒
纯 X25519 是真实降级；ECH 只是 GREASE 占位；形状等价于「PQ 之前的 Chrome」，版本年代假设未验证。

---

## 4. 待修队列（按优先级）

| 优先级 | 项 | 判据 | 负责 |
|---|---|---|---|
| P0 | V24 判据在 macOS 做实（真实现场 idle vs hover 两组数字） | `scripts/v24-cpu-probe.py` + 现场脚本，两组数字可复现 | `v24-integrator` |
| P0 | V27 出口瞬态导致首连失败 → 客户端**握手超时重试一次** | 仿真瞬态（延迟对端 + 复现 17s 停顿）下重试后成功，且 e2e 断言不动 | task-20 / `v27-wake`（进行中） |
| P1 | `reality.rs` 死线改定时器驱动 | 超时按 10s 生效（现在拖到 18s 才报） | lead |
| P2 | V24 根因 | 修完后 hover/idle 比值与 idle 同级，且 e2e-spin-test.sh 在 Linux 上绿 | `v24-integrator` + 10 路假设 |

## 4.5 V24 裁定与根因候选（`v24-integrator`，task-6）

**裁定：复现**（隔离干净构建，wasm sha256 `99efd472…`）。主判据 `marginal=(cpu@40s−cpu@15s)/25`，1.0 = 一核：

| 场景 | marginal | 原始 |
|---|---|---|
| idle（官方客户端起着、不发请求） | **−0.0001 核** | 0.362→0.359s/40s；重复 0.396s（离散度 0.037s） |
| **hover 300 条 CONNECT→10.255.255.1:5226 悬停** | **1.0862 核** | 38.63s/40s = **96.6%**；重复 35.46s = 88.6% |
| hover 60 条 | 0.0008 | 0.40/0.42s |
| 回落（悬停 12s 后关掉全部 300 条） | **−0.9886** | 25.4s → 0.72s ⇒ 与悬停状态相关，非时间漂移 |
| 功能正对照 curl | idle **200** / hover300 **000**（服务端 Forwarded=0、日志冻住）/ hover60 **200** | held=300、socks_ok=300、lsof_estab=557 |

连接数扫描**非单调**：100/150/200/250 不触发，**256 触发**，270 不触发，300 触发
⇒ 撞并发上限的**竞态**，不是简单阈值。

**根因候选（**已 falsified**，见下）**：`crates/xt-wasm-cli/src/server.rs:517-524` ——
accept 循环在 `live >= MAX_CONCURRENT_CONNS(256)` 时 `sleep(5ms)` 空转等待。
它同时解释：门槛≈256、非单调竞态、永不恢复（已 spawn 的任务被饿死 ⇒ live 永不回落 ⇒ 循环不退出）、
进程内 timer 超时全失效（V24 二十一续）、socket 层探针不复现（没有上限、进不了这段）。

**修完必须三条全过**（一键：`sh scripts/v24-field-test.sh`，`V24_REUSE=1` 已缓存核心场景、秒级复算）：
① hover300 marginal < 0.15；② 悬停期间 curl = 200；③ 回落 marginal < 0.15。

**最小区分实验**：A 把满员等待移进 `spawn_task`（accept 永不停）；B 满员直接 `drop(stream)`。
⚠️ 两者都有代价（A 失去 listen-backlog 背压；B 与既有设计「满了等槽位而不是丢弃」冲突），
必须**一次只改一处**并给出三条判据的前后数字。

### 候选已 falsified（`v27-wake`，task-23，A/B 变体都未修好）

| 判据（门槛 <0.15 / =200 / <0.15） | before `ec442a39` | 变体 A `81db47a4` | 变体 B `94b8f895` |
|---|---|---|---|
| ① hover300 marginal | 0.7045 ✗ | **0.9057 ✗** | **1.5355 ✗** |
| ② 悬停期间 curl | 000 ✗ | **000 ✗** | 200/000/200 ✗（flaky） |
| ③ 回落 marginal | 0.9820 ✗ | **0.9313 ✗** | −0.0177 ✓ |

**决定性反证**：在 accept 循环加每秒迭代计数（跑完已回滚）—— 悬停 300、`live=256` 时
`accept_loop = 313 / 151 / 149 次每秒`（= 5ms 一趟，**真的在睡**，≈0.2% CPU），不是 20k/s。
⇒ **那段背压代码不空转**。变体 B 里 accept 速率被压到 `322→112→44→4 次/秒`（它是被饿住的一方，方向相反）。

**⇒ 闸门 256 是「显现阈值」，不是成因。** 真正热的地方是那 ~256 条服务任务的读等待/反应器
（`before` 同形状下 8s 窗口完成 64 条、18s 窗口只完成 14 条 ⇒ 非线性退化且方差极大），
**在 `xt-wasm-runtime` 层**。下一步（task-24）：用 task-7 那套 `XT_DIAG`（`poll_read` 进入/Pending/数据 +
`Ready::poll` 进出计数 + 心跳）在 `V24_CONNS_A=300` 悬停现场跑一次，看 `poll_read` 是否 ~20,480/s 且每次 Pending。

### 埋点现场结果（task-24 第一步，lead 亲跑，2026-09-20 23:28）

命令：`XT_DIAG=1 V24_CONNS_A=300 V24_W1=5 V24_W2=12 V24_W3A=12 V24_W3B=12 V24_RELEASE_AFTER=6 sh scripts/v24-field-test.sh`
（心跳前缀是 **`[v24wd #]`**，写在 `target/v24-field/<tag>-server.err`；不是 `[v24diag]`）

| 场景 | CPU | 稳态 `sleep`/0.5s | 稳态 read/ready/accept/write |
|---|---|---|---|
| idle-12 | 0.378s | 1 | 全 0 |
| **hoverA-12（300 条）** | **4.551s** | **131–151** | **全 0** |
| hoverB-12（60 条） | 0.509s | 1 | 全 0 |

`hoverA-12-server.err` 原始（未删改）：
`#2 read_top=3937 accept=340 conn_att=167 sleep=53` → `#3 read_top=686 accept=0 conn_att=343 sleep=145`
→ **`#4…#7 每行都是 `read_top=0 read_pend=0 read_empty=0 read_data=0 ready_poll=0 ready_ready=0 ready_pend=0
waitfor_new=0 write=0 flush=0 accept=0 yield=0 sleep=135/147/151 sleep_early=0 | live_waits=0 pollables=513`**
→ `#8 read_top=844 accept=81 conn_to=81`。

**结论（三条，都可复现）**：

1. **「`poll_read` ~20,480/s 且每次 Pending」被 falsified**：300 条悬停的**稳态读/就绪/accept/write 计数全为 0**，
   而 CPU 仍烧到 ~38% 一核（4.551s/12s vs idle 0.378s）。热的不在读路径。
2. 稳态**唯一在增长的计数是 `sleep()` ≈ 275 次/秒**，且 `sleep_early=0`（睡够了才返回）、
   `live_waits=0`（没有任何任务停在 pollable 等待上）而 `pollables=513`。
   ⇒ 热点在 **定时器/sleep 路径**：那 ~300 条待处理连接各自在 `sleep` 驱动的循环里转；
   "读等待被高频重轮询" 的方向作废。
3. **60 条连接完全不复现**（`sleep=1`、CPU 0.509s ≈ idle 档），⇒ 退化对 N 非线性，与 256 闸门吻合。
4. 新症状（尚未解释）：300 条时**诊断心跳任务自己在 t+3.5s 后不再打印**（整个文件只有 8 行），
   而 60 条那轮 23 行打满 11.5s 窗口 ⇒ 反应器饿死的对象不止 accept，连无关任务也停摆。

**task-24 剩余**（未做，勿写成已定位）：把 `SLEEP_CALLS` 埋点**按调用点拆开**
（连接超时等待 / flow-control / 其它），确定这 ~275/s 出自哪一层；定位前不动生产代码。

**旁证阻塞**：`scripts/v24-field-test.sh` 第 4c 段（最小复现器交叉验证）在本机以
`awk: division by zero` 退出码 2 中止，`MINREPRO_DIR` 未设时也应跳过——本轮未修（属测试工程，非 V24 根因）。

### wstd 反应器空转：定位 + 补丁验证（lead，task-24 收尾，2026-09-21）

**采样（新判据：不看 guest，直接看进程）**：hover300 窗口内 `sample <wasmtime pid> 4` —— 3171 个样本里
**2887 个（91%）落在 host 的 `wasi:io/poll` 实现**：
`Host::poll → PollList::poll → wasmtime_wasi2p2 TcpSocket::ready → poll_finish_connect → tokio Registration::poll_ready`。
既不是 guest 代码，也不是阻塞在 syscall。⇒ **空转在 `wstd` 反应器的 `poll()` 循环里**。

**机制**（`wstd 0.6.8`，即当前最新版）：`block_on` 只在 `pop_ready_list()==None && wakers 表非空` 时阻塞；
而 `check_pollables` 唤醒时**只 wake、从不 remove**，注销只发生在 `WaitFor::drop`（且 poll 过 Pending）。
⇒ 只要出现「**孤儿 waitee（任务已消失）+ 该 pollable 永久就绪**」，`poll()` 立即返回、无任务可跑，
循环永不 break：**空转烧核，且进程自己不会退出**。与观测完全自洽（稳态 guest 计数全 0、CPU 38%、
**诊断心跳自己被饿死**）。上游自带注释也承认「poll 里空转」是已知失败模式。

**补丁（实验性）**：把 `wstd 0.6.8` vendor 进仓库 + `[patch.crates-io]`，`check_pollables` 改为**唤醒即摘除**
（边沿语义，被唤醒的活任务下一轮自己重新注册）。代码与论证见 `docs/findings/v24-reactor-spin.md`。

**验证**（`V24_REUSE=0 XT_DIAG=1 sh scripts/v24-field-test.sh`，判据同前）：

| 指标 | before `ec442a39` | 变体 A | 变体 B | **wstd 补丁** |
|---|---|---|---|---|
| ① hover300 marginal | 0.7045 ✗ | 0.9057 ✗ | 1.5355 ✗ | **0.3858 ✗** |
| ② 悬停期间 curl | 000 ✗ | 000 ✗ | flaky ✗ | hoverA 两轮**空**（✗），hoverA-rep=200 |
| ③ 回落 marginal | 0.9820 ✗ | 0.9313 ✗ | −0.0177 ✓ | **0.0035 ✓** |

**裁定：有改善、未解决。** ① 0.7045 → 0.3858（仍 >0.15）。三次重复揭示它是「随机踩进去就永久卡死」：
`hoverA-8=3.94s / hoverA-18=7.80s / hoverA-rep-18=1.14s`（18s 窗口同参数，差 6.8 倍）。
**新判据（廉价、应并入脚本）**：卡死的窗口**诊断心跳被饿死**（8s→2 行、18s→**1 行**），
没卡死的窗口心跳打满（18s→**35 行**、`sleep=1`）。⇒ 「`[v24wd]` 行数」可直接当卡死指示器。

**下一步（未做）**：区分两种残留形态 ——(a) `poll()` 被反复调用并立即返回（guest 侧等待路径；
注意 `connect_addr` 里那条裸 `WaitFor` **不在** `READY_POLLS` 计数内，与「`ready_poll=0`」并不矛盾）；
(b) 单次 `poll()` 调用长时间不返回（wasmtime 的 socket 就绪检查）。建议先给 `connect_addr` 那条等待
加计数 + 超时，再复测同一现场。

**门禁注意**：`crates/xt-wasm-runtime/src/wasi.rs` 里的 `XT_DIAG` 诊断目前带一个 `dead_code` 告警
（`CountedWait` 未构造），会让 `check.sh` 的 `clippy -D warnings` 变红 —— 定稿前要么清掉诊断代码、
要么修掉该告警。`vendor/` + `[patch.crates-io]` 属供应链改动，需决定是否随版本发布。

**罪魁已定位（2026-09-21，lead）**：把悬停目标换成「接受但永不回话」的本地监听器
（`scripts/v24-silent-listener.py`）后空转可稳定复现；在**反应器循环内部**加自打印计数
（`WSTD_DIAG=1`，任务级心跳被饿死也不影响它）后：

| 窗口 | CPU | 任务心跳 | `[v24diag-ready]` | `timeout` / 裸 `WaitFor` |
|---|---|---|---|---|
| hoverA-8 / hoverA-rep-18 | 0.82s / 1.05s | 15 / 35 行 | 0 | 0 |
| **hoverA-18** | **17.60s** | **1 行** | **`tag=read polls=200k/400k`** | 0 |
| **hoverR-18 / -30** | **9.35s / 21.33s** | 18 行（**t+8.5s 后停**） | **`tag=read polls=200k…800k`** | 0 |

⇒ 自旋的是 **`NetStream.read_ready`**（读就绪等待）：反应器 `wasi:io/poll::poll()` 报该 pollable **就绪**，
而 `WaitFor::poll` 里的 `pollable.ready()` 报**不就绪** ⇒ 该任务每次都被唤醒、每次返回 `Pending` 并重新注册，
`block_on` 永不阻塞（`iters≈21k–35k/s`，每轮恰好 1 个就绪），**其它任务全部饿死**。
触发点是「**一批连接同时关闭**」（t=8s 关 300 条，心跳正好停在 t+8.5s），与 256 闸门无因果。
`timeout()`、accept/connect 裸等待均已排除。

下一步：真 wasm 最小探针比对 `poll()` 与 `ready()`（对端关闭/无数据时）判定上游还是我方缓存；
兜底修法（未实现）：`Ready::poll` 连续 N 次「host 说就绪而 `ready()` 说不就绪」就直接放行去做 syscall。
详见 `docs/findings/v24-reactor-spin.md` §8。

**后续（已完成，2026-09-21）：V24 空转已修复。**
罪魁 = `NetStream.read_ready`（读就绪等待）：宿主 `wasi:io/poll::poll()` 报该 pollable **就绪**、
而 `pollable.ready()` 报**不就绪** ⇒ 该任务每次被唤醒都返回 `Pending` 并重新注册，
`block_on` 永不阻塞、以 ~21k–35k 次/秒空转（诊断心跳被饿到只剩 1 行）。

**修法两处合用**（单独任一处都不够）：
1. `crates/xt-wasm-runtime/src/wasi.rs`：`Ready::poll` 兜底 —— 连续 `READY_FUTILE_LIMIT=8` 次
   「被唤醒但 `ready()` 说不就绪」就**放行**，由 `read()/write()` 的返回值（数据/EOF/错误）裁定；
2. `vendor/wstd`（0.6.8 + `[patch.crates-io]`）：反应器 `check_pollables` **唤醒即摘除**。

**验证**（`sh scripts/v24-field-test.sh`，判据同表）：

| 配置 / 场景 | hover300 marginal | 悬停 curl | 回落 marginal | 裁定 |
|---|---|---|---|---|
| 仅 wstd 补丁 · 黑洞 | 0.3858 ✗ | 空 ✗ | 0.0035 ✓ | 未过 |
| 仅兜底 · 黑洞 | rep 14.2s（仍在转） | 200 | **1.8458 ✗** | 仍卡 |
| **合用 · 黑洞（原始场景）** | **0.0179 ✓** | **200 ✓** | **0.0054 ✓** | **不复现** |
| **合用 · 黑洞（复核轮）** | **−0.0036 ✓** | **200 ✓** | **−0.0018 ✓** | **不复现** |
| **合用 · 静默监听器（可达）** | **0.0366 ✓** | 000（256 上限排队，服务端 Forwarded=0） | **0.0684 ✓** | 不复现 |

兜底触发很局部（仅「一批连接同时关闭」的窗口 65/110/254 次，idle/hover/60 条窗口 0 次）；
心跳行数是卡死的直接读数（修复前 1–2 行，修复后 idle 15 / hover 35 / 回落 59 行，均打满窗口）。
**回归**：`e2e-wasm-to-wasm` 5/5 ✓、`e2e-vision` 4/4 ✓、`check.sh` **9/9** ✓。

**定稿待决**：① `vendor/` + `[patch.crates-io]` 是供应链改动（且是修复的一半，不能只删）；
② `XT_DIAG` 诊断当前保留（已加 `#[allow(dead_code)]`，不再让门禁变红），是否随版本发布待定；
③ 是否提交 / 是否出补丁版本。详见 `docs/findings/v24-reactor-spin.md` §8–§10。

### 方法论更正（比结论重要）

此前「最小探针不复现」测的是 `--examples` 编出的**宿主 Mach-O 二进制**（走 `host.rs` 的 1ms 轮询，
**根本没有 WASI pollable**）⇒ 不能代表产品路径。lead 早先那张四探针矩阵同样踩了这条，**其前提作废**。
真 wasm 最小探针在本机 inconclusive（静默悬停 ≈idle；一次 6.22s/6s 离群，重复只有 0.25s）。

## 4.6 P0 重试（`v27-wake`，task-20）已完成

`crates/xt-wasm-cli/src/main.rs`：新增 `REALITY_HANDSHAKE_ATTEMPTS=2` + `HANDSHAKE_TIMEOUT_FLOOR=9s` +
`is_handshake_timeout()`；**仅超时**重试（新 TCP、新 ClientHello），判据用「类别 = `Tls`」∧「本次尝试 ≥9s」
两个独立信号合取（不解析文案）。验收：workspace 全绿 + `check.sh` 9/9；正样本（`--stall-first 1`）
→ 重试后 **200**；负样本（`--stall-first 2`）→ 恰好 2 条 ClientHello、20.025s 失败、错误带两次耗时；
边界（快速回非法 record）→ **0 次重试**；e2e **3 轮 8/8 全绿** + 一轮「靠重试救回红的那步」（8/8，断言未改）。

代价（需写进 README 要点）：失败路径 **~10s → ~20s**、并发槽位最坏占用翻倍、
每次超时失败多发一条短 ClientHello；正常路径不变。
**已知边界**：`≥9s` 是启发式（前提是 TLS 死线 = 10s）⇒ 建议给超时加独立 variant（归 `xt-wasm-tls`）。

## 5. 已复现的问题 / 已排除的假设（由 findings 汇总，lead 维护）

### 已合并的 findings

| 来源 | 判定 | 一句话 | 文件 |
|---|---|---|---|
| V24-09 探针矩阵（lead） | inconclusive（有信号） | 只有**读写交替**随悬停连接数增长（0.6%→2.7% @32），其余三条平；但触发流量本身混入差值，**不足以判自旋**。下一步：**静默窗口**测量 + 规模扫描到 256 | `docs/findings/probe-matrix.md` |

### 方法论教训（写进规矩，避免再犯）

* `v27-cold-warm` 用「同机直连 dest」对照推翻了「冷启动慢」的归因 ⇒ **任何归因都要有同机对照**。
* 本矩阵暴露的坑：**比较 idle 与 hover 时必须保证两边的触发流量相同或为零**，否则差值里混着流量开销。
  `v24-integrator` 的现场脚本请按这条检查自己的两组数字。
