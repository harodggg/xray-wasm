# V24 修复尝试（task-23）：「满员背压空转」候选 —— **falsified**

> 任务：`task-23`。写者：`v27-wake`。
> 写范围：`crates/xt-wasm-cli/src/server.rs`（只改满员背压那段）+ 本文。
> 结论先行：**变体 A 与变体 B 都没有修好，候选作为「V24 根因/修法」被证伪**；
> 但它是**真实症状之一**（accept 在 `live=256` 处永久停摆，curl=000、永不恢复），
> 只是它**不是 CPU 自旋的来源** —— 这一条由新加的 accept 循环诊断直接证明。

---

## 0. 判据与冻结产物（全部实测）

* 命令（**同一条**）：`bash <冻结 rig>/scripts/v24-field-test.sh`，`V24_REUSE=0`、默认窗口
  （W1=8 W2=18 W3A=18 W3B=30，CONNS_A=300 CONNS_B=60，RELEASE_AFTER=8，XT_DIAG=1）。
* 冻结脚本 sha256：`v24-field-test.sh = 0481716c0292ed4d…`、`v24-cpu-probe.py = 78b9bf9d0cc4b517…`
  （均复制进 `target/v24-fix/<变体>/scripts/` 后运行，避免队友在跑的过程中改脚本）。
* 每个变体一份冻结产物（复制进 `target/v24-fix/<变体>/target/wasm32-wasip2/release/` 后由
  `run-local.sh` 加载，`target/` 正被队友重建也不影响）：

| 变体 | wasm sha256（前 16） | 说明 |
|---|---|---|
| `before` | `ec442a392aacaa28` | 当前树、`server.rs` **未改**（对照） |
| `A` | `81db47a49ea83335` | 满员等待移进 `spawn_task`，accept 永不停 |
| `B` | `94b8f89528217f52` | 满员直接 `drop(stream)` |
| `diag`（诊断，非判据） | `bc7937947e4fe9ca` | `before` + accept 循环速率埋点，只跑短窗口 |

参照：lead 给的基线（**另一份**冻结产物 `99efd472c1ed6f78`，窗口 15/40）是
hover300 marginal **1.0862**、curl **000**、回落 **−0.9886**。

---

## 1. 三条判据：前后对照

| 判据 | 门槛 | before | **变体 A** | **变体 B** |
|---|---|---|---|---|
| ① hover300 `marginal`（核） | `< 0.15` | **0.7045** ✗ | **0.9057** ✗ | **1.5355** ✗ |
| ② 悬停期间 `curl` | `= 200` | **000** ✗（三次：—/000/000） | **000** ✗（三次：—/—/000，curl 到窗口结束都没返回） | **200/000/200** ✗（flaky，不是稳定 200） |
| ③ 回落 `marginal`（核） | `< 0.15` | **0.9820** ✗ | **0.9313** ✗ | **−0.0177** ✓ |
| 旁证：`lsof_estab_lines` | — | 557 | 600 | 512 |

原始表格（同一条命令、同一份冻结产物）：

```
########## before (ec442a392aacaa28) ##########
│ idle                    0.440177s  0.395172s   -0.0045 │
│ hover 300  conns        4.811461s 11.856062s    0.7045 │
│ hover 300（重复）              —  13.347935s        —  │
│ hover 60   conns        0.491831s  0.431282s   -0.0061 │
│ 回落（关连接后）        14.446297s 26.229901s    0.9820 │
│ 功能正对照 curl：idle=200 hoverA=000 hoverB=200         │

########## A (81db47a49ea83335) ##########
│ idle                    0.373224s  0.373478s    0.0000 │
│ hover 300  conns        7.316825s 16.373731s    0.9057 │
│ hover 300（重复）              —  17.094171s        —  │
│ hover 60   conns        0.471033s  0.446512s   -0.0025 │
│ 回落（关连接后）        17.341746s 28.517595s    0.9313 │
│ 功能正对照 curl：idle=200 hoverA=（空） hoverB=200      │

########## B (94b8f89528217f52) ##########
│ idle                    0.421216s  0.380008s   -0.0041 │
│ hover 300  conns        1.066873s 16.421384s    1.5355 │
│ hover 300（重复）              —   0.977130s        —  │
│ hover 60   conns        0.488395s  0.514523s    0.0026 │
│ 回落（关连接后）        0.886199s  0.673792s   -0.0177 │
│ 功能正对照 curl：idle=200 hoverA=000 hoverB=200         │
```

**两条都不修好**：① 两个变体都远高于 0.15（甚至比 before 更高）；② A 完全没恢复
（curl 到窗口结束都没返回），B 只有 2/3 次是 200（且靠丢弃连接换来）。

---

## 2. 决定性反证：自旋**不在** accept 循环里（新证据）

给 `server.rs` 的 accept 循环加了 `XT_DIAG=1`（默认关）的每秒迭代计数。
它在 `/tmp`… 不对，它在被测服务端的 stderr（`work-*/hoverA-*-server.err`）：

**原代码（before），悬停 300 条、`live=256` 时：**

```
[v24diag] accept_loop=313 次/1.003s（live=256 max=256）
[v24diag] accept_loop=151 次/1.006s（live=256 max=256）
[v24diag] accept_loop=149 次/1.006s（live=256 max=256）
```

`while live >= MAX { sleep(5ms) }` 的真实速率是 **150–313 次/秒**（≈ 200 次/秒 = 5ms 一趟），
即这个循环**确实在睡**，CPU 占用约 **0.2%**。
⇒ 「满员背压空转把一核打满」这个说法**不成立**：它不空转。

**变体 A（accept 永不阻塞）时：**

```
[v24diag] accept_loop=302 次/3.215s（live=300 max=256）
```

accept 循环把 300 条全收下来了（`lsof_estab_lines` 557→600），**live=300**；
但同窗口服务端日志只有 **1** 条 `outcome=`。⇒ 收得进来，但**任务几乎不推进** ——
力气根本不在 accept 上。

**变体 B（满员丢弃）时：**

```
[v24diag] accept_loop=322 次/1.000s（live=256 max=256）
[v24diag] accept_loop=112 次/1.162s（live=256 max=256）
[v24diag] accept_loop= 44 次/1.178s（live=256 max=256）
[v24diag] accept_loop=  4 次/1.231s（live=256 max=256）      ← 速率一路衰减
```

`drop=` 224–225 次，`live` 钉在 256。注意这条**方向**：accept 循环的速率从 322/s
被压到 **4/s** —— 它是被自旋**饿住**的一方，不是自旋的源头。
（若自旋就在这个循环里，速率应该是 ~20,000/s 且恒定。）

---

## 3. 那自旋在哪：任务集 / 反应器（超出 server.rs 写范围）

同窗口服务端日志的 `outcome=` 条数（任务真正完成的次数）：

| 变体 | hoverA-8（8s 窗口） | hoverA-18（18s 窗口） |
|---|---|---|
| before | 64 | 14 |
| A | 1 | 1 |
| B | 258 | 1 |

* 同一份产物、同一条悬停形状，**8s 窗口能完成 64 条，18s 窗口只完成 14 条**；
  B 同参数两次跑出 258 与 1。⇒ 随并发任务数**非线性退化**，且方差极大。
* 256 条服务任务全部停在「读 VLESS 请求头」（悬停客户端不发数据），
  每个任务各自有读等待；CPU 却打满 —— 这与 V24 历轮结论一致：
  **热循环是流的读等待被高频重轮询**，而不是任何 accept/backpressure 代码。
* 因此根因在 `xt-wasm-runtime`（pollable / reactor / waker）那一层 ——
  **本次任务的写范围明确排除它**，需要由该层负责人接手。

**给下一手的建议（最小、可判定）**：用 `task-7`（`docs/findings/v27-wake.md` §9）那套
`XT_DIAG` 埋点（`poll_read` 进入/Pending/读到数据 + `Ready::poll` 进出计数 + 心跳），
在 `V24_CONNS_A=300` 的悬停现场跑一次，看：
* `poll_read` 的每秒次数是不是 ~20,000（V24 历轮测到过 20480/s）；
* 若是，且每次都返回 Pending ⇒ 就是「有人在高频唤醒它」，继续查 wstd reactor 的
  `wakers` 映射里是否有**永久就绪的 pollable**（例如 listener 在有 backlog 时恒就绪、
  或某个已消费的流 pollable 没有重新订阅）。

---

## 4. 结论与建议

**falsified**：`server.rs:517-524` 的满员等待**不是** V24 的 CPU 根因，改掉它也修不好。

| 说法 | 判定 | 依据 |
|---|---|---|
| 门槛 ≈ 256 | ✅ 成立 | `live=256 max=256`（diag 多次） |
| accept 因此停摆、curl 进不来 | ✅ 成立 | curl=000、`lsof_estab_lines=557`（300 客户端 + 257 = 256 已收 + 探针） |
| 永不恢复 | ✅ 成立 | 原代码 accept 停在 256；A 收满 300 也只完成 1 条 |
| **它就是 CPU 自旋（空转）** | ❌ **不成立** | 循环真实速率 **150–313 次/秒**（≈0.2% CPU），不是 20k/s |
| 改掉它就能修好 | ❌ **不成立** | A：0.9057 核 + curl 无响应；B：1.5355 核 + curl 200/000/200 |

* 变体 B 的额外代价（与既有设计冲突，实测确认）：悬停期间**丢弃了 224–225 条**连接
  （`/server] 并发已满（256），丢弃一条新连接`），k8s `tcpSocket` 探针会一起被丢 ⇒
  「探针失败触发重启」。它换来的只是 flaky 的 curl=200，**不值得采纳**。
* 变体 A 的额外代价：没有 listen-backlog 背压，`live` 随接受数无界增长
  （实测 300 → 任务几乎不推进，`lsof_estab_lines` 600），比 before 更差。
* `crates/xt-wasm-cli/src/server.rs` **已回滚到 HEAD**（诊断与两个变体都不留在代码里）；
  需要诊断时按 §2 的三行 patch 重新加。

**给 lead 的决策点**：V24 的下一步不应再投在 accept/backpressure 上，而应回到
`xt-wasm-runtime` 的 reactor/waker（见 §3 的最小实验）。本次结论同时说明：
「闸门在 256」只是**显现阈值**，不是**成因**。

---

## 5. 复现命令

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh
export XW_XRAY_BIN=$XW_WS/.scratch/xray-server/xray

# 冻结 rig（脚本 + 产物都在 target/ 下，不受队友重建影响）
for v in before A B; do mkdir -p target/v24-fix/$v/{scripts,target/wasm32-wasip2/release}; done
for v in before A B; do cp scripts/v24-field-test.sh scripts/v24-cpu-probe.py scripts/env.sh \
    scripts/run-local.sh target/v24-fix/$v/scripts/; done
# 把对应变体的 xt-wasm-cli.wasm 放进 target/v24-fix/$v/target/wasm32-wasip2/release/

# 同一条命令、同一份冻结产物
V24_WORK=$PWD/target/v24-fix/work-before V24_REUSE=0 XT_DIAG=1 \
  bash target/v24-fix/before/scripts/v24-field-test.sh
```

诊断补丁（`run_server` 的 accept 循环内，`XT_DIAG=1` 才打印）：

```rust
let diag = std::env::var_os("XT_DIAG").is_some();
let iters = Rc::new(Cell::new(0u64));
let last = Rc::new(Cell::new(Instant::now()));
// loop 内、accept 之后与 sleep 之前各调用一次：
//   iters += 1; if last.elapsed() >= 1s { eprintln!("accept_loop={} live={}", iters, live.get());
//                                   iters = 0; last = Instant::now(); }
```
