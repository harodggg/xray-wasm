# V24 定位：空转发生在 `wstd` 反应器的 host `poll()`（不是读路径）

作者：lead · 2026-09-21 · 现场：`XT_DIAG=1 V24_CONNS_A=300` 悬停（`scripts/v24-field-test.sh`）

## 1. 先被推翻的旧假设

板子 §4.5 原来的方向是「~256 条服务任务的读等待被高频重轮询（`poll_read` ~20,480/s）」。
**falsified**：300 条悬停的稳态里，guest 侧**所有**计数都为 0。

`target/v24-field/hoverA-12-server.err`（原始，未删改）：

```
#2 read_top=3937 read_pend=868 read_empty=681 read_data=2387 ready_poll=4619 ready_ready=3750 ready_pend=868 write=681 flush=681 accept=340 conn_att=167 sleep=53  | live_waits=172 pollables=513
#3 read_top=686 read_pend=0 read_empty=0 read_data=686 ready_poll=686 ready_ready=686 ready_pend=0 write=0 flush=0 accept=0 conn_att=343 sleep=145 | live_waits=0 pollables=513
#4 read_top=0 ... write=0 flush=0 accept=0 yield=0 sleep=149 sleep_early=0 | live_waits=0 pollables=513
#5 #6 #7 同 #4（sleep=135/147/151）
#8 read_top=844 accept=81 conn_to=81（窗口切换时的新一轮风暴）
```

同窗口 CPU：`hover300 = 4.551s / 12s`（≈38% 一核），而 `idle = 0.378s`、`hover60 = 0.509s`。
即：**CPU 在烧，但 guest 一条路径都没走**（读/写/accept/就绪/超时/yield 全 0）。

## 2. 决定性采样：100% 时间片在 host `poll()` 里

`sample <wasmtime pid> 4`（hover300 窗口内，pid 96199，3171 个样本全在主线程）：

```
+ 3171 wasmtime_fiber_start → ... → handle_guest_call → Func::call_unchecked_raw
+  3171 ??? (JIT)
+   ... → 2887 StaticHostFn wasi2io/poll Host::poll cabi_entrypoint
+     → wasmtime_wasi_io poll impls Host::poll / PollList::poll
+     → wasmtime_wasi2p2 tcp TcpSocket::ready
+     → tcp TcpSocket::poll_finish_connect
+     → with_ambient_tokio_runtime → tokio TcpStream start_connect
+     → tokio Registration::poll_ready / park::wake_by_ref / context::defer
```

→ 2887/3171 ≈ **91% 的样本落在 host 的 `wasi:io/poll` 实现里**，每轮都在对全部 pollable
（`pollables=513`）做 `ready()` 检查，其中一大批是 `start_connect` 后未完成的 TCP socket。
不是阻塞在 syscall，而是**在 poll 循环里反复进出**。

## 3. 机制（由 `wstd 0.6.8` 源码 + `block_on` 结构推定，且与观测完全自洽）

`block_on`（`wstd/src/runtime/block_on.rs`）：

```rust
loop {
    match reactor.pop_ready_list() {
        None if reactor.pending_pollables_is_empty() => break,   // ← 唯一的出口
        None => reactor.block_on_pollables(),                     // 阻塞 poll
        Some(runnable) => { ... }
    }
}
```

`reactor.check_pollables()`（`wstd/src/runtime/reactor.rs`）唤醒逻辑：

```rust
for waker in ready_wakers { waker.wake_by_ref() }   // 只 wake，**从不 remove**
```

而上游只在 `WaitFor::drop`（且 poll 过 Pending ⇒ `needs_deregistration`）时 `deregister_waitee`。
于是「**任务的 waitee 成了孤儿（任务已消失）、而该 pollable 永久就绪**」时：

1. `pop_ready_list()` → `None`（没有可运行任务）；
2. `pending_pollables_is_empty()` → **false**（孤儿 waitee 还在表里）⇒ 不 break；
3. `block_on_pollables()` → `poll(targets)` 因那个永久就绪的 pollable **立即返回**；
4. 唤醒一个已经不存在的任务的 waker ⇒ 什么也没有被调度；回到 1。

⇒ **死循环**：CPU 烧满、guest 侧任何计数都不动、连诊断心跳（`sleep(500ms)` 的任务）都拿不到
时间片（`hoverA-12` 整个文件只有 8 行心跳，而 60 条那轮 23 行打满 11.5s 窗口）。
进程也不会自己退出（表非空 ⇒ `break` 不可达）。

这也解释了「256 是显现阈值而非成因」：只有并发被顶到容量上限、连接/任务开始被丢弃时，
才会出现大量孤儿 waitee + 永久就绪 pollable 的组合；此前 `before` 的 8s 窗口完成 64 条、
18s 窗口只完成 14 条（非线性 + 方差极大）正是「偶尔踩进空转、踩进去就再也不出来」。

## 4. 补丁（实验性，`vendor/wstd` + `[patch.crates-io]`）

上游最新就是 0.6.8（docs.rs 确认），没有可升级版本，因此把 0.6.8 源码 vendor 进仓库并打最小补丁：
`check_pollables` 改为**唤醒即摘除**（边沿语义）：

```rust
for index in ready_indexes {
    if let Some(waitee) = indexed_waitees.get(index as usize) {
        if let Some(waker) = wakers.remove(waitee) {
            waker.wake_by_ref();       // 摘除后再唤醒
        }
    }
}
```

正确性论证：被唤醒的**活**任务会被 `wake_by_ref` 调度进 ready list，`block_on` 下一轮必定先
`pop_ready_list()` 执行它，若仍 Pending 则由 `WaitFor::poll` → `ready()` 重新注册 ⇒ 不丢唤醒；
**孤儿** waker 被永久摘除 ⇒ 表最终变空、循环可 break（或正确阻塞）。上游自带注释也承认
「poll 里空转」是已知失败模式（`subscribe_multiple_durations` 的注释），本补丁是同一类问题的修法。

## 5. 验证结果：有改善，**未解决**（不得写「已修」）

命令：`V24_REUSE=0 XT_DIAG=1 sh scripts/v24-field-test.sh`（默认窗口 W1=8 / W2=18 / W3A=18 / W3B=30，判据同前）

| 指标 | before `ec442a39` | 变体 A `81db47a4` | 变体 B `94b8f895` | **wstd 补丁** |
|---|---|---|---|---|
| ① hover300 marginal（门槛 <0.15） | 0.7045 ✗ | 0.9057 ✗ | 1.5355 ✗ | **0.3858 ✗** |
| ② 悬停期间 curl（=200） | 000 ✗ | 000 ✗ | flaky ✗ | hoverA 两轮**空**（✗）、hoverA-rep=200 |
| ③ 回落 marginal（<0.15） | 0.9820 ✗ | 0.9313 ✗ | −0.0177 ✓ | **0.0035 ✓** |

原始 `CPU_SECONDS`（`target/v24-field/report.txt` 同轮）：

```
idle   : 0.414767(8s)  0.417114(18s)  0.409715(rep)
hoverA : 3.944320(8s)  7.802394(18s)  1.135766(18s rep)     ← 同参数三次，差 6.8 倍
hoverB : 0.495790(8s)  0.526878(18s)
hoverR : 1.106004(18s) 1.148456(30s)                        ← 回落 marginal 0.0035 ✓
```

**关键新判据**：同一轮里，把「卡死窗口」和「没卡死窗口」放在一起看，`[v24wd]` 心跳行数完全分离：

| 窗口 | CPU | 心跳行数（0.5s/行） |
|---|---|---|
| hoverA-8 | 3.94s / 8s | 2 |
| hoverA-18 | 7.80s / 18s | **1** |
| hoverA-rep-18 | 1.14s / 18s | **35**（打满 17.2s 窗口，`sleep=1`） |

⇒ 卡死时连诊断心跳任务都拿不到时间片；没卡死时一切正常。**「心跳行数」可作为现场脚本的廉价卡死指示器。**

⇒ 补丁把 marginal 从 0.70 压到 0.39（≈减半），但①仍不过关：空转没有被消除，只是触发概率/严重度下降
（三次里一次健康、两次卡死）。**因此本补丁目前只能算「缩小触发面」，不能算修复。**

## 6. 下一步（未做）

1. 区分两种残留形态：
   (a) `poll()` 被反复调用且每次立即返回 ⇒ 某个**活**任务的等待无法推进。
       注意 `crates/xt-wasm-runtime/src/wasi.rs::connect_addr` 用的是**裸 `WaitFor`**
       （`AsyncPollable::new(socket.subscribe()).wait_for().await`），**不计入 `READY_POLLS`**
       —— 所以「`ready_poll=0`」并不能排除 (a)。
   (b) 单次 `poll()` 调用长时间不返回 ⇒ wasmtime 侧 socket 就绪检查（`poll_finish_connect`）的问题。
2. 建议的判别实验：给 `connect_addr` 那条等待加计数与超时（并让超时可配），在同一现场复测；
   若 `ready_poll/connect_wait` 在卡死窗口里飙高 ⇒ (a)；仍全 0 ⇒ (b)。
3. 若判为 (b)，则考虑给该路径加独立超时/退避，或向 wasmtime 报告（`poll_finish_connect` 在
   connect 挂起时的就绪语义）。

## 8. 罪魁已定位

方法：在**反应器循环内部**（`vendor/wstd/src/runtime/block_on.rs`，`WSTD_DIAG=1`）以及每条等待路径上
加「自己打印」的计数（`Ready::poll` 的 Pending 分支带标签、`timeout()`、裸 `WaitFor`）——
因为这些打印发生在空转循环里，**任务级心跳被饿死也不影响它们**。

命令：`V24_REUSE=0 XT_DIAG=1 WSTD_DIAG=1 V24_HOVER_TARGET=127.0.0.1:5226 sh scripts/v24-field-test.sh`
（悬停目标换成 `scripts/v24-silent-listener.py`：接受但永不回话 ⇒ connect 立刻成功、随后是读等待）

| 窗口 | CPU | 任务心跳行数 | `[v24diag-ready]` | 其它自打印 |
|---|---|---|---|---|
| hoverA-8 | 0.819s | 15 | 0 | 无 |
| hoverA-rep-18 | 1.050s | 35 | 0 | 无 |
| **hoverA-18** | **17.602s** | **1** | **`tag=read polls=200000, 400000`** | 无 |
| **hoverR-18 / hoverR-30** | **9.349s / 21.329s** | 18（**t+8.5s 后停止**） | **`tag=read polls=200k…800k`** | 无 |

* `timeout()` 与裸 `WaitFor`（accept / connect / listen）**一次都没打印** ⇒ 排除这三条路径。
* `tag=read` 就是 `NetStream.read_ready`（`Ready{tag:"read"}`）。
* 打印间隔 200k 次：hoverA-18 到 400k、hoverR-30 到 800k ⇒ 与反应器 `iters≈21k–35k/s` 同量级吻合。
* `ready_idx == poll_calls`（每轮恰好 1 个就绪）⇒ 每轮唤醒的**就是**这个读等待，它每次 poll 都返回 `Pending`。

**机制**：反应器的 `wasi:io/poll::poll()` 报该读 pollable **就绪**，而同一次 `WaitFor::poll` 走的
`pollable.ready()` 报**不就绪** ⇒ `Ready::poll` 一直 `Pending` 并重新注册 waker ⇒
`block_on` 永不阻塞、以 ~21k–35k 次/秒空转，**其它任务（含诊断心跳）全部饿死**。
起点很明确：**hoverR 的心跳打到 t+8.5s 就停**，而 300 条连接正是在 t=8s 被关闭
（CPU 9.349s/18s ≈ 8s→18s 的一核）⇒ 触发条件是「**一批连接同时关闭**」，与 256 那个闸门无因果关系。

**尚未确定（下一步）**：这个不一致是 wasmtime 48.0.2 的 `poll()` / `ready()` 语义分歧，
还是我们 `Ready` 里 `OnceLock` 缓存 pollable + `WaitFor` 复用/丢弃的时序问题。
判别实验（**计划**，未做）：写一个**真 wasm（wasm32-wasip2）最小探针**：socket `start_connect` 成功后
`subscribe_read()`，然后交替调用 `wasi:io/poll::poll([p])` 与 `p.ready()`，对比两者在
「对端关闭 / 无数据」时的返回值；若二者持续分歧 ⇒ 上游（wasmtime）问题，否则是我们缓存的 pollable 问题。

**可行的兜底修法（未实现）**：`Ready::poll` 在「host 说就绪而 `ready()` 说不就绪」时，
连续 N 次（例如 3 次）无进展就**直接返回 Ready**，让调用方去做真正的 syscall —— syscall 的返回值
（数据/EOF/error）才是权威。这样能立刻打断空转，代价是偶尔一次多余的 syscall。


## 11. 最小 wasm 探针裁定：**上游原生语义没有问题**（2026-09-21）

探针：`crates/xt-wasm-runtime/examples/poll_vs_ready.rs`（真 `wasm32-wasip2`，只碰
`wasi:sockets` + `wasi:io`，不经过本仓库任何封装）。做法：监听 → accept → 等对端关闭 →
用「读 pollable + 永远就绪的 0ms 定时器」做**非阻塞** `poll()`，同时读同一个 pollable 的 `ready()`。

```
# 对端 FIN 正常关闭
[probe] iter=0..7  poll()就绪列表=[0] 或 [0,1] ⇒ poll认为socket就绪=true ; ready()=true
[probe] input.read(64) => Err(StreamError::Closed)          ← 真 EOF

# 对端 RST 强制关闭（SO_LINGER 0）
[probe] iter=0..7  poll()就绪列表=[0] 或 [0,1] ⇒ poll认为socket就绪=true ; ready()=true
[probe] input.read(64) => Err(StreamError::LastOperationFailed(Error { handle: Resource { handle: 11 } }))
```

**结论**：

1. **`poll()` 与 `ready()` 在两种关闭方式下都一致**（都报就绪），`read()` 的返回值才是权威
   （`Closed` = 真 EOF；RST 后是错误）⇒ **不是 wasmtime / WASI 绑定的语义分歧**。
2. 因此 V24 那个「被唤醒但 `ready()` 说不就绪」的状态，只能来自 **wstd 反应器的唤醒簿记**
   （上游 `check_pollables` 唤醒时不做注销，wakers 表里会留下**过期 waker**）或我们 `Ready`
   的 pollable 缓存 / `WaitFor` 复用。这也正是修复里两个改动分别对应的位置。
3. 探针同时给出了**兜底修法成立的理由**：宿主说就绪时去读，`read()` 会立刻给出
   `Closed`/错误，不会真的写坏数据 —— 放行是安全的方向。

> 诚实边界：本探针只覆盖「单连接、FIN/RST」两种形状，**没有**复现 300 连接 + 批量关闭的
> wstd 反应器状态；「过期 waker 具体怎么让某个任务被反复唤醒」仍是**机制推定**，未做
> 逐 waker 的取证（需要改 wasmtime 或把 wstd 反应器的 wakers 表 dump 出来）。

## 9b. 修复与验证（2026-09-21）：两处改动**合起来**才成立


兜底实现（`crates/xt-wasm-runtime/src/wasi.rs`）：`Ready::poll` 在 `Pending` 分支累计
「被唤醒但 `ready()` 说不就绪」的次数，连续 `READY_FUTILE_LIMIT = 8` 次就**放行**
（丢掉这个 `WaitFor` 并返回 `Ready`），由 `read()`/`write()` 的返回值（数据 / EOF / 错误）裁定。
与 `vendor/wstd` 的「唤醒即摘除」补丁**合起来**使用。

| 配置 | 场景 | hover300 marginal | 悬停 curl | 回落 marginal | 裁定 |
|---|---|---|---|---|---|
| 仅 wstd 补丁 | 黑洞 | 0.3858 ✗ | 空 ✗ | 0.0035 ✓ | 有改善、未过 |
| 仅 futile 兜底 | 黑洞 | −0.3694 / rep 14.2s（仍在转） | 200 | **1.8458 ✗** | 仍卡 |
| **两者合用** | 静默监听器（可达） | **0.0366 ✓** | 000（见下） | **0.0684 ✓** | 不复现 |
| **两者合用** | 黑洞（原始场景） | **0.0179 ✓** | **200 ✓** | **0.0054 ✓** | 不复现 |
| **两者合用（复核轮）** | 黑洞（原始场景） | **−0.0036 ✓** | **200 ✓** | **−0.0018 ✓** | 不复现 |

* 兜底触发**很局部**：只在「一批连接同时关闭」的窗口出现（黑洞复核轮 65 / 254 / 110 次），
  idle / hover / 60 条那些窗口 0 次 ⇒ 误触发面很小。
* 心跳行数是「是否卡死」的直接读数：修复前卡死窗口 1–2 行，修复后 idle 15 行 / hover 35 行 / 回落 59 行（打满窗口）。
* **回归**：`e2e-wasm-to-wasm` 5/5 通过（含 Vision 自环 → 200）、`e2e-vision` 4/4 通过。
* 「静默监听器」那轮悬停 curl=000 的解释：该窗口服务端日志**只有启动横幅、Forwarded=0**，
  请求根本没到我们服务端 ⇒ 是 256 并发上限/上游侧排队，不是卡死（黑洞轮同参数 curl=200）。

## 10. 代码现状（未提交）

* `vendor/wstd`（0.6.8 + 唤醒即摘除补丁 + `WSTD_DIAG` 反应器内部心跳）+ 根 `Cargo.toml` 的 `[patch.crates-io]`；
  **补丁是修复的一半**（缺它回落 marginal 回到 1.8458），属供应链改动，需决定是否随版本发布。
* `crates/xt-wasm-runtime/src/wasi.rs`：`Ready::futile` 兜底（**修复的另一半**）+ `XT_DIAG` 诊断
  （**带 `dead_code` 告警**，会让 `check.sh` 的 `clippy -D warnings` 变红，定稿前必须清理或修掉）。
* `crates/xt-wasm-runtime/src/wasi.rs` 的 `XT_DIAG` 诊断（**带 `dead_code` 告警**，会让
  `check.sh` 的 `clippy -D warnings` 变红，定稿前必须清理或修掉）；
* 门禁与 e2e 尚未在补丁版上重跑。

