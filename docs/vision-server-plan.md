# 服务端 XTLS-Vision 流控 —— 实施方案

> 状态：**未实现**。本文是实施方案，不是完成报告。
> 依据：`crates/xt-wasm-vless/src/vless/vision.rs`（客户端侧，713 行，已实测可用）
> 以及 `crates/xt-wasm-vless/src/vless/server.rs` 里现有的明确拒绝。

---

## 0. 现在是什么状态

服务端对非空 `flow` **明确拒绝**（`InboundOutcome::Rejected`，reason 里写明改法）。
这是刻意的：Vision 会把负载包进填充帧，不拆帧就会把填充字节当原始数据发给目标站 ——
**输出是错的却不报错**，属于最难排查的那类故障。

所以现状是「不能用但不会错」，实现 Vision 之后变成「能用」。

---

## 1. 帧格式（从客户端实现反推，已在客户端侧验证）

### 第一帧：带 UUID 的完整头（21 字节）

```text
[uuid: 16] [command: 1] [content_len: 2 BE] [padding_len: 2 BE] [content] [padding]
             ^ 0x00 继续 / 0x01 结束 / 0x02 转为直传
```

`PADDING_HEADER_LEN = UUID_LEN + 1 + 2 + 2 = 21`

### 后续帧：短头（5 字节）

```text
[content_len: 2 BE] [padding_len: 2 BE] [content] [padding]
```

### `command == 0x02 (DIRECT)`

之后**不再有帧**，是裸字节流。客户端在这一步会调用
`enable_inner_raw_write_passthrough()`（见 `vision.rs:205`）。

### `command == 0x01 (END)`

padding 结束，但**仍可能继续有帧**（`build_write_frame` 里的分支，见 `vision.rs:151-161`）。

---

## 2. 服务端要实现什么

客户端 `vision.rs` 有**写侧组帧**和**读侧解帧**两半。服务端主要需要**读侧解帧**
（解客户端发来的帧），外加：

| 方向 | 需要做什么 |
|---|---|
| 客户端 → 服务端 | **解帧**：按上表剥离 content/padding，只把 content 交给目标站 |
| 服务端 → 客户端 | 客户端已有的读侧解帧逻辑要求服务端**按同样的规则组帧**（对称） |

**关键点：UUID 从哪来。** 第一帧的头里含 UUID（16 字节）。服务端在解帧之前**已经**
从 VLESS 请求头里拿到了 `user_id` —— 直接用 `req.user_id` 校验并跳过这 16 字节即可，
不需要重新解析。

---

## 3. 落点

* 新增 `crates/xt-wasm-vless/src/vless/vision_server.rs`：读侧解帧器
  （建议做成 `AsyncRead` 包装，与客户端的 `VisionConn` 对称，命名 `VisionServerConn`）
* `serve_inbound_with_events` 里把现有的「拒绝非空 flow」分支改成：
  flow 为空 → 现状；flow 就是我们支持的那个 → 套一层 `VisionServerConn`；
  **其它未知 flow → 仍然明确拒绝**（不要放宽）
* 出站方向（服务端 → 客户端）的组帧复用客户端 `vision.rs` 的 `build_write_frame`
  逻辑 —— 但注意方向语义要核对，**不要照抄了事**

---

## 4. 必须先写的测试（按这个顺序）

1. **解帧器单测**（纯函数，不碰网络）：
   * 第一帧（带 UUID）解得正确
   * 后续短头帧解得正确
   * content 与 padding 长度都为 0 的边界
   * `content_len` 很大 / 声明的长度超过实际字节（截断）→ 不能 panic，要报错
   * `command == 0x02` 之后是裸字节
   * **UUID 不匹配 → 拒绝**（防止把别人的帧当自己的解）
2. **往返测试**：用客户端 `vision.rs` 的**写侧**产出字节，喂给服务端解帧器，
   断言 content 原样还原。**这条最有价值** —— 它把两半钉在一起。
3. **互操作 e2e**（新脚本 `scripts/e2e-vision-test.sh`）：
   * **正向**：官方 Xray 客户端，`flow: "xtls-rprx-vision"` → 我们的服务端 → HTTP 200
     （**这是当前做不到的事**，也就是这个功能的目的）
   * **反向**：客户端 `flow` 留空 → 仍然可用（不得回归）
   * **未知 flow** → 仍然明确拒绝（不得静默降级）
4. 既有三道 e2e 全部不得回归。

---

## 5. 验收判据（硬）

```sh
cargo test --workspace
./scripts/check.sh
./scripts/e2e-test.sh                # wasm → stock（不得回归）
./scripts/e2e-server-test.sh         # stock → wasm，flow 空（不得回归）
./scripts/e2e-wasm-to-wasm-test.sh   # 自环（不得回归）
./scripts/e2e-vision-test.sh         # 新增：官方客户端 flow=vision → 200
```

**判据必须是双侧的**：既要「flow=vision 现在能通了」，也要「flow 空/未知 flow 的行为
没有变化」。本仓库在 V24 里吃过一次亏：用单侧指标（CPU 低）把「整个实例阻塞」
误读成「修好了」。

---

## 6. 不要做的事

* **不要为了让 e2e 变绿而放宽既有断言**。
* **不要静默降级**：不认识的 flow 必须报错并说明原因（既有设计）。
* **不要照抄客户端的分帧逻辑**——两个方向语义不同，抄错会得到「能连上但数据是坏的」。
* **不要把 Vision 和 V24 的自旋 bug 混在一起做**。自旋是独立缺陷，且已确认
  只能靠进程外兜底（`livenessProbe`）。混做会让两边都难以归因。

---

## 7. 工作量参考

客户端侧 `vision.rs` 是 **713 行**（组帧 + 解帧 + TLS 检测 + 状态机 + 测试）。
服务端只需要**解帧 + 出站组帧**，估计 **150–250 行实现 + 等量测试**，
外加一个 e2e 脚本。**不是一次能顺手带上的改动。**
