# V24-09 · 四探针 × {idle, hover1, hover8, hover32} 差异矩阵

**执行者**：lead（轮换制下由 lead 自己跑掉的第一条入手点）
**判据**：`scripts/v24-cpu-probe.py`（`os.wait4` 的 rusage；本机绝对值偏低，只看比值）
**命令**：`CARGO_TARGET_DIR=$PWD/target cargo build --examples -p xt-wasm-runtime`，然后对每个
探针 × 每个悬停档位跑 `python3 scripts/v24-cpu-probe.py --port <n> --seconds 5 --conns <N> -- ./target/debug/examples/<probe> <n>`

## 结果（cpu%，5s 窗口）

| probe | idle | hover1 | hover8 | hover32 |
|---|---|---|---|---|
| `stream_spin_probe`（只读） | 0.7 | 0.7 | 0.8 | 0.7 |
| `stream_spin_probe_w`（只写） | 0.7 | 0.7 | 0.7 | 0.8 |
| **`stream_spin_probe_rw`（读写交替）** | **0.6** | **1.1** | **1.8** | **2.7** |
| `stream_spin_probe_timeout` | 0.6 | 0.7 | 0.9 | 0.8 |

## 判定：**inconclusive（有信号，但不足以判自旋）**

* 唯一随悬停连接数增长的是 **读写交替** 那条：0.6% → 2.7%（32 连接，约 4.5 倍），
  其余三条全程平（0.7% 上下）。这与「读写交替是必要形状」的历史结论方向一致。
* **但这条矩阵不能证明自旋**，原因必须写明：我的触发是「每条连接每轮发 5 字节、共 3 轮」，
  **idle 档完全没有这段流量，而 rw 档的读会真的返回、让探针多走几轮**。
  也就是说 idle vs hover 的差里混着「触发流量本身的工作量」，不是纯悬停状态的开销。
* 另外 32 连接只有 2.7% ⇒ 即使全是空转，也远不是 V24 描述的「打满一核」；
  可能我的触发形状/规模还没到阈值，也可能 rw 与真正现场（含握手写入与协议层）不是同一件事。

## 下一步（已写进公告板，交给 `v24-integrator`）

1. **静默窗口测量**：先灌连接、跑完触发流量，然后**在完全没有新流量的窗口内**测 CPU
   （这才是「悬停状态下是否空转」的干净判据）。
2. **规模扫描**：hover ∈ {32, 64, 128, 256}（服务端并发上限 256），看是线性增长还是饱和。
3. **与真实现场对齐**：本矩阵用的是最小探针；真实现场（wasm 服务端 + 官方客户端 + 悬停 CONNECT）
   由 `v24-integrator` 的 `scripts/v24-field-test.sh` 覆盖。
