# 调查者共享规则（20 路独立调查 + 对抗测试）

> 这份文件是**所有调查者**的环境与铁律说明。每个调查者只做一件事：
> 把自己那一条入手点查出结论，写进 `docs/findings/<你的 slug>.md`，然后
> `send_message` 给 `lead` 报 3 行结论。
> 公告板（`docs/issue-board.md`）**只有 lead 写**，你不要改它。

## 环境（沙箱限制，必须照做）

```
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh
CARGO_TARGET_DIR=$PWD/target cargo build|test …      # 一律带这个变量
XW_TARGET_DIR=$PWD/target ./scripts/run-local.sh …   # 跑 wasm 客户端/服务端
```

* 本机是 **macOS**：**没有 `/proc`**（读不到 CPU ticks）、沙箱禁 `ps`/`top`、
  `docker` 二进制在但 **daemon 不可用**。
* V24 的替代 CPU 判据：`scripts/v24-cpu-probe.py`（用 `os.wait4` 的 rusage）。
  ⚠️ 本机绝对值偏低（2.0s 纯忙循环只报 1.09s），所以判据要**相对比较**：
  同一条命令跑「idle（不灌连接）」与「hover（灌悬停连接）」两遍，比值说话。
* 官方 Xray 二进制：`/Users/xbtg-/deepseek-harness/.scratch/xray-server/xray`；
  配套配置 `…/.scratch/xray-server/{server.json,client.json}`（8443 / 1080）。
* wasm 客户端是 **SOCKS5 代理**：必须先 `\x05\x01\x00` 协商，再发 CONNECT 才会出站。

## 端口纪律（避免 20 个人互相踩）

既有 e2e 占用：8443 / 9444 / 9543 / 1080 / 1082 / 1083 / 1084。
**你只能用 `20000 + 编号*10` 这一段**（编号见你的任务卡），例如编号 3 → 20030…20039。
跑完 `pkill -f wasmtime; pkill -f 'xray run'` 清理干净。

## 铁律

1. **写范围**：只能写 `docs/findings/<你的 slug>.md` + 你自己新建、名字带 slug 的脚本。
   **不要改任何生产代码**（`crates/**`）或别人的脚本；发现别人的问题 → 写进你的 findings 并说明。
2. **证据**：结论必须带可复现命令 + 原始输出片段。没跑过的写「未验证」。
   阴性与阳性结果同样有价值 —— 证明「此路不通」本身就是产出。
3. **不许**为了让结果好看而挑参数；参数（连接数、窗口、目标、次数）要写进报告。
4. **不许**把「看起来像」写成结论；也不许改动断言/脚本去让它变绿。
5. 报告要短：`send_message` 给 lead 三行以内 —— `task id / 判定 / 一句话结论 + findings 文件路径`。

## V24 的已排除清单

V24 已经排查过八轮，`docs/verification-log.md` 从 1117 行开始有全部历史，
包括 6 个已排除假设、3 次被撤回的过宽结论、以及三条负面结果
（按机制写的修复无效 / Pending 后丢弃重建 WaitFor 无效 / 用 wstd 类型替手写 Ready 不是 drop-in）。
**先读那一段**：若你打算走的假设已经被排除过，换一个入手点，并在报告里点明。
