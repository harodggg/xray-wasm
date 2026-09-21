# V27-D（task-20）：客户端对「REALITY 握手超时」重试一次

> 任务：`task-20`（P0 产品修复）。写者：`v27-wake`。
> 依据：`docs/findings/v27-wake.md`（瞬态停顿已证明在客户端之外；后续连接 0.211s 回包）。
> 写范围：`crates/xt-wasm-cli/src/main.rs` + 本文 + 临时脚本。`reality.rs`（P1 定时器死线，lead 做）
> 与 `scripts/e2e-test.sh`（lead 修端口硬编码）**一行未碰**。

## 0. 一句话

在 `open_tunnel` 里加了**一次**受控重试：**只**认「REALITY 握手超时」，**只**试 2 次。
正样本（首条卡死、后续正常）从「必失败」变成 **HTTP 200**；负样本（始终卡死）**恰好 2 次 ClientHello、20.0s 失败**；
协议/认证错误**不重试**（边界用例实测只连 1 条）。`e2e-test.sh` **一行未改**，连跑 3 轮 8/8 绿；
另做了一轮「靠重试救回来」的 e2e（首连被中间人卡死），同样 8/8。

---

## 1. 改了什么

全部在 `crates/xt-wasm-cli/src/main.rs`：

| 位置 | 内容 |
|---|---|
| `const REALITY_HANDSHAKE_ATTEMPTS: usize = 2`（新） | 1 次正常 + 至多 1 次重试 |
| `const HANDSHAKE_TIMEOUT_FLOOR: Duration = 9s`（新） | 「这次失败算超时」的墙钟下限 |
| `fn is_handshake_timeout(err, elapsed) -> bool`（新） | `matches!(err, TransportError::Tls(_)) && elapsed >= 9s` |
| `async fn open_tunnel` | 把「建连 + REALITY 握手」放进 2 次循环；超时才重试；其它错误原样上报 |
| `mod tests::only_handshake_timeouts_are_retried`（新） | 把判据的 4 个边界钉成确定性单测 |
| `use xt_wasm_tls::{…, TransportError}` | 新增一个 import |

**每次重试都是新 TCP 连接 + 新 ClientHello**（循环里重新 `connect()` 再 `layer.connect()`），
不复用任何握手中间状态。

日志（重试成功时）：

```
[socks5] REALITY 握手超时（10.0s）→ 新开一条连接重试一次（瞬态停顿；实测后续连接 0.2–0.7s 就能回包）
[socks5] REALITY 握手第 2/2 次尝试成功（本次 7.10s；第 1 次超时等了 10.0s）
```

负样本最终失败时把两次都写进错误里：

```
[socks5] … 失败：REALITY 握手失败：tls handshake: Reality TLS: handshake did not complete within 10s
         （共 2 次尝试；第 1 次超时 10.0s，第 2 次 10.0s）
```

不重试时也把这个决定写出来（避免被读成「重试没生效」）：

```
[socks5] … 失败：REALITY 握手失败：tls handshake: Reality TLS: unexpected plaintext handshake（非超时，不重试）
```

---

## 2. 判据为什么长这样（设计说明）

`TransportError` 只有 `Io / Tls(String) / WebSocket / … / Config`，**没有独立的 timeout variant**：
`xt-wasm-tls` 的握手死线到点后返回的是 `Tls("Reality TLS: handshake did not complete within 10s")`。
而 `reality.rs` 不在本次改动的写范围里，所以判据只能由两个**独立信号**合取：

1. 类别是 `TransportError::Tls` —— 排除 `Config`（配置错）、`Io`（连接层错）；
2. 这次尝试**确实耗满了死线**（≥ 9s；死线是 10s，留 1s 给定时器到点与错误冒泡的抖动）。

**刻意不解析错误文案**：文案一改（例如将来把消息改成中文/加字段），重试就会静默失效 ——
那正是本仓库最忌讳的「静默降级」。协议/认证/解析类错误全在**亚秒级**返回，第 2 条永远不成立。

如果将来 `xt-wasm-tls` 给超时加一个独立 variant（例如 `TransportError::Timeout`），
这里的第 2 条就该删掉，只留类别判断 —— 这是本判据唯一想被取代的地方（见 §7）。

---

## 3. 验收证据

### 3.1 `cargo test --workspace` —— 全绿

```
$ CARGO_TARGET_DIR=$PWD/target cargo test --workspace
test result: ok. 29 passed; 0 failed    (xt-wasm-cli，含新单测 only_handshake_timeouts_are_retried)
test result: ok.  8 passed; 0 failed    (xt-wasm-runtime)
test result: ok. 51 passed; 0 failed    (xt-wasm-tls)
test result: ok. 20 passed; 0 failed    (fingerprint_differential)
test result: ok. 26 passed; 0 failed    (fingerprint_security)
test result: ok. 59 passed; 0 failed    (xt-wasm-vless)
exit code: 0
```

### 3.2 `./scripts/check.sh` —— 9/9

```
$ XW_CARGO_HOME=$PWD/target/cargo XW_TARGET_DIR=$PWD/target ./scripts/check.sh
  ✓ fmt          ✓ clippy         ✓ tests        ✓ wasm        ✓ examples
  ✓ 依赖树干净    ✓ 无 tokio runtime 调用        ✓ 变量引用无多字节歧义
  ✓ 清单变量名与源码一致（17 个）
  CI 的全部检查都通过了。          (exit code: 0)
```

### 3.3 正样本：第一条卡死、后续正常 ⇒ 重试后 **200**

造法：用真服务端（`gen-test-server.sh` 生成，8643）+ `scripts/v27-delayed-peer.py --mode forward`
做中间人，`--stall-first 1`（第 1 条连接读掉 ClientHello 后**不回包也不转发**，让死线到点），
第 2 条起正常转发。

```
$ python3 scripts/v27-delayed-peer.py --port 18443 --mode forward --upstream 127.0.0.1:8643 \
      --stall-first 1 --accept 2 --hold 20
$ ./scripts/run-local.sh --server 127.0.0.1:18443 … --listen 127.0.0.1:1095
$ curl -sS -m 40 --proxy socks5h://127.0.0.1:1095 -o /dev/null -w 'http_code=%{http_code}\n' https://example.com
```

对端日志：

```
#1 accept 来自 127.0.0.1:61523
#1 卡死（stall-first）：收到 538 字节后静默 30.0s，不回包        ← 第 1 次尝试被卡死
#2 accept 来自 127.0.0.1:61622                                  ← 10.0s 后重试
#2 c2s 首批 602 字节 （accept 后 0.000s）hex=1603010255010002510303ce
#2 s2c 首批 2183 字节 （accept 后 6.209s）hex=160303007a02000076030357
```

客户端日志 + curl：

```
[socks5] REALITY 握手超时（10.0s）→ 新开一条连接重试一次（瞬态停顿；实测后续连接 0.2–0.7s 就能回包）
[socks5] REALITY 握手第 2/2 次尝试成功（本次 6.21s；第 1 次超时等了 10.0s）
[socks5] 127.0.0.1:61522 → example.com:443 完成
http_code=200        real 0m26.647s
```

（26.6s = 10.0s 首次超时 + 6.2s 第二次握手（当时服务端这次也慢，仍 <10s）+ 页面拉取。）

### 3.4 负样本：始终卡死 ⇒ **恰好 2 次 ClientHello**，不无限重试

`--stall-first 2 --accept 2`：

```
#1 卡死（stall-first）：收到 602 字节后静默 25.0s，不回包
#2 卡死（stall-first）：收到 506 字节后静默 25.0s，不回包        ← 总共就这 2 条
peer 卡死连接数 = 2
```

客户端：

```
[socks5] REALITY 握手超时（10.0s）→ 新开一条连接重试一次（…）      ← 只有 1 行重试
[socks5] 127.0.0.1:62462 失败：REALITY 握手失败：tls handshake: Reality TLS: handshake did not complete
         within 10s（共 2 次尝试；第 1 次超时 10.0s，第 2 次 10.0s）
  重试日志行数 = 1
curl: (97) Can't complete SOCKS5 connection to example.com. (1)      real 0m20.025s
```

### 3.5 边界（**必须**有）：协议错误不重试

对端 `--mode header0 --delay 0.2`（快速回一个非法 record）：

```
client: [socks5] … 失败：REALITY 握手失败：tls handshake: Reality TLS: unexpected plaintext handshake（非超时，不重试）
peer:   #1 收到客户端首包 602 字节     ← 只有 1 条连接
        重试日志行数 = 0
```

⇒ 「认证失败 / 配置错误 / TLS 版本不匹配 / 解析错误」不会被重试（也不会多等一个往返）。

### 3.6 `e2e-test.sh`（**一行未改**）

用生成的配置 + 独立端口（`XT_TEST_PORT=8643`、`XT_TEST_SOCKS=127.0.0.1:1091`；
**未用 8443/1080**，1080 是用户 XrayTun 应用的端口）：

```
$ . /tmp/v27a/test-server/params.env
$ XW_TARGET_DIR=$PWD/target XW_XRAY_DIR=/tmp/v27a/test-server \
    XT_TEST_SERVER=127.0.0.1:8643 XT_TEST_SOCKS=127.0.0.1:1091 ./scripts/e2e-test.sh

round 1: exit=0  8/8  ✓ 端到端通过
round 2: exit=0  8/8  ✓ 端到端通过
round 3: exit=0  8/8  ✓ 端到端通过
```

这 3 轮**没有触发重试**（首个飞行包都 <10s），说明重试不干扰正常路径。

**再加一轮「靠重试救回来」的 e2e**：把客户端指向中间人（`--stall-first 2`，第 1 条是 e2e 自己的
`nc -z` 探测、第 2 条是首个隧道连接，都被卡死；第 3 条起转发到真服务端 8643）：

```
==> 5/8 经隧道取一个真实页面（带正确凭据）
  ✓ https://example.com -> 200
    端到端通过。                                       exit=0，8/8
[e2e-client.log]
[socks5] REALITY 握手超时（10.0s）→ 新开一条连接重试一次（瞬态停顿；实测后续连接 0.2–0.7s 就能回包）
[socks5] REALITY 握手第 2/2 次尝试成功（本次 7.10s；第 1 次超时等了 10.0s）
```

⇒ **e2e 的断言一行没动，红的那一步是靠重试自己变绿的**（不是放宽断言）。

---

## 4. 代价（明确写下来）

| 项 | 正常路径 | 超时失败路径 |
|---|---|---|
| 每次请求墙钟 | 不变（0.2–0.7s 级） | **~10s → ~20s** |
| ClientHello 条数 | 1 | **2**（多一条短连接；指纹层面是多一次「握手失败」形状的连接） |
| 并发槽位占用（上限 64） | 不变 | 最坏翻倍到 ~20s |
| 失败时的日志 | 1 行 | 2 行（重试 + 最终失败，含两次耗时） |

**服务端可见的变化**：一次失败会看到两条来自客户端的连接（第 2 条在约 10s 后），
两条都会收到 ClientHello。对服务端是普通失败连接的形状，不需要任何服务端改动。

---

## 5. 明确**不**重试的清单

* 认证失败（REALITY HMAC / shortId / 时钟偏差）
* 配置错误（未知指纹、`--pbk` 解析、reality/ech 冲突）—— `RealityTlsLayer::new` 只做一次，不进循环
* TLS 版本/消息不匹配、记录解析错误（`unexpected plaintext handshake` / `unexpected handshake message`）
* `xt_wasm_runtime::connect` 失败（服务端不可达；它有自己的 10s 总预算，且不是握手错误）
* **≥9s 但类别不是 `Tls` 的失败**（例如长时间停顿后收到 RST）—— 严格按任务边界「只重试超时」

`--self-test`（`run_self_test`）**故意不重试**：它是单发诊断探针，重试会掩盖第一次的真实表现。

---

## 6. 与 P1（`reality.rs` 定时器死线）的关系

P1 让死线到点**主动唤醒**、错误准时冒泡（实测 10s 不再是 18s）。没有 P1，
`layer.connect()` 在被 poll 之前不会返回，`elapsed >= 9s` 这条虽然仍成立，
但第一次尝试的耗时会被拖长。两者配合起来：**P1 保证「超时」准时发生，本改动保证「超时」被救一次。**

---

## 7. 已知边界 / 后续

1. 判据里的「≥9s」是启发式，存在的前提是 `xt-wasm-tls` 的死线是 10s。**推荐的收敛办法**：
   给超时加独立 variant（`TransportError::Timeout`），`main.rs` 只判类别 —— 由 `xt-wasm-tls` 负责人决定。
2. 重试次数、是否退避、失败路径 20s 是否可接受：**产品语义决定**（本改动取「1 次、无退避」，
   因为实测第 2 条连接 0.211s 即可回包，退避只会更慢）。
3. 若运维侧已经有「启动自预热」，本重试是**第二道**防线，不冲突。
4. `scripts/v27-delayed-peer.py` 新增 `--stall-first N` / `--stall-hold S`（造「前 N 条卡死」），
   并修掉一个真 bug：`--mode forward` 之前把 `--hold` 当成上游**读**超时，真实服务端 6.2s 才回的
   飞行包会被代理主动关掉，客户端看到的是 EOF 而不是握手超时（判据失真）。现在连上后 `settimeout(None)`。

---

## 8. 复现命令

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh
CARGO_TARGET_DIR=$PWD/target cargo build -p xt-wasm-cli --release --target wasm32-wasip2

# 正样本：首条卡死、后续转发到真服务端
XT_TEST_PORT=8643 ./scripts/gen-test-server.sh /tmp/v27a/test-server
. /tmp/v27a/test-server/params.env
"$XW_WS/.scratch/xray-server/xray" run -c /tmp/v27a/test-server/server.json &
python3 scripts/v27-delayed-peer.py --port 18443 --mode forward --upstream 127.0.0.1:8643 \
    --stall-first 1 --accept 2 --hold 20 &
./scripts/run-local.sh --server 127.0.0.1:18443 --pbk "$XT_TEST_PBK" --sid "$XT_TEST_SID" \
    --sni "$XT_TEST_SNI" --uuid "$XT_TEST_UUID" --listen 127.0.0.1:1095 &
curl -sS -m 40 --proxy socks5h://127.0.0.1:1095 -o /dev/null -w '%{http_code}\n' https://example.com
# 期望：200；客户端日志出现「第 2/2 次尝试成功」

# 负样本：始终卡死
python3 scripts/v27-delayed-peer.py --port 18443 --mode forward --upstream 127.0.0.1:8643 \
    --stall-first 2 --accept 2 --stall-hold 25 &
# 期望：~20s 失败；对端恰好 2 条「卡死」；客户端恰好 1 行重试

# e2e（断言一行未改）
XW_TARGET_DIR=$PWD/target XW_XRAY_DIR=/tmp/v27a/test-server \
    XT_TEST_SERVER=127.0.0.1:8643 XT_TEST_SOCKS=127.0.0.1:1091 ./scripts/e2e-test.sh
```
