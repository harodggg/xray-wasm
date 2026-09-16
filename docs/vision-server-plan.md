# 服务端 XTLS-Vision 流控 —— 实施方案与当前状态

> 状态：**已实现并端到端跑通**（官方 Xray 26.3.27 客户端 `flow: "xtls-rprx-vision"`
> → 本工程 wasm 服务端 → 真实网站 HTTP 200）。
> 本文既是实施方案，也是诚实的进度报告 —— 结论只写被实测钉住的部分。

---

## 0. 当前状态（先看这一段）

| 方向 | 状态 | 证据 |
|---|---|---|
| 客户端 → 服务端（**解帧**） | ✅ **可用** | 官方 Xray 26.3.27 客户端带 `flow: "xtls-rprx-vision"` 连上来后，服务端解出内层 TLS ClientHello（321 字节，`16 03 01 01 3c 01 00 ...`）并原样转发到目标站 |
| 目标站 → 服务端 | ✅ 通 | 目标站的 `ServerHello`（`16 03 03 00 7a 02 00 ...`）被正确接收并组帧写出 |
| 服务端 → 客户端（**组帧**） | ✅ **可用** | `scripts/e2e-vision-test.sh` 第 2 条：官方客户端经本服务端取 `https://example.com` → **HTTP 200**；服务端日志 `outcome=Forwarded up_bytes=585 down_bytes=4870` |
| 空 flow（裸路径） | ✅ 未回归 | `e2e-vision-test.sh` 第 3 条 + `e2e-server-test.sh` + `e2e-wasm-to-wasm-test.sh` |
| 未知 flow | ✅ 仍明确拒绝 | 单测 `inbound_rejects_unknown_flow_with_actionable_hint` |
| 抗主动探测回退 | ✅ 未回归 | `e2e-vision-test.sh` 第 4 条：探测者看到 dest 的真实 EC 证书 |

**结论**：官方客户端的 `flow` 现在**可以直接指向本服务端**；`--no-flow` 不再必需
（保留它只是为了「对端只认空 flow」的兼容场景）。

### 之前为什么一直红：根因不在流控，在测试脚本

上一轮记录为「回程组帧未被官方客户端接受」，**这个判断是错的**。真正的原因是
验收脚本自己的一处取值 bug：

```sh
CODE=$(curl ... -w '%{http_code}' ...)   # 在 fetch_code 里
...
printf '  … 第 %s 次失败（%s），重试\n' "$ATTEMPT" "$CODE"   # ← 打到了 stdout
```

`fetch_code` 的重试进度是打到 **stdout** 的，而调用方是 `CODE=$(fetch_code ...)`
—— 于是**第一次重试之后** `$CODE` 变成
`"  … 第 1 次失败（000），重试\n200"`，`[ "$CODE" = "200" ]` 永远为假。
症状极具误导性：客户端日志干净、服务端日志写着 `outcome=Forwarded`，
脚本却报 000/✗。进度信息改到 stderr（`>&2`）后第 2 条立刻变绿。

同时确实修掉了一个**真实的**服务端 bug（见 §3.1），它与 Vision 的帧格式无关，
而是「目标站不是 TLS 时回程数据根本发不出去」。

---

## 1. 帧格式

```text
首帧:  [uuid:16][command:1][content_len:2 BE][padding_len:2 BE][content][padding]
后续:  [command:1][content_len:2 BE][padding_len:2 BE][content][padding]
```

命令：`0x00 CONTINUE`、`0x01 END`、`0x02 DIRECT`。
`PADDING_HEADER_LEN = 21`，短头 `= 5`。

### 已从 upstream 源码核实的三条语义

1. **响应头是裸的，不进帧。** 客户端 `getResponse` 先 `DecodeResponseHeader(conn, ...)`
   **裸读** 2 字节，之后才 `DecodeBodyAddons` → `NewVisionReader`。所以服务端必须
   **先写裸响应头、再套 Vision**。
   （upstream 服务端看起来像是把响应头也交给 VisionWriter，但
   `buf.NewBufferedWriter` 在 `SetFlushNext()` 后的第一次 `WriteMultiBuffer` 会
   **走 `w.writer`** —— 也就是裸写。这个细节以前理解反了，是回程失败的根因之一。）
2. **两个方向的首帧都必须带 UUID**：`XtlsPadding` 只在 `writeOnceUserUUID`
   非空时写那 16 字节，两侧 `XtlsUnpadding` 都要求首帧以本用户 UUID 开头。
3. **帧形状是整条流的属性**：首帧定了有没有 UUID 前缀，后续帧一律短头。

### 客户端何时停止解帧（决定了服务端何时必须停帧）

upstream `VisionReader`：读到 `CONTINUE` 且本帧 `content`/`padding` 都清零时，
会**主动退出解帧、切到裸字节**。所以服务端**必须在最后一帧上带终止命令**
（`END`/`DIRECT`），且那之后不能再发帧头 —— 两边要在同一刻切过去。

---

## 2. 已实现的东西

* `crates/xt-wasm-vless/src/vless/vision_server.rs`
  * `FrameParser`：纯状态机解帧器（跨读拼接、截断只消费实际字节、零长度帧透明、
    首帧 UUID 判别、未知命令报错、`DIRECT` 之后裸字节）
  * `VisionServerConn`：`AsyncRead`（解帧）+ `AsyncWrite`（组帧）
* `serve_inbound`：**先写裸响应头**，再套 `VisionServerConn`；flow 分支
  「空 → 裸路径；`xtls-rprx-vision` → 套包装；其它 → 仍明确拒绝」
* `InboundReport::vision: bool`（日志里能直接看出这条连接走的是 Vision 数据路径）
* `scripts/e2e-vision-test.sh`：官方客户端验收脚本（4 条全绿）

---

## 3. 已经排查掉的原因（都实测过）

### 3.0 三个真正的根因（都实测定位）

#### (a) 收到对端的 `DIRECT` 时**不能连写侧一起切**

XTLS-Vision 的两个方向是**各自独立**协商的，upstream 用四个不同的标志位
（`UplinkWriterDirectCopy` / `DownlinkReaderDirectCopy` …）：

* 我们发 `DIRECT` → 对端的**读侧**切裸字节 → 我们的**写侧**跟着切；
* 对端发 `DIRECT` → **我们的读侧**切裸字节 → **我们的写侧不动**。

原来的 `switch_both_to_raw()` 把两个方向一起切了。于是只要客户端**先**发
`DIRECT`（它一看到自己的 TLS 应用数据就会发），我们就停止组帧、开始裸写；
而客户端的读侧还在解帧，把裸字节当成外层 TLS 密文：

```
官方客户端日志：failed to transfer response payload > local error: tls: bad record MAC
```

**这是竞态**：谁先发 `DIRECT` 决定成败 —— 所以它时红时绿，是最难缠的一条。
修法：拆成 `switch_read_to_raw()`（对端 DIRECT 触发）与写侧单独的
`enable_inner_raw_write_passthrough()`（只由我们自己发终止帧触发）。
回归测试 `peer_direct_must_not_stop_our_write_framing` 用**真 REALITY 两端**
复现当年那个时序，把旧写法改回去它立刻变红。

#### (b) `DIRECT` 帧的 padding 没走完就去读内层

帧命令要等**整帧**（含 padding）走完才生效。原来的读循环在交出一帧的
`content` 之后，下一轮直接去读内层 —— 而对端此刻已经切到裸字节，
于是我们拿裸字节去喂外层 TLS 解密：

```
TLS AES-128-GCM decrypt: aead::Error
```

修法：`poll_read` 每轮先给解析器喂一个空切片，把 `parser.pending` 里的
残留（正是 padding）榨干，再决定要不要读内层。offline 的
`upstream_unpadding` 对拍「一次喂完整段」，照不出这条 —— 它只在
「padding 与随后的裸字节分处不同 TCP 段」时暴露。

#### (c) 目标站不是 TLS 时，回程数据被永久扣在缓冲区里

写侧为了让「VLESS 响应头」和紧随其后的 `ServerHello` 落在同一帧，会把
「还没确认对端是 TLS」的字节先攒进 `coalesce`；而 `poll_flush` 当时只在
`out_tls.is_tls()` 为真时才把这一帧交付出去。明文 HTTP 目标下 `is_tls()`
**永远不会**为真 —— 于是：

```
服务端日志：outcome=Forwarded up_bytes=78 down_bytes=129
客户端 curl：(52) Empty reply from server   ← 一个字节都没收到
```

修法：`poll_flush` / `poll_shutdown` 一律交付攒下的字节，不再等 TLS 判定
（`flush_coalesced()`）。回归测试 `vision_pair_relays_plain_http_response`
用一台**没有 TLS 的目标**跑完整一趟，钉住这个行为。

#### (d) 两侧 `poll_write` 把「上一帧的 consumed」当成当前 buf 的写入量

在途帧推完之后必须**继续给当前 `buf` 组帧**；原来的写法直接
`return Ok(consumed)`，而那个数字属于**上一个 buf** —— 调用方会据此跳过
`buf` 开头同样多的字节，**直接丢数据**。`RealityTlsStream::poll_write`
里早就写明了正确做法，两个 Vision 写侧都没照做；现已对齐。

### 3.1 更早修掉的一批（都是必修，不是猜测）

回程失败前后修掉了这些**真实的** bug：

1. **响应头被包进了帧** —— 客户端裸读，于是把帧头的 UUID 当版本号。
   现已改成先裸写响应头。
2. **`VisionConn::poll_flush` 顺序错**（客户端侧）—— 它先 flush 内层，导致
   `VlessConn` 把延迟的 VLESS 请求头当裸字节先发出去、**首帧丢 UUID**。
3. **VLESS flow addon 长度写错** —— `addon_length` 写成 18（正确值是 `2+len`），
   服务端按这个长度切片会把请求的 `cmd` 字节当成 flow 最后一字节。
4. **`poll_write` 违反 `Pending` 契约** —— 在途帧没写完就返回 `Pending`，
   调用方重递同一个 `buf`，于是同一个内容被编成两个帧。
5. **重复帧**：`poll_flush` 在已有在途帧时又组了一次帧，把前一帧覆盖掉。

以及这些**被排除**的写法（都仍然拿不到 200）：

* 首帧回 `END` + 之后裸字节；
* 首帧回 `CONTINUE`、握手期持续组帧、按「看到 TLS 应用数据」切裸字节；
* 按「记录数预算」（1/2/3/4）决定何时 `END`；
* 把响应头与该段负载合并进同一帧。

### 已确认的事实

* 服务端读侧解出的内层明文正确（以 `16 03 01` 开头）。
* 服务端确实把目标的 `ServerHello` 发出了（`down=4871`），且**两个方向都在搬数据**。
* 客户端**没有**报错日志，只是拿不到可用响应（`curl` 超时 0 字节）。

### 已经收敛到的事实

* **裸响应头**：客户端 `DecodeResponseHeader` 裸读 2 字节，服务端必须
  **先裸写、再套 Vision**（单测钉住形状）。
* **TLS 记录边界必须按状态机跟踪**：TCP 段边界与记录边界不对齐，一段里可能
  只有半条记录。`TlsRecordTracker` 做跨读的记录头拼接 + 负载首字节取样。
* **`ChangeCipherSpec` 必须排除**：TLS 1.3 的 CCS 是 `17 03 03 00 01 01`，
  与加密记录线格式一样。把它当成「握手结束」会让服务端在加密握手**开始前**
  就切裸字节（实测：终止帧 content 正好是 62 字节的 CCS）。单测
  `tracker_recognises_ccs_and_record_boundaries` 钉住。
* **客户端其实已经完成握手并发出了请求**：服务端日志稳定显示
  `up_bytes=585`（ClientHello 321 + Finished/HTTP 请求 264）、
  `down_bytes≈4870`（ServerHello 飞行 + 目标站响应），且**没有报错**。
  也就是说读侧、转发、回程写出都在工作。
* **我们自己的两端端到端跑通**：`vision_pair_round_trips_end_to_end` 绿。

### 对照基准已核实（重要）

* 实测用的二进制 `Xray 26.3.27 ... d2758a0` 是 **XTLS/Xray-core 官方仓库**
  构建的（README = Project X、LICENSE = MPL-2.0、符号里全是
  `github.com/xtls/xray-core/...`）。
* `d2758a0` 就是 **v26.3.27 的发布 commit**（该 commit 只改了版本号
  26.3.23 → 26.3.27）。
* 该 commit 上的 `proxy/proxy.go`（`VisionWriter` / `XtlsPadding` /
  `XtlsUnpadding` / `XtlsFilterTls` / `IsCompleteRecord`）与 `main` **逐字一致**
  —— 所以拿 `main` 做对照是有效的，不存在版本漂移。

### 写侧已改为与 upstream 逐条对应

```
if IsTLS && b.Len()>=6 && Equal(TlsApplicationDataStart, b.BytesTo(3)) && isComplete {
    command = (i==len-1) ? (EnableXtls ? DIRECT : END) : CONTINUE
    *isPadding = false
}
```

三个之前理解错的点，现已按 upstream 实现：

1. **`isComplete` = 整段全部由完整的 `0x17` 记录组成**（逐字实现
   `IsCompleteRecord`），不是「停在记录边界上」。ServerHello 那一段以
   `0x16` 开头 → 不完整 → 继续 CONTINUE。
2. **`EnableXtls`**：从 ServerHello 负载里取 cipher suite（偏移已修正：
   `hello` 含 4 字节 handshake 头，所以是 `38 + sid_len` 起 2 字节），
   配合 `supported_versions` 扩展判定 TLS 1.3。
3. **`longPadding` 仅在有 `IsTLS` 之后为真**。

实测确认这三处生效：抓帧看到

```
frame1 cmd=0x00 (ServerHello, 16…)  isComplete=false
frame2 cmd=0x00 (加密握手, 非 16 开头) isComplete=false
frame3 cmd=0x02 (DIRECT, 17…完整)   isComplete=true  xtls=true
```

即**终止命令已经落在正确的那一帧上**（应用数据、整段完整、DIRECT）。

### 线上字节是自证的

`upstream_unpadding_accepts_our_wire_bytes` 把上游 `proxy.XtlsUnpadding`
的状态机**逐字移植**过来，用它去解**我们服务端真实写出的字节**（含
`WithinPaddingBuffers` / `CurrentCommand` 的退出规则）。这条离线对拍是
「我们的线上字节符合官方读侧预期」的直接证据 —— 不必依赖官方客户端。

### 验收判据

| 检查 | 结果 |
|---|---|
| `scripts/e2e-vision-test.sh` 第 2 条（官方客户端 flow=vision） | ✅ **HTTP 200** |
| `scripts/e2e-vision-test.sh` 第 3/4 条（空 flow、抗探测） | ✅ |
| `./scripts/check.sh` | ✅ 9/9 |
| `cargo test --workspace` | ✅ 全绿（24 / 8 / 37 / 58） |
| `e2e-wasm-to-wasm-test.sh` | ✅ 5/5（第 4 步已收紧为「带 Vision 的自环也必须 200」） |
| `e2e-server-test.sh` | ✅ 未回归 |
| `e2e-test.sh`（wasm 客户端 → stock Xray 服务端） | ❌ **红，但是既有问题**：在 HEAD 干净 worktree 上逐字复现（见 `docs/verification-log.md` V27），与本方案的改动无关 |

---

## 4. 不要做的事

* **不要把「脚本取值 bug」当成「协议没通」**：这次就因此多排查了好几轮。
  验收脚本里凡是 `$(...)` 捕获的函数，进度/日志一律走 stderr。
* **不要为了让 e2e 变绿而放宽断言**；也不要靠删断言把红变绿。
* **不要静默降级**：不认识的 flow 必须报错并说明原因。
* **不要把 Vision 和 V24 的自旋 bug 混在一起做**。
