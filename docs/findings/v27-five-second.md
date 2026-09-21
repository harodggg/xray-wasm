# V27-D：那「精确 5.000s」在**客户端/运行时**一侧

> 任务：`task-21`。写者：`v27-cold-warm`（V27-B 同一人，接手 lead 立案的定位任务）。
> 复现：`./scripts/v27-five-second.sh`（可指定 `XW_V27D_PORT`/`XW_V27D_SOCKS`）。
> 结论口径：**只写实测到的**；没测到的写「未验证」。

## 0. 一句话结论

**5 秒不在官方服务端，也不在 TLS/REALITY 层，而在客户端：位置是「REALITY 握手已经双向完成、
SOCKS5 已放行」之后到「客户端把第一个应用记录写出去」之前。**

* 服务端收到合法 ClientHello 后 **0.24–0.44s** 内就把 `ServerHello` **和** 2657 字节的
  加密飞行包（TLS record type=23）一起写完了；
* 服务端在同一毫秒就**读到了客户端的 Finished**（`hs.readClientFinished() err: <nil>`），
  即 REALITY 握手本身只要 ~0.25s；
* 之后服务端干等 **5.001s** 才收到客户端的第一个应用记录（`firstLen = 52`，VLESS 头）；
* curl 侧同样：`SOCKS5 request granted` 在 +0.22s 就回来了，但首个响应字节在 **+5.87s**。

所以 ``REALITY_HANDSHAKE_TIMEOUT``（10s）与这个 5s **不是同一条路径**：死线管的是握手，
而 5s 发生在握手成功之后。V27 的红里至少有两种形态（见 §4）。

## 1. 裸探针：服务端侧一点不慢

`scripts/v27-five-second.sh` 第 1 步：Python 用 server.json 的 privateKey 现算公钥，
按 REALITY 客户端语义封装 session_id（X25519 + HKDF-SHA256(salt=random[0:20], info=b"REALITY")
+ AES-256-GCM(AAD=整条 ClientHello)），**走认证路径**，读完整条 ServerHello 与第一个 type=23 记录。

```
── 1) 裸探针（真 REALITY 认证）：服务端多久发出 ServerHello / 加密飞行包 ──
  冷启动轮 1 冷: t_ServerHello=0.444  t_first_encrypted_flight=0.444  records=22:122@0.444 20:1@0.444 23:2658@0.444
  冷启动轮 1 热: t_ServerHello=0.261  t_first_encrypted_flight=0.261  records=22:122@0.261 20:1@0.261 23:2658@0.261
  冷启动轮 1 热: t_ServerHello=0.237  t_first_encrypted_flight=0.237  records=22:122@0.237 20:1@0.237 23:2657@0.237
  冷启动轮 2 冷: t_ServerHello=0.291  t_first_encrypted_flight=0.291  records=22:122@0.291 20:1@0.291 23:2657@0.291
  冷启动轮 2 热: t_ServerHello=0.288  t_first_encrypted_flight=0.288  records=22:122@0.288 20:1@0.288 23:2657@0.288
  冷启动轮 2 热: t_ServerHello=0.266  t_first_encrypted_flight=0.266  records=22:122@0.266 20:1@0.266 23:2658@0.266
```

判读：`ServerHello` 与加密飞行包**同一时刻**（差值 <1ms，记在同一行），冷启动第一连 0.29–0.44s、
第 2/3 连 0.24–0.29s。**服务端没有「5s 后才发飞行包」这回事**。
（这份探针自己跑在 8643/1091 之外；倍率与网络有关，同一次运行内冷/热可比。）

## 2. 完整隧道：服务端日志 + curl -v 对表

`scripts/v27-five-second.sh` 第 2 步，两侧日志都用同一个绝对时钟（逐行 `time.time()` 前缀）：

```
  服务端: ClientHello=1789899968.482  ServerHello=1789899968.796 (++0.314)
          readClientFinished=1789899968.797 (++0.001)
          first-postHandshake=1789899973.798 (++5.001)  firstLen=1789899973.798 (++0.000)
  客户端: curl SOCKS5 request granted=1789899968.797 ...
  curl  : curl-done code=200 ttfb=5.865118 total=5.865254
```

同一现场用 `curl -v` 逐行打时间戳的一次（`/tmp/v27b/log/xv.curl`，另一次独立运行）：

```
1789899810.437 * SOCKS5 connect to example.com:443 (remotely resolved)
1789899810.661 * SOCKS5 request granted.                 ← 客户端已建好隧道并放行
1789899810.661 * (304) (OUT), TLS handshake, Client hello (1): } [316 bytes data]   ← curl 立刻发了首包
1789899815.890 * (304) (IN), TLS handshake, Server hello (2): { [122 bytes data]    ← 5.229s 后才见回应
```

服务端同一连接的日志（同一时钟）：

```
1789899810.438 REALITY remoteAddr: 127.0.0.1:56849
1789899810.660 REALITY remoteAddr: 127.0.0.1:56849	Server Hello: 127
1789899810.661 REALITY remoteAddr: 127.0.0.1:56849	hs.readClientFinished() err: <nil>
1789899815.662 REALITY remoteAddr: 127.0.0.1:56849	len(postHandshakeRecord): 450
```

**时间分解（这一条）**：ClientHello→ServerHello +0.222s；ServerHello→客户端 Finished 被服务端读到
**+0.001s**（双向握手完成）；→ 服务端收到客户端第一个应用记录 **+5.001s**。
curl 在 +0.661s 就把 316 字节塞进了 SOCKS 连接，这 5 秒是**客户端把它转出去**花的。

## 3. 判定

| 候选 | 判定 | 证据 |
|---|---|---|
| 官方服务端节拍 | **排除** | 裸探针：ServerHello 与加密飞行包都在 ≤0.44s；服务端 `readClientFinished→firstLen` 之间只是**等客户端** |
| TLS/REALITY 层节拍 | **排除** | 服务端在 ServerHello 同一毫秒读到客户端 Finished；握手本身 ~0.25s。（本仓库 reality.rs / 运行时都没有 5s 常量，lead 已核过） |
| 10s 死线 | **不是这 5s 的成因** | 死线包住的是握手，而 5s 在握手成功之后；`readClientFinished` 早于它 5.001s |
| **客户端 / 运行时** | **成立** | SOCKS 放行在 +0.22s、curl 首包在 +0.66s，而转出发生在 +5.66s；缺口完全在 guest 内 |

**位置**：在 `open_tunnel` 返回（REALITY 完成、`write_reply_ok` 已发出）之后，`relay_bidirectional`
把来自 SOCKS 侧的第一个 payload 写到隧道之前。即**首个应用数据写路径**，不是握手读路径。

## 4. 尚未确定的（未验证）

1. **这 5 秒是「固定 5s」还是「5s 一次的轮询节拍」**：所有样本都精确落在 +5.001/+5.002s，
   强指向一个 5s 周期；但**没有找到任何源码常量**（`crates/**` 里无处 `from_secs(5)`，
   wstd 0.6.8 里也没有）。所以「谁提供的节拍」**未验证**。
   * 线索：V27-B 的 10 次分解里，有 1 次落在 **+10.002s**（两个节拍）→ 更像「周期性重投递」而非
     「一次性 sleep(5)」；如果是固定 sleep，不该出现 10s。
2. **卡在哪个流**：客户端这条连接上有两个 `NetStream`（SOCKS 侧 / 隧道侧）。
   未分别插桩，**未验证**是「从 SOCKS 流读得晚」还是「往隧道流写得晚」。
3. **`--no-flow` 的对照**：把客户端设 `XT_NO_FLOW=1` 跑同一现场，**30s 内服务端始终没有收到
   VLESS 头**（curl `-m 30` 超时，code=000），而 `flow` 默认路径是 +5.001s。
   注意本测试服务端声明 `flow: xtls-rprx-vision`，`--no-flow` 本来就不是受支持的互通组合，
   所以这条**不能**用来证明 Vision 是成因；只能作为「首写路径确实卡住、且节拍可能变长」的旁证。
   **未验证**。
4. **为什么只有「进程的第一条连接」**：同一客户端进程内第 2/3 条隧道稳定 ~0.55s（见
   `v27-cold-warm.md` §2）。→ 与「首个写入」相关的初始化/一次性状态有关，机制**未验证**。

## 5. 与 v27-wake 结论的关系（需要合并口径）

`docs/findings/v27-wake.md` 的结论是「卡住期间 socket 上**根本没有数据**，数据到达时立刻被唤醒」。
两者的观测窗口不同、指向的也可能是两种形态：

* 他们在 17:37–17:46 窗口测到官方服务端首个飞行包要 17.1–19.3s 才出现（那是**服务端/链路慢**），
  此时 `subscribe().ready()==false` 是对的；
* 本文在 17:5x–18:2x 窗口测到服务端 ≤0.44s 就发完飞行包，而客户端仍要 5.000s 才把**首个应用写**
  发出去 —— 这时 socket 上不可能没数据（飞行包已在客户端读走，握手都完成了）。

⇒ 两者不矛盾：V27 至少有两种可独立触发的形态。**建议公告板把「5.000s 首写节拍（客户端侧）」
与「服务端首个飞行包晚于 10s（服务端/链路侧）」分开列**，否则「有时绿有时红」会被归到一个原因上。

## 6. 复现

```sh
cd /Users/xbtg-/deepseek-harness/xray-wasm
. scripts/env.sh
./scripts/v27-five-second.sh                 # 默认 8643/1091
XW_V27D_PORT=8645 XW_V27D_SOCKS=1095 ./scripts/v27-five-second.sh   # 避开占用
```

脚本会：冻结 target 下的 wasm（打印 sha256）、把 xray/wasmtime 复制改名后使用
（避免队友 `pkill -f xray`/`-f wasmtime` 误杀）、用 `scripts/gen-test-server.sh` 现生成一套
一次性凭据、跑完清理自己的进程。原始日志留在 `$WORK/log/`（默认 `/tmp/v27f/log/`）。

本次运行的被测 wasm sha256：`ec442a392aacaa285d5f1cabbf451f49180c7695989f7eb0442d1b9e789f64f9`。
