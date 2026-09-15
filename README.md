# xray-wasm

把 Xray 的 **VLESS + XTLS-Vision + REALITY** 协议栈用 **纯 Rust** 重写，
编译成 **wasm32-wasip2**，在 **wasmtime** 下跑真实的 TCP 代理。

**两个方向都实现了，同一个二进制靠子命令切换：**

| 方向 | 角色 | 入口 | 状态 |
|---|---|---|---|
| **socket → REALITY**（封装） | 客户端（出站） | 无子命令（默认） | ✅ 已实现，对官方服务端验证过 |
| **REALITY → socket**（解封装） | 服务端（入站） | `server` 子命令 | ✅ 已实现，被官方客户端验证过 |

```sh
# 客户端：本地 SOCKS5 → REALITY 隧道
docker run --rm -p 127.0.0.1:1080:1080 \
  -e XT_LISTEN=0.0.0.0:1080 \
  -e XT_SERVER=<服务端 ip:port> -e XT_PBK=<公钥> -e XT_SID=<shortId> \
  -e XT_SNI=<伪装域名> -e XT_UUID=<uuid> \
  ghcr.io/harodggg/xray-wasm:v0.4.0

# 服务端：REALITY 入站 → 目标站（k3s 用这个）
docker run --rm -p 8443:8443 \
  -e XT_PRIVATE_KEY=<私钥> -e XT_SHORT_IDS=<shortId> \
  -e XT_SERVER_NAMES=<伪装域名> -e XT_DEST=<同一个域名的 host:port> \
  -e XT_USERS=<uuid> \
  ghcr.io/harodggg/xray-wasm:v0.4.0 server
```

> 验证过程与原始输出见 [`docs/verification-log.md`](docs/verification-log.md)。
> 100 个单元测试 + 两个方向的真实端到端（对接官方 Xray-core）在 CI 里常态化跑。

---

## 给自动化 agent 的速查

需要在一个集群里把服务端跑起来时，按这个顺序做，**每一步都有可断言的输出**：

```sh
# 1) 生成凭据（只需要官方 xray 二进制，或任意 X25519 工具）
xray x25519
#   PrivateKey: <PRIV>              → 服务端 XT_PRIVATE_KEY
#   Password (PublicKey): <PUB>     → 客户端 XT_PBK
#   ⚠️ 这两行极易看反，看反的症状是客户端握手后拿到一个不属于自己 dest 的证书
SID=$(openssl rand -hex 8)          # → 两端 XT_SHORT_IDS / XT_SID
UUID=$(uuidgen | tr 'A-Z' 'a-z')    # → 两端 XT_USERS / XT_UUID

# 2) 部署服务端（k3s 自带 ServiceLB，LoadBalancer 会直接绑到节点 IP）
kubectl apply -f deploy/k8s/server-secret.example.yaml   # 先填好副本
kubectl apply -f deploy/k8s/server.yaml
kubectl rollout status deploy/xray-wasm-server
kubectl get svc xray-wasm-server        # EXTERNAL-IP 就是节点 IP，端口 8443

# 3) 断言：外部探测者必须看到 XT_DEST 的真实证书，而不是我们伪造的
#    注意不要解析 openssl 的人类可读输出 —— macOS(LibreSSL) 与 Ubuntu(OpenSSL 3)
#    的排版不同（`CN=` vs `CN = `、`a:PKEY: EC` vs `id-ecPublicKey`），
#    在一边通过、在另一边红。把证书取出来做结构化判定：
echo | openssl s_client -connect <节点IP>:8443 -servername <伪装域名> 2>/dev/null \
  | openssl x509 -noout -subject -nameopt RFC2253
#   期望：subject=CN=<伪装域名>
echo | openssl s_client -connect <节点IP>:8443 -servername <伪装域名> 2>/dev/null \
  | openssl x509 -noout -pubkey | openssl pkey -pubin -text -noout
#   期望：prime256v1（dest 的真实 EC 公钥）
#   若出现 ED25519 —— 说明回退没生效，服务端正在对探测者暴露自己

# 4) 断言：客户端能真的出去
curl -sS -o /dev/null -w '%{http_code}\n' --proxy socks5h://127.0.0.1:1080 https://example.com
#   期望：200
```

**必须记住的三条硬约束**（违反任一条都会得到一个「看起来在跑但不可用」的服务端）：

1. **客户端 `flow` 必须留空。** 服务端的 XTLS-Vision（服务端侧流控）**尚未实现**；
   请求里带非空 flow 时服务端会**明确报错**，不会静默降级。
   官方 Xray 客户端的 `users[].flow` 写 `""`。
2. **`XT_SERVER_NAMES` 与 `XT_DEST` 必须指向同一个真实站点。**
   否则认证失败时，探测者请求的 SNI 与拿到的证书域名对不上 —— 等于自曝。
3. **节点时钟必须准。** REALITY 校验客户端时间戳，超出 `XT_MAX_TIME_DIFF`（默认 60 秒）
   即认证失败。虚拟机从挂起恢复后时钟漂移是「昨天还好好的」的头号原因。

---

## 获取

| 方式 | 位置 |
|---|---|
| wasm 模块 | [Releases](https://github.com/harodggg/xray-wasm/releases) 里的 `xt-wasm-cli.wasm`（附 `SHA256SUMS`） |
| 容器镜像 | `ghcr.io/harodggg/xray-wasm:v0.4.0`（amd64 / arm64，匿名可拉） |
| 自行构建 | 见下方「从源码构建」 |

k8s 部署清单与安全须知：[`deploy/k8s/`](deploy/k8s/README.md)。
（客户端：`deployment.yaml` / `service.yaml` / `sidecar.example.yaml`；
服务端：`server.yaml` / `server-secret.example.yaml` / `server-networkpolicy.yaml`。）

---

## 从源码构建

```sh
# 0. 加载构建环境（必须，见下方「三个坑」）
cd xray-wasm && . scripts/env.sh

# 1. 编译到 wasm
cargo build -p xt-wasm-cli --release --target wasm32-wasip2
#    → $CARGO_TARGET_DIR/wasm32-wasip2/release/xt-wasm-cli.wasm

# 2. 全部静态检查 + 单测（本地与 CI 跑的是同一条命令）
./scripts/check.sh

# 3. 构建容器镜像
./scripts/build-image.sh <tag>
```

两个方向的端到端验收（都需要官方 `xray` 二进制，脚本会现场生成全新凭据）：

```sh
# 客户端方向：我们的 wasm 客户端 → stock Xray REALITY 服务端 → 外网
./scripts/gen-test-server.sh && . .test-server/params.env
XW_XRAY_DIR=$PWD/.test-server ./scripts/e2e-test.sh

# 服务端方向：stock Xray 客户端 → 我们的 wasm REALITY 服务端 → 外网
./scripts/e2e-server-test.sh
```

服务端方向那条还会断言「未认证的探测者看到 dest 的真实 EC 证书」——
这是 REALITY 抗主动探测的核心属性，也是唯一能证明回退真的生效的检查。

---

## 命令

`--help` / `server --help` 是权威来源；下面是等价的速查。

### 客户端（默认，无子命令）

```
xt-wasm-cli --self-test --server <ip:port> --pbk <base64url> --sid <hex> --sni <域名>
xt-wasm-cli --server <ip:port> --pbk <...> --sid <...> --sni <...> --uuid <uuid> [--listen 127.0.0.1:1080]
```

| 参数 | 环境变量 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `--server` | `XT_SERVER` | ✅ | | REALITY 服务端 `ip:port` |
| `--pbk` | `XT_PBK` | ✅ | | 服务端公钥（base64url，`xray x25519` 的 `Password (PublicKey)`） |
| `--sid` | `XT_SID` | ✅ | | shortId（hex，≤16 字符，不足 8 字节右侧补 0） |
| `--sni` | `XT_SNI` | ✅ | | 伪装域名，必须命中服务端的 `serverNames` |
| `--uuid` | `XT_UUID` | ✅ | | VLESS 用户 UUID |
| `--listen` | `XT_LISTEN` | | `127.0.0.1:1080` | SOCKS5 监听地址 |
| `--socks-user` | `XT_SOCKS_USER` | | | SOCKS5 用户名；**与 `--socks-pass` 必须同时给出** |
| `--socks-pass` | `XT_SOCKS_PASS` | | | SOCKS5 密码 |
| `--handshake-timeout` | `XT_HANDSHAKE_TIMEOUT` | | `15` | 协商阶段读超时（秒） |
| `--client-ver` | `XT_CLIENT_VER` | | `26.3.27` | REALITY 上报的 ClientVer，须落在服务端 `min/maxClientVer` 区间内 |
| `--self-test` | `XT_SELF_TEST` | | | 只做 REALITY 握手并报告耗时，不起 SOCKS5 |
| （无参数） | `XT_MODE=server` | | | 等价于子命令 `server`，供不方便写 args 的部署使用 |

### 服务端（`server` 子命令，为 k3s 而写）

```
xt-wasm-cli server --private-key <base64url> --short-ids <hex[,hex...]> \
                   --server-names <域名[,域名...]> --dest <host:port> \
                   --users <uuid[,uuid...]> [--listen 0.0.0.0:8443] [--max-time-diff 60]
```

| 参数 | 环境变量 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `--private-key` | `XT_PRIVATE_KEY` | ✅ | | X25519 **私钥**（base64url，`xray x25519` 的 `PrivateKey`） |
| `--short-ids` | `XT_SHORT_IDS` | ✅ | | 逗号分隔的 shortId（hex）。**空列表直接拒绝启动** |
| `--server-names` | `XT_SERVER_NAMES` | ✅ | | 逗号分隔的 SNI 白名单。必须与 `dest` 指向同一站点 |
| `--dest` | `XT_DEST` | ✅ | | 认证失败时原样转发的目标 `host:port`，应是真实 TLS 站点 |
| `--users` | `XT_USERS` | ✅ | | 逗号分隔的 VLESS UUID。**空列表直接拒绝启动** |
| `--listen` | `XT_SERVER_LISTEN` | | `0.0.0.0:8443` | 入站监听地址（注意与客户端的 `XT_LISTEN` 不是同一个变量） |
| `--max-time-diff` | `XT_MAX_TIME_DIFF` | | `60` | REALITY 时间戳容差（秒） |

配置解析顺序：**环境变量打底，命令行覆盖**。所有必填项缺失时以退出码 `2` 失败并说明原因。

**为什么服务端也做环境变量**：k8s 里 `kubectl describe pod` 会把 `args` 原样打印，
`kubectl get deploy -o yaml` 也是。密钥走 Secret → 环境变量，至少还隔着一层 RBAC。

**服务端的安全取向与客户端相反**：客户端默认只绑回环并警告开放代理；
服务端**天生就要暴露**（否则没人连得上），所以它的守卫是
「`users` / `short_ids` 为空就拒绝启动」——那种配置一定进不来任何人，几乎总是笔误。

---

## REALITY 入站（服务端）

### 一条连接会发生什么

```
公网客户端 → listen :8443
  ├─ 读第一条 TLS 记录（ClientHello）
  ├─ REALITY 认证：ECDH(x25519) → HKDF-SHA256 → AES-256-GCM 解 session_id
  │     明文 = [ver(3)][0][客户端时间戳(4)][shortId(8)]
  │     校验：版本区间 / |now - ts| ≤ max_time_diff / shortId 在列表里 / SNI 在列表里
  │
  ├─ 认证通过 → TLS 1.3 服务端握手（伪造证书，见下）→ 解 VLESS 请求头
  │     ├─ UUID 不在 users 里 → 报错断开（"认证过了" ≠ "这个用户被允许"）
  │     ├─ flow 非空 → 明确报 Unsupported（Vision 服务端侧未实现）
  │     └─ 回 2 字节 VLESS 响应头 [0x00, 0x00] → 连目标 → 双向转发
  │
  └─ 认证失败 → 连 dest，把**已经读走的那段 ClientHello 原样补发**给 dest，
                然后双向转发 —— 探测者看到的是一次访问真实站点的普通 TLS 会话
```

### 伪造证书的原理

客户端校验的不是证书链，而是一条 HMAC：

```
HMAC-SHA512(authKey, 证书里的 ed25519 公钥) == 证书的签名字段
```

`authKey` 来自客户端自己的 key_share，只有真服务端能算出来。所以服务端每连接
生成一对临时 ed25519 密钥，把公钥放进 SPKI，把 HMAC 结果放进 `signatureValue`。

> 这里踩过一个只对自己测永远发现不了的坑：第一版证书的 issuer / validity /
> signatureAlgorithm 都是空 SEQUENCE，我们自己的解析器能过，官方客户端直接回
> `bad_certificate`（alert `02 2a`）。**能被自己解析 ≠ 是合法的编码。**
> 现在 `forge_certificate` 会拼一份结构完整的 X.509 v3。

### 跨实现验证（已经跑通，可一键复现）

官方 Xray 客户端 → 我们的服务端 → `example.com` = **HTTP 200**；
同时 `openssl s_client` 探测同一个端口，拿到的是 dest 真实证书（`CN=www.cloudflare.com`，
`a:PKEY: EC`），没有任何伪造证书泄漏。

```sh
# CI 里常态化的那条（现场生成全新凭据，5 条断言）
./scripts/e2e-server-test.sh

# 只测握手层的最小复现
cargo run -p xt-wasm-tls --release --example reality_server_probe -- \
    4042424242424242424242424242424242424242424242424242424242424242 \
    deadbeef00112233 www.cloudflare.com 18450
```

### 日志的形态（写给要接日志的人）

```
[server] REALITY 入站：监听 0.0.0.0:8443，SNI ["www.example.com"]，用户 1 个，dest www.example.com:443
[server] 认证失败的连接会被原样转发到 dest（这是设计行为，不是漏洞）
[server] 10.0.0.5:51234 认证通过 user=8f1c…-… -> example.com:443
[server] 10.0.0.5:51234 未认证（sni=www.example.com），转发到 dest
[server] 10.0.0.5:51234 结束：Forwarded { target: "example.com:443" }
[server] 10.0.0.5:51235 失败：proxy authentication failed
```

两条设计决定，接日志/告警前请先知道：

* **判定一出就写「认证通过 / 未认证」，不等连接结束。** 长连接可能挂几小时，
  「断开时才记一笔」的日志在运维上没有意义。为此库层专门提供了
  `serve_inbound_with_events`（`serve_inbound` 是它的空回调包装）。
* **空连接（连上就关）刻意不记日志。** k8s 的 `tcpSocket` 探针、端口扫描器、
  LB 健康检查都长这样，是公网端口上最频繁的事件。它们在库层被识别成
  `InboundOutcome::EmptyConnection`（**不是 `Err`**），CLI 对它静默。否则探针每
  10 秒一行错误日志，真故障会被淹掉。

### 服务端的已知限制

| 限制 | 影响 |
|---|---|
| **服务端侧 XTLS-Vision 未实现** | 客户端必须把 `flow` 留空。带 flow 的请求会被明确拒绝（不是静默降级） |
| **只支持 VLESS TCP** | 无 UDP、无 Mux、无 `xtls-rprx-vision-udp443` |
| **single-hop，无 uTLS 服务端指纹伪装** | 证书与握手形状按 REALITY 要求构造，但不做额外的 TLS 栈指纹伪装 |
| **并发上限 256**（`MAX_CONCURRENT_CONNS`） | 满了会等槽位而不是丢弃连接 |

---

## 在 Kubernetes / k3s 里跑

详见 [`deploy/k8s/README.md`](deploy/k8s/README.md)。摘要：

| | 客户端 | 服务端 |
|---|---|---|
| 清单 | `deployment.yaml` + `service.yaml` | `server.yaml` + `server-networkpolicy.yaml` |
| Secret | `secret.example.yaml` | `server-secret.example.yaml` |
| Service 类型 | `ClusterIP`（**刻意不用 NodePort/LB**） | `LoadBalancer`（k3s ServiceLB 直接绑节点 IP） |
| 子命令 | 无 | `args: ["server"]` |
| 默认监听 | `127.0.0.1:1080`（安全默认值，共享模式需显式改 `0.0.0.0`） | `0.0.0.0:8443`（服务端天生要暴露） |
| egress 策略 | 收紧到服务端固定 IP | **必须开放**（它要代表客户端连任意目标），只封私有网段防打内网 |

---

## 架构

```
xray-wasm/
  crates/
    xt-wasm-runtime/   shim 类型 + 平台 socket 层（wasm 直连 wasi:sockets / 宿主用 std）+ 事件循环
    xt-wasm-tls/       手写 TLS 1.3 + REALITY 客户端（移植自 meow-rs）+ REALITY 服务端（原创）
    xt-wasm-vless/     VLESS 请求头 + XTLS-Vision 流控（移植自 meow-rs）+ VLESS 服务端解码（原创）
    xt-wasm-cli/       SOCKS5 客户端 + REALITY 入站编排 + 入口（两个模式同一个二进制）
  deploy/k8s/          Kubernetes 清单与部署须知
  docs/
    verification-log.md  每条结论的可复现实验与原始输出（V1–V20）
    port-map.md          移植依赖图（meow-rs 的精确依赖面与陷阱）
  scripts/
    check.sh             本地 = CI 的全部检查（唯一事实来源）
    env.sh               构建/运行环境
    gen-test-server.sh   生成一次性测试服务端
    run-local.sh         wasmtime 启动封装
    e2e-test.sh          端到端：我们的客户端 → stock 服务端
    e2e-server-test.sh   端到端：stock 客户端 → 我们的服务端
    build-image.sh       构建容器镜像
```

数据流（客户端）：

```
curl --proxy socks5h://…
  → SOCKS5 协商（含可选认证）
  → RealityTlsLayer::connect    TLS 1.3 + REALITY 认证（session_id 里塞 X25519 证明）
  → VlessConn::new_deferred     VLESS 请求头（含 xtls-rprx-vision 声明）
  → VisionConn::new             XTLS-Vision 流控
  → relay_bidirectional         两个方向并发搬运
```

**协议层与 socket 层是解耦的**：`xt-wasm-tls` / `xt-wasm-vless` 只依赖 tokio 的
`AsyncRead`/`AsyncWrite`，所以把底下的 socket 从 `std::net` 换成 `wasi:sockets` 时，
协议层**一行没改**。

---

## 为什么是这些技术选择

| 选择 | 原因 |
|---|---|
| **wasip2** 而不是 wasip1 | wasip1 的 `TcpStream::connect` 在 Rust 标准库里字面就是 `unsupported()`，**发不出站 TCP**。已实测，换运行时也救不了 |
| **wasmtime 的四个 flag** | `-S tcp=y -S inherit-network=y -S allow-ip-name-lookup=y -S inherit-env=y` **缺一不可**。缺 `inherit-network` 报 `PermissionDenied`（像被墙）；缺 `inherit-env` 则认证配置静默失效 |
| **纯 Rust 手写 TLS** | REALITY 的认证藏在 ClientHello 的 `session_id` 里，需要字节级控制；`rustls` 不暴露该控制点。而 `boring`(BoringSSL) 是 C++，编译到 wasm 代价极高 |
| **非阻塞 socket + 自研事件循环** | wasip2 没有 tokio reactor，也没有线程。socket 用 `wasi:sockets` 直连（非阻塞、pollable 就绪通知），事件循环用 Bytecode Alliance 的 `wstd` |
| **不使用 ML-KEM** | 现代 Chrome 指纹走 X25519MLKEM768 混合交换，但已实测服务端**同样接受纯 X25519**（见 V7），省掉一整个依赖。官方客户端的 ClientHello 里**同时**带纯 X25519 key_share，所以服务端侧也不必实现 ML-KEM |

---

## 三个坑（`scripts/env.sh` 就是为它们存在的）

1. **`CARGO_HOME` 指向不可写的 `~/.cargo`** → 依赖缓存改放工作区
   （CI 里用 `XW_CARGO_HOME` 显式指回标准路径以便缓存命中）。
2. **Homebrew 的 `rustc` 遮蔽 rustup 的 shim** → `rust-toolchain.toml` 失效，
   还会用错误的 rustc 编 wasm，报错是「can't find crate for core」，看不出真正原因。
3. **wasmtime 把 JIT 缓存写 `~/Library/Caches`** → 受限环境下直接报错退出。
   所有脚本都用 `-C cache=n` 绕开。

---

## 安全：客户端默认不是开放代理

一个**无认证**的 SOCKS5 代理一旦绑到非回环地址就是**开放代理**：
任何能连上该端口的人都能免费用你的隧道出网。客户端模式对此有三层防护：

1. **认证**（`--socks-user`/`--socks-pass`）。配置了认证时，即使客户端同时声明支持
   「无认证」，服务端也**绝不回退**（有专门的单测钉住这条）。
2. **显式警告**：绑非回环 + 无认证时，启动即打印醒目警告。
3. **容器镜像默认监听 `127.0.0.1`**，要用 Service 暴露必须显式改成 `0.0.0.0`。

端到端脚本里有两个**负向用例**守着这条线：不带凭据必须被拒、错误凭据必须被拒。

服务端模式的对应要点：

* `XT_PRIVATE_KEY` 是**长期密钥**，泄漏等于身份泄漏 → 必须走 Secret，且与客户端的
  `XT_*` 分开管理（它们不该放在同一个 Secret 里）。
* `dest` 回退意味着服务端会**主动向外发起连接**，NetworkPolicy 必须允许，
  否则探测者拿不到真实站点、伪装立刻失效。
* 服务端直接面对未认证的公网流量，**暴露面比客户端大得多**。在 wasm 沙箱里跑
  有隔离优势，但这不改变「协议实现必须正确」的要求。

---

## 已知限制（诚实清单）

| 限制 | 影响 | 说明 |
|---|---|---|
| **服务端无 XTLS-Vision** | 客户端必须 `flow: ""` | 带 flow 的请求被明确拒绝，不会静默做错 |
| **TLS 指纹非浏览器形状** | 功能可用，但抗 JA3/JA4 与主动探测弱于官方客户端 | 手写 ClientHello 未实现 uTLS 的 Chrome 伪装 |
| **无 XTLS-Vision DIRECT splice** | 仅性能差异，不影响连通 | 功能路径完整 |
| **无 UDP / Mux / 后量子** | QUIC / HTTP3 经此代理不可用 | ML-KEM、ML-DSA-65、`VlessPacketConn` 均未实现 |
| **无 SOCKS5 UDP ASSOCIATE / BIND** | 仅支持 CONNECT | 对验证协议栈无增量价值 |

> 宿主机构建（用于单元测试与本地调试）是**轮询式**的：宿主没有 pollable，
> 只能「试 + 让出」。**wasm 才是产品**，它跑在真正的 reactor 上。
> 所以宿主的 CPU 占用不代表线上表现。

### 并发与事件循环

wasip2 没有线程，但支持非阻塞 socket。实现为**单线程协作式并发**：
主循环只 accept，每条连接交给事件循环；socket 是非阻塞的，
**挂起与唤醒由 pollable 完成**（`wasi:io/poll`），不是轮询。
并发上限：客户端 64、服务端 256（各是一个 `MAX_CONCURRENT_CONNS` 常量），
满了会等槽位而不是丢弃连接（丢弃会让 k8s 探针失败并触发重启）。

一条 keep-alive 长连接**不会**独占代理。A/B 对照实测：

| 实现 | 长连接占用期间的新请求 |
|---|---|
| v0.1 顺序 accept | **超时失败，12s** |
| v0.2 起（非阻塞并发） | **HTTP 200，1s** |

去轮询的效果（30 秒空闲 CPU，两点法扣除 JIT 启动）：

| 版本 | 空闲 CPU |
|---|---|
| v0.2（1ms 轮询） | **0.233s**（约 0.78%） |
| v0.3（reactor 就绪通知） | **0.014s**（约 0.05%） |

详见 [`docs/verification-log.md`](docs/verification-log.md) 的 V16 / V17。

---

## 测试

```
cargo test --workspace        # 100 passed（cli 16 / runtime 8 / tls 37 / vless 39）
./scripts/check.sh            # 上面 + fmt + clippy -D warnings + wasm 构建 + 依赖树约束
```

`scripts/check.sh` 是**唯一事实来源**：本地和 CI 调用的都是它。它存在的理由很具体 ——
写服务端阶段 2 时，先跑了 `cargo fmt` 之后又新建了一个 example 文件，CI 直接红。
只要检查步骤是手打的，就一定会有某次顺序反了或漏一项。

---

## 许可

本项目代码为 MIT。`xt-wasm-tls` 与 `xt-wasm-vless` 的**客户端**部分移植自
[meow-rs](https://github.com/meow-rs/meow-rs)（MIT，Copyright (c) 2026 Max Lv），
分析版本 `a2be4de1c315daa22e53ad1118538936241d592f`；
每个移植文件头部保留了出处声明，上游许可证见 `LICENSE.meow-rs`。

REALITY **服务端**（`reality_server.rs`、VLESS 入站解码、入站编排）是本工程自己写的，
代码没有从任何上游复制 —— 上游 `xtls/reality` 是一个 15,584 行的 Go 包（本质是
`crypto/tls` 的完整 fork），本工程移植的 `meow-rs` 明确声明 client-only。

> **更正（2026-09）**：本文件此前写着「crates.io 上也没有可用的 REALITY 服务端 crate」，
> **这是错的**。[`shoes`](https://github.com/cfal/shoes)（`cfal/shoes`，crates.io 上可拉）
> 是一个 Rust 多协议代理**服务端**，含完整的 REALITY 入站
> （`src/reality/reality_server_connection.rs`、`reality_certificate.rs`、`reality_auth.rs`），
> 也有 `examples/reality_basic.yaml` 这种服务端配置示例；另有 `undead-undead/xray-lite`
> 等 Rust 实现。所以「本工程是唯一的非 Go REALITY 服务端」不成立。
>
> 本工程与之的**实际差别只有一条**：`shoes` 依赖 `aws-lc-rs`（含 C/汇编）+ tokio + h2，
> 编译不到 `wasm32-wasip2`；本工程整条链路是纯 Rust + WASI，因此能作为**能力受限的
> wasm 组件**跑在 wasmtime 下。这是部署形态的差别，不是实现首创性的差别。
> 想在自己的 Rust 程序里嵌入 REALITY，`shoes` 比本工程更成熟、协议更全，优先用它。
