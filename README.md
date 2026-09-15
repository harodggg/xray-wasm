# xray-wasm

把 Xray 的 **VLESS + XTLS-Vision + REALITY** 客户端协议栈用 **纯 Rust** 实现，
编译成 **wasm32-wasip2**，在 **wasmtime** 下跑真实的 TCP 代理。
可作为本地 SOCKS5 代理，也可部署到 Kubernetes。

> **方向：只做了「socket → REALITY」，没做「REALITY → socket」。**
> 本工程是**客户端**：把本地明文流封装进 REALITY 隧道送出去。
> 它不做服务端，即不能接住 REALITY 连接再解封装。
> 后者用官方 Xray 服务端就能做到（见 [「REALITY 入站」](#reality-入站服务端尚未实现)一节）。

> **能用，且已对着真实 Xray 服务端端到端验证过。**
> 验证过程与原始输出见 [`docs/verification-log.md`](docs/verification-log.md)。

---

## 获取

| 方式 | 位置 |
|---|---|
| wasm 模块 | [Releases](https://github.com/harodggg/xray-wasm/releases) 里的 `xt-wasm-cli.wasm`（附 SHA-256） |
| 容器镜像（k8s） | `ghcr.io/harodggg/xray-wasm:latest`（amd64 / arm64） |
| 自行构建 | 见下方「从源码构建」 |

k8s 部署清单与安全须知：[`deploy/k8s/`](deploy/k8s/README.md)。

---

## 从源码构建

```sh
# 0. 加载构建环境（必须，见下方「三个坑」）
cd xray-wasm && . scripts/env.sh

# 1. 编译到 wasm
cargo build -p xt-wasm-cli --release --target wasm32-wasip2

# 2. 起一个本地 REALITY 服务端用于测试（用官方 xray 二进制）
./scripts/gen-test-server.sh

# 3. 跑客户端：本地 SOCKS5 → 隧道
./scripts/run-local.sh \
    --server 127.0.0.1:8443 \
    --pbk <服务端公钥 base64url> \
    --sid <shortId hex> \
    --sni <伪装域名> \
    --uuid <UUID> \
    --listen 127.0.0.1:1080

# 4. 另一终端：经隧道访问（socks5h 的 h 让服务端解析域名）
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

一条命令跑完整验收（脚本会自己拉起服务端）：

```sh
./scripts/gen-test-server.sh && . .test-server/params.env
XW_XRAY_DIR=$PWD/.test-server ./scripts/e2e-test.sh
```

构建容器镜像：

```sh
./scripts/build-image.sh <tag>
```

---

## 命令

```
xt-wasm-cli --self-test --server <ip:port> --pbk <...> --sid <...> --sni <域名>
xt-wasm-cli --server <ip:port> --pbk <...> --sid <...> --sni <...> --uuid <uuid> [--listen 127.0.0.1:1080]
```

| 选项 | 说明 |
|---|---|
| `--self-test` | 只做 REALITY 握手并报告耗时。不依赖 VLESS 层，用于快速验证网络与密钥 |
| `--socks-user` / `--socks-pass` | 启用 SOCKS5 用户名/密码认证（RFC 1929）。**绑非回环地址时强烈建议启用** |
| `--handshake-timeout` | 协商阶段读超时秒数（默认 15），防止半开连接卡死 |
| `--client-ver x.y.z` | REALITY 上报的客户端版本（默认 `26.3.27`） |

全部选项也可用环境变量给出（`XT_SERVER`、`XT_PBK`、`XT_SID`、`XT_SNI`、`XT_UUID`、
`XT_LISTEN`、`XT_CLIENT_VER`、`XT_SOCKS_USER`、`XT_SOCKS_PASS`、
`XT_HANDSHAKE_TIMEOUT`、`XT_SELF_TEST`），命令行参数优先。

**为什么需要环境变量**：k8s 里凭证应当由 Secret 注入，而不是写在 `args` 里 ——
`kubectl describe pod` 会把 args 原样打印出来。

---

## 安全：默认不是开放代理

一个**无认证**的 SOCKS5 代理一旦绑到非回环地址就是**开放代理**：
任何能连上该端口的人都能免费用你的隧道出网。本项目对此有三层防护：

1. **认证**（`--socks-user`/`--socks-pass`）。配置了认证时，即使客户端同时声明支持
   「无认证」，服务端也**绝不回退**（有专门的单测钉住这条）。
2. **显式警告**：绑非回环 + 无认证时，启动即打印醒目警告。
3. **容器镜像默认监听 `127.0.0.1`**，要用 Service 暴露必须显式改成 `0.0.0.0`。

端到端脚本里有两个**负向用例**守着这条线：不带凭据必须被拒、错误凭据必须被拒。

---

## 架构

```
xray-wasm/
  crates/
    xt-wasm-runtime/   shim 类型 + 平台 socket 层（wasm 直连 wasi:sockets / 宿主用 std）+ 事件循环
    xt-wasm-tls/       手写 TLS 1.3 + REALITY 客户端（移植自 meow-rs）
    xt-wasm-vless/     VLESS 请求头 + XTLS-Vision 流控（移植自 meow-rs）
    xt-wasm-cli/       SOCKS5 服务端 + 转发核心 + 入口
  deploy/k8s/          Kubernetes 清单与部署须知
  docs/
    verification-log.md  每条结论的可复现实验与原始输出
    port-map.md          移植依赖图（meow-rs 的精确依赖面与陷阱）
  scripts/
    env.sh               构建/运行环境
    gen-test-server.sh   生成一次性测试服务端
    run-local.sh         wasmtime 启动封装
    e2e-test.sh          端到端验收（本地与 CI 同一条命令）
    build-image.sh       构建容器镜像
```

数据流：

```
curl --proxy socks5h://…
  → SOCKS5 协商（含可选认证）
  → RealityTlsLayer::connect    TLS 1.3 + REALITY 认证（session_id 里塞 X25519 证明）
  → VlessConn::new_deferred     VLESS 请求头（含 xtls-rprx-vision 声明）
  → VisionConn::new             XTLS-Vision 流控
  → relay_bidirectional         两个方向并发搬运
```

---

## 为什么是这些技术选择

| 选择 | 原因 |
|---|---|
| **wasip2** 而不是 wasip1 | wasip1 的 `TcpStream::connect` 在 Rust 标准库里字面就是 `unsupported()`，**发不出站 TCP**。已实测，换运行时也救不了 |
| **wasmtime 的四个 flag** | `-S tcp=y -S inherit-network=y -S allow-ip-name-lookup=y -S inherit-env=y` **缺一不可**。缺 `inherit-network` 报 `PermissionDenied`（像被墙）；缺 `inherit-env` 则认证配置静默失效 |
| **纯 Rust 手写 TLS** | REALITY 的认证藏在 ClientHello 的 `session_id` 里，需要字节级控制；`rustls` 不暴露该控制点。而 `boring`(BoringSSL) 是 C++，编译到 wasm 代价极高 |
| **非阻塞 socket + 自研事件循环** | wasip2 没有 tokio reactor，也没有线程。socket 用 `wasi:sockets` 直连（非阻塞、pollable 就绪通知），事件循环用 Bytecode Alliance 的 `wstd` |
| **不使用 ML-KEM** | 现代 Chrome 指纹走 X25519MLKEM768 混合交换，但已实测服务端**同样接受纯 X25519**（见 V7），省掉一整个依赖 |

---

## 三个坑（`scripts/env.sh` 就是为它们存在的）

1. **`CARGO_HOME` 指向不可写的 `~/.cargo`** → 依赖缓存改放工作区
   （CI 里用 `XW_CARGO_HOME` 显式指回标准路径以便缓存命中）。
2. **Homebrew 的 `rustc` 遮蔽 rustup 的 shim** → `rust-toolchain.toml` 失效，
   还会用错误的 rustc 编 wasm，报错是「can't find crate for core」，看不出真正原因。
3. **wasmtime 把 JIT 缓存写 `~/Library/Caches`** → 受限环境下直接报错退出。

---

## 已知限制（诚实清单）

| 限制 | 影响 | 说明 |
|---|---|---|
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
并发上限 64（`MAX_CONCURRENT_CONNS`），满了会等槽位而不是丢弃连接。

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

## REALITY 入站（服务端）：**尚未实现**

### 一句话：只做了「socket → REALITY」，没做「REALITY → socket」

REALITY 有两个方向，本工程只实现了其中**一个**：

| 方向 | 干什么 | 对应角色 | 本工程 |
|---|---|---|---|
| **socket → REALITY** | 把本地明文流**封装**进 REALITY 隧道送出去 | 客户端（出站） | ✅ **已实现** |
| **REALITY → socket** | 接住 REALITY 连接、**解封装**成明文再送往目标 | 服务端（入站） | ❌ **未实现** |

本工程的 SOCKS5 入站是**明文**的（那是给本机程序用的），它出去的那一侧才是 REALITY。
所以它能把明文变成 REALITY，不能把 REALITY 变回明文。

### 但这不代表「REALITY → socket」做不到

**官方 Xray 服务端做的就是这件事**，而且与本工程同属一个工作区的
[`harodggg/xray-deploy`](https://github.com/harodggg/xray-deploy) 里的
`install-xray.sh` 已经能一键部署它：
服务端配置就是 `inbound: vless + reality` + `outbound: freedom` ——
接住 REALITY、解封装、再直连目标。装完还会直接用官方客户端自测一遍并输出分享链接。

换句话说：**这个方向今天就能用，只是不在本工程里，而是官方实现。**
本工程缺的不是「能不能」，是「用 Rust 在 wasm 里重写一遍」——见下。

### 为什么用 Rust 重写是另一个大工程

这一节记录「要做什么」，以免反复被问到或产生误解。

**wasm 运行时已经不是障碍。** 这项能力所需的基础设施本工程都已具备并有实测：

| 需要的能力 | 现状 |
|---|---|
| 接受入站 TCP 连接（listen / accept） | ✅ 已在用（SOCKS5 监听就是它） |
| 非阻塞 socket + 就绪通知 | ✅ v0.3 换成 `wasi:sockets` + pollable |
| 主动向 `dest` 发起连接（回退伪装用） | ✅ 非阻塞 connect 已就绪 |
| X25519 / HKDF-SHA256 / AES-256-GCM | ✅ 客户端侧已在用，服务端侧同一套原语 |
| 出站 `dest` 的 TLS 1.3 客户端 | ✅ 已有（虽然是自己手写的那套） |

**缺的是协议实现本身**，而且这块不小：

| # | 要做的 | 为什么不能直接复用现有代码 |
|---|---|---|
| 1 | **完整的 TLS 1.3 服务端握手** | 现有代码只有**客户端**角色。ServerHello / EncryptedExtensions / Certificate / CertificateVerify / Finished 的服务端构造、以及服务端密钥调度都要新写 |
| 2 | **每连接生成临时 ed25519 证书** | REALITY 的核心反探测机制。客户端校验证书的方式是 `HMAC-SHA512(authKey, 证书公钥) == 证书签名域`，所以服务端必须**用 HMAC 冒充签名字段** |
| 3 | **X.509 DER 编码** | 上面那张证书要自己拼 DER（TBSCertificate + 伪造的 signatureValue）。这块繁琐且容易出错 |
| 4 | **服务端侧 REALITY 认证** | 反向做客户端那套：ECDH → HKDF → AES-GCM 解密 `session_id` → 校验版本 / 时钟窗口 / shortId |
| 5 | **VLESS 服务端解码 + Vision 服务端流控** | 现有的是编码方向（客户端）；解码方向在上游移植时被排除了 |
| 6 | **`dest` 回退** | 认证失败的连接必须**原样转发**到真实站点，让主动探测者看到真实网站——这是 REALITY 抗探测的根本，缺了它整个方案失去意义 |

参考：上游 `xtls/reality` 是一个 **15,584 行的 Go 包**（本质是 `crypto/tls` 的完整 fork），
服务端相关逻辑主要在其中。**没有任何现成的 Rust 实现可以移植** ——
本工程所移植的 `meow-rs` 明确声明是 client-only（"no server-side features"），
crates.io 上也没有可用的 REALITY 服务端 crate。

### 如果要做，规模大概是多少

诚实估计：**不小于本工程到目前为止的全部工作量**，主要成本在第 1、2、3 项
（TLS 服务端 + 证书伪造 + DER 编码）。第 4、5 项反而是最轻的，因为原语和线格式都清楚。

### 安全考量（若将来实现）

* 服务端的 `privateKey` 是**长期密钥**，一旦泄漏等于身份泄漏。在 k8s 里应走 Secret，
  且与客户端的 `XT_*` 分开管理。
* `dest` 回退意味着服务端会**主动向外发起连接**。k8s 的 NetworkPolicy 必须允许它，
  否则探测者拿不到真实站点、伪装立刻失效。
* 服务端比客户端**暴露面大得多**（它直接面对未认证的公网流量），
  在 wasm 沙箱里跑确实有隔离优势，但这不改变「协议实现必须正确」的要求。

### 想要它的话

这是一个独立的里程碑，涉及协议实现而非打包。若要推进，建议的顺序是：
先做**第 4 项（认证解密）**并对着已知的客户端 ClientHello 做单测
（数据都在 `docs/verification-log.md` 里），再做**第 1 项（TLS 服务端）**，
最后才是证书伪造与回退。

---

## 许可

本项目代码为 MIT。`xt-wasm-tls` 与 `xt-wasm-vless` 移植自
[meow-rs](https://github.com/meow-rs/meow-rs)（MIT，Copyright (c) 2026 Max Lv），
分析版本 `a2be4de1c315daa22e53ad1118538936241d592f`；
每个移植文件头部保留了出处声明，上游许可证见 `LICENSE.meow-rs`。
