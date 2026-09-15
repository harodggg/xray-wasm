# xray-wasm

把 Xray 的 **VLESS + XTLS-Vision + REALITY** 客户端协议栈用 **纯 Rust** 实现，
编译成 **wasm32-wasip2**，在 **wasmtime** 下跑真实的 TCP 代理。
可作为本地 SOCKS5 代理，也可部署到 Kubernetes。

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
    xt-wasm-runtime/   shim 类型 + 非阻塞 socket 反应堆 + executor
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
| **非阻塞 socket + 自研 executor** | wasip2 没有 tokio reactor，也没有线程。握手是顺序的（阻塞够用），但握手后的全双工转发必须读写同时存活，否则会死锁 |
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
| **一次只处理一条连接** ⚠️ | 长连接会独占进程，其它客户端排队；k8s 里影响更大 | wasip2 无线程，当前是顺序 accept。k8s 缓解手段见 [`deploy/k8s/README.md`](deploy/k8s/README.md)。根治需改成非阻塞多路复用，**这是下一步最值得做的事** |
| **TLS 指纹非浏览器形状** | 功能可用，但抗 JA3/JA4 与主动探测弱于官方客户端 | 手写 ClientHello 未实现 uTLS 的 Chrome 伪装 |
| **executor 是重试式** | 空闲时有空转开销 | 非 `wasi:io/poll` 就绪通知 |
| **无 XTLS-Vision DIRECT splice** | 仅性能差异，不影响连通 | 功能路径完整 |
| **无 UDP / Mux / 后量子** | QUIC / HTTP3 经此代理不可用 | ML-KEM、ML-DSA-65、`VlessPacketConn` 均未实现 |
| **无 SOCKS5 UDP ASSOCIATE / BIND** | 仅支持 CONNECT | 对验证协议栈无增量价值 |

---

## 许可

本项目代码为 MIT。`xt-wasm-tls` 与 `xt-wasm-vless` 移植自
[meow-rs](https://github.com/meow-rs/meow-rs)（MIT，Copyright (c) 2026 Max Lv），
分析版本 `a2be4de1c315daa22e53ad1118538936241d592f`；
每个移植文件头部保留了出处声明，上游许可证见 `LICENSE.meow-rs`。
