# xray-wasm

把 Xray 的 **VLESS + XTLS-Vision + REALITY** 客户端协议栈用 **纯 Rust** 实现，
编译成 **wasm32-wasip2**，在 **wasmtime** 下跑真实的 TCP 代理。

> 一句话结论：**能用，且已对着真实 Xray 服务端端到端验证过。**
> 验证过程与原始输出见 [`docs/verification-log.md`](docs/verification-log.md)。

---

## 快速开始

```sh
# 0. 加载构建环境（必须，见下方「三个坑」）
cd xray-wasm && . scripts/env.sh

# 1. 编译到 wasm
cargo build -p xt-wasm-cli --release --target wasm32-wasip2

# 2. 起一个本地 REALITY 服务端用于测试（用官方 xray 二进制）
#    密钥/UUID 的生成方式见 docs/verification-log.md V8

# 3. 跑客户端：本地 SOCKS5 → 隧道
./scripts/run-local.sh \
    --server 127.0.0.1:8443 \
    --pbk <服务端公钥 base64url> \
    --sid <shortId hex> \
    --sni <伪装域名> \
    --uuid <UUID> \
    --listen 127.0.0.1:1080

# 4. 另一终端：经隧道访问
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

一条命令跑完整验收（会自己拉起服务端）：

```sh
./scripts/e2e-test.sh
```

---

## 命令

```
xt-wasm-cli --self-test --server <ip:port> --pbk <...> --sid <...> --sni <域名>
xt-wasm-cli --server <ip:port> --pbk <...> --sid <...> --sni <...> --uuid <uuid> [--listen 127.0.0.1:1080]

可选：
  --client-ver x.y.z    REALITY 上报的客户端版本（默认 26.3.27）
```

* `--self-test`：只做 REALITY 握手并报告耗时。**不依赖 VLESS 层**，
  适合快速验证网络与密钥配置。
* 默认：SOCKS5 服务端，每条连接经隧道转发。

### `--client-ver` 为什么存在

REALITY 服务端会校验客户端版本（`xtls/reality/tls.go`）：

```go
MinClientVer <= ClientVer <= MaxClientVer
```

两项默认都为空（不校验），所以填错**在本机测试时完全看不出来**；
但部署方若设了 `minClientVer`，版本过低会被判为探测流量并转发给 `dest`，
客户端侧表现为「握手失败」。默认值取 `26.3.27`（与本工程验证过的 Xray 对齐）。

---

## 架构

```
xray-wasm/
  crates/
    xt-wasm-runtime/   shim 类型 + 非阻塞 socket 反应堆 + executor
    xt-wasm-tls/       手写 TLS 1.3 + REALITY 客户端（移植自 meow-rs）
    xt-wasm-vless/     VLESS 请求头 + XTLS-Vision 流控（移植自 meow-rs）
    xt-wasm-cli/       SOCKS5 服务端 + 转发核心 + 入口
  docs/
    verification-log.md  每条结论的可复现实验与原始输出
    port-map.md          移植依赖图（来自 meow-rs 的精确依赖面与陷阱）
  scripts/
    env.sh           构建/运行环境
    run-local.sh     wasmtime 启动封装
    e2e-test.sh      端到端验收
```

数据流：

```
curl --proxy socks5h://…
  → SOCKS5 协商
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
| **wasmtime 的两个 flag** | `-S tcp=y` 与 `-S inherit-network=y` **缺一不可**。只给前者会得到 `PermissionDenied`，极易误读成「被墙」 |
| **纯 Rust 手写 TLS** | REALITY 的认证藏在 ClientHello 的 `session_id` 里，需要字节级控制；`rustls` 不暴露这个。而 `boring`(BoringSSL) 是 C++，编译到 wasm 代价极高 |
| **非阻塞 socket + 自研 executor** | wasip2 没有 tokio reactor，也没有线程。握手是顺序的（阻塞够用），但握手后的全双工转发必须读写同时存活，否则会死锁 |
| **不使用 ML-KEM** | 现代 Chrome 指纹走 X25519MLKEM768 混合交换，但已实测服务端**同样接受纯 X25519**（见 V7），省掉一整个依赖 |

---

## 三个坑（`scripts/env.sh` 就是为它们存在的）

1. **`CARGO_HOME` 指向不可写的 `~/.cargo`** → 依赖缓存改放工作区。
2. **Homebrew 的 `rustc` 遮蔽 rustup 的 shim** → `rust-toolchain.toml` 失效，
   还会用错误的 rustc 编 wasm，报错是「can't find crate for core」，看不出真正原因。
3. **wasmtime 把 JIT 缓存写 `~/Library/Caches`** → 受限环境下直接报错退出。

---

## 已知限制（诚实清单）

| 限制 | 影响 | 说明 |
|---|---|---|
| **TLS 指纹非浏览器形状** | 功能可用，但抗 JA3/JA4 与主动探测弱于官方客户端 | 手写 ClientHello 未实现 uTLS 的 Chrome 伪装（扩展顺序/GREASE/ALPS） |
| **单连接顺序处理** | 无并发 | wasip2 无线程；executor 是重试式而非 `wasi:io/poll` 就绪通知 |
| **无 XTLS-Vision DIRECT splice** | 仅性能差异，不影响连通 | 功能路径完整 |
| **无 UDP / Mux / 后量子** | 明确排除在范围外 | ML-KEM、ML-DSA-65、`VlessPacketConn` 均未实现 |
| **无 SOCKS5 UDP ASSOCIATE / BIND** | 仅支持 CONNECT | 对验证协议栈无增量价值 |

---

## 许可

本项目代码为 MIT。`xt-wasm-tls` 与 `xt-wasm-vless` 移植自
[meow-rs](https://github.com/meow-rs/meow-rs)（MIT，Copyright (c) 2026 Max Lv），
分析版本 `a2be4de1c315daa22e53ad1118538936241d592f`；
每个移植文件头部保留了出处声明，上游许可证见各 crate 下的 `LICENSE.meow-rs`。
