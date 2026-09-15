# 在 Kubernetes 里使用 xray-wasm

镜像：`ghcr.io/harodggg/xray-wasm:<tag>`，内容是 wasmtime + 编译好的
wasm32-wasip2 模块。guest 只能看到 entrypoint 里显式开放的那几项能力，
拿不到文件系统、进程与任意网络。

---

## 先选模式

| | **Sidecar**（推荐先用这个） | 共享出口代理 |
|---|---|---|
| 形态 | 与业务容器同 Pod，业务连 `127.0.0.1:1080` | Deployment + ClusterIP Service |
| 暴露面 | 无（Pod 内回环） | 集群内所有能连上的 Pod |
| 需要的额外资源 | 只有一个 Secret | Secret + Service + NetworkPolicy |
| 当前单连接限制的影响 | 小 | **大**（见下方「已知限制」） |
| 清单 | `sidecar.example.yaml` | `deployment.yaml` + `service.yaml` + `networkpolicy.yaml` |

---

## 快速开始（共享出口代理）

```sh
# 1) 创建 Secret（不要写进 yaml 提交）
kubectl create secret generic xray-wasm -n <命名空间> \
  --from-literal=XT_UUID='<uuid>' \
  --from-literal=XT_PBK='<服务端公钥 base64url>' \
  --from-literal=XT_SID='<shortId hex>' \
  --from-literal=XT_SNI='<伪装域名>' \
  --from-literal=XT_SERVER='<服务端 ip:port>' \
  --from-literal=XT_SOCKS_USER='<代理用户名>' \
  --from-literal=XT_SOCKS_PASS='<代理密码>'

# 2) 部署
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/networkpolicy.yaml   # 记得先改里面的标签选择器

# 3) 验证
kubectl run -it --rm curl --image=curlimages/curl --restart=Never -- \
  curl -sS --proxy-user '<用户名>:<密码>' \
       --proxy socks5h://xray-wasm:1080 https://example.com -o /dev/null -w '%{http_code}\n'
```

客户端务必用 **`socks5h`**（带 h）：域名交给服务端解析，避免 Pod 本地 DNS
泄漏或被污染。

---

## 安全须知（请逐条确认）

1. **认证不是可选项。** 容器一旦 `XT_LISTEN=0.0.0.0:*` 而没设
   `XT_SOCKS_USER/PASS`，它就是一个**开放代理**：任何能连上该端口的 Pod
   都能免费用你的隧道出网。客户端会对这种组合打印显式警告，但不要依赖警告。
2. **不要用 LoadBalancer / NodePort。** 清单里刻意是 `ClusterIP`。
   暴露到集群外等于把出口代理公开。
3. **叠加 NetworkPolicy。** 认证管「谁能用」，网络策略管「谁能连」。
   两层都做；并且把 egress 收紧到服务端固定 IP，避免这个 Pod 被当跳板。
4. **凭证走 Secret。** 不要写在 Deployment 的 `args` 里 ——
   `kubectl describe pod` 会把 args 原样打印。
5. **`--client-ver` 要对齐。** 若你的服务端设了 `minClientVer`/`maxClientVer`，
   客户端上报的版本必须落在区间内。默认 `26.3.27`；可用
   `XT_CLIENT_VER` 覆盖。设错的症状是握手失败（服务端会把你当探测流量转发到 dest，
   客户端侧看到的是「证书不是 Ed25519」）。

---

## 已知限制（部署前请务必阅读）

### 1. 一次只处理一条连接 ⚠️

wasip2 没有线程，当前实现是**顺序 accept**：一条连接处理完才接受下一条。
后果是：

* 一个保持长连接的客户端（HTTP/2、keep-alive、长轮询）会**独占**该 Pod，
  其它客户端连上后只能排队；
* k8s 探针在忙时可能超时。

**当前可行的缓解**：

* 优先用 **sidecar** 模式（只服务本 Pod，竞争最小）；
* 共享代理模式下把 `replicas` 设 ≥2，不同客户端会落到不同 Pod；
* 清单里刻意**没有**配 `livenessProbe`（单连接模型下它更容易误杀），
  `readinessProbe` 也放宽了阈值。

**根治**需要把 accept 循环与 SOCKS5 协商改成非阻塞多路复用
（`xt-wasm-runtime` 的非阻塞 socket 与 executor 已经具备条件）。
这是本项目下一步最值得做的事。

### 2. 探针会占用连接

`tcpSocket` 探针会真的建一条 TCP 连接。当前实现能靠协商超时
（`XT_HANDSHAKE_TIMEOUT`，默认 15s）把它丢掉，不会卡死 ——
但探针本身仍会占用一次处理机会。

### 3. TLS 指纹不是浏览器形状

手写 ClientHello 未实现 uTLS 的 Chrome 伪装。功能可用，但抗 JA3/JA4
与主动探测的能力弱于官方客户端。见根目录 README 的「已知限制」。

### 4. 不支持 UDP

只有 TCP（SOCKS5 CONNECT）。UDP ASSOCIATE 未实现，因此 QUIC / HTTP3
经此代理不可用。

---

## 资源与镜像

| 项 | 值 |
|---|---|
| wasm 模块 | ~285 KB |
| 基础镜像 | `debian:bookworm-slim` + wasmtime v48.0.2 |
| 默认监听 | `127.0.0.1:1080`（**安全默认值**，共享模式需显式改成 `0.0.0.0:1080`） |
| 运行用户 | uid 10001，非 root，rootfs 只读，drop ALL capabilities |
| 多架构 | amd64 / arm64 |

镜像里包含 `LICENSE` 与 `LICENSE.meow-rs`（MIT 要求再分发时附带许可证）。
