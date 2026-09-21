# 在 Kubernetes / k3s 里使用 xray-wasm

镜像：`ghcr.io/harodggg/xray-wasm:<tag>`（amd64 / arm64），内容是 wasmtime +
编译好的 wasm32-wasip2 模块。guest 只能看到 entrypoint 里显式开放的那几项能力，
拿不到文件系统、进程与任意网络。

**同一个镜像、同一个 tag 跑两种模式**，靠子命令区分：

```sh
# 客户端（默认，无子命令）：本地 SOCKS5 → REALITY 隧道
docker run --rm -e XT_SERVER=… -e XT_PBK=… ghcr.io/harodggg/xray-wasm:v0.7.2

# 服务端（`server` 子命令）：REALITY 入站 → 目标站
docker run --rm -e XT_PRIVATE_KEY=… ghcr.io/harodggg/xray-wasm:v0.7.2 server
```

子命令写在**镜像名之后**（k8s 里就是 `args: ["server"]`）：镜像 ENTRYPOINT 是 exec
形式且以 wasm 路径结尾，所以 docker/k8s 传入的参数会直接追加成 wasm 模块的 argv。
不方便写 args 的部署可以用 `XT_MODE=server` 环境变量代替。

---

## 先选模式

| | **客户端 · Sidecar** | **客户端 · 共享出口代理** | **服务端（k3s）** |
|---|---|---|---|
| 用途 | 业务容器出网 | 集群内共享出口 | **接住公网 REALITY 连接** |
| 形态 | 与业务容器同 Pod，业务连 `127.0.0.1:1080` | Deployment + ClusterIP Service | Deployment + **LoadBalancer** Service |
| 暴露面 | 无（Pod 内回环） | 集群内 | **公网**（这是它的职责） |
| 清单 | `sidecar.example.yaml` | `deployment.yaml` + `service.yaml` + `networkpolicy.yaml` | `server.yaml` + `server-networkpolicy.yaml` |
| Secret | `secret.example.yaml` | 同左 | `server-secret.example.yaml` |
| 子命令 | 无 | 无 | `args: ["server"]` |
| 关键变量 | `XT_SERVER/PBK/SID/SNI/UUID` | 同左 + `XT_LISTEN=0.0.0.0:1080` + `XT_SOCKS_USER/PASS` | `XT_PRIVATE_KEY/SHORT_IDS/SERVER_NAMES/DEST/USERS` |

---

## 客户端：快速开始（共享出口代理）

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

## 服务端：快速开始（k3s）

### 1. 生成凭据

```sh
xray x25519
#   PrivateKey: <PRIV>            → 服务端 XT_PRIVATE_KEY
#   Password (PublicKey): <PUB>   → 客户端 XT_PBK
#   ⚠️ 这两行极易看反。看反的症状：客户端 REALITY 认证过不去，
#      表现为「握手后拿到一个不属于自己 dest 的证书」，非常难查。
SID=$(openssl rand -hex 8)        # → 两端 XT_SHORT_IDS / XT_SID
UUID=$(uuidgen | tr 'A-Z' 'a-z')  # → 两端 XT_USERS / XT_UUID
```

### 2. 选一个 `dest`

`dest` 是**认证失败时的回落目标**，也就是探测者会看到的东西。硬要求：

* 是一个**真实存在**的 TLS 站点；
* 它的**证书域名与 `XT_SERVER_NAMES` 一致**。

两者不一致等于自曝：探测者按 `serverName` 发 SNI，却拿到另一个域名的证书。
最省事、也最不容易错的做法就是**用同一个域名**：

```
XT_SERVER_NAMES = www.example.com
XT_DEST         = www.example.com:443
```

### 3. 创建 Secret 并部署

```sh
kubectl -n <命名空间> create secret generic xray-wasm-server \
  --from-literal=XT_PRIVATE_KEY='<PRIV>' \
  --from-literal=XT_SHORT_IDS="$SID" \
  --from-literal=XT_SERVER_NAMES='www.example.com' \
  --from-literal=XT_DEST='www.example.com:443' \
  --from-literal=XT_USERS="$UUID"

kubectl apply -f deploy/k8s/server.yaml
kubectl apply -f deploy/k8s/server-networkpolicy.yaml   # 先核对里面的 CIDR！

kubectl rollout status deploy/xray-wasm-server
kubectl get svc xray-wasm-server
#   TYPE           CLUSTER-IP   EXTERNAL-IP    PORT(S)
#   LoadBalancer   10.43.x.x    <节点IP>       8443:31xxx/TCP
```

k3s 自带 **ServiceLB（Klipper）**：`type: LoadBalancer` 不需要任何 cloud provider，
它会直接把端口绑到**每个节点的节点 IP** 上，`EXTERNAL-IP` 显示的就是节点 IP。
（若你的 k3s 禁用了 ServiceLB，改用 `type: NodePort` 并自己做端口转发。）

把 `<节点IP>:8443` 填进客户端即可：

```jsonc
// 官方 Xray 客户端的 outbound 片段
{
  "protocol": "vless",
  "settings": { "vnext": [{
    "address": "<节点IP>", "port": 8443,
    "users": [{ "id": "<UUID>", "encryption": "none", "flow": "xtls-rprx-vision" }]
    //                                                        ^^^^^^^^^^^^^^^^^^^
    //  服务端已实现 XTLS-Vision（解帧 + 组帧），照官方写法填即可。
    //  留空也支持（裸路径）；不认识的 flow 名会被明确拒绝，不静默降级。
  }]},
  "streamSettings": {
    "network": "tcp", "security": "reality",
    "realitySettings": {
      "serverName": "www.example.com",     // 必须命中 XT_SERVER_NAMES
      "publicKey": "<PUB>",                // 注意是公钥，不是私钥
      "shortId": "<SID>",
      "fingerprint": "chrome", "spiderX": ""
    }
  }
}
```

### 4. 两条必须做的验证

```sh
# a) 抗主动探测：外部看不到任何伪造证书
#    不要 grep openssl 的人类可读输出：macOS(LibreSSL) 与 Ubuntu(OpenSSL 3)
#    的排版不同（`CN=` vs `CN = `、`a:PKEY: EC` vs `id-ecPublicKey`），
#    会出现在一边通过、在另一边红。用结构化判定：
echo | openssl s_client -connect <节点IP>:8443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -subject -nameopt RFC2253        # 期望 subject=CN=www.example.com
echo | openssl s_client -connect <节点IP>:8443 -servername www.example.com 2>/dev/null \
  | openssl x509 -noout -pubkey | openssl pkey -pubin -text -noout
#   期望 prime256v1（dest 的真实 EC 公钥）
#   若出现 ED25519，说明回退没生效，服务端正在对探测者暴露自己

# b) 端到端：真实客户端能出去（HTTP 200）
#    官方客户端 + 上面的片段，然后：
curl -sS -o /dev/null -w '%{http_code}\n' --proxy socks5h://127.0.0.1:1080 https://example.com
```

本地不搭集群也能跑同样的断言：`./scripts/e2e-server-test.sh`（CI 里常态化跑）。

### 5. 服务端的日志与探针

```
[server] REALITY 入站：监听 0.0.0.0:8443，SNI ["www.example.com"]，用户 1 个，dest www.example.com:443
[server] 认证失败的连接会被原样转发到 dest（这是设计行为，不是漏洞）
[server] 10.0.0.5:51234 认证通过 user=8f1c… -> example.com:443
[server] 10.0.0.5:51234 未认证（sni=www.example.com），转发到 dest
```

* **判定一出就写日志**，不等连接结束。长连接可能挂几小时，「断开时才记一笔」
  的日志对接告警没有意义。
* **空连接（连上就关）刻意不记日志**。k8s 的 `tcpSocket` 探针、端口扫描器、
  LB 健康检查都长这样。它们在库层被识别为 `InboundOutcome::EmptyConnection`
  （**不是错误**），CLI 对它静默 —— 否则探针每 10 秒一行错误日志。
* 因此清单里的 `startupProbe`/`livenessProbe`/`readinessProbe` 可以放心用
  `tcpSocket`：它验证「accept 循环还活着」，这正是探针该管的范围。

---

## 安全须知（请逐条确认）

### 客户端

1. **认证不是可选项。** 容器一旦 `XT_LISTEN=0.0.0.0:*` 而没设
   `XT_SOCKS_USER/PASS`，它就是一个**开放代理**：任何能连上该端口的 Pod
   都能免费用你的隧道出网。客户端会对这种组合打印显式警告，但不要依赖警告。
2. **不要用 LoadBalancer / NodePort。** 客户端清单里刻意是 `ClusterIP`。
   暴露到集群外等于把出口代理公开。
3. **叠加 NetworkPolicy。** 认证管「谁能用」，网络策略管「谁能连」。
   两层都做；并且把 egress 收紧到服务端固定 IP，避免这个 Pod 被当跳板。
4. **凭证走 Secret。** 不要写在 Deployment 的 `args` 里 ——
   `kubectl describe pod` 会把 args 原样打印。
5. **`--client-ver` 要对齐。** 若你的服务端设了 `minClientVer`/`maxClientVer`，
   客户端上报的版本必须落在区间内。默认 `26.3.27`；可用
   `XT_CLIENT_VER` 覆盖。设错的症状是握手失败（服务端会把你当探测流量转发到 dest，
   客户端侧看到的是「证书不是 Ed25519」）。
6. **`XT_FINGERPRINT` 决定 ClientHello 长什么样（默认 `chrome`）。** 清单里显式写
   成 `chrome`，让「这条 Deployment 伪装成什么」一眼可见、可改；填 `plain` 则不伪装
   （最小形状，便于排障与对照）。认不出的名字会**启动即失败**并列出可用名字。
   * 能力边界要说清楚：只对齐**可观测字段**（cipher 列表 / 扩展集合与顺序 /
     ALPN / GREASE 模式…）。我们**不声明** `X25519MLKEM768` 也**不带**它的
     key_share（发了会触发对端 HelloRetryRequest 而握手失败），ECH 只是 GREASE 占位，
     扩展顺序按连接随机化；因此形状等价于「PQ 尚未默认开启的 Chrome」，
     与当前最新 Chrome 有一处已知差异。**纯 X25519 也是真实的密码学降级**
     （不具备抗「先存后解」的后量子性）。
   * 判据与证明方式（JA4 与官方夹包全等、JA3 为何不能当判据、已知不一致点清单）见
     `docs/fingerprint-plan.md` 与 `docs/fingerprint-security.md`。

### 服务端

1. **`XT_PRIVATE_KEY` 是长期身份密钥。** 泄漏等于身份泄漏，拿到它就能冒充你的
   服务端。必须走 Secret，**并且不要和客户端的 `XT_*` 放在同一个 Secret 里**。
2. **`short_ids` / `users` 为空会被拒绝启动。** 空列表意味着谁也进不来，
   几乎总是笔误；宁可起不来也不要起一个「配错了但看起来正常」的服务端。
   反过来说，`shortIds` 为空在协议上等于「任何知道公钥的人都能通过认证」——
   这正是我们拒绝它的原因。
3. **服务端的 egress 必须开放。** 它要代表客户端连任意目标站点。把 egress
   收紧到几个网段会直接让代理只能访问那几个站点 —— 那是功能性错误，不是加固。
   `server-networkpolicy.yaml` 因此只封**私有网段**，防的是「客户端被入侵后
   拿它扫内网」。
4. **ingress 只开 8443。** 「谁能用」由 REALITY 密钥认证负责，网络层只负责
   「哪个端口开着」，所以 ingress 规则里刻意没有 IP 白名单（客户端源 IP 是任意的）。
5. **节点时钟必须准。** REALITY 校验客户端时间戳，超出 `XT_MAX_TIME_DIFF`
   （默认 60 秒）即认证失败。**虚拟机从挂起恢复后的时钟漂移**是「昨天还好好的、
   今天全连不上」的头号原因。确认节点在跑 NTP。
6. **`dest` 不要指向集群内服务。** 它必须是真实的外网站点，否则探测者一眼看穿。

---

## 已知限制（部署前请务必阅读）

### 1. 并发与事件循环

wasip2 没有线程。实现是**单线程协作式并发**：主循环只 accept，每条连接交给
事件循环；socket 非阻塞，挂起与唤醒由 `wasi:io/poll` 的 pollable 完成。
并发上限：**客户端 64、服务端 256**，满了会**等槽位**而不是丢弃连接
（丢弃会让探针失败并触发重启）。

* 一条 keep-alive 长连接**不会**独占 Pod（实测：旧实现下并发请求超时 12s，
  现在 1s 内返回 200）。
* **建连不阻塞事件循环**（v0.3 起 socket 直连 `wasi:sockets`），
  所以即使服务端一时不可达，其它已建立的连接也不受影响。
  但**新建连接**仍会一直等到 TCP 超时，建议 `XT_SERVER` 指向稳定可达的地址。
* 空闲时进程阻塞在 pollable 上，CPU 占用接近零（实测 30 秒空闲约 0.05%）。

### 2. TLS 指纹不是浏览器形状

手写 ClientHello 未实现 uTLS 的 Chrome 伪装。功能可用，但抗 JA3/JA4
与主动探测的能力弱于官方客户端。见根目录 README 的「已知限制」。

### 3. 不支持 UDP

只有 TCP（客户端侧是 SOCKS5 CONNECT；服务端侧是 VLESS TCP）。
UDP ASSOCIATE 未实现，因此 QUIC / HTTP3 经此代理不可用。

---

## 已经不是限制的（曾经是）

* **服务端 XTLS-Vision（v0.6.0 起已实现）。** 解帧 + 组帧都通了：官方客户端带
  `flow: "xtls-rprx-vision"` 经本服务端取真实网页拿到 HTTP 200
  （`scripts/e2e-vision-test.sh` 常态化验证）。空 flow 的裸路径同样支持。
  **不认识的 flow 名仍会被明确拒绝**，不会静默降级 —— 静默降级会把 Vision 的
  填充帧当成原始数据发给目标站，输出是错的却不报错，属于最难排查的那类故障。
* **`--no-flow` 不再是必需。** 它保留给「对端只认空 flow」的场景。

---

## 资源与镜像

| 项 | 值 |
|---|---|
| wasm 模块 | ~400 KB（客户端与服务端是同一个模块） |
| 基础镜像 | `debian:bookworm-slim` + wasmtime v48.0.2 |
| 默认监听 | 客户端 `127.0.0.1:1080`（**安全默认值**，共享模式需显式改 `0.0.0.0:1080`）／服务端 `0.0.0.0:8443` |
| 暴露端口 | 镜像 `EXPOSE 1080 8443` |
| 运行用户 | uid 10001，非 root，rootfs 只读，drop ALL capabilities |
| 多架构 | amd64 / arm64 |

镜像里包含 `LICENSE` 与 `LICENSE.meow-rs`（MIT 要求再分发时附带许可证）。
