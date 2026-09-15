# syntax=docker/dockerfile:1
#
# xray-wasm 运行镜像：wasmtime + 预编译的 wasm 模块。
#
# # 为什么是「容器里跑 wasmtime」而不是原生二进制
#
# 好处是沙箱与可移植：guest 只能看到 wasmtime 显式开放的能力
# （下面前提是 -S 的那几个 flag），拿不到文件系统、进程、任意网络。
# 代价是多一层运行时与少量启动开销。
#
# # 为什么 wasm 文件是从外部拷进来的（而不是在镜像里 cargo build）
#
# 发布流程里 CI 先编译 wasm、把它作为 Release 附件发布，然后**同一个文件**
# 被打进镜像。这样「Release 里下载的 wasm」与「镜像里跑的 wasm」逐字节一致，
# 不会出现两者不同步却都自称同一版本的情况。
# 本地构建请先跑：cargo build -p xt-wasm-cli --release --target wasm32-wasip2
# 再执行 scripts/build-image.sh（它会帮你把产物拷过来）。

FROM debian:bookworm-slim

ARG WASMTIME_VERSION=v48.0.2
ARG TARGETARCH

LABEL org.opencontainers.image.title="xray-wasm" \
      org.opencontainers.image.description="VLESS + XTLS-Vision + REALITY client running as a wasm32-wasip2 module under wasmtime" \
      org.opencontainers.image.source="https://github.com/harodggg/xray-wasm" \
      org.opencontainers.image.licenses="MIT"

# 只装下载/解压所需，装完立刻清掉，尽量缩小镜像。
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl xz-utils; \
    case "${TARGETARCH:-amd64}" in \
        amd64) WT_ARCH=x86_64 ;; \
        arm64) WT_ARCH=aarch64 ;; \
        *) echo "不支持的架构: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/bytecodealliance/wasmtime/releases/download/${WASMTIME_VERSION}/wasmtime-${WASMTIME_VERSION}-${WT_ARCH}-linux.tar.xz" \
        -o /tmp/wasmtime.tar.xz; \
    tar -xJf /tmp/wasmtime.tar.xz -C /opt; \
    mv "/opt/wasmtime-${WASMTIME_VERSION}-${WT_ARCH}-linux" /opt/wasmtime; \
    rm -f /tmp/wasmtime.tar.xz; \
    apt-get purge -y curl xz-utils; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    /opt/wasmtime/wasmtime --version

# 非 root 运行。wasm 沙箱本身已经限制很强，但不该因此就默认用 root。
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin xt

WORKDIR /app
COPY xt-wasm-cli.wasm /app/xt-wasm-cli.wasm

# 再分发时附带许可证（MIT 要求）。LICENSE 是本工程，LICENSE.meow-rs 是移植部分的上游。
COPY LICENSE LICENSE.meow-rs /app/

USER 10001

# 默认只监听回环 —— **这是刻意的安全默认值**。
# 一旦绑到非回环地址而没设认证，就是一个开放代理（任何能连上的人都能白嫖你的隧道）。
# k8s 里需要被其它 Pod 访问时，请显式设 XT_LISTEN=0.0.0.0:1080，
# 并同时用 Secret 注入 XT_SOCKS_USER / XT_SOCKS_PASS。见 deploy/k8s/。
ENV XT_LISTEN=127.0.0.1:1080

EXPOSE 1080

# 这几个 -S flag 缺一不可，逐个说明：
#   tcp=y                允许 wasi:sockets 建立 TCP
#   inherit-network=y    允许连接任意地址/端口（缺了会得到 PermissionDenied，
#                        看起来像被墙，其实是 host 策略）
#   allow-ip-name-lookup=y  允许域名解析（隧道的目标域名由服务端解析，
#                        但连服务端本身若用域名就需要它）
#   inherit-env=y        **安全相关**：把 XT_* 环境变量传给 guest。
#                        缺了它，Secret 注入的认证配置根本进不去，
#                        一个本应受保护的代理会静默变成开放代理。
ENTRYPOINT ["/opt/wasmtime/wasmtime", "run", \
            "-C", "cache=n", \
            "-S", "tcp=y", \
            "-S", "inherit-network=y", \
            "-S", "allow-ip-name-lookup=y", \
            "-S", "inherit-env=y", \
            "/app/xt-wasm-cli.wasm"]
