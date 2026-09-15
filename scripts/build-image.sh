#!/bin/sh
# 构建运行镜像：先编 wasm，再打进 wasmtime 镜像。
#
#     ./scripts/build-image.sh [tag]        # 默认 ghcr.io/harodggg/xray-wasm:dev
#
# 本地构建用；CI 里由 .github/workflows/release.yml 完成同样的事，
# 只是 tag 取版本号并推送到 GHCR。
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

IMAGE="${XW_IMAGE:-ghcr.io/harodggg/xray-wasm}"
TAG="${1:-dev}"

command -v docker >/dev/null 2>&1 || {
    echo "找不到 docker。" >&2
    exit 1
}

echo "==> 1/3 编译 wasm32-wasip2"
cargo build -p xt-wasm-cli --release --target wasm32-wasip2

echo "==> 2/3 拷进构建上下文"
# Dockerfile 只 COPY 这一个文件。之所以不在镜像里 cargo build，
# 是为了让「Release 附件里的 wasm」与「镜像里的 wasm」逐字节一致。
cp "$XW_WASM/xt-wasm-cli.wasm" "$XW_DIR/xt-wasm-cli.wasm"
ls -la "$XW_DIR/xt-wasm-cli.wasm"

echo "==> 3/3 docker build -> ${IMAGE}:${TAG}"
if docker buildx version >/dev/null 2>&1; then
    docker buildx build --load -t "${IMAGE}:${TAG}" "$XW_DIR"
else
    docker build -t "${IMAGE}:${TAG}" "$XW_DIR"
fi

echo ""
echo "完成：${IMAGE}:${TAG}"
echo "试跑（本地回环，无认证）："
echo "  docker run --rm -p 1080:1080 -e XT_LISTEN=0.0.0.0:1080 \\"
echo "      -e XT_SERVER=<ip:port> -e XT_PBK=<公钥> -e XT_SID=<shortId> \\"
echo "      -e XT_SNI=<伪装域名> -e XT_UUID=<uuid> ${IMAGE}:${TAG}"
