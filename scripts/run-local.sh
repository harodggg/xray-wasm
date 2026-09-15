#!/bin/sh
# 在 wasmtime 下运行 xray-wasm 客户端。
#
#     ./scripts/run-local.sh --server <ip:port> --pbk <公钥> --sid <shortId> --sni <域名> --listen 127.0.0.1:1080
#
# 之所以包一层而不是直接调 wasmtime：需要的那几个 -S flag 缺一个就会失败，
# 而且失败信息完全看不出原因（缺 inherit-network 时报的是 PermissionDenied，像被墙）。
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

WASM="$XW_WASM/xt-wasm-cli.wasm"
if [ ! -f "$WASM" ]; then
    echo "找不到 $WASM" >&2
    echo "先构建： cargo build -p xt-wasm-cli --release --target wasm32-wasip2" >&2
    exit 1
fi
if [ -z "${WASMTIME_BIN:-}" ]; then
    echo "找不到 wasmtime。装一个，或把 WASMTIME_BIN 指到二进制。" >&2
    exit 1
fi

# -C cache=n：避免依赖 ~/Library/Caches（受限环境不可写）。
# shellcheck disable=SC2086
exec "$WASMTIME_BIN" run -C cache=n $XW_WASMTIME_ARGS "$WASM" "$@"
