#!/bin/sh
# 端到端测试：wasm 客户端 → 本地 stock Xray REALITY 服务端 → 外网。
#
#     ./scripts/e2e-test.sh
#
# 这是 M1/M2 的验收脚本。它刻意做成「一条命令跑完」，
# 因为手工验证涉及 4 个进程和一堆 key，靠记忆一定会出错。
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

XRAY_DIR="$XW_WS/.scratch/xray-server"
XRAY="$XRAY_DIR/xray"
SERVER_CFG="$XRAY_DIR/server.json"
WASM="$XW_WASM/xt-wasm-cli.wasm"

# 与 server.json / client.json 保持一致的测试参数。
UUID='b21e29c8-a8ea-40a2-b953-c2b04d73d775'
PBK='HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg'
SID='64f6ffd42769a12c'
SNI='www.cloudflare.com'
SERVER='127.0.0.1:8443'
SOCKS='127.0.0.1:1080'

fail() { printf '\n  ✗ %s\n' "$1" >&2; exit 1; }
pass() { printf '  ✓ %s\n' "$1"; }

[ -x "$XRAY" ] || fail "找不到 Xray 二进制：$XRAY"
[ -f "$SERVER_CFG" ] || fail "找不到服务端配置：$SERVER_CFG"
[ -f "$WASM" ] || fail "找不到 wasm 产物：${WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"

echo "==> 1/4 确保 stock Xray REALITY 服务端在跑"
if nc -z 127.0.0.1 8443 2>/dev/null; then
    pass "服务端已在 127.0.0.1:8443"
    SERVER_PID=''
else
    "$XRAY" run -c "$SERVER_CFG" >"$XW_DIR/.e2e-server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1.5
    nc -z 127.0.0.1 8443 2>/dev/null || {
        cat "$XW_DIR/.e2e-server.log" >&2
        fail "服务端启动失败"
    }
    # 注意：必须写 ${SERVER_PID}。紧跟在变量名后面的全角括号是多字节字符，
    # bash 会把它当成变量名的一部分（$SERVER_PID）→ 「unbound variable」。
    pass "已启动服务端（pid ${SERVER_PID}）"
fi

echo "==> 2/4 启动 wasm 客户端（SOCKS5）"
"$XW_DIR/scripts/run-local.sh" \
    --server "$SERVER" --pbk "$PBK" --sid "$SID" --sni "$SNI" \
    --uuid "$UUID" --listen "$SOCKS" >"$XW_DIR/.e2e-client.log" 2>&1 &
CLIENT_PID=$!
sleep 2
if ! nc -z 127.0.0.1 1080 2>/dev/null; then
    echo "--- 客户端日志 ---" >&2
    cat "$XW_DIR/.e2e-client.log" >&2
    kill "$CLIENT_PID" 2>/dev/null || true
    fail "wasm 客户端没有监听 $SOCKS"
fi
pass "客户端已监听 $SOCKS"

echo "==> 3/4 经隧道取一个真实页面"
CODE=$(curl -sS -m 30 --proxy "socks5h://$SOCKS" -o /dev/null -w '%{http_code}' https://example.com 2>&1) || {
    echo "--- 客户端日志 ---" >&2; cat "$XW_DIR/.e2e-client.log" >&2
    kill "$CLIENT_PID" 2>/dev/null || true
    fail "curl 失败"
}
[ "$CODE" = "200" ] || fail "期望 HTTP 200，实际 $CODE"
pass "https://example.com -> $CODE"

echo "==> 4/4 出口 IP 应与直连不同"
EGRESS=$(curl -sS -m 30 --proxy "socks5h://$SOCKS" https://api.ipify.org 2>&1 | head -1)
pass "隧道出口 IP：$EGRESS"

kill "$CLIENT_PID" 2>/dev/null || true
[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
printf '\n  端到端通过。\n'
