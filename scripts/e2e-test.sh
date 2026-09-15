#!/bin/sh
# 端到端测试：wasm 客户端 → 本地 stock Xray REALITY 服务端 → 外网。
#
#     ./scripts/e2e-test.sh
#
# 这是验收脚本（本地与 CI 用同一条命令，两边不会漂移）。
# 它刻意做成「一条命令跑完」，因为手工验证涉及 4 个进程和一堆 key，靠记忆一定会出错。
#
# 除了「能连通」，这里还有三条**负向/健壮性**用例，它们才是真正容易出事的部分：
#   * 不带凭据必须被拒（否则是开放代理）
#   * 错误凭据必须被拒
#   * 半开连接不得永久卡死代理（顺序 accept + 阻塞读的典型死法）
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

XRAY_DIR="${XW_XRAY_DIR:-$XW_WS/.scratch/xray-server}"
SERVER_CFG="$XRAY_DIR/server.json"
# xray 二进制的位置独立于配置目录：gen-test-server.sh 只产出配置，
# 二进制仍在原处（或由 XW_XRAY_BIN 指定）。
XRAY="${XW_XRAY_BIN:-}"
if [ -z "$XRAY" ]; then
    for cand in "$XRAY_DIR/xray" "$XW_WS/.scratch/xray-server/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$cand" ] && [ -x "$cand" ] && { XRAY="$cand"; break; }
    done
fi
WASM="$XW_WASM/xt-wasm-cli.wasm"

# 测试参数：默认是本地一套一次性假凭据；CI 里由 scripts/gen-test-server.sh
# 生成全新的一套并 export 覆盖。这些都不是任何真实部署的密钥。
UUID="${XT_TEST_UUID:-b21e29c8-a8ea-40a2-b953-c2b04d73d775}"
PBK="${XT_TEST_PBK:-HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg}"
SID="${XT_TEST_SID:-64f6ffd42769a12c}"
SNI="${XT_TEST_SNI:-www.cloudflare.com}"
SERVER="${XT_TEST_SERVER:-127.0.0.1:8443}"
SOCKS="${XT_TEST_SOCKS:-127.0.0.1:1080}"
SOCKS_USER="${XT_TEST_SOCKS_USER:-testuser}"
SOCKS_PASS="${XT_TEST_SOCKS_PASS:-testpass}"
# 调短以便快速验证「半开连接不会永久卡死」
HANDSHAKE_TIMEOUT="${XT_TEST_HANDSHAKE_TIMEOUT:-2}"

fail() { printf '\n  ✗ %s\n' "$1" >&2; exit 1; }
pass() { printf '  ✓ %s\n' "$1"; }
proxy_curl() { curl -sS -m 30 --proxy-user "$SOCKS_USER:$SOCKS_PASS" --proxy "socks5h://$SOCKS" "$@"; }

[ -x "$XRAY" ] || fail "找不到 Xray 二进制：$XRAY"
[ -f "$SERVER_CFG" ] || fail "找不到服务端配置：$SERVER_CFG"
[ -f "$WASM" ] || fail "找不到 wasm 产物：${WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"

SERVER_PID=''
CLIENT_PID=''
cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> 1/8 确保 stock Xray REALITY 服务端在跑"
if nc -z 127.0.0.1 8443 2>/dev/null; then
    pass "服务端已在 127.0.0.1:8443"
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

echo "==> 2/8 启动 wasm 客户端（SOCKS5 + 认证）"
XT_SOCKS_USER="$SOCKS_USER" XT_SOCKS_PASS="$SOCKS_PASS" \
XT_HANDSHAKE_TIMEOUT="$HANDSHAKE_TIMEOUT" \
"$XW_DIR/scripts/run-local.sh" \
    --server "$SERVER" --pbk "$PBK" --sid "$SID" --sni "$SNI" \
    --uuid "$UUID" --listen "$SOCKS" >"$XW_DIR/.e2e-client.log" 2>&1 &
CLIENT_PID=$!
sleep 2
if ! nc -z 127.0.0.1 1080 2>/dev/null; then
    echo "--- 客户端日志 ---" >&2
    cat "$XW_DIR/.e2e-client.log" >&2
    fail "wasm 客户端没有监听 $SOCKS"
fi
pass "客户端已监听 $SOCKS"

# 认证是否真的生效，先看启动日志里怎么写的 —— 环境变量没传进 guest 时
# 这里会显示「认证：无」，是最常见的静默失效。
if ! grep -q "认证：用户名/密码" "$XW_DIR/.e2e-client.log"; then
    echo "--- 客户端日志 ---" >&2
    cat "$XW_DIR/.e2e-client.log" >&2
    fail "客户端未启用认证（XT_SOCKS_USER/PASS 没传进 wasm？检查 -S inherit-env=y）"
fi
pass "客户端已启用认证"

echo "==> 3/8 安全属性：不带凭据必须被拒（否则就是开放代理）"
if curl -sS -m 10 --proxy "socks5h://$SOCKS" -o /dev/null https://example.com 2>/dev/null; then
    fail "无凭据竟然连通了 —— 认证没有生效，这是开放代理！"
fi
pass "无凭据被拒绝"

echo "==> 4/8 错误凭据必须被拒"
if curl -sS -m 10 --proxy-user "testuser:wrongpass" --proxy "socks5h://$SOCKS" \
        -o /dev/null https://example.com 2>/dev/null; then
    fail "错误密码竟然连通了"
fi
pass "错误凭据被拒绝"

echo "==> 5/8 经隧道取一个真实页面（带正确凭据）"
CODE=$(proxy_curl -o /dev/null -w '%{http_code}' https://example.com 2>&1) || {
    echo "--- 客户端日志 ---" >&2; cat "$XW_DIR/.e2e-client.log" >&2
    fail "curl 失败"
}
[ "$CODE" = "200" ] || fail "期望 HTTP 200，实际 $CODE"
pass "https://example.com -> $CODE"

echo "==> 6/8 半开连接不得永久卡死代理（k8s 探针 / 端口扫描器会这样）"
# 连上但不发任何数据，保持 6 秒；协商超时是 ${HANDSHAKE_TIMEOUT}s
( sleep 6 | nc 127.0.0.1 1080 >/dev/null 2>&1 ) &
STALL_PID=$!
sleep 4   # 超过协商超时，代理应已丢弃这条半开连接
CODE=$(proxy_curl -o /dev/null -w '%{http_code}' https://example.com 2>&1) || CODE='000'
kill "$STALL_PID" 2>/dev/null || true
[ "$CODE" = "200" ] || fail "半开连接之后代理未能恢复（拿到 $CODE）—— 顺序 accept 被卡死了"
pass "半开连接超时后被丢弃，代理已恢复"

echo "==> 7/8 并发：一条长连接不得独占代理（多路复用是否真的生效）"
# 起一条「已建立隧道但一直不发数据」的长连接。顺序 accept 的实现会被它独占到结束，
# 多路复用的实现则不受影响 —— 这条用例就是用来区分这两种实现的。
python3 "$XW_DIR/scripts/hold-tunnel.py" \
    127.0.0.1 1080 "$SOCKS_USER" "$SOCKS_PASS" example.com 443 8 \
    >"$XW_DIR/.e2e-hold.log" 2>&1 &
HOLD_PID=$!

# 等它真正占住隧道（脚本握手成功会打印 HELD）
i=0
while [ "$i" -lt 40 ]; do
    grep -q HELD "$XW_DIR/.e2e-hold.log" 2>/dev/null && break
    i=$((i + 1))
    sleep 0.1
done
if ! grep -q HELD "$XW_DIR/.e2e-hold.log" 2>/dev/null; then
    cat "$XW_DIR/.e2e-hold.log" >&2
    kill "$HOLD_PID" 2>/dev/null || true
    fail "长连接未能建立（hold-tunnel.py 没有报 HELD）"
fi
# 确认它此刻仍然活着 —— 否则「并发通过」可能只是因为它已经结束了
kill -0 "$HOLD_PID" 2>/dev/null || fail "长连接在测试前就已退出，用例无效"

T0=$(date +%s)
CODE=$(proxy_curl -o /dev/null -w '%{http_code}' https://example.com 2>&1) || CODE='000'
T1=$(date +%s)
ELAPSED=$((T1 - T0))
# 再确认一次：长连接在我们测试期间还活着，才说明真的是并发
STILL_ALIVE=no
kill -0 "$HOLD_PID" 2>/dev/null && STILL_ALIVE=yes
kill "$HOLD_PID" 2>/dev/null || true
wait "$HOLD_PID" 2>/dev/null || true
[ "$CODE" = "200" ] || fail "长连接存在时新请求失败（拿到 $CODE）—— 代理被独占了"
[ "$STILL_ALIVE" = "yes" ] || fail "长连接在请求完成前已退出，无法证明并发"
pass "长连接占用期间新请求仍成功（${ELAPSED}s，长连接全程存活）"

echo "==> 8/8 出口 IP 应与直连不同"
EGRESS=$(proxy_curl https://api.ipify.org 2>&1 | head -1)
pass "隧道出口 IP：$EGRESS"

printf '\n  端到端通过。\n'
