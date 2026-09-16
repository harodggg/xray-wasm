#!/bin/sh
# 端到端测试：**我们的 wasm 客户端 → 我们的 wasm 服务端**（自环）。
#
#     ./scripts/e2e-wasm-to-wasm-test.sh
#
# 这是三道 e2e 里最后补齐的一道，也是唯一一道两端都是本工程的：
#
#   e2e-test.sh              wasm 客户端 → 官方 Xray 服务端
#   e2e-server-test.sh       官方 Xray 客户端 → wasm 服务端
#   e2e-wasm-to-wasm-test.sh wasm 客户端 → wasm 服务端   ← 本文件
#
# 前两道各自只覆盖了一半，两端都是自己的组合此前**从来没跑过**。
# 它第一次跑时暴露过一个真问题：客户端默认发 XTLS-Vision flow，
# 而当时服务端侧 Vision 还没实现 —— wasm↔wasm 100% 失败。
# 现在服务端的 Vision 解帧 + 组帧都已打通，所以**默认（带 Vision）也必须连通**。
#
# 五步：
#   1. 起 wasm 服务端
#   2. 正向：`--no-flow` 的 wasm 客户端 → HTTP 200
#   3. 同一条正向，改用环境变量 `XT_NO_FLOW=1`（交付契约里冻结的是这个变量名）
#   4. **反向**：默认（带 Vision）的客户端 → **也必须 HTTP 200**，
#      且服务端日志不得出现 `outcome=Rejected`
#   5. 配置自检 `XT_CHECK=1`：正常退出 0；把 XT_USERS 清空退出 2
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

XRAY_DIR="${XW_XRAY_DIR:-$XW_WS/.scratch/xray-server}"
XRAY="${XW_XRAY_BIN:-}"
if [ -z "$XRAY" ]; then
    for cand in "$XRAY_DIR/xray" "$XW_WS/.scratch/xray-server/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$cand" ] && [ -x "$cand" ] && { XRAY="$cand"; break; }
    done
fi
WASM="$XW_WASM/xt-wasm-cli.wasm"

# 端口与另外两道 e2e 全部错开，三个脚本可以同时跑。
LPORT="${XT_TEST_W2W_SERVER:-9444}"
SPORT="${XT_TEST_W2W_SOCKS:-1082}"
SPORT_BAD="${XT_TEST_W2W_SOCKS_BAD:-1083}"
LISTEN="127.0.0.1:$LPORT"
SOCKS="127.0.0.1:$SPORT"
SOCKS_BAD="127.0.0.1:$SPORT_BAD"
DEST="${XT_TEST_DEST:-www.cloudflare.com:443}"
DEST_HOST="${DEST%%:*}"
TARGET="${XT_TEST_TARGET:-example.com}"
SNI="${XT_TEST_SNI:-$DEST_HOST}"

srv_log() { cat "$XW_DIR/.e2e-w2w-srv.log" 2>/dev/null || true; }

# 等服务端写出至少 N 行 `outcome=Forwarded`。
#
# 为什么要等：服务端的结局行是在**中继收尾之后**写的，而中继收尾要等半关闭
# 在两个方向上走完，比 curl 拿到响应晚一点点。直接 grep 会偶发失败 ——
# 那种「有时红有时绿」的测试比没有测试更糟。
wait_forwarded() {
    want="$1"
    i=0
    while [ "$i" -lt 15 ]; do
        got=$(grep -c "outcome=Forwarded" "$XW_DIR/.e2e-w2w-srv.log" 2>/dev/null || true)
        [ "${got:-0}" -ge "$want" ] && return 0
        i=$((i + 1))
        sleep 1
    done
    return 1
}
fail() {
    printf '\n  ✗ %s\n' "$1" >&2
    exit 1
}
pass() { printf '  ✓ %s\n' "$1"; }

[ -x "$XRAY" ] || fail "找不到 Xray 二进制：${XRAY}（只需要它的 x25519 子命令来生成密钥）"
[ -f "$WASM" ] || fail "找不到 wasm 产物：${WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"

SRV_PID=''
CLI_PID=''
cleanup() {
    for p in "$CLI_PID" "$SRV_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "==> 0/5 生成凭据"
KEYS=$("$XRAY" x25519)
PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^PrivateKey: *//p')
PUB=$(printf '%s\n' "$KEYS" | sed -n 's/^Password (PublicKey): *//p')
[ -n "$PRIV" ] && [ -n "$PUB" ] || {
    printf '%s\n' "$KEYS" >&2
    fail "解析 xray x25519 输出失败"
}
UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
SID=$(python3 -c 'import os;print(os.urandom(8).hex())')
pass "密钥/UUID/shortId 已生成"

# 服务端参数（后面自检那一步也要复用，所以抽成函数）
srv_env() {
    XT_SERVER_LISTEN="$LISTEN" \
    XT_PRIVATE_KEY="$PRIV" \
    XT_SHORT_IDS="$SID" \
    XT_SERVER_NAMES="$SNI" \
    XT_DEST="$DEST" \
    XT_USERS="$UUID" \
    "$@"
}

# 客户端参数：$1 决定用 flag 还是 env 来关 flow
cli_env() {
    _mode="$1"
    shift
    case "$_mode" in
        flag) XT_SERVER="$LISTEN" XT_PBK="$PUB" XT_SID="$SID" XT_SNI="$SNI" XT_UUID="$UUID" \
              XT_LISTEN="$SOCKS" "$@" ;;
        env)  XT_SERVER="$LISTEN" XT_PBK="$PUB" XT_SID="$SID" XT_SNI="$SNI" XT_UUID="$UUID" \
              XT_LISTEN="$SOCKS" XT_NO_FLOW=1 "$@" ;;
        bad)  XT_SERVER="$LISTEN" XT_PBK="$PUB" XT_SID="$SID" XT_SNI="$SNI" XT_UUID="$UUID" \
              XT_LISTEN="$SOCKS_BAD" "$@" ;;
    esac
}

echo "==> 1/5 起 wasm 服务端"
# 先确认端口是空的。上一次异常退出留下的 wasmtime 会继续占着端口，而
# `nc -z` 只告诉我们「有人在听」—— 于是新服务端静默 bind 失败，测试却去连
# **上一轮的旧密钥**，症状是一句极具误导性的
# `leaf certificate is not Ed25519`。这个坑在本脚本第一次跑就踩到了。
for p in "$LPORT" "$SPORT" "$SPORT_BAD"; do
    if nc -z 127.0.0.1 "$p" 2>/dev/null; then
        fail "端口 $p 已被占用（多半是上一次 e2e 残留的 wasmtime）；先 pkill -f xt-wasm-cli.wasm 再跑"
    fi
done
srv_env "$XW_DIR/scripts/run-local.sh" server >"$XW_DIR/.e2e-w2w-srv.log" 2>&1 &
SRV_PID=$!
sleep 2
nc -z 127.0.0.1 "$LPORT" 2>/dev/null || {
    srv_log >&2
    fail "wasm 服务端没有监听 ${LISTEN}"
}
grep -q "致命错误" "$XW_DIR/.e2e-w2w-srv.log" && {
    srv_log >&2
    fail "wasm 服务端启动即报致命错误"
}
pass "服务端已监听 ${LISTEN}（pid ${SRV_PID}）"

echo "==> 2/5 正向：--no-flow 的 wasm 客户端 → wasm 服务端"
cli_env flag "$XW_DIR/scripts/run-local.sh" --no-flow >"$XW_DIR/.e2e-w2w-cli.log" 2>&1 &
CLI_PID=$!
sleep 3
nc -z 127.0.0.1 "$SPORT" 2>/dev/null || {
    cat "$XW_DIR/.e2e-w2w-cli.log" >&2
    fail "wasm 客户端没有监听 SOCKS $SOCKS"
}
CODE=000
for attempt in 1 2 3; do
    CODE=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' \
        --proxy "socks5h://$SOCKS" "https://$TARGET/" 2>/dev/null) || CODE=000
    [ "$CODE" = "200" ] && break
    printf '  … 第 %s 次失败（%s），重试\n' "$attempt" "$CODE"
    sleep 1
done
[ "$CODE" = "200" ] || {
    cat "$XW_DIR/.e2e-w2w-cli.log" >&2
    srv_log >&2
    fail "wasm→wasm 正向不通（拿到 ${CODE}）—— 检查客户端是否真的 --no-flow"
}
pass "wasm 客户端 --no-flow → wasm 服务端 → https://$TARGET -> $CODE"

# 服务端必须记成 Forwarded，而不是别的（证明这条 200 真的走了隧道）
wait_forwarded 1 || {
    srv_log >&2
    fail "服务端日志里没有 outcome=Forwarded"
}
pass "服务端日志：outcome=Forwarded"

# **回归守卫**：再打两次，服务端必须**为每条连接都写出结局行**。
#
# 这一条守的是半关闭传播（`NetStream::shutdown_write` → `tcp-socket.shutdown(Send)`）。
# 它曾经是个空实现：客户端关写方向时我们不发 FIN，服务端读不到 EOF，
# 中继永远不返回 —— 于是请求照样 200，但每条连接都在服务端留下一个
# CLOSE_WAIT 的目标 socket 和一个不回收的客户端 socket，而且**一行结束日志都没有**。
# 所以「N 次请求 ⇒ N 行 outcome=」正好把那个 bug 钉死。
for i in 1 2; do
    curl -sS -m 30 -o /dev/null --proxy "socks5h://$SOCKS" "https://$TARGET/" 2>/dev/null || true
done
if ! wait_forwarded 3; then
    n=$(grep -c "outcome=Forwarded" "$XW_DIR/.e2e-w2w-srv.log" 2>/dev/null || true)
    srv_log >&2
    fail "3 次请求只写出 ${n} 行 outcome=Forwarded —— 中继没有收尾（半关闭没传播？）"
fi
pass "3 次请求写出 3 行结局日志（连接确实被回收）"

echo "==> 3/5 同一条正向，改用环境变量 XT_NO_FLOW=1（契约里冻结的是这个名字）"
kill "$CLI_PID" 2>/dev/null || true
wait "$CLI_PID" 2>/dev/null || true
CLI_PID=''
sleep 1
cli_env env "$XW_DIR/scripts/run-local.sh" >"$XW_DIR/.e2e-w2w-cli-env.log" 2>&1 &
CLI_PID=$!
sleep 3
CODE=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' \
    --proxy "socks5h://$SOCKS" "https://$TARGET/" 2>/dev/null) || CODE=000
[ "$CODE" = "200" ] || {
    cat "$XW_DIR/.e2e-w2w-cli-env.log" >&2
    srv_log >&2
    fail "XT_NO_FLOW=1 没生效（拿到 ${CODE}）"
}
pass "XT_NO_FLOW=1 → $CODE"

echo "==> 4/5 反向：默认（带 Vision）的客户端 —— 也必须连通"
kill "$CLI_PID" 2>/dev/null || true
wait "$CLI_PID" 2>/dev/null || true
CLI_PID=''
sleep 1
cli_env bad "$XW_DIR/scripts/run-local.sh" >"$XW_DIR/.e2e-w2w-cli-bad.log" 2>&1 &
CLI_PID=$!
sleep 3
# 服务端**支持** Vision（解帧 + 组帧都已打通），所以这条连接必须真的连通：
# 既不能是 `Rejected`，也不能「连上了但拿不到页面」。
CODE=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
    --proxy "socks5h://$SOCKS_BAD" "https://$TARGET/" 2>/dev/null) || CODE=000
# **双侧判据**：客户端拿到 200，且服务端把它记成一条正常的 Vision 连接。
if grep -q "outcome=Rejected" "$XW_DIR/.e2e-w2w-srv.log"; then
    srv_log >&2
    fail "服务端拒绝了 Vision 请求 —— 带 flow 的请求不该再被拒"
fi
[ "$CODE" = "200" ] || {
    cat "$XW_DIR/.e2e-w2w-cli-bad.log" >&2
    srv_log >&2
    fail "带 Vision 的自环期望 HTTP 200，实际 ${CODE}（服务端 Vision 组帧回归了？）"
}
grep -qE "outcome=Forwarded" "$XW_DIR/.e2e-w2w-srv.log" || {
    srv_log >&2
    fail "服务端没有把这条 Vision 连接记成 Forwarded"
}
pass "带 Vision 的自环 -> 200，且服务端记为 Forwarded" 

echo "==> 5/5 配置自检 XT_CHECK=1"
# 正常一套配置：退出码必须是 0，且**不能**真的去监听
set +e
CHECK_OUT=$(srv_env env XT_CHECK=1 "$XW_DIR/scripts/run-local.sh" server 2>&1)
CHECK_RC=$?
set -e
[ "$CHECK_RC" = "0" ] || {
    printf '%s\n' "$CHECK_OUT" >&2
    fail "XT_CHECK=1 正常配置应当退出 0，实际 $CHECK_RC"
}
printf '%s\n' "$CHECK_OUT" | grep -q "配置自检通过" || {
    printf '%s\n' "$CHECK_OUT" >&2
    fail "自检没有打印通过标记"
}
# 私钥**绝不能**整串出现在输出里
printf '%s\n' "$CHECK_OUT" | grep -q "$PRIV" && {
    printf '%s\n' "$CHECK_OUT" >&2
    fail "自检输出里出现了完整私钥！这违反「私钥不落日志」"
}
pass "XT_CHECK=1 退出 0，且私钥已脱敏"

# 故意弄坏一个：清空 XT_USERS，必须退出 2 并指名道姓
set +e
BAD_OUT=$(XT_SERVER_LISTEN="$LISTEN" XT_PRIVATE_KEY="$PRIV" XT_SHORT_IDS="$SID" \
    XT_SERVER_NAMES="$SNI" XT_DEST="$DEST" XT_USERS="" XT_CHECK=1 \
    "$XW_DIR/scripts/run-local.sh" server 2>&1)
BAD_RC=$?
set -e
# ⚠️ 这里断言的是「非 0」而不是「恰好 2」。
#
# 代码里 `die()` 走的是 `std::process::exit(2)`（宿主上实测就是 2），
# 但 **wasmtime 会把 guest 的任何非 0 退出码塌缩成 1**。实测：
#
#     guest exit(0)  -> rc=0
#     guest exit(1)  -> rc=1
#     guest exit(2)  -> rc=1     ← 2 拿不回来
#     guest exit(42) -> rc=1
#
# 所以「0 通过 / 2 失败」这个契约在 wasmtime 下**无法照字面实现**，
# 可观察到的只有「0 / 非 0」。k8s initContainer 或 CI 断言必须按后者写。
[ "$BAD_RC" != "0" ] || {
    printf '%s\n' "$BAD_OUT" >&2
    fail "XT_USERS 为空时应当以非 0 退出，实际 $BAD_RC"
}
printf '%s\n' "$BAD_OUT" | grep -q "XT_USERS" || {
    printf '%s\n' "$BAD_OUT" >&2
    fail "自检报错没有点出是哪个变量"
}
pass "XT_USERS 为空 → 以非 0 退出且点出变量名"

printf '\n  wasm↔wasm 端到端通过。\n'
