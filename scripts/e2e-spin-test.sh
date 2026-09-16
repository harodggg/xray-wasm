#!/bin/sh
# 自旋回归测试：**服务端在「有过连接之后」不得把 CPU 打满。**
#
#     ./scripts/e2e-spin-test.sh
#
# # 为什么需要它
#
# 这个 bug（verification-log V24）在**空闲时 CPU 是 0**，任何「起服务、发一个请求、
# 看着正常」的验证都发现不了；也正因为如此，它躲过了本仓库此前全部三道 e2e，
# 直到线上入口卡死 48 分钟才暴露。它需要**同时**满足两个条件才发作：
#
#   1. 已经来过至少一次事件（空闲时 pollable 还没触发过）；
#   2. 有一批连接悬在那里（比如目标不可达、或在等对端发数据）。
#
# 所以本测试专门构造这个状态：起服务端 → 灌入 N 条「连上但不发数据」的连接 →
# 直接读 `/proc/<pid>/stat` 的 CPU 时间，断言**增量接近 0**。
#
# 不用 wall-clock 估 CPU，是因为要看的是「有没有忙等」，而 ticks 是内核给的硬数字。
#
# 只依赖 Linux 的 /proc；其它平台直接跳过（不算失败）。
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

LPORT="${XT_TEST_SPIN_SERVER:-19443}"
SPORT="${XT_TEST_SPIN_SOCKS:-11083}"
CONNS="${XT_TEST_SPIN_CONNS:-300}"
# 300 条挂起连接、空闲 5 秒，CPU 增量应当接近 0。
# 自旋时是 ~500 ticks（100 ticks/秒 ⇒ 跑满一核）。阈值取 100，留足余量。
SAMPLES="${XT_TEST_SPIN_SAMPLES:-5}"
MAX_TICKS="${XT_TEST_SPIN_MAX_TICKS:-100}"

fail() { printf '\n  ✗ %s\n' "$1" >&2; exit 1; }
pass() { printf '  ✓ %s\n' "$1"; }

[ -f "$WASM" ] || fail "找不到 wasm 产物：${WASM}"

if [ ! -r /proc/self/stat ]; then
    printf '  ⊘ 非 Linux（没有 /proc），跳过自旋回归测试\n'
    exit 0
fi

SRV_PID=''
CLI_PID=''
ECHO_PID=''
cleanup() {
    for p in "$CLI_PID" "$SRV_PID" "$ECHO_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

# 端口预检：残留进程会连到「上一轮的旧密钥」，症状是具有误导性的
# `leaf certificate is not Ed25519`（这个坑 e2e-wasm-to-wasm-test.sh 里踩过）。
for p in "$LPORT" "$SPORT"; do
    if nc -z 127.0.0.1 "$p" 2>/dev/null; then
        fail "端口 $p 已被占用（多半是残留的 wasmtime/xray）；先清理再跑"
    fi
done

echo "==> 1/4 起 wasm 服务端 + 官方 Xray 客户端（目标指向本地 echo）"
python3 -c "
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19998)); s.listen(64)
def h(c):
    try:
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except Exception: pass
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
" &
ECHO_PID=$!
sleep 1

KEYS=$("$XRAY" x25519)
PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^PrivateKey: *//p')
PUB=$(printf '%s\n' "$KEYS" | sed -n 's/^Password (PublicKey): *//p')
[ -n "$PRIV" ] && [ -n "$PUB" ] || fail "解析 xray x25519 输出失败"
UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
SID=$(python3 -c 'import os;print(os.urandom(8).hex())')

cat > "$XW_DIR/.e2e-spin-client.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$SPORT,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":$LPORT,
   "users":[{"id":"$UUID","encryption":"none","flow":""}]}]},
  "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.cloudflare.com",
   "fingerprint":"chrome","publicKey":"$PUB","shortId":"$SID","spiderX":""}}}]}
EOF

XT_MODE=server XT_SERVER_LISTEN="127.0.0.1:$LPORT" XT_PRIVATE_KEY="$PRIV" XT_SHORT_IDS="$SID" \
  XT_SERVER_NAMES=www.cloudflare.com XT_DEST=127.0.0.1:19998 XT_USERS="$UUID" \
  "$WASMTIME_BIN" run $XW_WASMTIME_ARGS "$WASM" server >"$XW_DIR/.e2e-spin-server.log" 2>&1 &
SRV_PID=$!
sleep 2
nc -z 127.0.0.1 "$LPORT" 2>/dev/null || { cat "$XW_DIR/.e2e-spin-server.log" >&2; fail "服务端没起来"; }

"$XRAY" run -c "$XW_DIR/.e2e-spin-client.json" >"$XW_DIR/.e2e-spin-xray.log" 2>&1 &
CLI_PID=$!
sleep 2
nc -z 127.0.0.1 "$SPORT" 2>/dev/null || { cat "$XW_DIR/.e2e-spin-xray.log" >&2; fail "客户端没起来"; }
pass "服务端 :$LPORT / 客户端 SOCKS :$SPORT"

ticks() { awk '{print $14+$15}' "/proc/$SRV_PID/stat" 2>/dev/null || echo 0; }

echo "==> 2/4 基线：空闲 $SAMPLES 秒的 CPU 增量"
T0=$(ticks); sleep "$SAMPLES"; T1=$(ticks)
IDLE=$((T1 - T0))
printf '  空闲增量 = %s ticks\n' "$IDLE"

echo "==> 3/4 灌入 $CONNS 条「连上但不发数据」的连接（制造悬停状态）"
python3 - "$SPORT" "$CONNS" <<'PY'
import socket, sys, time
port, n = int(sys.argv[1]), int(sys.argv[2])
held = []
for _ in range(n):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            continue
        # CONNECT 到一个必然连不上的目标：这样连接会**悬在服务端**
        s.sendall(b"\x05\x01\x00\x01\x0a\xff\xff\x01\x14\x6a")  # 10.255.255.1:5226
        held.append(s)
    except Exception:
        break
print(f"  已建立 {len(held)} 条连接", flush=True)
time.sleep(60)
PY
sleep 3   # 让连接真正进到悬停状态

echo "==> 4/4 悬停状态下的 CPU 增量（判据：必须 < $MAX_TICKS ticks / $SAMPLES 秒）"
F0=$(ticks); sleep "$SAMPLES"; F1=$(ticks)
SPIN=$((F1 - F0))
printf '  悬停增量 = %s ticks\n' "$SPIN"

if [ "$SPIN" -gt "$MAX_TICKS" ]; then
    echo "--- 服务端日志尾部 ---" >&2
    tail -5 "$XW_DIR/.e2e-spin-server.log" >&2
    fail "服务端在悬停状态下忙等（$SPIN ticks / ${SAMPLES}s；空闲时只有 ${IDLE}）—— 这就是 V24 的自旋"
fi
pass "悬停状态下 CPU 增量 = $SPIN ticks（空闲基线 ${IDLE}），未自旋"

printf '\n  自旋回归通过。\n'
