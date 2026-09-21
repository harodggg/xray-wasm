#!/bin/sh
# V24 判据 · **真实现场**：wasm 服务端 + 官方 Xray 客户端 + 悬停 CONNECT。
#
#     ./scripts/v24-field-test.sh
#
# # 它解决什么问题
#
# `scripts/e2e-spin-test.sh` 是 V24 的权威复现脚本，但它的判据读 Linux
# `/proc/<pid>/stat`，在本机（macOS，无 /proc）**跑不了**；`scripts/v24-cpu-probe.py`
# 用 `os.wait4()` 的 rusage 给出了替代判据，但此前只接过**最小探针**。
# 最小探针在本机是 **Mach-O 宿主二进制**（`target/debug/examples/stream_spin_probe_*`），
# 走的是 `xt-wasm-runtime/src/host.rs` 那条「1ms 轮询模拟等待」的调试实现，
# **不是 wasm/WASI pollable 那一层** —— 所以「最小探针不复现」推不出「wasm 服务端不复现」。
# 本脚本把替代判据接到**产品路径**上：真 wasm 产物 + 真协议 + 真悬停连接。
#
# # 判据（两部分，缺一不可）
#
# 1. **CPU**：同一条被测命令（wasm 服务端）在两个场景下各测两个窗口
#
#        idle     官方客户端起着、不发任何请求
#        hover    N 条 SOCKS CONNECT 指向不可达目标（10.255.255.1:5226）并悬停
#
#    单窗口 cpu% = wait4 的 (utime+stime)/窗口。**绝对值不可比**：wasm 服务端每次
#    启动都要 JIT 编译（-C cache=n），这段常数开销被窗口长度稀释。所以主判据是
#    差分：
#
#        marginal = (cpu@W2 - cpu@W1) / (W2 - W1)      ← 常数开销相减即消
#
#    真自旋 → marginal ≈ 1.0（一核）；真空闲 → ≈ 0。
#
# 2. **功能正对照**：每个场景里（含悬停期间）都经隧道做一次真实 `curl`。
#    V24 十九续的教训：**「CPU = 0」不能区分「修好了」和「整个实例卡死」**，
#    只测症状消失的单侧判据会骗人。所以「CPU 低」只有在同场景功能仍通时才成立。
#
# 3. **落回实验**（场景 ④）：悬停 N 秒后**把所有连接关掉**，再测差分。
#    这条专门排除「CPU 抬升只是随时间漂移/机器负载波动」，不是 V24 信号。
#
# 4. **同参数重复**：idle / hover 各重复一遍，报离散度 —— 不给噪声当信号。
#
# 5. **最小 wasm 交叉验证**（可选，`V24_MINREPRO_DIR=<examples dir>`）：
#    把 Linux 上跑出 501 ticks 的最小复现器 `stream_spin_probe_w.wasm` 在同一台
#    机器、同一判据下跑一遍。若它自旋而现场不自旋 ⇒ 判「判据不足」（现场形状不够），
#    不许判「不复现」。这是「对照组必须覆盖触发路径」那条教训的直接落实。
#
# # 参数（全部写进报告，不许挑好看的）
#
# 环境变量可覆盖：V24_SERVER_PORT(8543) V24_SOCKS_PORT(1090) V24_CONNS_A(300)
# V24_CONNS_B(60) V24_HOVER_TARGET(10.255.255.1:5226) V24_W1(8) V24_W2(18)
# V24_W3A(18) V24_W3B(30) V24_RELEASE_AFTER(8) V24_WM(12) V24_MINREPRO_DIR
# V24_WASM V24_SERVER_RUNNER
#
# # 铁律
#
# * 端口 8543/1090 刻意避开既有 e2e（8443/9443/9543/1080/1081/1082/1083/1084…）；
# * 三种裁定：复现 / 不复现 / 判据不足 —— 判据不足必须说清差什么；
# * 跑完清理：被测 wasmtime 与官方客户端都由 `v24-cpu-probe.py` 按**进程组**杀。
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

SELF="$XW_DIR/scripts/v24-field-test.sh"
PROBE="$XW_DIR/scripts/v24-cpu-probe.py"
XRAY="${XW_XRAY_BIN:-}"
if [ -z "$XRAY" ]; then
    for cand in "$XW_WS/.scratch/xray-server/xray" "$XW_DIR/../.scratch/xray-server/xray" \
                "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$cand" ] && [ -x "$cand" ] && { XRAY="$cand"; break; }
    done
fi
WASM="${V24_WASM:-$XW_WASM/xt-wasm-cli.wasm}"
# 被测命令的 run-local.sh：默认用本仓库的；**保留覆盖**是因为本仓库的
# `target/wasm32-wasip2/release/xt-wasm-cli.wasm` 可能正被别的分支/队友重建
# （共享工作区里实测发生过：别人的未提交改动把产物换了字节）。
# 判据要可归因，就必须把「测的是哪个 wasm」钉死 —— 报告里记 sha256。
SERVER_RUNNER="${V24_SERVER_RUNNER:-$XW_DIR/scripts/run-local.sh}"

SERVER_PORT="${V24_SERVER_PORT:-8543}"
SOCKS_PORT="${V24_SOCKS_PORT:-1090}"
CONNS_A="${V24_CONNS_A:-300}"
CONNS_B="${V24_CONNS_B:-60}"
HOVER_TARGET="${V24_HOVER_TARGET:-10.255.255.1:5226}"
DEST="${V24_DEST:-www.cloudflare.com:443}"
DEST_HOST="${DEST%%:*}"
CURL_URL="${V24_CURL_URL:-https://example.com/}"
CURL_TIMEOUT="${V24_CURL_TIMEOUT:-15}"
W1="${V24_W1:-8}"
W2="${V24_W2:-18}"
W3A="${V24_W3A:-18}"           # 回落实验：关连接前的窗口
W3B="${V24_W3B:-30}"           # 回落实验：关连接后的窗口
RELEASE_AFTER="${V24_RELEASE_AFTER:-8}"  # 悬停多少秒后把所有连接关掉
WM="${V24_WM:-12}"             # 最小 wasm 复现器的单窗口
MINREPRO_DIR="${V24_MINREPRO_DIR:-}"     # 设了才跑最小 wasm 交叉验证
WORK="${V24_WORK:-$XW_DIR/target/v24-field}"

mkdir -p "$WORK"

# ══════════════════════════════════════════════════════════════════════════
# 子命令 `trigger`：由 v24-cpu-probe.py 作为**外部触发**拉起。
# 它必须自己起官方客户端、制造悬停、做功能正对照，然后挂住直到被 kill。
# ══════════════════════════════════════════════════════════════════════════
if [ "${1:-}" = "trigger" ]; then
    mode="${2:-idle}"
    conns="${3:-0}"
    target="${4:-none}"
    : "${V24_WORK:?trigger 需要 V24_WORK}"
    : "${V24_XRAY:?trigger 需要 V24_XRAY}"
    : "${V24_CLIENT_JSON:?trigger 需要 V24_CLIENT_JSON}"
    : "${V24_SOCKS_PORT:?trigger 需要 V24_SOCKS_PORT}"
    : "${V24_SERVER_PORT:?trigger 需要 V24_SERVER_PORT}"
    tag="${V24_RUN_TAG:-$mode-$conns}"
    ev="$V24_WORK/trigger-$tag.evidence"
    : >"$ev"

    # 1. 官方 Xray 客户端（VLESS+REALITY → 我们的 wasm 服务端）
    "$V24_XRAY" run -c "$V24_CLIENT_JSON" >"$V24_WORK/xray-$tag.log" 2>&1 &
    xpid=$!
    socks_up=0
    i=0
    while [ "$i" -lt 80 ]; do
        if nc -z 127.0.0.1 "$V24_SOCKS_PORT" 2>/dev/null; then socks_up=1; break; fi
        kill -0 "$xpid" 2>/dev/null || break
        i=$((i + 1))
        sleep 0.25
    done
    echo "socks_up=$socks_up" >>"$ev"
    echo "socks_port=$V24_SOCKS_PORT" >>"$ev"

    # 2. 悬停连接：N 条 SOCKS5 CONNECT → 不可达目标，**不读响应、不关闭**。
    #    形状抄 e2e-spin-test.sh 第 3 步，只是多了 SOCKS 应答计数（它等价于
    #    「REALITY 握手是否成功」，是连接真的进到服务端的证据）。
    hpid=''
    if [ "$conns" -gt 0 ]; then
        release_after="${V24_RELEASE_AFTER:-0}"
        python3 - "$V24_SOCKS_PORT" "$target" "$conns" "$release_after" >"$V24_WORK/trigger-$tag.conns" 2>&1 <<'PY' &
import socket, struct, sys, time

socks_port = int(sys.argv[1])
host, tport = sys.argv[2].rsplit(":", 1)
tport = int(tport)
n = int(sys.argv[3])
release_after = float(sys.argv[4])

attempted = held = socks_ok = 0
keep = []
for _ in range(n):
    attempted += 1
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=3)
        s.settimeout(4)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            s.close()
            continue
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", tport))
        keep.append(s)
        held += 1
        try:
            r = s.recv(10)
            if len(r) >= 2 and r[0] == 5 and r[1] == 0:
                socks_ok += 1
        except socket.timeout:
            pass
    except Exception:
        break

print(f"attempted={attempted}")
print(f"held={held}")
print(f"socks_ok={socks_ok}")
sys.stdout.flush()

if release_after > 0:
    # 「回落实验」：悬停一段时间后**把连接全部关掉**，看 CPU 是否落回 idle。
    # 这一条专门排除「CPU 抬升只是随时间漂移」的解释。
    time.sleep(release_after)
    for s in keep:
        try:
            s.close()
        except OSError:
            pass
    print("released=1")
    sys.stdout.flush()

# 挂住：连接必须一直悬着，直到触发被按进程组 kill
time.sleep(900)
PY
        hpid=$!
        i=0
        while [ "$i" -lt 200 ] && ! grep -q '^held=' "$V24_WORK/trigger-$tag.conns" 2>/dev/null; do
            kill -0 "$hpid" 2>/dev/null || break
            i=$((i + 1))
            sleep 0.25
        done
        # 把 holder 的连接数证据并进统一 evidence 文件（它自己 flush 过才 sleep）
        [ -f "$V24_WORK/trigger-$tag.conns" ] && cat "$V24_WORK/trigger-$tag.conns" >>"$ev"
    fi

    # 3. 悬停期间的独立旁证：本机到服务端口的 ESTABLISHED 套接字
    #    （harness 与 guest 共用宿主 socket；含客户端/服务端两端，只记原始行数）
    lsof_lines=0
    if command -v lsof >/dev/null 2>&1; then
        lsof_lines=$(lsof -nP -iTCP:"$V24_SERVER_PORT" -sTCP:ESTABLISHED 2>/dev/null \
            | tail -n +2 | wc -l | tr -d ' ')
    fi
    echo "lsof_estab_lines=$lsof_lines" >>"$ev"

    # 4. 功能正对照：悬停仍在时经隧道真实取一次页面
    sleep 2
    code=$(curl -sS -m "$CURL_TIMEOUT" -o /dev/null -w '%{http_code}' \
        --proxy "socks5h://127.0.0.1:$V24_SOCKS_PORT" "$CURL_URL" 2>/dev/null) || code=000
    echo "curl_url=$CURL_URL" >>"$ev"
    echo "curl_code=$code" >>"$ev"

    # 5. 挂住，直到 v24-cpu-probe.py 按进程组 SIGKILL
    sleep 900
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════
# 下面是「主流程」：编排 idle / hover 两组测量。
# 悬停 holder 的 python 已内联在上面 trigger 分支里（见 `<<'PY'`）。
# ══════════════════════════════════════════════════════════════════════════

fail() { printf '\n  ✗ %s\n' "$1" >&2; exit 1; }
say()  { printf '\n==> %s\n' "$1"; }

[ -x "$XRAY" ] || fail "找不到官方 Xray 二进制（设 XW_XRAY_BIN）：$XRAY"
[ -f "$WASM" ] || fail "找不到 wasm 产物：${WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"

SELF="$XW_DIR/scripts/v24-field-test.sh"
export V24_WORK="$WORK" V24_XRAY="$XRAY" V24_SOCKS_PORT="$SOCKS_PORT" \
       V24_SERVER_PORT="$SERVER_PORT" V24_CURL_URL="$CURL_URL" V24_CURL_TIMEOUT="$CURL_TIMEOUT"

port_free() { ! nc -z 127.0.0.1 "$1" 2>/dev/null; }

wait_port_free() { # $1=port $2=seconds
    i=0
    while [ "$i" -lt $(( $2 * 4 )) ]; do
        port_free "$1" && return 0
        i=$((i + 1))
        sleep 0.25
    done
    return 1
}

say "0/6 端口预检（残留进程会让本轮静默连到上一轮的旧实例）"
for p in "$SERVER_PORT" "$SOCKS_PORT"; do
    port_free "$p" || fail "端口 $p 已被占用；先清理残留的 wasmtime/xray 再跑"
done
printf '  服务端 :%s / SOCKS :%s 空闲\n' "$SERVER_PORT" "$SOCKS_PORT"

say "1/6 生成一套全新凭据（xray x25519 + uuid + shortId）"
KEYS=$("$XRAY" x25519)
PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^PrivateKey: *//p')
PUB=$(printf '%s\n' "$KEYS" | sed -n 's/^Password (PublicKey): *//p')
[ -n "$PRIV" ] && [ -n "$PUB" ] || { printf '%s\n' "$KEYS" >&2; fail "解析 xray x25519 失败"; }
UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
SID=$(python3 -c 'import os;print(os.urandom(8).hex())')

CFG="$WORK/client.json"
cat >"$CFG" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": $SOCKS_PORT, "protocol": "socks",
     "settings": {"auth": "noauth", "udp": false}}
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {"address": "127.0.0.1", "port": $SERVER_PORT,
           "users": [{"id": "$UUID", "encryption": "none", "flow": ""}]}
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$DEST_HOST",
          "fingerprint": "chrome",
          "publicKey": "$PUB",
          "shortId": "$SID",
          "spiderX": ""
        }
      }
    }
  ]
}
EOF
export V24_CLIENT_JSON="$CFG"

# 服务端配置：与 e2e-server-test.sh 同形（环境变量注入 Secret，正是 k3s 的用法）
XT_SERVER_LISTEN="127.0.0.1:$SERVER_PORT"
XT_PRIVATE_KEY="$PRIV"
XT_SHORT_IDS="$SID"
XT_SERVER_NAMES="$DEST_HOST"
XT_DEST="$DEST"
XT_USERS="$UUID"
export XT_SERVER_LISTEN XT_PRIVATE_KEY XT_SHORT_IDS XT_SERVER_NAMES XT_DEST XT_USERS
printf '  凭据已生成（uuid %s）；客户端配置 %s\n' "$UUID" "$CFG"

# ── 单次测量：同一条被测命令，只换触发场景与窗口 ──
# 注意：人类可读输出**一律走 stderr** —— 本函数由 `$( )` 调用，stdout 只允许
# 出现最终的 cpu 秒数，否则数字会被日志污染（第一次跑就踩了这个坑）。
measure() { # $1=label $2=secs $3=mode $4=conns $5=target $6=release_after → stdout: CPU_SECONDS
    mlabel="$1"; msecs="$2"; mmode="$3"; mn="$4"; mtgt="$5"; mrel="${6:-0}"
    mtag="$mlabel-$msecs"
    plog="$WORK/$mtag-probe.log"
    # 断点续跑：同 WORK、同参数下已有 CPU_SECONDS 就复用。
    # 一次完整现场要 5–7 分钟，中间被外部 kill 掉时不该从零重来；
    # 复用是否安全取决于 tag 是否编码了全部参数 —— 改 CONNS_A 之类的参数时
    # 请换一个 V24_WORK，或先 V24_REUSE=0 跑一遍。
    if [ "${V24_REUSE:-1}" = "1" ] && [ -f "$plog" ]; then
        mcpu_cached=$(sed -n 's/^CPU_SECONDS=//p' "$plog" | tail -1)
        if [ -n "$mcpu_cached" ]; then
            printf '  [%s] 复用已有结果 %s（cpu=%s）\n' "$mlabel" "$mtag" "$mcpu_cached" >&2
            printf '%s\n' "$mcpu_cached"
            return 0
        fi
    fi
    wait_port_free "$SERVER_PORT" 15 || fail "上一轮的服务端还没退出，端口 $SERVER_PORT 仍被占用"
    printf '  [%s] 窗口 %ss，场景 %s（conns=%s target=%s release=%s）…\n' \
        "$mlabel" "$msecs" "$mmode" "$mn" "$mtgt" "$mrel" >&2
    rc=0
    V24_RUN_TAG="$mtag" V24_RELEASE_AFTER="$mrel" python3 "$PROBE" \
        --port "$SERVER_PORT" --seconds "$msecs" --wait-port 30 \
        --out "$WORK/$mtag-server.log" \
        --err "$WORK/$mtag-server.err" \
        --trigger-out "$WORK/$mtag-trigger.log" \
        --trigger-cmd "bash $SELF trigger $mmode $mn $mtgt" \
        -- env "XW_TARGET_DIR=$XW_DIR/target" "$SERVER_RUNNER" server \
        >"$plog" 2>&1 || rc=$?
    sed 's/^/    /' "$plog" >&2
    [ "$rc" -eq 0 ] || { printf '    ✗ probe 退出码 %s\n' "$rc" >&2; return 1; }
    mcpu=$(sed -n 's/^CPU_SECONDS=//p' "$plog" | tail -1)
    [ -n "$mcpu" ] || { printf '    ✗ 探针没输出 CPU_SECONDS\n' >&2; return 1; }
    printf '%s\n' "$mcpu"
}

marg() { # $1=cpu@W1 $2=cpu@W2 $3=dW → 每 wall 秒消耗的 CPU 秒（1.0 = 一核）
    awk -v a="$1" -v b="$2" -v d="$3" 'BEGIN { printf "%.4f", (b - a) / d }'
}
pct() { awk -v a="$1" -v d="$2" 'BEGIN { printf "%.1f", a / d * 100.0 }'; }
awk_ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit (a >= b) ? 0 : 1 }'; }

# 最小 wasm 复现器（可选）：Linux 上 `stream_spin_probe_w.wasm` 曾在 300 条悬停
# 连接下打满一核（V24 十一/十二续）。在本机把它当**交叉验证**跑一遍：
#   * 它也自旋 ⇒ 判据在本机有效，真实现场若不自旋，就是现场形状不够；
#   * 它也不自旋 ⇒ 本机连「已知能在 Linux 自旋的最小形状」都不发作，
#     「不复现」才是硬结论（但仍限定在 macOS，不能外推到生产 Linux）。
measure_wasm() { # $1=label $2=secs $3=conns $4=wasm → stdout: CPU_SECONDS
    wlabel="$1"; wsecs="$2"; wn="$3"; wwasm="$4"
    wtag="$wlabel-$wsecs"
    plog="$WORK/$wtag-probe.log"
    if [ "${V24_REUSE:-1}" = "1" ] && [ -f "$plog" ]; then
        wcpu_cached=$(sed -n 's/^CPU_SECONDS=//p' "$plog" | tail -1)
        if [ -n "$wcpu_cached" ]; then
            printf '  [%s] 复用已有结果 %s（cpu=%s）\n' "$wlabel" "$wtag" "$wcpu_cached" >&2
            printf '%s\n' "$wcpu_cached"
            return 0
        fi
    fi
    wait_port_free "$SERVER_PORT" 15 || fail "端口 $SERVER_PORT 仍被占用"
    printf '  [%s] 窗口 %ss，%s 条悬停连接 → %s\n' "$wlabel" "$wsecs" "$wn" "$wwasm" >&2
    rc=0
    python3 "$PROBE" --port "$SERVER_PORT" --seconds "$wsecs" --wait-port 30 \
        --conns "$wn" --settle 0.1 \
        --out "$WORK/$wtag-server.log" --err "$WORK/$wtag-server.err" \
        -- "$WASMTIME_BIN" run -C cache=n $XW_WASMTIME_ARGS "$wwasm" "$SERVER_PORT" \
        >"$plog" 2>&1 || rc=$?
    sed 's/^/    /' "$plog" >&2
    [ "$rc" -eq 0 ] || { printf '    ✗ probe 退出码 %s\n' "$rc" >&2; return 1; }
    wcpu=$(sed -n 's/^CPU_SECONDS=//p' "$plog" | tail -1)
    [ -n "$wcpu" ] || { printf '    ✗ 探针没输出 CPU_SECONDS\n' >&2; return 1; }
    printf '%s\n' "$wcpu"
}

DW=$(awk -v a="$W1" -v b="$W2" 'BEGIN { printf "%.0f", b - a }')

say "2/6 场景 ① idle：官方客户端起着、不发请求（同一条被测命令）"
IDLE1=$(measure idle "$W1" idle 0 none)
IDLE2=$(measure idle "$W2" idle 0 none)
# 同参数重复一遍：报「同一命令的离散度」，防止把噪声当信号（lead 的方法论要求）
IDLE3=$(measure idle-rep "$W2" idle 0 none)

say "3/6 场景 ② hover：$CONNS_A 条 CONNECT → $HOVER_TARGET 悬停"
HA1=$(measure hoverA "$W1" hover "$CONNS_A" "$HOVER_TARGET")
HA2=$(measure hoverA "$W2" hover "$CONNS_A" "$HOVER_TARGET")
HA3=$(measure hoverA-rep "$W2" hover "$CONNS_A" "$HOVER_TARGET")

say "4/6 场景 ③ hover（换一组参数复核）：$CONNS_B 条"
HB1=$(measure hoverB "$W1" hover "$CONNS_B" "$HOVER_TARGET")
HB2=$(measure hoverB "$W2" hover "$CONNS_B" "$HOVER_TARGET")

say "4b/6 场景 ④ 回落实验：悬停 ${RELEASE_AFTER}s 后**把连接全部关掉**"
# 这条专门排除「CPU 抬升只是随时间漂移」：W3A 窗口基本在悬停里，W3B 窗口基本在
# 关掉之后；两者的差分只反映「关掉之后」的稳态。
HR1=$(measure hoverR "$W3A" hover-release "$CONNS_A" "$HOVER_TARGET" "$RELEASE_AFTER")
HR2=$(measure hoverR "$W3B" hover-release "$CONNS_A" "$HOVER_TARGET" "$RELEASE_AFTER")

# 场景 ⑤（可选）：连接数扫描 —— 定「最小触发连接数」
SWEEP_RESULT='未跑（未设 V24_SWEEP）'
SWEEP_TABLE=''
if [ -n "${V24_SWEEP:-}" ]; then
    say "4d/6 连接数扫描 V24_SWEEP=${V24_SWEEP}（单窗口 ${V24_SWEEP_W:-25}s）"
    for sn in $(printf '%s' "$V24_SWEEP" | tr ',' ' '); do
        scpu=$(measure "sweep$sn" "${V24_SWEEP_W:-25}" hover "$sn" "$HOVER_TARGET")
        spct=$(pct "$scpu" "${V24_SWEEP_W:-25}")
        sflag='否'
        awk_ge "$(awk -v p="$spct" 'BEGIN{printf "%.4f", p/100}')" 0.5 && sflag='是'
        SWEEP_TABLE="${SWEEP_TABLE}  N=${sn}: cpu=${scpu}s cpu%=${spct}% 自旋=${sflag}
"
    done
    SWEEP_RESULT="见下方扫描表"
fi

say "4c/6 最小 wasm 复现器交叉验证（Linux 上 stream_spin_probe_w 曾 501 ticks/5s）"
MR_MW=''; MR_W_MW=''; MINREPRO_NOTE='未跑（未设 V24_MINREPRO_DIR）'
if [ -n "$MINREPRO_DIR" ]; then
    for f in stream_spin_probe stream_spin_probe_w; do
        [ -f "$MINREPRO_DIR/$f.wasm" ] || fail "缺最小复现器：$MINREPRO_DIR/$f.wasm"
    done
    # 单窗口即可：这两个 wasm 只有 11 万字节，JIT 启动开销小；判据是绝对 cpu%
    # （对照 V24 十一/十二续在 Linux 上用同一形状测到的 501 ticks / 5s ≈ 一核）
    MRC=$(measure_wasm minreproR "$WM" "$CONNS_A" "$MINREPRO_DIR/stream_spin_probe.wasm")
    MWC=$(measure_wasm minreproW "$WM" "$CONNS_A" "$MINREPRO_DIR/stream_spin_probe_w.wasm")
    MR_MW=$(pct "$MRC" "$WM")
    MR_W_MW=$(pct "$MWC" "$WM")
    MINREPRO_NOTE="read-only 对照 cpu%=${MR_MW}；write-only（Linux 上的自旋复现器）cpu%=${MR_W_MW}"
fi

IDLE_M=$(marg "$IDLE1" "$IDLE2" "$DW")
HA_M=$(marg "$HA1" "$HA2" "$DW")
HB_M=$(marg "$HB1" "$HB2" "$DW")
HR_M=$(marg "$HR1" "$HR2" "$(awk -v a="$W3A" -v b="$W3B" 'BEGIN{printf "%.0f", b-a}')")

ev_get() { # $1=tag $2=key
    sed -n "s/^$2=//p" "$WORK/trigger-$1.evidence" 2>/dev/null | tail -1
}
ev_conns() { # $1=tag $2=key（从 holder 自己的文件读，因为它在释放后还会追加）
    sed -n "s/^$2=//p" "$WORK/trigger-$1.conns" 2>/dev/null | tail -1
}

say "5/6 现场证据（每个场景期间都做了一次真实转发：功能正对照）"
EVID_TAGS="idle-$W1 idle-$W2 idle-rep-$W2 hoverA-$W1 hoverA-$W2 hoverA-rep-$W2 hoverB-$W1 hoverB-$W2 hoverR-$W3A hoverR-$W3B"
for t in $EVID_TAGS; do
    printf '  %-14s socks_up=%s held=%s socks_ok=%s released=%s curl=%s lsof_estab=%s\n' \
        "$t" "$(ev_get "$t" socks_up)" "$(ev_get "$t" held)" "$(ev_get "$t" socks_ok)" \
        "$(ev_conns "$t" released)" "$(ev_get "$t" curl_code)" "$(ev_get "$t" lsof_estab_lines)"
done
IDLE_CURL=$(ev_get "idle-$W2" curl_code)
HA_CURL=$(ev_get "hoverA-$W2" curl_code)
HB_CURL=$(ev_get "hoverB-$W2" curl_code)
FWD_A=$(grep -c 'outcome=Forwarded' "$WORK/hoverA-$W2-server.log" 2>/dev/null || true)
FWD_IDLE=$(grep -c 'outcome=Forwarded' "$WORK/idle-$W2-server.log" 2>/dev/null || true)
printf '  服务端日志 Forwarded 行数：idle=%s hoverA=%s\n' "${FWD_IDLE:-0}" "${FWD_A:-0}"
printf '  悬停连接建立（客户端侧自报）：hoverA=%s  hoverB=%s  关连接标记 released=%s\n' \
    "$(ev_get "hoverA-$W2" held)" "$(ev_get "hoverB-$W2" held)" "$(ev_conns "hoverR-$W3B" released)"
printf '  最小 wasm 交叉验证：%s\n' "$MINREPRO_NOTE"

# ── 裁定（全部用 awk 比较，避免 shell 对负数/小数的字符串判断出错） ──
say "6/6 裁定"

verdict_why=''
VERDICT='判据不足'
HA_SOCKS_UP=$(ev_get "hoverA-$W2" socks_up)
HA_HELD=$(ev_get "hoverA-$W2" held)
HR_RELEASED=$(ev_conns "hoverR-$W3B" released)

# 0) 现场本身必须成立：官方客户端起来了、隧道能真正转发；否则测的不是 V24。
if [ "${IDLE_CURL:-000}" != "200" ]; then
    verdict_why="idle 场景的功能正对照就没通（curl=${IDLE_CURL}）：现场没建起来，任何 CPU 数字都无意义"
elif [ "${HA_SOCKS_UP:-0}" != "1" ]; then
    verdict_why="hover 场景官方客户端没起来（socks_up=${HA_SOCKS_UP}）"
elif [ -z "${HA_HELD:-}" ] || [ "${HA_HELD:-0}" -lt $(( CONNS_A / 2 )) ]; then
    verdict_why="悬停连接只建立到 ${HA_HELD:-0}/$CONNS_A 条：触发形状没到位"
# 1) 复现：hover（A 组 = CONNS_A 条）marginal ≥ 0.5 核，且 ≥ 3×idle + 余量。
#    注意**不能要求小连接数组也跟着自旋** —— 实测 300 条自旋、60 条不自旋，
#    「明显与连接数相关」本身就是一个结论，不是「判据不足」。
elif awk_ge "$HA_M" 0.5 && awk_ge "$HA_M" "$(awk -v i="$IDLE_M" 'BEGIN{printf "%.4f", 3*i+0.05}')"; then
    VERDICT='复现'
    verdict_why="hover(${CONNS_A} 条) marginal=${HA_M} 核（一核=1.0），idle=${IDLE_M}，重复组 ${HA3}s/@${W2}s 同量级"
    if [ -n "$HB_M" ]; then
        verdict_why="${verdict_why}；${CONNS_B} 条时 marginal=${HB_M} ⇒ 触发与连接数强相关"
    fi
    if [ "$HR_RELEASED" = "1" ] && awk -v m="$HR_M" 'BEGIN{exit (m<0.15)?0:1}'; then
        verdict_why="${verdict_why}；回落实验：关掉全部悬停连接后 marginal=${HR_M}（回落）⇒ 抬升与悬停状态相关"
    fi
    if [ "${HA_CURL:-000}" != "200" ]; then
        verdict_why="${verdict_why}；悬停期间功能正对照 curl=${HA_CURL}（实例已被自旋占死，正是线上症状）"
    fi
# 2) 不复现（前置条件）：真实现场 A/B 两组的 marginal 都落在 idle 噪声量级
elif awk -v a="$HA_M" -v b="$HB_M" -v c="$IDLE_M" 'BEGIN { exit (a < 0.15 && b < 0.15 && c < 0.15) ? 0 : 1 }'; then
    if [ -n "$MR_W_MW" ] && awk_ge "$MR_W_MW" 50; then
        # 现场不自旋、但「Linux 上的那个最小复现器」在本机自旋 ⇒ 现场形状不够，
        # 这时判「不复现」会把一个真实机制掩盖掉。
        verdict_why="最小 wasm 写探针（stream_spin_probe_w）在本机 cpu%=$MR_W_MW 仍自旋，但真实现场不自旋：现场形状不够，不能判「不复现」"
    else
        VERDICT='不复现'
        verdict_why="hover（${CONNS_A}/${CONNS_B} 两组）与 idle 的 marginal 全 < 0.15（=15% 一核），落在 idle 噪声量级"
        [ -n "$MR_W_MW" ] && verdict_why="${verdict_why}；同一判据下最小 wasm 写探针也不自旋（cpu%=${MR_W_MW}）"
        if [ "$HR_RELEASED" = "1" ]; then
            verdict_why="${verdict_why}；回落实验：关掉全部悬停连接后 marginal=${HR_M}（已回落）"
        fi
    fi
else
    verdict_why="数字落在中间态（见下表），单靠 CPU 无法裁定；需要更大窗口/更多连接数再测"
fi

REPORT="$WORK/report.txt"
{
    echo "# V24 真实现场报告（scripts/v24-field-test.sh 原始输出）"
    echo
    echo "参数：server=127.0.0.1:$SERVER_PORT socks=127.0.0.1:$SOCKS_PORT hover_target=$HOVER_TARGET"
    echo "      connsA=$CONNS_A connsB=$CONNS_B 窗口 W1=${W1}s W2=${W2}s  ΔW=${DW}s"
    echo "      回落实验 W3A=${W3A}s W3B=${W3B}s 悬停 ${RELEASE_AFTER}s 后关连接；最小 wasm 窗口 WM=${WM}s"
    echo "      dest=$DEST curl=$CURL_URL (timeout ${CURL_TIMEOUT}s)"
    echo "      官方 Xray：$XRAY"
    echo "      wasm 产物：$WASM"
    echo "      wasm sha256：$(shasum -a 256 "$WASM" 2>/dev/null | awk '{print $1}')"
    echo "      git HEAD：$(git -C "$XW_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "      官方 Xray 版本：$("$XRAY" version 2>/dev/null | head -1)"
    echo "      被测 run-local.sh：$SERVER_RUNNER"
    echo
    echo "| 场景 | cpu@W1 | cpu@W2 | cpu%@W1 | cpu%@W2 | marginal(CPU秒/wall秒) |"
    echo "|---|---|---|---|---|---|"
    printf '| idle | %s | %s | %s%% | %s%% | %s |\n' "$IDLE1" "$IDLE2" "$(pct "$IDLE1" "$W1")" "$(pct "$IDLE2" "$W2")" "$IDLE_M"
    printf '| idle（重复） | — | %s | — | %s%% | — |\n' "$IDLE3" "$(pct "$IDLE3" "$W2")"
    printf '| hover %s conns | %s | %s | %s%% | %s%% | %s |\n' "$CONNS_A" "$HA1" "$HA2" "$(pct "$HA1" "$W1")" "$(pct "$HA2" "$W2")" "$HA_M"
    printf '| hover %s（重复） | — | %s | — | %s%% | — |\n' "$CONNS_A" "$HA3" "$(pct "$HA3" "$W2")"
    printf '| hover %s conns | %s | %s | %s%% | %s%% | %s |\n' "$CONNS_B" "$HB1" "$HB2" "$(pct "$HB1" "$W1")" "$(pct "$HB2" "$W2")" "$HB_M"
    printf '| 回落实验 %s conns（关连接） | %s | %s | %s%% | %s%% | %s |\n' \
        "$CONNS_A" "$HR1" "$HR2" "$(pct "$HR1" "$W3A")" "$(pct "$HR2" "$W3B")" "$HR_M"
    if [ -n "$MINREPRO_DIR" ]; then
        printf '| 最小 wasm 只读对照 | — | %s | — | %s%% | — |\n' "$MRC" "$MR_MW"
        printf '| 最小 wasm 只写（Linux 复现器） | — | %s | — | %s%% | — |\n' "$MWC" "$MR_W_MW"
    fi
    echo
    echo "离散度（同一命令重复两遍，同参数同窗口）："
    printf '  idle@%ss  %s vs %s（差 %s 秒）\n' "$W2" "$IDLE2" "$IDLE3" \
        "$(awk -v a="$IDLE2" -v b="$IDLE3" 'BEGIN{printf "%.3f", b-a}')"
    printf '  hoverA@%ss %s vs %s（差 %s 秒）\n' "$W2" "$HA2" "$HA3" \
        "$(awk -v a="$HA2" -v b="$HA3" 'BEGIN{printf "%.3f", b-a}')"
    echo
    echo "功能正对照（同场景期间的真实 curl，单侧判据的补丁）："
    echo "  idle   curl=$IDLE_CURL  服务端 Forwarded 行=$FWD_IDLE"
    echo "  hoverA curl=$HA_CURL  服务端 Forwarded 行=$FWD_A  悬停 held=$(ev_get "hoverA-$W2" held) socks_ok=$(ev_get "hoverA-$W2" socks_ok)"
    echo "  hoverB curl=$HB_CURL  悬停 held=$(ev_get "hoverB-$W2" held) socks_ok=$(ev_get "hoverB-$W2" socks_ok)"
    echo "  回落实验关连接标记 released=$HR_RELEASED"
    echo "  最小 wasm 交叉验证：$MINREPRO_NOTE"
    if [ -n "${V24_SWEEP:-}" ]; then
        echo "  连接数扫描（单窗口 ${V24_SWEEP_W:-25}s，≥50% 记自旋）："
        printf '%s' "$SWEEP_TABLE"
    fi
    echo
    echo "裁定：$VERDICT —— $verdict_why"
    echo
    echo "## 原始探针输出（每窗口一次）"
    for mtag in "idle-$W1" "idle-$W2" "idle-rep-$W2" "hoverA-$W1" "hoverA-$W2" "hoverA-rep-$W2" \
                "hoverB-$W1" "hoverB-$W2" "hoverR-$W3A" "hoverR-$W3B" "minreproR-$WM" "minreproW-$WM"; do
        echo
        echo "### $mtag"
        sed 's/^/    /' "$WORK/$mtag-probe.log" 2>/dev/null || echo "    （无）"
        echo "    --- 触发场景证据 ---"
        sed 's/^/    /' "$WORK/trigger-$mtag.evidence" 2>/dev/null || echo "    （无）"
        sed 's/^/    /' "$WORK/trigger-$mtag.conns" 2>/dev/null || true
        echo "    --- 服务端日志（尾部）---"
        tail -5 "$WORK/$mtag-server.log" 2>/dev/null | sed 's/^/    /' || echo "    （无）"
    done
} >"$REPORT"

printf '\n  ┌────────────────────────────────────────────────────────────────────────┐\n'
printf '  │ 场景                          cpu@%ss    cpu@%ss    marginal(核)      │\n' "$W1" "$W2"
printf '  ├────────────────────────────────────────────────────────────────────────┤\n'
printf '  │ idle                          %7ss  %7ss   %8s          │\n' "$IDLE1" "$IDLE2" "$IDLE_M"
printf '  │ idle（重复）                  %7s   %7ss   %8s          │\n' "—" "$IDLE3" "—"
printf '  │ hover %-4s conns               %7ss  %7ss   %8s          │\n' "$CONNS_A" "$HA1" "$HA2" "$HA_M"
printf '  │ hover %-4s（重复）             %7s   %7ss   %8s          │\n' "$CONNS_A" "—" "$HA3" "—"
printf '  │ hover %-4s conns               %7ss  %7ss   %8s          │\n' "$CONNS_B" "$HB1" "$HB2" "$HB_M"
printf '  │ 回落实验（关连接后）           %7ss  %7ss   %8s          │\n' "$HR1" "$HR2" "$HR_M"
if [ -n "$MINREPRO_DIR" ]; then
printf '  │ 最小 wasm 只读对照            %7s   %7ss   cpu%%=%s       │\n' "—" "$MRC" "$MR_MW"
printf '  │ 最小 wasm 只写（Linux 复现器）  %7s   %7ss   cpu%%=%s       │\n' "—" "$MWC" "$MR_W_MW"
fi
printf '  └────────────────────────────────────────────────────────────────────────┘\n'
printf '\n  marginal = (cpu@W2 - cpu@W1)/(W2-W1)（消掉 JIT/启动常数开销）；1.0 = 跑满一核\n'
printf '  功能正对照 curl：idle=%s hoverA=%s hoverB=%s（200 = 同场景下实例仍然活着）\n' \
    "$IDLE_CURL" "$HA_CURL" "$HB_CURL"
printf '  悬停 held=%s socks_ok=%s；回落实验 released=%s\n' \
    "$(ev_get "hoverA-$W2" held)" "$(ev_get "hoverA-$W2" socks_ok)" "$HR_RELEASED"
printf '  最小 wasm 交叉验证：%s\n' "$MINREPRO_NOTE"
if [ -n "${V24_SWEEP:-}" ]; then
    printf '  连接数扫描（单窗口 %ss）：\n%s' "${V24_SWEEP_W:-25}" "$SWEEP_TABLE"
fi
printf '\n  ⇒ 裁定：%s\n     %s\n' "$VERDICT" "$verdict_why"
printf '\n  原始输出：%s\n' "$REPORT"

# 收尾自检：端口应当已经释放（探针按进程组杀）
for p in "$SERVER_PORT" "$SOCKS_PORT"; do
    if ! port_free "$p"; then
        printf '\n  ⚠️ 端口 %s 仍有监听：\n' "$p" >&2
        lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null >&2 || true
    fi
done

if [ "$VERDICT" = "判据不足" ]; then
    exit 2
fi
exit 0
