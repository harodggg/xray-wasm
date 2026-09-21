#!/bin/sh
# V27-B：把 V27（wasm 客户端首次 REALITY 握手卡住）与「官方服务端冷启动」解耦，
# 并给出延迟定量 + 工程兜底的可行性判据。
#
#     ./scripts/v27-cold-warm.sh latency   # 服务端 TLS 层冷/热延迟（裸探针，真 REALITY 认证）
#     ./scripts/v27-cold-warm.sh table     # 首连时间分解 + 有无「认证被拒前置连接」对照
#     ./scripts/v27-cold-warm.sh retry     # 兜底：首连失败后「新连接重试一次」是否可行
#     ./scripts/v27-cold-warm.sh e2e       # 真 e2e-test.sh N 次（冷启动 / 自建端口）
#     ./scripts/v27-cold-warm.sh cpu       # 首次请求窗口里 wasm 客户端自己的 CPU（复用 v24 探针）
#     ./scripts/v27-cold-warm.sh all       # 以上全部
#
# 端口默认 8643（服务端）/ 1091（客户端 SOCKS），与既有 e2e(8443/1080) 及
# 队友脚本（8743/1092、8543/1090、20000+）都不冲突。
#
# # 为什么要把二进制/产物复制到 $WORK 再跑
#
# 本机是多人共享的工作区：队友会在实验收尾时 `pkill -f xray` / `pkill -f wasmtime`，
# 而 cargo 构建会**覆盖** target/ 下的 wasm。实测过两种污染：
#   * 队友 pkill 把我正在跑的官方服务端杀掉 → 客户端报
#     `Reality TLS: EOF while reading ServerHello`（看起来像协议问题，其实是外部 kill）；
#   * target/ 下的 wasm 在两次对照之间被重新构建（475071 → 484484 字节），
#     不冻结的话「冷/热对照」可能在比两个不同的二进制。
# 所以这里把 xray / wasmtime / wasm 各复制一份到 $WORK，**并且改名去掉
# `xray` / `wasmtime` 字样**，让队友的 pkill 模式匹配不到；脚本每次打印被测
# wasm 的 sha256，保证报告里的数字能对上具体产物。
#
# # 判据
#
# * `latency`：冷启动服务端上**第一条** REALITY 连接的 ClientHello→ServerHello，
#   与第 2/3 条对比；同机直连 dest 作对照。若首连 ≈ dest RTT，则「冷启动要连
#   dest 取证书 ⇒ 慢 ~1.5s」不成立。
# * `table`：(a) 干净首连 vs (b) 先做两次「认证被拒的 SOCKS 连接」再首连，
#   各 SAMPLES 次；用服务端日志时间戳把 curl 起→ClientHello→ServerHello→
#   VLESS 头→首个响应字节分解开。
# * `e2e`：真 e2e-test.sh，冷启动服务端 + 自己的 SOCKS 端口，N 次成功率与耗时。
# * `cpu`：把 wasm 客户端本身交给 scripts/v24-cpu-probe.py，比「空转窗口」与
#   「首个请求窗口」的 CPU —— 用来判定停顿期间是在忙等还是真的挂起。

set -u

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

MODE="${1:-latency}"
PORT="${XW_V27B_PORT:-8643}"
CSOCKS="${XW_V27B_SOCKS:-1091}"
RUNS="${XW_V27B_RUNS:-3}"          # latency：冷启动轮数（每轮 3 连）
SAMPLES="${XW_V27B_SAMPLES:-5}"    # table：每个场景样本数
E2E_N="${XW_V27B_E2E_N:-10}"       # e2e：次数
CPU_SECONDS="${XW_V27B_CPU_SECONDS:-10}"
LOAD_N="${XW_V27B_LOAD:-0}"        # >0：table 期间自造 N 个 CPU 忙循环
WORK="${XW_V27B_WORK:-/tmp/v27b}"

SRC_XRAY="${XW_XRAY_BIN:-}"
if [ -z "$SRC_XRAY" ]; then
    for c in "$XW_WS/.scratch/xray-server/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$c" ] && [ -x "$c" ] && { SRC_XRAY="$c"; break; }
    done
fi
SRC_WASM="$XW_WASM/xt-wasm-cli.wasm"

die() { printf '  ✗ %s\n' "$1" >&2; exit 1; }
say() { printf '%s\n' "$1"; }

# ── 冻结被测件（并改名，避开队友的 pkill / 重建） ──────────────────────────
mkdir -p "$WORK/bin" "$WORK/frozen" "$WORK/log"
SRVBIN="$WORK/bin/v27srv"       # 原名 xray
RTBIN="$WORK/bin/v27rt"         # 原名 wasmtime
GUEST="$WORK/frozen/client.bin" # 原名 xt-wasm-cli.wasm
[ -n "$SRC_XRAY" ] && [ -x "$SRC_XRAY" ] || die "找不到官方服务端二进制（用 XW_XRAY_BIN= 指定）"
[ -n "${WASMTIME_BIN:-}" ] && [ -x "$WASMTIME_BIN" ] || die "找不到 wasmtime"
[ -f "$SRC_WASM" ] || die "找不到 wasm 产物：${SRC_WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"
cp -f "$SRC_XRAY" "$SRVBIN" && chmod +x "$SRVBIN"
cp -f "$WASMTIME_BIN" "$RTBIN" && chmod +x "$RTBIN"
cp -f "$SRC_WASM" "$GUEST"
GUEST_SHA="$(shasum -a 256 "$GUEST" | cut -d' ' -f1)"
SRV_VER="$("$SRVBIN" version 2>/dev/null | head -1 || echo '?')"

# ── 一次性服务端配置（沿用 e2e 的 gen-test-server.sh，避免硬编码凭据） ──────
CONF_DIR="$WORK/srv"
if [ ! -f "$CONF_DIR/server.json" ]; then
    XW_XRAY_BIN="$SRVBIN" XT_TEST_PORT="$PORT" scripts/gen-test-server.sh "$CONF_DIR" \
        >"$WORK/log/gen-server.log" 2>&1 || { cat "$WORK/log/gen-server.log" >&2; die "生成测试服务端配置失败"; }
fi
# shellcheck disable=SC1091
. "$CONF_DIR/params.env"
CFG="$CONF_DIR/server.json"
XT_TEST_SOCKS="127.0.0.1:$CSOCKS"   # params.env 默认写 1080（用户自己的应用），必须覆盖

PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    [ -n "${CP:-}" ] && kill "$CP" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

port_free() { ! nc -z 127.0.0.1 "$1" 2>/dev/null; }
preflight() {
    port_free "$PORT" || die "端口 $PORT 已被占用；换 XW_V27B_PORT= 或先清掉占用者"
    port_free "$CSOCKS" || die "端口 $CSOCKS 已被占用；换 XW_V27B_SOCKS="
}

# 给一行日志加绝对时间戳的小包装：把子进程输出按行加前缀。
write_helpers() {
    cat >"$WORK/tsrun.py" <<'PY'
import signal, subprocess, sys, time
p = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     bufsize=1, text=True)
def bye(sig, frm):
    try: p.terminate()
    except Exception: pass
signal.signal(signal.SIGTERM, bye); signal.signal(signal.SIGINT, bye)
for line in p.stdout:
    sys.stdout.write(f"{time.time():.3f} {line}"); sys.stdout.flush()
p.wait()
PY
    cat >"$WORK/probe.py" <<'PY'
"""对官方 Xray REALITY 入站发一条**真正通过 REALITY 认证**的 ClientHello，
只测「服务端收到 ClientHello → 发出 ServerHello」的墙上时间。

用 server.json 里的 privateKey 现算公钥、按 REALITY 客户端语义封装 session_id
（X25519 + HKDF-SHA256(salt=random[0:20], info=b"REALITY") + AES-256-GCM(AAD=整条 hello)），
所以走的是**认证路径**（会连 dest 取证书），不是「认证失败回退成中继」那条路。
耗时含 127.0.0.1 回环 RTT（<1ms），可忽略。
"""
import base64, json, os, socket, struct, sys, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

cfg_path, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
cfg = json.load(open(cfg_path))
rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
sni = rs["serverNames"][0]
short_id = bytes.fromhex(rs["shortIds"][0]).ljust(8, b"\x00")
b64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
srv_pub = X25519PrivateKey.from_private_bytes(b64(rs["privateKey"])).public_key().public_bytes_raw()

def ext(t, d):
    return struct.pack(">HH", t, len(d)) + d

def hello():
    csk = X25519PrivateKey.generate()
    cpub = csk.public_key().public_bytes_raw()
    shared = csk.exchange(X25519PublicKey.from_public_bytes(srv_pub))
    random = os.urandom(32)
    auth = HKDF(algorithm=hashes.SHA256(), length=32, salt=random[:20], info=b"REALITY").derive(shared)
    name = sni.encode()
    e = ext(0, struct.pack(">H", len(name) + 3) + b"\x00" + struct.pack(">H", len(name)) + name)
    e += ext(10, struct.pack(">H", 2) + struct.pack(">H", 0x001D))
    e += ext(13, struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804))
    e += ext(43, b"\x02" + struct.pack(">H", 0x0304))
    entry = struct.pack(">HH", 0x001D, 32) + cpub
    e += ext(51, struct.pack(">H", len(entry)) + entry)
    e += ext(45, b"\x01\x01")
    cs = [0x1301, 0x1302, 0x1303]
    body = struct.pack(">H", 0x0303) + random + b"\x20" + b"\x00" * 32
    body += struct.pack(">H", len(cs) * 2) + b"".join(struct.pack(">H", c) for c in cs)
    body += b"\x01\x00" + struct.pack(">H", len(e)) + e
    msg = b"\x01" + struct.pack(">I", len(body))[1:] + body
    aead = AESGCM(auth)
    plain = bytes([26, 3, 27, 0]) + struct.pack(">I", int(time.time())) + short_id
    sealed = aead.encrypt(random[20:32], plain, msg)
    msg = msg[:39] + sealed + msg[71:]
    return b"\x16\x03\x01" + struct.pack(">H", len(msg)) + msg

def probe():
    ch = hello()
    s = socket.create_connection((host, port), timeout=20)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t0 = time.perf_counter()
    s.sendall(ch)
    hdr = b""
    while len(hdr) < 5:
        b = s.recv(5 - len(hdr))
        if not b:
            raise RuntimeError("EOF before server hello")
        hdr += b
    t_hdr = time.perf_counter()
    ln = struct.unpack(">H", hdr[3:5])[0]
    pay = b""
    while len(pay) < ln:
        b = s.recv(ln - len(pay))
        if not b:
            raise RuntimeError("EOF in server hello")
        pay += b
    t1 = time.perf_counter()
    s.close()
    kind = "ServerHello" if hdr[0] == 22 and pay and pay[0] == 2 else \
           ("ALERT(%d,%d)" % (pay[0], pay[1]) if hdr[0] == 21 and len(pay) >= 2 else "type%d" % hdr[0])
    print("%.1f %.1f %s len=%d" % ((t_hdr - t0) * 1000, (t1 - t0) * 1000, kind, ln))

print(sys.argv[4] if len(sys.argv) > 4 else "", end=" ")
probe()
PY
}

# ── 起/停 ──────────────────────────────────────────────────────────────────
start_server() { # $1=logfile
    python3 -u "$WORK/tsrun.py" "$SRVBIN" run -c "$CFG" >"$1" 2>&1 &
    SP=$!
    PIDS="$PIDS $SP"
    for _ in $(seq 1 300); do grep -q "listening TCP" "$1" 2>/dev/null && return 0; sleep 0.02; done
    return 1
}
stop_server() { [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null; sleep 0.2; SP=""; }
stop_client() { [ -n "${CP:-}" ] && kill "$CP" 2>/dev/null; sleep 0.2; CP=""; }

start_client() { # $1=logfile
    XT_HANDSHAKE_TIMEOUT=2 XT_SOCKS_USER=testuser XT_SOCKS_PASS=testpass \
        "$RTBIN" run -C cache=n $XW_WASMTIME_ARGS "$GUEST" \
        --server "127.0.0.1:$PORT" --pbk "$XT_TEST_PBK" --sid "$XT_TEST_SID" \
        --sni "$XT_TEST_SNI" --uuid "$XT_TEST_UUID" --listen "127.0.0.1:$CSOCKS" \
        >"$1" 2>&1 &
    CP=$!
    for _ in $(seq 1 300); do grep -q '监听' "$1" 2>/dev/null && return 0; sleep 0.05; done
    return 1
}
curl_tunnel() { # $1=max-time
    curl -sS -m "$1" --proxy-user testuser:testpass --proxy "socks5h://127.0.0.1:$CSOCKS" \
        -o /dev/null -w '%{http_code}|appconnect=%{time_appconnect}|ttfb=%{time_starttransfer}|total=%{time_total}' \
        https://example.com 2>&1 || true
}
log_ts_of() { # $1=file $2=pattern → 第一处匹配行的绝对时间戳
    awk -v pat="$2" '$0 ~ pat { print $1; exit }' "$1" 2>/dev/null
}
delta() { awk -v a="$1" -v b="$2" 'BEGIN{ if (a=="" || b=="") print "NA"; else printf "%+.3f", a-b }'; }

probe_dest() { # 直连 dest 作对照
    python3 "$WORK/probe.py" "$CFG" "$XT_TEST_SNI" 443 direct
}

# ── 模式：服务端 TLS 层冷/热 ───────────────────────────────────────────────
mode_latency() {
    say ""
    say "══ latency：服务端 ClientHello→ServerHello（真 REALITY 认证路径） ══"
    say "  被测：$SRV_VER"
    preamble
    say "  对照：直连 dest ($XT_TEST_SNI:443)"
    probe_dest
    say "  冷/热：每轮重启服务端（真冷启动），连测 3 条"
    for r in $(seq 1 "$RUNS"); do
        L="$WORK/log/lat-$r.log"
        start_server "$L" || { say "  轮 ${r}：服务端没起来"; continue; }
        printf '  轮 %d 冷: ' "$r"; python3 "$WORK/probe.py" "$CFG" 127.0.0.1 "$PORT" c1
        printf '  轮 %d 热: ' "$r"; python3 "$WORK/probe.py" "$CFG" 127.0.0.1 "$PORT" c2
        printf '  轮 %d 热: ' "$r"; python3 "$WORK/probe.py" "$CFG" 127.0.0.1 "$PORT" c3
        # 服务端侧外部证据：日志里确实出现了 Server Hello（认证成功，不是回退中继）
        say "        服务端日志: $(grep -c 'Server Hello' "$L" 2>/dev/null || true) 条 Server Hello, $(grep -c 'authentication failed' "$L" 2>/dev/null || true) 条认证失败"
        stop_server
    done
}

# ── 模式：首连时间分解 + 前置连接对照 ────────────────────────────────────
one_tunnel() { # $1=label $2=scenario(a|b)
    L="$1"; S="$2"
    SRV="$WORK/log/$L.srv"; CLI="$WORK/log/$L.cli"
    start_server "$SRV" || { say "  [$L] 服务端没起来"; return 1; }
    start_client "$CLI" || { say "  [$L] 客户端没起来：$(tail -2 "$CLI" 2>/dev/null | tr '\n' ' ')"; stop_server; return 1; }
    if [ "$S" = b ]; then
        curl -sS -m 10 --proxy "socks5h://127.0.0.1:$CSOCKS" -o /dev/null https://example.com 2>/dev/null || true
        curl -sS -m 10 --proxy-user testuser:wrongpass --proxy "socks5h://127.0.0.1:$CSOCKS" \
            -o /dev/null https://example.com 2>/dev/null || true
    fi
    T0="$(python3 -c 'import time;print(f"{time.time():.3f}")')"
    R="$(curl_tunnel 30)"
    T1="$(python3 -c 'import time;print(f"{time.time():.3f}")')"
    CH="$(log_ts_of "$SRV" 'REALITY remoteAddr: 127')"
    SH="$(log_ts_of "$SRV" 'Server Hello: 127')"
    VL="$(log_ts_of "$SRV" 'firstLen = 52')"
    say "  [$L/$S] $R"
    say "        +ClientHello=$(delta "$CH" "$T0")  +ServerHello=$(delta "$SH" "$T0")  +VLESS-at-server=$(delta "$VL" "$T0")  wall=$(delta "$T1" "$T0")"
    say "        client: $(grep -E '完成|失败' "$CLI" 2>/dev/null | tail -1 | sed 's/^\[socks5\] //')"
    stop_client; stop_server
}

mode_table() {
    say ""
    say "══ table：首连时间分解 + 有无前置被拒连接 ══"
    preamble
    LOADPIDS=""
    if [ "$LOAD_N" -gt 0 ]; then
        say "  自造负载：$LOAD_N 个 CPU 忙循环"
        i=0
        while [ "$i" -lt "$LOAD_N" ]; do
            python3 -c 'while True: pass' & LOADPIDS="$LOADPIDS $!"
            i=$((i + 1))
        done
    fi
    say "  (a) 干净首连，$SAMPLES 次"
    for n in $(seq 1 "$SAMPLES"); do one_tunnel "a$n" a; done
    say "  (b) 先 2 次「认证被拒的 SOCKS 连接」再首连，$SAMPLES 次"
    for n in $(seq 1 "$SAMPLES"); do one_tunnel "b$n" b; done
    for p in $LOADPIDS; do kill "$p" 2>/dev/null || true; done
    say "  load=$(uptime | sed 's/.*load averages: //')"
}

# ── 模式：兜底可行性（失败后用**新连接**重试一次） ───────────────────────
#
# 这是「在客户端内部加重试」的**脚本级等价验证**：每次重试都是全新的 SOCKS
# 连接 → 全新的 TCP + 全新的 REALITY ClientHello（与内部重试的代价同构）。
# 注意它只能回答「重试这条路通不通、要多久」，不能回答「生产代码里该不该加重试」
# —— 后者取决于失败在 curl 超时之前还是之后才被检测到（见 findings）。
mode_retry() {
    say ""
    say "══ retry：首连失败后「新连接重试一次」可行性（$SAMPLES 轮） ══"
    preamble
    LOADPIDS=""
    if [ "$LOAD_N" -gt 0 ]; then
        say "  自造负载：$LOAD_N 个 CPU 忙循环（用来把首连推出 10s 死线）"
        i=0
        while [ "$i" -lt "$LOAD_N" ]; do
            python3 -c 'while True: pass' & LOADPIDS="$LOADPIDS $!"
            i=$((i + 1))
        done
    fi
    first_ok=0; first_fail=0; retry_ok=0; retry_fail=0
    for n in $(seq 1 "$SAMPLES"); do
        SRV="$WORK/log/rt-$n.srv"; CLI="$WORK/log/rt-$n.cli"
        start_server "$SRV" || { say "  轮 $n 服务端没起来"; continue; }
        start_client "$CLI" || { say "  轮 $n 客户端没起来"; stop_server; continue; }
        # 复刻 e2e-test.sh 第 3/4 步：两条认证被拒的 SOCKS 连接
        curl -sS -m 10 --proxy "socks5h://127.0.0.1:$CSOCKS" -o /dev/null https://example.com 2>/dev/null || true
        curl -sS -m 10 --proxy-user testuser:wrongpass --proxy "socks5h://127.0.0.1:$CSOCKS" \
            -o /dev/null https://example.com 2>/dev/null || true
        R1="$(curl_tunnel 30)"
        C1="$(echo "$R1" | cut -d'|' -f1)"
        if [ "$C1" = "200" ]; then
            first_ok=$((first_ok + 1))
            say "  轮 $n 首连 OK  : $R1"
        else
            first_fail=$((first_fail + 1))
            say "  轮 $n 首连 FAIL: $R1"
            R2="$(curl_tunnel 30)"
            C2="$(echo "$R2" | cut -d'|' -f1)"
            if [ "$C2" = "200" ]; then
                retry_ok=$((retry_ok + 1)); say "        重试 OK  : $R2"
            else
                retry_fail=$((retry_fail + 1)); say "        重试 FAIL: $R2"
            fi
        fi
        stop_client; stop_server
    done
    for p in $LOADPIDS; do kill "$p" 2>/dev/null || true; done
    rt_total=$((retry_ok + retry_fail))
    say "  → 首连成功 $first_ok/${SAMPLES}（失败 ${first_fail}）；失败后重试成功 $retry_ok/${rt_total}（失败 ${retry_fail}）"
}

# ── 模式：真 e2e-test.sh ───────────────────────────────────────────────────
mode_e2e() {
    say ""
    say "══ e2e：scripts/e2e-test.sh × ${E2E_N}（冷启动服务端 $PORT / SOCKS ${CSOCKS}） ══"
    preamble
    ok=0; fail=0
    for n in $(seq 1 "$E2E_N"); do
        preflight || { say "  第 $n 次前端口被占，跳过"; continue; }
        # ⚠️ e2e-test.sh 的客户端走 scripts/run-local.sh，而 run-local.sh 里 env.sh 会
        # 强行把 XW_WASM 指回仓库 target/ —— 所以这一模式的被测 wasm 是**仓库当前产物**，
        # 队友恰好在这一轮里重建就会换掉被测对象。故每次打印它的 sha256，跑完再对一次。
        live_sha="$(shasum -a 256 "$SRC_WASM" 2>/dev/null | cut -d' ' -f1)"
        T0="$(python3 -c 'import time;print(time.time())')"
        if XW_XRAY_BIN="$SRVBIN" XW_XRAY_DIR="$CONF_DIR" XT_TEST_SERVER="127.0.0.1:$PORT" \
                XT_TEST_SOCKS="127.0.0.1:$CSOCKS" \
                ./scripts/e2e-test.sh >"$WORK/log/e2e-$n.log" 2>&1; then
            ok=$((ok + 1)); res=PASS
        else
            fail=$((fail + 1)); res=FAIL
        fi
        T1="$(python3 -c 'import time;print(time.time())')"
        say "  #$n $res  $(awk -v a="$T1" -v b="$T0" 'BEGIN{printf "%.1fs", a-b}')  wasm-sha8=$(echo "$live_sha" | cut -c1-8)  $(grep -m1 '✗' "$WORK/log/e2e-$n.log" 2>/dev/null | sed 's/^ *//')"
    done
    say "  → 成功 $ok / ${E2E_N}，失败 ${fail}（本次 e2e 用的仓库产物 sha256=$(shasum -a 256 "$SRC_WASM" 2>/dev/null | cut -d' ' -f1)）"
}

# ── 模式：首次请求窗口里客户端自己的 CPU ─────────────────────────────────
mode_cpu() {
    say ""
    say "══ cpu：wasm 客户端在「空转」与「首个请求」两个窗口的 CPU ══"
    preamble
    for scen in idle first-req; do
        L="$WORK/log/cpu-$scen.srv"
        start_server "$L" || { say "  服务端没起来"; continue; }
        # 触发命令写成脚本，避免「空触发 / curl 触发」两套参数在 shell 里做拼接。
        TRIG="$WORK/log/trig-$scen.sh"
        if [ "$scen" = idle ]; then
            printf '#!/bin/sh\nexit 0\n' >"$TRIG"
        else
            printf '#!/bin/sh\nexec curl -sS -m 30 --proxy-user testuser:testpass --proxy socks5h://127.0.0.1:%s -o /dev/null https://example.com\n' \
                "$CSOCKS" >"$TRIG"
        fi
        chmod +x "$TRIG"
        # v24-cpu-probe.py 自己 spawn 被测进程并按 os.wait4 的 rusage 报 CPU
        OUT=$(python3 scripts/v24-cpu-probe.py --port "$CSOCKS" --seconds "$CPU_SECONDS" \
              --out "$WORK/log/cpu-$scen.cli" \
              --trigger-cmd "sh $TRIG" --trigger-out "$WORK/log/cpu-$scen.trig" \
              -- "$RTBIN" run -C cache=n $XW_WASMTIME_ARGS "$GUEST" \
              --server "127.0.0.1:$PORT" --pbk "$XT_TEST_PBK" --sid "$XT_TEST_SID" \
              --sni "$XT_TEST_SNI" --uuid "$XT_TEST_UUID" --listen "127.0.0.1:$CSOCKS" 2>&1 | tail -3)
        say "  [$scen] $(echo "$OUT" | tr '\n' ' ')"
        stop_server
    done
}

preamble() {
    say "  被测 wasm : $GUEST  sha256=$GUEST_SHA"
    say "  官方服务端: $SRVBIN  ($SRV_VER)"
    say "  端口      : server=$PORT socks=$CSOCKS   work=$WORK"
}

case "$MODE" in
    latency) write_helpers; preflight; mode_latency ;;
    table)   write_helpers; preflight; mode_table ;;
    retry)   write_helpers; preflight; mode_retry ;;
    e2e)     write_helpers; mode_e2e ;;
    cpu)     write_helpers; preflight; mode_cpu ;;
    all)     write_helpers; preflight; mode_latency; mode_table; mode_retry; mode_e2e; mode_cpu ;;
    *)       die "未知模式 ${MODE}（latency|table|retry|e2e|cpu|all）" ;;
esac
say ""
say "  done."
