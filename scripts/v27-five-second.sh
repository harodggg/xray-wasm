#!/bin/sh
# V27-D：定位「ServerHello → 服务端收到 VLESS 头 = 精确 5.000s」在哪一侧。
#
#     ./scripts/v27-five-second.sh
#
# 输出三组可复现证据：
#   1. `flight.py`（Python 手写、**真 REALITY 认证**的 ClientHello）裸连冷启动官方服务端：
#      ServerHello 与**首个加密飞行包**（TLS record type=23）分别何时到达。
#   2. 完整隧道：wasm 客户端 + `curl -v`（全程绝对时间戳），把
#      「SOCKS 请求 → SOCKS 放行 → 首个响应字节」切开。
#   3. 官方服务端自己的日志（加绝对时间戳）：ClientHello → ServerHello →
#      **读到客户端 Finished** → 首个应用记录。第三项是关键：
#      `readClientFinished` 与 `firstLen` 之间的差就是那 5 秒。
#
# 结论（本机实测，见 docs/findings/v27-five-second.md）：
#   * 服务端在收到合法 ClientHello 后 ~0.25s 内就把 ServerHello **和** 2657 字节的
#     加密飞行包一起写出来了 —— 服务端不是瓶颈；
#   * 服务端在 ServerHello 同一毫秒内就**读到了客户端的 Finished** —— 握手本身也是快的；
#   * 之后它等 **5.001s** 才收到客户端的第一个应用记录（VLESS 头）。
#   ⇒ 这 5 秒在**客户端/运行时**一侧，且位于「REALITY 握手完成、SOCKS 已放行」之后、
#     「首个 payload 转发」之前。10s 死线与之无关（那是握手层的）。
#
# # 可复现性注意
# 仓库 `target/` 下的 wasm 会被队友重新构建。本脚本把它**冻结**到 $WORK 并打印 sha256；
# xray / wasmtime 也各复制一份并改名（去掉 `xray`/`wasmtime` 字样），否则队友收尾时
# `pkill -f xray` 可能把你正在跑的服务端杀掉，症状会伪装成协议失败。
set -u

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

WORK="${XW_V27D_WORK:-/tmp/v27f}"
PORT="${XW_V27D_PORT:-8643}"
CSOCKS="${XW_V27D_SOCKS:-1091}"

SRC_XRAY="${XW_XRAY_BIN:-}"
if [ -z "$SRC_XRAY" ]; then
    for c in "$XW_WS/.scratch/xray-server/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$c" ] && [ -x "$c" ] && { SRC_XRAY="$c"; break; }
    done
fi
die() { printf '  ✗ %s\n' "$1" >&2; exit 1; }
say() { printf '%s\n' "$1"; }

mkdir -p "$WORK/bin" "$WORK/log"
SRVBIN="$WORK/bin/v27srv"; RTBIN="$WORK/bin/v27rt"; GUEST="$WORK/frozen/client.bin"
[ -n "$SRC_XRAY" ] && [ -x "$SRC_XRAY" ] || die "找不到官方服务端二进制（XW_XRAY_BIN= 指定）"
[ -n "${WASMTIME_BIN:-}" ] && [ -x "$WASMTIME_BIN" ] || die "找不到 wasmtime"
mkdir -p "$WORK/frozen"
[ -f "$XW_WASM/xt-wasm-cli.wasm" ] || die "找不到 wasm 产物：$XW_WASM/xt-wasm-cli.wasm"
cp -f "$SRC_XRAY" "$SRVBIN" && chmod +x "$SRVBIN"
cp -f "$WASMTIME_BIN" "$RTBIN" && chmod +x "$RTBIN"
cp -f "$XW_WASM/xt-wasm-cli.wasm" "$GUEST"
GUEST_SHA="$(shasum -a 256 "$GUEST" | cut -d' ' -f1)"

CONF_DIR="$WORK/srv"
if [ ! -f "$CONF_DIR/server.json" ]; then
    XW_XRAY_BIN="$SRVBIN" XT_TEST_PORT="$PORT" scripts/gen-test-server.sh "$CONF_DIR" \
        >"$WORK/log/gen.log" 2>&1 || { cat "$WORK/log/gen.log" >&2; die "生成测试服务端配置失败"; }
fi
# shellcheck disable=SC1091
. "$CONF_DIR/params.env"
CFG="$CONF_DIR/server.json"

PIDS=""
CP=''
cleanup() {
    [ -n "$CP" ] && kill "$CP" 2>/dev/null || true
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

# 给子进程输出逐行加绝对时间戳（便于两侧日志按同一时钟对齐）。
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

cat >"$WORK/flight.py" <<'PY'
"""真 REALITY 认证的 ClientHello → 分别测 ServerHello 与首个加密飞行包到达时刻。"""
import base64, json, os, socket, struct, sys, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

cfg = json.load(open(sys.argv[1])); host, port = sys.argv[2], int(sys.argv[3])
rs = cfg["inbounds"][0]["streamSettings"]["realitySettings"]
sni = rs["serverNames"][0]
short_id = bytes.fromhex(rs["shortIds"][0]).ljust(8, b"\x00")
b64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
srv_pub = X25519PrivateKey.from_private_bytes(b64(rs["privateKey"])).public_key().public_bytes_raw()

def ext(t, d): return struct.pack(">HH", t, len(d)) + d

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
    e += ext(51, struct.pack(">H", len(entry)) + entry) + ext(45, b"\x01\x01")
    cs = [0x1301, 0x1302, 0x1303]
    body = struct.pack(">H", 0x0303) + random + b"\x20" + b"\x00" * 32
    body += struct.pack(">H", len(cs) * 2) + b"".join(struct.pack(">H", c) for c in cs)
    body += b"\x01\x00" + struct.pack(">H", len(e)) + e
    msg = b"\x01" + struct.pack(">I", len(body))[1:] + body
    plain = bytes([26, 3, 27, 0]) + struct.pack(">I", int(time.time())) + short_id
    sealed = AESGCM(auth).encrypt(random[20:32], plain, msg)
    msg = msg[:39] + sealed + msg[71:]
    return b"\x16\x03\x01" + struct.pack(">H", len(msg)) + msg

def recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c: raise RuntimeError("EOF")
        b += c
    return b

s = socket.create_connection((host, port), timeout=40)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
t0 = time.perf_counter(); s.sendall(hello())
t_sh = t_app = None; records = []
while True:
    hdr = recvn(s, 5)
    ln = struct.unpack(">H", hdr[3:5])[0]
    recvn(s, ln)
    t = time.perf_counter() - t0
    records.append("%d:%d@%.3f" % (hdr[0], ln, t))
    if hdr[0] == 22 and t_sh is None: t_sh = t
    if hdr[0] == 23: t_app = t; break
print("t_ServerHello=%.3f  t_first_encrypted_flight=%.3f  records=%s" % (
    t_sh if t_sh is not None else -1, t_app if t_app is not None else -1, " ".join(records)))
s.close()
PY

start_server() { # $1=logfile [prefix]
    python3 -u "$WORK/tsrun.py" "$SRVBIN" run -c "$CFG" >"$1" 2>&1 &
    SP=$!; PIDS="$PIDS $SP"
    for _ in $(seq 1 300); do grep -q "listening TCP" "$1" 2>/dev/null && return 0; sleep 0.02; done
    return 1
}
stop_server() { [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null; sleep 0.2; SP=''; }
port_free() { ! nc -z 127.0.0.1 "$1" 2>/dev/null; }

say ""
say "══ V27-D：5.000s 在哪一侧 ══"
say "  wasm  : $GUEST  sha256=$GUEST_SHA"
say "  服务端: $SRVBIN  ($("$SRVBIN" version 2>/dev/null | head -1))"
port_free "$PORT"  || die "端口 $PORT 被占用（XW_V27D_PORT= 换一个）"
port_free "$CSOCKS" || die "端口 $CSOCKS 被占用（XW_V27D_SOCKS= 换一个）"

say ""
say "── 1) 裸探针（真 REALITY 认证）：服务端多久发出 ServerHello / 加密飞行包 ──"
for r in 1 2; do
    start_server "$WORK/log/f$r.srv" || { say "  轮 $r 服务端没起来"; continue; }
    printf '  冷启动轮 %d 冷: ' "$r"; python3 "$WORK/flight.py" "$CFG" 127.0.0.1 "$PORT"
    printf '  冷启动轮 %d 热: ' "$r"; python3 "$WORK/flight.py" "$CFG" 127.0.0.1 "$PORT"
    printf '  冷启动轮 %d 热: ' "$r"; python3 "$WORK/flight.py" "$CFG" 127.0.0.1 "$PORT"
    stop_server
done

say ""
say "── 2) 完整隧道：curl -v（绝对时间戳）+ 服务端日志对表 ──"
start_server "$WORK/log/tunnel.srv" || die "服务端没起来"
XT_HANDSHAKE_TIMEOUT=2 XT_SOCKS_USER=testuser XT_SOCKS_PASS=testpass \
    python3 -u "$WORK/tsrun.py" "$RTBIN" run -C cache=n $XW_WASMTIME_ARGS "$GUEST" \
    --server "127.0.0.1:$PORT" --pbk "$XT_TEST_PBK" --sid "$XT_TEST_SID" \
    --sni "$XT_TEST_SNI" --uuid "$XT_TEST_UUID" --listen "127.0.0.1:$CSOCKS" \
    >"$WORK/log/tunnel.cli" 2>&1 &
CP=$!
for _ in $(seq 1 300); do grep -q '监听' "$WORK/log/tunnel.cli" 2>/dev/null && break; sleep 0.05; done
sleep 0.3
python3 -u "$WORK/tsrun.py" curl -v -sS -m 30 --proxy-user testuser:testpass \
    --proxy "socks5h://127.0.0.1:$CSOCKS" -o /dev/null \
    -w 'curl-done code=%{http_code} ttfb=%{time_starttransfer} total=%{time_total}\n' \
    https://example.com >"$WORK/log/tunnel.curl" 2>&1 || true
sleep 0.5
kill "$CP" 2>/dev/null || true; CP=''; stop_server

python3 - "$WORK/log/tunnel.srv" "$WORK/log/tunnel.curl" <<'PY'
import re, sys
srv = open(sys.argv[1]).read().splitlines()
curl = open(sys.argv[2]).read().splitlines()
def first(lines, pat):
    rx = re.compile(pat)
    for l in lines:
        if rx.search(l):
            return float(l.split()[0])
    return None
def f(v):
    return "NA" if v is None else "%.3f" % v
def d(a, b):
    return "NA" if a is None or b is None else "%+.3f" % (a - b)
ch  = first(srv, r'REALITY remoteAddr: [0-9.]+:[0-9]+$')
sh  = first(srv, r'Server Hello: 127')
fin = first(srv, r'readClientFinished')
app = first(srv, r'postHandshakeRecord')
vless = first(srv, r'firstLen = 52')
granted = first(curl, r'SOCKS5 request granted')
ttfb_line = [l for l in curl if 'curl-done' in l]
print("  服务端: ClientHello=%s  ServerHello=%s (+%s)  readClientFinished=%s (+%s)  first-postHandshake=%s (+%s)  firstLen=%s (+%s)" % (
    f(ch), f(sh), d(sh, ch), f(fin), d(fin, sh), f(app), d(app, fin), f(vless), d(vless, app)))
print("  客户端: curl SOCKS5 request granted=%s ... 首个响应字节见 curl-done" % f(granted))
print("  curl  : %s" % (ttfb_line[-1].split(None, 1)[1] if ttfb_line else "(无)"))
if fin is not None and app is not None:
    print("  ⇒ readClientFinished → 服务端收到第一个应用记录 = %s 秒；服务端在此之前一直等客户端。" % d(app, fin))
PY
say ""
say "  判据：若 (a) 裸探针的 ServerHello 与加密飞行包都在 ~0.3s 内、且 (b) 服务端"
say "        readClientFinished 与 ServerHello 同毫秒、而 first-postHandshake − readClientFinished ≈ 5.000s，"
say "        则这 5 秒在客户端/运行时一侧（不是官方服务端、不是 TLS/REALITY 层）。"
say ""
