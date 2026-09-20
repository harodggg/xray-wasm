#!/bin/sh
# 抓一份**新的**官方 Xray 客户端 ClientHello 夹具（task-3 交付物之一）。
#
#     ./scripts/capture-clienthello.sh
#
# ## 抓法（为什么是这个抓法）
#
# 官方客户端只有在**真正发起 outbound 连接**时才会发 ClientHello，所以需要一个
# 「目标地址」。这里起一个**裸 TCP 监听**冒充 outbound 的 server：
#
#   1. python3 监听 127.0.0.1:$PORT（默认 18443），accept 后**什么都不回**；
#   2. 用官方 xray 二进制 + 参考配置 client.json（其 realitySettings.fingerprint=chrome）
#      起一个临时客户端，把 outbound 的 address/port 改指向我们的监听器、socks 入站
#      端口改成 $SOCKS 以免和正在跑的实例撞车；
#   3. 用 curl 走 socks5h 触发一次真实 outbound —— 这时客户端必须先把 ClientHello
#      发出去（REALITY 的认证数据就藏在 ClientHello 里），所以**不需要**实现任何
#      TLS 服务端就能拿到真货；
#   4. 监听器只读第一条 TLS record（5 字节 record 头 + record 长度指定的载荷），
#      认 content_type=0x16(handshake) 且载荷首字节 0x01(ClientHello) 的那一条，
#      然后退出。curl 因为永远等不到 ServerHello 而失败，这是**预期**的。
#
# 产物 = **handshake 消息**（**去掉** 5 字节 record 头），与仓库里已有的夹具
# `crates/xt-wasm-tls/src/testdata/xray-clienthello.hex` 粒度一致：首字节 0x01，
# 随后 3 字节长度 == 剩余字节数。已有那份夹具不能被覆盖，所以本脚本每次都写
# **新文件**（带 UTC 时间戳），并用 O_EXCL 防止覆盖。
#
# ## 用法 / 环境变量
#
#   ./scripts/capture-clienthello.sh
#   PORT=28443 SOCKS=11081 ./scripts/capture-clienthello.sh
#   XW_XRAY_BIN=/path/to/xray XW_XRAY_CLIENT_CFG=/path/to/client.json ./scripts/capture-clienthello.sh
#   OUT=/tmp/whatever.hex ./scripts/capture-clienthello.sh
#
# 默认值：
#   XW_XRAY_BIN        <workspace>/.scratch/xray-server/xray          （26.3.27）
#   XW_XRAY_CLIENT_CFG <workspace>/.scratch/xray-server/client.json   （fingerprint: chrome）
#   PORT               18443
#   SOCKS              11080
#   OUT                crates/xt-wasm-tls/src/testdata/xray-clienthello-<UTC 时间戳>.hex
#
# ## 拿到夹具之后
#
# 算这份新夹具的 JA3/JA4（顺带与 xray-clienthello.hex 对拍）：
#   CARGO_TARGET_DIR=$PWD/target cargo test -p xt-wasm-tls --test fingerprint_differential -- --nocapture
# 或手工 JA3（五段串见测试输出）：
#   printf %s '<preimage>' | openssl md5
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$XW_DIR/scripts/env.sh"

XW_XRAY_BIN="${XW_XRAY_BIN:-$XW_WS/.scratch/xray-server/xray}"
XW_XRAY_CLIENT_CFG="${XW_XRAY_CLIENT_CFG:-$XW_WS/.scratch/xray-server/client.json}"
PORT="${PORT:-18443}"
SOCKS="${SOCKS:-11080}"
DEADLINE="${DEADLINE:-25}"

[ -x "$XW_XRAY_BIN" ] || { echo "找不到官方 Xray 二进制：${XW_XRAY_BIN}（用 XW_XRAY_BIN= 指定）" >&2; exit 1; }
[ -f "$XW_XRAY_CLIENT_CFG" ] || { echo "找不到客户端配置：$XW_XRAY_CLIENT_CFG" >&2; exit 1; }
command -v python3 >/dev/null || { echo "需要 python3" >&2; exit 1; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$XW_DIR/crates/xt-wasm-tls/src/testdata/xray-clienthello-$TS-$$.hex}"
[ -e "$OUT" ] && { echo "产物已存在，拒绝覆盖：${OUT}（换个 OUT= 或等下一秒）" >&2; exit 1; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/xw-capture.XXXXXX")"
XRAY_PID=''
cleanup() {
    [ -n "$XRAY_PID" ] && kill "$XRAY_PID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

echo "==> 1/4 生成本次专用客户端配置（outbound -> 127.0.0.1:$PORT, socks -> ${SOCKS}）"
python3 - "$XW_XRAY_CLIENT_CFG" "$TMP/client.json" "$PORT" "$SOCKS" <<'PY'
import json, sys
src, dst, port, socks = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
cfg = json.load(open(src))
cfg.setdefault("log", {})["loglevel"] = "warning"
cfg["inbounds"][0]["port"] = socks
cfg["outbounds"][0]["settings"]["vnext"][0]["address"] = "127.0.0.1"
cfg["outbounds"][0]["settings"]["vnext"][0]["port"] = port
json.dump(cfg, open(dst, "w"), indent=2)
print("    fingerprint =", cfg["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"])
print("    sni         =", cfg["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"])
PY

echo "==> 2/4 起裸 TCP 监听 127.0.0.1:${PORT}（只读第一条 ClientHello record，不回任何字节）"
# 监听器在后台跑；成功时把 handshake hex 写进 $TMP/ch.hex，失败/超时写 $TMP/listener.err。
python3 - "$PORT" "$TMP/ch.hex" "$TMP/listener.err" "$DEADLINE" <<'PY' &
import socket, struct, sys, time
port, out, errf, deadline = int(sys.argv[1]), sys.argv[2], sys.argv[3], float(sys.argv[4])

def recvn(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(8)
srv.settimeout(1.0)
end = time.time() + deadline
seen = 0
while time.time() < end:
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        continue
    conn.settimeout(5.0)
    try:
        hdr = recvn(conn, 5)
        if len(hdr) < 5:
            open(errf, "a").write("short record header %r from %s\n" % (hdr, addr))
            continue
        ctype, ver, ln = hdr[0], struct.unpack(">H", hdr[1:3])[0], struct.unpack(">H", hdr[3:5])[0]
        payload = recvn(conn, ln)
        if len(payload) != ln:
            open(errf, "a").write("short record payload %d != %d\n" % (len(payload), ln))
            continue
        seen += 1
        open(errf, "a").write("record #%d type=%d ver=0x%04x len=%d first=0x%02x\n"
                              % (seen, ctype, ver, ln, payload[0] if payload else 0))
        # content_type 0x16 = handshake；handshake type 0x01 = ClientHello
        if ctype == 0x16 and payload and payload[0] == 0x01:
            blen = (payload[1] << 16) | (payload[2] << 8) | payload[3]
            if blen != len(payload) - 4:
                open(errf, "a").write("ClientHello 长度字段 %d != 实长 %d\n" % (blen, len(payload) - 4))
                sys.exit(3)
            open(out, "w").write(payload.hex())
            print("    captured %d bytes (record %d bytes)" % (len(payload), ln))
            sys.exit(0)
    except socket.timeout:
        open(errf, "a").write("read timeout from %s\n" % (addr,))
    finally:
        conn.close()
open(errf, "a").write("deadline exceeded, no ClientHello; %d record(s) seen\n" % seen)
sys.exit(2)
PY
LISTENER_PID=$!

echo "==> 3/4 起官方 xray 客户端并触发一次 outbound"
"$XW_XRAY_BIN" run -c "$TMP/client.json" >"$TMP/xray.log" 2>&1 &
XRAY_PID=$!

i=0
while [ "$i" -lt 50 ]; do
    nc -z 127.0.0.1 "$SOCKS" 2>/dev/null && break
    i=$((i + 1))
    sleep 0.1
done
[ "$i" -lt 50 ] || { echo "xray 客户端没起来，日志：" >&2; cat "$TMP/xray.log" >&2; exit 1; }

# 触发：这次握手注定失败（我们没有 TLS 服务端），失败是预期，抓不到才算失败。
curl -sS -m 8 --proxy "socks5h://127.0.0.1:$SOCKS" https://example.com -o /dev/null 2>"$TMP/curl.log" || true
echo "    curl（预期失败，仅用于触发握手）：$(head -1 "$TMP/curl.log" 2>/dev/null || echo '(无输出)')"

wait "$LISTENER_PID" || {
    echo "监听器没抓到 ClientHello —— xray 日志：" >&2
    cat "$TMP/xray.log" >&2
    echo "监听器记录：" >&2
    cat "$TMP/listener.err" >&2
    exit 1
}
kill "$XRAY_PID" 2>/dev/null || true
XRAY_PID=''

echo "==> 4/4 校验并落盘"
[ -s "$TMP/ch.hex" ] || { echo "产物为空" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
# 用 python 做一次结构性校验（首字节 0x01、长度字段自洽，不信任监听器的自我报告），
# 并顺带算出 JA3 / JA4 —— 这是**独立于 Rust 测试**的另一份实现，用于交叉验证
# `tests/fingerprint_differential.rs` 里的 JA3/JA4 计算器（两份实现 + openssl/hashlib）。 
# JA4 的定义见 https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
python3 - "$TMP/ch.hex" "$OUT" <<'PY'
import sys, os, struct, hashlib

hexs = open(sys.argv[1]).read().strip()
out = sys.argv[2]
b = bytes.fromhex(hexs)
assert b[0] == 1, "首字节不是 0x01(ClientHello)：0x%02x" % b[0]
blen = (b[1] << 16) | (b[2] << 8) | b[3]
assert blen == len(b) - 4, "长度字段 %d != 实长 %d" % (blen, len(b) - 4)

is_grease = lambda v: (v & 0x0F0F) == 0x0A0A
p = 4
legacy = struct.unpack(">H", b[p:p + 2])[0]; p += 2
p += 32
sid_len = b[p]; p += 1 + sid_len
cs_len = struct.unpack(">H", b[p:p + 2])[0]; p += 2
ciphers = [struct.unpack(">H", b[p + 2 * i:p + 2 * i + 2])[0] for i in range(cs_len // 2)]; p += cs_len
cmp_len = b[p]; p += 1 + cmp_len
ext_len = struct.unpack(">H", b[p:p + 2])[0]; p += 2
q, exts = p, []
while q < p + ext_len:
    t, l = struct.unpack(">HH", b[q:q + 4]); exts.append((t, q + 4, l)); q += 4 + l
assert q == p + ext_len, "扩展区长度不自洽"
body = lambda e: b[e[1]:e[1] + e[2]]
one = lambda t: next((e for e in exts if e[0] == t), None)
ng = lambda vs: [v for v in vs if not is_grease(v)]

# ---- JA3 ----
sg = one(0x000a); sgd = body(sg) if sg else b"\x00\x00"
n = struct.unpack(">H", sgd[:2])[0]
curves = ng([struct.unpack(">H", sgd[2 + 2 * i:4 + 2 * i])[0] for i in range(n // 2)])
pf = one(0x000b); pfd = body(pf) if pf else b"\x00"
pts = list(pfd[1:1 + pfd[0]])
ja3_pre = "%d,%s,%s,%s,%s" % (
    legacy,
    "-".join(str(c) for c in ng(ciphers)),
    "-".join(str(t) for t, _, _ in exts if not is_grease(t)),
    "-".join(str(c) for c in curves),
    "-".join(str(x) for x in pts),
)
ja3 = hashlib.md5(ja3_pre.encode()).hexdigest()

# ---- JA4 ----
sv = one(0x002b); svd = body(sv) if sv else b"\x00"
vers = ng([struct.unpack(">H", svd[1 + 2 * i:3 + 2 * i])[0] for i in range(svd[0] // 2)]) if sv else []
vstr = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}.get(max(vers) if vers else legacy, "00")
sni = "d" if one(0x0000) else "i"
cng = ng(ciphers)
eng = [t for t, _, _ in exts if not is_grease(t)]
al = one(0x0010)
if al:
    ad = body(al); plen = ad[2]; alpn = ad[3:3 + plen]
    alnum = lambda c: (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122)
    if not alpn:
        afp = "00"
    elif alnum(alpn[0]) and alnum(alpn[-1]):
        afp = chr(alpn[0]) + chr(alpn[-1])   # 单字符时首尾同字符
    else:
        h = alpn.hex()                      # 非字母数字 -> 用 hex 表示的首尾字符
        afp = h[0] + h[-1]
else:
    afp = "00"
ja4_a = "t%s%s%02d%02d%s" % (vstr, sni, min(len(cng), 99), min(len(eng), 99), afp)
ja4_b = hashlib.sha256(",".join("%04x" % c for c in sorted(cng)).encode()).hexdigest()[:12] if cng else "000000000000"
eph = sorted(t for t in eng if t not in (0x0000, 0x0010))
sa = one(0x000d)
sigs = []
if sa:
    sad = body(sa); salen = struct.unpack(">H", sad[:2])[0]
    sigs = ng([struct.unpack(">H", sad[2 + 2 * i:4 + 2 * i])[0] for i in range(salen // 2)])
cpre = ",".join("%04x" % t for t in eph)
if sigs:
    cpre += "_" + ",".join("%04x" % s for s in sigs)
ja4_c = hashlib.sha256(cpre.encode()).hexdigest()[:12] if eph else "000000000000"

fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
with os.fdopen(fd, "w") as f:
    f.write(hexs)
print("    写出 %s（%d 字节 handshake 消息，session_id=%d）" % (out, len(b), sid_len))
print("    JA3 : %s" % ja3)
print("     →     %s" % ja3_pre)
print("    JA4 : %s_%s_%s" % (ja4_a, ja4_b, ja4_c))
print("     →     %s_%s|%s" % (ja4_a, ja4_b, cpre))
print("    extensions 顺序（type:len）: %s" % " ".join("%04x:%d" % (t, l) for t, _, l in exts))
PY

echo
echo "完成。新夹具：$OUT"
echo "监听器记录（record 头信息）："
cat "$TMP/listener.err"
echo
echo "下一步："
echo "  CARGO_TARGET_DIR=\$PWD/target cargo test -p xt-wasm-tls --test fingerprint_differential -- --nocapture"
