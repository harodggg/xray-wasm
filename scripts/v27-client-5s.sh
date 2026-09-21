#!/bin/sh
# V27-E：那「精确 5.000s」到底卡在客户端哪一步？**结论：不在客户端任何一步。**
#
#     ./scripts/v27-client-5s.sh              # 完整现场（会编译一次带埋点的 /tmp 副本）
#     V27E_SKIP_BUILD=1 ./scripts/v27-client-5s.sh   # 复用已编好的带埋点产物
#
# # 这个脚本回答三个问题
#
# 1. **客户端内部**：把源码树复制到 $WORK/src（**不碰仓库 crates/**），在客户端
#    `serve_inner`／`open_tunnel`／relay 以及 WASI 读写就绪侧打时间戳，跑一次看 5s 卡在哪。
# 2. **去掉 curl 变量**：不只用 curl，还用一个**回环 TCP 代理**给「客户端→服务端」
#    的字节打上线时刻（代理知道字节什么时候真的离开客户端进程）。
# 3. **Vision 对照**：`--no-flow` 客户端 + 空 flow 服务端配置，看 5s 是否消失。
#    并且加了**官方 Xray 客户端**做同机对照（这一条最关键，见下）。
#
# # 判据
#
# * 客户端埋点：`client:a2b first_write`（把入站首包写进隧道）与 `client:b2a first_read`
#   （第一次从隧道读到回应）之间的差，就是「停顿」。
# * 回环代理：客户端写出去的字节什么时候真的上线。
# * 对照矩阵：wasm 客户端 / **官方 Xray 客户端** × flow / --no-flow，各测冷启动后第 1/2/3 个请求。
#   —— 如果官方客户端也慢 ~5s，而缓存/暖机后同样快，那这 5s 与客户端实现无关。
#
# # 可复现性
#
# 仓库 `target/` 会被队友重建，所以本脚本把 wasm 与 xray 二进制**冻结**到 $WORK 并打印 sha256；
# 端口用 8643/1091/1092/18080/8644（避开 1080 用户应用与 8443 既有 e2e）。
set -u

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

WORK="${V27E_WORK:-/tmp/v27e}"
PORT="${V27E_PORT:-8643}"
WSOCKS="${V27E_WSOCKS:-1091}"
OSOCKS="${V27E_OSOCKS:-1092}"
TARGET_PORT="${V27E_TARGET:-18080}"
PROXY_PORT="${V27E_PROXY:-8644}"
SRC="$WORK/src"
BIN="$WORK/target/wasm32-wasip2/release/xt-wasm-cli.wasm"

XRAY="${XW_XRAY_BIN:-}"
if [ -z "$XRAY" ]; then
    for c in "$XW_WS/.scratch/xray-server/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$c" ] && [ -x "$c" ] && { XRAY="$c"; break; }
    done
fi
say() { printf '%s\n' "$1"; }
die() { printf '  ✗ %s\n' "$1" >&2; exit 1; }
port_free() { ! nc -z 127.0.0.1 "$1" 2>/dev/null; }

[ -n "$XRAY" ] && [ -x "$XRAY" ] || die "找不到官方 xray 二进制（XW_XRAY_BIN= 指定）"
[ -n "${WASMTIME_BIN:-}" ] && [ -x "$WASMTIME_BIN" ] || die "找不到 wasmtime"
mkdir -p "$WORK/log" "$WORK/bin"

PIDS=''      # 常驻：本地目标 / 代理（跨用例复用，不能被杀）
CPIDS=''     # 单用例：服务端 + 客户端（每个用例结束就杀）
cleanup() {
    for p in $CPIDS $PIDS; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

# ── 0) 冻结 + 埋点 + 编译（只动 $WORK 里的副本）─────────────────────────────
say ""
say "══ V27-E：5.000s 卡在客户端哪一步 ══"
if [ "${V27E_SKIP_BUILD:-0}" != "1" ] || [ ! -f "$BIN" ]; then
    say "── 0) 复制源码树到 $SRC 并打埋点（仓库 crates/** 只读）──"
    rm -rf "$SRC"; mkdir -p "$SRC"
    # 用当前工作树（含队友未提交改动）——重现的是「现在这个版本」；哈希写进报告。
    tar -cf - --exclude ./.git --exclude ./target . 2>/dev/null | tar -xf - -C "$SRC"
    cat >"$WORK/patch.py" <<'PYEOF'
#!/usr/bin/env python3
"""V27-E 埋点：客户端生命周期 + relay 两个方向的 first_read/first_write + WASI 读写就绪计数。"""
import sys, pathlib

def repl(path, old, new, count=1):
    p = pathlib.Path(path); s = p.read_text()
    n = s.count(old)
    assert n == count, f"anchor in {path}: expected {count}, found {n}: {old[:70]!r}"
    p.write_text(s.replace(old, new, count))

R = sys.argv[1] + "/crates/xt-wasm-runtime/src"
C = sys.argv[1] + "/crates/xt-wasm-cli/src"

repl(R + "/lib.rs", "pub use relay::{relay_bidirectional, RelayStats};",
'''pub use relay::{relay_bidirectional, relay_bidirectional_tagged, RelayStats};

/// V27-E 埋点：`XT_DIAG=1` 时打印带单调时间戳的事件（只给 /tmp 副本用）。
pub fn xdiag(ev: &str, n: usize) {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::OnceLock;
    static STATE: AtomicU8 = AtomicU8::new(0);
    static T0: OnceLock<std::time::Instant> = OnceLock::new();
    if STATE.load(Ordering::Relaxed) == 0 {
        let on = std::env::var_os("XT_DIAG").is_some();
        STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
    }
    if STATE.load(Ordering::Relaxed) != 2 { return; }
    let t0 = T0.get_or_init(std::time::Instant::now);
    eprintln!("[XDIAG] {} t=+{:.3} n={}", ev, t0.elapsed().as_secs_f64(), n);
}''')

repl(R + "/relay.rs", "use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};",
     "use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};")
repl(R + "/relay.rs",
'''pub async fn relay_bidirectional(a: Box<dyn Stream>, b: Box<dyn Stream>) -> io::Result<RelayStats> {
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);

    let a_to_b = copy_then_eof(a_read, b_write);
    let b_to_a = copy_then_eof(b_read, a_write);''',
'''pub async fn relay_bidirectional(a: Box<dyn Stream>, b: Box<dyn Stream>) -> io::Result<RelayStats> {
    relay_bidirectional_tagged(a, b, "relay").await
}

/// 带标签版本：`tag:a2b` = 调用方这一侧 → 对端；`tag:b2a` = 反方向。
pub async fn relay_bidirectional_tagged(
    a: Box<dyn Stream>,
    b: Box<dyn Stream>,
    tag: &'static str,
) -> io::Result<RelayStats> {
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let a_to_b = copy_then_eof(a_read, b_write, format!("{tag}:a2b"));
    let b_to_a = copy_then_eof(b_read, a_write, format!("{tag}:b2a"));''')
repl(R + "/relay.rs",
'''async fn copy_then_eof<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader, &mut writer).await?;
    // 对端可能已经关了；shutdown 失败不是错误（ENOTCONN / BrokenPipe）。
    let _ = writer.shutdown().await;
    Ok(copied)
}''',
'''async fn copy_then_eof<R, W>(mut reader: R, mut writer: W, tag: String) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    crate::xdiag(&format!("{tag} task_start"), 0);
    // 与 tokio::io::copy 等价（read → write_all），但每一步都能打时间戳。
    let mut buf = vec![0u8; 16 * 1024];
    let mut total: u64 = 0;
    let mut first_read = true;
    let mut first_write = true;
    loop {
        let n = reader.read(&mut buf).await?;
        if first_read {
            crate::xdiag(&format!("{tag} first_read"), n);
            first_read = false;
        }
        if n == 0 { break; }
        writer.write_all(&buf[..n]).await?;
        if first_write {
            crate::xdiag(&format!("{tag} first_write"), n);
            first_write = false;
        }
        total += n as u64;
    }
    crate::xdiag(&format!("{tag} read_eof"), total as usize);
    // 对端可能已经关了；shutdown 失败不是错误（ENOTCONN / BrokenPipe）。
    let _ = writer.shutdown().await;
    Ok(total)
}''')
repl(C + "/main.rs",
     "    block_on, relay_bidirectional, sleep, spawn_task, timeout, NetStream, Stream,",
     "    block_on, relay_bidirectional_tagged, sleep, spawn_task, timeout, NetStream, Stream,")
repl(C + "/main.rs",
'''    let mut tls_stream: Option<Box<dyn Stream>> = None;
    let mut first_timeout: Option<Duration> = None;''',
'''    xt_wasm_runtime::xdiag("cli tunnel_begin", 0);
    let mut tls_stream: Option<Box<dyn Stream>> = None;
    let mut first_timeout: Option<Duration> = None;''')
repl(C + "/main.rs",
'''            })?;

        match layer.connect(Box::new(sock) as Box<dyn Stream>).await {''',
'''            })?;
        xt_wasm_runtime::xdiag("cli outbound_tcp_connected", 0);

        match layer.connect(Box::new(sock) as Box<dyn Stream>).await {''')
repl(C + "/main.rs",
'''                tls_stream = Some(stream);
                break;''',
'''                xt_wasm_runtime::xdiag("cli reality_handshake_done", 0);
                tls_stream = Some(stream);
                break;''')
repl(C + "/main.rs",
'''    if shared.no_flow {
        // 不包 VisionConn：请求头会在首次写时直接发出去（`new_deferred` 的语义），
        // 之后就是裸 VLESS 负载。
        Ok(Box::new(vless))''',
'''    xt_wasm_runtime::xdiag("cli vless_header_queued", 0);
    if shared.no_flow {
        // 不包 VisionConn：请求头会在首次写时直接发出去（`new_deferred` 的语义），
        // 之后就是裸 VLESS 负载。
        Ok(Box::new(vless))''')
repl(C + "/main.rs",
'''async fn serve_inner(mut stream: NetStream, shared: &Shared) -> Result<(String, u16), String> {
    // **非阻塞读永远不会自己超时**，所以协商必须套一层墙钟超时。''',
'''async fn serve_inner(mut stream: NetStream, shared: &Shared) -> Result<(String, u16), String> {
    xt_wasm_runtime::xdiag("cli conn_start", 0);
    // **非阻塞读永远不会自己超时**，所以协商必须套一层墙钟超时。''')
repl(C + "/main.rs",
'''    .map_err(|e| format!("SOCKS5 协商失败：{e}"))?;

    let (host, port) = match req {''',
'''    .map_err(|e| format!("SOCKS5 协商失败：{e}"))?;
    xt_wasm_runtime::xdiag("cli socks_request_read", 0);

    let (host, port) = match req {''')
repl(C + "/main.rs",
'''    let tunnel = match open_tunnel(shared, &host, port).await {
        Ok(t) => t,''',
'''    xt_wasm_runtime::xdiag("cli open_tunnel_begin", 0);
    let tunnel = match open_tunnel(shared, &host, port).await {
        Ok(t) => {
            xt_wasm_runtime::xdiag("cli tunnel_ready", 0);
            t
        }''')
repl(C + "/main.rs",
'''    socks5::write_reply_ok(&mut stream)
        .await
        .map_err(|e| format!("回 SOCKS5 应答失败：{e}"))?;

    relay_bidirectional(Box::new(stream), Box::new(tunnel))''',
'''    socks5::write_reply_ok(&mut stream)
        .await
        .map_err(|e| format!("回 SOCKS5 应答失败：{e}"))?;
    xt_wasm_runtime::xdiag("cli socks_granted", 0);

    xt_wasm_runtime::xdiag("cli relay_begin", 0);
    relay_bidirectional_tagged(Box::new(stream), Box::new(tunnel), "client")''')
repl(R + "/wasi.rs", "use std::sync::{Mutex, OnceLock};",
'''use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

static RD_ENTER: AtomicU64 = AtomicU64::new(0);
static RD_PEND: AtomicU64 = AtomicU64::new(0);
static RD_DATA: AtomicU64 = AtomicU64::new(0);
static WR_ENTER: AtomicU64 = AtomicU64::new(0);
static WR_CW0: AtomicU64 = AtomicU64::new(0);
static WR_PEND: AtomicU64 = AtomicU64::new(0);
static WR_OK: AtomicU64 = AtomicU64::new(0);
static FL_ENTER: AtomicU64 = AtomicU64::new(0);
static FL_PEND: AtomicU64 = AtomicU64::new(0);

/// 每个事件都自增；只打前 20 次与每 2000 次（前 20 条就是首连的时间线）。
fn tick(c: &AtomicU64, ev: &str, n: usize) {
    let v = c.fetch_add(1, Ordering::Relaxed) + 1;
    if v <= 20 || v % 2000 == 0 { crate::xdiag(ev, n); }
}''')
repl(R + "/wasi.rs",
'''        let this = self.get_mut();
        loop {
            if this
                .read_ready
                .poll(&|| this.input.subscribe(), cx)
                .is_pending()
            {
                return Poll::Pending;
            }''',
'''        let this = self.get_mut();
        tick(&RD_ENTER, "wasi read_enter", 0);
        loop {
            if this
                .read_ready
                .poll(&|| this.input.subscribe(), cx)
                .is_pending()
            {
                tick(&RD_PEND, "wasi read_pending", 0);
                return Poll::Pending;
            }''')
repl(R + "/wasi.rs",
'''                Ok(chunk) => {
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }''',
'''                Ok(chunk) => {
                    tick(&RD_DATA, "wasi read_data", chunk.len());
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }''')
repl(R + "/wasi.rs",
'''        let this = self.get_mut();
        match this.output.check_write() {
            // 0 表示当前写不进去：注册就绪后挂起，不空转。
            Ok(0) => {
                if this''',
'''        let this = self.get_mut();
        tick(&WR_ENTER, "wasi write_enter", buf.len());
        match this.output.check_write() {
            // 0 表示当前写不进去：注册就绪后挂起，不空转。
            Ok(0) => {
                tick(&WR_CW0, "wasi write_check_write_zero", 0);
                if this''')
repl(R + "/wasi.rs",
'''                    .is_pending()
                {
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0))
            }
            Ok(n) => {
                let k = (n as usize).min(buf.len());
                match this.output.write(&buf[..k]) {''',
'''                    .is_pending()
                {
                    tick(&WR_PEND, "wasi write_pending_on_zero", 0);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0))
            }
            Ok(n) => {
                let k = (n as usize).min(buf.len());
                tick(&WR_OK, "wasi write_fast_path", k);
                match this.output.write(&buf[..k]) {''')
repl(R + "/wasi.rs",
'''    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.output.flush() {''',
'''    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        tick(&FL_ENTER, "wasi flush_enter", 0);
        if let Err(e) = this.output.flush() {''')
repl(R + "/wasi.rs",
'''        if this
            .write_ready
            .poll(&|| this.output.subscribe(), cx)
            .is_pending()
        {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }''',
'''        if this
            .write_ready
            .poll(&|| this.output.subscribe(), cx)
            .is_pending()
        {
            tick(&FL_PEND, "wasi flush_pending", 0);
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }''')
print("patch OK")
PYEOF
    python3 "$WORK/patch.py" "$SRC" || die "埋点补丁没打上（源码锚点变了）"
    ( cd "$SRC" && CARGO_TARGET_DIR="$WORK/target" cargo build -p xt-wasm-cli --release \
        --target wasm32-wasip2 >"$WORK/log/build.log" 2>&1 ) || { tail -20 "$WORK/log/build.log"; die "编译失败"; }
else
    say "── 0) 复用已有带埋点产物（V27E_SKIP_BUILD=1）──"
fi
[ -f "$BIN" ] || die "找不到埋点产物 $BIN"
mkdir -p "$WORK/frozen"
GUEST="$WORK/frozen/client.bin"
cp -f "$BIN" "$GUEST"
cp -f "$XRAY" "$WORK/bin/v27e-srv" && chmod +x "$WORK/bin/v27e-srv"
SRVBIN="$WORK/bin/v27e-srv"
say "  wasm(埋点) sha256=$(shasum -a 256 "$GUEST" | cut -d' ' -f1)  size=$(wc -c <"$GUEST")"
say "  官方 xray   $("$SRVBIN" version 2>/dev/null | head -1)"
say "  源码快照    git HEAD=$(git -C "$XW_DIR" rev-parse HEAD 2>/dev/null || echo '?')  (工作树，含未提交改动)"
git -C "$XW_DIR" status --short 2>/dev/null | sed 's/^/    /'

for p in "$PORT" "$WSOCKS" "$OSOCKS" "$TARGET_PORT" "$PROXY_PORT"; do
    port_free "$p" || die "端口 $p 被占用"
done

# ── 1) 服务端配置（Vision + 空 flow 两套）与本地目标 ──
CONF="$WORK/srv"
[ -f "$CONF/server.json" ] || XW_XRAY_BIN="$SRVBIN" XT_TEST_PORT="$PORT" \
    scripts/gen-test-server.sh "$CONF" >"$WORK/log/gen.log" 2>&1 \
    || { cat "$WORK/log/gen.log"; die "生成服务端配置失败"; }
. "$CONF/params.env"
python3 - "$CONF/server.json" "$WORK/srv-empty.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["inbounds"][0]["settings"]["clients"][0]["flow"] = ""
json.dump(d, open(sys.argv[2], "w"), indent=1)
PY

cat >"$WORK/official-client.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": $OSOCKS, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": false}}],
  "outbounds": [{"protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": $PORT,
      "users": [{"id": "$XT_TEST_UUID", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
    "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"serverName": "$XT_TEST_SNI", "fingerprint": "chrome",
        "publicKey": "$XT_TEST_PBK", "shortId": "$XT_TEST_SID", "spiderX": ""}}}]
}
EOF
cat >"$WORK/official-client-empty.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{"listen": "127.0.0.1", "port": $OSOCKS, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": false}}],
  "outbounds": [{"protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": $PORT,
      "users": [{"id": "$XT_TEST_UUID", "encryption": "none", "flow": ""}]}]},
    "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"serverName": "$XT_TEST_SNI", "fingerprint": "chrome",
        "publicKey": "$XT_TEST_PBK", "shortId": "$XT_TEST_SID", "spiderX": ""}}}]
}
EOF

# 本地目标：去掉 DNS/公网变量
python3 -u - "$TARGET_PORT" >"$WORK/log/target.log" 2>&1 <<'PY' &
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"ok"
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
PIDS="$PIDS $!"
sleep 0.5

start_server() { # $1=server.json $2=log
    "$SRVBIN" run -c "$1" >"$2" 2>&1 & CPIDS="$CPIDS $!"
    for _ in $(seq 1 200); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && return 0; sleep 0.05; done
    return 1
}
start_official_client() { # $1=client.json $2=log
    "$SRVBIN" run -c "$1" >"$2" 2>&1 & CPIDS="$CPIDS $!"
    for _ in $(seq 1 200); do nc -z 127.0.0.1 "$OSOCKS" 2>/dev/null && return 0; sleep 0.05; done
    return 1
}
start_wasm_client() { # $1=log $2=server_addr [extra args...]
    wlog="$1"; waddr="$2"; shift 2
    XT_DIAG=1 "$WASMTIME_BIN" run -C cache=n $XW_WASMTIME_ARGS "$GUEST" \
        --server "$waddr" --pbk "$XT_TEST_PBK" --sid "$XT_TEST_SID" \
        --sni "$XT_TEST_SNI" --uuid "$XT_TEST_UUID" --listen "127.0.0.1:$WSOCKS" "$@" \
        >"$wlog" 2>&1 & CPIDS="$CPIDS $!"
    for _ in $(seq 1 300); do nc -z 127.0.0.1 "$WSOCKS" 2>/dev/null && return 0; sleep 0.05; done
    return 1
}
stop_case() { for p in $CPIDS; do kill "$p" 2>/dev/null || true; done; CPIDS=''; sleep 0.4; }

# 三个请求：第 1 个（冷）与第 2/3 个（暖）的 ttfb 对比就是判据
curl3() { # $1=socks $2=label
    for i in 1 2 3; do
        t=$(curl -sS -m 30 --proxy "socks5h://127.0.0.1:$1" -o /dev/null \
            -w '%{time_starttransfer}' "http://127.0.0.1:$TARGET_PORT/" 2>/dev/null) || t=FAIL
        printf '    %-12s req%d ttfb=%s\n' "$2" "$i" "$t"
    done
}

say ""
say "── 1) 对照矩阵（每次冷启动服务端；本地目标 127.0.0.1:${TARGET_PORT}，无 DNS/公网）──"
say "  A) wasm 客户端 + Vision flow"
start_server "$CONF/server.json" "$WORK/log/A.srv" || die "服务端没起来"
start_wasm_client "$WORK/log/A.cli" "127.0.0.1:$PORT" || die "wasm 客户端没起来"
sleep 0.3; curl3 "$WSOCKS" "A:wasm"
stop_case

say "  B) **官方 Xray 客户端** + Vision flow（同机对照）"
start_server "$CONF/server.json" "$WORK/log/B.srv" || die "服务端没起来"
start_official_client "$WORK/official-client.json" "$WORK/log/B.cli" || die "官方客户端没起来"
sleep 0.3; curl3 "$OSOCKS" "B:official"
stop_case

say "  C) wasm 客户端 + --no-flow + 空 flow 服务端（Vision 对照）"
start_server "$WORK/srv-empty.json" "$WORK/log/C.srv" || die "服务端没起来"
start_wasm_client "$WORK/log/C.cli" "127.0.0.1:$PORT" --no-flow || die "wasm 客户端没起来"
sleep 0.3; curl3 "$WSOCKS" "C:wasm-noflow"
stop_case

say "  D) 官方 Xray 客户端 + 空 flow 服务端"
start_server "$WORK/srv-empty.json" "$WORK/log/D.srv" || die "服务端没起来"
start_official_client "$WORK/official-client-empty.json" "$WORK/log/D.cli" || die "官方客户端没起来"
sleep 0.3; curl3 "$OSOCKS" "D:official"
stop_case

say ""
say "── 2) 客户端内部时间线（wasm，XT_DIAG=1）──"
say "  上面 A 组的关键事件："
grep -E "cli conn_start|cli socks_request_read|cli outbound_tcp_connected|cli reality_handshake_done|cli socks_granted|client:a2b first_read|client:a2b first_write|client:b2a first_read|client:b2a first_write|wasi flush_enter" \
    "$WORK/log/A.cli" | tail -25 | sed 's/^/    /'

say ""
say "── 3) 回环 TCP 代理：客户端写出的字节什么时候真的上线 ──"
say "    （客户端 --server 指向代理 :${PROXY_PORT}，代理转发到服务端 :${PORT}）"
cat >"$WORK/proxy.py" <<'PY'
import socket, threading, time, sys
LP = int(sys.argv[1]); RH = sys.argv[2]; RP = int(sys.argv[3])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", LP)); s.listen(4)
def pipe(a, b, label):
    n = 0; total = 0; last = time.time()
    while True:
        try: d = a.recv(65536)
        except OSError: break
        if not d: break
        now = time.time(); n += 1; total += len(d)
        if n <= 12 or now - last > 1.0:
            print(f"{now:.6f} {label} #{n} {len(d)}B gap={now-last:.3f} total={total}", flush=True)
        last = now
        try: b.sendall(d)
        except OSError: break
    print(f"{time.time():.6f} {label} CLOSE total={total}", flush=True)
    try: b.shutdown(socket.SHUT_WR)
    except OSError: pass
c, _ = s.accept()
u = socket.create_connection((RH, RP))
threading.Thread(target=pipe, args=(c, u, "c2s"), daemon=True).start()
pipe(u, c, "s2c")
PY
start_server "$CONF/server.json" "$WORK/log/P.srv" || die "服务端没起来"
python3 -u "$WORK/proxy.py" "$PROXY_PORT" 127.0.0.1 "$PORT" >"$WORK/log/P.proxy" 2>&1 & PIDS="$PIDS $!"
sleep 0.4
CLIENT_ABS=$(date +%s.%N)
start_wasm_client "$WORK/log/P.cli" "127.0.0.1:$PROXY_PORT" || die "wasm 客户端没起来"
sleep 0.3
curl -sS -m 30 --proxy "socks5h://127.0.0.1:$WSOCKS" -o /dev/null \
    -w '    curl ttfb=%{time_starttransfer}\n' "http://127.0.0.1:$TARGET_PORT/" 2>/dev/null || true
sleep 0.2
say "    CLIENT_PROC_START_ABS=${CLIENT_ABS}（XDIAG 的 t0 在这之后 ~1.5s，即 wasmtime JIT 之后）"
sed 's/^/    proxy: /' "$WORK/log/P.proxy"
say "    客户端关键事件："
grep -E "cli socks_granted|client:a2b first_read|client:a2b first_write|client:b2a first_read|client:b2a first_write" \
    "$WORK/log/P.cli" | sed 's/^/    /'
stop_case

say ""
say "── 判据 ──"
say "  * 若 A/B/C/D **四组**都是「第 1 个请求 ~5s、第 2/3 个 <0.5s」⇒ 停顿是"
say "    **官方服务端进程启动后第一条连接**的一次性代价，与客户端实现、与 Vision 都无关。"
say "  * 若只有 wasm 组慢 ⇒ 才轮到客户端。"
say "  * 客户端埋点里 a2b first_write 很早、b2a first_read 晚 ~5s ⇒ 客户端已经把数据写出去，在等回应。"
say "  * 回环代理里 c2s 的应用记录 #4 紧跟在握手后 ⇒ 客户端写出的字节**立刻**上了线。"
say ""
