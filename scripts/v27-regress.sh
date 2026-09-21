#!/bin/sh
# V27 回归判据：REALITY 握手必须在 N 秒内**结束**（成功或失败），
# 不得被一个不回包的对端永久挂住。
#
#     ./scripts/v27-regress.sh            # 对照 + 判据，自判红绿（CI 入口）
#     ./scripts/v27-regress.sh --stats    # 统计：首连专属 vs 随机（见 --help）
#
# # 为什么用「永不回包的对端」而不是官方 Xray 二进制
#
# e2e-test.sh 的第 5 步要连官方 Xray 服务端，CI 里就要下载一份外部二进制
# （本机沙箱里连 docker 都起不来）。而 V27 的症状本身与「官方」无关：
# 客户端发完 ClientHello 后等 ServerHello，**对端晚回或不回**时它卡住。
# 所以判据用一个本地 TCP 桩替代对端：
#
#     桩 accept → 把 ClientHello 读掉 → 一个字节都不回。
#
# 这是「延迟回包」的极限情况，且**完全确定**：不依赖网络、不依赖 xray、
# 不依赖机器快慢 —— 只有被测客户端的调度行为能决定红绿。
#
# # 为什么这一定是个 bug（不是「对端慢就该等」）
#
# 引擎自己声明了握手总预算 `REALITY_HANDSHAKE_TIMEOUT = 10s`
# （crates/xt-wasm-tls/src/reality.rs），所以「15s 内这条 SOCKS5 请求必须
# 拿到一个失败应答」是引擎自身契约的直接推论，不需要任何环境阈值。
#
# 而 `handshake_with_deadline` 的检查是**墙钟 + 每次被 poll 时看一眼**：
# 它没有自己的 timer pollable。`xt_wasm_runtime::block_on` 又是 waker 驱动的：
# 只有某个 pollable 就绪，任务才会被重新 poll。对端永不回包 ⇒ 读 pollable
# 永不就绪 ⇒ future 再也不会被 poll ⇒ **10s 期限永远不检查**。
#
# 实测（原始输出见 docs/findings/v27-repro.md）：
#   * 静默对端：40s 内没有任何 SOCKS 应答，客户端日志里连它自己的
#     "handshake did not complete within 10s" 都没有；
#   * 12s 才回包的对端：应答在 ~12.0s 才出现（错误文案却是 10s 超时）——
#     说明期限确实只在「下一次被唤醒」时才被检查。
#
# 这不只是「慢」：每条卡住的连接永久占住一个并发槽位
# （MAX_CONCURRENT_CONNS），一个不回包的扫描器就能把代理钉死。
#
# # 判据怎么算红/绿（脚本自己判，不靠人工看）
#
#   对照  peer 0.3s 后回一段 TLS 记录形状的字节
#         ⇒ 客户端 5s 内必须回 SOCKS5 失败（证明确实是 REALITY 层失败，
#           而且客户端本身是活的）
#   判据  peer 永不回包
#         ⇒ 客户端 15s（> 引擎自己的 10s 预算）内必须回 SOCKS5 失败
#
# 对照绿 + 判据绿 ⇒ exit 0；判据没在期限内应答 ⇒ exit 1（红），并把原始
# 探针输出与客户端日志打出来。设置错误（缺 wasm / 缺 wasmtime）⇒ exit 2。
#
# # 共享沙箱里的一个坑（本轮实测踩到）
#
# 本脚本会把 wasm 复制到临时目录**换个名字**再跑。原因：多个 agent/CI 作业
# 共用一台机器时，别人收尾用的 `pkill -f xt-wasm-cli` 会误杀我们正在跑的
# 客户端，表现为客户端在 ~6s 被 SIGTERM —— 看上去像「卡住」或「崩溃」，
# 其实与 V27 无关。换名字后同一个二元组可以稳定跑满 25s。
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

TIMEOUT_CASE="${V27_TIMEOUT:-15}"        # 判据：静默对端下的最长容忍（秒）
TIMEOUT_CTRL="${V27_CONTROL_TIMEOUT:-5}" # 对照：延迟回包下的最长容忍（秒）
PEER_DELAY="${V27_PEER_DELAY:-0.3}"      # 对照对端的回包延迟（秒）
REPEAT="${V27_REPEAT:-1}"                # 判据里同进程连续请求次数
STATS_PROCS="${V27_STATS_PROCS:-10}"
STATS_REQS="${V27_STATS_REQS:-5}"
STATS_DELAY="${V27_STATS_DELAY:-1.5}"
STATS_POLLUTE="${V27_STATS_POLLUTE:-0}"

STATS=no
while [ $# -gt 0 ]; do
    case "$1" in
        --stats) STATS=yes ;;
        --timeout) shift; TIMEOUT_CASE="$1" ;;
        -h|--help)
            cat <<'USAGE'
./scripts/v27-regress.sh [--stats] [--timeout N]

默认：跑「对照 + 判据」两条，自判红绿（约 20s）。
  --timeout N   判据容忍秒数（默认 15，必须 > 引擎自己的 10s 预算）
  --stats       额外跑统计表：对「延迟回包」对端，比较
                「每次新进程的首个连接」与「同进程后续连接」
                的卡住概率（默认 10 进程 × 5 请求）。

环境变量：V27_TIMEOUT V27_CONTROL_TIMEOUT V27_PEER_DELAY V27_REPEAT
          V27_STATS_PROCS V27_STATS_REQS V27_STATS_DELAY V27_STATS_POLLUTE
USAGE
            exit 0 ;;
        *) echo "未知参数：$1（--help 看用法）" >&2; exit 2 ;;
    esac
    shift
done

WASM="${XW_WASM}/xt-wasm-cli.wasm"
FAIL=0

die() { printf '\n  ✗ %s\n' "$1" >&2; exit 2; }
ok() { printf '  ✓ %s\n' "$1"; }
bad() { printf '  ✗ %s\n' "$1"; FAIL=1; }

[ -f "$WASM" ] || die "找不到 wasm 产物：${WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"
[ -n "${WASMTIME_BIN:-}" ] || die "找不到 wasmtime（设置 WASMTIME_BIN 或装一个）"
command -v python3 >/dev/null 2>&1 || die "需要 python3（桩 + 探针都是 python；本机 python3 可用）"

WORK="${TMPDIR:-/tmp}/v27-regress.$$"
mkdir -p "$WORK"

PEER_PID=''
CLIENT_PID=''
cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$PEER_PID" ] && kill "$PEER_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# 换名字：见文件头「共享沙箱里的一个坑」。
UNIT="$WORK/v27-unit-$$.wasm"
cp "$WASM" "$UNIT"

# ───────────────────────── 桩 + 探针（内联，不往仓库里加文件） ─────────────────────────

cat > "$WORK/peer.py" <<'PY'
#!/usr/bin/env python3
"""本地 TCP 桩，站官方 Xray 服务端的位置。

mode=silent      accept → 读掉 ClientHello → 永不回包（V27 的极限情形）
mode=after:S     accept → 读掉 ClientHello → 等 S 秒 → 回一段 TLS 记录形状的字节

回包形状刻意是「TLS handshake record 头 + 垃圾载荷」：客户端只要真的被唤醒，
就会立刻在 REALITY/TLS 解析上报错（而不是等超时）—— 于是「有没有被唤醒」
直接体现在 SOCKS5 应答的耗时上。
"""
import socket, sys, threading, time

PORT = int(sys.argv[1])
MODE = sys.argv[2] if len(sys.argv) > 2 else "silent"

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(64)
print("READY %d" % PORT, flush=True)


def handle(c, i):
    try:
        c.settimeout(60)
        try:
            c.recv(4096)
        except Exception:
            pass
        if MODE.startswith("after:"):
            time.sleep(float(MODE.split(":", 1)[1]))
            c.sendall(b"\x16\x03\x03\x00\x64" + b"\x02" * 100)
            time.sleep(0.05)
        else:
            time.sleep(3600)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


i = 0
while True:
    conn, _ = srv.accept()
    i += 1
    threading.Thread(target=handle, args=(conn, i), daemon=True).start()
PY

cat > "$WORK/probe.py" <<'PY'
#!/usr/bin/env python3
"""一条 SOCKS5（无认证）CONNECT，打印「多久拿到应答」——应答本身是失败也没关系。

输出（stdout 第一行）：
    REPLY <ms>      拿到了 4 字节应答头（rep != 0 也算「结束」）
    STALL <ms>      到超时都没有任何应答 —— 这条被永久挂住了

exit: 0 = REPLY，3 = STALL，4 = 连接/协商层面就失败（环境问题，另算）
"""
import socket, sys, struct, time

port = int(sys.argv[1])
budget = float(sys.argv[2])
host = sys.argv[3] if len(sys.argv) > 3 else "example.com"
dport = int(sys.argv[4]) if len(sys.argv) > 4 else 443

t0 = time.time()
try:
    s = socket.create_connection(("127.0.0.1", port), min(budget, 10))
    s.settimeout(budget)
except Exception as e:
    print("CONNFAIL %r" % (e,), flush=True)
    sys.exit(4)

try:
    s.sendall(b"\x05\x01\x00")          # 客户端无认证：GREETING
    r = s.recv(2)
    if r != b"\x05\x00":
        print("NEGFAIL %r" % (r,), flush=True)
        sys.exit(4)
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode()
              + struct.pack(">H", dport))
    head = s.recv(4)
    ms = (time.time() - t0) * 1000
    if len(head) < 4:
        print("EOF %s %.0f" % (head, ms), flush=True)
        sys.exit(4)
    print("REPLY %.0f rep=0x%02x" % (ms, head[1]), flush=True)
    sys.exit(0)
except socket.timeout:
    print("STALL %.0f" % ((time.time() - t0) * 1000,), flush=True)
    sys.exit(3)
except Exception as e:
    print("CONNFAIL %r" % (e,), flush=True)
    sys.exit(4)
finally:
    try:
        s.close()
    except Exception:
        pass
PY

cat > "$WORK/pollute.py" <<'PY'
#!/usr/bin/env python3
"""制造 N 条「被拒连接」——e2e-test.sh 步骤 3/4 的形状：
连上 SOCKS 端口、发一半协商就断（客户端日志会出现 `SOCKS5 协商失败：early eof`）。
用法: pollute.py <socks_port> <n>
"""
import socket, sys, time

port = int(sys.argv[1])
n = int(sys.argv[2])
for _ in range(n):
    try:
        s = socket.create_connection(("127.0.0.1", port), 3)
        s.settimeout(2)
        s.sendall(b"\x05\x01\x00")   # 只发 greeting，不发 request
        time.sleep(0.05)
        s.close()
    except Exception as e:
        print("pollute-error %r" % (e,), file=sys.stderr)
    time.sleep(0.25)
PY

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# 等端口能连上。注意：这个探测本身会在客户端侧留下一条「连上就断」的连接，
# 这正是 e2e-test.sh 步骤 3/4 的形状；本轮统计里它被单独当作变量考察。
wait_port() {
    _port="$1"; _tries="$2"; _i=0
    while [ "$_i" -lt "$_tries" ]; do
        if python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.4)
sys.exit(0 if s.connect_ex(('127.0.0.1',$_port))==0 else 1)" 2>/dev/null; then
            return 0
        fi
        _i=$((_i + 1))
        sleep 0.25
    done
    return 1
}

# 起桩 + 起客户端；把端口写进全局 PEER_PORT / CLIENT_PORT。
start_pair() {
    _mode="$1"
    PEER_PORT="$(free_port)"
    CLIENT_PORT="$(free_port)"
    python3 "$WORK/peer.py" "$PEER_PORT" "$_mode" > "$WORK/peer.log" 2>&1 &
    PEER_PID=$!
    _i=0
    while [ "$_i" -lt 60 ]; do
        grep -q '^READY' "$WORK/peer.log" 2>/dev/null && break
        _i=$((_i + 1)); sleep 0.1
    done
    grep -q '^READY' "$WORK/peer.log" 2>/dev/null || { cat "$WORK/peer.log" >&2; die "桩没起来"; }

    "$WASMTIME_BIN" run -C cache=n $XW_WASMTIME_ARGS "$UNIT" \
        --server "127.0.0.1:${PEER_PORT}" \
        --pbk "${V27_PBK:-HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg}" \
        --sid "${V27_SID:-64f6ffd42769a12c}" \
        --sni "${V27_SNI:-www.cloudflare.com}" \
        --uuid "${V27_UUID:-b21e29c8-a8ea-40a2-b953-c2b04d73d775}" \
        --listen "127.0.0.1:${CLIENT_PORT}" \
        > "$WORK/client.log" 2>&1 &
    CLIENT_PID=$!
    wait_port "$CLIENT_PORT" 120 || {
        echo "--- 客户端日志 ---" >&2; cat "$WORK/client.log" >&2
        die "wasm 客户端没有监听 127.0.0.1:${CLIENT_PORT}"
    }
    sleep 0.3
}

stop_pair() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$PEER_PID" ] && kill "$PEER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    CLIENT_PID=''; PEER_PID=''
}

# 一条探针；第一行写进 PROBE_LINE，python 的退出码透传。
# 不能写成 `... | head -1`：管道的退出码是 head 的，永远为 0，判据就永远绿了。
run_probe() {
    _budget="$1"
    _rc=0
    python3 "$WORK/probe.py" "$CLIENT_PORT" "$_budget" > "$WORK/probe.out" 2>&1 || _rc=$?
    PROBE_LINE="$(head -1 "$WORK/probe.out")"
    return "$_rc"
}

echo "==> V27 回归判据（本地桩，不依赖官方 Xray 二进制）"
echo "    被测      ${WASM}"
echo "    判据      静默对端（读掉 ClientHello 后永不回包）⇒ ${TIMEOUT_CASE}s 内必须回 SOCKS5 应答"
echo "    对照      ${PEER_DELAY}s 后回包的对端 ⇒ ${TIMEOUT_CTRL}s 内必须回 SOCKS5 应答"
echo "    引擎预算  REALITY_HANDSHAKE_TIMEOUT = 10s（crates/xt-wasm-tls/src/reality.rs）"
echo

# ───────────────────────── 对照：延迟回包 ─────────────────────────
echo "==> 对照：回包延迟 ${PEER_DELAY}s 的对端（证明客户端是活的、REALITY 层能失败）"
start_pair "after:${PEER_DELAY}"
CTRL_ALL_OK=yes
_k=1
while [ "$_k" -le "$REPEAT" ]; do
    if run_probe "$TIMEOUT_CTRL"; then
        ok "第 ${_k} 次：${PROBE_LINE}"
    else
        CTRL_ALL_OK=no
        bad "第 ${_k} 次在 ${TIMEOUT_CTRL}s 内没有应答：${PROBE_LINE}"
    fi
    _k=$((_k + 1))
done
if [ "$CTRL_ALL_OK" != yes ]; then
    echo "--- 客户端日志 ---"; cat "$WORK/client.log"
fi
stop_pair
echo

# ───────────────────────── 判据：静默对端 ─────────────────────────
echo "==> 判据：静默对端（永不回包）—— 引擎应在自己的 10s 预算内结束这条连接"
start_pair silent
CASE_ALL_OK=yes
_k=1
while [ "$_k" -le "$REPEAT" ]; do
    if run_probe "$TIMEOUT_CASE"; then
        ok "第 ${_k} 次：${PROBE_LINE}"
    else
        CASE_ALL_OK=no
        bad "第 ${_k} 次在 ${TIMEOUT_CASE}s 内没有任何应答：${PROBE_LINE}"
    fi
    _k=$((_k + 1))
done
if [ "$CASE_ALL_OK" != yes ]; then
    echo
    echo "--- 判据为红时的原始证据 ---"
    echo "探针输出：${PROBE_LINE}"
    echo "客户端日志（注意：没有它自己的 \"handshake did not complete within 10s\"）："
    sed 's/^/    /' "$WORK/client.log"
    echo "桩日志（桩已就绪 ⇒ 客户端确实出站了、卡在读上）："
    sed 's/^/    /' "$WORK/peer.log"
fi
stop_pair
echo

if [ "$STATS" = yes ]; then
    # ───────────────────── 统计：首连专属 vs 随机 ─────────────────────
    #
    # 对「1.5s 后回包」的对端（模拟冷启动服务端那种一次性延迟）跑：
    #   每个进程 5 条连续请求 × 10 个新进程
    # 把「每个进程的第 1 条」与「同进程第 2..5 条」分开统计。
    # 如果只有首连卡 ⇒ 指向订阅/注册时序；随机卡 ⇒ 指向竞态。
    echo "==> 统计：对端延迟 ${STATS_DELAY}s，${STATS_PROCS} 个新进程 × ${STATS_REQS} 条连续请求"
    echo "    (第 1 条 = 新进程的首个出站连接；第 2..N 条 = 同进程后续连接)"
    echo "    前置被拒连接数 V27_STATS_POLLUTE = ${STATS_POLLUTE}"
    echo
    _p=1
    _first_stall=0
    _first_ok=0
    _later_stall=0
    _later_ok=0
    printf '    %-10s %s\n' "进程" "逐次结果（ms，STALL=卡住）"
    while [ "$_p" -le "$STATS_PROCS" ]; do
        start_pair "after:${STATS_DELAY}"
        if [ "$STATS_POLLUTE" != 0 ]; then
            python3 "$WORK/pollute.py" "$CLIENT_PORT" "$STATS_POLLUTE" >/dev/null 2>&1 || true
            sleep 0.2
        fi
        _line=""
        _k=1
        while [ "$_k" -le "$STATS_REQS" ]; do
            if run_probe "$TIMEOUT_CASE"; then
                _line="${_line} ${PROBE_LINE#REPLY }"
                if [ "$_k" = 1 ]; then _first_ok=$((_first_ok + 1)); else _later_ok=$((_later_ok + 1)); fi
            else
                _line="${_line} STALL(${PROBE_LINE##* })"
                if [ "$_k" = 1 ]; then _first_stall=$((_first_stall + 1)); else _later_stall=$((_later_stall + 1)); fi
            fi
            _k=$((_k + 1))
        done
        printf '    %-10s%s\n' "#${_p}" "${_line}"
        stop_pair
        _p=$((_p + 1))
    done
    echo
    printf '    首个连接：%s 绿 / %s 卡（n=%s）\n' "$_first_ok" "$_first_stall" "$STATS_PROCS"
    printf '    后续连接：%s 绿 / %s 卡（n=%s）\n' "$_later_ok" "$_later_stall" "$((STATS_PROCS * (STATS_REQS - 1)))"
    echo
fi

if [ "$FAIL" = 0 ]; then
    printf '\n  V27 回归判据为绿：对端不回包时，客户端在期限内结束了握手。\n'
    exit 0
fi
printf '\n  V27 回归判据为红：客户端被一个不回包的对端永久挂住（见上面的原始证据）。\n' >&2
exit 1
