#!/bin/sh
# 端到端测试：**stock Xray 客户端 → 我们的 wasm REALITY 服务端** → 外网。
#
#     ./scripts/e2e-server-test.sh
#
# 与 e2e-test.sh 正好是镜像关系：
#   e2e-test.sh        我们的 wasm 客户端 → stock Xray 服务端
#   e2e-server-test.sh stock Xray 客户端 → 我们的 wasm 服务端
#
# 四条用例，后两条才是真正容易出事的部分：
#   1. 认证过的客户端能拿到页面（VLESS 应答头、目标解析、双向 relay 都对了）
#   2. 服务端日志确实记的是 Forwarded，而不是偷偷退化成直连
#   3. **未认证的探测者看到的是 dest 的真实证书** —— REALITY 抗探测的核心断言。
#      这一条如果错了，服务端就是一个「会主动暴露自己是代理」的端点。
#   4. 错误 UUID 必须连不上（认证真的在生效，而不是来者不拒）
#
# 每次运行都现场生成一套全新凭据（xray x25519 + uuid + shortId），
# 所以脚本不会依赖任何写死的密钥，也不会因为上一轮的残留状态而误判。
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

# 端口刻意与 e2e-test.sh 错开，两个脚本可以同时跑而不打架。
LPORT="${XT_TEST_SERVER_PORT:-9443}"
SPORT="${XT_TEST_SERVER_SOCKS:-1081}"
LISTEN="127.0.0.1:$LPORT"
SOCKS="127.0.0.1:$SPORT"
DEST="${XT_TEST_DEST:-www.cloudflare.com:443}"
DEST_HOST="${DEST%%:*}"
TARGET="${XT_TEST_TARGET:-example.com}"

fail() { printf '\n  ✗ %s\n' "$1" >&2; exit 1; }
pass() { printf '  ✓ %s\n' "$1"; }
srv_log() { cat "$XW_DIR/.e2e-srv-wasm.log" 2>/dev/null || true; }

[ -x "$XRAY" ] || fail "找不到 Xray 二进制：$XRAY"
[ -f "$WASM" ] || fail "找不到 wasm 产物：${WASM}（先 cargo build -p xt-wasm-cli --release --target wasm32-wasip2）"

SERVER_PID=''
CLIENT_PID=''
BAD_PID=''
cleanup() {
    for p in "$BAD_PID" "$CLIENT_PID" "$SERVER_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "==> 0/5 生成一套全新凭据"
KEYS=$("$XRAY" x25519)
PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^PrivateKey: *//p')
PBK=$(printf '%s\n' "$KEYS" | sed -n 's/^Password (PublicKey): *//p')
[ -n "$PRIV" ] && [ -n "$PBK" ] || { printf '%s\n' "$KEYS" >&2; fail "解析 xray x25519 输出失败"; }
UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
BAD_UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
SID=$(python3 -c 'import os;print(os.urandom(8).hex())')
# 注意 ${UUID} 的花括号：紧跟在变量名后面的全角「）」是多字节字符，
# 本机的 /bin/sh 会把它当成变量名的一部分 → unbound variable。
# e2e-test.sh 踩过同一个坑，这里不再踩第二次。
pass "privateKey/publicKey/shortId/uuid 已生成（uuid ${UUID}）"

echo "==> 1/5 启动 wasm 服务端（server 子命令 + 环境变量传 Secret）"
# 刻意用**环境变量**而不是命令行参数：这正是 k3s 的用法
# （Secret 注入 → env，避免密钥出现在 Pod 的 args 里）。
# 走 run-local.sh 而不是直接调 wasmtime：它带着 -C cache=n 等必要开关，
# 手写一份必然漂移。
XT_SERVER_LISTEN="$LISTEN" \
XT_PRIVATE_KEY="$PRIV" \
XT_SHORT_IDS="$SID" \
XT_SERVER_NAMES="$DEST_HOST" \
XT_DEST="$DEST" \
XT_USERS="$UUID" \
"$XW_DIR/scripts/run-local.sh" server \
    >"$XW_DIR/.e2e-srv-wasm.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! nc -z 127.0.0.1 "$LPORT" 2>/dev/null; then
    srv_log >&2
    fail "wasm 服务端没有监听 $LISTEN"
fi
grep -q "REALITY 入站" "$XW_DIR/.e2e-srv-wasm.log" || {
    srv_log >&2
    fail "服务端启动日志不像是服务端模式（XT_* 没传进 guest？检查 -S inherit-env=y）"
}
pass "服务端已监听 ${LISTEN}（pid ${SERVER_PID}）"

write_client_cfg() {
    # $1=文件 $2=uuid $3=socks 端口
    cat >"$1" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": $3, "protocol": "socks",
     "settings": {"auth": "noauth", "udp": false}}
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": $LPORT,
            "users": [{"id": "$2", "encryption": "none", "flow": ""}]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "serverName": "$DEST_HOST",
          "fingerprint": "chrome",
          "publicKey": "$PBK",
          "shortId": "$SID",
          "spiderX": ""
        }
      }
    }
  ]
}
EOF
}

echo "==> 2/5 stock Xray 客户端（flow 必须留空）→ 经隧道取页面"
CFG="$XW_DIR/.e2e-srv-client.json"
write_client_cfg "$CFG" "$UUID" "$SPORT"
"$XRAY" run -c "$CFG" >"$XW_DIR/.e2e-srv-client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
nc -z 127.0.0.1 "$SPORT" 2>/dev/null || {
    cat "$XW_DIR/.e2e-srv-client.log" >&2
    fail "stock 客户端没有监听 SOCKS $SOCKS"
}
# 这一步要出公网，会有偶发的瞬时抖动（本机实测遇到过一次：
# 服务端已经记下「认证通过 → example.com:443」，但 curl 侧没等到响应）。
# 所以允许重试，但**把重试次数打印出来** —— 悄悄重试会掩盖真实的间歇性故障，
# 那正是端到端测试最该抓的东西。
CODE=000
ATTEMPT=1
while [ "$ATTEMPT" -le 3 ]; do
    CODE=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' \
        --proxy "socks5h://$SOCKS" "https://$TARGET/" 2>/dev/null) || CODE=000
    [ "$CODE" = "200" ] && break
    printf '  … 第 %s 次失败（%s），重试\n' "$ATTEMPT" "$CODE"
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
done
if [ "$CODE" != "200" ]; then
    cat "$XW_DIR/.e2e-srv-client.log" >&2
    srv_log >&2
    fail "期望 HTTP 200，3 次尝试后仍是 $CODE"
fi
if [ "$ATTEMPT" -gt 1 ]; then
    pass "https://$TARGET -> 200（第 $ATTEMPT 次尝试成功，前几次是公网抖动）"
else
    pass "https://$TARGET -> 200"
fi

echo "==> 3/5 服务端确实做了转发（而不是退化成了直连）"
# 断言的是「认证通过」那一行，它在判定做出的**当下**就写出去了。
# 不要去等「结束：Forwarded ...」—— 那一行要等隧道关闭，测试会变成看运气。
grep -q "认证通过 user=$UUID -> $TARGET:443" "$XW_DIR/.e2e-srv-wasm.log" || {
    srv_log >&2
    fail "服务端日志里没有到 $TARGET:443 的转发记录"
}
pass "服务端日志：认证通过 user=$UUID -> $TARGET:443"

echo "==> 4/5 抗探测：未认证的 TLS 探测者必须看到 dest 的真实证书"
# 判别依据：真证书是 EC (prime256v1)，我们伪造的证书是 Ed25519。
# 只看 subject 是不够的 —— 伪造证书的 CN 也等于 serverName，那正是它该有的样子。
#
# 这里**不解析 openssl 的人类可读输出**。第一版图省事去 grep `a:PKEY: EC`，
# 本地（LibreSSL/macOS）通过、CI（OpenSSL 3/Ubuntu）直接红 —— 两边的格式不同：
#     macOS：  s:CN=www.cloudflare.com        a:PKEY: EC, (prime256v1)
#     Ubuntu： s:CN = www.cloudflare.com      a:PKEY: id-ecPublicKey, 256 (bit)
# 改成把证书取出来交给 `openssl x509` / `openssl pkey` 做**结构化**判定，
# 这两个子命令的输出格式跨平台稳定得多。
PROBE_CERT=$(echo | openssl s_client -connect "127.0.0.1:$LPORT" -servername "$DEST_HOST" 2>/dev/null \
    | openssl x509 2>/dev/null || true)
[ -n "$PROBE_CERT" ] || fail "探测者连证书都没拿到（回退路径没生效？）"

# -nameopt RFC2253 让 subject 输出成无空格的 `CN=www.example.com`，两端一致。
SUBJECT=$(printf '%s\n' "$PROBE_CERT" | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null || true)
printf '%s\n' "$SUBJECT" | grep -q "CN=$DEST_HOST" || {
    printf '  实际 subject：%s\n' "$SUBJECT" >&2
    fail "探测者没拿到 CN=$DEST_HOST 的证书"
}

# 公钥算法交给 openssl 判定，不看文本排版。
KEYINFO=$(printf '%s\n' "$PROBE_CERT" | openssl x509 -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -text -noout 2>/dev/null || true)
printf '%s\n' "$KEYINFO" | grep -qi "ED25519" && {
    printf '%s\n' "$KEYINFO" >&2
    fail "探测者拿到了我们伪造的 Ed25519 证书 —— 这就是可被主动探测的特征！"
}
printf '%s\n' "$KEYINFO" | grep -qi "prime256v1" || {
    printf '%s\n' "$KEYINFO" >&2
    fail "探测者拿到的证书不是 dest 的真实 EC (prime256v1) 证书"
}
# 服务端也必须把这条连接记成回退（而不是当成错误吞掉）——
# 探测流量在日志里看不见的话，运维根本无法判断自己有没有被扫。
sleep 0.5
grep -q "未认证" "$XW_DIR/.e2e-srv-wasm.log" || {
    srv_log >&2
    fail "探测连接没有被记成未认证/回退"
}
pass "探测者看到 dest 的真实证书（CN=$DEST_HOST, EC），伪造证书没有泄漏"

echo "==> 5/5 认证确实在生效：REALITY 过了但 UUID 不在名单里，必须被拒"
# 注意这一条与上一条测的**不是同一件事**：
#   * 上一条：REALITY 认证都没过 → 回退到 dest（探测者待遇）
#   * 这一条：REALITY 认证过了，但 UUID 不被允许 → 明确报错，**绝不能**当成合法用户转发。
# 客户端用的是正确的 publicKey/shortId，所以它会成功建立 REALITY 会话，
# 然后在 VLESS 这一层被挡下 —— 这正是「有密钥 ≠ 有权限」的分界。
BADCFG="$XW_DIR/.e2e-srv-bad.json"
write_client_cfg "$BADCFG" "$BAD_UUID" "$((SPORT + 1))"
"$XRAY" run -c "$BADCFG" >"$XW_DIR/.e2e-srv-bad.log" 2>&1 &
BAD_PID=$!
sleep 3
if curl -sS -m 15 -o /dev/null --proxy "socks5h://127.0.0.1:$((SPORT + 1))" \
        "https://$TARGET/" 2>/dev/null; then
    srv_log >&2
    fail "错误 UUID 竟然连通了 —— VLESS 用户名单没有生效！"
fi
sleep 0.5
grep -q "失败：proxy authentication failed" "$XW_DIR/.e2e-srv-wasm.log" || {
    srv_log >&2
    fail "错误 UUID 的连接没有被记成认证失败"
}
pass "错误 UUID 被拒（服务端日志：失败：proxy authentication failed）"

printf '\n  服务端端到端通过。\n'
