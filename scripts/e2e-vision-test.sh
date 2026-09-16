#!/bin/sh
# 端到端测试：**官方 Xray 客户端 + flow=xtls-rprx-vision** → 我们的 wasm 服务端 → 外网。
#
#     ./scripts/e2e-vision-test.sh
#
# 这是「服务端 XTLS-Vision 流控」的验收脚本（见 docs/vision-server-plan.md）。
#
# # 当前状态
#
# * flow="xtls-rprx-vision"：**通过** —— 官方客户端经本服务端取真实网页
#   拿到 HTTP 200，服务端日志 outcome=Forwarded。
# * flow=""（裸路径）与抗探测回退：**通过**（回归）。
#
# # 一个会误导人的坑（已修）
#
# `fetch_code` 的重试进度必须打到 **stderr**：调用方是
# `CODE=$(fetch_code ...)`，进度信息走 stdout 会被一起捕获，`$CODE` 就变成
# 「备注 + 200」，于是**明明拿到了 200 却报 ✗**。这一处曾让「协议没通」
# 的结论多挂了好几轮。
#
# 每次运行都现场生成一套全新凭据，不依赖任何写死的密钥。
set -u

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

XRAY_DIR="${XW_XRAY_DIR:-$XW_WS/.scratch/xray-server}"
XRAY="${XW_XRAY_BIN:-}"
if [ -z "$XRAY" ]; then
    for cand in "$XRAY_DIR/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$cand" ] && [ -x "$cand" ] && { XRAY="$cand"; break; }
    done
fi
WASM="$XW_WASM/xt-wasm-cli.wasm"

LPORT="${XT_TEST_VISION_PORT:-9543}"
SPORT="${XT_TEST_VISION_SOCKS:-1083}"
LISTEN="127.0.0.1:$LPORT"
DEST="${XT_TEST_DEST:-www.cloudflare.com:443}"
DEST_HOST="${DEST%%:*}"
TARGET="${XT_TEST_TARGET:-example.com}"

FAILED=0
fail() { printf '\n  ✗ %s\n' "$1" >&2; FAILED=$((FAILED + 1)); }
pass() { printf '  ✓ %s\n' "$1"; }
srv_log() { cat "$XW_DIR/.e2e-vision-srv.log" 2>/dev/null || true; }

[ -x "$XRAY" ] || { printf '找不到 Xray 二进制：%s\n' "$XRAY" >&2; exit 1; }
[ -f "$WASM" ] || { printf '找不到 wasm 产物：%s\n' "$WASM" >&2; exit 1; }

SERVER_PID=''
CLIENT_PID=''
cleanup() {
    for p in "$CLIENT_PID" "$SERVER_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

echo "==> 0/4 生成一套全新凭据"
KEYS=$("$XRAY" x25519)
PRIV=$(printf '%s\n' "$KEYS" | sed -n 's/^PrivateKey: *//p')
PBK=$(printf '%s\n' "$KEYS" | sed -n 's/^Password (PublicKey): *//p')
[ -n "$PRIV" ] && [ -n "$PBK" ] || { printf '%s\n' "$KEYS" >&2; fail "解析 xray x25519 输出失败"; exit 1; }
UUID=$(python3 -c 'import uuid;print(uuid.uuid4())')
SID=$(python3 -c 'import os;print(os.urandom(8).hex())')
pass "凭据已生成（uuid ${UUID}）"

echo "==> 1/4 启动 wasm 服务端"
XT_SERVER_LISTEN="$LISTEN" \
XT_PRIVATE_KEY="$PRIV" \
XT_SHORT_IDS="$SID" \
XT_SERVER_NAMES="$DEST_HOST" \
XT_DEST="$DEST" \
XT_USERS="$UUID" \
"$XW_DIR/scripts/run-local.sh" server \
    >"$XW_DIR/.e2e-vision-srv.log" 2>&1 &
SERVER_PID=$!
sleep 2
nc -z 127.0.0.1 "$LPORT" 2>/dev/null || { srv_log >&2; fail "wasm 服务端没有监听 $LISTEN"; exit 1; }
pass "服务端已监听 ${LISTEN}（pid ${SERVER_PID}）"

write_client_cfg() {
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
            "users": [{"id": "$2", "encryption": "none", "flow": "$4"}]
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

start_client() {
    "$XRAY" run -c "$1" >"$3" 2>&1 &
    CLIENT_PID=$!
    i=0
    while [ "$i" -lt 20 ]; do
        nc -z 127.0.0.1 "$2" 2>/dev/null && return 0
        i=$((i + 1))
        sleep 0.5
    done
    cat "$3" >&2
    fail "官方客户端没有监听 SOCKS 127.0.0.1:$2"
    return 1
}

fetch_code() {
    CODE=000
    ATTEMPT=1
    while [ "$ATTEMPT" -le 3 ]; do
        CODE=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' \
            --proxy "socks5h://127.0.0.1:$1" "https://$TARGET/" 2>/dev/null) || CODE=000
        [ "$CODE" = "200" ] && break
        # 必须打到 stderr：本函数是 `CODE=$(fetch_code ...)` 这样取值的，
        # 进度信息走 stdout 会被一起捕获，`$CODE` 就变成「备注 + 200」，
        # 断言随之失败 —— 症状是「明明拿到了 200 却报 ✗」。
        printf '  … 第 %s 次失败（%s），重试\n' "$ATTEMPT" "$CODE" >&2
        ATTEMPT=$((ATTEMPT + 1))
        sleep 1
    done
    printf '%s' "$CODE"
}

stop_client() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null
    wait "$CLIENT_PID" 2>/dev/null
    CLIENT_PID=''
    sleep 1
}

echo "==> 2/4 官方客户端 flow=xtls-rprx-vision → 期望 HTTP 200"
VCFG="$XW_DIR/.e2e-vision-client.json"
write_client_cfg "$VCFG" "$UUID" "$SPORT" "xtls-rprx-vision"
if start_client "$VCFG" "$SPORT" "$XW_DIR/.e2e-vision-client.log"; then
    CODE=$(fetch_code "$SPORT")
    if [ "$CODE" = "200" ]; then
        pass "https://$TARGET -> 200（flow=xtls-rprx-vision）"
    else
        cat "$XW_DIR/.e2e-vision-client.log" >&2
        srv_log >&2
        fail "flow=xtls-rprx-vision 期望 HTTP 200，实际 ${CODE}（回程组帧还没被官方客户端接受）"
    fi
fi
stop_client

echo "==> 3/4 回归：官方客户端 flow 留空 → 必须仍然 200"
ECFG="$XW_DIR/.e2e-vision-empty.json"
write_client_cfg "$ECFG" "$UUID" "$((SPORT + 1))" ""
if start_client "$ECFG" "$((SPORT + 1))" "$XW_DIR/.e2e-vision-empty.log"; then
    CODE=$(fetch_code "$((SPORT + 1))")
    if [ "$CODE" = "200" ]; then
        pass "https://$TARGET -> 200（flow 留空，裸路径未回归）"
    else
        cat "$XW_DIR/.e2e-vision-empty.log" >&2
        srv_log >&2
        fail "flow 留空时期望 HTTP 200，实际 ${CODE}（裸路径回归了）"
    fi
fi
stop_client

echo "==> 4/4 抗探测：未认证的 TLS 探测者必须看到 dest 的真实证书"
PROBE_CERT=$(echo | openssl s_client -connect "127.0.0.1:$LPORT" -servername "$DEST_HOST" 2>/dev/null \
    | openssl x509 2>/dev/null || true)
if [ -z "$PROBE_CERT" ]; then
    fail "探测者连证书都没拿到（回退路径没生效？）"
else
    SUBJECT=$(printf '%s\n' "$PROBE_CERT" | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null || true)
    KEYINFO=$(printf '%s\n' "$PROBE_CERT" | openssl x509 -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -text -noout 2>/dev/null || true)
    if ! printf '%s\n' "$SUBJECT" | grep -q "CN=$DEST_HOST"; then
        fail "探测者没拿到 CN=$DEST_HOST 的证书（实际：${SUBJECT}）"
    elif printf '%s\n' "$KEYINFO" | grep -qi "ED25519"; then
        fail "探测者拿到了我们伪造的 Ed25519 证书 —— 这就是可被主动探测的特征！"
    else
        pass "探测者看到 dest 的真实证书（CN=$DEST_HOST, EC）"
    fi
fi

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    printf '  Vision 服务端端到端全部通过。\n'
    exit 0
else
    printf '  %s 项未通过（见上面的 ✗）。\n' "$FAILED"
    printf '  已知：flow=xtls-rprx-vision 的回程组帧尚未被官方客户端接受，\n'
    printf '  详见 docs/vision-server-plan.md 的「当前状态」。\n'
    exit 1
fi
