#!/bin/sh
# 生成一套**一次性**的 REALITY 测试服务端配置（X25519 密钥 / UUID / shortId），
# 并把客户端参数写成可直接 source 的 env 文件。
#
#     ./scripts/gen-test-server.sh [输出目录]
#     . .test-server/params.env
#     XW_XRAY_DIR=.test-server ./scripts/e2e-test.sh
#
# # 为什么要有这个脚本
#
# e2e 测试原本把密钥硬编码在脚本里。那样有两个问题：
#   * 每次 CI 都复用同一对密钥，测试之间会互相干扰（服务端有 maxTimeDiff 之类的状态）；
#   * 发布出去的脚本里带着固定凭据，容易让人误以为是真实密钥。
# 改成每次现生成，两个问题都没有了。
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

OUT_DIR="${1:-$XW_DIR/.test-server}"
DEST="${XT_TEST_DEST:-www.cloudflare.com:443}"
PORT="${XT_TEST_PORT:-8443}"

# 找 xray 二进制：环境变量优先，其次本地 .scratch，最后 PATH。
XRAY="${XW_XRAY_BIN:-}"
if [ -z "$XRAY" ]; then
    for cand in "$XW_WS/.scratch/xray-server/xray" "$(command -v xray 2>/dev/null || true)"; do
        [ -n "$cand" ] && [ -x "$cand" ] && { XRAY="$cand"; break; }
    done
fi
[ -n "$XRAY" ] && [ -x "$XRAY" ] || {
    echo "找不到 xray 二进制。设置 XW_XRAY_BIN 指向它，或先跑一次 e2e 让脚本下载。" >&2
    exit 1
}

mkdir -p "$OUT_DIR"

# ── 生成凭据 ──
X25519_OUT="$("$XRAY" x25519)"
PRIV="$(printf '%s\n' "$X25519_OUT" | sed -n 's/^PrivateKey: //p' | head -n1)"
PUB="$(printf '%s\n' "$X25519_OUT" | sed -n 's/^Password (PublicKey): //p' | head -n1)"
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "xray x25519 输出无法解析：" >&2; printf '%s\n' "$X25519_OUT" >&2; exit 1; }

UUID="$("$XRAY" uuid)"
# shortId 用 openssl；没有就用 od 兜底。
if command -v openssl >/dev/null 2>&1; then
    SID="$(openssl rand -hex 8)"
else
    SID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
fi

DEST_HOST="${DEST%%:*}"
DEST_PORT="${DEST##*:}"

# ── 服务端配置 ──
# show:true 会打印 REALITY 认证的逐字段细节，是端到端验证的外部证据来源。
cat > "$OUT_DIR/server.json" <<EOF
{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": true,
          "dest": "$DEST",
          "xver": 0,
          "serverNames": ["$DEST_HOST"],
          "privateKey": "$PRIV",
          "shortIds": ["$SID"]
        }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF

# ── 客户端参数 ──
# 必须带 export：这份文件会被 source 后**在子进程**（e2e-test.sh）里使用。
# 不 export 的话子进程看不到，会静默回退到脚本里的默认旧密钥，
# 而症状是服务端认证失败后回退转发、报「leaf certificate is not Ed25519」，
# 极难从错误信息联想到「环境变量没导出」。
cat > "$OUT_DIR/params.env" <<EOF
# 由 scripts/gen-test-server.sh 生成于 $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# 一次性测试凭据，请勿用于任何真实部署。
export XT_TEST_UUID='$UUID'
export XT_TEST_PBK='$PUB'
export XT_TEST_SID='$SID'
export XT_TEST_SNI='$DEST_HOST'
export XT_TEST_SERVER='127.0.0.1:$PORT'
export XT_TEST_SOCKS='127.0.0.1:1080'
export XT_TEST_SOCKS_USER='testuser'
export XT_TEST_SOCKS_PASS='testpass'
export XT_TEST_HANDSHAKE_TIMEOUT='2'
EOF

chmod 600 "$OUT_DIR/server.json" "$OUT_DIR/params.env"

echo "已生成一次性测试服务端："
echo "  目录      $OUT_DIR"
echo "  伪装目标  $DEST_HOST:$DEST_PORT"
echo "  公钥      $PUB"
echo ""
echo "使用："
echo "  . $OUT_DIR/params.env"
echo "  XW_XRAY_DIR=$OUT_DIR ./scripts/e2e-test.sh"
