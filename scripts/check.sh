#!/bin/sh
# 本地跑一遍 CI 跑的全部检查。
#
# # 为什么需要它
#
# 写 REALITY 服务端阶段 2 时，我先跑了 `cargo fmt --all`，**之后**又新建了一个
# example 文件就提交了 —— 结果 CI 的 `cargo fmt --check` 直接红，而本地那 7 项
# 我心里「刚跑过」。问题不在「忘了」，而在**本地检查的顺序与内容全靠记忆**：
# 只要步骤是手打的，就一定会有某次顺序反了、或者漏一项。
#
# 所以这里把 CI 的每一步固化成同一条命令，`ci.yml` 也直接调用它 ——
# 两边不可能再漂移。
#
#     ./scripts/check.sh
set -eu

XW_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$XW_DIR"
. scripts/env.sh

fail() { printf '\n  ✗ %s\n' "$1" >&2; exit 1; }
ok() { printf '  ✓ %s\n' "$1"; }

echo "==> 1/7 格式检查（含 examples，容易漏）"
cargo fmt --all -- --check || fail "格式不符合 rustfmt（跑 cargo fmt --all）"
ok "fmt"

echo "==> 2/7 Clippy（warnings 视为错误）"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy 有告警"
ok "clippy"

echo "==> 3/7 单元测试"
cargo test --workspace || fail "单元测试失败"
ok "tests"

echo "==> 4/7 构建 wasm32-wasip2"
cargo build -p xt-wasm-cli --release --target wasm32-wasip2 || fail "wasm 构建失败"
ok "wasm"

echo "==> 5/7 构建 examples（CI 会构建它们，别只在本地跑 bin）"
cargo build -p xt-wasm-tls --release --example reality_server_probe || fail "example 构建失败"
ok "examples"

echo "==> 6/7 依赖树约束（不得引入 C++/mio）"
# BoringSSL 是 C++、mio 依赖 epoll/kqueue —— 两者在 wasm 上都不可能工作。
if cargo tree -p xt-wasm-cli --target wasm32-wasip2 2>/dev/null \
   | grep -iE 'boring|mio|parking_lot|socket2|openssl'; then
    fail "wasm 依赖树里出现了不该有的 C++/运行时依赖"
fi
ok "依赖树干净"

echo "==> 7/7 生产代码不得引用 tokio runtime"
# tokio 的 net/time/rt 等在 wasm 上是 compile_error! 或不可用。
# 必须排除**注释行**：文档里为了解释「为什么不能用 tokio::net」会提到它。
hits=$(grep -rnE 'tokio::(net|time|spawn|runtime|fs|process|signal)' crates/*/src/ \
       | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)
if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    fail "生产代码里出现了 tokio runtime 调用"
fi
ok "无 tokio runtime 调用"

printf '\n  CI 的全部检查都通过了。\n'
