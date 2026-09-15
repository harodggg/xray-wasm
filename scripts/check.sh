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

echo "==> 1/9 格式检查（含 examples，容易漏）"
cargo fmt --all -- --check || fail "格式不符合 rustfmt（跑 cargo fmt --all）"
ok "fmt"

echo "==> 2/9 Clippy（warnings 视为错误）"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy 有告警"
ok "clippy"

echo "==> 3/9 单元测试"
cargo test --workspace || fail "单元测试失败"
ok "tests"

echo "==> 4/9 构建 wasm32-wasip2"
cargo build -p xt-wasm-cli --release --target wasm32-wasip2 || fail "wasm 构建失败"
ok "wasm"

echo "==> 5/9 构建 examples（CI 会构建它们，别只在本地跑 bin）"
cargo build -p xt-wasm-tls --release --example reality_server_probe || fail "example 构建失败"
ok "examples"

echo "==> 6/9 依赖树约束（不得引入 C++/mio）"
# BoringSSL 是 C++、mio 依赖 epoll/kqueue —— 两者在 wasm 上都不可能工作。
if cargo tree -p xt-wasm-cli --target wasm32-wasip2 2>/dev/null \
   | grep -iE 'boring|mio|parking_lot|socket2|openssl'; then
    fail "wasm 依赖树里出现了不该有的 C++/运行时依赖"
fi
ok "依赖树干净"

echo "==> 7/9 生产代码不得引用 tokio runtime"
# tokio 的 net/time/rt 等在 wasm 上是 compile_error! 或不可用。
# 必须排除**注释行**：文档里为了解释「为什么不能用 tokio::net」会提到它。
hits=$(grep -rnE 'tokio::(net|time|spawn|runtime|fs|process|signal)' crates/*/src/ \
       | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)
if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    fail "生产代码里出现了 tokio runtime 调用"
fi
ok "无 tokio runtime 调用"

echo "==> 8/9 shell 脚本里不得有无花括号变量紧跟全角字符"
# `"…（uuid $UUID）"` 里的全角「）」是多字节字符，/bin/sh 会把它当成变量名的
# 一部分 → `UUID）: unbound variable`。这个坑在本仓库踩过两次
# （e2e-test.sh 一次、e2e-server-test.sh 一次），所以固化成检查项：
# 变量后面只要跟非 ASCII 字符，就必须写成 ${VAR}。
#
# 必须排除**注释行**：解释这个坑本身就要在注释里写出反例
# （`"…（uuid $UUID）"`），否则检查会被自己的文档绊倒 ——
# 与第 7 项排除注释是同一个教训。
bad=$(grep -rnE '\$[A-Za-z_][A-Za-z0-9_]*[^ -~]' scripts/*.sh \
      | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)
if [ -n "$bad" ]; then
    printf '%s\n' "$bad"
    fail "变量名后面紧跟全角字符，请写 \${VAR}"
fi
ok "变量引用无多字节歧义"

echo "==> 9/9 k8s 清单里的 XT_* 变量必须真的被代码读取"
# 这一项防的是一类**静默**故障：清单里写 `XT_PRIVATEKEYS`（少个下划线），
# 代码读的是 `XT_PRIVATE_KEY`。结果是 Secret 挂上了、Pod 起来了、
# 服务端起不来（或更糟：起得来但用了默认值），而 kubectl 一切正常。
# YAML 语法检查抓不到它，只有把清单和源码对起来看才行。
#
# 反向不检查：源码里合法的变量不必都出现在清单里（很多是可选的）。
known=$(grep -rhoE 'XT_[A-Z0-9_]+' crates/*/src/ | sort -u)
used=$(grep -rhoE 'XT_[A-Z0-9_]+' deploy/k8s/*.yaml | sort -u)
missing=$(printf '%s\n' "$used" | while read -r v; do
    [ -n "$v" ] || continue
    printf '%s\n' "$known" | grep -qx "$v" || printf '%s\n' "$v"
done)
if [ -n "$missing" ]; then
    printf '  清单里出现但代码从不读取的变量（多半是拼错了）：\n' >&2
    printf '%s\n' "$missing" | sed 's/^/    /' >&2
    fail "k8s 清单与源码的 XT_* 变量名不一致"
fi
ok "清单变量名与源码一致（$(printf '%s\n' "$used" | wc -l | tr -d ' ') 个）"

printf '\n  CI 的全部检查都通过了。\n'
