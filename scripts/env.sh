#!/bin/sh
# 统一的构建/运行环境。用法（**在仓库内**执行）：
#
#     cd xray-wasm && . scripts/env.sh
#
# 放成一个可 source 的脚本，是因为这里有三个「不说清楚就一定会踩」的坑。

# 坑 0：被 source 的脚本里 $0 是**调用它的那个 shell**，不是脚本自己。
#       所以 `dirname "$0"` 会算出完全错误的位置（我第一次就把根目录算成了 $HOME）。
#       优先用 BASH_SOURCE；拿不到就退化成「从当前目录向上找仓库根」。
_xw_self_dir() {
    if [ -n "${BASH_SOURCE:-}" ]; then
        (cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
        return 0
    fi
    _d="$(pwd)"
    while [ "$_d" != "/" ]; do
        if [ -f "$_d/rust-toolchain.toml" ] && [ -f "$_d/scripts/env.sh" ]; then
            printf '%s/scripts' "$_d"
            return 0
        fi
        _d="$(dirname "$_d")"
    done
    return 1
}

XW_ROOT="$(cd "$(_xw_self_dir)/.." && pwd)" || {
    echo "env.sh: 请在 xray-wasm 目录内 source 本脚本" >&2
    return 1 2>/dev/null || exit 1
}
XW_WS="$(cd "$XW_ROOT/.." && pwd)"

# 坑 1：依赖缓存默认写 ~/.cargo，而受限环境下 ~ 不可写（表现为
#       "Operation not permitted" 或莫名其妙的 "No such file or directory"）。
#       放工作区里，与 xray-tun 的做法一致。这里**无条件覆盖**，
#       因为继承来的 CARGO_HOME 往往正指向那个不可写的位置。
export CARGO_HOME="$XW_WS/.cargo"
export CARGO_TARGET_DIR="$XW_WS/.cargo-target"

# 坑 2：系统里同时有 Homebrew 的 rustc(/usr/local/bin) 和 rustup 的 shim(~/.cargo/bin)，
#       而 Homebrew 在 PATH 里更靠前。那样 rust-toolchain.toml 会被完全忽略，
#       还会用 Homebrew 的 rustc 去编 wasm，报错是「can't find crate for core」，看不出真正原因。
#       必须把 rustup shim 移到**最前面**（只判断「存在」是不够的）。
_xw_path_strip() {
    _out=""
    _old_ifs="$IFS"; IFS=:
    for _p in $PATH; do
        if [ "$_p" != "$HOME/.cargo/bin" ]; then
            _out="${_out}${_out:+:}${_p}"
        fi
    done
    IFS="$_old_ifs"
    printf '%s' "$_out"
}
PATH="$HOME/.cargo/bin:$(_xw_path_strip)"
export PATH

# 坑 3：wasmtime 默认把 JIT 缓存写 ~/Library/Caches，受限环境下会直接报错退出。
export WASMTIME_CACHE_DIR="$XW_ROOT/.wasmtime-cache"
mkdir -p "$WASMTIME_CACHE_DIR" 2>/dev/null || true

# wasmtime 二进制：优先工作区内下载好的，其次 PATH 里的。
if [ -z "${WASMTIME_BIN:-}" ]; then
    if [ -x "$XW_WS/.scratch/wasmtime/wasmtime-v48.0.2-aarch64-macos/wasmtime" ]; then
        WASMTIME_BIN="$XW_WS/.scratch/wasmtime/wasmtime-v48.0.2-aarch64-macos/wasmtime"
    else
        WASMTIME_BIN="$(command -v wasmtime 2>/dev/null || true)"
    fi
fi
export WASMTIME_BIN

# 跑 wasm 必须带的 flag。缺 tcp=y 或 inherit-network=y 的失败信息很不直观
# （后者表现为 error 2 = PermissionDenied，看起来像被墙）。
XW_WASMTIME_ARGS="-S tcp=y -S inherit-network=y -S allow-ip-name-lookup=y"
export XW_WASMTIME_ARGS

export XW_ROOT XW_WS
export XW_WASM="$CARGO_TARGET_DIR/wasm32-wasip2/release"

xw_info() {
    printf '  rustc        %s\n' "$(rustc --version 2>/dev/null || echo '缺失')"
    printf '  cargo        %s\n' "$(cargo --version 2>/dev/null || echo '缺失')"
    printf '  CARGO_HOME   %s\n' "$CARGO_HOME"
    printf '  wasmtime     %s\n' "${WASMTIME_BIN:-未找到}"
    printf '  wasm 产物目录 %s\n' "$XW_WASM"
}
