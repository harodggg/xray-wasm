#!/usr/bin/env python3
"""在 macOS 上测量「一个进程在给定场景下的 CPU 占用」——V24 的替代判据。

## 为什么需要它

`scripts/e2e-spin-test.sh` 的判据是读 Linux `/proc/<pid>/stat` 的 CPU ticks。
本机是 macOS：没有 `/proc`，沙箱又禁掉 `ps` / `top`。所以 V24 在这台机器上
**原本无法用原判据复现**（而「无法判定」正是这类 bug 反复失手的原因之一）。

本脚本用 **`os.wait4()` 的 rusage** 取代它：直接 spawn 被测进程，到点 SIGKILL，
`wait4` 返回内核给这个子进程记的 `ru_utime + ru_stime`。这是内核级数字，
不是 wall-clock 估算。已实测排除的两条路：

* `proc_pid_rusage()`（macOS 的 `/proc` 等价物）：对同一个忙进程只报 0.068s/3s，
  **不可信，未采用**；
* `/usr/bin/time -l` 包装：kill `time` 不会杀掉它 exec 的子进程，stderr 管道
  不关 → 挂死。**未采用**。

⚠️ **本机校准（必须看）**：一个 2.0s wall 的纯忙循环，`wait4` 只报 **1.09s（55%）**，
而 2.0s 的 sleep 报 0.04s（2%）。也就是说这台机器上「CPU%」的绝对值偏低，
判据必须用**相对比较**：同一条命令跑两遍，一遍不灌连接（idle）、一遍灌悬停连接
（hover），比 `hover / idle` 的比值 —— 而不是拿绝对 80% 当阈值。

⚠️ **启动开销会污染分母（实测后才发现的第二处坑）**：`wait4` 报的是进程**整个生命周期**的
CPU，而 wasm 服务端每次启动都要 JIT 编译（`-C cache=n`），这段常数开销会按窗口长度稀释。
所以现场脚本 `v24-field-test.sh` 用**两个窗口的差分**做判据：

    marginal = (cpu@W2 - cpu@W1) / (W2 - W1)

常数开销在两个窗口里相同、相减即消。真自旋 → marginal ≈ 100%；真空闲 → ≈ 0%。
单窗口的 `cpu%` 仍然打印，只作参考。

## 用法

    # 只测一个自带监听的探针（触发 = 灌 N 条悬停连接）
    ./scripts/v24-cpu-probe.py --port 12397 --conns 4 --seconds 6 \
        -- ./target/debug/examples/stream_spin_probe_rw 12397

    # 测完整现场（服务端 + 外部触发命令，例如官方客户端 + 悬停 CONNECT）
    ./scripts/v24-cpu-probe.py --port 8543 --seconds 10 \
        --out /tmp/srv.log --err /tmp/srv.err --trigger-out /tmp/trigger.log \
        --trigger-cmd "bash scripts/v24-field-test.sh trigger hover 300 10.255.255.1:5226" \
        -- "$WASMTIME_BIN" run -S tcp=y … xt-wasm-cli.wasm server

判据：`cpu% = (user+sys)/seconds * 100`。正常/空闲 → 个位数；V24 自旋 → 接近 100%。

⚠️ **绝对值只做参考，不要当阈值。** 另一半必须由调用方补：自旋（CPU 高）与
「整个实例死锁/卡住」（CPU 也是 0）在单侧指标上无法区分 —— V24 十九续就是被
这一点骗过一次。真实现场脚本 `scripts/v24-field-test.sh` 因此在每个场景里**同时**
做一次真实转发（`curl` 经隧道取页面），把「CPU 低」和「功能还在」一起断言。

退出码：0 = 测到结果；2 = 端口没起来；3 = /usr/bin/time 不可用或解析失败。
标准输出末行固定为 `CPU_SECONDS=<浮点>`，供脚本解析（`cpu%` 的分子）。
"""

import argparse
import os
import re
import shlex
import signal
import socket
import subprocess
import sys
import time

TIME_BIN = "/usr/bin/time"  # 仅用于存在性提示；实际测量走 os.wait4


def wait_port(port, timeout, pid=None):
    """等端口起来。`pid` 用来早失败：子进程若已退出就立刻返回 False。

    这里用 `os.waitpid(pid, WNOHANG)` 判活 —— 它**会回收**已退出的子进程，
    但那只发生在「我们本来就要放弃这次测量」的分支里（拿不到端口 = 拿不到数字），
    所以不影响后面的 `os.wait4`。
    """
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pid is not None:
            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return False
            if wpid != 0:
                return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def spawn_measured(cmd, out_path=None, err_path=None):
    """用 fork/exec 起被测进程 —— **不走 `subprocess`**，返回裸 pid。

    为什么不用`subprocess.Popen`：实测在这里踩到过一次
    `os.wait4(pid, 0)` 抛 `ChildProcessError`（子进程已被别处 wait 掉，拿不到
    rusage），而且是**间歇**发生。真因没有查到底（`subprocess._cleanup()` 只在
    Popen 被 `__del__` 时才接管，理论上不该发生在活引用上），但可以确定的是：
    **让被测进程完全不在 subprocess 的管理面里，这类风险就不存在**。
    rusage 是 V24 判据的唯一硬数字，这条路径必须最稳。
    """
    out_fd = os.open(out_path or os.devnull, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    err_fd = os.open(err_path or os.devnull, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    devnull = os.open(os.devnull, os.O_RDONLY)
    pid = os.fork()
    if pid == 0:  # 子进程
        try:
            os.setsid()                      # 新会话 → 可按进程组整组 SIGKILL
            os.dup2(devnull, 0)
            os.dup2(out_fd, 1)
            os.dup2(err_fd, 2)
            os.execvpe(cmd[0], cmd, os.environ)
        except BaseException:
            pass
        os._exit(127)
    os.close(out_fd)
    os.close(err_fd)
    os.close(devnull)
    return pid


def hover(port, conns, settle, quiet=False):
    """灌 N 条「连上」的连接。

    * quiet=False（默认）：连上后发 3 轮 15 字节（模拟握手期有数据到达）。
    * quiet=True：**连上后什么都不发、也不读** —— 这才是 V24 十一续在 Linux 上
      用的触发形状（"连上但不发数据、也不读"）。两者差别很大，不能混用：
      对 `stream_spin_probe`（读一次就结束）来说，发不发数据决定 read 有没有就绪过。
    """
    socks = []
    for _ in range(conns):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=2)
            s.settimeout(0.2)
            socks.append(s)
        except OSError:
            pass
    if quiet:
        return socks
    for _ in range(3):
        for s in socks:
            try:
                s.sendall(b"\x16\x03\x01\x00\x64")
            except OSError:
                pass
        time.sleep(settle)
    return socks


def parse_time_report(text):
    m = re.search(r"(\d+\.\d+)\s+real\s+(\d+\.\d+)\s+user\s+(\d+\.\d+)\s+sys", text)
    return tuple(float(g) for g in m.groups()) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True, help="被测进程监听的端口")
    ap.add_argument("--conns", type=int, default=0, help=">0 时灌这么多悬停连接")
    ap.add_argument("--hover-quiet", action="store_true",
                    help="悬停连接**一个字节都不发**（这才是 V24 十一续在 Linux 上的触发形状）。"
                         "默认会发 3 轮 15 字节 —— 两者含义不同，见 hover() 注释")
    ap.add_argument("--seconds", type=float, default=8.0, help="测量窗口（秒）")
    ap.add_argument("--settle", type=float, default=0.15)
    ap.add_argument("--trigger-cmd", default=None, help="端口起来后另起的外部触发命令")
    ap.add_argument("--trigger-out", default=None, help="触发命令的 stdout+stderr 落盘位置")
    ap.add_argument("--out", default=None, help="被测进程 stdout 落盘位置（默认丢弃）")
    ap.add_argument("--err", default=None, help="被测进程 stderr 落盘位置（默认丢弃）")
    ap.add_argument("--wait-port", type=float, default=12.0)
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- 之后的被测命令")
    args = ap.parse_args()

    cmd = [c for c in args.cmd if c != "--"]
    if not cmd:
        print("!! 缺少被测命令（放在 -- 之后）", file=sys.stderr)
        return 3
    if not os.access(TIME_BIN, os.X_OK):
        print(f"!! {TIME_BIN} 不可用", file=sys.stderr)
        return 3

    pid = spawn_measured(cmd, args.out, args.err)

    if not wait_port(args.port, args.wait_port, pid):
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except OSError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        print(f"!! 端口 {args.port} 一直没起来 —— 命令是不是没在监听？", file=sys.stderr)
        if args.out:
            print(f"!! 被测进程输出见 {args.out} / {args.err}", file=sys.stderr)
        return 2

    trigger = None
    if args.trigger_cmd:
        trig_out = open(args.trigger_out, "wb") if args.trigger_out else subprocess.DEVNULL
        # start_new_session + 后面 killpg：触发脚本几乎一定会自己起子进程
        # （官方 Xray 客户端、holding python），只 kill 顶层会把它们漏在后台，
        # 残留的客户端会占着 SOCKS 端口，下一次测量静默地连到上一轮的进程。
        trigger = subprocess.Popen(
            shlex.split(args.trigger_cmd),
            stdout=trig_out,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    socks = hover(args.port, args.conns, args.settle, quiet=args.hover_quiet) if args.conns else []

    time.sleep(args.seconds)

    # 杀整个进程组（被测命令可能自己 fork），再用 wait4 拿它的 rusage
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except OSError as e:
        print(f"!! killpg 失败（{e}），退化为 kill(pid)", file=sys.stderr)
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        _, status, ru = os.wait4(pid, 0)
    except ChildProcessError:
        # 没有 rusage 就**不会**有数字，绝不能瞎编一个 0 出来（这正是 V24 判据
        # 最怕的「看起来有数字」）。明确报错，让调用方重建测量。
        print(f"!! 被测子进程 pid={pid} 已被别处 wait 掉（ChildProcessError）；"
              f"本次无 rusage，拒绝输出数字。", file=sys.stderr)
        return 4
    if trigger is not None:
        try:
            os.killpg(os.getpgid(trigger.pid), signal.SIGKILL)
        except OSError:
            trigger.kill()
        try:
            trigger.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    for s in socks:
        try:
            s.close()
        except OSError:
            pass

    cpu = ru.ru_utime + ru.ru_stime
    pct = cpu / args.seconds * 100.0
    print(f"  被测命令 : {' '.join(cmd[:3])}{' …' if len(cmd) > 3 else ''}")
    print(f"  窗口     : {args.seconds:g}s（悬停连接 {args.conns} 条{', 静默' if args.hover_quiet else ''}）")
    print(f"  user/sys = {ru.ru_utime:.3f} / {ru.ru_stime:.3f}")
    print(f"  cpu = {cpu:.3f}s   cpu% = {pct:.1f}%（本机绝对值偏低，见文件头校准说明）")
    if pct >= 80:
        print("  ⇒ 绝对 cpu% 偏高（仅供参考：本机绝对值偏低，必须与 idle 比）")
    elif pct <= 15:
        print("  ⇒ 绝对值低（⚠️ 单侧判据：CPU 低也可能是整个实例卡死，需配功能断言）")
    else:
        print("  ⇒ 中间态，需人工判断")
    # 机器可读：脚本用 (cpu@W2 - cpu@W1)/(W2-W1) 消掉启动/JIT 的常数开销。
    print(f"CPU_SECONDS={cpu:.6f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
