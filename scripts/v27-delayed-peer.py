#!/usr/bin/env python3
"""V27 最小复现对端：裸 TCP，**accept 之后先静默 delay 秒，再回包**。

为什么需要它
------------
V27 的现象是「wasm 客户端 → **刚启动**的官方 Xray 服务端，首次 REALITY 握手
卡在读 5 字节 TLS 记录头上（10s 超时）」；同一个服务端**预热后** 8/8 通过。
两种情形唯一的差别是**第一份字节回到客户端的时间**：

* 冷启动：官方服务端要先连 dest 取证书，飞行包晚 ~1.5s 才来 ⇒ 客户端必须
  先挂起、再被**唤醒**；
* 预热：飞行包几乎立刻可读 ⇒ 客户端第一次 `poll_read` 就拿到数据，**不需要唤醒**。

本脚本把「晚一点回包」这件事从官方 Xray 里剥出来，只留一个裸 TCP 对端：
accept → 读掉 ClientHello（可选）→ sleep `--delay` → 发一个**合法形状的
TLS record 头**。如果这样也能让握手卡到 10s 超时，那么 V27 就与「官方服务端
冷启动慢」解耦，根因锁定在客户端的**唤醒/就绪**路径上。

判据（两种失败必须区分）
------------------------
* **卡住**：客户端报 `REALITY 握手失败：… did not complete within 10s`
  —— 说明 5 字节头 **一个都没读到**，唤醒丢了。
* **不卡**：客户端在 delay 之后**立刻**读到头并报协议层错误
  （默认 `--mode header0` 会报 `unexpected plaintext handshake`；
  `--mode bogus-serverhello` 会走得更远，报 `invalid ServerHello`）
  —— 说明唤醒正常，只是我们回的不是真 ServerHello。

本脚本**不关连接**（`--hold` 秒内保持打开）：如果 accept 后立刻 close，
客户端会收到 FIN，pollable 同样会变就绪，那会把「唤醒失败」洗成
「读到 EOF」，判据就废了。

用法
----
    # 冷（复现）：1.5s 后才回包
    python3 scripts/v27-delayed-peer.py --port 18443 --delay 1.5

    # 热（对照）：立刻回包，同一份脚本、同一份 wasm
    python3 scripts/v27-delayed-peer.py --port 18443 --delay 0

    # 只回 5 字节头、分两次发（测部分读的重注册）
    python3 scripts/v27-delayed-peer.py --port 18443 --delay 1.5 --mode split-header

脚本打印带单调时钟的时间线，便于把「对端何时发包」和「客户端何时报错」
对齐；`--accept N` 可以连收 N 条连接（同一进程内先冷后热）。
"""

import argparse
import socket
import sys
import threading
import time

TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_VERSION = b"\x03\x03"


def log(msg: str) -> None:
    print(f"[peer {time.strftime('%H:%M:%S')} t+{time.monotonic() - T0:8.3f}] {msg}",
          flush=True)


T0 = time.monotonic()


def read_hello(conn: socket.socket, window: float) -> int:
    """把客户端先写过来的 ClientHello 读掉。

    只读到窗口结束为止：我们**不解析**它，也不依赖它 —— 这一步纯粹是让日志
    能证明「客户端确实写了 ClientHello」（即卡点在读、不在写）。
    """
    total = 0
    deadline = time.monotonic() + window
    conn.settimeout(0.05)
    while time.monotonic() < deadline:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            continue
        except OSError as e:
            log(f"recv 出错：{e}")
            break
        if not chunk:
            log(f"客户端在读完前就半关了（累计 {total} 字节）")
            break
        total += len(chunk)
        if total >= 5:
            # TLS record 头里的 length 字段在 offset 3..5（大端）。
            # 多等一会把整条记录收全，仅为了让日志更可信。
            if total >= 5:
                deadline = min(deadline, time.monotonic() + 0.15)
    return total


def send_record(conn: socket.socket, mode: str, delay: float) -> None:
    t0 = time.monotonic()
    if mode == "header0":
        # 合法 TLS 记录头：type=handshake(0x16) version=0x0303 length=0
        payload = bytes([TLS_RECORD_HANDSHAKE]) + TLS_RECORD_VERSION + b"\x00\x00"
        log(f"回包 mode=header0 len={len(payload)}：{payload.hex()}")
        conn.sendall(payload)
    elif mode == "bogus-serverhello":
        # 合法头 + 「长度自称 1」的 ServerHello 体（HS type=0x02）。
        # 客户端会通过 record 层校验，然后在 parse_server_hello 里失败 ——
        # 比 header0 多证明一步：它真的把 5 字节头解析成了记录。
        body = b"\x02\x00\x00\x01\x00"
        payload = (bytes([TLS_RECORD_HANDSHAKE]) + TLS_RECORD_VERSION
                   + len(body).to_bytes(2, "big") + body)
        log(f"回包 mode=bogus-serverhello len={len(payload)}：{payload.hex()}")
        conn.sendall(payload)
    elif mode == "split-header":
        # 先 2 字节、睡 0.3s、再 3 字节：测试「部分读之后重新注册」是否也有效。
        head = bytes([TLS_RECORD_HANDSHAKE]) + TLS_RECORD_VERSION + b"\x00\x00"
        log(f"回包 mode=split-header 第一段 2 字节：{head[:2].hex()}")
        conn.sendall(head[:2])
        time.sleep(0.3)
        log(f"回包 mode=split-header 第二段 3 字节：{head[2:].hex()}")
        conn.sendall(head[2:])
    else:
        raise SystemExit(f"未知 mode: {mode}")
    log(f"对端发完，用时 {time.monotonic() - t0:.3f}s（delay 参数 {delay}s）")


def serve_capture(conn: socket.socket, addr, args, index: int) -> None:
    """把客户端发来的第一段字节存盘（供 replay 模式使用）。"""
    conn.settimeout(0.5)
    buf = b""
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
    open(args.hello_file, "wb").write(buf)
    log(f"#{index} 抓到 {len(buf)} 字节 → {args.hello_file}")
    conn.close()


def pump(src: socket.socket, dst: socket.socket, label: str, index: int,
         save_path: str = "") -> None:
    """单向转发并记录字节数/时间线（用于 forward 模式）。"""
    total = 0
    t0 = time.monotonic()
    first_logged = False
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                log(f"#{index} {label} EOF，累计 {total} 字节")
                break
            total += len(chunk)
            if not first_logged:
                first_logged = True
                log(f"#{index} {label} 首批 {len(chunk)} 字节 "
                    f"（accept 后 {time.monotonic() - t0:.3f}s）hex={chunk[:12].hex()}")
                if label == "c2s" and save_path:
                    with open(save_path, "wb") as f:
                        f.write(chunk)
            dst.sendall(chunk)
    except OSError as e:
        log(f"#{index} {label} 结束：{e}，累计 {total} 字节")
    finally:
        log(f"#{index} {label} 总计 {total} 字节，持续 {time.monotonic() - t0:.3f}s")
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def serve_forward(conn: socket.socket, addr, args, index: int) -> None:
    """透明代理：把客户端连到 `--upstream`，双向记录字节。

    用途是**切开 client / server 两侧**：如果本代理看到 s2c 有 N 字节而客户端
    仍然卡在读，那卡点就在客户端的 socket/唤醒这一侧；如果 s2c 一个字节都没有，
    那「卡住」根本不在客户端 —— 是服务端没写。
    """
    host, _, port = args.upstream.rpartition(":")
    up = socket.create_connection((host, int(port)), timeout=args.hold)
    # 连上之后**必须去掉读超时**：透明代理不该给「对端合法地沉默很久」判死。
    # （踩过：`--hold` 默认 5s 会让真实服务端 6.2s 才回的飞行包被当成超时，
    # 代理主动关连接，客户端看到的是 EOF 而不是握手超时，判据整个失真。）
    up.settimeout(None)
    log(f"#{index} 已连上游 {args.upstream}")
    t1 = threading.Thread(target=pump, args=(conn, up, "c2s", index, args.save_c2s),
                          daemon=True)
    t2 = threading.Thread(target=pump, args=(up, conn, "s2c", index), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    up.close()
    conn.close()
    log(f"#{index} 连接关闭")


def serve_one(conn: socket.socket, addr, args, index: int) -> None:
    log(f"#{index} accept 来自 {addr[0]}:{addr[1]}")
    if index <= args.stall_first:
        # 卡死前 N 条：读掉 ClientHello 后**不回包、不转发**，让客户端的握手死线到点。
        # 用来造「第一条卡死、后续正常」的瞬态现场（重试的验收正样本）。
        n = read_hello(conn, args.read_window)
        log(f"#{index} 卡死（stall-first）：收到 {n} 字节后静默 {args.stall_hold}s，不回包")
        time.sleep(args.stall_hold)
        conn.close()
        log(f"#{index} 卡死连接关闭（客户端此时应当已经超时）")
        return
    if index - 1 < args.pre_reject:
        # 前 N 条连接立刻关闭（RST）：用来检验「前序连接留下的状态污染」。
        log(f"#{index} 前序连接 → 立刻 RST（pre-reject）")
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            b"\x01\x00\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        conn.close()
        return
    if args.mode == "forward":
        serve_forward(conn, addr, args, index)
        return
    if args.mode == "capture":
        serve_capture(conn, addr, args, index)
        return
    if args.mode == "reject":
        # 立刻关闭：模拟「前序连接」污染。
        log(f"#{index} 立刻关闭（reject）")
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            b"\x01\x00\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        conn.close()
        return
    t_accept = time.monotonic()
    hello = read_hello(conn, args.read_window)
    log(f"#{index} 收到客户端首包 {hello} 字节，"
        f"距 accept {time.monotonic() - t_accept:.3f}s")
    if args.delay > 0:
        log(f"#{index} 静默等待 {args.delay}s（模拟冷启动服务端取证书的飞行时间）")
        time.sleep(args.delay)
    send_record(conn, args.mode, args.delay)
    # 保持连接：见文件头「本脚本不关连接」。
    log(f"#{index} 保持连接到 {args.hold}s 后关闭")
    time.sleep(args.hold)
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    conn.close()
    log(f"#{index} 连接关闭")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0,
                    help="监听端口（replay 模式不需要，改为直接连 --upstream）")
    ap.add_argument("--delay", type=float, default=1.5,
                    help="accept 之后静默多少秒再回包（0 = 热对照）")
    ap.add_argument("--mode", default="header0",
                    choices=["header0", "bogus-serverhello", "split-header", "forward",
                             "capture", "replay", "reject"])
    ap.add_argument("--upstream", default="",
                    help="forward 模式的上游 host:port（例如 127.0.0.1:8443）")
    ap.add_argument("--save-c2s", default="",
                    help="forward 模式下把客户端首批字节另存一份（供 replay 用）")
    ap.add_argument("--hello-file", default="/tmp/v27a/clienthello.bin",
                    help="capture/replay 模式的 ClientHello 文件")
    ap.add_argument("--accept", type=int, default=1, help="总共接受多少条连接后退出")
    ap.add_argument("--pre-reject", type=int, default=0,
                    help="最前面的 N 条连接立刻 RST 关闭（测状态污染）")
    ap.add_argument("--stall-first", type=int, default=0,
                    help="最前面的 N 条连接卡死（读掉 ClientHello 后不回包、不转发）")
    ap.add_argument("--stall-hold", type=float, default=30.0,
                    help="卡死连接保持不回包的秒数（要 > 客户端握手死线）")
    ap.add_argument("--hold", type=float, default=5.0,
                    help="回包后保持连接打开的秒数（0 会立刻发 FIN，勿用）")
    ap.add_argument("--read-window", type=float, default=0.3,
                    help="读 ClientHello 的最长窗口（秒）")
    ap.add_argument("--serial", action="store_true",
                    help="串行处理（默认每连接一个线程）")
    args = ap.parse_args()
    if args.mode == "forward" and not args.upstream:
        raise SystemExit("forward 模式必须给 --upstream host:port")

    if args.mode == "replay":
        # replay 模式就是「合成客户端」：直接连 --upstream，把抓下来的
        # ClientHello 发过去，测「第一份响应字节」的延迟。不监听任何端口。
        if not args.upstream:
            raise SystemExit("replay 模式必须给 --upstream host:port")
        host, _, port = args.upstream.rpartition(":")
        sock = socket.create_connection((host, int(port)), timeout=5)
        hello = open(args.hello_file, "rb").read()
        t0 = time.monotonic()
        sock.sendall(hello)
        log(f"已向 {args.upstream} 发回放 ClientHello {len(hello)} 字节")
        sock.settimeout(args.hold)
        try:
            first = sock.recv(65536)
        except socket.timeout:
            log(f"✗ 等待首个响应字节超时（{args.hold}s）: ClientHello→首字节 > {args.hold}s")
            sock.close()
            return 3
        dt = time.monotonic() - t0
        log(f"★ ClientHello→首字节 = {dt:.3f}s，首批 {len(first)} 字节 "
            f"hex={first[:12].hex()}")
        sock.close()
        return 0

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(16)
    log(f"监听 {args.host}:{args.port}  delay={args.delay}s mode={args.mode} "
        f"accept={args.accept} hold={args.hold}s")

    threads = []
    for i in range(1, args.accept + 1):
        conn, addr = srv.accept()
        if args.serial:
            serve_one(conn, addr, args, i)
        else:
            t = threading.Thread(target=serve_one, args=(conn, addr, args, i),
                                 daemon=True)
            t.start()
            threads.append(t)
    for t in threads:
        t.join()
    srv.close()
    log("退出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
