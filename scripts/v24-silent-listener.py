#!/usr/bin/env python3
"""V24 A/B 实验用：一个「接受连接但永不回话」的本地 TCP 监听器。

用途：把 `V24_HOVER_TARGET` 从黑洞地址（10.255.255.1:5226，connect 会长期挂起）
换成这个监听器（connect 立刻成功、然后**读等待**），用来区分 V24 的空转到底挂在
「connect 挂起路径」还是「已建立但空闲的连接」上。

    python3 scripts/v24-silent-listener.py 127.0.0.1:5226

行为：
* `listen(backlog)` + 循环 `accept()`，把连接**留着不放**（不读、不写、不关）；
* 每 2 秒向 stderr 打一行已接受数量（stdout 保持干净，方便 `$(...)` 取用）；
* 收到 SIGTERM/SIGINT 时关闭全部连接并退出。
"""

import signal
import socket
import sys
import time

held: list[socket.socket] = []
running = True


def stop(*_args: object) -> None:
    global running
    running = False


def main() -> int:
    if len(sys.argv) != 2 or ":" not in sys.argv[1]:
        print(f"用法：{sys.argv[0]} <ip:port>", file=sys.stderr)
        return 2
    host, _, port_s = sys.argv[1].rpartition(":")
    port = int(port_s)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1024)
    srv.settimeout(0.5)
    print(f"silent listener 就绪 {host}:{port}", file=sys.stderr)

    last_report = time.monotonic()
    while running:
        try:
            conn, peer = srv.accept()
        except socket.timeout:
            conn = None
        if conn is not None:
            conn.settimeout(None)
            held.append(conn)
            # 明确不做任何读写：对端会停在「等数据」。
        if time.monotonic() - last_report >= 2.0:
            print(f"accepted={len(held)}", file=sys.stderr)
            last_report = time.monotonic()

    for c in held:
        try:
            c.close()
        except OSError:
            pass
    srv.close()
    print(f"退出，累计 accepted={len(held)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
