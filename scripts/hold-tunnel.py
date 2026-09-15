#!/usr/bin/env python3
"""完成 SOCKS5 协商（含 RFC 1929 认证）并保持连接打开一段时间。

用来验证代理的**并发**能力：这个脚本占住一条长连接时，
另一条请求必须仍能被正常服务。旧实现是顺序 accept，会被它独占。

用法：
    hold-tunnel.py <代理host> <代理port> <用户> <密码> \
                   <目标host> <目标port> <保持秒数>

握手成功即向 stdout 打印 "HELD"，便于调用方同步。
"""

import socket
import sys
import time


def fail(msg):
    print(f"HOLD_FAIL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            fail(f"对端提前关闭（已收到 {len(buf)}/{n} 字节）")
        buf += chunk
    return buf


def main():
    if len(sys.argv) != 8:
        fail("参数个数不对，见文件头用法")
    proxy_host, proxy_port = sys.argv[1], int(sys.argv[2])
    user, password = sys.argv[3].encode(), sys.argv[4].encode()
    target_host, target_port = sys.argv[5], int(sys.argv[6])
    hold_secs = float(sys.argv[7])

    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=10)
    except OSError as e:
        fail(f"连接代理失败：{e}")

    # ── 方法协商：只声明支持用户名/密码（0x02）──
    s.sendall(b"\x05\x01\x02")
    if recv_exact(s, 2) != b"\x05\x02":
        fail("代理没有选择用户名/密码认证")

    # ── RFC 1929 ──
    s.sendall(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
    if recv_exact(s, 2) != b"\x01\x00":
        fail("认证失败")

    # ── CONNECT（域名形式，SOCKS5 的 ATYP=0x03）──
    th = target_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(th)]) + th + target_port.to_bytes(2, "big"))
    resp = recv_exact(s, 4)
    if resp[0] != 5 or resp[1] != 0:
        fail(f"CONNECT 被拒，应答码 {resp[1]}")

    # 立刻告诉调用方「已经占住了」
    print("HELD", flush=True)

    # 保持打开，并且**不发任何数据** —— 这正是旧实现会被独占的场景。
    time.sleep(hold_secs)
    s.close()
    print("RELEASED", flush=True)


if __name__ == "__main__":
    main()
