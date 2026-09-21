//! 最小 wasm 探针（`wasm32-wasip2`）：**对端关闭后**，比较
//! `wasi:io/poll::poll()` 与 `pollable.ready()` 对同一个读 pollable 的判定。
//!
//! 用途（V24/V29 的最后一个缺口）：裁定「宿主 `poll()` 报就绪、而 `ready()` 报不就绪」
//! 这个分歧是**上游语义**（wasmtime / WASI 绑定）还是**我们自己的封装**。
//! 探针只碰 `wasi:sockets` 与 `wasi:io`，不经过本仓库的任何封装。
//!
//! 跑法：
//!
//! ```sh
//! cargo build -p xt-wasm-runtime --release --target wasm32-wasip2 --example poll_vs_ready
//! # 另一端（连接 1s 后关闭）：
//! python3 -c 'import socket,time; s=socket.create_connection(("127.0.0.1",8600)); time.sleep(1); s.close()'
//! wasmtime run -S tcp=y -S inherit-network=y -S allow-ip-name-lookup=y -S inherit-env=y \
//!   target/wasm32-wasip2/release/examples/poll_vs_ready.wasm 8600
//! ```
//!
//! 判据：若「对端已关闭、`poll()` 恒报该 pollable 就绪」而「`ready()` 恒为 false」，
//! 则分歧在上游；若两者一致，则问题在我们的封装（`Ready` 的 pollable 缓存 / `WaitFor` 复用）。
//!
//! ⚠️ 本 example 只在 wasm 目标上可用；宿主目标下走空实现（否则 `clippy --all-targets` 会
//! 因为 `wstd` 只在 wasi 目标下是依赖而编译失败）。

#[cfg(target_os = "wasi")]
mod probe {
    use std::time::Duration;

    use wasip2::io::poll::{poll, Pollable};
    use wasip2::sockets::network::Ipv4SocketAddress;
    use wasip2::sockets::tcp::{IpAddressFamily, IpSocketAddress};
    use wstd::__internal::wasip2;

    /// 阻塞到 `pollable` 就绪（用 `poll()`，与 `ready()` 无关）。
    fn wait_ready(p: &Pollable) {
        let targets = [p];
        let _ = poll(&targets);
    }

    pub fn run() {
        let port: u16 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(8600);

        let socket = wasip2::sockets::tcp_create_socket::create_tcp_socket(IpAddressFamily::Ipv4)
            .expect("create_tcp_socket");
        let network = wasip2::sockets::instance_network::instance_network();
        let addr = IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port,
            address: (127, 0, 0, 1),
        });

        socket.start_bind(&network, addr).expect("start_bind");
        let bind_poll = socket.subscribe();
        wait_ready(&bind_poll);
        socket.finish_bind().expect("finish_bind");

        socket.start_listen().expect("start_listen");
        let listen_poll = socket.subscribe();
        wait_ready(&listen_poll);
        socket.finish_listen().expect("finish_listen");

        println!("[probe] 监听 127.0.0.1:{port}，等对端连上");
        wait_ready(&listen_poll);
        let (conn, input, _output) = socket.accept().expect("accept");
        println!("[probe] 已 accept；等对端关闭（另一端 python 会在 1s 后 close）");

        // 关键：读 pollable **只订阅一次**（每次 subscribe 都会新建子资源）。
        let read_poll = conn.subscribe();

        // 永远就绪的定时器：让 `poll()` 变成非阻塞（wstd 的 nonblock_check_pollables 同款手法）。
        let tick = wasip2::clocks::monotonic_clock::subscribe_duration(0);

        // 先阻塞等一次「有事件」，确认探针确实被唤醒过。
        let kicked = poll(&[&read_poll]);
        println!("[probe] 首次 poll() 返回：{kicked:?}（对被唤醒而言非空即可）");

        for i in 0..8 {
            let targets = [&read_poll, &tick];
            let by_poll = poll(&targets);
            let poll_says_sock_ready = by_poll.contains(&0);
            let ready_says_sock_ready = read_poll.ready();
            println!(
                "[probe] iter={i} poll()就绪列表={by_poll:?} ⇒ poll认为socket就绪={poll_says_sock_ready} ; ready()={ready_says_sock_ready}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }

        // 真读一次：返回值才是权威（模块文档第 3 条：空列表 ≠ EOF，真 EOF 是 Closed）。
        match input.read(64) {
            Ok(v) => println!("[probe] input.read(64) => Ok(len={}) {:?}", v.len(), v),
            Err(e) => println!("[probe] input.read(64) => Err({e:?})"),
        }

        // 资源释放顺序：pollable → 流 → socket（WASI 要求子资源先于父资源）。
        drop(read_poll);
        drop(tick);
        drop(listen_poll);
        drop(bind_poll);
        drop(input);
        drop(_output);
        drop(conn);
        drop(socket);
        println!("[probe] 结束");
    }
}

#[cfg(not(target_os = "wasi"))]
mod probe {
    pub fn run() {
        eprintln!("本探针只在 wasm32-wasip2 上运行（宿主目标下为空实现）");
    }
}

fn main() {
    probe::run();
}
