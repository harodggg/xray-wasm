//! 运行时桥接层：shim 类型 + 平台相关的 socket / 事件循环。
//!
//! # 这个 crate 解决什么问题
//!
//! 移植过来的协议代码是 `async` 的，用 `tokio::io` 的 `AsyncRead` / `AsyncWrite`。
//! 但 **wasip2 上没有 tokio runtime，也没有 reactor**：
//!
//! * `tokio::net` 依赖 mio，mio 依赖 epoll/kqueue —— wasm 里都没有，
//!   且 tokio 在 wasm 上遇到 `net` feature 会直接 `compile_error!`；
//! * `std::thread::spawn` 在 wasip2 上是 `unsupported()`，开不了 runtime。
//!
//! 所以这一层的职责是：**提供一个能被 async 代码使用的 socket**，
//! 以及一个能驱动它们的执行器。
//!
//! # 两个平台实现，边界是 tokio 的那两个 trait
//!
//! | | `target_os = "wasi"`（产品） | 其它（调试/测试） |
//! |---|---|---|
//! | socket | 直接调 `wasi:sockets`，非阻塞 + pollable | `std::net`，非阻塞 |
//! | 等待 | **真就绪通知**（waker 由 reactor 唤醒） | 轮询 + 让出（无 pollable 可用） |
//! | 超时 | WASI 单调时钟定时器 | 墙钟轮询 |
//!
//! 关键性质：**协议层只认 tokio 的 `AsyncRead`/`AsyncWrite`**。
//! 所以底下换实现（这正是本次做的事：从 `std::net` 换到 `wasi:sockets`）时，
//! TLS / VLESS / Vision 一行都不用改。
//!
//! # 为什么要离开 `std::net`
//!
//! 不是因为 `std::net` 不能用 —— 它能用，v0.1/v0.2 就是基于它验证的。
//! 而是它在 wasip2 上**只能阻塞**，且拿不到 pollable，导致：
//!
//! * 没有非阻塞 connect：服务端不可达时整个进程卡到 TCP 超时；
//! * 等数据只能「轮询 + 让出」，空闲时也在周期性唤醒。
//!
//! 详见 `wasi.rs` 与 `host.rs` 的模块文档。

use std::any::Any;

use tokio::io::{AsyncRead, AsyncWrite};

// ─────────────────────────── shim 类型 ───────────────────────────
//
// 这些类型原本在 meow-rs 的 meow-transport / meow-common 里。
// 移植时下沉到本层，让 tls / vless 都能依赖，避免循环依赖。
// 定义逐字取自上游（见 docs/port-map.md §3）。

/// `meow-transport` 的全部错误类型。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls handshake: {0}")]
    Tls(String),

    #[error("websocket handshake: {0}")]
    WebSocket(String),

    #[error("grpc framing: {0}")]
    Grpc(String),

    #[error("h2: {0}")]
    H2(String),

    #[error("http upgrade: {0}")]
    HttpUpgrade(String),

    #[error("xhttp: {0}")]
    Xhttp(String),

    #[error("invalid config: {0}")]
    Config(String),
}

/// crate 级 `Result` 别名。
pub type Result<T> = std::result::Result<T, TransportError>;

/// 传输层之间传递的双工字节流。
///
/// 对每个 `T: AsyncRead + AsyncWrite + Unpin + Send + Sync` 有 blanket 实现。
///
/// `Any` supertrait 是必需的：Vision 的 DIRECT splice 靠
/// [`Stream::as_any_mut`] 向下转型拿到具体的 REALITY 流（见 port-map §3.5）。
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any> Stream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// 包装一个内层 [`Stream`] 并产出新 [`Stream`] 的传输层。
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}

// ─────────────────────── 平台实现（见模块文档的表格）───────────────────────

#[cfg(target_os = "wasi")]
#[path = "wasi.rs"]
mod platform;

#[cfg(not(target_os = "wasi"))]
#[path = "host.rs"]
mod platform;

pub use platform::{
    block_on, connect, listen, sleep, spawn_task, timeout, yield_now, Elapsed, NetListener,
    NetStream,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 一条连接经 `AsyncRead`/`AsyncWrite` 收发，与直接同步收发等价。
    #[test]
    fn net_stream_round_trips_through_async_traits() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (mut sock, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(sock.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            sock.write_all(format!("echo:{line}").as_bytes()).unwrap();
            sock.flush().unwrap();
            line
        });

        let got = block_on(async {
            let mut client = connect(&addr.to_string()).await.unwrap();
            client.write_all(b"ping\n").await.unwrap();
            client.flush().await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = client.read(&mut buf).await.unwrap();
            String::from_utf8(buf[..n].to_vec()).unwrap()
        });

        assert_eq!(got, "echo:ping\n");
        assert_eq!(server.join().unwrap(), "ping\n");
    }

    /// 半关闭：关掉写方向后仍要能读到对端数据 —— Vision 的收尾路径依赖这个语义。
    #[test]
    fn shutdown_keeps_read_side_open() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).unwrap(); // 收到 EOF 才返回
            sock.write_all(b"after-eof").unwrap();
            sock.flush().unwrap();
            buf
        });

        let got = block_on(async {
            let mut client = connect(&addr.to_string()).await.unwrap();
            client.write_all(b"body").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = vec![0u8; 32];
            let n = client.read(&mut buf).await.unwrap();
            String::from_utf8(buf[..n].to_vec()).unwrap()
        });

        assert_eq!(server.join().unwrap(), b"body");
        assert_eq!(got, "after-eof");
    }

    /// 没有数据可读时必须返回 `Pending`（而不是阻塞住）——
    /// 这是「一条连接不会卡住其它连接」的前提。
    #[test]
    fn read_on_idle_socket_is_pending_not_blocking() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = std::thread::spawn(move || {
            let (_sock, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });

        block_on(async {
            let mut client = connect(&addr.to_string()).await.unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let mut buf = [0u8; 16];
            let mut cx = Context::from_waker(Waker::noop());
            let poll = std::pin::Pin::new(&mut client)
                .poll_read(&mut cx, &mut tokio::io::ReadBuf::new(&mut buf));
            assert!(
                matches!(poll, Poll::Pending),
                "空闲读应当是 Pending，实际 {poll:?}"
            );
        });
    }

    /// 卡住的 future 必须被超时打断 —— 这是「连上不发数据」不会占死并发槽位的前提。
    #[test]
    fn timeout_fires_on_a_stalled_future() {
        let t0 = Instant::now();
        let r = block_on(timeout(
            Duration::from_millis(200),
            std::future::pending::<()>(),
        ));
        let elapsed = t0.elapsed();
        assert!(r.is_err(), "永不完成的 future 必须超时");
        assert!(
            elapsed >= Duration::from_millis(150),
            "过早触发：{elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "超时未被察觉：{elapsed:?}"
        );
    }

    /// 已经就绪的 future 不该被超时影响。
    #[test]
    fn timeout_passes_through_a_ready_future() {
        let r = block_on(timeout(Duration::from_secs(30), async { 42 }));
        assert_eq!(r.unwrap(), 42);
    }

    /// `spawn_task` 投递的任务必须被 `block_on` 推进。
    ///
    /// ⚠️ 注意主 future 里**不能**用长同步 sleep：那会把执行器整个阻塞住，
    /// 被 spawn 的任务根本没机会跑。这里用「短 sleep + 检查」模拟真实的
    /// 无限 accept 循环（真实主 future 永不完成，任务自然会被持续推进）。
    #[test]
    fn spawned_tasks_are_driven() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let observe = counter.clone();
        let c1 = counter.clone();
        let c2 = counter.clone();

        block_on(async move {
            spawn_task(async move {
                std::thread::sleep(Duration::from_millis(30));
                c1.fetch_add(1, Ordering::SeqCst);
            });
            spawn_task(async move {
                std::thread::sleep(Duration::from_millis(60));
                c2.fetch_add(1, Ordering::SeqCst);
            });
            // 反复显式让出，让被 spawn 的任务有机会被推进。
            // （真实主 future 是无限 accept 循环，会自然让出。）
            for _ in 0..2000 {
                if observe.load(Ordering::SeqCst) == 2 {
                    break;
                }
                yield_now().await;
            }
        });

        assert_eq!(counter.load(Ordering::SeqCst), 2, "两个任务都应已完成");
    }
}
