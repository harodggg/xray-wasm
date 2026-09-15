//! wasip2 运行时桥接层：shim 类型 + 非阻塞 socket 反应堆。
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
//! 而 **`std::net::TcpStream` 在 wasip2 上可用**，并且 `set_nonblocking` 是**真实实现**
//! （`library/std/src/sys/pal/wasip2/net.rs:315`，走 `ioctl(FIONBIO)`）——
//! 这一点已实测确认：`set_nonblocking(true)` 后 `read` 立即返回 `WouldBlock`。
//!
//! # 为什么必须非阻塞
//!
//! 握手阶段是严格顺序的（写 ClientHello → 读 ServerHello），阻塞式就够。
//! 但握手之后的 Vision/REALITY **全双工转发**需要读写同时存活：
//! 单线程上如果 `poll_read` 阻塞住，写方向就被饿死，直接死锁。
//!
//! # 反应堆模型（v1 的取舍，写在这里以免被误解为疏忽）
//!
//! 本层用**非阻塞 socket + 重试式 executor**：socket 返回 `WouldBlock` 时
//! future 返回 `Poll::Pending`，executor 短暂让出后重新 poll。
//!
//! 代价是空闲时仍会周期性唤醒（CPU 换简单）。更优雅的做法是把 waker 接到
//! `wasi:io/poll` 上做真正的就绪通知，那需要 preview2 绑定；
//! v1 先用这个模型把协议跑通，[`block_on`] 是唯一需要替换的入口。

use std::any::Any;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

// ───────────────────────── 非阻塞 socket 桥接 ─────────────────────────

/// 包 `std::net::TcpStream` 的异步流适配器（非阻塞）。
///
/// `poll_*` 遇到 `WouldBlock` 返回 [`Poll::Pending`]，由 [`block_on`] 重试。
pub struct NonBlockingStream {
    inner: TcpStream,
}

impl NonBlockingStream {
    /// 接管一个已连接的 socket 并切到非阻塞模式。
    pub fn new(inner: TcpStream) -> io::Result<Self> {
        inner.set_nonblocking(true)?;
        // 协议栈假设握手不会被 Nagle 拖成两段发出。
        inner.set_nodelay(true)?;
        Ok(Self { inner })
    }

    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// 用 `MSG_PEEK` 探一眼，不消费数据；无数据时返回 `Ok(false)`。
    /// Vision 的 ClientHello 嗅探会用到。
    pub fn peek_available(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.inner.peek(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

impl AsyncRead for NonBlockingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let unfilled = buf.initialize_unfilled();
        match this.inner.read(unfilled) {
            Ok(0) => {
                // 对端关闭：返回 0 字节即为 EOF，不要当成错误。
                Poll::Ready(Ok(()))
            }
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e) if would_block(&e) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for NonBlockingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut().inner.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if would_block(&e) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // TcpStream 无用户态缓冲，flush 是空操作。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 只关写方向（半关闭）：读方向必须留着，对端可能还有数据要回。
        match self.get_mut().inner.shutdown(std::net::Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 建立到 `addr` 的非阻塞连接。
///
/// 域名解析需要 wasmtime 打开 `-S allow-ip-name-lookup=y`；
/// **出站连接本身需要 `-S inherit-network=y`，缺了会得到 `PermissionDenied`
/// （看起来像被墙，其实是 host 策略）。**
pub fn connect(addr: impl ToSocketAddrs) -> io::Result<NonBlockingStream> {
    // 连接阶段先用阻塞模式：connect 不涉及「读写并发」，阻塞最简单。
    let stream = TcpStream::connect(addr)?;
    NonBlockingStream::new(stream)
}

/// 绑定本地监听。
pub fn listen(addr: impl ToSocketAddrs) -> io::Result<TcpListener> {
    TcpListener::bind(addr)
}

// ─────────────────────────── executor ───────────────────────────

/// Pending 时的让出时长。
///
/// 反应堆没有真正的就绪通知，只能重试。1ms 是在
/// 「空转 CPU」与「增加延迟」之间的折中；真正修法是接 `wasi:io/poll`。
const RETRY_INTERVAL: Duration = Duration::from_millis(1);

/// 驱动一个 future 到完成。
///
/// **这是本层唯一与「没有 reactor」这一事实强耦合的地方。**
/// 用自研 executor 而不是 `futures::executor::block_on`：后者会 park 在 waker 上，
/// 而我们的 `Poll::Pending` 不保证有人来唤醒 —— 会直接挂死。
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    // 不依赖唤醒，所以用 noop waker。
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut spins = 0u32;
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                // 先自旋几次吃掉短等待（避免为一个立即就绪的 socket 白睡 1ms），
                // 仍然 Pending 才真正让出，交给 host 的 poll_oneoff。
                spins += 1;
                if spins > 8 {
                    std::thread::sleep(RETRY_INTERVAL);
                    spins = 0;
                } else {
                    std::hint::spin_loop();
                }
            }
        }
    }
}

// ─────────────────────────── 超时 ───────────────────────────

/// 超时错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("操作超时")]
pub struct Elapsed;

/// 到点即就绪的 future。
///
/// 只含一个 `Instant`，因此天然 `Unpin`，不需要任何 unsafe 的 pin 投影。
struct Deadline {
    at: std::time::Instant,
}

impl Future for Deadline {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if std::time::Instant::now() >= self.at {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// 给任意 future 加一个墙钟超时。
///
/// # 为什么必须有它
///
/// socket 是**非阻塞**的：对端不发数据时读操作会一直返回 `Pending`，
/// 永远不会自己失败。多路复用下这意味着一个「连上但不发数据」的客户端
/// 可以永久占住一个并发槽位（k8s 的 TCP 探针、端口扫描器都会这么做），
/// 槽位耗尽后代理就再也接不了新连接。
///
/// # 为什么不用 unsafe
///
/// `futures::future::select` 要求两个 future 都是 `Unpin`。
/// 把内层 future `Box::pin` 之后它就是 `Unpin`，`Deadline` 本身也只含
/// `Instant` —— 于是不需要任何 `unsafe` 的 pin 投影。
///
/// 返回类型写全 `std::result::Result`：本 crate 的 [`Result`] 是
/// `TransportError` 的单参数别名，直接写 `Result<T, E>` 会撞上它。
pub async fn timeout<F: Future>(
    dur: Duration,
    future: F,
) -> std::result::Result<F::Output, Elapsed> {
    let inner = Box::pin(future);
    let deadline = Deadline {
        at: std::time::Instant::now() + dur,
    };
    match futures::future::select(inner, deadline).await {
        futures::future::Either::Left((value, _)) => Ok(value),
        futures::future::Either::Right(((), _)) => Err(Elapsed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 阻塞 socket 经 async trait 收发，与同步收发等价（宿主上验证语义）。
    #[test]
    fn non_blocking_stream_round_trips_through_async_traits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(sock.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            sock.write_all(format!("echo:{line}").as_bytes()).unwrap();
            sock.flush().unwrap();
            line
        });

        let mut client = connect(addr).unwrap();
        let got = block_on(async {
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).unwrap(); // 收到 EOF 才返回
            sock.write_all(b"after-eof").unwrap();
            sock.flush().unwrap();
            buf
        });

        let mut client = connect(addr).unwrap();
        let got = block_on(async {
            client.write_all(b"body").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = vec![0u8; 32];
            let n = client.read(&mut buf).await.unwrap();
            String::from_utf8(buf[..n].to_vec()).unwrap()
        });

        assert_eq!(server.join().unwrap(), b"body");
        assert_eq!(got, "after-eof");
    }

    /// 没有数据可读时必须返回 Pending（而不是阻塞住）——这正是全双工不死锁的前提。
    #[test]
    fn read_on_idle_socket_is_pending_not_blocking() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // 接受连接但保持沉默
        let _server = std::thread::spawn(move || {
            let (_sock, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });

        let mut client = connect(addr).unwrap();
        let mut buf = [0u8; 16];
        let mut cx = Context::from_waker(Waker::noop());
        // 刚连上还没有数据；socket 是非阻塞的，所以必须得到 Pending。
        std::thread::sleep(Duration::from_millis(50));
        let poll = Pin::new(&mut client).poll_read(&mut cx, &mut ReadBuf::new(&mut buf));
        assert!(
            matches!(poll, Poll::Pending),
            "idle read should be Pending, got {poll:?}"
        );
    }

    /// 卡住的 future 必须被超时打断 —— 这是「连上不发数据」不会占死并发槽位的前提。
    #[test]
    fn timeout_fires_on_a_stalled_future() {
        let t0 = std::time::Instant::now();
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
        // 上界放得很宽：这条只用来抓「超时根本没生效、一直挂着」。
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
}
