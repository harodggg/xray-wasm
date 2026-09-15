//! 宿主机平台层：同 [`crate::wasi`] 的 API，但基于 `std::net`。
//!
//! # 这一层存在的意义
//!
//! 单元测试跑在宿主上（协议层与平台无关，在宿主上测更快也更好调试）。
//! 另外 `--self-test` 在宿主上跑能开 tracing 日志，排查协议问题时非常有用。
//!
//! # 与 wasm 层的差别（刻意为之，不是疏漏）
//!
//! 宿主上没有 pollable，所以：
//!
//! * **等待用轮询模拟**（`WouldBlock` 后让出 1ms 重试）。wasm 侧是真就绪通知，
//!   宿主侧不是 —— 所以宿主上的 CPU 占用不代表线上表现。
//! * `TcpStream`/`TcpListener` 虽有非阻塞模式，但没有「就绪队列」可挂 waker，
//!   因此这里用一个简单的任务队列把 `spawn_task` 撑起来。
//!
//! 换句话说：**宿主是调试环境，wasm 才是产品**。两边行为一致的部分是协议语义。

use std::cell::RefCell;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 宿主上让出的粒度。
const YIELD: Duration = Duration::from_millis(1);

/// 超时错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("操作超时")]
pub struct Elapsed;

thread_local! {
    /// 由 [`spawn_task`] 投递、由 [`block_on`] 推进的任务队列。
    static TASKS: RefCell<Vec<Pin<Box<dyn Future<Output = ()>>>>> = const { RefCell::new(Vec::new()) };
}

/// 生成一个后台任务。
///
/// 任务只是入队；真正的推进发生在 [`block_on`] 的循环里。
pub fn spawn_task<F: Future<Output = ()> + 'static>(f: F) {
    TASKS.with(|t| t.borrow_mut().push(Box::pin(f)));
}

/// 驱动 `main` 直到完成，期间顺带推进所有已投递的任务。
pub fn block_on<F: Future>(main: F) -> F::Output {
    let mut main = Box::pin(main);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        if let Poll::Ready(v) = main.as_mut().poll(&mut cx) {
            return v;
        }
        // 先把队列「取出」再 poll：任务在 poll 里可能又 spawn 新任务，
        // 直接借用会重入 panic。
        let mut tasks = TASKS.with(|t| std::mem::take(&mut *t.borrow_mut()));
        let mut i = 0;
        while i < tasks.len() {
            if tasks[i].as_mut().poll(&mut cx).is_ready() {
                // swap_remove 返回被移除的 future；显式 drop 掉，
                // 否则 `#[must_use]` 会警告（future 不 poll 就没有意义）。
                drop(tasks.swap_remove(i));
            } else {
                i += 1;
            }
        }
        // 放回，并合并 poll 期间新投递的任务。
        TASKS.with(|t| t.borrow_mut().append(&mut tasks));
        std::thread::sleep(YIELD);
    }
}

/// 墙钟超时（宿主侧）。
pub async fn timeout<F: Future>(
    dur: Duration,
    future: F,
) -> std::result::Result<F::Output, Elapsed> {
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
    let deadline = Deadline {
        at: std::time::Instant::now() + dur,
    };
    match futures::future::select(Box::pin(future), Box::pin(deadline)).await {
        futures::future::Either::Left((value, _)) => Ok(value),
        futures::future::Either::Right(((), _)) => Err(Elapsed),
    }
}

fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// 宿主上的连接流。语义与 wasm 侧的 `NetStream` 对齐。
pub struct NetStream {
    inner: TcpStream,
}

impl NetStream {
    fn new(inner: TcpStream) -> io::Result<Self> {
        inner.set_nonblocking(true)?;
        inner.set_nodelay(true)?;
        Ok(Self { inner })
    }

    pub fn peer_addr(&self) -> io::Result<String> {
        self.inner.peer_addr().map(|a| a.to_string())
    }
}

impl AsyncRead for NetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.inner.read(buf.initialize_unfilled()) {
            Ok(0) => Poll::Ready(Ok(())), // EOF
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e) if would_block(&e) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl AsyncWrite for NetStream {
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
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().inner.shutdown(std::net::Shutdown::Write) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

/// 宿主上的监听器。
pub struct NetListener {
    inner: TcpListener,
}

impl NetListener {
    pub fn local_addr(&self) -> io::Result<String> {
        self.inner.local_addr().map(|a| a.to_string())
    }

    /// 接受一条连接。
    ///
    /// # 为什么无连接时要返回 `Pending` 而不是在这里睡
    ///
    /// 如果在这里 `sleep` 死等，主 future 就**永远不返回 Pending**，
    /// [`block_on`] 便没有机会去推进被 [`spawn_task`] 投递的任务 ——
    /// 宿主上的并发会直接失效（这个坑是被单元测试抓出来的）。
    /// 返回 `Pending` 后由 `block_on` 统一让出再回来，任务就有机会跑。
    pub async fn accept(&self) -> io::Result<NetStream> {
        futures::future::poll_fn(|_cx| match self.inner.accept() {
            Ok((sock, _)) => Poll::Ready(NetStream::new(sock)),
            // 未注册 waker 也安全：宿主侧 block_on 会无条件重试。
            Err(e) if would_block(&e) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }
}

/// 主动让出一次。
///
/// wasm 侧用 0 时长定时器实现（会注册一个 pollable，避免 reactor 因
/// 「无待决 pollable」而 panic）；宿主侧就是一个返回一次 Pending 的 future。
pub async fn yield_now() {
    struct YieldOnce(bool);
    impl Future for YieldOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                Poll::Pending
            }
        }
    }
    YieldOnce(false).await
}

/// 睡一会儿。
///
/// 宿主上不能直接用 `std::thread::sleep` —— 那会在 poll 里把整个执行器阻塞住。
/// 这里用「反复让出 + 查时钟」模拟，让其它任务与主循环仍能推进。
pub async fn sleep(dur: Duration) {
    let deadline = std::time::Instant::now() + dur;
    while std::time::Instant::now() < deadline {
        yield_now().await;
    }
}

/// 建立连接（宿主侧走阻塞 connect）。
pub async fn connect(addr: &str) -> io::Result<NetStream> {
    let sock = TcpStream::connect(addr)?;
    NetStream::new(sock)
}

/// 绑定并监听。
pub async fn listen(addr: &str) -> io::Result<NetListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(NetListener { inner: listener })
}
