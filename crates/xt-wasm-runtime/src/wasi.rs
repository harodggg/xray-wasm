//! `wasm32-wasip2` 平台层：直接使用 `wasi:sockets` + wstd 的 reactor。
//!
//! # 为什么不继续用 `std::net`
//!
//! `std::net::TcpStream` 在 wasip2 上**只能阻塞**：
//!
//! * 没有非阻塞 connect 的接口 —— 服务端不可达时会把整个进程卡到 TCP 超时；
//! * 拿不到 pollable —— 只能靠「轮询 + 让出」模拟等待，空闲时也在周期性唤醒。
//!
//! 这两件事都源自同一层：标准库不暴露底下的 WASI 资源。所以这里直接操作
//! `wasi:sockets`：`start_connect` 本身是非阻塞的，完成与否用 pollable 通知；
//! 读写的就绪同样由 pollable 通知。
//!
//! # 与协议层的边界
//!
//! 本模块把原始 WASI 流包成 **tokio 的 `AsyncRead`/`AsyncWrite`**（poll 式）。
//! 移植过来的 TLS / VLESS / Vision 只依赖这两个 trait，因此**一行都不用改** ——
//! 换掉的只是最底下的 socket 层。
//!
//! # 三个容易踩的点（都是实测撞出来的）
//!
//! 1. **必须持有 `TcpSocket`**。丢开父资源会让它派生出的流失效。
//! 2. **字段顺序决定 drop 顺序**，而 WASI 要求子资源先于父资源释放，
//!    否则组件模型报 `resource has children`。正确顺序：
//!    pollable → input/output 流 → socket。
//! 3. WASI 的 `input-stream.read` 返回**空列表不等于 EOF**，要重试；
//!    真正的 EOF 是 `StreamError::Closed`。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasip2::io::streams::{InputStream, OutputStream, StreamError};
use wasip2::sockets::network::{Ipv4SocketAddress, Ipv6SocketAddress};
use wasip2::sockets::tcp::{IpAddressFamily, IpSocketAddress, TcpSocket};
use wstd::__internal::wasip2;
use wstd::runtime::{AsyncPollable, WaitFor};

/// 复用 `wstd` 的事件循环：它会在所有任务都挂起时阻塞在 pollable 上，
/// 而不是空转轮询。
pub use wstd::runtime::block_on;

/// 超时错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("操作超时")]
pub struct Elapsed;

/// 生成一个后台任务（单线程协作式，不要求 `Send`）。
pub fn spawn_task<F: Future<Output = ()> + 'static>(f: F) {
    wstd::runtime::spawn(f).detach();
}

/// 给任意 future 加墙钟超时。
///
/// 用 WASI 的单调时钟定时器（`subscribe-duration` 的 pollable），
/// 所以到点会**主动唤醒**，不需要靠轮询发现超时。
pub async fn timeout<F: Future>(
    dur: Duration,
    future: F,
) -> std::result::Result<F::Output, Elapsed> {
    let timer = wstd::time::Timer::after(wstd::time::Duration::from(dur));
    let wait = timer.wait();
    match futures::future::select(Box::pin(future), Box::pin(wait)).await {
        futures::future::Either::Left((value, _)) => Ok(value),
        // 超时分支：右侧的输出类型不用关心（wstd 的 Wait 返回 Instant）。
        futures::future::Either::Right((_, _)) => Err(Elapsed),
    }
}

fn wasi_err(e: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

/// 等待某个 WASI 资源就绪。
///
/// 做法与 `wstd` 内部 `AsyncInputStream::poll_ready` 一致：把 pollable 的 waker
/// 注册到当前任务，就绪时由 reactor 唤醒。
struct Ready {
    pollable: OnceLock<AsyncPollable>,
    wait: Mutex<Option<Pin<Box<WaitFor>>>>,
}

impl Ready {
    fn new() -> Self {
        Self {
            pollable: OnceLock::new(),
            wait: Mutex::new(None),
        }
    }

    fn poll(
        &self,
        subscribe: &dyn Fn() -> wasip2::io::poll::Pollable,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        // pollable 只订阅一次：每次 subscribe 都会新建一个子资源。
        let pollable = self
            .pollable
            .get_or_init(|| AsyncPollable::new(subscribe()));
        let mut slot = self.wait.lock().unwrap();
        let wait = slot.get_or_insert_with(|| Box::pin(pollable.wait_for()));
        match wait.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            // 就绪后必须丢弃这个 WaitFor，否则它的 Drop 会去注销已失效的 waker。
            Poll::Ready(()) => {
                let _ = slot.take();
                Poll::Ready(())
            }
        }
    }
}

/// 一条到远端的 TCP 连接。
///
/// ⚠️ 字段顺序即 drop 顺序，见模块文档第 2 条。不要重排。
pub struct NetStream {
    read_ready: Ready,
    write_ready: Ready,
    input: InputStream,
    output: OutputStream,
    /// 必须持有：它是上面两个流的父资源。
    socket: TcpSocket,
}

impl NetStream {
    fn new(input: InputStream, output: OutputStream, socket: TcpSocket) -> Self {
        Self {
            read_ready: Ready::new(),
            write_ready: Ready::new(),
            input,
            output,
            socket,
        }
    }

    pub fn peer_addr(&self) -> io::Result<String> {
        let addr = self.socket.remote_address().map_err(wasi_err)?;
        Ok(format_sockaddr(addr))
    }

    /// 关闭写方向。
    ///
    /// 注意：WASI 的 `tcp-socket` 只能整体 shutdown，没有半关闭。
    /// 想只关写方向只能靠 drop 整个流，所以这里返回 `Ok(())` 表示「尽力而为」。
    fn shutdown_write(&self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for NetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this
                .read_ready
                .poll(&|| this.input.subscribe(), cx)
                .is_pending()
            {
                return Poll::Pending;
            }
            match this.input.read(buf.remaining() as u64) {
                // WASI 里读到 0 字节**不是** EOF（就绪不代表有数据），重试。
                Ok(chunk) if chunk.is_empty() => continue,
                Ok(chunk) => {
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                // 这才是 EOF。
                Err(StreamError::Closed) => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(wasi_err(e))),
            }
        }
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.output.check_write() {
            // 0 表示当前写不进去：注册就绪后挂起，不空转。
            Ok(0) => {
                if this
                    .write_ready
                    .poll(&|| this.output.subscribe(), cx)
                    .is_pending()
                {
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0))
            }
            Ok(n) => {
                let k = (n as usize).min(buf.len());
                match this.output.write(&buf[..k]) {
                    Ok(()) => Poll::Ready(Ok(k)),
                    Err(StreamError::Closed) => {
                        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                    }
                    Err(e) => Poll::Ready(Err(wasi_err(e))),
                }
            }
            Err(StreamError::Closed) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Err(e) => Poll::Ready(Err(wasi_err(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(e) = this.output.flush() {
            return Poll::Ready(Err(wasi_err(e)));
        }
        if this
            .write_ready
            .poll(&|| this.output.subscribe(), cx)
            .is_pending()
        {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.shutdown_write()?;
        Poll::Ready(Ok(()))
    }
}

/// 主动让出一次。
///
/// 用 0 时长定时器实现：它会注册一个 pollable。不能简单地返回一次 `Pending` ——
/// wstd 的 reactor 在「有任务挂起但没有任何待决 pollable」时会 panic。
pub async fn yield_now() {
    wstd::time::Timer::after(wstd::time::Duration::from_millis(0))
        .wait()
        .await;
}

/// 睡一会儿。
///
/// 用 WASI 单调时钟定时器，到点由 reactor 唤醒 —— 不占用 CPU。
pub async fn sleep(dur: Duration) {
    wstd::time::Timer::after(wstd::time::Duration::from(dur))
        .wait()
        .await;
}

/// 监听套接字。
///
/// ⚠️ 字段顺序同理：pollable 是 socket 派生的子资源，必须先释放。
pub struct NetListener {
    pollable: AsyncPollable,
    socket: TcpSocket,
}

impl NetListener {
    pub fn local_addr(&self) -> io::Result<String> {
        self.socket
            .local_address()
            .map_err(wasi_err)
            .map(format_sockaddr)
    }

    /// 等待并接受一条连接。
    ///
    /// `accept` 本身是同步的（非阻塞），所以先等 pollable 就绪，再调用它。
    pub async fn accept(&self) -> io::Result<NetStream> {
        self.pollable.wait_for().await;
        let (socket, input, output) = self.socket.accept().map_err(wasi_err)?;
        Ok(NetStream::new(input, output, socket))
    }
}

fn to_wasi_addr(addr: std::net::SocketAddr) -> IpSocketAddress {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let o = v4.ip().octets();
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: v4.port(),
                address: (o[0], o[1], o[2], o[3]),
            })
        }
        std::net::SocketAddr::V6(v6) => {
            let s = v6.ip().segments();
            IpSocketAddress::Ipv6(Ipv6SocketAddress {
                port: v6.port(),
                address: (s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
                flow_info: v6.flowinfo(),
                scope_id: v6.scope_id(),
            })
        }
    }
}

fn format_sockaddr(addr: IpSocketAddress) -> String {
    match addr {
        IpSocketAddress::Ipv4(Ipv4SocketAddress { address, port }) => {
            format!(
                "{}.{}.{}.{}:{}",
                address.0, address.1, address.2, address.3, port
            )
        }
        IpSocketAddress::Ipv6(Ipv6SocketAddress { address, port, .. }) => {
            let (a0, a1, a2, a3, a4, a5, a6, a7) = address;
            format!("[{a0:x}:{a1:x}:{a2:x}:{a3:x}:{a4:x}:{a5:x}:{a6:x}:{a7:x}]:{port}")
        }
    }
}

fn family_of(addr: std::net::SocketAddr) -> IpAddressFamily {
    match addr {
        std::net::SocketAddr::V4(_) => IpAddressFamily::Ipv4,
        std::net::SocketAddr::V6(_) => IpAddressFamily::Ipv6,
    }
}

/// 建立连接。支持 IP 字面量与域名。
///
/// 连接本身是**非阻塞**的：`start_connect` 立即返回，完成由 pollable 通知。
///
/// # DNS 是一个残留的阻塞点
///
/// `std::net::ToSocketAddrs` 在 wasip2 上是**同步**的（内部走
/// `wasi:sockets/ip-name-lookup`，但 std 不暴露它的 pollable 版本），
/// 所以域名解析会阻塞事件循环。IP 字面量不经过解析，不阻塞。
/// 服务端连目标站时拿到的是域名，因此这一项在服务端路径上确实会命中 ——
/// 记为已知限制，后续可换用 `ip-name-lookup` 的异步接口。
/// 解析需要 wasmtime 打开 `-S allow-ip-name-lookup=y`。
pub async fn connect(addr: &str) -> io::Result<NetStream> {
    use std::net::ToSocketAddrs;

    let resolved: Vec<std::net::SocketAddr> = addr.to_socket_addrs()?.collect();
    let mut last_err = None;
    for sa in resolved {
        match connect_addr(sa).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("无法解析出任何地址：{addr}"),
        )
    }))
}

/// 连到一个已解析的地址。
async fn connect_addr(sa: std::net::SocketAddr) -> io::Result<NetStream> {
    let socket =
        wasip2::sockets::tcp_create_socket::create_tcp_socket(family_of(sa)).map_err(wasi_err)?;
    let network = wasip2::sockets::instance_network::instance_network();

    socket
        .start_connect(&network, to_wasi_addr(sa))
        .map_err(wasi_err)?;
    AsyncPollable::new(socket.subscribe()).wait_for().await;
    let (input, output) = socket.finish_connect().map_err(wasi_err)?;

    Ok(NetStream::new(input, output, socket))
}

/// 绑定并开始监听。每步都由 pollable 等待完成，不阻塞。
pub async fn listen(addr: &str) -> io::Result<NetListener> {
    let sa: std::net::SocketAddr = addr.parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("地址无法解析：{addr}"))
    })?;

    let socket =
        wasip2::sockets::tcp_create_socket::create_tcp_socket(family_of(sa)).map_err(wasi_err)?;
    let network = wasip2::sockets::instance_network::instance_network();

    socket
        .start_bind(&network, to_wasi_addr(sa))
        .map_err(wasi_err)?;
    let pollable = AsyncPollable::new(socket.subscribe());
    pollable.wait_for().await;
    socket.finish_bind().map_err(wasi_err)?;

    socket.start_listen().map_err(wasi_err)?;
    pollable.wait_for().await;
    socket.finish_listen().map_err(wasi_err)?;

    Ok(NetListener { pollable, socket })
}
