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
use wasip2::sockets::tcp::{IpAddressFamily, IpSocketAddress, ShutdownType, TcpSocket};
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
/// 诊断用：存活中的 `WaitFor` 注册数、以及创建过的 `AsyncPollable` 数。
///
/// 目的只有一个：挂起期间这个数是不是**单调增长不回落**。
/// 若是，就是 waker 注册泄漏 —— reactor 里留着失效 waker，
/// `poll_oneoff` 每轮立刻返回 ⇒ 忙等（V24 的自旋）。
static LIVE_WAITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static MADE_POLLABLES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static READY_POLLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 给 `WaitFor` 包一层，好在它真的被 Drop 时把存活数减回去。
struct CountedWait(Pin<Box<WaitFor>>);

impl std::ops::Deref for CountedWait {
    type Target = Pin<Box<WaitFor>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for CountedWait {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for CountedWait {
    fn drop(&mut self) {
        LIVE_WAITS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

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
    /// 关掉**写方向**，向对端发 FIN，但保留读方向。
    ///
    /// # 这里曾经是个 `Ok(())` 空实现，后果很严重
    ///
    /// 空实现意味着**半关闭永远不会传播给对端**。而 `relay_bidirectional`
    /// 的收尾恰恰完全依赖它：某个方向读到 EOF 后 `shutdown` 对端写方向，
    /// 让对端也知道「我这边说完了」。
    ///
    /// 空实现之下这条链根本走不完：客户端关掉写方向 → 我们没发 FIN →
    /// 服务端读不到 EOF → 它那边的 `a_to_b` 永远挂着 → 中继永远不返回。
    /// 实测症状是每条连接都在服务端留下一个 `CLOSE_WAIT` 的目标 socket 和
    /// 一个 `ESTABLISHED` 的客户端 socket，**请求成功、连接不回收** ——
    /// 长跑就是一个 fd 泄漏，同时也让「连接结束时记账」的日志永远不出现。
    ///
    /// WASI 的 `OutputStream` 没有 shutdown；要发 FIN 得用底层的
    /// `tcp-socket.shutdown(Send)` —— 这正是本结构体持有 `socket` 的原因之一。
    fn shutdown_write(&self) -> io::Result<()> {
        self.socket.shutdown(ShutdownType::Send).map_err(wasi_err)
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
                // `check_write()` 报 0 时**不能只等** —— 实测（V24）它在一条新建的、
                // 一个字节都没写过的连接上就恒为 0，而纯 wstd 的最小复现器同样会因此
                // 以 ~18k 次/秒空转把一核吃满。
                //
                // 这里改用 WASI 的阻塞版写：若 `check_write()==0` 只是**误报**，
                // 它会立刻写成功；若真的写不进，它会阻塞（代价是单线程实例被卡住，
                // 但那比确定性的忙等要好，且有 livenessProbe 兜底）。
                let k = buf.len().min(16 * 1024);
                match this.output.blocking_write_and_flush(&buf[..k]) {
                    Ok(()) => Poll::Ready(Ok(k)),
                    Err(StreamError::Closed) => {
                        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                    }
                    Err(e) => Poll::Ready(Err(wasi_err(e))),
                }
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 与 `poll_write` 同样的理由（见那里的说明）：`write_ready` 的就绪判定在
        // wasmtime 上会**误报未就绪**，若在此挂起就会变成 ~18k 次/秒的忙等。
        // `blocking_flush` 直接把它落盘/发出，不做就绪门控。
        match this.output.blocking_flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(StreamError::Closed) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Err(e) => Poll::Ready(Err(wasi_err(e))),
        }
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

/// 解析 `host:port` 到一组地址。
///
/// 与 `connect` 拆开是为了让调用方能**分别报告**「解析失败」和「连不上」——
/// 这两件事的排查方向完全不同（域名/DNS vs 对端端口/防火墙），
/// 混成一句 `connect failed` 等于把排障成本推给运维。
///
/// # 这是一个残留的阻塞点
///
/// `std::net::ToSocketAddrs` 在 wasip2 上是**同步**的（内部走
/// `wasi:sockets/ip-name-lookup`，但 std 不暴露它的 pollable 版本），
/// 所以域名解析会阻塞事件循环。IP 字面量不经过解析，不阻塞。
/// 服务端连目标站时拿到的是域名，因此这一项在服务端路径上确实会命中 ——
/// 记为已知限制，后续可换用 `ip-name-lookup` 的异步接口。
/// 解析需要 wasmtime 打开 `-S allow-ip-name-lookup=y`。
pub fn resolve(addr: &str) -> io::Result<Vec<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    Ok(addr.to_socket_addrs()?.collect())
}

/// 单次 `connect` 的**总**时间预算。
///
/// # 为什么必须有这个
///
/// 一个域名常常解析出十几个地址（实测 `www.google.com` 是 8 个 IPv4 + 8 个 IPv6），
/// 而它们是**顺序**试的、每个各自超时。目标端口若被丢包（而不是回 RST），
/// 每个地址都要等满 TCP 超时 —— 实测一条请求 **1080 秒（18 分钟）** 才失败：
///
/// ```text
/// dur_ms=1080453  target=www.google.com:5222  outcome=ConnectFailed
/// ```
///
/// 18 分钟里它一直占着一个并发槽位（上限 256）。客户端并发一高，
/// 槽位被这些「慢慢失败」的连接占满，accept 循环就不再收新连接 ——
/// 对外表现就是「TCP 连不上、readiness 探针超时、Service 没有 endpoints」。
///
/// 所以这里给**整次 connect** 一个硬预算：宁可快速失败让客户端重试，
/// 也不能让一条连接把整个服务端拖死。
const CONNECT_TOTAL_BUDGET: Duration = Duration::from_secs(10);

/// 单个地址的预算。取总预算的零头，保证试完前几个地址后还能留时间给后面的。
const CONNECT_PER_ADDR_BUDGET: Duration = Duration::from_secs(3);

/// 建立连接。支持 IP 字面量与域名。
///
/// 连接本身是**非阻塞**的：`start_connect` 立即返回，完成由 pollable 通知。
/// 解析的部分见 [`resolve`]（那里的阻塞说明同样适用）。
///
/// 地址是顺序试的，但整体受 [`CONNECT_TOTAL_BUDGET`] 约束。
pub async fn connect(addr: &str) -> io::Result<NetStream> {
    let resolved = resolve(addr)?;
    if resolved.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("无法解析出任何地址：{addr}"),
        ));
    }

    let started = std::time::Instant::now();
    let mut last_err = None;
    let mut tried = 0usize;

    // IPv4 优先：容器里常常没有 IPv6 出口，先试 v6 只会白等一个超时。
    let mut ordered: Vec<std::net::SocketAddr> = resolved.clone();
    ordered.sort_by_key(|a| a.is_ipv6());

    for sa in ordered {
        let left = CONNECT_TOTAL_BUDGET.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        let budget = left.min(CONNECT_PER_ADDR_BUDGET);
        tried += 1;
        match timeout(budget, connect_addr(sa)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("连接 {sa} 超过 {} 秒未完成", budget.as_secs()),
                ))
            }
        }
    }

    let elapsed = started.elapsed();
    Err(match last_err {
        Some(e) => io::Error::new(
            e.kind(),
            format!(
                "{}（{addr} 共 {} 个地址，试了 {tried} 个，耗时 {:.1}s；\
                 总预算 {}s）",
                e,
                resolved.len(),
                elapsed.as_secs_f32(),
                CONNECT_TOTAL_BUDGET.as_secs()
            ),
        ),
        None => io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{addr} 在 {}s 预算内没试出可用地址",
                CONNECT_TOTAL_BUDGET.as_secs()
            ),
        ),
    })
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
