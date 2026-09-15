//! 全双工转发的核心。
//!
//! # 为什么这一段值得单独拿出来测
//!
//! 这是整个 wasip2 移植里**唯一真正的新子系统**。协议代码（TLS/REALITY/VLESS/Vision）
//! 都是上游写好的、存进度的状态机；而「同时朝两个方向搬运字节」在单线程 +
//! 无 reactor 的环境里恰恰最容易写错：
//!
//! * 如果读方向用阻塞 IO，写方向会被饿死 → **死锁**（curl 会一直挂着，没有报错）；
//! * 如果不做半关闭传播，TLS 内层连接收不到 EOF → 表现为「页面卡住不结束」。
//!
//! 所以这里刻意用 `tokio::io::split` 把两个流各拆成读写两半，
//! 再让两个方向的搬运**并发**跑在同一个 executor 上。
//! 两个底层 socket 都是非阻塞的（见 `xt-wasm-runtime`），
//! `Pending` 会把控制权交还给另一个方向 —— 这正是不会死锁的原因。

use std::io;

use crate::Stream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// 一次转发的字节统计。
///
/// 方向以**调用方**为基准：`a` 是调用方这一侧的流，`b` 是对端。
/// 所以 `up` = a→b，`down` = b→a。服务端调用时 a 是客户端连接、b 是目标站，
/// 于是 `up` = 客户端上传、`down` = 目标回传。
///
/// 为什么要把它返回出来：服务端的一条日志要能回答「这次请求到底搬了多少字节」。
/// 只报一个 `Forwarded` 而不带字节数，运维无法区分「隧道通了但目标没回内容」
/// 和「压根没转发」—— 这恰恰是最需要日志来分辨的两种情形。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// a → b 的字节数。
    pub up: u64,
    /// b → a 的字节数。
    pub down: u64,
}

/// 在两个流之间双向搬运，直到**两个方向都结束**。
///
/// 半关闭语义：某个方向读到 EOF 时，立刻 `shutdown` 对端的写方向，
/// 但**不**终止另一个方向 —— 对端可能还有数据要回（HTTP 的
/// 「客户端先关、服务器再答」就依赖这一点）。
pub async fn relay_bidirectional(a: Box<dyn Stream>, b: Box<dyn Stream>) -> io::Result<RelayStats> {
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);

    let a_to_b = copy_then_eof(a_read, b_write);
    let b_to_a = copy_then_eof(b_read, a_write);

    // 并发跑两个方向。任一方向出错不影响另一个继续收尾，
    // 所以这里先收齐两个结果再决定是否报错。
    let (r1, r2) = futures::join!(a_to_b, b_to_a);
    let stats = RelayStats {
        up: r1.as_ref().copied().unwrap_or(0),
        down: r2.as_ref().copied().unwrap_or(0),
    };
    // 报错时也把**已经搬完的字节数**带上：半途断掉的连接恰恰是排障重点，
    // 「转发到一半断了、断之前搬了多少」比一句 `ConnectionReset` 有用得多。
    match (r1, r2) {
        (Ok(_), Ok(_)) => Ok(stats),
        (Err(e), _) | (_, Err(e)) => Err(io::Error::new(e.kind(), RelayError { source: e, stats })),
    }
}

/// 把字节统计挂在 `io::Error` 上一起往上带。
#[derive(Debug)]
struct RelayError {
    source: io::Error,
    stats: RelayStats,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}（断之前 up={} 字节 down={} 字节）",
            self.source, self.stats.up, self.stats.down
        )
    }
}

impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// 单向搬运，读到 EOF 后把 EOF 传播给对端。
async fn copy_then_eof<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader, &mut writer).await?;
    // 对端可能已经关了；shutdown 失败不是错误（ENOTCONN / BrokenPipe）。
    let _ = writer.shutdown().await;
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 造一对内存管道：返回 (网线这头, 网线那头)。
    fn pipe() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    /// 全双工：客户端与「远端」同时收发，中继必须两个方向都通。
    ///
    /// 如果中继退化成「先读完 A 再读 B」，这个测试会挂死（而不是失败），
    /// 这恰好也是线上会出现的症状。
    #[test]
    fn relays_both_directions_concurrently() {
        let (client, relay_a) = pipe();
        let (relay_b, server) = pipe();

        let out = crate::block_on(async move {
            futures::join!(
                // 中继
                async move { relay_bidirectional(Box::new(relay_a), Box::new(relay_b)).await },
                // 远端：收到什么回什么，连回两轮
                async move {
                    let mut server = server;
                    for _ in 0..2 {
                        let mut buf = [0u8; 5];
                        server.read_exact(&mut buf).await.unwrap();
                        server.write_all(&buf).await.unwrap();
                        server.flush().await.unwrap();
                    }
                    Ok::<_, io::Error>(())
                },
                // 客户端：发一轮收一轮，再发一轮收一轮
                async move {
                    let mut client = client;
                    for msg in [b"ping1", b"ping2"] {
                        client.write_all(msg).await.unwrap();
                        client.flush().await.unwrap();
                        let mut buf = [0u8; 5];
                        client.read_exact(&mut buf).await.unwrap();
                        assert_eq!(&buf, msg);
                    }
                    Ok::<_, io::Error>(())
                }
            )
        });

        out.0.expect("relay ok");
        out.1.expect("server ok");
        out.2.expect("client ok");
    }

    /// 半关闭传播：客户端关掉写方向后，远端必须看到 EOF，
    /// 且**仍然能把应答发回来**（这是 HTTP/1.0 与很多协议的收尾模式）。
    #[test]
    fn propagates_half_close_without_killing_the_other_direction() {
        let (client, relay_a) = pipe();
        let (relay_b, server) = pipe();

        let out = crate::block_on(async move {
            futures::join!(
                async move { relay_bidirectional(Box::new(relay_a), Box::new(relay_b)).await },
                async move {
                    let mut server = server;
                    // 一直读到 EOF（只有收到半关闭才会返回 0）
                    let mut all = Vec::new();
                    server.read_to_end(&mut all).await.unwrap();
                    assert_eq!(all, b"request");
                    // EOF 之后仍然能写回
                    server.write_all(b"response").await.unwrap();
                    server.flush().await.unwrap();
                    Ok::<_, io::Error>(())
                },
                async move {
                    let mut client = client;
                    client.write_all(b"request").await.unwrap();
                    client.flush().await.unwrap();
                    client.shutdown().await.unwrap();
                    // 关掉写方向之后，读方向必须还活着
                    let mut buf = Vec::new();
                    client.read_to_end(&mut buf).await.unwrap();
                    assert_eq!(buf, b"response");
                    Ok::<_, io::Error>(())
                }
            )
        });

        out.0.expect("relay ok");
        out.1.expect("server ok");
        out.2.expect("client ok");
    }
}
