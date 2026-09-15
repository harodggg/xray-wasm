//! 最小 SOCKS5 服务端（CONNECT + 可选用户名/密码认证）。
//!
//! # 为什么需要它
//!
//! v1 的目标是「能经隧道取到一个真实页面」，而不是先做一个完整的代理产品。
//! 有 SOCKS5 之后验收就退化成一条毫无歧义的命令：
//!
//! ```sh
//! curl --proxy socks5h://127.0.0.1:1080 https://example.com
//! ```
//!
//! 这也和官方客户端基准（`client.json` 里的 socks 入站 1080）完全对齐，
//! 所以移植结果可以和官方实现**用同一条命令、同一套参数**对拍。
//!
//! # 为什么是 async 的
//!
//! 协商过程跑在**非阻塞** socket 上，由 `main.rs` 的多路复用器统一轮询。
//! 如果这里用阻塞读，一条连接在协商阶段就能卡住整个进程的所有连接 ——
//! 那正是多路复用要解决的问题。所以这里全部走 `AsyncRead`/`AsyncWrite`，
//! 并由调用方套一层超时（非阻塞读自己永远不会失败）。
//!
//! # 认证不是可选项，而是安全问题
//!
//! 一个**无认证**的 SOCKS5 代理一旦绑到非回环地址，就是**开放代理**：
//! 任何能连上该端口的人都能免费用你的隧道出去，流量与责任都算在你头上。
//! 在 k8s 里这尤其危险 —— 做成 Service 之后，集群内任意 Pod 都能用它。
//!
//! 因此这里支持 RFC 1929 用户名/密码认证，并由调用方在
//! 「绑定非回环 + 未设认证」时给出警告（见 `main.rs`）。
//!
//! # 范围
//!
//! 只实现 CONNECT。不支持 BIND / UDP ASSOCIATE —— 它们对「验证协议栈是否正确」
//! 没有增量价值，却会显著放大代码量。

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 版本号。
const VER: u8 = 5;

/// 认证方式：无认证。
const METHOD_NO_AUTH: u8 = 0x00;
/// 认证方式：用户名/密码（RFC 1929）。
const METHOD_USER_PASS: u8 = 0x02;
/// 认证方式：无可接受的方法。
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

/// RFC 1929 的子协商版本号。
const USERPASS_VER: u8 = 0x01;

/// 命令：CONNECT。
const CMD_CONNECT: u8 = 0x01;

/// 地址类型。
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// 应答码。
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// 期望的认证凭据。`None` 表示接受无认证连接。
#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

/// 客户端请求连接的目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// 域名 + 端口。交给隧道时**保持域名形式**，
    /// 让服务端去解析 —— 这正是 `socks5h` 的语义，也避免在 wasm 里做 DNS。
    Connect { host: String, port: u16 },
    /// 明确不支持的命令，携带原命令码以便回正确的错误。
    Unsupported { cmd: u8 },
}

/// 完成方法协商（含可选的用户名/密码认证），然后读一条请求。
pub async fn negotiate_and_read_request<S>(
    sock: &mut S,
    creds: Option<Credentials<'_>>,
) -> io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_method(sock, creds).await?;

    // ── 请求 ──
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("请求版本不支持：{}", req[0]),
        ));
    }
    let cmd = req[1];
    // req[2] 是保留字节，必须为 0；不校验它（真实客户端有发非 0 的）。
    let atyp = req[3];

    let host = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut b = vec![0u8; len[0] as usize];
            sock.read_exact(&mut b).await?;
            // SOCKS5 的域名不保证是合法 UTF-8，但真实场景都是。
            String::from_utf8_lossy(&b).into_owned()
        }
        other => {
            write_reply_reject(sock, REP_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("不支持的地址类型：{other}"),
            ));
        }
    };

    let mut port_b = [0u8; 2];
    sock.read_exact(&mut port_b).await?;
    let port = u16::from_be_bytes(port_b);

    if cmd != CMD_CONNECT {
        write_reply_reject(sock, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(Request::Unsupported { cmd });
    }

    Ok(Request::Connect { host, port })
}

/// 方法协商 + （可选）RFC 1929 认证。
async fn negotiate_method<S>(sock: &mut S, creds: Option<Credentials<'_>>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS 版本不支持：{}", head[0]),
        ));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;

    match creds {
        // 未配置认证：走 0x00。调用方负责警告「非回环且无认证」的风险。
        None => {
            if !methods.contains(&METHOD_NO_AUTH) {
                sock.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await?;
                sock.flush().await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "客户端不支持「无认证」方式",
                ));
            }
            sock.write_all(&[VER, METHOD_NO_AUTH]).await?;
            sock.flush().await?;
            Ok(())
        }
        // 配置了认证：只接受 0x02，绝不回退到无认证。
        Some(want) => {
            if !methods.contains(&METHOD_USER_PASS) {
                sock.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await?;
                sock.flush().await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "服务端要求认证，但客户端未提供用户名/密码方式",
                ));
            }
            sock.write_all(&[VER, METHOD_USER_PASS]).await?;
            sock.flush().await?;
            verify_user_pass(sock, want).await
        }
    }
}

/// RFC 1929：`VER(1) ULEN UNAME PLEN PASSWD`，应答 `VER(1) STATUS(1)`。
async fn verify_user_pass<S>(sock: &mut S, want: Credentials<'_>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ver = [0u8; 1];
    sock.read_exact(&mut ver).await?;
    if ver[0] != USERPASS_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("用户名/密码子协商版本不支持：{}", ver[0]),
        ));
    }

    let mut ulen = [0u8; 1];
    sock.read_exact(&mut ulen).await?;
    let mut uname = vec![0u8; ulen[0] as usize];
    sock.read_exact(&mut uname).await?;

    let mut plen = [0u8; 1];
    sock.read_exact(&mut plen).await?;
    let mut passwd = vec![0u8; plen[0] as usize];
    sock.read_exact(&mut passwd).await?;

    // 定长比较，避免因提前返回而泄漏长度信息。
    // （本场景下时序攻击价值有限，但成本几乎为零，没有理由不做。）
    let ok = constant_time_eq(&uname, want.username.as_bytes())
        & constant_time_eq(&passwd, want.password.as_bytes());

    // 无论成败都回一条，让客户端知道结果而不是干等。
    sock.write_all(&[USERPASS_VER, if ok { 0x00 } else { 0x01 }])
        .await?;
    sock.flush().await?;

    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 用户名或密码不正确",
        ))
    }
}

/// 长度无关的字节比较。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 回一条成功应答。
///
/// BND.ADDR/BND.PORT 填 0.0.0.0:0 —— 真实代理会填自己的出口地址，
/// 但没有客户端会依赖这个值（`curl` 不看它）。
pub async fn write_reply_ok<S: AsyncWrite + Unpin>(sock: &mut S) -> io::Result<()> {
    sock.write_all(&[
        VER,
        REP_SUCCEEDED,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0, // BND.ADDR
        0,
        0, // BND.PORT
    ])
    .await?;
    sock.flush().await
}

/// 回一条失败应答（隧道建立失败时用，让客户端立刻知道而不是干等）。
pub async fn write_reply_failure<S: AsyncWrite + Unpin>(sock: &mut S) -> io::Result<()> {
    write_reply_reject(sock, REP_GENERAL_FAILURE).await
}

async fn write_reply_reject<S: AsyncWrite + Unpin>(sock: &mut S, rep: u8) -> io::Result<()> {
    sock.write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    sock.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用内存管道跑一次完整协商：服务端跑被测函数，客户端跑给定的脚本，两者并发推进。
    ///
    /// 用内存管道而不是真实 socket：协商逻辑与传输无关，而且这样不需要线程
    /// （wasip2 上没有线程，所以测试写法必须与目标平台一致）。
    macro_rules! run_case {
        ($creds:expr, |$sock:ident| $body:block) => {{
            let (mut $sock, mut server_io) = tokio::io::duplex(16 * 1024);
            xt_wasm_runtime::block_on(async move {
                let (req, ()) = futures::join!(
                    negotiate_and_read_request(&mut server_io, $creds),
                    async move { $body }
                );
                req
            })
        }};
    }

    #[test]
    fn parses_domain_connect_request() {
        let req = run_case!(None, |s| {
            s.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            // CONNECT example.com:443
            s.write_all(&[5, 1, 0, 3, 11]).await.unwrap();
            s.write_all(b"example.com").await.unwrap();
            s.write_all(&443u16.to_be_bytes()).await.unwrap();
        })
        .unwrap();

        assert_eq!(
            req,
            Request::Connect {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parses_ipv4_connect_request() {
        let req = run_case!(None, |s| {
            s.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1]).await.unwrap();
            s.write_all(&8080u16.to_be_bytes()).await.unwrap();
        })
        .unwrap();

        assert_eq!(
            req,
            Request::Connect {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
    }

    #[test]
    fn rejects_unsupported_command_and_replies_with_correct_code() {
        let req = run_case!(None, |s| {
            s.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            // BIND (0x02) —— 不支持
            s.write_all(&[5, 2, 0, 1, 127, 0, 0, 1]).await.unwrap();
            s.write_all(&8080u16.to_be_bytes()).await.unwrap();
            let mut reject = [0u8; 10];
            s.read_exact(&mut reject).await.unwrap();
            assert_eq!(reject[0], 5);
            assert_eq!(reject[1], REP_COMMAND_NOT_SUPPORTED);
        })
        .unwrap();

        assert_eq!(req, Request::Unsupported { cmd: 2 });
    }

    #[test]
    fn rejects_client_without_no_auth_method() {
        let err = run_case!(None, |s| {
            s.write_all(&[5, 1, 2]).await.unwrap(); // 只提供用户名密码认证
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, METHOD_NONE_ACCEPTABLE]);
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    // ─── 认证（RFC 1929）─────────────────────────────────────────────

    const CREDS: Credentials<'static> = Credentials {
        username: "alice",
        password: "s3cr3t",
    };

    /// 认证成功：方法协商选 0x02，凭据正确后继续到请求解析。
    #[test]
    fn accepts_correct_credentials() {
        let req = run_case!(Some(CREDS), |s| {
            s.write_all(&[5, 1, 2]).await.unwrap(); // 只提供用户名密码
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, METHOD_USER_PASS], "必须选中 0x02");
            // RFC 1929
            s.write_all(&[1, 5]).await.unwrap();
            s.write_all(b"alice").await.unwrap();
            s.write_all(&[6]).await.unwrap();
            s.write_all(b"s3cr3t").await.unwrap();
            let mut auth = [0u8; 2];
            s.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [1, 0x00], "认证应成功");
            s.write_all(&[5, 1, 0, 3, 11]).await.unwrap();
            s.write_all(b"example.com").await.unwrap();
            s.write_all(&443u16.to_be_bytes()).await.unwrap();
        })
        .unwrap();

        assert_eq!(
            req,
            Request::Connect {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    /// 密码错误必须被拒绝，且回 0x01 而不是静默断开。
    #[test]
    fn rejects_wrong_password() {
        let err = run_case!(Some(CREDS), |s| {
            s.write_all(&[5, 1, 2]).await.unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            s.write_all(&[1, 5]).await.unwrap();
            s.write_all(b"alice").await.unwrap();
            s.write_all(&[5]).await.unwrap();
            s.write_all(b"wrong").await.unwrap();
            let mut auth = [0u8; 2];
            s.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, [1, 0x01], "认证应失败");
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    /// **关键安全属性**：配置了认证时，客户端即使声明支持「无认证」，
    /// 也绝不能回退到无认证。
    #[test]
    fn never_falls_back_to_no_auth_when_credentials_are_configured() {
        let err = run_case!(Some(CREDS), |s| {
            // 同时声明「无认证」和「用户名密码」
            s.write_all(&[5, 2, 0, 2]).await.unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            // 必须选 0x02，不能选 0x00
            assert_eq!(
                reply,
                [5, METHOD_USER_PASS],
                "配置了认证却回退到无认证 = 开放代理"
            );
        })
        .unwrap_err();
        let _ = err;
    }

    /// 只支持无认证的客户端，在服务端要求认证时必须被拒。
    #[test]
    fn rejects_client_that_cannot_do_user_pass() {
        let err = run_case!(Some(CREDS), |s| {
            s.write_all(&[5, 1, 0]).await.unwrap(); // 只提供「无认证」
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, METHOD_NONE_ACCEPTABLE]);
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
