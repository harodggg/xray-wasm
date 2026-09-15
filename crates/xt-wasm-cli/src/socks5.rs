//! 最小 SOCKS5 服务端（仅 CONNECT / 无认证）。
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
//! # 范围
//!
//! 只实现 CONNECT。不支持 BIND / UDP ASSOCIATE —— 它们对「验证协议栈是否正确」
//! 没有增量价值，却会显著放大代码量。

use std::io::{self, Read, Write};

/// SOCKS5 版本号。
const VER: u8 = 5;

/// 认证方式：无认证。
const METHOD_NO_AUTH: u8 = 0x00;
/// 认证方式：无可接受的方法。
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

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

/// 客户端请求连接的目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// 域名 + 端口。交给隧道时**保持域名形式**，
    /// 让服务端去解析 —— 这正是 `socks5h` 的语义，也避免在 wasm 里做 DNS。
    Connect { host: String, port: u16 },
    /// 明确不支持的命令，携带原命令码以便回正确的错误。
    Unsupported { cmd: u8 },
}

/// 完成方法协商，然后读一条请求。
///
/// 协商阶段用的是**阻塞** IO：此时隧道还没建立，没有并发的读写要照顾，
/// 阻塞写法最简单也最不容易错。
pub fn negotiate_and_read_request<S: Read + Write>(sock: &mut S) -> io::Result<Request> {
    // ── 方法协商 ──
    let mut head = [0u8; 2];
    sock.read_exact(&mut head)?;
    if head[0] != VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS 版本不支持：{}", head[0]),
        ));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods)?;

    if !methods.contains(&METHOD_NO_AUTH) {
        sock.write_all(&[VER, METHOD_NONE_ACCEPTABLE])?;
        sock.flush()?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "客户端不支持「无认证」方式",
        ));
    }
    sock.write_all(&[VER, METHOD_NO_AUTH])?;
    sock.flush()?;

    // ── 请求 ──
    let mut req = [0u8; 4];
    sock.read_exact(&mut req)?;
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
            sock.read_exact(&mut b)?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b)?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len)?;
            let mut b = vec![0u8; len[0] as usize];
            sock.read_exact(&mut b)?;
            // SOCKS5 的域名不保证是合法 UTF-8，但真实场景都是。
            String::from_utf8_lossy(&b).into_owned()
        }
        other => {
            write_reply_reject(sock, REP_ADDRESS_TYPE_NOT_SUPPORTED)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("不支持的地址类型：{other}"),
            ));
        }
    };

    let mut port_b = [0u8; 2];
    sock.read_exact(&mut port_b)?;
    let port = u16::from_be_bytes(port_b);

    if cmd != CMD_CONNECT {
        write_reply_reject(sock, REP_COMMAND_NOT_SUPPORTED)?;
        return Ok(Request::Unsupported { cmd });
    }

    Ok(Request::Connect { host, port })
}

/// 回一条成功应答。
///
/// BND.ADDR/BND.PORT 填 0.0.0.0:0 —— 真实代理会填自己的出口地址，
/// 但没有客户端会依赖这个值（`curl` 不看它）。
pub fn write_reply_ok<S: Write>(sock: &mut S) -> io::Result<()> {
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
    ])?;
    sock.flush()
}

/// 回一条失败应答（隧道建立失败时用，让客户端立刻知道而不是干等）。
pub fn write_reply_failure<S: Write>(sock: &mut S) -> io::Result<()> {
    write_reply_reject(sock, REP_GENERAL_FAILURE)
}

fn write_reply_reject<S: Write>(sock: &mut S, rep: u8) -> io::Result<()> {
    sock.write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])?;
    sock.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// 起一对本地连接，把 `client_side` 的输出交给被测函数。
    fn with_pair<F>(client_side: F) -> io::Result<Request>
    where
        F: FnOnce(TcpStream) -> io::Result<()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let h = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            client_side(s).unwrap();
        });
        let mut server = TcpStream::connect(addr)?;
        let r = negotiate_and_read_request(&mut server);
        h.join().unwrap();
        r
    }

    #[test]
    fn parses_domain_connect_request() {
        let req = with_pair(|mut s| {
            s.write_all(&[5, 1, 0])?; // 问候：无认证
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply)?;
            assert_eq!(reply, [5, 0]);
            // CONNECT example.com:443
            s.write_all(&[5, 1, 0, 3, 11])?;
            s.write_all(b"example.com")?;
            s.write_all(&443u16.to_be_bytes())?;
            std::thread::sleep(std::time::Duration::from_millis(50));
            Ok(())
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
        let req = with_pair(|mut s| {
            s.write_all(&[5, 1, 0])?;
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply)?;
            s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1])?;
            s.write_all(&8080u16.to_be_bytes())?;
            std::thread::sleep(std::time::Duration::from_millis(50));
            Ok(())
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
        let req = with_pair(|mut s| {
            s.write_all(&[5, 1, 0])?;
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply)?;
            // BIND (0x02) —— 不支持
            s.write_all(&[5, 2, 0, 1, 127, 0, 0, 1])?;
            s.write_all(&8080u16.to_be_bytes())?;
            // 应答的第二个字节必须是 REP_COMMAND_NOT_SUPPORTED
            let mut reject = [0u8; 10];
            s.read_exact(&mut reject)?;
            assert_eq!(reject[0], 5);
            assert_eq!(reject[1], REP_COMMAND_NOT_SUPPORTED);
            Ok(())
        })
        .unwrap();

        assert_eq!(req, Request::Unsupported { cmd: 2 });
    }

    #[test]
    fn rejects_client_without_no_auth_method() {
        let err = with_pair(|mut s| {
            s.write_all(&[5, 1, 2])?; // 只提供用户名密码认证
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply)?;
            assert_eq!(reply, [5, METHOD_NONE_ACCEPTABLE]);
            Ok(())
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
