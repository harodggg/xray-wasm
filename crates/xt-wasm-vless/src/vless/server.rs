//! VLESS **服务端**方向：解析客户端发来的请求头。
//!
//! 与 `header::encode_request` 严格对称。线格式：
//!
//! ```text
//! version(1) | uuid(16) | addon_len(1) | addon(addon_len)
//!   | command(1) | port(2, BE) | addr_type(1) | addr(...)
//! ```
//!
//! * `addr_type`：`1` = IPv4(4B)、`2` = 域名(1B 长度 + n)、`3` = IPv6(16B)
//!   （注意顺序：**端口在地址类型之前**，这是 VLESS 特有的一处容易记反的地方）
//! * addon 为 flow 时是 `[0x0A][0x10][16 字节 "xtls-rprx-vision"]`
//!   （protobuf：field 1、wire type 2、长度 16）
//!
//! # 读取策略
//!
//! 用 `read_exact` **精确**读，绝不多读：多读的字节会吞掉本该转发给目标站的
//! 首批负载。调用方拿到的流位置正好停在 VLESS 头之后，可以直接接着转发。
//!
//! # 抗畸形输入
//!
//! 这个头来自**未经认证的网络**（认证只保证对方知道共享密钥，不保证它守规矩），
//! 所以长度字段一律校验，未知的 addr_type / command 一律拒绝，不允许 panic。

use tokio::io::{AsyncRead, AsyncReadExt};

use super::header::{Cmd, VlessAddr};
use crate::{MeowError, Result};

const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;
const ADDR_IPV6: u8 = 0x03;

/// 域名长度上限。VLESS 用 1 字节表示长度，所以上限就是 255。
const MAX_DOMAIN_LEN: usize = 255;

/// 解析出来的 VLESS 请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: u8,
    pub user_id: [u8; 16],
    pub command: Cmd,
    pub port: u16,
    pub addr: VlessAddr,
    /// 客户端声明的 flow（例如 `xtls-rprx-vision`）。没有则为 `None`。
    pub flow: Option<String>,
}

impl Request {
    /// 目标是否是我们支持的命令（目前只有 TCP）。
    pub fn is_tcp(&self) -> bool {
        matches!(self.command, Cmd::Tcp)
    }
}

fn bad(what: impl std::fmt::Display) -> MeowError {
    MeowError::Proxy(format!("VLESS 请求头畸形：{what}"))
}

async fn read_u8<R: AsyncRead + Unpin>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).await?;
    Ok(b[0])
}

/// 读一个 VLESS 请求头。
///
/// 成功返回后，流正好停在请求头之后 —— 后续字节是真正的载荷。
pub async fn decode_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request> {
    let version = read_u8(r).await?;
    if version != 0 {
        return Err(bad(format!("不支持的版本 {version}")));
    }

    let mut user_id = [0u8; 16];
    r.read_exact(&mut user_id).await?;

    let addon_len = read_u8(r).await? as usize;
    let mut addon = vec![0u8; addon_len];
    r.read_exact(&mut addon).await?;
    let flow = parse_flow_addon(&addon)?;

    let command = match read_u8(r).await? {
        0x01 => Cmd::Tcp,
        0x02 => Cmd::Udp,
        other => return Err(bad(format!("未知命令 {other:#04x}"))),
    };

    // 顺序：端口在地址类型之前
    let mut port_b = [0u8; 2];
    r.read_exact(&mut port_b).await?;
    let port = u16::from_be_bytes(port_b);

    let addr = match read_u8(r).await? {
        ADDR_IPV4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            VlessAddr::Ipv4(b)
        }
        ADDR_IPV6 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            VlessAddr::Ipv6(b)
        }
        ADDR_DOMAIN => {
            let len = read_u8(r).await? as usize;
            if len == 0 || len > MAX_DOMAIN_LEN {
                return Err(bad(format!("域名长度非法：{len}")));
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            // VLESS 不保证域名是合法 UTF-8；真实场景都是。
            VlessAddr::Domain(String::from_utf8_lossy(&b).into_owned())
        }
        other => return Err(bad(format!("未知地址类型 {other:#04x}"))),
    };

    Ok(Request {
        version,
        user_id,
        command,
        port,
        addr,
        flow,
    })
}

/// 解析 addon 里的 flow 字段。
///
/// 格式是 protobuf 的 `field 1, wire type 2`：`0x0A` `len` `<bytes>`。
/// 认不出来的 addon 一律当作「没有 flow」而不是报错 —— 上游以后可能加新字段，
/// 因为一个不认识的 addon 就断开连接并不合适。
fn parse_flow_addon(addon: &[u8]) -> Result<Option<String>> {
    if addon.is_empty() {
        return Ok(None);
    }
    // 0x0A = (field 1 << 3) | wire type 2
    if addon[0] != 0x0A {
        return Ok(None);
    }
    let Some(&len) = addon.get(1) else {
        return Err(bad("addon 声明了 flow 但没有长度"));
    };
    let len = len as usize;
    let body = addon
        .get(2..2 + len)
        .ok_or_else(|| bad("addon 声明的 flow 长度超出实际"))?;
    Ok(Some(String::from_utf8_lossy(body).into_owned()))
}

// ───────────── 入站编排：REALITY → VLESS → 目标 / dest 回退 ─────────────
//
// 到这里服务端才算**可用**。前面几个阶段只做到「能握手」；真正让 REALITY
// 成立的是两条路径都要走通：
//
//   授权客户端：握手 → 解 VLESS 头 → 连目标 → 双向转发
//   其他人    ：握手失败 → 把已读字节补发给 dest → 双向转发
//
// 第二条不是「错误处理」，而是 REALITY 的**抗主动探测机制本身**：
// 探测者看到的必须是真实网站的正常响应，任何异常（连接被断、TLS 告警）都等于自我暴露。

use tokio::io::AsyncWriteExt;
use xt_wasm_runtime::{connect, relay_bidirectional, Stream};
use xt_wasm_tls::{reality_server_handshake, HandshakeOutcome, RealityServerConfig};

/// 入站配置。
#[derive(Debug, Clone)]
pub struct InboundConfig {
    pub reality: RealityServerConfig,
    /// 认证失败时**原样转发**到哪（通常是伪装用的真实站点）。
    pub dest: String,
    /// 允许的 VLESS 用户 UUID。空列表表示不接受任何用户。
    pub users: Vec<[u8; 16]>,
}

/// 一条连接最终走了哪条路。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundOutcome {
    /// 授权用户，已转发到目标
    Forwarded { target: String },
    /// 未通过认证，已转发到 dest（探测者看到的是一次普通访问）
    FellBack,
}

fn to_meow(e: xt_wasm_tls::TransportError) -> MeowError {
    MeowError::Proxy(format!("REALITY 服务端：{e}"))
}

/// 把 VLESS 地址渲染成 `host:port`（IPv6 加方括号）。
fn addr_to_target(addr: &VlessAddr, port: u16) -> String {
    match addr {
        VlessAddr::Ipv4(o) => format!("{}.{}.{}.{}:{port}", o[0], o[1], o[2], o[3]),
        VlessAddr::Ipv6(o) => format!("[{}]:{port}", std::net::Ipv6Addr::from(*o)),
        VlessAddr::Domain(d) => format!("{d}:{port}"),
    }
}

/// 处理一条入站连接直到转发结束。
pub async fn serve_inbound(stream: Box<dyn Stream>, cfg: &InboundConfig) -> Result<InboundOutcome> {
    match reality_server_handshake(stream, &cfg.reality)
        .await
        .map_err(to_meow)?
    {
        HandshakeOutcome::Authenticated { mut stream, .. } => {
            let req = decode_request(&mut stream).await?;

            // 认证只证明对方知道共享密钥，不代表这个 UUID 被允许
            if !cfg.users.iter().any(|u| u == &req.user_id) {
                return Err(MeowError::ProxyAuthFailed);
            }
            if !req.is_tcp() {
                return Err(MeowError::NotSupported(
                    "服务端目前只实现了 VLESS TCP".into(),
                ));
            }

            // 客户端请求了 Vision 流控，但服务端侧还没实现。
            // **必须在这里明确拒绝，不能装作没看见** —— Vision 会把负载包进填充帧，
            // 不拆帧就会把这些字节当成原始数据发给目标站，输出是错的却不报错，
            // 属于最难排查的那类故障。
            if let Some(flow) = req.flow.as_deref() {
                if !flow.is_empty() {
                    return Err(MeowError::NotSupported(format!(
                        "服务端尚未实现 Vision 流控（客户端请求了 flow={flow}）；\
                         请把客户端 flow 置空，或等待服务端支持"
                    )));
                }
            }

            let target = addr_to_target(&req.addr, req.port);
            let outbound = connect(&target)
                .await
                .map_err(|e| MeowError::Proxy(format!("连接目标 {target} 失败：{e}")))?;

            // **必须回一条 VLESS 响应头**：`[version=0][addon_len=0]`。
            // 客户端连接建立后会先读这两个字节再读负载；不发的话它会把负载的
            // 第一个字节当成版本号。这个细节是集成测试抓出来的
            // （症状是 `version mismatch: expected 0x00, got 0x68`，0x68 正是
            // 负载首字符 'h'）。
            stream.write_all(&[0x00, 0x00]).await?;
            stream.flush().await?;

            relay_bidirectional(Box::new(stream), Box::new(outbound)).await?;
            Ok(InboundOutcome::Forwarded { target })
        }

        HandshakeOutcome::Fallback {
            stream, buffered, ..
        } => {
            let mut outbound = connect(&cfg.dest)
                .await
                .map_err(|e| MeowError::Proxy(format!("连接 dest {} 失败：{e}", cfg.dest)))?;

            // **先把已经读走的字节补发给 dest**。认证流程要读 ClientHello 才能判断，
            // 那一段已经被我们消费了；不补发的话 dest 看到的是半截握手，会直接断开。
            outbound.write_all(&buffered).await?;
            outbound.flush().await?;

            relay_bidirectional(stream, Box::new(outbound)).await?;
            Ok(InboundOutcome::FellBack)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── 入站编排：授权客户端转发 / 未授权回退 ─────────────────────────

    /// 起一个本机 echo 服务，返回它的地址。
    fn spawn_echo() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                    let _ = s.flush();
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        });
        addr
    }

    /// **端到端**：授权客户端 → 我们的入站 → 本机 echo 目标，数据原样往返。
    ///
    /// 覆盖整条服务端链路：REALITY 握手 → VLESS 解码 → 连目标 → 双向转发。
    #[test]
    fn inbound_forwards_authorized_client_to_target() {
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::block_on;
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        const SNI: &str = "www.cloudflare.com";
        const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let uuid = [0x11u8; 16];

        let echo = spawn_echo();

        let server_priv = xt_wasm_tls::test_support::fixture_private_key();
        let server_pub = xt_wasm_tls::test_support::public_from_private(&server_priv);

        let inbound = InboundConfig {
            reality: RealityServerConfig {
                private_key: server_priv,
                short_ids: vec![SHORT_ID],
                server_names: vec![SNI.to_string()],
                max_time_diff_secs: 60,
            },
            // 这条用例不该走到回退，随便给一个不可达地址即可
            dest: "127.0.0.1:9".to_string(),
            users: vec![uuid],
        };
        let client_cfg = RealityConfig {
            public_key: server_pub,
            short_id: SHORT_ID,
            client_version: [26, 3, 27],
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let echo_port = echo.port();

        let (outcome, got) = block_on(async {
            futures::join!(serve_inbound(Box::new(server_io), &inbound), async {
                let tls = reality_handshake(Box::new(client_io), SNI, &[], &client_cfg)
                    .await
                    .expect("客户端握手");
                // flow 置空：服务端尚未实现 Vision（见 serve_inbound 里的守卫）
                let mut vless = VlessConn::new_deferred(
                    Box::new(tls),
                    &uuid,
                    None,
                    Cmd::Tcp,
                    echo_port,
                    &VlessAddr::Ipv4([127, 0, 0, 1]),
                )
                .await
                .expect("VLESS 请求头");

                vless.write_all(b"hello through reality").await.expect("写");
                vless.flush().await.expect("flush");
                let mut buf = [0u8; 128];
                let n = vless.read(&mut buf).await.expect("读");
                buf[..n].to_vec()
            })
        });

        assert_eq!(
            got, b"hello through reality",
            "目标站回显应原样返回（说明 VLESS 解码与双向转发都对了）"
        );
        assert!(
            matches!(
                outcome.expect("入站不应报错"),
                InboundOutcome::Forwarded { .. }
            ),
            "授权客户端应当走转发路径"
        );
    }

    /// 未授权的 UUID 必须被拒（认证过了不等于这个用户被允许）。
    #[test]
    fn inbound_rejects_unknown_user_id() {
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use tokio::io::AsyncWriteExt;
        use xt_wasm_runtime::block_on;
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        const SNI: &str = "www.cloudflare.com";
        const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        let server_priv = xt_wasm_tls::test_support::fixture_private_key();
        let server_pub = xt_wasm_tls::test_support::public_from_private(&server_priv);

        let inbound = InboundConfig {
            reality: RealityServerConfig {
                private_key: server_priv,
                short_ids: vec![SHORT_ID],
                server_names: vec![SNI.to_string()],
                max_time_diff_secs: 60,
            },
            dest: "127.0.0.1:9".to_string(),
            // 只允许另一个 UUID
            users: vec![[0x99u8; 16]],
        };
        let client_cfg = RealityConfig {
            public_key: server_pub,
            short_id: SHORT_ID,
            client_version: [26, 3, 27],
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (outcome, ()) = block_on(async {
            futures::join!(serve_inbound(Box::new(server_io), &inbound), async {
                let tls = reality_handshake(Box::new(client_io), SNI, &[], &client_cfg)
                    .await
                    .expect("客户端握手仍会成功（认证是另一回事）");
                if let Ok(mut vless) = VlessConn::new_deferred(
                    Box::new(tls),
                    &[0x11u8; 16], // 不在允许列表里
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([127, 0, 0, 1]),
                )
                .await
                {
                    // `new_deferred` 把请求头**延迟到第一次写**才发出去
                    // （为了让请求搭上首个 Vision 帧）。不写的话服务端只会看到 EOF。
                    let _ = vless.write_all(b"x").await;
                    let _ = vless.flush().await;
                }
            })
        });

        let err = outcome.expect_err("未授权 UUID 必须被拒");
        assert!(
            matches!(err, MeowError::ProxyAuthFailed),
            "应当是认证失败，实际 {err:?}"
        );
    }

    /// 请求了 Vision 流控时必须明确报错，而不是把填充帧当成原始数据发出去。
    #[test]
    fn inbound_rejects_vision_flow_instead_of_misreading_bytes() {
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use xt_wasm_runtime::block_on;
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        const SNI: &str = "www.cloudflare.com";
        const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let uuid = [0x11u8; 16];

        let server_priv = xt_wasm_tls::test_support::fixture_private_key();
        let server_pub = xt_wasm_tls::test_support::public_from_private(&server_priv);

        let inbound = InboundConfig {
            reality: RealityServerConfig {
                private_key: server_priv,
                short_ids: vec![SHORT_ID],
                server_names: vec![SNI.to_string()],
                max_time_diff_secs: 60,
            },
            dest: "127.0.0.1:9".to_string(),
            users: vec![uuid],
        };
        let client_cfg = RealityConfig {
            public_key: server_pub,
            short_id: SHORT_ID,
            client_version: [26, 3, 27],
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (outcome, ()) = block_on(async {
            futures::join!(serve_inbound(Box::new(server_io), &inbound), async {
                let tls = reality_handshake(Box::new(client_io), SNI, &[], &client_cfg)
                    .await
                    .expect("握手");
                if let Ok(mut vless) = VlessConn::new_deferred(
                    Box::new(tls),
                    &uuid,
                    Some("xtls-rprx-vision"),
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([127, 0, 0, 1]),
                )
                .await
                {
                    // 同上：触发延迟写的请求头
                    let _ = vless.write_all(b"x").await;
                    let _ = vless.flush().await;
                }
            })
        });

        let err = outcome.expect_err("请求 Vision 时必须明确报错");
        assert!(
            err.to_string().contains("Vision"),
            "错误信息应当点明 Vision，实际：{err}"
        );
    }

    /// **回退路径**：未授权客户端必须被**原样转发**到 dest，而不是被断开。
    ///
    /// 这是 REALITY 抗主动探测的根本 —— 探测者看到的应当是一次普通网站访问。
    /// 这里用一个假的 dest 记录它收到的字节，验证两件事：
    ///   1. 服务端确实去连了 dest；
    ///   2. **已经读走的 ClientHello 被补发了**（否则 dest 看到的是半截握手）。
    #[test]
    fn inbound_falls_back_to_dest_and_replays_buffered_bytes() {
        use std::io::Read;
        use std::sync::mpsc;
        use std::time::Duration;
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        // 假的 dest：收到什么就回报什么
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dest");
        let dest_addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                // **必须一直读到 EOF 再关**：只读几个字节就 close 的话，
                // 接收缓冲里还有未读数据，OS 会给对端发 RST，
                // 服务端的中继就会拿到 ConnectionReset 而不是正常结束。
                let mut all = Vec::new();
                let mut buf = [0u8; 1024];
                let mut sent = false;
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            all.extend_from_slice(&buf[..n]);
                            if !sent && all.len() >= 8 {
                                let _ = tx.send(all[..8].to_vec());
                                sent = true;
                            }
                        }
                    }
                }
            }
        });

        let server_priv = xt_wasm_tls::test_support::fixture_private_key();
        let inbound = InboundConfig {
            reality: RealityServerConfig {
                private_key: server_priv,
                short_ids: vec![[1, 2, 3, 4, 5, 6, 7, 8]],
                server_names: vec!["www.cloudflare.com".to_string()],
                max_time_diff_secs: 60,
            },
            dest: dest_addr.to_string(),
            users: vec![[0x11u8; 16]],
        };

        // 客户端拿**别的**公钥 —— 服务端解不开 session_id，走回退
        let wrong_priv = {
            let mut k = [0x99u8; 32];
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
            k
        };
        let client_cfg = RealityConfig {
            public_key: xt_wasm_tls::test_support::public_from_private(&wrong_priv),
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            client_version: [26, 3, 27],
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let outcome = xt_wasm_runtime::block_on(async {
            let (out, ()) = futures::join!(serve_inbound(Box::new(server_io), &inbound), async {
                // **必须加超时**：回退路径下服务端什么都不会回给客户端，
                // 而 `reality_handshake` 会一直等 ServerHello。
                // 不加超时它就一直握着连接，中继两端都不结束 —— 测试直接挂死。
                let _ = xt_wasm_runtime::timeout(
                    Duration::from_millis(500),
                    reality_handshake(Box::new(client_io), "www.cloudflare.com", &[], &client_cfg),
                )
                .await;
            });
            out
        });

        assert!(
            matches!(outcome.expect("回退本身不应报错"), InboundOutcome::FellBack),
            "未授权客户端应当走回退路径"
        );

        let received = rx
            .recv_timeout(Duration::from_secs(3))
            .expect("dest 应当收到转发过来的字节");
        assert!(!received.is_empty(), "dest 收到的不能是空");
        assert_eq!(
            received[0], 0x16,
            "dest 收到的应当以 TLS 握手记录开头（说明已读的 ClientHello 被补发了），实际 {:02x?}",
            received
        );
    }
    use crate::vless::header::encode_request;
    use bytes::BytesMut;

    /// 走一遍编码 → 解码，验证两侧严格对称。
    async fn roundtrip(flow: Option<&str>, port: u16, addr: VlessAddr) -> Request {
        let uuid = [0xABu8; 16];
        let mut buf = BytesMut::new();
        encode_request(&mut buf, &uuid, flow, Cmd::Tcp, port, &addr);
        let bytes = buf.to_vec();

        let mut cursor = std::io::Cursor::new(bytes);
        decode_request(&mut cursor).await.expect("解码应当成功")
    }

    #[test]
    fn roundtrip_domain_with_vision_flow() {
        let req = xt_wasm_runtime::block_on(roundtrip(
            Some("xtls-rprx-vision"),
            443,
            VlessAddr::Domain("example.com".into()),
        ));
        assert_eq!(req.version, 0);
        assert_eq!(req.user_id, [0xABu8; 16]);
        assert_eq!(req.port, 443);
        assert_eq!(req.addr, VlessAddr::Domain("example.com".into()));
        assert_eq!(req.flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(req.is_tcp());
    }

    #[test]
    fn roundtrip_ipv4_without_flow() {
        let req = xt_wasm_runtime::block_on(roundtrip(None, 8080, VlessAddr::Ipv4([1, 2, 3, 4])));
        assert_eq!(req.addr, VlessAddr::Ipv4([1, 2, 3, 4]));
        assert_eq!(req.port, 8080);
        assert_eq!(req.flow, None);
    }

    #[test]
    fn roundtrip_ipv6() {
        let v6 = [0x20u8, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let req = xt_wasm_runtime::block_on(roundtrip(None, 53, VlessAddr::Ipv6(v6)));
        assert_eq!(req.addr, VlessAddr::Ipv6(v6));
    }

    /// **跨实现向量**：这段字节是**官方 Xray 客户端**真实发出来的 VLESS 请求头。
    ///
    /// 它来自 `examples/reality_server_probe.rs` 的互通验证 —— 官方客户端与我们的
    /// REALITY 服务端握手成功后发来的第一批应用数据。用真数据而不是自己构造的，
    /// 才能真正验证解码器对不对。
    const OFFICIAL_CLIENT_REQUEST_HEX: &str = concat!(
        "00",                                   // version
        "b21e29c8a8ea40a2b953c2b04d73d775",     // uuid
        "12",                                   // addon_len = 18
        "0a1078746c732d727072782d766973696f6e", // flow = xtls-rprx-vision
        "01",                                   // command = TCP
        "01bb",                                 // port = 443
        "02",                                   // addr_type = domain
        "0b",                                   // 域名长度 11
        "6578616d706c652e636f6d",               // "example.com"
    );

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn decodes_official_xray_client_request_header() {
        let bytes = hex_to_bytes(OFFICIAL_CLIENT_REQUEST_HEX);
        let mut cursor = std::io::Cursor::new(bytes);
        let req = xt_wasm_runtime::block_on(decode_request(&mut cursor))
            .expect("官方客户端的请求头必须能解出来");

        assert_eq!(
            req.user_id,
            [
                0xb2, 0x1e, 0x29, 0xc8, 0xa8, 0xea, 0x40, 0xa2, 0xb9, 0x53, 0xc2, 0xb0, 0x4d, 0x73,
                0xd7, 0x75
            ]
        );
        assert_eq!(req.flow.as_deref(), Some("xtls-rprx-vision"));
        assert!(req.is_tcp());
        assert_eq!(req.port, 443);
        assert_eq!(req.addr, VlessAddr::Domain("example.com".into()));
    }

    /// 多读一个字节都不能发生：请求头之后就是本该转发给目标站的负载。
    #[test]
    fn decode_stops_exactly_after_the_header() {
        let mut bytes = hex_to_bytes(OFFICIAL_CLIENT_REQUEST_HEX);
        let header_len = bytes.len();
        bytes.extend_from_slice(b"PAYLOAD"); // 模拟紧随其后的首批负载

        let mut cursor = std::io::Cursor::new(bytes);
        xt_wasm_runtime::block_on(decode_request(&mut cursor)).expect("解码");

        let pos = cursor.position() as usize;
        assert_eq!(pos, header_len, "必须正好停在请求头末尾");
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut cursor, &mut rest).unwrap();
        assert_eq!(rest, b"PAYLOAD", "后续负载不能被吞掉");
    }

    // ─── 畸形输入：未经认证的网络来的数据，不能 panic ──────────────

    #[test]
    fn rejects_malformed_headers_without_panicking() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x01],     // 版本不为 0
            vec![0x00],     // uuid 不全
            vec![0x00; 17], // 只到 uuid，没有 addon_len
            {
                let mut v = vec![0x00];
                v.extend_from_slice(&[0u8; 16]);
                v.push(40); // 声称 addon 有 40 字节但没有
                v
            },
            {
                let mut v = vec![0x00];
                v.extend_from_slice(&[0u8; 16]);
                v.push(0); // 无 addon
                v.push(0x09); // 未知命令
                v
            },
            {
                let mut v = vec![0x00];
                v.extend_from_slice(&[0u8; 16]);
                v.push(0);
                v.push(0x01); // TCP
                v.extend_from_slice(&[0x01, 0xbb]);
                v.push(0x07); // 未知地址类型
                v
            },
            {
                let mut v = vec![0x00];
                v.extend_from_slice(&[0u8; 16]);
                v.push(0);
                v.push(0x01);
                v.extend_from_slice(&[0x01, 0xbb]);
                v.push(0x02); // 域名
                v.push(0); // 长度 0，非法
                v
            },
        ];
        for (i, c) in cases.iter().enumerate() {
            let mut cursor = std::io::Cursor::new(c.clone());
            let r = xt_wasm_runtime::block_on(decode_request(&mut cursor));
            assert!(r.is_err(), "第 {i} 个畸形输入应当被拒绝");
        }
    }

    /// 认不出的 addon 不应当导致断连（上游以后可能加字段）。
    #[test]
    fn unknown_addon_is_tolerated() {
        let mut v = vec![0x00];
        v.extend_from_slice(&[0u8; 16]);
        v.push(3);
        v.extend_from_slice(&[0x99, 0x01, 0x02]); // 不认识的 addon
        v.push(0x01);
        v.extend_from_slice(&[0x00, 0x50]);
        v.push(0x01);
        v.extend_from_slice(&[127, 0, 0, 1]);

        let mut cursor = std::io::Cursor::new(v);
        let req = xt_wasm_runtime::block_on(decode_request(&mut cursor)).expect("应当容忍");
        assert_eq!(req.flow, None);
        assert_eq!(req.port, 80);
    }
}
