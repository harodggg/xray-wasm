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
// `TransportError` 由 xt-wasm-tls 转出（它就是 xt-wasm-runtime 的那一个类型）。
use xt_wasm_tls::TransportError;
/// 入站配置。
#[derive(Debug, Clone)]
pub struct InboundConfig {
    pub reality: RealityServerConfig,
    /// 认证失败时**原样转发**到哪（通常是伪装用的真实站点）。
    pub dest: String,
    /// 允许的 VLESS 用户 UUID。空列表表示不接受任何用户。
    pub users: Vec<[u8; 16]>,
}

/// 一条连接最终**怎么了**。这是日志里 `outcome=` 字段的全部取值。
///
/// 刻意做成「分类」而不是「错误」：除了 `EmptyConnection`，其余每一个都是
/// 服务端**正常处理完毕**的结果 —— 包括它决定拒绝、以及它连不上目标。
/// 于是 `serve_inbound*` 的 `Err` 只剩一种含义：**服务端自己坏了**。
/// 这个区分让调用方不必再从错误字符串里猜发生了什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundOutcome {
    /// 授权用户，已转发到目标（字节数在 [`InboundReport`] 上）。
    Forwarded,
    /// 未通过 REALITY 认证，已原样转发到 `dest`（探测者看到的是一次普通访问）。
    FellBack,
    /// 请求没被接受：用户不在名单里 / 不是 TCP / 声明了服务端还不支持的 flow。
    ///
    /// `reason` 是**给运维看的**，必须写清「客户端要怎么改」，不能只说「不支持」。
    Rejected { reason: String },
    /// 目标域名解析失败（DNS 问题，与「端口没人听」是两回事）。
    ResolveFailed { reason: String },
    /// 解析到了地址但连不上（端口没开、被防火墙挡、目标拒绝）。
    ConnectFailed { reason: String },
    /// 对端连上后一个字节没发就关了。
    ///
    /// 这**不是失败**：k8s 的 `tcpSocket` 探针、端口扫描器、LB 健康检查
    /// 都长这样，而且是公网端口上最频繁的事件。单独成一类，
    /// 调用方才能对它静音，不至于让探针淹没真正的错误。
    EmptyConnection,
}

/// 一条连接的**完整结局**：分类 + 足以写出一行可排障日志的全部上下文。
///
/// 为什么把上下文和分类分开而不是塞进枚举变体：这十几个字段里有几个是
/// 「有没有走到那一步才知道」（比如 `short_id` 要握手成功、`target` 要 VLESS 解出来），
/// 塞进变体会让每个变体都长出一堆 `Option`，匹配起来反而更乱。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundReport {
    pub outcome: InboundOutcome,
    /// ClientHello 里的 SNI。握手成功就有。
    pub server_name: Option<String>,
    /// 客户端上报的 REALITY ClientVer。握手成功就有。
    pub client_version: Option<[u8; 3]>,
    /// 客户端上报的 shortId。握手成功就有。
    pub short_id: Option<[u8; 8]>,
    /// VLESS 请求里的目标 `host:port`。解出请求头才有。
    pub target: Option<String>,
    /// 客户端 → 目标 的字节数。
    pub up_bytes: u64,
    /// 目标 → 客户端 的字节数。
    pub down_bytes: u64,
}

impl InboundReport {
    /// 只带一个分类的最小报告。
    fn bare(outcome: InboundOutcome) -> Self {
        Self {
            outcome,
            server_name: None,
            client_version: None,
            short_id: None,
            target: None,
            up_bytes: 0,
            down_bytes: 0,
        }
    }

    /// 这条连接是不是「连上就关」的空连接（调用方通常要对它静音）。
    pub fn is_empty_connection(&self) -> bool {
        matches!(self.outcome, InboundOutcome::EmptyConnection)
    }
}

/// 连接**刚做出判定**时发出的事件，早于任何字节被转发。
///
/// 为什么需要它：`InboundOutcome` 要等整条连接结束（长连接可能几小时）才返回，
/// 只靠它会得到一个「连接断开时才知道曾经连上过」的日志 —— 运维上没用，
/// 测试里也只能靠 sleep 猜时机。服务端必须能在连接**建立的当下**说话。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundEvent {
    /// REALITY 认证通过、VLESS 请求头解析完成。
    ///
    /// **此时还没有判定 user / cmd / flow 是否被接受** —— 那三件事的结果在
    /// [`InboundOutcome`] 里（`Forwarded` 还是 `Rejected`）。这里给的是身份，
    /// 它的用途是「这条连接是谁发来的」：多客户端/多配置时，
    /// 一个 `short_id` 就能定位到是哪一份配置出了问题。
    Authenticated {
        user: [u8; 16],
        target: String,
        /// 客户端上报的 REALITY ClientVer。
        client_version: [u8; 3],
        /// 客户端上报的 shortId。
        short_id: [u8; 8],
        /// ClientHello 里的 SNI（客户端没发就是 `None`）。
        server_name: Option<String>,
    },
    /// 未通过 REALITY 认证，按陌生流量原样转发到 `dest`。
    Fallback { server_name: Option<String> },
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
///
/// 返回值里的 [`InboundReport`] 带着这条连接的**完整结局**（分类 + SNI + 身份 +
/// 目标 + 字节数），足以写出一行可排障的日志。
///
/// 想在连接**建立时**就收到通知（而不是等它结束），用
/// [`serve_inbound_with_events`]。
///
/// # `Ok` / `Err` 的分工
///
/// `Ok` 表示服务端**正常处理完了**这条连接 —— 包括它决定拒绝、以及它连不上目标。
/// `Err` 只剩「服务端自己出了问题」（握手内部错误、转发中途 IO 失败等）。
/// 这样调用方不必再从错误字符串里猜发生了什么。
pub async fn serve_inbound(stream: Box<dyn Stream>, cfg: &InboundConfig) -> Result<InboundReport> {
    serve_inbound_with_events(stream, cfg, |_| {}).await
}

/// 同 [`serve_inbound`]，但在**拿到身份的当下**回调 `on_event`。
///
/// 回调时机早于任何字节被转发，所以：
/// * 它可以安全地打日志/记指标；
/// * 它不能阻塞（整个 future 是单线程跑的），别在里面做 IO。
pub async fn serve_inbound_with_events<F>(
    stream: Box<dyn Stream>,
    cfg: &InboundConfig,
    mut on_event: F,
) -> Result<InboundReport>
where
    F: FnMut(InboundEvent),
{
    // ── 1) REALITY 握手 ──
    let handshake = match reality_server_handshake(stream, &cfg.reality).await {
        Ok(h) => h,
        // 空连接在这里就终结：不当作错误往上抛。
        // 抛成 Err 的话，每个调用方都得去字符串匹配「是不是那个 EOF」才能静音，
        // 而总有人会忘 —— 于是 k8s 探针每 10 秒刷一条错误日志。
        Err(TransportError::EmptyConnection) => {
            return Ok(InboundReport::bare(InboundOutcome::EmptyConnection));
        }
        Err(e) => return Err(to_meow(e)),
    };

    match handshake {
        // ── 2) 授权路径 ──
        HandshakeOutcome::Authenticated {
            mut stream,
            auth,
            server_name,
        } => {
            let base = InboundReport {
                outcome: InboundOutcome::Rejected {
                    reason: String::new(),
                },
                server_name: server_name.clone(),
                client_version: Some(auth.client_version),
                short_id: Some(auth.short_id),
                target: None,
                up_bytes: 0,
                down_bytes: 0,
            };

            // VLESS 请求头解不出来：可能是客户端根本不是 VLESS，或版本对不上。
            // 注意这**不能**回退到 dest —— 此时我们已经用一个真证书完成了握手，
            // 半路改道只会让对端看到更奇怪的东西。明确拒绝并记下原因。
            let req = match decode_request(&mut stream).await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(InboundReport {
                        outcome: InboundOutcome::Rejected {
                            reason: format!(
                                "VLESS 请求头解析失败：{e}；\
                                 请确认客户端是 VLESS（而不是 VMess/Trojan），\
                                 且与服务端版本兼容"
                            ),
                        },
                        ..base
                    });
                }
            };

            let target = addr_to_target(&req.addr, req.port);

            // 身份在这一刻就齐了。**早于** user/cmd/flow 的判定发出，
            // 这样被拒绝的连接在日志里也能指名道姓（否则运维只能看到
            // 一句「有个连接被拒了」，无从知道是哪台设备/哪份配置）。
            on_event(InboundEvent::Authenticated {
                user: req.user_id,
                target: target.clone(),
                client_version: auth.client_version,
                short_id: auth.short_id,
                server_name: server_name.clone(),
            });

            let base = InboundReport {
                target: Some(target.clone()),
                ..base
            };

            // 认证只证明对方知道共享密钥，不代表这个 UUID 被允许
            if !cfg.users.iter().any(|u| u == &req.user_id) {
                return Ok(InboundReport {
                    outcome: InboundOutcome::Rejected {
                        reason: format!(
                            "REALITY 认证已通过，但该 UUID 不在服务端 users 名单里（user={}）；\
                             请把客户端的 id 改成 XT_USERS 里的某一个",
                            format_uuid(&req.user_id)
                        ),
                    },
                    ..base
                });
            }

            if !req.is_tcp() {
                return Ok(InboundReport {
                    outcome: InboundOutcome::Rejected {
                        reason: format!(
                            "服务端目前只实现了 VLESS TCP（收到 cmd={:?}，即 UDP）；\
                             请在客户端关闭 UDP/QUIC 与 mux（udp:false / mux:false）后重试",
                            req.command
                        ),
                    },
                    ..base
                });
            }

            // 客户端请求了 Vision 流控，但服务端侧还没实现。
            // **必须在这里明确拒绝，不能装作没看见** —— Vision 会把负载包进填充帧，
            // 不拆帧就会把这些字节当成原始数据发给目标站，输出是错的却不报错，
            // 属于最难排查的那类故障。
            if let Some(flow) = req.flow.as_deref() {
                if !flow.is_empty() {
                    return Ok(InboundReport {
                        outcome: InboundOutcome::Rejected {
                            reason: format!(
                                "服务端尚未实现 Vision 流控（客户端请求了 flow={flow}）；\
                                 请在客户端把 flow 置空（官方 Xray 写 flow:\"\"），\
                                 或改用本工程客户端并加 --no-flow"
                            ),
                        },
                        ..base
                    });
                }
            }

            // ── 解析与连接分开 ──
            // 这两步的排查方向完全不同：解析失败是 DNS/域名问题，
            // 连不上是「端口没人听 / 被防火墙挡」。混成一句 connect failed
            // 等于把排障成本推给运维。
            let addrs = match xt_wasm_runtime::resolve(&target) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(InboundReport {
                        outcome: InboundOutcome::ResolveFailed {
                            reason: resolve_hint("目标", &target, &e),
                        },
                        ..base
                    });
                }
            };

            let outbound = match connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    return Ok(InboundReport {
                        outcome: InboundOutcome::ConnectFailed {
                            reason: format!(
                                "连接目标 {target}（解析为 {addrs:?}）失败：{e}；\
                                 若为 remote-unreachable，先确认该端口确实有服务在监听，\
                                 且本服务端的 egress 未被 NetworkPolicy 挡住"
                            ),
                        },
                        ..base
                    });
                }
            };

            // **必须回一条 VLESS 响应头**：`[version=0][addon_len=0]`。
            // 客户端连接建立后会先读这两个字节再读负载；不发的话它会把负载的
            // 第一个字节当成版本号。这个细节是集成测试抓出来的
            // （症状是 `version mismatch: expected 0x00, got 0x68`，0x68 正是
            // 负载首字符 'h'）。
            stream.write_all(&[0x00, 0x00]).await?;
            stream.flush().await?;

            let stats = relay_bidirectional(Box::new(stream), Box::new(outbound)).await?;
            Ok(InboundReport {
                outcome: InboundOutcome::Forwarded,
                up_bytes: stats.up,
                down_bytes: stats.down,
                ..base
            })
        }

        // ── 3) 回退路径（抗主动探测）──
        HandshakeOutcome::Fallback {
            stream,
            buffered,
            server_name,
        } => {
            on_event(InboundEvent::Fallback {
                server_name: server_name.clone(),
            });

            let base = InboundReport {
                outcome: InboundOutcome::FellBack,
                server_name,
                client_version: None,
                short_id: None,
                target: Some(cfg.dest.clone()),
                up_bytes: 0,
                down_bytes: 0,
            };

            let addrs = match xt_wasm_runtime::resolve(&cfg.dest) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(InboundReport {
                        outcome: InboundOutcome::ResolveFailed {
                            reason: resolve_hint("dest", &cfg.dest, &e),
                        },
                        ..base
                    });
                }
            };

            let mut outbound = match connect(&cfg.dest).await {
                Ok(s) => s,
                Err(e) => {
                    return Ok(InboundReport {
                        outcome: InboundOutcome::ConnectFailed {
                            reason: format!(
                                "连接 dest {}（解析为 {addrs:?}）失败：{e}；\
                                 dest 不可达时抗主动探测会**失效**（探测者拿不到真实站点），\
                                 请优先修好它",
                                cfg.dest
                            ),
                        },
                        ..base
                    });
                }
            };

            // **先把已经读走的字节补发给 dest**。认证流程要读 ClientHello 才能判断，
            // 那一段已经被我们消费了；不补发的话 dest 看到的是半截握手，会直接断开。
            outbound.write_all(&buffered).await?;
            outbound.flush().await?;

            let stats = relay_bidirectional(stream, Box::new(outbound)).await?;
            Ok(InboundReport {
                up_bytes: stats.up,
                down_bytes: stats.down,
                ..base
            })
        }
    }
}

/// 给解析失败配一句**能直接照着做**的提示。
///
/// # 为什么不能只写一句「解析失败」
///
/// 实测过两种完全不同的解析失败，排查方向相反：
///
/// * `Permission denied` —— 宿主没给 `ip-name-lookup` 能力（wasmtime 漏了
///   `-S allow-ip-name-lookup=y`）。**改配置**就好。
/// * `Name does not resolve` / 超时 —— 解析器本身没能作答。**改配置没用**，
///   要去查宿主（或容器）的 DNS。实测在 wasmtime 上这类失败会**卡满 30 秒**
///   才返回，于是现象是「每个请求都慢 30 秒然后失败」，很容易被误判成
///   「隧道不通」。
///
/// 把这两种混成一句话，就等于把排查成本又推回给运维 —— 而这正是本次改动
/// 要消灭的东西。
fn resolve_hint(what: &str, host: &str, e: &std::io::Error) -> String {
    let raw = e.to_string();
    let denied = raw.contains("Permission denied")
        || raw.contains("permission denied")
        || e.kind() == std::io::ErrorKind::PermissionDenied;
    if denied {
        format!(
            "解析{what} {host} 失败：{raw}；\
             这是**宿主缺少 ip-name-lookup 能力**，不是网络问题 —— \
             请在 wasmtime 参数里加上 -S allow-ip-name-lookup=y \
             （k8s 下检查运行时清单是否透传了该 flag）"
        )
    } else {
        format!(
            "解析{what} {host} 失败：{raw}；\
             解析器没能作答（不是权限问题，加 -S allow-ip-name-lookup=y 无效）。\
             若耗时接近 30 秒，说明是 DNS 超时：请检查宿主/容器的 DNS 配置，\
             或把 {host} 换成 IP 字面量以绕开解析（IP 不经过 DNS，也不阻塞事件循环）"
        )
    }
}

/// 把 UUID 渲染回 `8-4-4-4-12` 的规范形式，供拒绝原因里点名用。
fn format_uuid(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
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
                outcome.expect("入站不应报错").outcome,
                InboundOutcome::Forwarded
            ),
            "授权客户端应当走转发路径"
        );
    }

    /// 事件必须在**转发完成之前**发出。
    ///
    /// 这条用例不是在测「事件能不能发」——那太弱了——而是在测发生时序。
    /// 关键在于**客户端全程不读回包**，只是等事件出现：
    /// 如果事件是转发结束后才发的，双向转发会一直卡着，事件永远不出现，
    /// 这里就会超时失败。而这正是「服务端日志有没有用」的分界线 ——
    /// 长连接上，事后才写的日志等于没有日志。
    ///
    /// 注意不能断言「客户端写入返回时事件已就绪」：`tokio::io::duplex` 是内存管道，
    /// 写入会先落进缓冲区，服务端甚至还没被 poll 到。
    #[test]
    fn inbound_emits_authenticated_event_before_relaying() {
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use std::cell::RefCell;
        use std::rc::Rc;
        use std::time::{Duration, Instant};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::{block_on, yield_now};
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        const SNI: &str = "www.cloudflare.com";
        const SHORT_ID: [u8; 8] = [2, 3, 4, 5, 6, 7, 8, 9];
        let uuid = [0x22u8; 16];
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
            dest: "127.0.0.1:9".to_string(),
            users: vec![uuid],
        };

        let events: Rc<RefCell<Vec<InboundEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let events_srv = Rc::clone(&events);
        let events_cli = Rc::clone(&events);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let echo_port = echo.port();

        block_on(async {
            let server = serve_inbound_with_events(Box::new(server_io), &inbound, move |ev| {
                events_srv.borrow_mut().push(ev)
            });
            let client = async {
                let tls = reality_handshake(
                    Box::new(client_io),
                    SNI,
                    &[],
                    &RealityConfig {
                        public_key: server_pub,
                        short_id: SHORT_ID,
                        client_version: [26, 3, 27],
                    },
                )
                .await
                .expect("客户端握手");
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

                vless.write_all(b"x").await.expect("写");
                vless.flush().await.expect("flush");

                // 只等事件，**不读回包**：转发此刻仍卡在半途。
                let deadline = Instant::now() + Duration::from_secs(5);
                while events_cli.borrow().is_empty() {
                    assert!(
                        Instant::now() < deadline,
                        "超时：事件只在转发结束后才发出，长连接下日志就等于没有"
                    );
                    yield_now().await;
                }
                assert_eq!(
                    events_cli.borrow().clone(),
                    vec![InboundEvent::Authenticated {
                        user: uuid,
                        target: format!("127.0.0.1:{echo_port}"),
                        client_version: [26, 3, 27],
                        short_id: SHORT_ID,
                        server_name: Some(SNI.to_string()),
                    }],
                );

                let mut buf = [0u8; 8];
                let n = vless.read(&mut buf).await.expect("读");
                assert_eq!(&buf[..n], b"x");
            };
            let (outcome, ()) = futures::join!(server, client);
            assert!(matches!(
                outcome.expect("入站不应报错").outcome,
                InboundOutcome::Forwarded
            ));
        });
    }

    /// 未认证的连接也要发事件 —— 回退是正常路径，不是错误路径，
    /// 日志里必须能看见它（否则探测流量会完全静默）。
    #[test]
    fn inbound_emits_fallback_event_for_unauthenticated_client() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use std::time::Duration;
        use xt_wasm_runtime::block_on;
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        const SNI: &str = "www.cloudflare.com";
        let echo = spawn_echo(); // 充作 dest
        let server_priv = xt_wasm_tls::test_support::fixture_private_key();
        let server_pub = xt_wasm_tls::test_support::public_from_private(&server_priv);

        let inbound = InboundConfig {
            reality: RealityServerConfig {
                private_key: server_priv,
                short_ids: vec![[9u8; 8]],
                server_names: vec![SNI.to_string()],
                max_time_diff_secs: 60,
            },
            dest: format!("127.0.0.1:{}", echo.port()),
            users: vec![[0x33u8; 16]],
        };
        // shortId 故意写错 → REALITY 认证必然失败 → 走回退
        let bad_client = RealityConfig {
            public_key: server_pub,
            short_id: [0xAAu8; 8],
            client_version: [26, 3, 27],
        };

        let events: Rc<RefCell<Vec<InboundEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let events_srv = Rc::clone(&events);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        block_on(async {
            let server = serve_inbound_with_events(Box::new(server_io), &inbound, move |ev| {
                events_srv.borrow_mut().push(ev)
            });
            let client = async {
                // 认证失败后，我们要把 TLS 客户端握手的客户端 hello 原样送给 dest（echo）。
                // echo 只会回显后关闭，所以这里必然失败 —— 这正是「探测者拿不到
                // 一个可用隧道」的表现。用 timeout 兜底，避免等一个永远不会来的 ServerHello。
                let _ = xt_wasm_runtime::timeout(
                    Duration::from_secs(2),
                    reality_handshake(Box::new(client_io), SNI, &[], &bad_client),
                )
                .await;
            };
            let (outcome, ()) = futures::join!(server, client);
            assert!(
                matches!(
                    outcome.expect("回退路径本身不应报错").outcome,
                    InboundOutcome::FellBack
                ),
                "认证失败必须走 FellBack"
            );
        });

        let seen = events.borrow().clone();
        assert_eq!(
            seen,
            vec![InboundEvent::Fallback {
                server_name: Some(SNI.to_string()),
            }],
            "回退也要发事件"
        );
    }

    /// 空连接必须是 **Ok(EmptyConnection)**，不是 Err。
    ///
    /// 这条用例看着琐碎，但它守着一个运维后果：k8s 的 `tcpSocket` 探针、
    /// 端口扫描器、LB 健康检查全是「连上就关」。如果这里返回 Err，
    /// 服务端就必然把它们记成失败 —— 每 10 秒一行错误日志，真正的故障被淹掉。
    /// 而且调用方只能靠字符串匹配来静音，总有实现会忘。
    #[test]
    fn empty_connection_is_an_outcome_not_an_error() {
        use std::cell::RefCell;
        use std::rc::Rc;
        use xt_wasm_runtime::block_on;
        use xt_wasm_tls::RealityServerConfig;

        let inbound = InboundConfig {
            reality: RealityServerConfig {
                private_key: xt_wasm_tls::test_support::fixture_private_key(),
                short_ids: vec![[5u8; 8]],
                server_names: vec!["www.cloudflare.com".to_string()],
                max_time_diff_secs: 60,
            },
            dest: "127.0.0.1:9".to_string(),
            users: vec![[0x44u8; 16]],
        };

        let events: Rc<RefCell<Vec<InboundEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let events_srv = Rc::clone(&events);
        let (client_io, server_io) = tokio::io::duplex(4096);

        let outcome = block_on(async move {
            // 客户端一个字节都不发，直接断开
            drop(client_io);
            serve_inbound_with_events(Box::new(server_io), &inbound, move |ev| {
                events_srv.borrow_mut().push(ev)
            })
            .await
        });

        assert_eq!(
            outcome.expect("空连接不该是 Err").outcome,
            InboundOutcome::EmptyConnection
        );
        assert!(
            events.borrow().is_empty(),
            "空连接不该产生认证/回退事件（那两行日志表示真的有人在用）"
        );
    }

    /// 解析失败的提示必须**区分**两种成因，且各自给出可执行动作。
    ///
    /// 这两类失败排查方向相反（改 wasmtime flag vs 查 DNS），
    /// 混成一句就等于把成本推回给运维 —— 而本次改动就是要消灭这种事。
    #[test]
    fn resolve_failure_hint_distinguishes_the_two_real_causes() {
        use std::io::{Error, ErrorKind};

        // ① 缺 ip-name-lookup 能力：提示指向 wasmtime flag
        let denied = Error::new(ErrorKind::PermissionDenied, "Permission denied");
        let h = resolve_hint("目标", "example.com:443", &denied);
        assert!(h.contains("allow-ip-name-lookup=y"), "{h}");
        assert!(h.contains("不是网络问题"), "要明确排除网络方向：{h}");

        // ② 解析器没作答（实测到的 30 秒超时就是这一类）：
        //    必须明确说「加 flag 无效」，否则运维会照着上一条去改一个无关的开关
        let nores = Error::other("failed to lookup address information: Name does not resolve");
        let h = resolve_hint("目标", "example.com:443", &nores);
        assert!(h.contains("不是权限问题"), "{h}");
        assert!(
            h.contains("加 -S allow-ip-name-lookup=y 无效"),
            "必须明确劝阻那个无效动作：{h}"
        );
        assert!(h.contains("30 秒"), "要点出超时这个特征：{h}");
        assert!(h.contains("IP 字面量"), "要给出可执行的绕开办法：{h}");
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

        // REALITY 认证过了但 UUID 不在名单里 —— 这是 `Rejected`（服务端正常判定
        // 的结果），**不是** `Err`（那表示服务端自己坏了）。见 `InboundOutcome` 的说明。
        let report = outcome.expect("未授权 UUID 应当被正常判定为 Rejected，而不是 Err");
        let InboundOutcome::Rejected { reason } = &report.outcome else {
            panic!("未授权 UUID 必须被拒，实际 {:?}", report.outcome);
        };
        // 拒绝原因必须**可执行**：点名是哪个 UUID，并说清客户端要怎么改。
        assert!(reason.contains("不在服务端 users 名单里"), "{reason}");
        assert!(
            reason.contains("11111111-1111-1111-1111-111111111111"),
            "拒绝原因应当点名出问题的 UUID（多设备/多配置时才知道是哪一份）：{reason}"
        );
        assert!(reason.contains("XT_USERS"), "要给修复建议：{reason}");
        // 身份必须被带出来，否则日志里这条拒绝记录无从定位
        assert_eq!(report.short_id, Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(report.client_version, Some([26, 3, 27]));
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

        let report = outcome.expect("请求 Vision 应当被正常判定为 Rejected，而不是 Err");
        let InboundOutcome::Rejected { reason } = &report.outcome else {
            panic!("请求 Vision 必须被拒，实际 {:?}", report.outcome);
        };
        assert!(
            reason.contains("Vision"),
            "要点明是 Vision 的问题：{reason}"
        );
        // 关键：**必须给出客户端怎么改**，不能只说「不支持」。
        assert!(
            reason.contains("flow") && reason.contains("--no-flow"),
            "拒绝原因应当告诉客户端怎么改（置空 flow / 用 --no-flow）：{reason}"
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
            matches!(
                outcome.expect("回退本身不应报错").outcome,
                InboundOutcome::FellBack
            ),
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
