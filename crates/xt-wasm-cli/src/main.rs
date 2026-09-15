//! xt-wasm-cli —— 在 wasmtime 下运行的代理客户端。
//!
//! 两种模式：
//!
//! * `--self-test`：只做 REALITY 握手并报告结果。不依赖 VLESS 层，
//!   用于 M1 验收（TLS 一落地就能对真实服务端验证）。
//! * 默认：本地 SOCKS5 监听 → VLESS + XTLS-Vision + REALITY 隧道。
//!
//! ```sh
//! ./scripts/run-local.sh --server 127.0.0.1:8443 \
//!     --pbk <公钥> --sid <shortId> --sni www.cloudflare.com \
//!     --uuid <uuid> --listen 127.0.0.1:1080
//! ```
//!
//! # 一次连接的完整链路
//!
//! ```text
//! curl --proxy socks5h://127.0.0.1:1080
//!   → SOCKS5 协商（阻塞 IO，此时还没有并发读写要照顾）
//!   → RealityTlsLayer::connect     TLS 1.3 + REALITY 认证
//!   → VlessConn::new_deferred      VLESS 请求头（含 Vision flow 声明）
//!   → VisionConn::new              XTLS-Vision 流控
//!   → relay_bidirectional          两个方向并发搬运
//! ```
//!
//! 顺序与 port-map §4.3 一致。VLESS 请求头用 `new_deferred`（不在此刻等服务端应答），
//! 应答在首次读时顺带处理。

mod relay;
mod socks5;

use std::net::{Ipv4Addr, Ipv6Addr, TcpStream};
use std::time::Instant;

use xt_wasm_runtime::{block_on, NonBlockingStream, Stream};
use xt_wasm_tls::{RealityConfig, RealityTlsLayer, TlsConfig, Transport};
use xt_wasm_vless::{Cmd, VisionConn, VlessAddr, VlessConn};

/// XTLS-Vision 的流控名。服务端 `settings.clients[].flow` 必须与此一致。
const VISION_FLOW: &str = "xtls-rprx-vision";

/// 命令行参数。
struct Args {
    server: String,
    public_key: [u8; 32],
    short_id: [u8; 8],
    /// REALITY ClientVer。服务端设了 minClientVer/maxClientVer 时决定成败。
    client_version: [u8; 3],
    sni: String,
    uuid: String,
    listen: String,
    /// SOCKS5 认证。两个都设了才启用；否则无认证（绑非回环时会告警）。
    socks_user: Option<String>,
    socks_pass: Option<String>,
    /// SOCKS5 协商阶段的读超时（秒）。
    ///
    /// 必须有：wasip2 无线程，accept 循环是**顺序**的，而协商是阻塞读。
    /// 没有超时的话，任何一个「连上但不发数据」的客户端（k8s 存活探针、
    /// 端口扫描器、半开连接）都会把整个代理永久卡住。
    handshake_timeout_secs: u64,
    self_test: bool,
}

fn usage() -> ! {
    eprintln!(
        "用法：
  xt-wasm-cli --self-test --server <ip:port> --pbk <base64url 公钥> --sid <hex shortId> --sni <域名>
  xt-wasm-cli --server <ip:port> --pbk <...> --sid <...> --sni <...> --uuid <uuid> [--listen 127.0.0.1:1080]

可选：
  --client-ver x.y.z   REALITY 上报的客户端版本（默认 {}）。
                       服务端若设了 minClientVer/maxClientVer，必须对齐，否则握手会被拒。
  --socks-user U --socks-pass P
                       启用 SOCKS5 用户名/密码认证。**监听非回环地址时强烈建议启用**，
                       否则就是开放代理。两者必须同时给出。
  --handshake-timeout S
                       协商阶段读超时秒数（默认 {}）。防止「连上不发数据」的连接
                       卡死顺序 accept 循环。

环境变量（命令行参数优先，便于 k8s 用 Secret 注入而不用写进 args）：
  XT_SERVER  XT_PBK  XT_SID  XT_SNI  XT_UUID  XT_LISTEN  XT_CLIENT_VER
  XT_SOCKS_USER  XT_SOCKS_PASS  XT_HANDSHAKE_TIMEOUT  XT_SELF_TEST",
        version_string(RealityConfig::DEFAULT_CLIENT_VERSION),
        DEFAULT_HANDSHAKE_TIMEOUT_SECS
    );
    std::process::exit(2)
}

/// 把 ClientVer 三元组渲染成 `x.y.z`。
///
/// 帮助文本里不直接写死版本号，避免与 `RealityConfig::DEFAULT_CLIENT_VERSION`
/// 各说各话（改了一处忘了另一处，用户会照着错的填）。
fn version_string(v: [u8; 3]) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

/// 读一个环境变量；空串按「未设置」处理（k8s 里没填的字段常是空串）。
fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// 读一个布尔环境变量。`1`/`true`/`yes`/`on`（不分大小写）为真。
fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_args() -> Args {
    // 环境变量作为默认值，命令行参数覆盖之。
    //
    // 为什么需要环境变量：k8s 里凭证应当由 Secret 注入，而不是写在 args 里 ——
    // `kubectl describe pod` 会把 args 原样打出来，等于把 UUID 摊在终端历史和
    // 工单里。Secret 注入的环境变量则以 valueFrom.secretKeyRef 引用，不落明文。
    let mut server = env_opt("XT_SERVER");
    let mut pbk = env_opt("XT_PBK");
    let mut sid = env_opt("XT_SID");
    let mut sni = env_opt("XT_SNI");
    let mut uuid = env_opt("XT_UUID");
    let mut client_ver = env_opt("XT_CLIENT_VER");
    let mut listen = env_opt("XT_LISTEN").unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let mut socks_user = env_opt("XT_SOCKS_USER");
    let mut socks_pass = env_opt("XT_SOCKS_PASS");
    let mut handshake_timeout_secs = env_opt("XT_HANDSHAKE_TIMEOUT");
    let mut self_test = env_flag("XT_SELF_TEST");

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let need = |i: usize| -> String {
            argv.get(i + 1).cloned().unwrap_or_else(|| {
                eprintln!("参数 {} 缺少取值", argv[i]);
                usage()
            })
        };
        match argv[i].as_str() {
            "--server" => server = Some(need(i)),
            "--pbk" => pbk = Some(need(i)),
            "--sid" => sid = Some(need(i)),
            "--sni" => sni = Some(need(i)),
            "--uuid" => uuid = Some(need(i)),
            "--client-ver" => client_ver = Some(need(i)),
            "--listen" => listen = need(i),
            "--socks-user" => socks_user = Some(need(i)),
            "--socks-pass" => socks_pass = Some(need(i)),
            "--handshake-timeout" => handshake_timeout_secs = Some(need(i)),
            "--self-test" => self_test = true,
            "-h" | "--help" => usage(),
            other => {
                eprintln!("未知参数：{other}");
                usage()
            }
        }
        i += if argv[i].starts_with("--") && argv[i] != "--self-test" {
            2
        } else {
            1
        };
    }

    let server = server.unwrap_or_else(|| {
        eprintln!("缺少 --server");
        usage()
    });
    let sni = sni.unwrap_or_else(|| {
        eprintln!("缺少 --sni");
        usage()
    });
    let public_key = decode_base64url_32(&pbk.unwrap_or_else(|| {
        eprintln!("缺少 --pbk");
        usage()
    }));
    let short_id = decode_hex_8(&sid.unwrap_or_else(|| {
        eprintln!("缺少 --sid");
        usage()
    }));

    // 认证必须成对出现：只设一半几乎总是配置错误，静默降级成「无认证」
    // 会把一个本意是受保护的代理变成开放代理。
    if socks_user.is_some() != socks_pass.is_some() {
        eprintln!("--socks-user 与 --socks-pass 必须同时设置（只设一个会静默变成无认证）");
        std::process::exit(2);
    }

    Args {
        server,
        public_key,
        short_id,
        client_version: client_ver
            .map(|s| parse_version(&s))
            .unwrap_or(RealityConfig::DEFAULT_CLIENT_VERSION),
        sni,
        uuid: uuid.unwrap_or_default(),
        listen,
        socks_user,
        socks_pass,
        handshake_timeout_secs: handshake_timeout_secs
            .map(|s| {
                s.parse::<u64>().unwrap_or_else(|_| {
                    eprintln!("--handshake-timeout 应为秒数，实际 {s:?}");
                    std::process::exit(2)
                })
            })
            .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
        self_test,
    }
}

/// 协商阶段默认读超时。取 15s：足够慢客户端完成握手，又不至于被半开连接长期占用。
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// 监听地址是否只在回环上。
///
/// 用于判断「是否需要警告开放代理风险」：回环地址只有本机能连，
/// 无认证也不构成开放代理。
fn is_loopback_listen(addr: &str) -> bool {
    // 支持 `host:port` 与 `[v6]:port`
    let host = if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
    };
    match host {
        "localhost" => true,
        other => other
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            // 解析不了（比如主机名）时按「非回环」从严处理，宁可多警告。
            .unwrap_or(false),
    }
}

/// 解析 `x.y.z` 形式的客户端版本号。
fn parse_version(s: &str) -> [u8; 3] {
    let mut out = [0u8; 3];
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        eprintln!("--client-ver 应为 x.y.z 形式，实际 {s:?}");
        std::process::exit(2);
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().unwrap_or_else(|_| {
            eprintln!("--client-ver 的每一段都应是 0..=255，实际 {p:?}");
            std::process::exit(2)
        });
    }
    out
}

// ───────────────────────────── 解码 ─────────────────────────────

/// 解 Xray `x25519` 输出的 base64url（无填充）公钥。
fn decode_base64url_32(s: &str) -> [u8; 32] {
    let bytes = decode_base64url(s).unwrap_or_else(|e| {
        eprintln!("--pbk 不是合法的 base64url：{e}");
        std::process::exit(2)
    });
    bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!("--pbk 解出来是 {} 字节，X25519 公钥应为 32 字节", v.len());
        std::process::exit(2)
    })
}

/// 解 shortId（hex）。不足 8 字节时右侧补 0，与 Xray 的语义一致。
fn decode_hex_8(s: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let n = s.len() / 2;
    if n > 8 {
        eprintln!("--sid 过长（{} 个 hex 字符，最多 16）", s.len());
        std::process::exit(2);
    }
    for i in 0..n {
        let b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("--sid 含非 hex 字符：{:?}", &s[i * 2..i * 2 + 2]);
            std::process::exit(2)
        });
        out[i] = b;
    }
    out
}

/// 解 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 形式的 UUID。
fn decode_uuid(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        eprintln!(
            "--uuid 格式不对：去掉连字符后应为 32 个 hex 字符，实际 {}",
            hex.len()
        );
        std::process::exit(2);
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("--uuid 含非 hex 字符：{:?}", &hex[i * 2..i * 2 + 2]);
            std::process::exit(2)
        });
    }
    out
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = val(c).ok_or_else(|| format!("非法字符 {:?}", c as char))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

// ───────────────────────────── 入口 ─────────────────────────────

fn main() {
    // 宿主上打开移植代码里的 tracing 日志（`tracing::debug!` 打了握手各阶段）。
    // wasm 侧不装 subscriber：没必要，也会把体积和依赖带进去。
    #[cfg(not(target_os = "wasi"))]
    {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    }

    let args = parse_args();
    let tls = TlsConfig {
        reality: Some(RealityConfig {
            client_version: args.client_version,
            ..RealityConfig::new(args.public_key, args.short_id)
        }),
        ..TlsConfig::new(&args.sni)
    };

    if args.self_test {
        run_self_test(&args, &tls);
    } else {
        run_socks5(&args, &tls);
    }
}

/// 建立一条到目标地址的隧道（REALITY → VLESS → Vision）。
fn open_tunnel(
    args: &Args,
    tls: &TlsConfig,
    uuid: &[u8; 16],
    host: &str,
    port: u16,
) -> Result<VisionConn, String> {
    // 域名保持域名形式交给服务端解析（socks5h 语义，也避免在 wasm 里做 DNS）。
    let addr = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        VlessAddr::Ipv4(v4.octets())
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        VlessAddr::Ipv6(v6.octets())
    } else {
        VlessAddr::domain(host).map_err(|e| format!("目标地址非法：{e}"))?
    };

    let sock = xt_wasm_runtime::connect(&args.server).map_err(|e| {
        format!(
            "连接服务端 {} 失败：{e}（wasmtime 需要 -S tcp=y -S inherit-network=y）",
            args.server
        )
    })?;

    let layer = RealityTlsLayer::new(tls).map_err(|e| format!("构造 REALITY 层失败：{e}"))?;
    let tls_stream = block_on(layer.connect(Box::new(sock) as Box<dyn Stream>))
        .map_err(|e| format!("REALITY 握手失败：{e}"))?;

    let vless = block_on(VlessConn::new_deferred(
        tls_stream,
        uuid,
        Some(VISION_FLOW),
        Cmd::Tcp,
        port,
        &addr,
    ))
    .map_err(|e| format!("VLESS 请求头发送失败：{e}"))?;

    Ok(VisionConn::new(vless, *uuid))
}

fn run_socks5(args: &Args, tls: &TlsConfig) -> ! {
    let uuid = decode_uuid(&args.uuid);
    let listener = xt_wasm_runtime::listen(&args.listen).unwrap_or_else(|e| {
        eprintln!("监听 {} 失败：{e}", args.listen);
        std::process::exit(1)
    });

    // 「绑了非回环地址 + 没有认证」= 开放代理：任何能连上该端口的人都能
    // 免费用这条隧道出去。k8s 里做成 Service 之后尤其危险。这里必须显式告警，
    // 因为这种配置看起来完全正常，出事之前没有任何症状。
    let has_auth = args.socks_user.is_some();
    if !is_loopback_listen(&args.listen) && !has_auth {
        eprintln!("──────────────────────────────────────────────────────────────");
        eprintln!(
            "警告：监听 {} 且未启用认证，这是一个**开放代理**。",
            args.listen
        );
        eprintln!("      任何能连上该端口的人都可以经你的隧道访问外网。");
        eprintln!("      请设置 --socks-user/--socks-pass（或 XT_SOCKS_USER/XT_SOCKS_PASS），");
        eprintln!("      并配合网络策略限制来源。详见 README 的 k8s 一节。");
        eprintln!("──────────────────────────────────────────────────────────────");
    }

    println!(
        "[socks5] 监听 {}，隧道目标 {}，认证：{}",
        args.listen,
        args.server,
        if has_auth { "用户名/密码" } else { "无" }
    );
    println!(
        "[socks5] 用法： curl --proxy socks5h://{} https://example.com",
        args.listen
    );

    // wasip2 无线程，所以是「accept 一条、处理到结束、再 accept 下一条」的顺序模型。
    // 见 xt-wasm-runtime 的模块文档。
    loop {
        let (local, peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[socks5] accept 失败：{e}");
                continue;
            }
        };
        println!("[socks5] 新连接 {peer}");
        match handle_connection(local, args, tls, &uuid) {
            Ok((host, port)) => println!("[socks5] {peer} → {host}:{port} 完成"),
            Err(e) => eprintln!("[socks5] {peer} 失败：{e}"),
        }
    }
}

/// 处理一条 SOCKS5 连接直到转发结束。
fn handle_connection(
    mut local: TcpStream,
    args: &Args,
    tls: &TlsConfig,
    uuid: &[u8; 16],
) -> Result<(String, u16), String> {
    // 协商阶段用阻塞 IO：此时隧道还没建立，没有并发读写要照顾。
    //
    // 但**必须设读超时**：accept 循环是顺序的，若某客户端连上却不发数据，
    // 阻塞读会把整个代理永久卡住（k8s 探针、扫描器都会这么做）。
    // 超时后返回 would-block/timed-out，由调用方关掉这条连接继续 accept。
    local
        .set_read_timeout(Some(std::time::Duration::from_secs(
            args.handshake_timeout_secs,
        )))
        .map_err(|e| format!("设置协商超时失败：{e}"))?;

    let creds = match (&args.socks_user, &args.socks_pass) {
        (Some(u), Some(p)) => Some(socks5::Credentials {
            username: u,
            password: p,
        }),
        _ => None,
    };
    let req = socks5::negotiate_and_read_request(&mut local, creds)
        .map_err(|e| format!("SOCKS5 协商失败：{e}"))?;
    let (host, port) = match req {
        socks5::Request::Connect { host, port } => (host, port),
        socks5::Request::Unsupported { cmd } => {
            return Err(format!(
                "不支持的 SOCKS5 命令 0x{cmd:02x}（只支持 CONNECT）"
            ))
        }
    };

    let tunnel = match open_tunnel(args, tls, uuid, &host, port) {
        Ok(t) => t,
        Err(e) => {
            // 回一条失败应答，让客户端立刻知道，而不是干等超时。
            let _ = socks5::write_reply_failure(&mut local);
            return Err(e);
        }
    };

    socks5::write_reply_ok(&mut local).map_err(|e| format!("回 SOCKS5 应答失败：{e}"))?;

    // 转成非阻塞，转发阶段两个方向必须能同时存活（否则会死锁）。
    let local = NonBlockingStream::new(local).map_err(|e| format!("切换非阻塞失败：{e}"))?;
    block_on(relay::relay_bidirectional(
        Box::new(local),
        Box::new(tunnel),
    ))
    .map_err(|e| format!("转发失败：{e}"))?;

    Ok((host, port))
}

/// M1 验收：只做 REALITY 握手，证明 TLS 1.3 + REALITY 认证在 wasm 里成立。
///
/// 判据有两重，缺一不可：
/// 1. 本进程握手成功返回（否则 REALITY 的证书 HMAC 校验会失败）；
/// 2. **服务端日志**出现 `isHandshakeComplete: true` 与匹配的 `ClientShortId`
///    —— 这是独立于我们自己的外部证据。
fn run_self_test(args: &Args, tls: &TlsConfig) -> ! {
    println!("[self-test] 目标 {}  SNI {}", args.server, args.sni);

    let layer = match RealityTlsLayer::new(tls) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[self-test] 构造 REALITY 层失败：{e}");
            std::process::exit(1);
        }
    };

    let sock = match xt_wasm_runtime::connect(&args.server) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[self-test] TCP 连接失败：{e}");
            eprintln!("  提示：wasmtime 需要 -S tcp=y 和 -S inherit-network=y");
            std::process::exit(1);
        }
    };
    println!("[self-test] TCP 已连接");

    let t0 = Instant::now();
    let result = block_on(layer.connect(Box::new(sock) as Box<dyn Stream>));
    let elapsed = t0.elapsed();

    match result {
        Ok(_stream) => {
            println!("[self-test] ✓ REALITY 握手完成，用时 {elapsed:?}");
            println!(
                "[self-test] 现在去服务端日志里确认 isHandshakeComplete=true 与 ClientShortId"
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[self-test] ✗ REALITY 握手失败（{elapsed:?}）：{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_decodes_xray_public_key() {
        // 来自 `xray x25519` 的真实输出
        let b = decode_base64url("HgNph_44uv7AO4OZFb4vROlrokgklJ98HiqldBWroFg").unwrap();
        assert_eq!(b.len(), 32);
    }

    #[test]
    fn hex_short_id_pads_to_eight_bytes() {
        assert_eq!(
            decode_hex_8("64f6ffd42769a12c"),
            [0x64, 0xf6, 0xff, 0xd4, 0x27, 0x69, 0xa1, 0x2c]
        );
        // 短 shortId 右侧补零
        assert_eq!(decode_hex_8("abcd"), [0xab, 0xcd, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn uuid_decodes_with_dashes() {
        assert_eq!(
            decode_uuid("b21e29c8-a8ea-40a2-b953-c2b04d73d775"),
            [
                0xb2, 0x1e, 0x29, 0xc8, 0xa8, 0xea, 0x40, 0xa2, 0xb9, 0x53, 0xc2, 0xb0, 0x4d, 0x73,
                0xd7, 0x75
            ]
        );
    }

    #[test]
    fn client_version_parses_xyz() {
        assert_eq!(parse_version("26.3.27"), [26, 3, 27]);
        assert_eq!(parse_version("1.8.1"), [1, 8, 1]);
        assert_eq!(parse_version("0.0.1"), [0, 0, 1]);
    }

    /// k8s 里没填的字段常常是空串而不是未设置，必须按「未设置」处理，
    /// 否则会拿空串去解析 key，得到难以定位的报错。
    #[test]
    fn env_opt_treats_empty_string_as_unset() {
        assert!(env_opt("XT_TEST_VAR_THAT_IS_NOT_SET").is_none());
        std::env::set_var("XT_TEST_EMPTY_VAR", "");
        assert!(env_opt("XT_TEST_EMPTY_VAR").is_none());
        std::env::remove_var("XT_TEST_EMPTY_VAR");
    }

    #[test]
    fn env_flag_accepts_common_truthy_spellings() {
        for truthy in ["1", "true", "TRUE", "yes", "On"] {
            std::env::set_var("XT_TEST_FLAG", truthy);
            assert!(env_flag("XT_TEST_FLAG"), "{truthy} 应视为真");
        }
        for falsy in ["", "0", "false", "no"] {
            std::env::set_var("XT_TEST_FLAG", falsy);
            assert!(!env_flag("XT_TEST_FLAG"), "{falsy:?} 应视为假");
        }
        std::env::remove_var("XT_TEST_FLAG");
    }

    /// 默认版本必须与服务端校验的大小关系自洽：
    /// 它应当是一个较新的 Xray 版本，才能通过常见的 minClientVer 设置。
    #[test]
    fn default_client_version_is_modern() {
        let v = RealityConfig::DEFAULT_CLIENT_VERSION;
        assert!(
            v[0] >= 24,
            "默认 ClientVer {v:?} 过旧，会被设置了 minClientVer 的服务端判为探测流量"
        );
    }
}
