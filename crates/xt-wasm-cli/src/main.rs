//! xt-wasm-cli —— 在 wasmtime 下运行的代理，**客户端与服务端同一个二进制**。
//!
//! 三种模式：
//!
//! * `server` 子命令：REALITY **入站**（服务端）。给 k3s 用，见下。
//! * `--self-test`：只做 REALITY 握手并报告结果。不依赖 VLESS 层，
//!   用于 M1 验收（TLS 一落地就能对真实服务端验证）。
//! * 默认（无子命令）：本地 SOCKS5 监听 → VLESS + XTLS-Vision + REALITY 隧道。
//!
//! ```sh
//! # 客户端
//! ./scripts/run-local.sh --server 127.0.0.1:8443 \
//!     --pbk <公钥> --sid <shortId> --sni www.cloudflare.com \
//!     --uuid <uuid> --listen 127.0.0.1:1080
//!
//! # 服务端（k3s）
//! xt-wasm-cli server --listen 0.0.0.0:8443 --private-key <base64url> \
//!     --short-ids <hex> --server-names www.example.com \
//!     --dest www.example.com:443 --users <uuid>
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
//!
//! **本工程的服务端也实现了 Vision**（见 `docs/vision-server-plan.md`），所以默认
//! 路径与官方 Xray 服务端一致。`--no-flow` 仍然保留：它是一条「两端都同意跳过
//! Vision」的兼容开关，而不是历史遗留。

mod server;
mod socks5;

use std::cell::Cell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use xt_wasm_runtime::{
    block_on, relay_bidirectional, sleep, spawn_task, timeout, NetStream, Stream,
};
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
    /// 不发 XTLS-Vision flow 声明，也不做客户端侧 Vision 分帧。
    ///
    /// 两端都实现了 Vision，所以**默认不需要它**；它用于「对端只认空 flow」的
    /// 场景（对端配置写成 `flow: ""`，或排障时先排除 Vision）。
    ///
    /// 注意这不只是「请求头少两个字节」：Vision 的客户端侧会把**最初的负载
    /// 包进填充帧**。所以 `--no-flow` 必须**同时**关掉 flow 声明和
    /// `VisionConn` 包装 —— 只关一半会让服务端把填充字节当成原始数据。
    no_flow: bool,
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
                       长期占住一个并发槽位。
  --no-flow            不发 XTLS-Vision flow 声明，也不做客户端侧 Vision 分帧。
                       **默认不需要**：本工程的服务端与 stock Xray 服务端都支持
                       Vision。只在「对端只认空 flow」或排障时才加。

环境变量（命令行参数优先，便于 k8s 用 Secret 注入而不用写进 args）：
  XT_SERVER  XT_PBK  XT_SID  XT_SNI  XT_UUID  XT_LISTEN  XT_CLIENT_VER
  XT_SOCKS_USER  XT_SOCKS_PASS  XT_HANDSHAKE_TIMEOUT  XT_NO_FLOW  XT_SELF_TEST

互操作（默认走 Vision；四种组合都必须能通）：
  wasm 客户端（默认）    →  wasm 服务端         ✅
  wasm 客户端（默认）    →  stock Xray 服务端   ✅
  wasm 客户端 --no-flow  →  wasm 服务端         ✅（flow 为空是合法配置）
  wasm 客户端 --no-flow  →  stock Xray 服务端   ✅
  未知 flow 名           →  任一服务端         ❌ 明确拒绝，不静默降级",
        version_string(RealityConfig::DEFAULT_CLIENT_VERSION),
        DEFAULT_HANDSHAKE_TIMEOUT_SECS
    );
    std::process::exit(2)
}

/// 把 ClientVer 三元组渲染成 `x.y.z`。
///
/// `server` 子命令的帮助文本。
pub fn usage_server() -> ! {
    eprintln!(
        "用法：
  xt-wasm-cli server --private-key <base64url> --short-ids <hex[,hex...]>
                     --server-names <域名[,域名...]> --dest <host:port>
                     --users <uuid[,uuid...]> [--listen 0.0.0.0:8443]
                     [--max-time-diff <秒>]

这是 REALITY **入站**（服务端）。为 k3s 而写：所有参数都有对应环境变量，
凭证可以只从 Secret 注入，不必出现在 Pod 的 args 里。

必填：
  --private-key / XT_PRIVATE_KEY   X25519 私钥（base64url）。`xray x25519` 生成，
                                   注意用 Private key 那一行。
  --short-ids   / XT_SHORT_IDS     shortId（hex，逗号分隔）。至少一个。
  --server-names/ XT_SERVER_NAMES  允许的 SNI（逗号分隔）。客户端 SNI 必须命中其一。
  --dest        / XT_DEST          认证失败时的回落目标 host:port。
                                   应是一个**真实的 TLS 站点**，探测者会看到它的证书。
  --users       / XT_USERS         允许的 VLESS UUID（逗号分隔）。至少一个。

可选：
  --listen      / XT_SERVER_LISTEN 监听地址（默认 0.0.0.0:8443）。
  --max-time-diff / XT_MAX_TIME_DIFF
                                   REALITY 时间戳容差秒数（默认 60）。两端时钟偏移超过
                                   这个值就认证失败 —— k3s 节点上务必有 NTP。

对应的客户端参数见 `xt-wasm-cli --help`（无子命令时）。"
    );
    std::process::exit(2)
}

/// 帮助文本里不直接写死版本号，避免与 `RealityConfig::DEFAULT_CLIENT_VERSION`
/// 各说各话（改了一处忘了另一处，用户会照着错的填）。
fn version_string(v: [u8; 3]) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

/// 读一个环境变量；空串按「未设置」处理（k8s 里没填的字段常是空串）。
pub(crate) fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// 读一个布尔环境变量。`1`/`true`/`yes`/`on`（不分大小写）为真。
pub(crate) fn env_flag(key: &str) -> bool {
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
    let mut no_flow = env_flag("XT_NO_FLOW");
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
            "--no-flow" => no_flow = true,
            "--self-test" => self_test = true,
            "-h" | "--help" => usage(),
            other => {
                eprintln!("未知参数：{other}");
                usage()
            }
        }
        // 不带取值的开关不能多吃一个参数，否则会把后面的 flag 吞掉。
        i += if matches!(argv[i].as_str(), "--self-test" | "--no-flow") {
            1
        } else {
            2
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
    let short_id = decode_hex_8(
        "--sid",
        &sid.unwrap_or_else(|| {
            eprintln!("缺少 --sid");
            usage()
        }),
    );

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
        no_flow,
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
pub(crate) fn decode_base64url_32(s: &str) -> [u8; 32] {
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
///
/// `flag` 只用于报错文案：客户端叫 `--sid`，服务端叫 `--short-ids`。
/// 报错里指错参数名比不报错更费时间 —— 用户会去改一个根本没有问题的参数。
pub(crate) fn decode_hex_8(flag: &str, s: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    if !s.len().is_multiple_of(2) {
        eprintln!("{flag} 的 {s:?} 是奇数个 hex 字符，无法成字节");
        std::process::exit(2);
    }
    let n = s.len() / 2;
    if n > 8 {
        eprintln!("{flag} 的 {s:?} 过长（{} 个 hex 字符，最多 16）", s.len());
        std::process::exit(2);
    }
    for i in 0..n {
        let b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("{flag} 含非 hex 字符：{:?}", &s[i * 2..i * 2 + 2]);
            std::process::exit(2)
        });
        out[i] = b;
    }
    out
}

/// 解 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 形式的 UUID。
///
/// `flag` 只用于报错文案（客户端 `--uuid` / 服务端 `--users`）。
pub(crate) fn decode_uuid(flag: &str, s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        eprintln!(
            "{flag} 的 {s:?} 格式不对：去掉连字符后应为 32 个 hex 字符，实际 {}",
            hex.len()
        );
        std::process::exit(2);
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("{flag} 含非 hex 字符：{:?}", &hex[i * 2..i * 2 + 2]);
            std::process::exit(2)
        });
    }
    out
}

pub(crate) fn decode_base64url(s: &str) -> Result<Vec<u8>, String> {
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

    // 子命令分派。第一个参数是 `server` → 服务端模式；`--help` 一律给客户端帮助，
    // `server --help` 给服务端帮助（parse_server_args 里处理）。
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("server") {
        let args = server::parse_server_args(&argv[1..]);
        server::run_server(args);
    }
    if matches!(
        std::env::var("XT_MODE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "server"
    ) {
        let args = server::parse_server_args(&[]);
        server::run_server(args);
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

/// 各连接共享的配置。
///
/// `spawn_task` 要求 future 是 `'static`，所以配置不能靠借用传递，必须放进 `Rc`。
/// wasm 是单线程，`Rc` 足够（`wstd::runtime::spawn` 也不要求 `Send`）。
struct Shared {
    server: String,
    tls: TlsConfig,
    uuid: [u8; 16],
    socks_user: Option<String>,
    socks_pass: Option<String>,
    handshake_timeout_secs: u64,
    /// 见 `Args::no_flow`。
    no_flow: bool,
}

impl Shared {
    fn creds(&self) -> Option<socks5::Credentials<'_>> {
        match (&self.socks_user, &self.socks_pass) {
            (Some(u), Some(p)) => Some(socks5::Credentials {
                username: u,
                password: p,
            }),
            _ => None,
        }
    }
}

/// 建立一条到目标地址的隧道（REALITY → VLESS → Vision）。
///
/// 建连是**真异步**的：`connect` 内部走 `start_connect` + pollable，不会阻塞其它连接。
/// （v0.2 及以前用的是 `std::net` 的阻塞 connect，服务端不可达时会把整个代理
/// 卡到 TCP 超时。）
async fn open_tunnel(shared: &Shared, host: &str, port: u16) -> Result<Box<dyn Stream>, String> {
    // 域名保持域名形式交给服务端解析（socks5h 语义，也避免在 wasm 里做 DNS）。
    let addr = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        VlessAddr::Ipv4(v4.octets())
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        VlessAddr::Ipv6(v6.octets())
    } else {
        VlessAddr::domain(host).map_err(|e| format!("目标地址非法：{e}"))?
    };

    let sock = xt_wasm_runtime::connect(&shared.server)
        .await
        .map_err(|e| {
            format!(
                "连接服务端 {} 失败：{e}（wasmtime 需要 -S tcp=y 和 -S inherit-network=y）",
                shared.server
            )
        })?;

    let layer =
        RealityTlsLayer::new(&shared.tls).map_err(|e| format!("构造 REALITY 层失败：{e}"))?;
    let tls_stream = layer
        .connect(Box::new(sock) as Box<dyn Stream>)
        .await
        .map_err(|e| format!("REALITY 握手失败：{e}"))?;

    // flow 声明与 VisionConn 必须**同进同退**：只关掉声明却仍然做 Vision 分帧，
    // 会把填充帧当成普通数据发给一个不做拆帧的服务端 —— 「连上了但数据是坏的」，
    // 属于最难查的那类故障。所以这里由同一个 `no_flow` 决定两件事。
    let flow = if shared.no_flow {
        None
    } else {
        Some(VISION_FLOW)
    };
    let vless = VlessConn::new_deferred(tls_stream, &shared.uuid, flow, Cmd::Tcp, port, &addr)
        .await
        .map_err(|e| format!("VLESS 请求头发送失败：{e}"))?;

    if shared.no_flow {
        // 不包 VisionConn：请求头会在首次写时直接发出去（`new_deferred` 的语义），
        // 之后就是裸 VLESS 负载。
        Ok(Box::new(vless))
    } else {
        Ok(Box::new(VisionConn::new(vless, shared.uuid)))
    }
}

/// 同时处理的连接数上限。
///
/// 有上限是必须的：内存与 fd 都有限，没有背压的话攻击者可以用一堆慢连接拖垮进程。
const MAX_CONCURRENT_CONNS: usize = 64;

/// SOCKS5 服务端。
///
/// # 并发模型
///
/// 主循环只负责 accept，每条连接通过 [`spawn_task`] 交给事件循环。socket 是
/// **非阻塞**的，等待由 pollable（wasm）或让出（宿主）完成 —— 所以一条
/// keep-alive 长连接不会独占进程（v0.1 是顺序 accept，那会让 k8s 探针都超时）。
///
/// v0.2 曾用手写的「连接集合 + 每轮全量 poll + 1ms 让出」实现并发。v0.3 换成
/// 真正的 reactor 之后那段代码删掉了：挂起与唤醒交给事件循环，不再需要轮询。
fn run_socks5(args: &Args, tls: &TlsConfig) -> ! {
    let shared = Rc::new(Shared {
        server: args.server.clone(),
        tls: tls.clone(),
        uuid: decode_uuid("--uuid", &args.uuid),
        socks_user: args.socks_user.clone(),
        socks_pass: args.socks_pass.clone(),
        handshake_timeout_secs: args.handshake_timeout_secs,
        no_flow: args.no_flow,
    });

    // 指向本工程的服务端时必须 --no-flow。这条提示放在启动日志里而不是只写在
    // --help 里：真正会用错的人不会去读 --help，但一定会看到启动输出。
    if !args.no_flow {
        eprintln!(
            "提示：当前发送 XTLS-Vision flow。若服务端是本工程的 xt-wasm-cli server \
             （已实现 Vision 流控）；若对端只认空 flow，请加 --no-flow 或设 XT_NO_FLOW=1。"
        );
    }

    let has_auth = shared.socks_user.is_some();
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
        "[socks5] 监听 {}，隧道目标 {}，认证：{}，并发上限 {}",
        args.listen,
        args.server,
        if has_auth { "用户名/密码" } else { "无" },
        MAX_CONCURRENT_CONNS
    );
    println!(
        "[socks5] 用法： curl --proxy socks5h://{} https://example.com",
        args.listen
    );

    let listen_addr = args.listen.clone();
    let result = block_on(async move {
        let listener = xt_wasm_runtime::listen(&listen_addr).await?;
        // 在途连接计数：每个 spawn 出来的任务结束时自减。
        let live = Rc::new(Cell::new(0usize));

        loop {
            let stream = listener.accept().await?;

            // 满了就等一个槽位空出来，而不是直接丢弃 ——
            // 直接关掉会让 k8s 探针失败并可能触发重启。
            while live.get() >= MAX_CONCURRENT_CONNS {
                sleep(Duration::from_millis(5)).await;
            }
            live.set(live.get() + 1);

            let shared = Rc::clone(&shared);
            let live_task = Rc::clone(&live);
            spawn_task(async move {
                serve_connection(stream, &shared).await;
                live_task.set(live_task.get().saturating_sub(1));
            });
        }

        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });

    if let Err(e) = result {
        eprintln!("[socks5] 致命错误：{e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// 处理一条连接，并把结果打成日志。作为独立任务交给事件循环。
async fn serve_connection(stream: NetStream, shared: &Shared) {
    let peer = stream.peer_addr().unwrap_or_else(|_| "?".to_string());
    match serve_inner(stream, shared).await {
        Ok((host, port)) => println!("[socks5] {peer} → {host}:{port} 完成"),
        Err(e) => eprintln!("[socks5] {peer} 失败：{e}"),
    }
}

/// 一条连接的完整生命周期：协商 → 建隧道 → 双向转发。
async fn serve_inner(mut stream: NetStream, shared: &Shared) -> Result<(String, u16), String> {
    // **非阻塞读永远不会自己超时**，所以协商必须套一层墙钟超时。
    // 没有它，一个「连上但不发数据」的客户端会长期占住一个并发槽位
    // （k8s 探针、扫描器都会这么做）。
    let req = timeout(
        Duration::from_secs(shared.handshake_timeout_secs),
        socks5::negotiate_and_read_request(&mut stream, shared.creds()),
    )
    .await
    .map_err(|_| format!("SOCKS5 协商超时（{}s）", shared.handshake_timeout_secs))?
    .map_err(|e| format!("SOCKS5 协商失败：{e}"))?;

    let (host, port) = match req {
        socks5::Request::Connect { host, port } => (host, port),
        socks5::Request::Unsupported { cmd } => {
            return Err(format!(
                "不支持的 SOCKS5 命令 0x{cmd:02x}（只支持 CONNECT）"
            ))
        }
    };

    let tunnel = match open_tunnel(shared, &host, port).await {
        Ok(t) => t,
        Err(e) => {
            // 回一条失败应答，让客户端立刻知道，而不是干等超时。
            let _ = socks5::write_reply_failure(&mut stream).await;
            return Err(e);
        }
    };

    socks5::write_reply_ok(&mut stream)
        .await
        .map_err(|e| format!("回 SOCKS5 应答失败：{e}"))?;

    relay_bidirectional(Box::new(stream), Box::new(tunnel))
        .await
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

    // 整个流程放进一个 async 块：`connect` 现在是异步的（非阻塞 connect +
    // pollable 等待），不能再像以前那样先同步连上再 block_on 握手。
    let server = args.server.clone();
    let outcome = block_on(async move {
        let t0 = Instant::now();
        let sock = match xt_wasm_runtime::connect(&server).await {
            Ok(s) => s,
            Err(e) => {
                return Err(format!(
                    "TCP 连接失败：{e}\n  提示：wasmtime 需要 -S tcp=y 和 -S inherit-network=y"
                ))
            }
        };
        println!("[self-test] TCP 已连接");
        match layer.connect(Box::new(sock) as Box<dyn Stream>).await {
            Ok(_) => Ok(t0.elapsed()),
            Err(e) => Err(format!("REALITY 握手失败（{:?}）：{e}", t0.elapsed())),
        }
    });

    match outcome {
        Ok(elapsed) => {
            println!("[self-test] ✓ REALITY 握手完成，用时 {elapsed:?}");
            println!(
                "[self-test] 现在去服务端日志里确认 isHandshakeComplete=true 与 ClientShortId"
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[self-test] ✗ {e}");
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
            decode_hex_8("--sid", "64f6ffd42769a12c"),
            [0x64, 0xf6, 0xff, 0xd4, 0x27, 0x69, 0xa1, 0x2c]
        );
        // 短 shortId 右侧补零
        assert_eq!(
            decode_hex_8("--sid", "abcd"),
            [0xab, 0xcd, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn uuid_decodes_with_dashes() {
        assert_eq!(
            decode_uuid("--uuid", "b21e29c8-a8ea-40a2-b953-c2b04d73d775"),
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

    /// **`--no-flow` 必须在线上真的生效**，而且两件事要一起生效：
    /// VLESS 请求头里的 flow 声明、以及客户端侧的 Vision 分帧。
    ///
    /// 这条用例走真 socket、真 REALITY 握手、真的让我们自己的服务端去解包，
    /// 断言的是**服务端实际读到的字节**，不是某个内部布尔量 ——
    /// 「只关掉声明却仍然做 Vision 分帧」这种一半的修法必须被抓住。
    ///
    /// 判据用的是服务端给出的 outcome：
    /// * `no_flow=true`  → 服务端接受了请求，随后去连目标（目标故意指向没人听的端口），
    ///   于是得到 `ConnectFailed`
    /// * `no_flow=false` → 服务端在 VLESS 请求头里读到非空 flow → `Rejected{…Vision…}`
    #[test]
    fn no_flow_changes_what_the_server_actually_reads() {
        use std::sync::mpsc;
        use std::time::Duration;
        use xt_wasm_tls::{RealityConfig, RealityServerConfig};
        use xt_wasm_vless::{serve_inbound, InboundConfig, InboundOutcome, InboundReport};

        const SNI: &str = "www.cloudflare.com";
        const SHORT_ID: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];
        const UUID: [u8; 16] = [0x77; 16];

        // 跑一轮：起一个真监听的服务端线程，用 open_tunnel 连上去，写一点数据，
        // 再取回服务端对这条连接的判定。
        fn run(no_flow: bool) -> InboundOutcome {
            let server_priv = xt_wasm_tls::test_support::fixture_private_key();
            let server_pub = xt_wasm_tls::reality_public_key(&server_priv);

            let inbound = InboundConfig {
                reality: RealityServerConfig {
                    private_key: server_priv,
                    short_ids: vec![SHORT_ID],
                    server_names: vec![SNI.to_string()],
                    max_time_diff_secs: 60,
                },
                // 故意指向一个不会有人监听的端口：这样「flow 被接受」的下场是
                // ConnectFailed，与「flow 被拒绝」的 Rejected 能清楚区分开。
                dest: "127.0.0.1:9".to_string(),
                users: vec![UUID],
            };

            let (addr_tx, addr_rx) = mpsc::channel::<String>();
            let (out_tx, out_rx) = mpsc::channel::<xt_wasm_vless::Result<InboundReport>>();
            let server = std::thread::spawn(move || {
                let report = xt_wasm_runtime::block_on(async move {
                    let listener = xt_wasm_runtime::listen("127.0.0.1:0").await?;
                    addr_tx
                        .send(listener.local_addr()?)
                        .expect("主线程应当还在等地址");
                    let stream = listener.accept().await?;
                    serve_inbound(Box::new(stream), &inbound).await
                });
                let _ = out_tx.send(report);
            });

            let listen_addr = addr_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("服务端未能在 10 秒内绑定端口");

            let shared = Shared {
                server: listen_addr,
                tls: TlsConfig {
                    reality: Some(RealityConfig::new(server_pub, SHORT_ID)),
                    ..TlsConfig::new(SNI)
                },
                uuid: UUID,
                socks_user: None,
                socks_pass: None,
                handshake_timeout_secs: 10,
                no_flow,
            };

            // 目标端口 1：一定有东西在监听的可能性极低，服务端会 ConnectFailed。
            xt_wasm_runtime::block_on(async move {
                let Ok(mut tunnel) = open_tunnel(&shared, "127.0.0.1", 1).await else {
                    panic!("REALITY 握手/建隧道就失败了，这条用例就测不到 flow");
                };
                // `new_deferred` 把请求头延迟到第一次写，所以必须写一下。
                use tokio::io::AsyncWriteExt;
                let _ = tunnel.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
                let _ = tunnel.flush().await;
                drop(tunnel);
            });

            let report = out_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("服务端没有给出报告")
                .expect("服务端不应返回 Err（Err 表示服务端自己坏了）");
            server.join().expect("服务端线程 panic");
            report.outcome
        }

        // 带 flow（默认）：服务端现在**支持** Vision 流控，所以会把请求头解出来、
        // 走到连接目标那一步（目标不可达 → ConnectFailed）。
        //
        // 这里刻意**不**断言 Rejected：Vision 从「明确拒绝」变成「能用」是本次
        // 改动的目的。判据是「没有把填充帧当原始数据转发出去」——所以要求
        // 必须走到 `ConnectFailed`（说明解析是成功的），而不是 `Rejected`。
        match run(false) {
            InboundOutcome::ConnectFailed { reason } => {
                assert!(
                    reason.contains("127.0.0.1:1"),
                    "应当是因为连不上目标而失败：{reason}"
                );
            }
            InboundOutcome::Rejected { reason } => {
                panic!("服务端仍然拒绝了 Vision 请求，说明 Vision 流控没有生效：{reason}")
            }
            other => panic!("带 Vision 时应当走到连接目标那一步，实际 {other:?}"),
        }

        // 不带 flow：请求头里没有 flow，服务端放行，往后走才因为目标不可达而失败
        match run(true) {
            InboundOutcome::ConnectFailed { reason } => {
                assert!(
                    reason.contains("127.0.0.1:1"),
                    "应当是因为连不上目标而失败：{reason}"
                );
            }
            InboundOutcome::Rejected { reason } => {
                panic!("--no-flow 之后服务端仍然拒绝了请求，说明 flow 没真的置空：{reason}")
            }
            other => panic!("--no-flow 时应当走到连接目标那一步，实际 {other:?}"),
        }
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
