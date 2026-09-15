//! **服务端模式**（REALITY 入站）：`xt-wasm-cli server ...`
//!
//! 与默认的 SOCKS5 客户端模式相对：这个模式**接受**连接、解开 REALITY 隧道、
//! 把流量转发到目标站；认证失败的连接则原样转发到 `dest`（抗主动探测）。
//!
//! # 这个模式主要是给 k3s 用的
//!
//! 因此配置全部支持环境变量（k3s 里用 Secret 注入，而不是把密钥写进 `args` ——
//! `kubectl describe pod` 会把 args 原样打出来）。命令行参数优先于环境变量。
//!
//! ```sh
//! xt-wasm-cli server \
//!     --listen 0.0.0.0:8443 \
//!     --private-key <base64url> \
//!     --short-ids 0123456789abcdef \
//!     --server-names www.example.com \
//!     --dest www.example.com:443 \
//!     --users b21e29c8-a8ea-40a2-b953-c2b04d73d775
//! ```
//!
//! # 与客户端模式的安全取向**相反**
//!
//! 客户端默认只监听回环、并警告「开放代理」；服务端**天生就是要暴露的**（否则没人连得上）。
//! 所以这里的警告方向不同：
//!
//! * `users` / `short_ids` 为空 → 直接拒绝启动（配置出来是个谁都进不来的服务端，几乎总是笔误）；
//! * 没有认证的探测者会被转发到 `dest`，这是**设计行为**而非漏洞。
//!
//! # 日志：一行 = 一次请求的完整结局
//!
//! ```text
//! ts=2026-09-15T11:02:03Z dir=in src=10.0.0.5:51234 sni=www.example.com \
//!   ver=26.3.27 sid=0011223344556677 target=example.com:443 outcome=Forwarded \
//!   dur_ms=412 up_bytes=830 down_bytes=41230
//! ```
//!
//! `outcome=` 的全部取值见 [`xt_wasm_vless::InboundOutcome`]：
//! `Forwarded | FellBack | Rejected | ResolveFailed | ConnectFailed`
//! （外加 `Error`，表示服务端自身出错）。
//! 于是 `grep outcome=Rejected` 一眼就能看出「是客户端配置不对」，
//! 而且**不必再配对两行日志**。
//!
//! ## 为什么值要转义
//!
//! `sni` 与 `target` 是**对端可控**的字节。不转义的话，攻击者只要在 SNI 里塞一个
//! 换行，就能在日志里凭空伪造出一条 `outcome=Forwarded` —— 日志是排障与审计的依据，
//! 能被伪造就等于没有。所以所有网络来源的字段都过 [`field`]，控制字符一律转义。

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use xt_wasm_runtime::{block_on, sleep, spawn_task};
use xt_wasm_tls::RealityServerConfig;
use xt_wasm_vless::{serve_inbound, InboundConfig, InboundOutcome, InboundReport};

use crate::{decode_base64url, decode_hex_8, decode_uuid, env_flag, env_opt, usage_server};

/// 并发上限。与客户端同量级：内存与 fd 有限，没有背压会被慢连接拖垮。
const MAX_CONCURRENT_CONNS: usize = 256;

fn format_short_id(b: &[u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn format_version(v: &[u8; 3]) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

// ───────────────────────────── 日志格式化 ─────────────────────────────

/// 转义一个**值**，保证它不会破坏「一行一条」。
///
/// 之所以是安全相关的而不是美化：`sni` / `target` 直接来自对端。
/// 见模块头的说明。
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 渲染一个 `key=value` 字段。
///
/// 正常值（域名、host:port、UUID）原样输出，日志保持工单里规定的形状；
/// 一旦值里出现空白或引号（只可能来自畸形输入），就加引号 ——
/// 这样**任何**输入下这一行都仍然能被按空格切分。
fn field(key: &str, value: &str) -> String {
    let needs_quote = value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c.is_control());
    if needs_quote {
        format!("{key}=\"{}\"", esc(value))
    } else {
        format!("{key}={value}")
    }
}

/// 自由文本字段（我们自己的话），一律加引号。
fn text(key: &str, value: &str) -> String {
    format!("{key}=\"{}\"", esc(value))
}

/// 当前 UTC 时间的 RFC3339 表示（秒精度）。
///
/// 自己算而不是引依赖：本次改动要求「不加新依赖」，而我们只需要
/// `YYYY-MM-DDTHH:MM:SSZ` 这一种形状。
fn rfc3339_utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_from_unix(secs)
}

/// 把 unix 秒格式化成 RFC3339（UTC）。
fn rfc3339_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant 的 `civil_from_days`：把「1970-01-01 起的天数」转成 (年,月,日)。
///
/// 纯整数运算、无查表、无依赖；写成这样是为了不必为了一个时间戳把
/// `chrono`/`time` 拖进 wasm。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 一次请求的日志行。字段顺序与工单一致。
struct LogLine<'a> {
    dir: &'a str,
    src: &'a str,
    sni: Option<&'a str>,
    ver: Option<[u8; 3]>,
    sid: Option<[u8; 8]>,
    target: Option<&'a str>,
    outcome: &'a str,
    reason: Option<&'a str>,
    dur_ms: u64,
    up_bytes: u64,
    down_bytes: u64,
}

impl std::fmt::Display for LogLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = vec![
            format!("ts={}", rfc3339_utc_now()),
            format!("dir={}", self.dir),
            field("src", self.src),
        ];
        // 缺失的字段写 `-` 而不是省略：列数固定，`awk`/`cut` 才好用。
        parts.push(field("sni", self.sni.unwrap_or("-")));
        parts.push(format!(
            "ver={}",
            self.ver
                .as_ref()
                .map(format_version)
                .unwrap_or_else(|| "-".into())
        ));
        parts.push(format!(
            "sid={}",
            self.sid
                .as_ref()
                .map(format_short_id)
                .unwrap_or_else(|| "-".into())
        ));
        parts.push(field("target", self.target.unwrap_or("-")));
        parts.push(format!("outcome={}", self.outcome));
        if let Some(r) = self.reason {
            parts.push(text("reason", r));
        }
        parts.push(format!("dur_ms={}", self.dur_ms));
        parts.push(format!("up_bytes={}", self.up_bytes));
        parts.push(format!("down_bytes={}", self.down_bytes));
        write!(f, "{}", parts.join(" "))
    }
}

/// 把一条连接的结局渲染成日志行。
///
/// `peer` / `dur_ms` 由调用方测量后传进来 —— 它们是「连接级」的事实，
/// 报告里没有，硬塞进 report 会让库层多背两个与协议无关的字段。
fn report_line(report: &InboundReport, peer: &str, dur_ms: u64) -> Option<String> {
    // `dir` 由「握手有没有认证成功」决定：认证成功必有 client_version，
    // 回退路径必没有。用 `client_version` 而不是 outcome 来判，是因为
    // `ConnectFailed`/`ResolveFailed` 两条路径都可能发生，光看 outcome 分不出来。
    let dir = if report.client_version.is_some() {
        "in"
    } else {
        "fallback"
    };

    let (outcome, reason) = match &report.outcome {
        InboundOutcome::Forwarded => ("Forwarded", None),
        InboundOutcome::FellBack => ("FellBack", None),
        InboundOutcome::Rejected { reason } => ("Rejected", Some(reason.as_str())),
        InboundOutcome::ResolveFailed { reason } => ("ResolveFailed", Some(reason.as_str())),
        InboundOutcome::ConnectFailed { reason } => ("ConnectFailed", Some(reason.as_str())),
        // 空连接**故意不记日志**（返回 None）。公网端口上探针/扫描器是最频繁的事件，
        // 一条 k8s tcpSocket 探针每 10 秒来一次，记下来就是每天 8000+ 行噪音，
        // 真出故障时反而找不到北。
        InboundOutcome::EmptyConnection => return None,
    };

    Some(
        LogLine {
            dir,
            src: peer,
            sni: report.server_name.as_deref(),
            ver: report.client_version,
            sid: report.short_id,
            target: report.target.as_deref(),
            outcome,
            reason,
            dur_ms,
            up_bytes: report.up_bytes,
            down_bytes: report.down_bytes,
        }
        .to_string(),
    )
}

// ───────────────────────────── 参数 ─────────────────────────────

/// 服务端参数。
pub struct ServerArgs {
    pub listen: String,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub dest: String,
    pub users: Vec<[u8; 16]>,
    pub max_time_diff_secs: u64,
    /// 只做配置自检：解析、打印、退出，**不监听**。
    pub check: bool,
}

/// 配置错误：打印原因并以 2 退出。
///
/// # 一个必须知道的平台差异
///
/// 退出码 2 只在**宿主**上可观察。**wasmtime 会把 guest 的任何非 0 退出码
/// 塌缩成 1**（实测 `exit(2)`/`exit(42)` 都得到 1）。所以容器里、
/// k8s `initContainer` 里、CI 里能断言的只有「0 / 非 0」，
/// 不能断言「恰好 2」—— 写成 `== 2` 的检查在宿主上过、在 wasm 上必红。
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[server] 配置错误：{msg}");
    std::process::exit(2)
}

/// 解析 `a,b,c` 形式的列表（去空项、去空白）。
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// 解析服务端参数：环境变量打底，命令行覆盖。
pub fn parse_server_args(argv: &[String]) -> ServerArgs {
    let mut listen = env_opt("XT_SERVER_LISTEN").unwrap_or_else(|| "0.0.0.0:8443".to_string());
    let mut private_key = env_opt("XT_PRIVATE_KEY");
    let mut short_ids = env_opt("XT_SHORT_IDS");
    let mut server_names = env_opt("XT_SERVER_NAMES");
    let mut dest = env_opt("XT_DEST");
    let mut users = env_opt("XT_USERS");
    let mut max_time_diff = env_opt("XT_MAX_TIME_DIFF");
    let mut check = env_flag("XT_CHECK");

    let mut i = 0;
    while i < argv.len() {
        let need = |i: usize| -> String {
            argv.get(i + 1).cloned().unwrap_or_else(|| {
                eprintln!("参数 {} 缺少取值", argv[i]);
                usage_server()
            })
        };
        match argv[i].as_str() {
            "--listen" => listen = need(i),
            "--private-key" => private_key = Some(need(i)),
            "--short-ids" => short_ids = Some(need(i)),
            "--server-names" => server_names = Some(need(i)),
            "--dest" => dest = Some(need(i)),
            "--users" => users = Some(need(i)),
            "--max-time-diff" => max_time_diff = Some(need(i)),
            "--check" => {
                check = true;
                // 这个开关不带取值，单独处理以免多吃一个参数
                i += 1;
                continue;
            }
            "-h" | "--help" => usage_server(),
            other => {
                eprintln!("未知参数：{other}");
                usage_server()
            }
        }
        i += 2;
    }

    let private_key_raw = private_key
        .unwrap_or_else(|| die("缺少 --private-key（或 XT_PRIVATE_KEY）。用 `xray x25519` 生成"));
    let private_key_bytes = decode_base64url(&private_key_raw).unwrap_or_else(|e| {
        die(format!(
            "XT_PRIVATE_KEY / --private-key 不是合法 base64url：{e}"
        ))
    });
    let private_key: [u8; 32] = private_key_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        die(format!(
            "XT_PRIVATE_KEY 解出 {} 字节，X25519 私钥应为 32 字节",
            v.len()
        ))
    });

    let short_ids_raw = split_list(&short_ids.unwrap_or_default());
    if short_ids_raw.is_empty() {
        die("XT_SHORT_IDS / --short-ids 为空。至少要有一个，否则没有客户端能通过认证");
    }
    let short_ids: Vec<[u8; 8]> = short_ids_raw
        .iter()
        .map(|s| decode_hex_8("--short-ids", s))
        .collect();

    let server_names = split_list(&server_names.unwrap_or_default());
    if server_names.is_empty() {
        die("XT_SERVER_NAMES / --server-names 为空。客户端的 SNI 必须落在这个列表里");
    }

    let dest = dest.unwrap_or_else(|| {
        die("缺少 XT_DEST / --dest。认证失败的连接要原样转发到它，例如 www.example.com:443")
    });
    if !is_host_port(&dest) {
        die(format!(
            "XT_DEST / --dest 应为 host:port 形式，实际 {dest:?}"
        ));
    }

    let users_raw = split_list(&users.unwrap_or_default());
    if users_raw.is_empty() {
        die("XT_USERS / --users 为空。空列表意味着谁也连不上");
    }
    let users: Vec<[u8; 16]> = users_raw
        .iter()
        .map(|s| decode_uuid("--users", s))
        .collect();

    let max_time_diff_secs = max_time_diff
        .map(|s| {
            s.parse::<u64>()
                .unwrap_or_else(|_| die(format!("XT_MAX_TIME_DIFF 应为秒数，实际 {s:?}")))
        })
        .unwrap_or(60);

    ServerArgs {
        listen,
        private_key,
        short_ids,
        server_names,
        dest,
        users,
        max_time_diff_secs,
        check,
    }
}

/// `host:port` 的粗校验。
///
/// 只要求「有非空的 host 和能解析成 u16 的 port」。刻意不在这里做 DNS ——
/// 配置自检不该依赖网络可达性（k8s 的 initContainer 里可能还没有网）。
fn is_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().is_ok()
}

// ───────────────────────────── 配置自检 ─────────────────────────────

/// 私钥脱敏：只留头尾各 4 个字符。
///
/// 目的是让人能对着 `xray x25519` 的输出确认「是不是这一串」，
/// 同时**绝不**把整串私钥写进任何日志、控制台或 CI 输出。
fn mask_secret(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        // 太短就整体遮掉 —— 露 4 个头尾等于全露。
        return "…".to_string();
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail}")
}

/// 打印生效配置并返回退出码。**不监听任何端口。**
///
/// 这是给 k8s 用的：可以放进 initContainer，或用 `kubectl run` 一次性跑，
/// 在真正起服务之前就确认「Secret 挂对了、变量名没拼错、私钥能解出来」。
/// 三件事里任何一件错了，现在都只有一个笼统的启动失败。
pub fn check_config(args: &ServerArgs) -> u8 {
    let pubkey = xt_wasm_tls::reality_public_key(&args.private_key);
    println!("[check] 配置自检通过（未监听任何端口）");
    println!("[check] listen          = {}", args.listen);
    println!(
        "[check] private_key     = {}（已脱敏，{} 字符）",
        mask_secret(&enc_b64url(&args.private_key)),
        enc_b64url(&args.private_key).chars().count()
    );
    // 公钥**不算机密** —— 它本来就要发给每一个客户端。把它打出来是为了回答
    // 真正有用的那个问题：「Secret 里的私钥，和客户端配的 XT_PBK 是一对吗？」
    // 只有私钥的运维此前没法自查这一点。
    println!("[check] public_key      = {}", enc_b64url(&pubkey));
    println!(
        "[check] server_names    = {}（{} 个）",
        args.server_names.join(","),
        args.server_names.len()
    );
    println!(
        "[check] short_ids       = {}（{} 个）",
        args.short_ids
            .iter()
            .map(format_short_id)
            .collect::<Vec<_>>()
            .join(","),
        args.short_ids.len()
    );
    println!(
        "[check] users           = {} 个（UUID 不逐条打印，避免刷屏）",
        args.users.len()
    );
    println!("[check] dest            = {}", args.dest);
    println!("[check] max_time_diff   = {} 秒", args.max_time_diff_secs);
    0
}

/// base64url 编码（无填充）。只为把私钥/公钥按 `xray x25519` 的形状打印出来。
fn enc_b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

// ───────────────────────────── 主循环 ─────────────────────────────

/// 跑服务端，永不返回。
pub fn run_server(args: ServerArgs) -> ! {
    // 自检模式：打印完就退出，绝不监听。
    if args.check {
        std::process::exit(check_config(&args) as i32);
    }

    println!(
        "[server] REALITY 入站：监听 {}，SNI {:?}，用户 {} 个，dest {}",
        args.listen,
        args.server_names,
        args.users.len(),
        args.dest
    );
    println!("[server] 认证失败的连接会被原样转发到 dest（这是设计行为，不是漏洞）");
    println!("[server] 日志格式：ts= dir= src= sni= ver= sid= target= outcome= dur_ms= up_bytes= down_bytes=");

    let inbound = InboundConfig {
        reality: RealityServerConfig {
            private_key: args.private_key,
            short_ids: args.short_ids,
            server_names: args.server_names,
            max_time_diff_secs: args.max_time_diff_secs,
        },
        dest: args.dest.clone(),
        users: args.users,
    };

    let listen_addr = args.listen.clone();
    let result = block_on(async move {
        let listener = xt_wasm_runtime::listen(&listen_addr).await?;
        let live = Rc::new(Cell::new(0usize));

        loop {
            let stream = listener.accept().await?;
            // 先拿对端地址：装箱之后就拿不到了
            let peer = stream.peer_addr().unwrap_or_else(|_| "?".to_string());

            while live.get() >= MAX_CONCURRENT_CONNS {
                sleep(Duration::from_millis(5)).await;
            }
            live.set(live.get() + 1);

            let inbound = inbound.clone();
            let live_task = Rc::clone(&live);
            spawn_task(async move {
                let started = Instant::now();
                let result = serve_inbound(Box::new(stream), &inbound).await;
                let dur_ms = started.elapsed().as_millis() as u64;

                // **一次请求一行**。`serve_inbound` 返回的 report 里已经带齐了
                // 分类 + SNI + 身份 + 目标 + 字节数，所以这里不必再去配对
                // 「开始」和「结束」两行。
                match result {
                    Ok(report) => {
                        if let Some(line) = report_line(&report, &peer, dur_ms) {
                            println!("[server] {line}");
                        }
                    }
                    // `Err` 只剩一种含义：服务端自己出了问题。
                    Err(e) => eprintln!(
                        "[server] {}",
                        LogLine {
                            dir: "in",
                            src: &peer,
                            sni: None,
                            ver: None,
                            sid: None,
                            target: None,
                            outcome: "Error",
                            reason: Some(&e.to_string()),
                            dur_ms,
                            up_bytes: 0,
                            down_bytes: 0,
                        }
                    ),
                }
                live_task.set(live_task.get().saturating_sub(1));
            });
        }

        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });

    if let Err(e) = result {
        eprintln!("[server] 致命错误：{e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instants() {
        // 这些是外部可核对的值：1970 起点、闰年 2 月 29、以及一个普通时刻。
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_770_000_000), "2026-02-02T02:40:00Z");
        // 2026-09-15T11:02:03Z 是本工程写这段代码时的一个真实时刻
        assert_eq!(rfc3339_from_unix(1_789_470_123), "2026-09-15T11:02:03Z");
    }

    #[test]
    fn log_line_has_every_field_in_order() {
        let line = LogLine {
            dir: "in",
            src: "10.0.0.5:51234",
            sni: Some("www.example.com"),
            ver: Some([26, 3, 27]),
            sid: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
            target: Some("example.com:443"),
            outcome: "Forwarded",
            reason: None,
            dur_ms: 412,
            up_bytes: 830,
            down_bytes: 41230,
        }
        .to_string();

        assert!(
            line.contains("dir=in")
                && line.contains("src=10.0.0.5:51234")
                && line.contains("sni=www.example.com")
                && line.contains("ver=26.3.27")
                && line.contains("sid=0011223344556677")
                && line.contains("target=example.com:443")
                && line.contains("outcome=Forwarded")
                && line.contains("dur_ms=412")
                && line.contains("up_bytes=830")
                && line.contains("down_bytes=41230"),
            "字段缺失：{line}"
        );
        assert!(line.starts_with("ts="), "ts 必须是第一个字段：{line}");
        assert!(!line.contains('\n'));
    }

    /// 畸形 SNI 不得伪造出第二行日志。
    ///
    /// 这是**安全用例**，不是格式用例：SNI 完全由对端控制，
    /// 不转义的话攻击者能往日志里注入任意内容，审计就废了。
    #[test]
    fn hostile_sni_cannot_inject_a_log_line() {
        let line = LogLine {
            dir: "in",
            src: "10.0.0.5:1",
            sni: Some("evil\n[server] ts=x outcome=Forwarded dur_ms=1"),
            ver: None,
            sid: None,
            target: Some("a b"),
            outcome: "Rejected",
            reason: Some("因为\n换行"),
            dur_ms: 0,
            up_bytes: 0,
            down_bytes: 0,
        }
        .to_string();

        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "日志里出现了真换行，可以被注入伪造行：{line}"
        );
        assert!(line.contains("\\n"), "换行应被转义成字面量 \\n：{line}");
    }

    #[test]
    fn missing_fields_render_as_dash_to_keep_columns_fixed() {
        let line = LogLine {
            dir: "fallback",
            src: "-",
            sni: None,
            ver: None,
            sid: None,
            target: None,
            outcome: "FellBack",
            reason: None,
            dur_ms: 0,
            up_bytes: 0,
            down_bytes: 0,
        }
        .to_string();
        assert!(line.contains("sni=-"), "{line}");
        assert!(line.contains("ver=-"), "{line}");
        assert!(line.contains("sid=-"), "{line}");
        assert!(line.contains("target=-"), "{line}");
    }

    #[test]
    fn secret_is_masked_and_never_echoed_whole() {
        let s = "OE-2HOj2MdvfztxO5IHpjTTFz_hhsjUqerU3NyIs12E";
        let m = mask_secret(s);
        assert_eq!(m, "OE-2…s12E");
        assert_ne!(m, s);
        // 短串必须整体遮掉：露 4 个头尾等于全露
        assert_eq!(mask_secret("abcd"), "…");
    }

    #[test]
    fn host_port_validation() {
        assert!(is_host_port("www.example.com:443"));
        assert!(is_host_port("1.2.3.4:8443"));
        assert!(is_host_port("[::1]:443"));
        assert!(!is_host_port("www.example.com"));
        assert!(!is_host_port(":443"));
        assert!(!is_host_port("www.example.com:notaport"));
        assert!(!is_host_port("www.example.com:99999"));
    }

    #[test]
    fn b64url_matches_xray_output_shape() {
        // 32 字节 → 43 个字符（无填充），与 `xray x25519` 的输出一致
        assert_eq!(enc_b64url(&[0u8; 32]).len(), 43);
        assert_eq!(enc_b64url(&[]), "");
        assert_eq!(enc_b64url(&[0xff, 0xff, 0xff]), "____");
    }
}
