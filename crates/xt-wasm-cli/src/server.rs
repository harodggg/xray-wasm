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

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use xt_wasm_runtime::{block_on, sleep, spawn_task};
use xt_wasm_tls::RealityServerConfig;
use xt_wasm_vless::{serve_inbound_with_events, InboundConfig, InboundEvent, InboundOutcome};

use crate::{decode_base64url, decode_hex_8, decode_uuid, env_flag, env_opt, usage_server};

/// 并发上限。与客户端同量级：内存与 fd 有限，没有背压会被慢连接拖垮。
const MAX_CONCURRENT_CONNS: usize = 256;

/// 把 UUID 渲染回 `8-4-4-4-12` 的规范形式。
///
/// 日志里用的是它，不是 16 字节裸 hex —— 运维要拿这一行去和 Secret 里的
/// `XT_USERS` 对照，格式必须一致。
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

/// 服务端参数。
pub struct ServerArgs {
    pub listen: String,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub dest: String,
    pub users: Vec<[u8; 16]>,
    pub max_time_diff_secs: u64,
}

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
    let _ = env_flag("XT_SELF_TEST"); // 服务端模式没有这个开关，读一下保持行为一致

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
    let private_key_bytes = decode_base64url(&private_key_raw)
        .unwrap_or_else(|e| die(format!("--private-key 不是合法 base64url：{e}")));
    let private_key: [u8; 32] = private_key_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        die(format!(
            "--private-key 解出 {} 字节，X25519 私钥应为 32 字节",
            v.len()
        ))
    });

    let short_ids_raw = split_list(&short_ids.unwrap_or_default());
    if short_ids_raw.is_empty() {
        die("缺少 --short-ids（或 XT_SHORT_IDS）。至少要有一个，否则没有客户端能通过认证");
    }
    let short_ids: Vec<[u8; 8]> = short_ids_raw.iter().map(|s| decode_hex_8(s)).collect();

    let server_names = split_list(&server_names.unwrap_or_default());
    if server_names.is_empty() {
        die("缺少 --server-names（或 XT_SERVER_NAMES）。客户端的 SNI 必须落在这个列表里");
    }

    let dest = dest.unwrap_or_else(|| {
        die("缺少 --dest（或 XT_DEST）。认证失败的连接要原样转发到它，例如 www.example.com:443")
    });

    let users_raw = split_list(&users.unwrap_or_default());
    if users_raw.is_empty() {
        die("缺少 --users（或 XT_USERS）。空列表意味着谁也连不上");
    }
    let users: Vec<[u8; 16]> = users_raw.iter().map(|s| decode_uuid(s)).collect();

    let max_time_diff_secs = max_time_diff
        .map(|s| {
            s.parse::<u64>()
                .unwrap_or_else(|_| die(format!("--max-time-diff 应为秒数，实际 {s:?}")))
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
    }
}

/// 跑服务端，永不返回。
pub fn run_server(args: ServerArgs) -> ! {
    println!(
        "[server] REALITY 入站：监听 {}，SNI {:?}，用户 {} 个，dest {}",
        args.listen,
        args.server_names,
        args.users.len(),
        args.dest
    );
    println!("[server] 认证失败的连接会被原样转发到 dest（这是设计行为，不是漏洞）");

    let inbound = InboundConfig {
        reality: RealityServerConfig {
            private_key: args.private_key,
            short_ids: args.short_ids,
            server_names: args.server_names,
            max_time_diff_secs: args.max_time_diff_secs,
        },
        dest: args.dest,
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
                // 判定一出来就记一笔。`serve_inbound` 的返回值要等整条连接结束
                // （长连接可能几小时）才拿到，只靠它等于没有实时日志。
                let peer_ev = peer.clone();
                let outcome =
                    serve_inbound_with_events(Box::new(stream), &inbound, move |ev| match ev {
                        InboundEvent::Authenticated { user, target } => println!(
                            "[server] {peer_ev} 认证通过 user={} -> {target}",
                            format_uuid(&user)
                        ),
                        InboundEvent::Fallback { server_name } => println!(
                            "[server] {peer_ev} 未认证（sni={}），转发到 dest",
                            server_name.as_deref().unwrap_or("-")
                        ),
                    })
                    .await;

                match outcome {
                    // 空连接**故意不记日志**。公网端口上探针/扫描器是最频繁的事件，
                    // 一条 k8s tcpSocket 探针每 10 秒来一次，记下来就是每天 8000+ 行噪音，
                    // 真出故障时反而找不到北。要确认「端口通不通」看 accept 循环有没有日志
                    // （认证/回退那两行），要排查客户端问题看它有没有发出 ClientHello。
                    Ok(InboundOutcome::EmptyConnection) => {}
                    Ok(o) => println!("[server] {peer} 结束：{o:?}"),
                    Err(e) => eprintln!("[server] {peer} 失败：{e}"),
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
