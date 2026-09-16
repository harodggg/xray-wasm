//! 完整 REALITY 入站探针：握手 + VLESS 解码 + 转发 + dest 回退。
//!
//! 与 `xt-wasm-tls` 的同名探针的区别：那个只做到握手，这个把整条链路都跑起来，
//! 可以用来验证 **官方 Xray 客户端 → 我们的服务端 → 真实网站** 的完整通路。
//!
//! ```sh
//! cargo run -p xt-wasm-vless --release --example reality_server_full -- \
//!     4042424242424242424242424242424242424242424242424242424242424242 \
//!     deadbeef00112233 www.cloudflare.com www.cloudflare.com:443 \
//!     b21e29c8a8ea40a2b953c2b04d73d775 18470
//! ```
//!
//! 参数：私钥(hex) / shortId(hex) / SNI / dest(认证失败时转发到哪) / 允许的 UUID(hex) / 端口
//!
//! 支持的 `flow`：空（裸路径）与 `xtls-rprx-vision`（服务端已实现解帧 + 组帧）。
//! 其它 flow 名会被**明确拒绝**，不会静默降级。

use xt_wasm_runtime::{block_on, listen, spawn_task};
use xt_wasm_tls::RealityServerConfig;
use xt_wasm_vless::{serve_inbound, InboundConfig};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 7 {
        eprintln!(
            "用法: reality_server_full <私钥hex> <shortId hex> <SNI> <dest> <UUID hex> <端口>"
        );
        std::process::exit(2);
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&from_hex(&a[1]));
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&from_hex(&a[2]));
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&from_hex(&a[5]));
    let port = a[6].clone();

    let cfg = InboundConfig {
        reality: RealityServerConfig {
            private_key,
            short_ids: vec![short_id],
            server_names: vec![a[3].clone()],
            max_time_diff_secs: 60,
        },
        dest: a[4].clone(),
        users: vec![uuid],
    };

    block_on(async move {
        let listener = listen(&format!("127.0.0.1:{port}"))
            .await
            .expect("监听失败");
        println!("READY {}", listener.local_addr().expect("local_addr"));

        loop {
            let stream = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    println!("ACCEPT_ERR {e}");
                    continue;
                }
            };
            // 每条连接独立成任务 —— 与 CLI 里的并发模型一致
            let cfg = cfg.clone();
            spawn_task(async move {
                match serve_inbound(Box::new(stream), &cfg).await {
                    Ok(o) => println!("OK {o:?}"),
                    Err(e) => println!("ERR {e}"),
                }
            });
        }
    });
}
