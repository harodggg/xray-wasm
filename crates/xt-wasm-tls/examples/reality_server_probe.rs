//! 手工互通探针：起一个**只做握手**的 REALITY 服务端，让**官方 Xray 客户端**连过来。
//!
//! 运行（先在 `.scripts/gen-test-server.sh` 那种环境里备好密钥，或者直接用固定夹具）：
//!
//! ```sh
//! cargo run -p xt-wasm-tls --release --example reality_server_probe -- \
//!     4042424242424242424242424242424242424242424242424242424242424242 \
//!     deadbeef00112233 www.cloudflare.com 18450
//! ```
//!
//! 参数依次是：服务端私钥(hex)、shortId(hex)、SNI、监听端口。
//!
//! # 这个探针验的是什么
//!
//! 单元测试里已经有「我们客户端 ↔ 我们服务端」的自环握手，但那只能证明**自洽**。
//! 官方客户端会做两件我们自己客户端不做的事：
//!
//! 1. **真的校验 CertificateVerify 的签名**（我们客户端目前跳过这一步），
//!    所以服务端必须用真 ed25519 私钥签，糊弄不过去；
//! 2. 用 Go 真正的 `x509.ParseCertificate` 解析证书 —— 第一版那张「最小证书」
//!    就是这么被拒的（回 `bad_certificate` 告警）。
//!
//! 所以这个探针是阶段 2 唯一有说服力的验证手段：它成功即说明官方实现认可
//! 我们的 TLS 1.3 服务端握手。
//!
//! # 为什么只做到握手
//!
//! VLESS 服务端解码与 `dest` 回退还没实现（见 README 的「REALITY 入站」），
//! 所以这里读到的应用数据就是客户端发来的 **VLESS 请求头**，
//! 探针把它打印出来就结束 —— 足够证明握手与解密都对了。

use tokio::io::AsyncReadExt;
use xt_wasm_runtime::{block_on, listen};
use xt_wasm_tls::{reality_server_handshake, HandshakeOutcome, RealityServerConfig};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("用法: reality_server_probe <私钥hex> <shortId hex> <SNI> [端口]");
        std::process::exit(2);
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&from_hex(&args[1]));
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&from_hex(&args[2]));
    let sni = args[3].clone();
    let port = args.get(4).cloned().unwrap_or_else(|| "18450".to_string());

    let cfg = RealityServerConfig {
        private_key,
        short_ids: vec![short_id],
        server_names: vec![sni],
        max_time_diff_secs: 60,
    };

    block_on(async move {
        let listener = listen(&format!("127.0.0.1:{port}")).await.expect("监听失败");
        println!("PROBE_READY {}", listener.local_addr().expect("local_addr"));

        let stream = listener.accept().await.expect("accept 失败");
        println!("PROBE_ACCEPTED");

        match reality_server_handshake(Box::new(stream), &cfg).await {
            Ok(HandshakeOutcome::Authenticated { mut stream, auth }) => {
                println!(
                    "PROBE_AUTH_OK short_id={:02x?} client_ver={:?}",
                    auth.short_id, auth.client_version
                );
                let mut buf = [0u8; 512];
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let head: String =
                            buf[..n.min(48)].iter().map(|b| format!("{b:02x}")).collect();
                        println!("PROBE_APPDATA {n} bytes, head={head}");
                    }
                    Ok(_) => println!("PROBE_APPDATA_EOF"),
                    Err(e) => println!("PROBE_APPDATA_ERR {e}"),
                }
            }
            Ok(HandshakeOutcome::Fallback { .. }) => println!("PROBE_FALLBACK"),
            Err(e) => println!("PROBE_ERR {e}"),
        }
    });
}
