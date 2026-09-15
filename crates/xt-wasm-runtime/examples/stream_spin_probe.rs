//! 第二刀的最小复现器：**只用我们自己的 NetListener/NetStream**，不含协议层。
//!
//! accept 一条连接 → 起一个任务去 `read`（客户端不发数据 ⇒ 永久 park）。
//! 若这里也自旋 ⇒ 根因在我们的 socket 层 + wstd executor，与 TLS/VLESS 无关。
//! 若不自旋 ⇒ 嫌疑回到协议层（它大量读写、并在此之上创建了第二批等待）。
//!
//! 用法： wasmtime run ... stream_spin_probe.wasm <port>
use tokio::io::AsyncReadExt;
use xt_wasm_runtime::{block_on, listen, spawn_task, Stream};

fn main() {
    let port = std::env::args().nth(1).unwrap_or_else(|| "12399".into());
    block_on(async move {
        let listener = listen(&format!("127.0.0.1:{port}")).await.expect("listen");
        eprintln!("[stream-probe] listening {port}");
        loop {
            let stream = listener.accept().await.expect("accept");
            spawn_task(async move {
                let mut s: Box<dyn Stream> = Box::new(stream);
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
            });
        }
    })
}
