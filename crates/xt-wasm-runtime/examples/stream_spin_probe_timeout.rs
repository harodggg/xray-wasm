//! 第三刀 · 第 1 步：在 socket 层探针上**只加一层 `timeout(...)`**。
//!
//! 本仓库的 `timeout` 用 `futures::future::select` 把「被包裹的 future」和
//! 「Timer」放在**同一个 task** 里轮询。而 `Ready` 只有**一颗** `WaitFor` 槽位 ——
//! 若同一条流上先后有不同 future 来注册，waker 会被互相覆盖，可能留下失效注册。
//!
//! 若这个探针开始自旋，而 `stream_spin_probe`（不带 timeout）不自旋 ⇒
//! 根因就在这一层。
use std::time::Duration;
use tokio::io::AsyncReadExt;
use xt_wasm_runtime::{block_on, listen, spawn_task, timeout, Stream};

fn main() {
    let port = std::env::args().nth(1).unwrap_or_else(|| "12398".into());
    block_on(async move {
        let listener = listen(&format!("127.0.0.1:{port}")).await.expect("listen");
        eprintln!("[stream-probe-timeout] listening {port}");
        loop {
            let stream = listener.accept().await.expect("accept");
            spawn_task(async move {
                let mut s: Box<dyn Stream> = Box::new(stream);
                let mut buf = [0u8; 1024];
                // 只加这一层：超时 1 小时（不会真的触发，只是为了引入 select 的结构）
                let _ = timeout(Duration::from_secs(3600), s.read(&mut buf)).await;
            });
        }
    })
}
