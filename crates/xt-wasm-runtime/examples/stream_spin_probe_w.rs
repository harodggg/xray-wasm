//! 第三刀 · 第 2b 步：只写不读（用于区分「写」本身 vs「读写交替」）。
//!
//! 模拟握手期的形状：对同一条流 write → read → write → read …，最后停在一个
//! 永远等不到数据的 read 上（客户端不发数据）。目的是看同一条流的读/写两侧
//! 反复注册 waker 是否会引发自旋。
use tokio::io::AsyncWriteExt;
use xt_wasm_runtime::{block_on, listen, spawn_task, Stream};

fn main() {
    let port = std::env::args().nth(1).unwrap_or_else(|| "12396".into());
    block_on(async move {
        let listener = listen(&format!("127.0.0.1:{port}")).await.expect("listen");
        eprintln!("[stream-probe-rw] listening {port}");
        loop {
            let stream = listener.accept().await.expect("accept");
            spawn_task(async move {
                let mut s: Box<dyn Stream> = Box::new(stream);
                let buf = [0u8; 1024];
                // 只写不读：写完就挂着（用一个永不完成的 future 让任务活着）
                for _ in 0..3 {
                    if s.write_all(&[0x16, 0x03, 0x01, 0x00, 0x64]).await.is_err() {
                        return;
                    }
                    let _ = s.flush().await;
                }
                let _ = buf;
                std::future::pending::<()>().await;
            });
        }
    })
}
