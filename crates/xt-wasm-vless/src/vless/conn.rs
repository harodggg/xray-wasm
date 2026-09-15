// Ported from meow-rs <https://github.com/meow-rs/meow-rs> @ a2be4de1c315daa22e53ad1118538936241d592f
// (crates/meow-proxy/src/vless/conn.rs, lines 1-327 — the `VlessConn` TCP half).
// MIT licensed, Copyright (c) 2026 Max Lv. See LICENSE.meow-rs.
//
// Modified for the wasm32-wasip2 port:
//   * `meow_common`/`meow_transport` paths → `crate`/`xt_wasm_tls`;
//   * tokio's `net` feature is never referenced; the socket bridge lives in
//     `xt-wasm-runtime`;
//   * Mux.Cool (`new_mux`/`new_mux_deferred`) is out of scope and dropped;
//   * `VlessPacketConn` (UDP-over-TCP, upstream lines 329+) is out of scope and
//     absent, which drops `ProxyPacketConn`, `check_not_desynced` and
//     `PoisonOnIncomplete` too;
//   * `#[tokio::test]` → `#[test]` + `xt_wasm_runtime::block_on`, with
//     tokio's task spawn replaced by `futures::join!`.

//! `VlessConn` — TCP passthrough connection wrapping a transport-layer stream.
//!
//! After construction (`new().await`), the VLESS request header has been sent and
//! the VLESS response header has been read and validated.  Subsequent `AsyncRead`
//! and `AsyncWrite` calls pass through to the underlying stream directly.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xt_wasm_tls::Stream;

use super::header::{encode_request, Cmd, VlessAddr};
use crate::{MeowError, ProxyConn, Result};

// ─── VlessConn ────────────────────────────────────────────────────────────────

/// A VLESS TCP connection — request header sent, response header consumed lazily.
///
/// The response header is read on the first `poll_read` call, not during
/// construction. This matches upstream xray-core behavior where the server
/// only sends the response after connecting to the destination.
pub struct VlessConn {
    pub(crate) inner: Box<dyn Stream>,
    /// `true` until the 2-byte response header has been consumed.
    pub(crate) response_pending: bool,
    /// Partial response-header read progress.  Cancel-safe: a Pending
    /// between the two header bytes must not lose the byte already
    /// consumed (a local buffer would shift the whole stream by one byte).
    pub(crate) response_buf: [u8; 2],
    pub(crate) response_pos: usize,
    /// Scratch buffer for the response addon bytes (usually empty).
    pub(crate) response_addon: Vec<u8>,
    /// Pre-encoded request header, written ahead of the first payload.
    /// `Some` only for deferred-header connections (Vision): the request
    /// must ride inside the first Vision-padded record, matching
    /// mihomo/xray, so it is emitted on the first write instead of during
    /// construction.
    pub(crate) header_pending: Option<Bytes>,
    /// Set once the deferred header has reached the inner stream and cleared
    /// after the next flush.  A read-first protocol must flush the request
    /// before waiting for the server response.
    pub(crate) header_needs_flush: bool,
}

impl VlessConn {
    /// Establish a VLESS connection:
    /// 1. Write the request header.
    /// 2. Return immediately — response header is read lazily on first read.
    pub async fn new(
        mut stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
        cmd: Cmd,
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        // Write the VLESS request header.
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, flow, cmd, dst_port, addr);
        tracing::debug!("VLESS: writing {} byte request header", buf.len());
        stream.write_all(&buf).await.map_err(MeowError::Io)?;
        stream.flush().await.map_err(MeowError::Io)?;
        tracing::debug!("VLESS: request header sent, response will be read lazily");

        Ok(Self {
            inner: stream,
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: None,
            header_needs_flush: false,
        })
    }

    /// Like [`Self::new`], but defers the request header to the first
    /// write so a wrapping Vision layer can pad it together with the first
    /// payload (xray expects the request inside the first Vision record).
    pub async fn new_deferred(
        stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
        cmd: Cmd,
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, flow, cmd, dst_port, addr);
        Ok(Self {
            inner: stream,
            response_pending: true,
            response_buf: [0; 2],
            response_pos: 0,
            response_addon: Vec::new(),
            header_pending: Some(buf.freeze()),
            header_needs_flush: false,
        })
    }

    /// Write a deferred request header before the caller's first payload.
    /// Header-only progress may continue inside one poll; payload progress is
    /// reported immediately so `AsyncWrite` never returns `Pending` or
    /// `Ok(0)` after consuming caller bytes.
    fn poll_write_deferred(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let Some(header) = self.header_pending.take() else {
                return Pin::new(&mut *self.inner).poll_write(cx, buf);
            };
            let header_len = header.len();
            let mut combined = BytesMut::with_capacity(header_len + buf.len());
            combined.extend_from_slice(&header);
            combined.extend_from_slice(buf);
            match Pin::new(&mut *self.inner).poll_write(cx, &combined) {
                Poll::Pending => {
                    self.header_pending = Some(header);
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    self.header_pending = Some(header);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vless: failed to write deferred request header",
                    )));
                }
                Poll::Ready(Ok(written)) if written < header_len => {
                    self.header_pending = Some(header.slice(written..));
                }
                Poll::Ready(Ok(written)) => {
                    self.header_needs_flush = true;
                    let payload_written = written - header_len;
                    if payload_written > 0 || buf.is_empty() {
                        return Poll::Ready(Ok(payload_written));
                    }
                }
            }
        }
    }

    /// Ensure a deferred request is sent and flushed before reading or
    /// shutting down.  This is the server-first path used by SMTP, IMAP,
    /// MySQL and similar protocols that do not write application data first.
    fn poll_flush_deferred_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.header_pending.is_some() {
            let written = ready!(self.poll_write_deferred(cx, &[]))?;
            debug_assert_eq!(written, 0);
        }
        if self.header_needs_flush {
            ready!(Pin::new(&mut *self.inner).poll_flush(cx))?;
            self.header_needs_flush = false;
        }
        Poll::Ready(Ok(()))
    }

    // Called only from the Vision wrapper.
    pub(crate) fn enable_raw_read_passthrough(&mut self) -> bool {
        xt_wasm_tls::enable_raw_read_passthrough(&mut *self.inner)
    }

    pub(crate) fn enable_raw_write_passthrough(&mut self) -> bool {
        xt_wasm_tls::enable_raw_write_passthrough(&mut *self.inner)
    }
}

// ─── AsyncRead / AsyncWrite pass-through ──────────────────────────────────────

impl AsyncRead for VlessConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Lazily consume the response header on first read.  Progress lives
        // in self (response_buf/response_pos): a Pending between the two
        // header bytes must keep the byte already consumed — a local buffer
        // would lose it and shift the whole stream by one byte.
        let this = &mut *self;
        ready!(this.poll_flush_deferred_header(cx))?;
        if this.response_pending {
            while this.response_pos < 2 {
                let pos = this.response_pos;
                let mut tmp = ReadBuf::new(&mut this.response_buf[pos..]);
                match Pin::new(&mut *this.inner).poll_read(cx, &mut tmp) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vless: server closed before response header",
                            )));
                        }
                        this.response_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let version = this.response_buf[0];
            let addon_length = this.response_buf[1] as usize;
            if version != 0x00 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vless: version mismatch: expected 0x00, got {version:#04x}"),
                )));
            }
            // Discard addon bytes if any — also cancel-safe: progress
            // counts against the persistent response_pos, and the scratch
            // buffer survives Pending.
            if addon_length > 0 {
                if this.response_addon.len() != addon_length {
                    this.response_addon = vec![0u8; addon_length];
                }
                while this.response_pos - 2 < addon_length {
                    let pos = this.response_pos - 2;
                    let mut tmp = ReadBuf::new(&mut this.response_addon[pos..]);
                    match Pin::new(&mut *this.inner).poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vless: EOF during addon discard",
                                )));
                            }
                            this.response_pos += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            this.response_pending = false;
            this.response_addon = Vec::new();
            tracing::debug!("VLESS: response header consumed lazily");
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.poll_write_deferred(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_deferred_header(cx))?;
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_deferred_header(cx))?;
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl Unpin for VlessConn {}

impl ProxyConn for VlessConn {}

// NOTE: upstream's `VlessPacketConn` (UDP-over-TCP, conn.rs:329-586) and its
// UDP/mux tests are out of scope and are not ported.

// ─── Unit tests (§F) ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    struct ChunkedStream {
        inner: tokio::io::DuplexStream,
        max_write: usize,
    }

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ChunkedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let count = buf.len().min(this.max_write);
            Pin::new(&mut this.inner).poll_write(cx, &buf[..count])
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Test UUID: b831381d-6324-4d53-ad4f-8cda48b30811
    const TEST_UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    // Upstream spawned a mock server as a tokio task and shipped the header
    // bytes back through a `oneshot`.  With no runtime available, the client and
    // the mock server are two futures driven concurrently by `futures::join!`
    // under `xt_wasm_runtime::block_on`; the server future simply returns the
    // bytes it observed.

    // ─── F1: request header written on connect ────────────────────────────────

    #[test]
    fn vless_conn_writes_request_header_on_connect() {
        // The minimum VLESS header for IPv4 is:
        // version(1) + uuid(16) + addon_length(1) + cmd(1) + port(2) + addr_type(1) + ipv4(4) = 26
        let (client, mut server) = duplex(1024);

        let (conn, hdr) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut req_hdr = vec![0u8; 26];
                server.read_exact(&mut req_hdr).await.unwrap();
                req_hdr
            };
            let client_task = async {
                VlessConn::new(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .expect("VlessConn::new")
            };
            futures::join!(client_task, server_task)
        });

        drop(conn);

        // version must be 0x00
        assert_eq!(hdr[0], 0x00, "version byte must be 0x00");
        // uuid must match
        assert_eq!(&hdr[1..17], &TEST_UUID, "uuid must match");
    }

    #[test]
    fn deferred_header_handles_one_byte_partial_writes() {
        let (client, mut server) = duplex(1024);

        let (response, ()) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut request = vec![0u8; 26 + 4];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[26..], b"ping");
                server.write_all(&[0x00, 0x00, b'!']).await.unwrap();
            };

            let client_task = async {
                let mut conn = VlessConn::new_deferred(
                    Box::new(ChunkedStream {
                        inner: client,
                        max_write: 1,
                    }),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .unwrap();
                conn.write_all(b"ping").await.unwrap();
                let mut response = [0u8; 1];
                conn.read_exact(&mut response).await.unwrap();
                response
            };

            futures::join!(client_task, server_task)
        });

        assert_eq!(response, [b'!']);
    }

    #[test]
    fn deferred_header_is_flushed_before_server_first_read() {
        let (client, mut server) = duplex(1024);

        let (banner, ()) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut request = vec![0u8; 26];
                server.read_exact(&mut request).await.unwrap();
                server.write_all(&[0x00, 0x00]).await.unwrap();
                server.write_all(b"banner").await.unwrap();
            };

            let client_task = async {
                let mut conn = VlessConn::new_deferred(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    25,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .unwrap();
                let mut banner = [0u8; 6];
                conn.read_exact(&mut banner).await.unwrap();
                banner
            };

            futures::join!(client_task, server_task)
        });

        assert_eq!(&banner, b"banner");
    }

    // ─── F2: payload round-trip ───────────────────────────────────────────────

    #[test]
    fn vless_conn_tcp_payload_round_trips() {
        let (client, mut server) = duplex(4096);
        let payload = vec![0xAB; 1024];

        let (received, ()) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut hdr = vec![0u8; 26];
                server.read_exact(&mut hdr).await.unwrap();
                server.write_all(&[0x00, 0x00]).await.unwrap();
                let mut echo = vec![0u8; 1024];
                server.read_exact(&mut echo).await.unwrap();
                server.write_all(&echo).await.unwrap();
            };

            let client_task = async {
                let mut conn = VlessConn::new(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .expect("VlessConn::new");

                conn.write_all(&payload).await.unwrap();

                let mut received = vec![0u8; 1024];
                conn.read_exact(&mut received).await.unwrap();
                received
            };

            futures::join!(client_task, server_task)
        });

        assert_eq!(received, payload, "round-trip payload must match");
    }

    // ─── F3: response header discarded ───────────────────────────────────────

    #[test]
    fn vless_conn_reads_and_discards_response_header() {
        let (client, mut server) = duplex(1024);

        let (buf, ()) = xt_wasm_runtime::block_on(async {
            // The mock sends [0x00, 0x00] then a distinguishable byte pattern.
            let server_task = async move {
                // Consume the request header.
                let mut hdr = vec![0u8; 26];
                server.read_exact(&mut hdr).await.unwrap();
                // Send response header + payload.
                server
                    .write_all(&[0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
                    .await
                    .unwrap();
            };

            let client_task = async {
                let mut conn = VlessConn::new(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .expect("VlessConn::new");

                // First read must yield payload bytes (0xDE 0xAD 0xBE 0xEF),
                // not the response header.
                let mut buf = [0u8; 4];
                conn.read_exact(&mut buf).await.unwrap();
                buf
            };

            futures::join!(client_task, server_task)
        });

        assert_eq!(
            buf,
            [0xDE, 0xAD, 0xBE, 0xEF],
            "response header must be discarded"
        );
    }

    // ─── F4: nonzero addon_length in response ─────────────────────────────────

    /// Mock sends [0x00, 0x03, 0xAA, 0xBB, 0xCC] (version=0, addon=3 bytes).
    /// VlessConn must discard the 3 addon bytes and expose only subsequent payload.
    #[test]
    fn vless_conn_response_with_nonzero_addon_length() {
        let (client, mut server) = duplex(1024);

        let (byte, ()) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut hdr = vec![0u8; 26];
                server.read_exact(&mut hdr).await.unwrap();
                // Response: version=0, addon_length=3, 3 addon bytes, then payload.
                server
                    .write_all(&[0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x42])
                    .await
                    .unwrap();
            };

            let client_task = async {
                let mut conn = VlessConn::new(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .expect("VlessConn::new");

                let mut buf = [0u8; 1];
                conn.read_exact(&mut buf).await.unwrap();
                buf[0]
            };

            futures::join!(client_task, server_task)
        });

        assert_eq!(
            byte, 0x42,
            "addon bytes must be discarded; next byte is payload 0x42"
        );
    }

    // ─── F5: version mismatch → ConnError ────────────────────────────────────

    #[test]
    fn vless_conn_version_mismatch_tears_down() {
        let (client, mut server) = duplex(1024);

        let (result, ()) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut hdr = vec![0u8; 26];
                let _ = server.read_exact(&mut hdr).await;
                server.write_all(&[0x01, 0x00]).await.unwrap();
            };

            let client_task = async {
                // VlessConn::new succeeds (response is read lazily).
                let mut conn = VlessConn::new(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .expect("new succeeds with lazy response");

                // First read triggers lazy response consumption and must error.
                let mut buf = [0u8; 1];
                tokio::io::AsyncReadExt::read(&mut conn, &mut buf)
                    .await
                    .map(|_| ())
            };

            futures::join!(client_task, server_task)
        });

        let err = result.expect_err("version mismatch must return Err on read");
        let msg = err.to_string();
        assert!(
            msg.contains("version") || msg.contains("mismatch"),
            "error must mention version mismatch, got: {msg}"
        );
    }

    // ─── F6: server EOF after header ─────────────────────────────────────────

    #[test]
    fn vless_conn_server_eof_after_header() {
        let (client, mut server) = duplex(1024);

        let (result, ()) = xt_wasm_runtime::block_on(async {
            let server_task = async move {
                let mut hdr = vec![0u8; 26];
                let _ = server.read_exact(&mut hdr).await;
                // Close immediately (no response).
                drop(server);
            };

            let client_task = async {
                // VlessConn::new succeeds (response is read lazily).
                let mut conn = VlessConn::new(
                    Box::new(client),
                    &TEST_UUID,
                    None,
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([1, 2, 3, 4]),
                )
                .await
                .expect("new succeeds with lazy response");

                // First read triggers lazy response consumption and must error on EOF.
                let mut buf = [0u8; 1];
                tokio::io::AsyncReadExt::read(&mut conn, &mut buf)
                    .await
                    .map(|_| ())
            };

            futures::join!(client_task, server_task)
        });

        let err = result.expect_err("EOF after header must return Err on read");
        let msg = err.to_string();
        assert!(
            msg.contains("closed")
                || msg.contains("eof")
                || msg.contains("EOF")
                || msg.contains("server")
                || msg.contains("Eof"),
            "error must give diagnostic, got: {msg}"
        );
    }
}
