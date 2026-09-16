// Ported from meow-rs <https://github.com/meow-rs/meow-rs> @ a2be4de1c315daa22e53ad1118538936241d592f
// (crates/meow-proxy/src/vless/vision.rs).
// MIT licensed, Copyright (c) 2026 Max Lv. See LICENSE.meow-rs.
//
// Modified for the wasm32-wasip2 port: `meow_common::ProxyConn` → `crate::ProxyConn`;
// `rand::rng()` (rand 0.9) → `rand::thread_rng()` (the workspace pins rand 0.8).
// The padding-frame layout and the DIRECT-splice logic are ported verbatim — in
// particular the 21-byte mihomo/xray header and the `content.len() < 900` guard
// in `build_padding_frame` are unchanged.
//
// NOTE: `docs/specs/proxy-vless.md`'s `## XTLS-Vision` section documents a
// stale 5-byte padding header.  The implemented reality (pinned by the test
// `padding_frame_with_uuid_matches_mihomo_layout`) is the 21-byte layout
// `UUID(16) ‖ cmd(1) ‖ content_len_be(2) ‖ padding_len_be(2) ‖ content ‖ padding`.

//! XTLS-Vision padding wrapper for VLESS.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::conn::VlessConn;
use crate::ProxyConn;

const UUID_LEN: usize = 16;
/// 第一帧的头长（带 UUID）：`16 + 1 + 2 + 2`。
pub(crate) const PADDING_HEADER_LEN: usize = UUID_LEN + 1 + 2 + 2;
/// 后续帧的短头长：`1 + 2 + 2`。
pub(crate) const SHORT_HEADER_LEN: usize = PADDING_HEADER_LEN - UUID_LEN;
pub(crate) const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub(crate) const COMMAND_PADDING_END: u8 = 0x01;
pub(crate) const COMMAND_PADDING_DIRECT: u8 = 0x02;
pub(crate) const TLS_HANDSHAKE: u8 = 0x16;
pub(crate) const TLS_APPLICATION_DATA: u8 = 0x17;
pub(crate) const TLS_MAJOR: u8 = 0x03;
pub(crate) const TLS_CLIENT_HELLO: u8 = 0x01;
pub(crate) const TLS_SERVER_HELLO: u8 = 0x02;
const TLS13_SUPPORTED_VERSIONS_EXT: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS13_CIPHER_SUITES: [u16; 4] = [0x1301, 0x1302, 0x1303, 0x1304];
const TLS_FILTER_PACKETS: usize = 8;

/// 组帧时单帧 content 的上限。
///
/// 帧头的 content/padding 长度是 **u16**，而长填充最长会把帧撑到约 1400 字节；
/// 不分块的话超长写会让长度字段回绕，对端的解帧器直接失步。
/// 客户端 [`VisionConn`] 与服务端 [`super::vision_server::VisionServerConn`]
/// 用同一个常量，避免两边各自漂移。
pub(crate) const MAX_FRAME_CONTENT: usize = 16 * 1024;

enum ReadState {
    Header {
        buf: Vec<u8>,
        need_uuid: bool,
    },
    Content {
        command: u8,
        remaining_content: usize,
        remaining_padding: usize,
    },
    Padding {
        command: u8,
        remaining_padding: usize,
    },
    Through,
}

struct PendingWrite {
    frame: Vec<u8>,
    pos: usize,
    consumed: usize,
    command: u8,
    end_padding_after_drain: bool,
}

pub struct VisionConn {
    inner: VlessConn,
    user_uuid: [u8; UUID_LEN],
    read_state: ReadState,
    read_plain: VecDeque<u8>,
    write_pending: Option<PendingWrite>,
    write_padding: bool,
    write_sent_uuid: bool,
    write_seen_tls: bool,
    write_direct_enabled: bool,
    read_tls_filter: ServerHelloFilter,
    vision_entered: bool,
}

impl VisionConn {
    pub fn new(inner: VlessConn, user_uuid: [u8; UUID_LEN]) -> Self {
        Self {
            inner,
            user_uuid,
            read_state: ReadState::Header {
                buf: Vec::with_capacity(PADDING_HEADER_LEN),
                need_uuid: true,
            },
            read_plain: VecDeque::new(),
            write_pending: None,
            write_padding: true,
            write_sent_uuid: false,
            write_seen_tls: false,
            write_direct_enabled: false,
            read_tls_filter: ServerHelloFilter::new(),
            vision_entered: false,
        }
    }

    #[allow(dead_code)]
    pub fn vision_entered(&self) -> bool {
        self.vision_entered
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<usize>>> {
        let Some(pending) = &mut self.write_pending else {
            return Poll::Ready(Ok(None));
        };

        while pending.pos < pending.frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.frame[pending.pos..])? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision: zero write during frame drain",
                    )));
                }
                Poll::Ready(n) => pending.pos += n,
            }
        }

        let pending = self.write_pending.take().expect("pending checked above");
        if pending.end_padding_after_drain {
            self.write_padding = false;
            if pending.command == COMMAND_PADDING_DIRECT {
                if !self.enable_inner_raw_write_passthrough() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "vision: DIRECT requested but transport cannot switch to raw passthrough",
                    )));
                }
                tracing::debug!("XTLS Vision direct write passthrough enabled");
            }
        }
        Poll::Ready(Ok(Some(pending.consumed)))
    }

    fn build_write_frame(&mut self, buf: &[u8]) {
        let contains_tls_handshake = contains_tls_client_hello(buf);
        let starts_tls_app_data =
            buf.len() >= 3 && buf[0] == TLS_APPLICATION_DATA && buf[1] == TLS_MAJOR;
        if contains_tls_handshake {
            self.write_seen_tls = true;
            self.vision_entered = true;
        }

        let padding_tls = self.write_seen_tls;
        let mut command = COMMAND_PADDING_CONTINUE;
        let mut end_after_drain = false;
        if starts_tls_app_data && self.write_seen_tls {
            command = if self.write_direct_enabled {
                COMMAND_PADDING_DIRECT
            } else {
                COMMAND_PADDING_END
            };
            end_after_drain = true;
        } else if !self.write_seen_tls && !contains_tls_handshake {
            command = COMMAND_PADDING_END;
            end_after_drain = true;
        }

        let frame = build_padding_frame(
            command,
            (!self.write_sent_uuid).then_some(&self.user_uuid),
            buf,
            padding_tls,
        );
        tracing::debug!(
            command,
            content_len = buf.len(),
            frame_len = frame.len(),
            padding_tls,
            contains_tls_handshake,
            starts_tls_app_data,
            "XTLS Vision write padding"
        );
        self.write_sent_uuid = true;
        self.write_pending = Some(PendingWrite {
            frame,
            pos: 0,
            consumed: buf.len(),
            command,
            end_padding_after_drain: end_after_drain,
        });
    }

    fn drain_read_plain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_plain.is_empty() {
            return false;
        }
        let n = buf.remaining().min(self.read_plain.len());
        for b in self.read_plain.drain(..n) {
            buf.put_slice(&[b]);
        }
        true
    }

    fn enable_inner_raw_read_passthrough(&mut self) -> bool {
        self.inner.enable_raw_read_passthrough()
    }

    fn enable_inner_raw_write_passthrough(&mut self) -> bool {
        self.inner.enable_raw_write_passthrough()
    }

    fn filter_server_tls(&mut self, chunk: &[u8]) {
        if !self.write_direct_enabled && self.read_tls_filter.observe(chunk) {
            self.write_direct_enabled = true;
            tracing::debug!("XTLS Vision found TLS 1.3, direct enabled");
        }
    }
}

pub(crate) fn contains_tls_client_hello(buf: &[u8]) -> bool {
    buf.windows(6)
        .any(|w| w[0] == TLS_HANDSHAKE && w[1] == TLS_MAJOR && w[5] == TLS_CLIENT_HELLO)
}

struct ServerHelloFilter {
    packets_left: usize,
    expected_len: Option<usize>,
    buffer: Vec<u8>,
    done: bool,
}

impl ServerHelloFilter {
    fn new() -> Self {
        Self {
            packets_left: TLS_FILTER_PACKETS,
            expected_len: None,
            buffer: Vec::new(),
            done: false,
        }
    }

    fn observe(&mut self, chunk: &[u8]) -> bool {
        if self.done || self.packets_left == 0 || chunk.is_empty() {
            return false;
        }
        self.packets_left -= 1;

        if self.expected_len.is_none() {
            self.buffer.extend_from_slice(chunk);
            let Some(pos) = find_tls_server_hello_start(&self.buffer) else {
                return false;
            };
            if pos > 0 {
                self.buffer.drain(..pos);
            }
            let record_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
            self.expected_len = Some(5 + record_len);
        } else {
            self.buffer.extend_from_slice(chunk);
        }

        let expected_len = self.expected_len.unwrap_or(self.buffer.len());
        if self.buffer.len() < expected_len {
            return false;
        }

        self.done = true;
        let hello = &self.buffer[..expected_len];
        let Some(cipher) = tls_server_hello_cipher_suite(hello) else {
            return false;
        };
        TLS13_CIPHER_SUITES.contains(&cipher)
            && hello
                .windows(TLS13_SUPPORTED_VERSIONS_EXT.len())
                .any(|w| w == TLS13_SUPPORTED_VERSIONS_EXT)
    }
}

/// 出站方向的 TLS 状态跟踪（服务端写侧）。
///
/// 服务端要看的是**目标站**发回来的 TLS：这里需要两个信息 ——
/// 「是不是 TLS」（决定要不要长填充）与「一条记录是否恰好在这里结束」
/// （决定在哪一帧上打终止命令）。
///
/// # 为什么必须按记录边界跟踪，而不是看开头几个字节
///
/// * 「看到 `0x17 0x03 0x03` 就是应用数据」是**错的**：TLS 1.3 把握手后半段
///   （EncryptedExtensions/Certificate/Finished）也加密成 `0x17` 记录，
///   与应用数据线格式完全一样（实测过：提前切裸字节会让客户端把后续帧头
///   当成密文）。
/// * 「一段里出现了几个记录头」也不够：TCP 段的边界与记录边界不对齐，
///   一段里可能只有半条记录，靠它判不出「这条记录到哪儿结束」。
///
/// 所以这里做一个**跨读的极小状态机**：记住「下一条记录还需要多少字节」，
/// 逐段推进。它只关心记录头（5 字节）与长度，不碰内容 —— 目标站回的是
/// 密文，我们本来也看不懂内容。
#[derive(Debug, Default)]
pub(crate) struct TlsRecordTracker {
    /// 已经确认对端在讲 TLS。
    is_tls: bool,
    /// 当前记录的剩余字节数；`None` 表示正等着读一个新的记录头。
    remaining: Option<usize>,
    /// 当前记录的头 5 字节里已经攒了几个（用于跨读拼接记录头）。
    header: [u8; 5],
    header_len: usize,
    /// 当前记录的类型字节。
    rec_type: u8,
    /// 当前记录声明的负载长度。
    rec_len: usize,
    /// 当前记录的第一个负载字节（用于识别 CCS）。
    first_payload: Option<u8>,
    /// 当前记录是不是 ChangeCipherSpec（不是数据）。
    is_ccs: bool,
    /// 正在攒的 ServerHello 记录负载（用于判 TLS 1.3）。
    server_hello: Option<Vec<u8>>,
    /// 内层确认是 TLS 1.3（对应 upstream `TrafficState.EnableXtls`）。
    ///
    /// 判据与 upstream `XtlsFilterTls` 一致：ServerHello 的 cipher suite
    /// 落在 TLS 1.3 列表里、且带 `supported_versions` 扩展。
    /// 只有它为真才允许切 `DIRECT`（连 splice 一起切）；否则只发 `END`。
    enable_xtls: bool,
    /// 已经**完整读完**的记录条数。
    pub(crate) records_done: u32,
}

impl TlsRecordTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 已经确认对端在讲 TLS。
    pub(crate) fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// 内层确认是 TLS 1.3。
    pub(crate) fn enable_xtls(&self) -> bool {
        self.enable_xtls
    }

    /// 观察一段出站字节，推进记录状态机。
    pub(crate) fn observe(&mut self, buf: &[u8]) {
        let mut i = 0usize;
        while i < buf.len() {
            match self.remaining {
                None => {
                    // 攒记录头（5 字节）
                    let want = 5 - self.header_len;
                    let take = want.min(buf.len() - i);
                    self.header[self.header_len..self.header_len + take]
                        .copy_from_slice(&buf[i..i + take]);
                    self.header_len += take;
                    i += take;
                    if self.header_len < 5 {
                        return; // 头还没齐
                    }
                    let t = self.header[0];
                    let ver = [self.header[1], self.header[2]];
                    let len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                    self.header_len = 0;
                    if ver != [TLS_MAJOR, TLS_MAJOR]
                        || (t != TLS_HANDSHAKE && t != TLS_APPLICATION_DATA)
                    {
                        // 不是 TLS 记录：保持 is_tls 不变，也不再继续跟踪
                        // （避免把随机字节当记录头）。
                        return;
                    }
                    self.is_tls = true;
                    self.rec_type = t;
                    self.rec_len = len;
                    // 见到 ServerHello 记录就把负载攒下来，稍后判 TLS 1.3。
                    if t == TLS_HANDSHAKE && len + 5 >= 79 {
                        self.server_hello = Some(Vec::with_capacity(len + 5));
                    }
                    self.first_payload = None;
                    self.is_ccs = false;
                    self.remaining = Some(len);
                }
                Some(0) => {
                    // 上一条记录已经结算过：转去读下一条记录的头。
                    self.remaining = None;
                }
                Some(rem) => {
                    let take = rem.min(buf.len() - i);
                    // 记录的第一个负载字节：用来识别 ChangeCipherSpec。
                    if rem == self.rec_len && take > 0 {
                        self.first_payload = Some(buf[i]);
                    }
                    if let Some(acc) = self.server_hello.as_mut() {
                        if acc.len() + take <= 4096 {
                            acc.extend_from_slice(&buf[i..i + take]);
                        }
                    }
                    i += take;
                    self.remaining = Some(rem - take);
                    if self.remaining == Some(0) {
                        // **负载刚好在这一段读完**：当场结算这条记录。
                        // 拖到下一轮会漏掉「本段以记录边界结束」这个事实。
                        self.finish_record();
                    }
                }
            }
        }
    }

    /// 结算一条刚读完的记录：判定 CCS、记录计数、以及「握手是否结束」。
    ///
    /// CCS 的判据是**负载**：`17 03 03` + 负载首字节 `01`（长度 1 或 32）。
    /// 它必须在这一刻判（负载刚读完），否则判到的会是下一条记录。
    fn finish_record(&mut self) {
        // ServerHello 收全了：判「内层是不是 TLS 1.3」，据此决定能否切 DIRECT。
        //
        // 与 upstream `XtlsFilterTls` 同一套判据：
        //   * 带 `supported_versions` 扩展（`00 2b 00 02 03 04`）；
        //   * cipher suite 落在 TLS 1.3 列表里。
        if let Some(hello) = self.server_hello.take() {
            const TLS13_EXT: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
            if hello.windows(6).any(|w| w == TLS13_EXT) {
                // `hello` 是 ServerHello 的**负载**，含 4 字节 handshake 头：
                //   handshake_type(1) length(3) | version(2) random(32)
                //   | session_id_len(1) session_id(0..32) | cipher(2) …
                let sid_len = hello.get(38).copied().unwrap_or(0) as usize;
                if let Some(b) = hello.get(39 + sid_len..41 + sid_len) {
                    let c = u16::from_be_bytes([b[0], b[1]]);
                    if matches!(c, 0x1301..=0x1304) {
                        self.enable_xtls = true;
                    }
                }
            }
        }

        self.is_ccs = self.rec_type == TLS_APPLICATION_DATA
            && self.first_payload == Some(0x01)
            && (self.rec_len == 1 || self.rec_len == 32);
        self.records_done = self.records_done.saturating_add(1);
        // 保持 `Some(0)`：它表示「上一条记录刚好读完」，也就是当前正好
        // 停在记录边界上（`ends_on_record_boundary`）。下一轮循环会把它
        // 当成 `Some(0)` 再结算一次 —— 因此结算逻辑必须是幂等的。
        self.remaining = Some(0);
    }

    /// 这一段是不是**恰好以一条完整记录结束**。
    ///
    /// 注意：写侧的终止判据用的是更严格的
    /// [`is_complete_application_records`]（整段全由完整 `0x17` 记录组成），
    /// 这个较松的判定只用于诊断与测试。
    #[allow(dead_code)]
    pub(crate) fn ends_on_record_boundary(&self) -> bool {
        self.is_tls && self.remaining == Some(0) && self.header_len == 0
    }

    /// 当前记录的类型（诊断用）。
    #[allow(dead_code)]
    pub(crate) fn current_type(&self) -> u8 {
        self.rec_type
    }
}

pub(crate) fn find_tls_server_hello_start(buf: &[u8]) -> Option<usize> {
    buf.windows(6).position(|w| {
        w[0] == TLS_HANDSHAKE && w[1] == TLS_MAJOR && w[2] == TLS_MAJOR && w[5] == TLS_SERVER_HELLO
    })
}

fn tls_server_hello_cipher_suite(record: &[u8]) -> Option<u16> {
    if record.len() < 46 || !matches!(find_tls_server_hello_start(record), Some(0)) {
        return None;
    }
    let session_id_len = *record.get(43)? as usize;
    let cipher_offset = 44 + session_id_len;
    let bytes = record.get(cipher_offset..cipher_offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn build_padding_frame(
    command: u8,
    user_uuid: Option<&[u8; UUID_LEN]>,
    content: &[u8],
    padding_tls: bool,
) -> Vec<u8> {
    let padding_len = if content.len() < 900 {
        let mut rng = rand::thread_rng();
        if padding_tls {
            (rng.next_u32() as usize % 500) + 900 - content.len()
        } else {
            rng.next_u32() as usize % 256
        }
    } else {
        0
    };

    let header_len = if user_uuid.is_some() {
        PADDING_HEADER_LEN
    } else {
        SHORT_HEADER_LEN
    };
    let mut frame = Vec::with_capacity(header_len + content.len() + padding_len);
    if let Some(uuid) = user_uuid {
        frame.extend_from_slice(uuid);
    }
    frame.push(command);
    frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
    frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
    frame.extend_from_slice(content);
    frame.resize(frame.len() + padding_len, 0);
    frame
}

impl AsyncRead for VisionConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.drain_read_plain(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            let state = std::mem::replace(&mut self.read_state, ReadState::Through);
            match state {
                ReadState::Through => {
                    self.read_state = ReadState::Through;
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
                ReadState::Header {
                    buf: mut h,
                    need_uuid,
                } => {
                    let need = if need_uuid {
                        PADDING_HEADER_LEN
                    } else {
                        PADDING_HEADER_LEN - UUID_LEN
                    };
                    while h.len() < need {
                        let mut tmp = [0u8; PADDING_HEADER_LEN];
                        let want = (need - h.len()).min(tmp.len());
                        let mut rb = ReadBuf::new(&mut tmp[..want]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = ReadState::Header { buf: h, need_uuid };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = ReadState::Header { buf: h, need_uuid };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = ReadState::Header { buf: h, need_uuid };
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "vision: EOF while reading padding header",
                                    )));
                                }
                                h.extend_from_slice(rb.filled());
                            }
                        }
                    }

                    let offset = if need_uuid {
                        if h[..UUID_LEN] != self.user_uuid {
                            self.read_state = ReadState::Header { buf: h, need_uuid };
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vision: server responded with unknown UUID",
                            )));
                        }
                        UUID_LEN
                    } else {
                        0
                    };

                    let command = h[offset];
                    let content_len = u16::from_be_bytes([h[offset + 1], h[offset + 2]]) as usize;
                    let padding_len = u16::from_be_bytes([h[offset + 3], h[offset + 4]]) as usize;
                    tracing::debug!(
                        command,
                        content_len,
                        padding_len,
                        need_uuid,
                        "XTLS Vision read padding"
                    );
                    self.read_state = ReadState::Content {
                        command,
                        remaining_content: content_len,
                        remaining_padding: padding_len,
                    };
                }
                ReadState::Content {
                    command,
                    mut remaining_content,
                    remaining_padding,
                } => {
                    if remaining_content == 0 {
                        self.read_state = ReadState::Padding {
                            command,
                            remaining_padding,
                        };
                        continue;
                    }
                    if buf.remaining() == 0 {
                        self.read_state = ReadState::Content {
                            command,
                            remaining_content,
                            remaining_padding,
                        };
                        return Poll::Ready(Ok(()));
                    }

                    let mut tmp = vec![0u8; remaining_content.min(buf.remaining()).min(8192)];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            self.read_state = ReadState::Content {
                                command,
                                remaining_content,
                                remaining_padding,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_state = ReadState::Content {
                                command,
                                remaining_content,
                                remaining_padding,
                            };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                self.read_state = ReadState::Content {
                                    command,
                                    remaining_content,
                                    remaining_padding,
                                };
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vision: EOF while reading padded content",
                                )));
                            }
                            remaining_content -= n;
                            self.filter_server_tls(rb.filled());
                            buf.put_slice(rb.filled());
                            self.read_state = if remaining_content == 0 {
                                ReadState::Padding {
                                    command,
                                    remaining_padding,
                                }
                            } else {
                                ReadState::Content {
                                    command,
                                    remaining_content,
                                    remaining_padding,
                                }
                            };
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                ReadState::Padding {
                    command,
                    mut remaining_padding,
                } => {
                    while remaining_padding > 0 {
                        let mut tmp = [0u8; 1024];
                        let want = remaining_padding.min(tmp.len());
                        let mut rb = ReadBuf::new(&mut tmp[..want]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = ReadState::Padding {
                                    command,
                                    remaining_padding,
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = ReadState::Padding {
                                    command,
                                    remaining_padding,
                                };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = ReadState::Padding {
                                        command,
                                        remaining_padding,
                                    };
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "vision: EOF while reading padding",
                                    )));
                                }
                                remaining_padding -= n;
                            }
                        }
                    }

                    self.read_state = match command {
                        COMMAND_PADDING_CONTINUE => ReadState::Header {
                            buf: Vec::with_capacity(SHORT_HEADER_LEN),
                            need_uuid: false,
                        },
                        COMMAND_PADDING_END => ReadState::Through,
                        COMMAND_PADDING_DIRECT => {
                            if !self.enable_inner_raw_read_passthrough() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    "vision: DIRECT requested but transport cannot switch to raw passthrough",
                                )));
                            }
                            tracing::debug!("XTLS Vision direct passthrough enabled");
                            ReadState::Through
                        }
                        other => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("vision: unknown padding command {other}"),
                            )));
                        }
                    };
                }
            }
        }
    }
}

impl AsyncWrite for VisionConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 先把在途帧推完。**推完要继续往下给 `buf` 组帧**，不能把
        // `Some(consumed)` 直接返回：那个数字是**上一个 buf** 的写入量，
        // 调用方（`write_all` / `tokio::io::copy`）会据此跳过 `buf` 开头
        // 同样多的字节 —— 直接丢数据。`RealityTlsStream::poll_write` 里
        // 对同一件事有更详细的注释。
        match this.drain_pending_write(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => {} // 排空（或本来就没有）→ 继续组帧
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write_padding {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // The padding frame carries u16 content/padding length fields:
        // chunk large writes so those fields cannot wrap and
        // desynchronise the peer's vision decoder.
        let chunk_len = buf.len().min(MAX_FRAME_CONTENT);
        this.build_write_frame(&buf[..chunk_len]);
        match this.drain_pending_write(cx) {
            Poll::Ready(Ok(Some(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        // **顺序很关键**：必须先把待发的 Vision 帧写完，再去 flush 内层。
        //
        // `VlessConn` 的 `poll_flush` 会先把「延迟的 VLESS 请求头」当成裸字节
        // 写出去。如果这里先 flush 内层，请求头就会先落到线上，随后才是
        // Vision 帧 —— 于是**首帧没有 UUID 前缀**，对端（服务端）按
        // upstream 的规则要求首帧以用户 UUID 开头，会直接判为「UUID 不符」。
        //
        // 反过来先 drain，请求头就会被 `VlessConn::poll_write_deferred`
        // 拼到帧前面一起发出去（upstream 也是把请求头放进第一个 Vision
        // 记录里的）。
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for VisionConn {}

impl ProxyConn for VisionConn {}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: [u8; UUID_LEN] = [0x11; UUID_LEN];

    #[test]
    fn padding_frame_with_uuid_matches_mihomo_layout() {
        let content = b"\x16\x03\x01\x00\x01\x01";
        let frame = build_padding_frame(COMMAND_PADDING_CONTINUE, Some(&UUID), content, true);

        assert_eq!(&frame[..UUID_LEN], &UUID);
        assert_eq!(frame[UUID_LEN], COMMAND_PADDING_CONTINUE);

        let content_len = u16::from_be_bytes([frame[UUID_LEN + 1], frame[UUID_LEN + 2]]) as usize;
        let padding_len = u16::from_be_bytes([frame[UUID_LEN + 3], frame[UUID_LEN + 4]]) as usize;

        assert_eq!(content_len, content.len());
        assert_eq!(
            &frame[PADDING_HEADER_LEN..PADDING_HEADER_LEN + content.len()],
            content
        );
        assert_eq!(
            frame.len(),
            PADDING_HEADER_LEN + content.len() + padding_len
        );
        assert!(padding_len >= 900 - content.len());
        assert!(padding_len < 1400 - content.len());
    }

    #[test]
    fn padding_frame_without_uuid_uses_short_header() {
        let content = b"abc";
        let frame = build_padding_frame(COMMAND_PADDING_END, None, content, false);

        assert_eq!(frame[0], COMMAND_PADDING_END);
        let content_len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        let padding_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;

        assert_eq!(content_len, content.len());
        assert_eq!(&frame[5..8], content);
        assert_eq!(frame.len(), 5 + content.len() + padding_len);
        assert!(padding_len < 256);
    }

    #[test]
    fn detects_client_hello_inside_vless_prefixed_payload() {
        let mut payload = vec![0u8; 56];
        payload.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x01, 0x01]);

        assert!(contains_tls_client_hello(&payload));
        assert!(!contains_tls_client_hello(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn server_hello_filter_detects_tls13() {
        let mut filter = ServerHelloFilter::new();

        assert!(filter.observe(&tls13_server_hello(0x1301)));
    }

    #[test]
    fn server_hello_filter_handles_fragmented_record_header() {
        let hello = tls13_server_hello(0x1301);
        let mut filter = ServerHelloFilter::new();

        assert!(!filter.observe(&hello[..3]));
        assert!(filter.observe(&hello[3..]));
    }

    #[test]
    fn server_hello_filter_rejects_non_tls13_cipher() {
        let mut filter = ServerHelloFilter::new();

        assert!(!filter.observe(&tls13_server_hello(0xc02f)));
    }

    fn tls13_server_hello(cipher_suite: u16) -> Vec<u8> {
        let supported_versions = TLS13_SUPPORTED_VERSIONS_EXT;
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(supported_versions.len() as u16).to_be_bytes());
        body.extend_from_slice(&supported_versions);

        let mut handshake = Vec::new();
        handshake.push(TLS_SERVER_HELLO);
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[
            TLS_HANDSHAKE,
            TLS_MAJOR,
            TLS_MAJOR,
            ((handshake.len() >> 8) & 0xff) as u8,
            (handshake.len() & 0xff) as u8,
        ]);
        record.extend_from_slice(&handshake);
        record
    }
}
