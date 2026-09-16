//! XTLS-Vision **服务端**侧的流控：解帧（客户端 → 服务端）+ 组帧（服务端 → 客户端）。
//!
//! 这是 `docs/vision-server-plan.md` 里那一项「协议部分唯一还没做的功能」的实现。
//! 与客户端 [`super::vision::VisionConn`] 严格对称，线格式见该文件顶部注释：
//!
//! ```text
//! 第一帧（仅此一帧带 UUID）:
//!   [uuid:16][command:1][content_len:2 BE][padding_len:2 BE][content][padding]
//! 后续帧（短头）:
//!   [command:1][content_len:2 BE][padding_len:2 BE][content][padding]
//! ```
//!
//! # 为什么必须有这个模块，而不能「不拆帧直接转发」
//!
//! Vision 把负载包进填充帧。服务端不拆帧的话，填充字节会被当成原始数据发给
//! 目标站 —— **输出是错的却不报错**。所以在此之前服务端对非空 flow 是
//! **明确拒绝**（见 `server.rs` 的守卫与 `inbound_rejects_vision_flow_instead_of_misreading_bytes`）。
//! 现在它变成「能用」。
//!
//! # 语义（依据 upstream `proxy/proxy.go`，不是照抄客户端）
//!
//! upstream 的 `VisionReader` / `VisionWriter` 两边共用同一份 `XtlsPadding` /
//! `XtlsUnpadding`，区别只在 `isUplink` 选中哪一组状态：
//!
//! | 方向 | upstream | 本文件 |
//! |---|---|---|
//! | 客户端 → 服务端（服务端读） | `NewVisionReader(..., isUplink=true)` | [`VisionServerConn`] 的读侧 |
//! | 服务端 → 客户端（服务端写） | `EncodeBodyAddons(..., isUplink=false)` → `VisionWriter` | [`VisionServerConn`] 的写侧 |
//!
//! 两处刻意的差异，都有实测理由：
//!
//! 1. **第一帧带 UUID**。upstream `XtlsPadding` 只在 `writeOnceUserUUID` 还非空时
//!    写那 16 字节，读写两侧的 `XtlsUnpadding` 都要求第一帧以本用户的 UUID 开头
//!    （`bytes.Equal(s.UserUUID, b.BytesTo(16))`）。所以**两个方向的第一帧都必须带 UUID**，
//!    包括服务端 → 客户端这一侧 —— 否则客户端读侧会直接报
//!    `vision: server responded with unknown UUID`。
//! 2. **出站的首帧必须是 VLESS 响应头**。upstream 是
//!    `EncodeBodyAddons(bufferWriter, ...)`，也就是响应头 **也走 VisionWriter**（会被
//!    当作普通负载组帧）。我们照做：`[0x00,0x00]` 由 `VisionServerConn` 写出，
//!    于是它成为第一帧的内容。写成裸字节的话，客户端读侧会拿它当帧头解析
//!    （UUID 校验立刻失败），而 `VlessConn` 自己永远读不到响应头。
//!
//! 与客户端一样，这里**不**实现 upstream 的 DIRECT/splice 性能优化：功能路径完整，
//! 只是少了「内核零拷贝」那一档吞吐（见 `PLAN.md` §7 风险登记）。
//! 但**协议上仍然必须正确响应 DIRECT**，否则客户端切到裸字节流之后我们还在发帧。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use xt_wasm_tls::Stream;

use super::vision::{TlsRecordTracker, MAX_FRAME_CONTENT};
use crate::ProxyConn;

const UUID_LEN: usize = 16;
/// 第一帧的头长（带 UUID）：`16 + 1 + 2 + 2`。
pub(crate) const PADDING_HEADER_LEN: usize = UUID_LEN + 1 + 2 + 2;
/// 后续帧的短头长：`1 + 2 + 2`。
pub(crate) const SHORT_HEADER_LEN: usize = PADDING_HEADER_LEN - UUID_LEN;

pub(crate) const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub(crate) const COMMAND_PADDING_END: u8 = 0x01;
pub(crate) const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// 一次读里最多解析多少字节。
///
/// 不必等于帧长：解析器是**可跨读续解**的纯状态机，所以这里只影响内存上界，
/// 不影响正确性。8192 与 upstream 的 `buf.Size` 同量级。
const READ_CHUNK: usize = 8192;

/// 判别「有没有 UUID 前缀」至少要看的字节数（= UUID 长度）。
/// 解析一帧（或一帧的一部分）之后，调用方要做什么。
#[derive(Debug, Clone, PartialEq, Eq)]
enum FrameAction {
    /// 输入被整段吃掉了（帧头/填充/跨读的负载），还需要更多字节。
    Need,
    /// 解出了 `produced` 个字节（已写进 `out`），`advance` 个输入字节可以丢弃。
    Produced { advance: usize, produced: usize },
    /// 命令是 DIRECT：从这里起是**裸字节流**，不再有帧头。
    Direct { advance: usize, produced: usize },
}

/// Vision 解帧器（读侧）的纯状态机。
///
/// 拆成纯逻辑是为了能**不碰网络**地测边界：截断、零长度、UUID 不匹配、
/// DIRECT 之后的裸字节。带 `AsyncRead` 的版本没法把这些情形逐一钉死。
///
/// # 线格式
///
/// ```text
/// 首帧: [uuid:16][cmd:1][content_len:2 BE][padding_len:2 BE][content][padding]
/// 后续: [cmd:1][content_len:2 BE][padding_len:2 BE][content][padding]
/// ```
///
/// `content` 交给调用方，`padding` 丢弃。命令有三种：
/// `CONTINUE(0)` 后面还有帧、`END(1)` 本帧读完就切裸字节、
/// `DIRECT(2)` 同 END 且对端也要切裸字节。
#[derive(Debug)]
pub(crate) struct FrameParser {
    expected_uuid: [u8; UUID_LEN],
    /// 首帧是否已经解析过（决定帧头是 21 还是 5 字节）。
    first_frame_done: bool,
    /// 当前帧的帧头长度：首帧定下来之后就不再变（21 或 5）。
    header_len: usize,
    /// 整条流的帧形状：首帧前 16 字节等于本用户 UUID 时为 `true`（21 字节头），
    /// 否则为 `false`（5 字节短头）。**定下来就固定**，不随帧重算。
    uuid_prefixed: Option<bool>,
    remaining_content: usize,
    remaining_padding: usize,
    /// `true` 之后全是裸字节（收到过 END 或 DIRECT 并读完了那一帧）。
    through: bool,
    /// 当前帧的命令。
    command: u8,
    /// 当前帧的命令尚未生效（帧还没读完）。
    command_applied: bool,
    /// 待处理字节（帧头 / 内容 / 填充共用）。
    ///
    /// **必须有它**：调用方的读缓冲区可能只有几个字节（例如它只想读 2 字节
    /// 的 VLESS 响应头），21 字节的帧头会被拆成好几段。靠调用方「把上一段
    /// 留着再喂一次」不行 —— 它每次只看到当前那一段。
    pending: Vec<u8>,
}

impl FrameParser {
    pub(crate) fn new(expected_uuid: [u8; UUID_LEN]) -> Self {
        Self {
            expected_uuid,
            first_frame_done: false,
            header_len: 0,
            remaining_content: 0,
            remaining_padding: 0,
            through: false,
            command: COMMAND_PADDING_CONTINUE,
            command_applied: true,
            uuid_prefixed: None,
            pending: Vec::with_capacity(PADDING_HEADER_LEN),
        }
    }

    /// 已经进入裸字节模式（END 或 DIRECT 那一帧读完之后）。
    #[cfg(test)]
    pub(crate) fn is_through(&self) -> bool {
        self.through
    }

    /// 解析器里还留着多少没处理完的字节（帧头/内容/填充残段）。
    ///
    /// **真实读循环必须用它的**：一帧的 `content` 交出去之后，帧尾的
    /// padding 还留在 `pending` 里，而帧命令（尤其 `DIRECT`）要等 padding
    /// 走完才生效。读循环若这时直接去读内层，就会拿对端的裸字节去喂外层
    /// TLS 解密（症状：`aead::Error`）。详见 `VisionServerConn::poll_read`。
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// 是否还有没处理完的字节（测试里用得多，等价于 `pending_len() > 0`）。
    #[cfg(test)]
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// 处理一小段输入，返回下一步动作。
    ///
    /// `advance` 是相对于 `input` 开头、**调用方可以丢弃**的字节数；
    /// `Need` 表示 `input` 被整段吃掉，再来一段。
    ///
    /// # 两条关键约束
    ///
    /// 1. **绝不按帧头里声明的长度去要求字节**。声明值可以大于实际
    ///    （连接被截断），所以只报告「实际吃掉了多少」：畸形长度既不会
    ///    让调用方分配大缓冲区，也不会 panic。
    /// 2. **解出字节就立刻返回**。不能先攒着继续解析下一帧 —— 返回
    ///    `Need` 时调用方会把输入整段丢掉，攒着的字节就丢了。
    fn feed(
        &mut self,
        input: Option<&[u8]>,
        eof: bool,
        out: &mut Vec<u8>,
    ) -> io::Result<FrameAction> {
        let input = input.unwrap_or(&[]);
        if self.through {
            out.extend_from_slice(input);
            return Ok(FrameAction::Produced {
                advance: input.len(),
                produced: input.len(),
            });
        }

        // 先把这一段输入收进来。`pending` 是**唯一**的字节来源与去处：
        // 帧头跨读、内容跨读、填充跨读都靠它，状态与缓冲永远一致。
        self.pending.extend_from_slice(input);

        loop {
            // ① 内容：解出多少就交多少。
            if self.remaining_content > 0 {
                let take = self.remaining_content.min(self.pending.len());
                out.extend_from_slice(&self.pending[..take]);
                self.pending.drain(..take);
                self.remaining_content -= take;
                return Ok(FrameAction::Produced {
                    advance: input.len(),
                    produced: out.len(),
                });
            }

            // ② 填充：丢弃，扔完回到 ③ 判「帧读完」。
            if self.remaining_padding > 0 {
                let take = self.remaining_padding.min(self.pending.len());
                self.pending.drain(..take);
                self.remaining_padding -= take;
                if self.remaining_padding > 0 {
                    break;
                }
                continue;
            }

            // ③ content 与 padding 都清零了 → 本帧命令生效。
            if !self.command_applied {
                self.command_applied = true;
                if self.command != COMMAND_PADDING_CONTINUE {
                    self.through = true;
                    // 帧读完之后剩下的字节属于裸字节流。
                    out.extend_from_slice(&self.pending);
                    self.pending.clear();
                    let produced = out.len();
                    return Ok(if self.command == COMMAND_PADDING_DIRECT {
                        FrameAction::Direct {
                            advance: input.len(),
                            produced,
                        }
                    } else {
                        FrameAction::Produced {
                            advance: input.len(),
                            produced,
                        }
                    });
                }
                continue; // CONTINUE：接着读下一帧
            }

            // ④ 读下一帧的帧头。
            //
            // 只有**首帧**可能带 UUID 前缀（21 字节头）；后续帧一律 5 字节短头。
            // 首帧的形状由前 16 字节是否等于本用户 UUID 决定，**定下来就固定**
            // （`uuid_prefixed`）—— 否则帧头跨读时每来一段不足 16 字节的残段
            // 都会重新判断一次，永远判不出结果。
            if !self.first_frame_done {
                if self.pending.len() < UUID_LEN {
                    if !eof {
                        break; // 帧头跨读，还判断不出有没有 UUID 前缀
                    }
                    // 对端不会再发了：这一定是不带 UUID 前缀的短头首帧。
                    self.uuid_prefixed = Some(false);
                } else {
                    self.uuid_prefixed = Some(self.pending[..UUID_LEN] == self.expected_uuid);
                }
                self.first_frame_done = true;
            }
            // `self.header_len == 0` 表示「本帧的头长还没定」；定完就写回
            // `self.header_len`，下一帧再重新按「首帧 / 后续帧」判断。
            let header_len = if self.header_len == 0 {
                if self.uuid_prefixed == Some(true) {
                    PADDING_HEADER_LEN // 首帧带 UUID
                } else {
                    SHORT_HEADER_LEN
                }
            } else {
                self.header_len
            };
            if self.pending.len() < header_len {
                break; // 帧头还没齐
            }
            let (command, content_len, padding_len) = {
                // 只有「带 UUID 的 21 字节头」才跳过那 16 字节。
                let offset = if header_len == PADDING_HEADER_LEN {
                    UUID_LEN
                } else {
                    0
                };
                let h = &self.pending;
                (
                    h[offset],
                    u16::from_be_bytes([h[offset + 1], h[offset + 2]]) as usize,
                    u16::from_be_bytes([h[offset + 3], h[offset + 4]]) as usize,
                )
            };
            // 注意 drain 的是**本帧**的头长（局部变量），不是 `self.header_len`
            // —— 后者是「下一帧」的头长，用错会把内容当成帧头丢掉。
            self.pending.drain(..header_len);
            self.command = command;
            self.remaining_content = content_len;
            self.remaining_padding = padding_len;
            self.header_len = SHORT_HEADER_LEN; // 后续帧固定短头
            self.command_applied = false;

            // 未知命令在读到头的那一刻就报错：content 与 padding 都为 0 的帧
            // 没有「读完」这一步可等，拖到那时判会把它静默当成 CONTINUE。
            if !matches!(
                self.command,
                COMMAND_PADDING_CONTINUE | COMMAND_PADDING_END | COMMAND_PADDING_DIRECT
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vision: 未知的 padding 命令 {:#04x}", self.command),
                ));
            }
        }

        Ok(FrameAction::Need)
    }
}

// ─────────────────────────── 组帧：纯函数 ───────────────────────────

/// 这一段是否**全部由完整的 TLS 应用数据记录组成**。
///
/// 逐字对应 upstream `proxy.IsCompleteRecord`：
///
/// ```go
/// for i < totalLen {
///     if headerLen > 0 { // 逐字节校验 `17 03 03` + 长度
///         case 5: if data != 0x17 { return false }
///         case 4: if data != 0x03 { return false }
///         case 3: if data != 0x03 { return false }
///         ...
///     } else if recordLen > 0 {
///         if totalLen - i < recordLen { return false } // 末尾半条记录
///         i += recordLen; recordLen = 0; headerLen = 5
///     } else { return false }
/// }
/// return headerLen == 5 && recordLen == 0
/// ```
///
/// 注意它比「停在记录边界上」**严格得多**：只要段内出现 `0x16`（握手）
/// 就返回 false。这正是区分「ServerHello 那一段」与「真正的应用数据段」
/// 的依据。
fn is_complete_application_records(buf: &[u8]) -> bool {
    let mut header_left = 5usize;
    let mut record_len = 0usize;
    let mut i = 0usize;
    while i < buf.len() {
        if header_left > 0 {
            let data = buf[i];
            i += 1;
            match header_left {
                5 => {
                    if data != super::vision::TLS_APPLICATION_DATA {
                        return false;
                    }
                }
                4 | 3 => {
                    if data != super::vision::TLS_MAJOR {
                        return false;
                    }
                }
                2 => record_len = (data as usize) << 8,
                1 => record_len |= data as usize,
                _ => {}
            }
            header_left -= 1;
        } else if record_len > 0 {
            if buf.len() - i < record_len {
                return false; // 末尾是半条记录
            }
            i += record_len;
            record_len = 0;
            header_left = 5;
        } else {
            return false;
        }
    }
    header_left == 5 && record_len == 0
}

/// 造一个 Vision 帧。与客户端 `build_padding_frame` 同一线格式。
///
/// `user_uuid` 只在**本侧的第一帧**给 `Some`（upstream 的 `writeOnceUserUUID`）。
fn build_padding_frame(
    command: u8,
    user_uuid: Option<&[u8; UUID_LEN]>,
    content: &[u8],
    long_padding: bool,
) -> Vec<u8> {
    let padding_len = if long_padding && content.len() < 900 {
        let mut rng = rand::thread_rng();
        (rng.next_u32() as usize % 500) + 900 - content.len()
    } else {
        let mut rng = rand::thread_rng();
        rng.next_u32() as usize % 256
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

// ─────────────────────────── 连接包装 ───────────────────────────

struct PendingWrite {
    frame: Vec<u8>,
    pos: usize,
    consumed: usize,
    /// 这一帧发完之后，本侧的 Vision（组帧）就结束了。
    end_padding_after_drain: bool,
    /// 这一帧是 DIRECT：发完之后两个方向都要切裸字节。
    direct_after_drain: bool,
}

/// 服务端的 XTLS-Vision 连接：读侧解帧，写侧组帧。
pub struct VisionServerConn {
    inner: Box<dyn Stream>,
    user_uuid: [u8; UUID_LEN],
    parser: FrameParser,
    /// 已解出的明文，等 `poll_read` 取走。
    read_plain: Vec<u8>,
    read_plain_pos: usize,
    scratch: Vec<u8>,
    write_pending: Option<PendingWrite>,
    write_padding: bool,
    write_sent_uuid: bool,
    /// 已看到客户端请求 DIRECT：清空后不再解帧。
    client_direct: bool,
    out_tls: TlsRecordTracker,
    /// 「还没攒够一次写出」的字节：响应头与紧随其后的握手记录要**合并成
    /// 同一帧**。
    ///
    /// 为什么必须合并：客户端读侧（upstream `XtlsUnpadding`）是按**一次读到的
    /// 字节**处理的 —— 读到 `CONTINUE` 且本帧 content/padding 清零就退出解帧。
    /// 所以「响应头单独一帧 + ServerHello 另一帧」在客户端那里会被拆到两次
    /// 读里，第二次读时客户端已经切到裸字节，帧头就被当成 TLS 密文。
    ///
    /// upstream 靠 `buf.NewBufferedWriter` 把响应头与第一段握手数据攒到一起
    /// 写出（`bufferWriter.SetFlushNext()`），我们在这里做同样的事。
    coalesce: Vec<u8>,
}

impl VisionServerConn {
    /// 用 VLESS 请求头里已经拿到的 `user_uuid` 建立包装。
    ///
    /// UUID **不需要**再解析一遍：`decode_request` 已经把它读出来了，
    /// 第一帧里那 16 字节只用来校验「这确实是我这个用户的流」。
    ///
    /// `inner` 是**已经解出明文**的传输层（服务端的 `RealityTlsStream`），
    /// 不包 `VlessConn` —— 那是客户端才需要的「读服务端响应头」逻辑，
    /// 服务端既没有响应头要读，也不该把 Vision 帧重新塞回 VLESS 层。
    pub fn new(inner: Box<dyn Stream>, user_uuid: [u8; UUID_LEN]) -> Self {
        Self {
            inner,
            user_uuid,
            parser: FrameParser::new(user_uuid),
            read_plain: Vec::new(),
            read_plain_pos: 0,
            scratch: Vec::new(),
            write_pending: None,
            write_padding: true,
            write_sent_uuid: false,
            client_direct: false,
            out_tls: TlsRecordTracker::new(),
            coalesce: Vec::new(),
        }
    }

    /// 客户端是否已经要求裸字节直传（DIRECT）。
    #[allow(dead_code)]
    pub fn client_direct(&self) -> bool {
        self.client_direct
    }

    fn enable_inner_raw_read_passthrough(&mut self) -> bool {
        xt_wasm_tls::enable_raw_read_passthrough(&mut *self.inner)
    }

    fn enable_inner_raw_write_passthrough(&mut self) -> bool {
        xt_wasm_tls::enable_raw_write_passthrough(&mut *self.inner)
    }

    /// 收到客户端的 DIRECT：**只切读侧**。
    ///
    /// # 为什么不能顺手把写侧也切了
    ///
    /// 两个方向是**各自独立**协商的，upstream 也是这么做的
    /// （`UplinkWriterDirectCopy` / `DownlinkReaderDirectCopy` 是四个不同的
    /// 标志位）：
    ///
    /// * 我们发 `DIRECT` → **对端的读侧**切裸字节 → 我们的**写侧**跟着切；
    /// * 对端发 `DIRECT` → **我们的读侧**切裸字节 → 我们的**写侧不动**。
    ///
    /// 写侧只能由「我们自己发出终止帧」来切。之前这里把两个方向一起切了，
    /// 于是只要**客户端先发 DIRECT**（它一看到自己的 TLS 应用数据就会发），
    /// 我们就停止组帧、开始裸写 —— 而客户端的读侧还在解帧，把裸字节当成
    /// 外层 TLS 密文，报 `tls: bad record MAC` 并断开（实测症状）。
    ///
    /// 这条 bug 是**竞态**：谁先发 DIRECT 决定成败，所以之前一直时红时绿。
    fn switch_read_to_raw(&mut self) -> io::Result<()> {
        if !self.enable_inner_raw_read_passthrough() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vision: 客户端要求 DIRECT，但底层传输无法切换成裸字节直传",
            ));
        }
        tracing::debug!("XTLS Vision（服务端）DIRECT：读侧已切裸字节");
        Ok(())
    }

    /// 写侧的组帧判定。与客户端 `build_write_frame` 同一套规则，只是
    /// 「TLS 客户端问候」换成「TLS 服务端问候」（两个方向的第 6 字节分别是
    /// ClientHello=0x01 / ServerHello=0x02）。
    ///
    /// 返回值：`(命令, 本帧后停止组帧, 本帧是 DIRECT)`。
    ///
    /// # 组帧的生命周期
    ///
    /// 与 upstream `proxy.VisionWriter` 的 `*isPadding` 一致：
    /// TLS 握手期间一直 `CONTINUE`，看到目标站的 TLS 应用数据才发 `DIRECT`
    /// 并停止组帧；非 TLS 目标才发 `END`。
    fn choose_write_command(&mut self, buf: &[u8]) -> (u8, bool, bool) {
        self.out_tls.observe(buf);

        // # 与 upstream `VisionWriter.WriteMultiBuffer` 逐条对应
        //
        // ```go
        // if *isPadding {
        //     isComplete := IsCompleteRecord(mb)
        //     longPadding := trafficState.IsTLS
        //     for i, b := range mb {
        //         if IsTLS && b.Len() >= 6 && Equal(TlsApplicationDataStart, b.BytesTo(3)) && isComplete {
        //             if EnableXtls { *switchToDirectCopy = true }
        //             command = (i == len(mb)-1) ? (EnableXtls ? DIRECT : END) : CONTINUE
        //             *isPadding = false
        //             longPadding = false
        //             continue
        //         }
        //         ...
        //     }
        // }
        // ```
        //
        // 三个要点，缺一个就会在错的时机切裸字节：
        //
        // 1. **`isComplete` 是「整段全部由完整的 `0x17` 记录组成」**，不是
        //    「停在记录边界上」。ServerHello 那一段以 `0x16` 开头 → 不完整
        //    → 继续 CONTINUE；加密握手那一段虽然全是 `0x17`，但它与
        //    ServerHello 常常同处一段 → 也不完整 → 继续 CONTINUE。
        // 2. **`EnableXtls`**：只有确认内层是 TLS 1.3（ServerHello 的
        //    cipher suite 在 TLS 1.3 列表里，且带 supported_versions 扩展）
        //    才允许切（`DIRECT`）；否则只发 `END`（不切 splice）。
        // 3. `longPadding` 只在 `IsTLS` 之后为真。
        if !self.out_tls.is_tls() {
            // 响应头那一帧：还不知道对端是不是 TLS，继续 CONTINUE。
            return (COMMAND_PADDING_CONTINUE, false, false);
        }

        let is_complete = is_complete_application_records(buf);
        let app_start = buf.len() >= 6
            && buf[0] == super::vision::TLS_APPLICATION_DATA
            && buf[1] == super::vision::TLS_MAJOR
            && buf[2] == super::vision::TLS_MAJOR;

        if app_start && is_complete {
            // 这就是真正的应用数据：本帧是最后一段需要打帧的数据。
            // 确认内层是 TLS 1.3 时用 `DIRECT`（让客户端也切裸字节），
            // 否则用 `END`。
            if self.out_tls.enable_xtls() {
                return (COMMAND_PADDING_DIRECT, true, true);
            }
            return (COMMAND_PADDING_END, true, false);
        }

        // 否则继续 CONTINUE + 长填充。
        (COMMAND_PADDING_CONTINUE, false, false)
    }

    fn build_write_frame(&mut self, buf: &[u8]) {
        let (command, end_after_drain, direct_after_drain) = self.choose_write_command(buf);
        // 与客户端写侧同一规则：只有**看到 TLS 握手之后**才长填充。
        // 服务端的第一帧是 VLESS 响应头（非 TLS），用短填充 ——
        // 这也正是「同一份 `build_padding_frame` 服务两个方向」的意思。
        let long_padding = self.out_tls.is_tls();
        let uuid = (!self.write_sent_uuid).then_some(&self.user_uuid);
        let frame = build_padding_frame(command, uuid, buf, long_padding);
        tracing::debug!(
            command,
            content_len = buf.len(),
            frame_len = frame.len(),
            long_padding,
            "XTLS Vision（服务端）组帧"
        );

        self.write_sent_uuid = true;
        self.write_pending = Some(PendingWrite {
            frame,
            pos: 0,
            consumed: buf.len(),
            end_padding_after_drain: end_after_drain,
            direct_after_drain,
        });
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
                        "vision: 写帧过程中写了 0 字节",
                    )));
                }
                Poll::Ready(n) => pending.pos += n,
            }
        }

        let pending = self.write_pending.take().expect("上面已确认 Some");
        if pending.end_padding_after_drain {
            self.write_padding = false;
            if pending.direct_after_drain {
                // 写侧切裸字节；读侧等客户端自己的 DIRECT 到来时再切
                // （客户端的 DIRECT 与我们的 DIRECT 是同一条规则的两个方向，
                //   但到达顺序不保证，所以两边各自切自己那半）。
                if !self.enable_inner_raw_write_passthrough() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "vision: DIRECT 已发出，但底层传输无法切换成裸字节直传",
                    )));
                }
                tracing::debug!("XTLS Vision（服务端）DIRECT：写侧已切裸字节");
            }
        }
        Poll::Ready(Ok(Some(pending.consumed)))
    }

    /// 把已经解出的明文交给调用方。返回 `true` 表示交出了一部分。
    fn drain_read_plain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_plain_pos >= self.read_plain.len() {
            return false;
        }
        let n = buf
            .remaining()
            .min(self.read_plain.len() - self.read_plain_pos);
        let end = self.read_plain_pos + n;
        buf.put_slice(&self.read_plain[self.read_plain_pos..end]);
        self.read_plain_pos = end;
        if self.read_plain_pos >= self.read_plain.len() {
            self.read_plain.clear();
            self.read_plain_pos = 0;
        }
        true
    }

    /// 处理一段刚从内层读到的字节（解出的明文追加到 `out`）。
    fn feed(
        &mut self,
        chunk: Option<&[u8]>,
        eof: bool,
        out: &mut Vec<u8>,
    ) -> io::Result<FrameAction> {
        self.parser.feed(chunk, eof, out)
    }
    /// 把「攒下的字节」编成一帧并交付给底层。
    ///
    /// 必须在**没有在途帧**时才能做 —— 否则会把正在写的帧覆盖掉，
    /// 线上就只剩一帧。
    ///
    /// # 为什么不能等「确认是 TLS」再发
    ///
    /// 这里**故意不加 `out_tls.is_tls()` 前置条件**。目标站不是 TLS 时
    /// （最典型的：明文 HTTP），`is_tls()` 永远不会为真；如果等它，
    /// 回程数据会永远留在 `coalesce` 里 —— 服务端日志显示
    /// `outcome=Forwarded down_bytes=...`，客户端却一个字节都收不到
    /// （curl 报 `(52) Empty reply from server`）。这正是线上抓到的症状。
    fn flush_coalesced(&mut self) {
        if self.write_padding && self.write_pending.is_none() && !self.coalesce.is_empty() {
            let merged = std::mem::take(&mut self.coalesce);
            self.build_write_frame(&merged);
        }
    }
}

impl AsyncRead for VisionServerConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.drain_read_plain(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            let this = &mut *self;

            // ── 先把解析器**内部**残留的字节榨干，再去读内层 ──
            //
            // 这一步不是优化，是正确性。一帧的 `content` 交出去之后，帧尾的
            // padding 还留在 `parser.pending` 里，而帧命令（尤其 `DIRECT`）
            // 要等 padding 走完才会生效。若这里直接去读内层：对端在写完这
            // 一帧后就已经切到裸字节了，我们会拿那段裸字节去喂外层 TLS
            // 解密 → `TLS AES-128-GCM decrypt: aead::Error`，连接直接死。
            //
            // 这条只在对端那一帧的 padding 与随后的裸字节**分处不同 TCP
            // 段**时暴露，所以之前一直是偶发红；`upstream_unpadding` 那种
            // 「一次喂完整段」的离线对拍也照不出来。
            if this.parser.pending_len() > 0 {
                let mut produced = Vec::new();
                match this.feed(None, false, &mut produced) {
                    Ok(FrameAction::Direct { .. }) => {
                        this.client_direct = true;
                        this.switch_read_to_raw()?;
                    }
                    Ok(_) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
                if !produced.is_empty() {
                    this.read_plain = produced;
                    this.read_plain_pos = 0;
                    let delivered = this.drain_read_plain(buf);
                    debug_assert!(delivered);
                    return Poll::Ready(Ok(()));
                }
            }

            let want = buf.remaining().min(READ_CHUNK);
            this.scratch.resize(want, 0);
            let mut rb = ReadBuf::new(&mut this.scratch[..want]);
            let read = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
            let n = match read {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => rb.filled().len(),
            };
            if n == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            let chunk = this.scratch[..n].to_vec();
            let mut produced = Vec::with_capacity(n);
            match this.feed(Some(&chunk), false, &mut produced) {
                Ok(FrameAction::Direct { .. }) => {
                    this.client_direct = true;
                    this.switch_read_to_raw()?;
                }
                Ok(_) => {}
                // 校验失败（UUID 不符 / 未知命令）必须**立刻**变成 io 错误，
                // 绝不能静默继续：把别人的帧当自己的解，输出会是一堆
                // 看似合法的垃圾。
                Err(e) => return Poll::Ready(Err(e)),
            }

            if !produced.is_empty() {
                this.read_plain = produced;
                this.read_plain_pos = 0;
                let delivered = this.drain_read_plain(buf);
                debug_assert!(delivered);
                return Poll::Ready(Ok(()));
            }
            // 这一段全是帧头/填充：继续读，直到有明文或 Pending。
            // 若调用方的缓冲区已经满了就没有意义再读。
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}
impl AsyncWrite for VisionServerConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // # 为什么「有在途帧」必须最先处理
        //
        // `poll_write` 有这样一个契约：**返回 `Pending` 时不能已经消费 buf**。
        // 而我们的组帧是「把 buf 编进 frame 再慢慢写出去」。如果在途帧没写完
        // 就返回 Pending，调用方会把同一个 buf 再递进来 —— 于是同一个 buf 被
        // 编成第二个帧，线上就出现了重复帧（拿官方客户端抓包时看到每帧出现
        // 两次，正是这个原因）。
        //
        // 所以：只要还有帧没写完，就只推它，不碰 buf。
        //
        // 推完之后**必须继续往下走**去编 `buf`，不能把「上一帧的
        // `consumed`」当成 `buf` 的写入量返回：那个数字是**上一个 buf**
        // 的，调用方（`write_all` / `tokio::io::copy`）会据此跳过 `buf`
        // 开头同样多的字节 —— 直接丢数据。`RealityTlsStream::poll_write`
        // 里对同一件事有更详细的注释。
        if this.write_pending.is_some() {
            match this.drain_pending_write(cx) {
                Poll::Ready(Ok(_)) => {} // 排空 → 落到下面给 `buf` 组帧
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write_padding {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // 还没看到目标站的 TLS 握手之前，先把字节攒起来（通常是那 2 字节
        // VLESS 响应头）。它与紧随其后的 `ServerHello` 必须落在**同一帧**里，
        // 否则客户端会把第二次读到的帧头当成 TLS 密文（见 `coalesce` 字段）。
        //
        // 先观察这一段：若它本身就是握手记录（例如调用方只写了一个单独的
        // `ServerHello`），下面的合并分支会立刻把它与攒下的响应头一起发出去。
        this.out_tls.observe(buf);
        if !this.out_tls.is_tls() {
            this.coalesce.extend_from_slice(buf);
            return Poll::Ready(Ok(buf.len()));
        }
        // 已经看到握手：把攒下的响应头与这一段合并成一次组帧。
        if !this.coalesce.is_empty() {
            let mut merged = std::mem::take(&mut this.coalesce);
            merged.extend_from_slice(buf);
            this.build_write_frame(&merged);
        } else {
            // 没有攒下的字节：直接把这一段编成一帧。
            let chunk_len = buf.len().min(MAX_FRAME_CONTENT);
            this.build_write_frame(&buf[..chunk_len]);
        }
        match this.drain_pending_write(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_coalesced();
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 调用方可能只 `write_all` 而没 `flush` 就关了（半关闭是常态）。
        // 少了这一次，攒下的回程数据会随连接一起消失。
        self.flush_coalesced();
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for VisionServerConn {}

impl ProxyConn for VisionServerConn {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    const UUID: [u8; UUID_LEN] = [0x11; UUID_LEN];

    /// 组一个帧（不含 UUID 前缀）。
    ///
    /// 参数顺序刻意是 `(content, command, padding)` —— 之前写成
    /// `(uuid, command, content, padding)`，结果好几条测试把 UUID 当成了
    /// 负载传进去，症状是「解出来的明文是 0x11」。参数少一个歧义就少一个。
    fn frame(content: &[u8], command: u8, padding: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(command);
        v.extend_from_slice(&(content.len() as u16).to_be_bytes());
        v.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        v.extend_from_slice(content);
        v.extend_from_slice(padding);
        v
    }

    /// 首帧（带 UUID 前缀）。
    fn first_frame(content: &[u8], command: u8, padding: &[u8]) -> Vec<u8> {
        let mut v = UUID.to_vec();
        v.extend(frame(content, command, padding));
        v
    }

    /// 喂一段输入，模拟真实读循环：报告消费多少就丢掉多少；输入读完后
    /// **继续喂空切片**，直到 pending 排空或进入裸字节模式。
    fn drive(input: &[u8]) -> io::Result<(Vec<u8>, Vec<FrameAction>, FrameParser)> {
        let mut p = FrameParser::new(UUID);
        let (out, actions) = drive_with(&mut p, input)?;
        Ok((out, actions, p))
    }

    fn drive_with(p: &mut FrameParser, input: &[u8]) -> io::Result<(Vec<u8>, Vec<FrameAction>)> {
        let mut out = Vec::new();
        let mut actions = Vec::new();
        let mut rest = input.to_vec();
        loop {
            let eof = rest.is_empty();
            let chunk: Option<&[u8]> = if rest.is_empty() { None } else { Some(&rest) };
            let mut produced = Vec::new();
            let a = p.feed(chunk, eof, &mut produced)?;
            let done = matches!(a, FrameAction::Direct { .. });
            let advance = match &a {
                FrameAction::Need => rest.len(),
                FrameAction::Produced { advance, .. } | FrameAction::Direct { advance, .. } => {
                    *advance
                }
            };
            out.extend_from_slice(&produced);
            actions.push(a);
            if done {
                let tail = advance.min(rest.len());
                out.extend_from_slice(&rest[tail..]);
                break;
            }
            let drop = advance.min(rest.len());
            rest.drain(..drop);
            // 停在「输入与解析器缓冲都空了，且这次的 feed 什么都没推进」。
            if rest.is_empty() && !p.has_pending() && produced_is_empty(&actions) {
                break;
            }
        }
        Ok((out, actions))
    }

    fn produced_is_empty(actions: &[FrameAction]) -> bool {
        matches!(
            actions.last(),
            Some(FrameAction::Produced { produced: 0, .. })
        )
    }

    // ─── 解帧 ───

    /// 首帧（21 字节头）与后续短头帧都要解得正确。
    #[test]
    fn parses_first_frame_with_uuid_and_short_frames_after() {
        let mut bytes = first_frame(b"abc", COMMAND_PADDING_CONTINUE, &[0xEE, 0xEE]);
        bytes.extend(frame(b"wxyz", COMMAND_PADDING_END, &[]));

        let (out, _, parser) = drive(&bytes).expect("应当解得出来");
        assert_eq!(out, b"abcwxyz", "content 必须原样还原，padding 必须丢掉");
        assert!(parser.is_through(), "END 那一帧读完后应进入裸字节模式");
    }

    /// content 与 padding 都为 0 的空帧不能把后面的帧头当成负载。
    #[test]
    fn empty_frame_is_transparent() {
        let mut bytes = first_frame(b"", COMMAND_PADDING_CONTINUE, &[]);
        bytes.extend(frame(b"Z", COMMAND_PADDING_END, &[]));

        let (out, _, _) = drive(&bytes).expect("空帧应当被跳过");
        assert_eq!(out, b"Z");
    }

    /// 首帧**没有 UUID 前缀**（首字节就是命令）时按短头解 —— upstream 兼容分支。
    ///
    /// 我们的客户端在 Vision 模式下就是这种形状：VLESS 请求头以裸字节先发出，
    /// 首个 Vision 帧因此没有 UUID 前缀。身份校验在 VLESS 层完成。
    #[test]
    fn unprefixed_first_frame_is_accepted_as_short_header() {
        let bytes = frame(b"abc", COMMAND_PADDING_END, &[]);

        let (out, _, parser) = drive(&bytes).expect("短头首帧应当被接受");
        assert_eq!(out, b"abc");
        assert!(parser.is_through());
    }

    /// 声明长度超过实际字节（截断）：不许 panic，只消费实际存在的字节。
    #[test]
    fn truncated_frame_consumes_only_what_exists() {
        // 帧头声明 content_len = 1000，实际只跟了 10 字节。
        let mut bytes = UUID.to_vec();
        bytes.push(COMMAND_PADDING_CONTINUE);
        bytes.extend_from_slice(&1000u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(b"only-a-few");

        let mut p = FrameParser::new(UUID);
        let mut out = Vec::new();
        let a = p
            .feed(Some(&bytes), false, &mut out)
            .expect("截断不是错误，只是还没读完");
        match a {
            FrameAction::Produced { advance, .. } => assert_eq!(advance, bytes.len()),
            other => panic!("应当只消费实际存在的字节，实际 {other:?}"),
        }
        assert_eq!(out, b"only-a-few");
        assert!(!p.is_through());
        // 再喂一段空的：仍然只是「等更多」，不报错也不吐东西。
        let mut more = Vec::new();
        let a = p.feed(None, true, &mut more).expect("空读不应报错");
        assert!(more.is_empty());
        assert!(matches!(
            a,
            FrameAction::Need | FrameAction::Produced { .. }
        ));
    }

    /// 未知命令必须报错（不能静默当成 CONTINUE）。
    #[test]
    fn unknown_command_is_rejected() {
        let bytes = first_frame(b"", 0x7f, &[]);

        let mut p = FrameParser::new(UUID);
        let mut out = Vec::new();
        let err = p
            .feed(Some(&bytes), true, &mut out)
            .expect_err("未知命令必须报错而不是静默降级");
        assert!(err.to_string().contains("0x7f"), "{err}");
    }

    /// DIRECT 之后是裸字节：不再有帧头，字节原样交出。
    #[test]
    fn direct_switches_to_raw_bytes() {
        let mut bytes = first_frame(b"hi", COMMAND_PADDING_DIRECT, &[]);
        // 后面是「裸字节」，即使看起来像帧头也必须原样交出。
        bytes.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, b'!']);

        let (out, actions, parser) = drive(&bytes).expect("DIRECT 应当切裸字节");
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, FrameAction::Direct { .. })),
            "必须报告 Direct：{actions:?}"
        );
        assert_eq!(
            out, b"hi\x01\x00\x00\x00\x00!",
            "DIRECT 之后的字节必须原样交出（不能再解帧）"
        );
        assert!(parser.is_through());
    }

    /// 帧头/内容/填充跨读边界（一次只喂 1 字节）也必须解得出来。
    #[test]
    fn parser_survives_arbitrary_read_boundaries() {
        let mut bytes = first_frame(b"hello", COMMAND_PADDING_CONTINUE, &[0x00; 7]);
        bytes.extend(frame(b"end", COMMAND_PADDING_END, &[0x00; 2]));

        let mut p = FrameParser::new(UUID);
        let mut out = Vec::new();
        let mut fed: Vec<u8> = Vec::new();
        for b in &bytes {
            fed.push(*b);
            loop {
                let mut produced = Vec::new();
                let action = p.feed(Some(&fed), false, &mut produced).expect("逐字节喂");
                let advance = match action {
                    FrameAction::Need => fed.len(),
                    FrameAction::Produced { advance, .. } | FrameAction::Direct { advance, .. } => {
                        advance
                    }
                };
                fed.drain(..advance.min(fed.len()));
                out.extend_from_slice(&produced);
                if fed.is_empty() {
                    break;
                }
            }
        }
        assert_eq!(out, b"helloend");
        assert!(p.is_through());
    }

    /// 零长度帧之后 DIRECT，且 DIRECT 帧本身也带内容。
    #[test]
    fn zero_content_zero_padding_then_direct() {
        let mut bytes = first_frame(b"", COMMAND_PADDING_CONTINUE, &[]);
        bytes.extend(frame(b"", COMMAND_PADDING_DIRECT, &[]));
        bytes.extend_from_slice(b"RAW");

        let (out, _, parser) = drive(&bytes).expect("应当解得出来");
        assert_eq!(out, b"RAW");
        assert!(parser.is_through());
    }

    // ─── 组帧 ───

    #[test]
    fn first_frame_carries_uuid_and_long_padding() {
        let content = [0u8; 2]; // VLESS 响应头
        let f = build_padding_frame(COMMAND_PADDING_END, Some(&UUID), &content, true);
        assert_eq!(&f[..UUID_LEN], &UUID, "第一帧必须带 UUID");
        assert_eq!(f[UUID_LEN], COMMAND_PADDING_END);
        let padding_len = u16::from_be_bytes([f[UUID_LEN + 3], f[UUID_LEN + 4]]) as usize;
        assert!(padding_len >= 900 - content.len(), "第一帧要长填充");
        assert_eq!(f.len(), PADDING_HEADER_LEN + content.len() + padding_len);
    }

    #[test]
    fn later_frames_use_short_header() {
        let f = build_padding_frame(COMMAND_PADDING_CONTINUE, None, b"payload", true);
        assert_eq!(f[0], COMMAND_PADDING_CONTINUE, "短头第一字节是命令");
        assert_eq!(u16::from_be_bytes([f[1], f[2]]) as usize, 7);
        assert_eq!(&f[SHORT_HEADER_LEN..SHORT_HEADER_LEN + 7], b"payload");
    }

    /// 一个只记录「写出去」的字节的假传输；读永远 Pending。
    #[derive(Clone)]
    struct Recorder(Arc<Mutex<Vec<u8>>>);

    impl AsyncRead for Recorder {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// **服务端写侧**：裸响应头 + 「首个 Vision 帧」的形状。
    ///
    /// 两个断言：
    ///
    /// * 响应头那 2 字节是**裸的**（客户端 `DecodeResponseHeader` 裸读它）；
    /// * 第一帧带 UUID、content 就是 `ServerHello`（客户端读侧要求首帧以
    ///   本用户 UUID 开头，并且是按一次读到的字节解帧的）。
    #[test]
    fn write_side_coalesces_response_header_and_server_hello() {
        use xt_wasm_runtime::block_on;

        let recorded = Arc::new(Mutex::new(Vec::new()));
        // 一条**完整**的 ServerHello 记录：记录头声明 11 字节负载，
        // 负载也真的给满 —— 组帧的终止判定要看「是否停在记录边界上」。
        let mut server_hello = vec![0x16u8, 0x03, 0x03, 0x00, 0x0b];
        server_hello.extend_from_slice(&[0x02, 0x00, 0x00, 0x07, 0x03, 0x03]);
        server_hello.extend_from_slice(&[0xaa; 5]);
        let expected = server_hello.clone();
        let rec = Arc::clone(&recorded);

        block_on(async move {
            // 与真实服务端一致：**先裸写响应头**（不在 Vision 帧里），
            // 之后才把流套上 `VisionServerConn`。
            let mut raw: Box<dyn Stream> = Box::new(Recorder(rec));
            raw.write_all(&[0x00, 0x00]).await.expect("响应头");
            raw.flush().await.expect("flush");

            let mut conn = VisionServerConn::new(raw, UUID);
            conn.write_all(&server_hello).await.expect("ServerHello");
            conn.flush().await.expect("flush");
        });

        let bytes = recorded.lock().unwrap().clone();
        // 前面 2 字节是**裸的** VLESS 响应头（不进帧）。
        const RAW_HEADER: usize = 2;
        assert_eq!(&bytes[..RAW_HEADER], &[0x00, 0x00], "响应头必须是裸的");
        let frame = &bytes[RAW_HEADER..];
        assert!(
            frame.len() >= PADDING_HEADER_LEN,
            "第一帧太短：{frame:02x?}"
        );
        assert_eq!(&frame[..UUID_LEN], &UUID, "首帧必须带 UUID");
        assert_eq!(
            frame[UUID_LEN], COMMAND_PADDING_CONTINUE,
            "还有握手帧要发，首帧必须是 CONTINUE"
        );
        let content_len = u16::from_be_bytes([frame[UUID_LEN + 1], frame[UUID_LEN + 2]]) as usize;
        assert_eq!(
            content_len,
            expected.len(),
            "首帧的 content 就是 ServerHello"
        );
        assert_eq!(
            &frame[PADDING_HEADER_LEN..PADDING_HEADER_LEN + expected.len()],
            &expected[..],
            "紧接着就是 ServerHello"
        );
    }

    /// **端到端对拍**：客户端 `VisionConn` ⇄ 服务端 `VisionServerConn`。
    ///
    /// 形状与真实链路一致：
    ///   * 服务端先写**裸的** 2 字节 VLESS 响应头（客户端也是这么裸读的）；
    ///   * 之后套上 `VisionServerConn`，回程按 Vision 组帧；
    ///   * 客户端用 `VlessConn::new_deferred` 把请求头与首个负载打进同一帧。
    ///
    /// 这条一旦绿，就说明「我们自己的两端」在帧层面是对齐的；
    /// 那时若官方客户端仍然不接受，问题就只在「与 upstream 的差异」上。
    #[test]
    fn vision_pair_round_trips_with_large_payload() {
        use crate::vless::vision::VisionConn;
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::block_on;

        block_on(async {
            let (client_side, server_side) = tokio::io::duplex(64 * 1024);
            let up = b"hello-up";
            let down = b"payload-from-target";

            let server = async move {
                // 0) 与真实服务端一致：**先解掉 VLESS 请求头**（那一段是裸的，
                //    不属于任何 Vision 帧）。这一步决定了后续流的对齐。
                let mut raw: Box<dyn Stream> = Box::new(server_side);
                let req = crate::vless::decode_request(&mut raw)
                    .await
                    .expect("VLESS 请求头");
                assert!(req.is_tcp());

                // 1) 裸响应头（与真实服务端一致）
                raw.write_all(&[0x00, 0x00]).await.expect("裸响应头");
                raw.flush().await.expect("flush");

                // 2) 之后才是 Vision 组帧
                let mut server = VisionServerConn::new(raw, UUID);
                let mut got = vec![0u8; up.len()];
                server.read_exact(&mut got).await.expect("服务端解帧");
                assert_eq!(&got[..], up, "服务端必须解出客户端的原始负载");

                // 3) 回程：真实目标是 TLS 站点，先来 ServerHello 再来应用数据。
                //    服务端会把「响应头的 2 字节」与 ServerHello 合并进同一帧
                //    （客户端是按一次读到的字节解帧的，拆帧会失步）。
                let server_hello = [
                    0x16u8, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03,
                ];
                server.write_all(&server_hello).await.expect("ServerHello");
                // 应用数据（`0x17 0x03 0x03`）：这一帧之后应当切到裸字节。
                let mut app = vec![0x17u8, 0x03, 0x03, 0x00, 0x04];
                app.extend_from_slice(down);
                server.write_all(&app).await.expect("应用数据");
                server.flush().await.expect("flush");
            };

            let client = async {
                let vless = VlessConn::new_deferred(
                    Box::new(client_side),
                    &UUID,
                    Some("xtls-rprx-vision"),
                    Cmd::Tcp,
                    80,
                    &VlessAddr::Ipv4([127, 0, 0, 1]),
                )
                .await
                .expect("VLESS 请求头");
                let mut client = VisionConn::new(vless, UUID);
                client.write_all(up).await.expect("客户端写");
                client.flush().await.expect("flush");

                // 回程总量 = ServerHello(11) + 应用数据头(5) + down
                let mut got = vec![0u8; 11 + 5 + down.len()];
                client.read_exact(&mut got).await.expect("客户端解帧");
                got[16..].to_vec()
            };

            let (got, ()) = futures::join!(client, server);
            assert_eq!(&got, down, "客户端必须原样解出服务端帧里的负载");
        });
    }

    /// **对端的 `DIRECT` 只能切我们的读侧**，写侧必须继续组帧，
    /// 直到**我们自己**发出终止帧。
    ///
    /// # 这条守着一个真实的线上故障
    ///
    /// 两个方向是**各自独立**协商的（upstream 用四个不同的标志位：
    /// `UplinkWriterDirectCopy` / `DownlinkReaderDirectCopy` …）。曾经在
    /// 收到对端 `DIRECT` 时把写侧也一起切了 —— 客户端一看到自己的 TLS
    /// 应用数据就会发 `DIRECT`，于是只要它比我们先发，我们就会停止组帧、
    /// 开始裸写；而客户端的读侧还在解帧，把裸字节当外层 TLS 密文，报
    /// `tls: bad record MAC` 并断开。**是竞态**，所以之前时红时绿。
    ///
    /// 这里用**真 REALITY 两端**复现当年那个时序：对端先发 `DIRECT`，
    /// 服务端随后写回一段响应。若服务端错误地切了写侧，响应会以裸字节
    /// 出去，客户端的外层 TLS 解不开 —— 测试立即失败。
    #[test]
    fn peer_direct_must_not_stop_our_write_framing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::block_on;
        use xt_wasm_tls::{reality_handshake, RealityConfig, RealityServerConfig};

        const SNI: &str = "www.cloudflare.com";
        const SHORT_ID: [u8; 8] = [7, 7, 7, 7, 7, 7, 7, 7];

        // 对端（客户端）先发的三段：握手帧 → DIRECT 帧 → 裸字节。
        let mut hello = vec![0x16u8, 0x03, 0x01, 0x00, 0x04];
        hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let mut direct = vec![0x17u8, 0x03, 0x03, 0x00, 0x04];
        direct.extend_from_slice(b"DOWN");
        let raw_tail = b"raw-tail".to_vec();
        let response = b"HTTP/1.1 200 OK\r\n\r\nhi".to_vec();

        let server_priv = xt_wasm_tls::test_support::fixture_private_key();
        let server_pub = xt_wasm_tls::test_support::public_from_private(&server_priv);
        let server_cfg = RealityServerConfig {
            private_key: server_priv,
            short_ids: vec![SHORT_ID],
            server_names: vec![SNI.to_string()],
            max_time_diff_secs: 60,
        };
        let client_cfg = RealityConfig {
            public_key: server_pub,
            short_id: SHORT_ID,
            client_version: [26, 3, 27],
        };

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let expect_up = [hello.clone(), direct.clone(), raw_tail.clone()].concat();
        let resp = response.clone();

        block_on(async {
            let server = async move {
                let xt_wasm_tls::HandshakeOutcome::Authenticated { stream, .. } =
                    xt_wasm_tls::reality_server_handshake(Box::new(server_io), &server_cfg)
                        .await
                        .expect("REALITY 服务端握手")
                else {
                    panic!("必须是认证路径");
                };
                // 与 `serve_inbound` 同序：裸响应头 → 套 Vision。
                let mut raw: Box<dyn Stream> = Box::new(stream);
                raw.write_all(&[0x00, 0x00]).await.expect("裸响应头");
                raw.flush().await.expect("flush");

                let mut srv = VisionServerConn::new(raw, UUID);
                let mut got = vec![0u8; expect_up.len()];
                srv.read_exact(&mut got).await.expect("服务端解帧");
                assert_eq!(got, expect_up, "读侧必须解出帧负载 + DIRECT 之后的裸字节");

                // 对端已经 DIRECT 了，但**我们还没发终止帧** ——
                // 所以这一段必须仍然是「帧」，不是裸字节。
                srv.write_all(&resp).await.expect("写响应");
                srv.flush().await.expect("flush");
            };

            let client = async {
                let mut tls = reality_handshake(Box::new(client_io), SNI, &[], &client_cfg)
                    .await
                    .expect("REALITY 客户端握手");

                let mut framed = first_frame(&hello, COMMAND_PADDING_CONTINUE, &[0xEE; 8]);
                framed.extend(frame(&direct, COMMAND_PADDING_DIRECT, &[0xEE; 8]));
                tls.write_all(&framed).await.expect("写帧");
                tls.flush().await.expect("flush");

                // 与真实客户端一致：发出 DIRECT 之后**自己的写侧**才切裸字节。
                assert!(
                    xt_wasm_tls::enable_raw_write_passthrough(&mut tls),
                    "REALITY 流必须支持裸写直传"
                );
                tls.write_all(&raw_tail).await.expect("写裸字节");
                tls.flush().await.expect("flush");

                // 服务端回程的第一件事是**裸的** 2 字节 VLESS 响应头。
                let mut vless_hdr = [0u8; 2];
                tls.read_exact(&mut vless_hdr).await.expect("裸响应头");
                assert_eq!(vless_hdr, [0x00, 0x00]);

                // 然后是 Vision 帧：**应当是一帧**（读侧我们还没切）。
                // 这是写侧的第一帧，所以带 16 字节 UUID 前缀。
                let mut uuid_prefix = [0u8; UUID_LEN];
                tls.read_exact(&mut uuid_prefix).await.expect("首帧 UUID");
                assert_eq!(uuid_prefix, UUID, "写侧首帧必须带 UUID");
                let mut hdr = [0u8; 5];
                tls.read_exact(&mut hdr).await.expect("读帧头");
                assert_eq!(
                    hdr[0], COMMAND_PADDING_CONTINUE,
                    "对端 DIRECT 不该让我们停止组帧（帧头 {hdr:02x?}）"
                );
                let content_len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
                let padding_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                assert_eq!(
                    content_len,
                    response.len(),
                    "帧里应当是完整响应（帧头 {hdr:02x?}）"
                );
                let mut body = vec![0u8; content_len + padding_len];
                tls.read_exact(&mut body).await.expect("读帧内容");
                body.truncate(content_len);
                body
            };

            let (got, ()) = futures::join!(client, server);
            assert_eq!(got, response, "客户端必须原样解出响应");
        });
    }

    /// `ChangeCipherSpec` 会被识别出来，且记录边界判定正确。
    ///
    /// TLS 1.3 的 CCS 是 `17 03 03 00 01 01` —— 与加密记录/应用数据线格式
    /// 一样。**踩过的坑**：把 CCS 当成「握手结束」会让服务端在加密握手
    /// 开始前就切裸字节（实测：终止帧 content 正好是 62 字节的 CCS，
    /// `curl` 拿 000）。所以跟踪器必须能把 CCS 单独认出来。
    #[test]
    fn tracker_recognises_ccs_and_record_boundaries() {
        let mut t = TlsRecordTracker::new();

        // ServerHello（明文握手记录）
        let mut hello = vec![0x16u8, 0x03, 0x03, 0x00, 0x0b];
        hello.extend_from_slice(&[0x02, 0x00, 0x00, 0x07, 0x03, 0x03]);
        hello.extend_from_slice(&[0xaa; 5]);
        t.observe(&hello);
        assert!(t.is_tls(), "ServerHello 之后应当确认是 TLS");
        assert!(t.ends_on_record_boundary(), "刚好停在记录边界上");
        assert_eq!(t.records_done, 1);

        // ChangeCipherSpec：`17 03 03 00 01 01`
        t.observe(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x01]);
        assert!(t.ends_on_record_boundary());
        assert_eq!(t.records_done, 2);

        // 半条记录：不能算「停在边界上」
        t.observe(&[0x17, 0x03, 0x03, 0x00, 0x10, 0x00]);
        assert!(!t.ends_on_record_boundary(), "记录没收完，不是边界");

        // 把它收完
        t.observe(&[0x00; 15]);
        assert!(t.ends_on_record_boundary(), "收完之后才是边界");
    }

    /// **非 TLS 目标**（明文 HTTP）：回程响应必须真的发出去。
    ///
    /// 这条盯着一个真实踩过的坑：写侧为了把「VLESS 响应头」和紧随其后的
    /// `ServerHello` 拼进**同一帧**，会把「还没确认对端是 TLS」的字节先攒在
    /// `coalesce` 里；而 `poll_flush` 当时只在 `out_tls.is_tls()` 为真时才
    /// 交付这一帧。目标站是明文 HTTP 时 `is_tls()` 永远为假 —— 于是响应被
    /// 永久扣在缓冲区里：服务端日志显示 `outcome=Forwarded down_bytes=…`，
    /// 客户端却一个字节都收不到（curl 报 `(52) Empty reply from server`）。
    ///
    /// 所以这里用一台**没有 TLS 的目标**跑完整一趟（请求 + 响应），断言
    /// 客户端能解出完整的 HTTP 响应。
    #[test]
    fn vision_pair_relays_plain_http_response() {
        use crate::vless::vision::VisionConn;
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::block_on;

        let request = b"GET / HTTP/1.1
Host: x

"
        .to_vec();
        let response = b"HTTP/1.1 200 OK
Content-Length: 16

hello-plain-http"
            .to_vec();

        let (client_side, server_side) = tokio::io::duplex(1024 * 1024);
        let req2 = request.clone();
        let resp2 = response.clone();

        let server = async move {
            let mut raw: Box<dyn Stream> = Box::new(server_side);
            // 与 `serve_inbound` 完全同序：先裸读 VLESS 请求头，再裸写响应头，
            // 最后才套 Vision。少了第一步就会把请求头当成帧头，测出假 bug。
            let decoded = crate::vless::server::decode_request(&mut raw)
                .await
                .expect("服务端解 VLESS 请求头");
            assert_eq!(decoded.flow.as_deref(), Some("xtls-rprx-vision"));
            raw.write_all(&[0x00, 0x00]).await.expect("裸响应头");
            raw.flush().await.expect("flush");
            let mut srv = VisionServerConn::new(raw, UUID);
            let mut got = vec![0u8; req2.len()];
            srv.read_exact(&mut got).await.expect("服务端解帧");
            assert_eq!(&got[..], &req2[..], "服务端必须解出客户端请求");
            srv.write_all(&resp2).await.expect("写 HTTP 响应");
            srv.flush().await.expect("flush");
        };

        let client = async {
            let vless = VlessConn::new_deferred(
                Box::new(client_side),
                &UUID,
                Some("xtls-rprx-vision"),
                Cmd::Tcp,
                80,
                &VlessAddr::Ipv4([127, 0, 0, 1]),
            )
            .await
            .expect("VLESS 请求头");
            let mut client = VisionConn::new(vless, UUID);
            client.write_all(&request).await.expect("客户端写");
            client.flush().await.expect("flush");
            let mut got = vec![0u8; response.len()];
            client.read_exact(&mut got).await.expect("客户端解帧");
            got
        };

        let (got, ()) = block_on(async { futures::join!(client, server) });
        assert_eq!(&got[..], &response[..], "客户端必须收到完整 HTTP 响应");
    }

    /// **与 upstream 解帧算法对拍**。
    ///
    /// 这里逐字移植 upstream `proxy.XtlsUnpadding` 的状态机（含
    /// `WithinPaddingBuffers` / `CurrentCommand` 的退出规则），用它去解
    /// **我们服务端真实写出的字节**。这是唯一能判定「我们的线上字节是否
    /// 符合 upstream 读侧预期」的离线手段 —— 不必依赖官方客户端。
    ///
    /// upstream 的退出规则（决定了它何时切到裸字节）：
    ///   * `RemainingContent > 0 || RemainingPadding > 0 || CurrentCommand == 0`
    ///     → 继续解帧；
    ///   * `CurrentCommand == 1`（END）或 `== 2`（DIRECT）→ **退出解帧**，
    ///     之后的字节按裸字节处理。
    #[test]
    fn upstream_unpadding_accepts_our_wire_bytes() {
        use tokio::io::AsyncWriteExt;
        use xt_wasm_runtime::block_on;

        // ── 用真实服务端路径产出线上字节 ──
        // 服务端把「响应头」裸写、然后套 VisionServerConn 写回程。
        // 我们直接构造同样的形状，并让目标是「一条 TLS 1.3 ServerHello +
        // 一条完整应用数据记录」，覆盖三个决策分支。
        let mut server_hello = vec![0x16u8, 0x03, 0x03, 0x00, 0x7a];
        // ServerHello 负载（含 4 字节 handshake 头），带 supported_versions
        // 扩展与 TLS 1.3 cipher suite，好让 EnableXtls 被置位。
        let mut sh_body = vec![0x02u8, 0x00, 0x00, 0x76, 0x03, 0x03];
        sh_body.extend_from_slice(&[0x11; 32]); // random
        sh_body.push(0); // session_id_len = 0
        sh_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        sh_body.push(0); // compression
        sh_body.extend_from_slice(&[0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        // handshake body 要等于记录声明的 122 字节
        sh_body.truncate(122);
        while sh_body.len() < 122 {
            sh_body.push(0);
        }
        server_hello.extend_from_slice(&sh_body);
        assert_eq!(server_hello.len(), 5 + 0x7a, "记录长度要对上");

        // 一条完整的 `0x17` 应用数据记录
        let mut app = vec![0x17u8, 0x03, 0x03, 0x00, 0x08];
        app.extend_from_slice(b"HTTP/1.1");

        let expected: Vec<u8> = [server_hello.clone(), app.clone()].concat();
        let wire = Arc::new(Mutex::new(Vec::new()));
        let rec = Recorder(Arc::clone(&wire));
        block_on(async move {
            let mut raw: Box<dyn Stream> = Box::new(rec);
            raw.write_all(&[0x00, 0x00]).await.expect("裸响应头");
            raw.flush().await.expect("flush");
            let mut srv = VisionServerConn::new(raw, UUID);
            srv.write_all(&server_hello).await.expect("ServerHello");
            // 应用数据那一帧会发 DIRECT 并尝试切裸字节。假传输不是
            // `RealityTlsStream`，切不了 —— 这是**预期的**：帧已经写进
            // `Recorder` 了，我们只关心线上字节。所以这里忽略该错误。
            // 应用数据那一帧会发 DIRECT 并尝试切裸字节。假传输不是
            // `RealityTlsStream`，切不了 —— 这是**预期的**：帧本身已经
            // 写进 `Recorder` 了，我们只关心线上字节，所以这里忽略该错误。
            let _ = srv.write_all(&app).await;
            let _ = srv.flush().await;
        });

        let bytes = wire.lock().unwrap().clone();
        // 前 2 字节是裸响应头：客户端先裸读掉它。
        assert_eq!(&bytes[..2], &[0x00, 0x00]);
        let frames = &bytes[2..];

        // ── upstream `XtlsUnpadding` 的解帧状态机（逐字移植）──
        //
        // 结构照抄：`remaining_command/content/padding` 三个游标 + 一个
        // 外层 `for b := range buffer`。每处理完一个「块」就判一次
        // `currentCommand`：0 → 继续读下一个块；1/2 → 退出解帧。
        let mut remaining_content: i64 = -1;
        let mut remaining_padding: i64 = -1;
        let mut current_command: i64 = 0;
        let mut out: Vec<u8> = Vec::new();
        let mut exited = false;
        const HEADER: i64 = 5;

        // upstream 里一个 `buf.Buffer` 就是一次读到的字节；这里把整段
        // 当作一个 buffer 处理（等价于一次读全）。
        let b: Vec<u8> = frames.to_vec();
        let mut bi = 0usize;
        let mut initial = true;

        // initial state：要求以本用户 UUID 开头
        if b.len() >= 16 && &b[..16] == UUID.as_slice() {
            bi = 16;
            initial = false;
        }
        assert!(!initial, "首帧没有以用户 UUID 开头（upstream 要求）");

        let mut remaining_command: i64 = 5;
        while bi < b.len() {
            if remaining_command > 0 {
                let data = b[bi];
                bi += 1;
                match remaining_command {
                    5 => current_command = data as i64,
                    4 => remaining_content = (data as i64) << 8,
                    3 => remaining_content = (remaining_content & !0xff) | data as i64,
                    2 => remaining_padding = (data as i64) << 8,
                    1 => remaining_padding = (remaining_padding & !0xff) | data as i64,
                    _ => {}
                }
                remaining_command -= 1;
            } else if remaining_content > 0 {
                let n = remaining_content.min((b.len() - bi) as i64) as usize;
                out.extend_from_slice(&b[bi..bi + n]);
                bi += n;
                remaining_content -= n as i64;
            } else {
                let n = remaining_padding.min((b.len() - bi) as i64).max(0) as usize;
                bi += n;
                remaining_padding -= n as i64;
            }
            if remaining_command <= 0 && remaining_content <= 0 && remaining_padding <= 0 {
                if current_command == 0 {
                    remaining_command = HEADER;
                } else {
                    // 终止命令：退出解帧，剩余字节按裸字节交给上层
                    exited = true;
                    out.extend_from_slice(&b[bi..]);
                    break;
                }
            }
        }
        let _ = HEADER;

        assert!(exited, "upstream 读侧应当因为 END/DIRECT 而退出解帧");
        assert_eq!(
            &out, &expected,
            "upstream 解帧算法必须还原出我们写出的 TLS 记录"
        );
    }

    /// **服务端读侧**：把一帧喂进去，必须原样解出内容。
    #[test]
    fn read_side_unpads_frames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::block_on;

        let mut wire = first_frame(b"abcd", COMMAND_PADDING_CONTINUE, &[0xAA; 3]);
        wire.extend(frame(b"ef", COMMAND_PADDING_END, &[]));

        let (mut peer, server) = tokio::io::duplex(4096);
        let conn = VisionServerConn::new(Box::new(server), UUID);

        block_on(async move {
            peer.write_all(&wire).await.expect("喂帧");
            peer.flush().await.expect("flush");
            drop(peer);

            let mut conn = conn;
            let mut got = vec![0u8; 6];
            conn.read_exact(&mut got).await.expect("服务端解帧");
            assert_eq!(&got, b"abcdef", "content 必须原样解出，padding 必须丢掉");
        });
    }

    /// **往返**：客户端 `VisionConn` 写出的帧，服务端 `FrameParser` 必须解得出。
    ///
    /// 客户端在 Vision 模式下会先以裸字节写 VLESS 请求头，因此首个 Vision 帧
    /// 没有 UUID 前缀 —— 服务端的短头分支就是为它准备的。
    #[test]
    fn client_write_is_readable_by_server_parser() {
        use crate::vless::vision::VisionConn;
        use crate::vless::{Cmd, VlessAddr, VlessConn};
        use xt_wasm_runtime::block_on;

        let recorded = Arc::new(Mutex::new(Vec::new()));
        let rec = Recorder(Arc::clone(&recorded));

        block_on(async move {
            let vless = VlessConn::new_deferred(
                Box::new(rec),
                &UUID,
                Some("xtls-rprx-vision"),
                Cmd::Tcp,
                80,
                &VlessAddr::Ipv4([127, 0, 0, 1]),
            )
            .await
            .unwrap();
            let mut client = VisionConn::new(vless, UUID);
            client.write_all(b"hello-up").await.unwrap();
        });

        let bytes = recorded.lock().unwrap().clone();
        // 请求头长度别写死：flow 非空时 addon 是 18 字节。
        let addon_len = bytes[17] as usize;
        let header_len = 18 + addon_len + 8;
        assert!(bytes.len() > header_len, "写出的字节太少");

        let mut parser = FrameParser::new(UUID);
        let mut out = Vec::new();
        parser
            .feed(Some(&bytes[header_len..]), true, &mut out)
            .expect("服务端应当能解客户端的帧");
        assert!(
            out.ends_with(b"hello-up"),
            "解出来的负载末尾应当是客户端写的载荷，实际 {:02x?}",
            &out[..out.len().min(80)]
        );
    }
}
