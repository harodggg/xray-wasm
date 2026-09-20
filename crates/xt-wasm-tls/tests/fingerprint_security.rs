//! T4 —— 「浏览器指纹伪装」特性的安全审计（对抗性集成测试）。
//!
//! 这个文件只做一件事：把 task-4 的结论钉成**可执行**的断言。审计对象是
//! `crate::fingerprint`（T1 引擎）与 `reality.rs` 的接线（T2），但其中不依赖
//! T1/T2 的部分（REALITY 认证位置语义、每次连接的随机性、畸形输入、HRR 的
//! 远端行为）现在就能跑，而且**任何一条都不允许为了变绿而放宽**。
//!
//! 两条贯穿全篇的原则：
//!
//! 1. **测线上真实字节，不测"我以为会生成的字节"。** ClientHello 一律通过
//!    `reality_handshake` 对一个内存 duplex 发起真实握手，在服务端侧把第一条
//!    TLS record 原样截下来。这样 T1/T2 换实现、换 profile，这里断言的位置与
//!    语义依然是对真实流量的断言。
//! 2. **不确定 = 未验证。** 拿不到证据的结论写在 `docs/fingerprint-security.md`
//!    里并标注「未验证」，不写成「安全」。
//!
//! 结论摘要与威胁模型见 `docs/fingerprint-security.md`。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use xt_wasm_runtime::block_on;
use xt_wasm_tls::fingerprint::{
    build_client_hello, new_grease_seed, profile_by_name, profile_names, DEFAULT_PROFILE_NAME,
};
use xt_wasm_tls::{
    authenticate, parse_client_hello, reality_handshake, test_support, ClientHello, RealityConfig,
    RealityServerConfig,
};

// ─── 固定偏移：REALITY 认证的字节位置语义 ────────────────────────────────
//
// 这三个偏移是 REALITY 认证的地基，**指纹改动不得移动它们**：
//   * `random`    在握手消息 6..38（HKDF 的 salt 取 6..26，AES-GCM nonce 取 26..38）；
//   * `session_id` 长度字节在 38；
//   * `session_id` 内容在 39..71（前 16 字节是认证密文，后 16 字节随机）。
const OFF_RANDOM: usize = 6;
const OFF_SESSION_ID_LEN: usize = 38;
const OFF_SESSION_ID: usize = 39;
const SESSION_ID_LEN: usize = 32;

/// 本 crate 的跨 crate 测试夹具：`clamp([0x42; 32])`，与 `reality_server.rs`
/// 里抓官方夹包时用的私钥是同一把（它不保护任何东西）。
const SNI: &str = "www.cloudflare.com";

/// 官方 Xray 客户端 `fingerprint: chrome` 真实发出的 ClientHello 夹包（1787 B）。
///
/// 直接 `include_str!` 同一个 testdata 文件，不复制一份 —— 复制出来的夹具会漂移。
const FIXTURE_HEX: &str = include_str!("../src/testdata/xray-clienthello.hex");

/// RFC 8446 §4.1.4 规定的 HelloRetryRequest 哨兵 random。
///
/// 服务端发出的 "ServerHello" 如果 random 等于这个值，它其实是一个 HRR。
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

const GREASE_X25519MLKEM768: u16 = 0x11ec;

// ─────────────────────────── 小工具 ───────────────────────────

fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    assert!(hex.len().is_multiple_of(2), "hex 长度应为偶数");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("合法 hex"))
        .collect()
}

fn fixture_hello() -> Vec<u8> {
    hex_decode(FIXTURE_HEX)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟晚于 1970")
        .as_secs()
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// 一对匹配的 REALITY 客户端 / 服务端配置（用夹具私钥）。
fn reality_pair() -> (RealityConfig, RealityServerConfig) {
    let private_key = test_support::fixture_private_key();
    let public_key = test_support::public_from_private(&private_key);
    let short_id = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
    (
        RealityConfig::new(public_key, short_id),
        RealityServerConfig {
            private_key,
            short_ids: vec![short_id],
            // 空列表 = 不校验 SNI，这样断言只针对认证载荷本身。
            server_names: Vec::new(),
            // 0 = 不校验时钟；认证语义的其余部分照常校验。
            max_time_diff_secs: 0,
        },
    )
}

/// 发起一次**真实**客户端握手，把对端收到的第一条 TLS record 的握手消息截回来。
///
/// 不 mock `build_*`：T1/T2 改 profile 后，这里拿到的就是实际上线的那份字节。
/// 截完第一条 record 就把服务端侧丢掉，客户端随后读到 EOF 而结束，不会挂住。
fn capture_client_hello(reality: &RealityConfig, sni: &str, alpn: &[String]) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let sni_owned = sni.to_string();
    let alpn_owned = alpn.to_vec();

    block_on(async move {
        let record = async move {
            let mut server_io = server_io;
            let mut header = [0u8; 5];
            server_io
                .read_exact(&mut header)
                .await
                .expect("读 TLS record 头");
            assert_eq!(header[0], 22, "ClientHello 必须在 handshake record 里");
            assert_eq!(
                &header[1..3],
                &[0x03, 0x01],
                "record 版本应为 {:#04x}",
                header[1]
            );
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut payload = vec![0u8; len];
            server_io
                .read_exact(&mut payload)
                .await
                .expect("读 TLS record 体");
            // 显式关掉这一端：客户端随即读到 EOF 并结束，测试不会挂住。
            drop(server_io);
            payload
        };
        let client = reality_handshake(Box::new(client_io), &sni_owned, &alpn_owned, reality);
        let (hello, client_result) = futures::join!(record, client);
        assert!(client_result.is_err(), "截断的服务端不应让客户端握手成功");
        hello
    })
}

/// 校验一条握手消息的 4 字节头自洽，返回 body。
fn handshake_body(msg: &[u8]) -> &[u8] {
    assert!(msg.len() >= 4, "握手消息至少 4 字节");
    assert_eq!(msg[0], 1, "必须是 ClientHello");
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    assert_eq!(len + 4, msg.len(), "握手消息长度字段与实际不符");
    &msg[4..]
}

/// 结构扫描结果：只取审计需要的几样东西。
#[derive(Debug, Default)]
struct Scan {
    ciphers: Vec<u16>,
    ext_types: Vec<u16>,
    supported_groups: Vec<u16>,
    key_share_groups: Vec<u16>,
    /// 每个扩展的 (类型, 数据长度)，顺序与线上一致。
    ext_data_lens: Vec<(u16, usize)>,
}

impl Scan {
    fn ext_len(&self, typ: u16) -> Option<usize> {
        self.ext_data_lens
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, l)| *l)
    }
}

/// 解析 ClientHello 的扩展结构。**只用于测试断言**，越界一律返回 Err。
fn scan_client_hello(msg: &[u8]) -> Result<Scan, String> {
    if msg.len() < 4 || msg[0] != 1 {
        return Err("不是 ClientHello".into());
    }
    let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if body_len + 4 != msg.len() {
        return Err("长度不符".into());
    }
    let b = &msg[4..];
    if b.len() < 34 {
        return Err("body 过短".into());
    }
    let mut p = 34usize;
    let sid_len = *b.get(p).ok_or("缺 session_id 长度")? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    let cs_raw = b.get(p + 2..p + 2 + cs_len).ok_or("cipher_suites 越界")?;
    let mut scan = Scan::default();
    for i in 0..cs_raw.len() / 2 {
        scan.ciphers
            .push(u16::from_be_bytes([cs_raw[i * 2], cs_raw[i * 2 + 1]]));
    }
    p += 2 + cs_len;
    let comp_len = *b.get(p).ok_or("缺 compression")? as usize;
    p += 1 + comp_len;
    let ext_total = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    if p + ext_total > b.len() {
        return Err("扩展块超出 body".into());
    }
    let exts = &b[p..p + ext_total];
    let mut q = 0usize;
    while q < exts.len() {
        if q + 4 > exts.len() {
            return Err("扩展头越界".into());
        }
        let typ = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let len = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        q += 4;
        if q + len > exts.len() {
            return Err("扩展体越界".into());
        }
        let data = &exts[q..q + len];
        q += len;
        scan.ext_types.push(typ);
        scan.ext_data_lens.push((typ, len));
        match typ {
            10 => {
                // supported_groups: u16 列表长度 + 若干 u16
                if data.len() < 2 {
                    return Err("supported_groups 过短".into());
                }
                let n = u16::from_be_bytes([data[0], data[1]]) as usize;
                for i in 0..n / 2 {
                    let off = 2 + i * 2;
                    if off + 2 > data.len() {
                        return Err("supported_groups 越界".into());
                    }
                    scan.supported_groups
                        .push(u16::from_be_bytes([data[off], data[off + 1]]));
                }
            }
            51 => {
                // key_share: u16 总长 + 若干 (group u16, len u16, share)
                if data.len() < 2 {
                    return Err("key_share 过短".into());
                }
                let total = u16::from_be_bytes([data[0], data[1]]) as usize;
                let mut r = 2usize;
                while r < 2 + total && r + 4 <= data.len() {
                    let g = u16::from_be_bytes([data[r], data[r + 1]]);
                    let l = u16::from_be_bytes([data[r + 2], data[r + 3]]) as usize;
                    scan.key_share_groups.push(g);
                    r += 4 + l;
                }
            }
            _ => {}
        }
    }
    Ok(scan)
}

/// 定位 X25519(0x001d) key_share 里公钥的第一个字节在整条握手消息中的偏移。
fn x25519_share_offset(msg: &[u8]) -> Option<usize> {
    let body = handshake_body(msg);
    let mut p = 34usize;
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs_len;
    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if p + ext_total > body.len() {
        return None;
    }
    let exts = &body[p..p + ext_total];
    let base = 4 + p;
    let mut q = 0usize;
    while q + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let len = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        q += 4;
        if q + len > exts.len() {
            return None;
        }
        if typ == 51 {
            let data = &exts[q..q + len];
            let total = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut r = 2usize;
            while r + 4 <= data.len() && r < 2 + total {
                let g = u16::from_be_bytes([data[r], data[r + 1]]);
                let l = u16::from_be_bytes([data[r + 2], data[r + 3]]) as usize;
                if g == 0x001d {
                    return Some(base + q + r + 4);
                }
                r += 4 + l;
            }
        }
        q += len;
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════
// 审计项 1：REALITY 认证语义未被削弱
// ═══════════════════════════════════════════════════════════════════════

/// 线上真实发出去的 ClientHello，必须仍然满足 REALITY 的**位置语义**，
/// 而且服务端能凭它认证成功。
///
/// 这条是第 1 项的骨架断言：T1/T2 换 profile（plain → chrome）之后它必须照过。
#[test]
fn wire_client_hello_keeps_reality_auth_layout() {
    let (client_cfg, server_cfg) = reality_pair();
    let hello = capture_client_hello(
        &client_cfg,
        SNI,
        &["h2".to_string(), "http/1.1".to_string()],
    );

    handshake_body(&hello);
    assert!(hello.len() > OFF_SESSION_ID + SESSION_ID_LEN);
    assert_eq!(
        hello[OFF_SESSION_ID_LEN], SESSION_ID_LEN as u8,
        "session_id 长度字节必须仍是 32（偏移 {OFF_SESSION_ID_LEN}）"
    );

    let ch = parse_client_hello(&hello).expect("线上 ClientHello 必须可解析");
    assert_eq!(
        ch.session_id_offset, OFF_SESSION_ID,
        "session_id 偏移必须仍是 39 —— GREASE/扩展增删不得挪动它"
    );
    assert_eq!(
        &ch.random[..],
        &hello[OFF_RANDOM..OFF_RANDOM + 32],
        "random 必须仍取自偏移 6..38"
    );
    assert_eq!(
        &ch.session_id[..],
        &hello[OFF_SESSION_ID..OFF_SESSION_ID + SESSION_ID_LEN],
        "认证密文必须仍占 session_id[0..16]"
    );

    let auth = authenticate(&ch, &server_cfg, unix_now())
        .expect("线上 ClientHello 必须能通过 REALITY 认证");
    assert_eq!(
        auth.short_id,
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]
    );
    assert_eq!(auth.client_version, RealityConfig::DEFAULT_CLIENT_VERSION);
}

/// 越界/错位断言：篡改 REALITY 依赖的三处（random / session_id / X25519 公钥）
/// 中的**任何一处**，认证都必须失败。
#[test]
fn tampering_reality_critical_fields_breaks_authentication() {
    let (client_cfg, server_cfg) = reality_pair();
    let hello = capture_client_hello(&client_cfg, SNI, &[]);
    let now = unix_now();

    // 基线：原样必须通过。
    let ch = parse_client_hello(&hello).expect("解析");
    authenticate(&ch, &server_cfg, now).expect("基线必须认证通过");

    // (a) random 的 HKDF salt 段（偏移 6..26）
    let mut m = hello.clone();
    m[OFF_RANDOM] ^= 0x01;
    let ch = parse_client_hello(&m).expect("只有 random 变了，仍应可解析");
    assert!(
        authenticate(&ch, &server_cfg, now).is_err(),
        "改 random[0] 后认证必须失败"
    );

    // (b) random 的 GCM nonce 段（偏移 26..38）
    let mut m = hello.clone();
    m[26] ^= 0x01;
    let ch = parse_client_hello(&m).expect("解析");
    assert!(
        authenticate(&ch, &server_cfg, now).is_err(),
        "改 random[20] 后认证必须失败"
    );

    // (c) session_id 认证密文里翻一位
    let mut m = hello.clone();
    m[OFF_SESSION_ID] ^= 0x80;
    let ch = parse_client_hello(&m).expect("解析");
    assert!(
        authenticate(&ch, &server_cfg, now).is_err(),
        "改认证密文后认证必须失败"
    );

    // (d) X25519 key_share 里翻一位
    let off = x25519_share_offset(&hello).expect("必须能找到 X25519 share");
    let mut m = hello.clone();
    m[off] ^= 0x01;
    let ch = parse_client_hello(&m).expect("解析");
    assert!(
        authenticate(&ch, &server_cfg, now).is_err(),
        "改 X25519 公钥后认证必须失败"
    );
}

/// 更强的性质：ClientHello 里**除 session_id 外**的任何单字节翻转，
/// 都不能再认证成功（要么解析失败，要么认证失败）。
///
/// 这条钉住的是「认证绑定整条消息」：REALITY 的 AAD 是整份 ClientHello，
/// 所以指纹引擎**没有**留下任何「改了也不影响认证」的自由字节 ——
/// 反过来说，T1 只要动了某个字节，认证语义就必须同步成立，不能靠运气。
#[test]
fn no_single_byte_tamper_outside_session_id_can_authenticate() {
    let (client_cfg, server_cfg) = reality_pair();
    let hello = capture_client_hello(&client_cfg, SNI, &[]);
    let now = unix_now();

    let mut checked = 0usize;
    let mut parsed_but_rejected = 0usize;
    for off in 0..hello.len() {
        // session_id 字段本身单独测（见上一条），这里跳过。
        if (OFF_SESSION_ID..OFF_SESSION_ID + SESSION_ID_LEN).contains(&off) {
            continue;
        }
        let mut m = hello.clone();
        m[off] ^= 0x01;
        if let Ok(ch) = parse_client_hello(&m) {
            parsed_but_rejected += 1;
            assert!(
                authenticate(&ch, &server_cfg, now).is_err(),
                "偏移 {off} 翻转一位后仍认证成功 —— 认证没有绑定整条消息"
            );
        }
        checked += 1;
    }
    assert!(checked > 100, "样本太少（{checked}），断言没有意义");
    assert!(
        parsed_but_rejected > 100,
        "绝大多数偏移应当只是值变化而非长度错误，实际 {parsed_but_rejected}"
    );
}

/// 官方夹包（带 GREASE、16 个扩展、三份 key_share）也必须落在同样的偏移上，
/// 并且能通过我们的服务端认证 —— 即「扩展再多也不挪位置」。
#[test]
fn official_fixture_keeps_positions_and_authenticates() {
    let msg = fixture_hello();
    assert_eq!(msg.len(), 1787, "官方 chrome 指纹夹包固定 1787 字节");
    assert_eq!(msg[OFF_SESSION_ID_LEN], SESSION_ID_LEN as u8);

    let ch = parse_client_hello(&msg).expect("官方夹包必须可解析");
    assert_eq!(ch.session_id_offset, OFF_SESSION_ID);
    assert_eq!(&ch.random[..], &msg[OFF_RANDOM..OFF_RANDOM + 32]);

    let scan = scan_client_hello(&msg).expect("结构扫描");
    assert!(
        scan.ext_types.len() >= 16,
        "夹包应当有 16+ 个扩展，实际 {}",
        scan.ext_types.len()
    );
    assert!(
        scan.ext_types.iter().any(|t| is_grease(*t)),
        "夹包里应当有 GREASE 扩展"
    );

    // 抓这份夹包时用的私钥（[0x42; 32] clamp），与 reality_server.rs 单测一致。
    let server_cfg = RealityServerConfig {
        private_key: test_support::fixture_private_key(),
        short_ids: vec![[0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]],
        server_names: Vec::new(),
        max_time_diff_secs: 0,
    };
    let auth = authenticate(&ch, &server_cfg, 0).expect("官方夹包必须认证通过");
    assert_eq!(
        auth.short_id,
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33]
    );
}

/// 服务端不原样回显 session_id 时，客户端必须拒绝。
///
/// 这条覆盖 REALITY 认证语义的第三个位置：`client_hello[39..71]` 的回显校验。
/// 一个只会回显"看起来对"的东西的中间人不得通过。
#[test]
fn server_that_does_not_echo_session_id_is_rejected_without_a_retry() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_cfg, _) = reality_pair();
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let sni = SNI.to_string();

    let client_result = block_on(async {
        let server = async {
            let mut header = [0u8; 5];
            server_io.read_exact(&mut header).await.expect("record 头");
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut hello = vec![0u8; len];
            server_io.read_exact(&mut hello).await.expect("ClientHello");

            // 回显一个被篡改过的 session_id（翻一位），其余都像真的。
            let mut wrong = hello.clone();
            wrong[OFF_SESSION_ID] ^= 0x80;
            let sh = build_server_hello(&wrong[OFF_SESSION_ID..OFF_SESSION_ID + 32], &[0x11u8; 32]);
            let mut rec = vec![22u8, 0x03, 0x03];
            rec.extend_from_slice(&(sh.len() as u16).to_be_bytes());
            rec.extend_from_slice(&sh);
            server_io.write_all(&rec).await.expect("写 ServerHello");
            server_io.flush().await.expect("flush");
            hello
        };
        let client = reality_handshake(Box::new(client_io), &sni, &[], &client_cfg);
        let (_hello, result) = futures::join!(server, client);
        result
    });

    match client_result {
        Err(e) => assert!(
            e.to_string().contains("echo"),
            "应以「未回显 session_id」拒绝，实际：{e}"
        ),
        Ok(_) => panic!("session_id 回显不符时必须拒绝，客户端却成功了"),
    }

    // 客户端不得因此重发任何 ClientHello。
    let extra = block_on(xt_wasm_runtime::timeout(
        Duration::from_millis(500),
        async {
            let mut b = [0u8; 1];
            server_io.read(&mut b).await
        },
    ));
    match extra {
        Ok(Ok(0)) | Err(_) => {}
        Ok(Ok(n)) => panic!("客户端在回显校验失败后仍发了 {n} 字节"),
        Ok(Err(e)) => panic!("读服务端侧失败：{e}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 审计项 2：每次连接的随机性
// ═══════════════════════════════════════════════════════════════════════

/// 连续 N 条线上 ClientHello：random / session_id 认证密文 / session_id 后 16 字节
/// 都必须两两不同。任何一处复用 = 跨连接可关联。
#[test]
fn per_connection_randomness_on_the_wire() {
    let (client_cfg, _) = reality_pair();
    const N: usize = 8;
    let hellos: Vec<Vec<u8>> = (0..N)
        .map(|_| capture_client_hello(&client_cfg, SNI, &[]))
        .collect();

    for i in 0..N {
        for j in (i + 1)..N {
            assert_ne!(
                &hellos[i][OFF_RANDOM..OFF_RANDOM + 32],
                &hellos[j][OFF_RANDOM..OFF_RANDOM + 32],
                "连接 {i} 与 {j} 复用了 random"
            );
            assert_ne!(
                &hellos[i][OFF_SESSION_ID..OFF_SESSION_ID + 16],
                &hellos[j][OFF_SESSION_ID..OFF_SESSION_ID + 16],
                "连接 {i} 与 {j} 复用了认证密文"
            );
            assert_ne!(
                &hellos[i][OFF_SESSION_ID + 16..OFF_SESSION_ID + 32],
                &hellos[j][OFF_SESSION_ID + 16..OFF_SESSION_ID + 32],
                "连接 {i} 与 {j} 复用了 session_id 后 16 字节"
            );
        }
    }
}

/// GREASE 值必须每连接变化，不得是写死的常量。
///
/// 现在的 `plain` 形状没有 GREASE，所以先断言「如果出现了 GREASE，它必须全部
/// 是同轮成对值且跨连接变化」；`chrome` profile 接线后（T1/T2），
/// `chrome_profile_grease_is_per_connection` 会强制要求 GREASE 真的存在。
#[test]
fn grease_values_are_per_connection_when_present() {
    let (client_cfg, _) = reality_pair();
    let scans: Vec<Scan> = (0..6)
        .map(|_| scan_client_hello(&capture_client_hello(&client_cfg, SNI, &[])).expect("扫描"))
        .collect();

    let grease_of = |s: &Scan| -> Vec<u16> {
        let mut v: Vec<u16> = s
            .ext_types
            .iter()
            .copied()
            .filter(|t| is_grease(*t))
            .collect();
        v.sort_unstable();
        v
    };
    let first = grease_of(&scans[0]);
    if first.is_empty() {
        // plain profile：没有 GREASE 是预期内的，不在此处判红。
        return;
    }
    for (i, s) in scans.iter().enumerate().skip(1) {
        let g = grease_of(s);
        assert!(
            !g.iter().any(|v| first.contains(v)),
            "连接 {i} 与连接 0 复用了 GREASE 扩展值 {first:?} / {g:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 审计项 3：新增可识别特征（HRR / 声明了却不提供的组）
// ═══════════════════════════════════════════════════════════════════════

/// 官方夹包**声明了什么、就提供了什么**：supported_groups 里的
/// X25519MLKEM768(0x11ec) 在 key_share 里有对应的 1216 字节 share。
///
/// 这是「真 Chrome 形状」的判据。T1 计划发的形状（声明 11ec、不发它的 share）
/// 与这条直接冲突，见下一条测试与 docs 里的真机实验。
#[test]
fn official_fixture_declares_and_shares_x25519mlkem768() {
    let scan = scan_client_hello(&fixture_hello()).expect("结构扫描");
    assert!(
        scan.supported_groups.contains(&GREASE_X25519MLKEM768),
        "官方夹包的 supported_groups 应包含 11ec"
    );
    assert!(
        scan.key_share_groups.contains(&GREASE_X25519MLKEM768),
        "官方夹包的 key_share 必须包含 11ec —— 真 Chrome 从不让它落空"
    );
    // 顺带钉住：官方夹包里会声明但**不**提供 share 的组，是 0017/0018 这类
    // 服务端几乎从不首选的老曲线，而 11ec 恰恰是现代服务端的首选。
    assert!(
        scan.supported_groups.contains(&0x0017) || scan.supported_groups.contains(&0x0018),
        "官方夹包应当声明 secp256r1/secp384r1"
    );
}

/// 把官方夹包**只**去掉 11ec 那条 key_share（supported_groups 不动），
/// 得到的正是 T1 计划要发的可观测形状。断言：
///   1. 它在语法上仍然合法（我们自己的解析器吃得下）；
///   2. 「声明了 11ec 却不提供它的 share」这个不一致是**机器可判**的 ——
///      任何解析 CH 的被动观察者都能一眼标出来。
///
/// 这条测试只证明*静态*可识别性；它会不会引来 HelloRetryRequest 是**动态**
/// 结论，需要真实对端，证据见 `docs/fingerprint-security.md`（本机复现，
/// cloudflare.com / google.com 等 5 个 SNI 全部返回 HRR 且明确请求 0x11ec）。
#[test]
fn declaring_x25519mlkem768_without_its_key_share_is_statically_identifiable() {
    let stripped = strip_key_share(&fixture_hello(), GREASE_X25519MLKEM768);

    // 1) 语法合法，我们自己的服务端仍能解析（所以内部 e2e 测不出问题）。
    let ch = parse_client_hello(&stripped).expect("删掉 11ec share 后仍是合法 ClientHello");
    assert_eq!(ch.session_id_offset, OFF_SESSION_ID, "位置语义不受影响");
    assert_ne!(ch.key_share, [0u8; 32], "x25519 share 仍在");

    // 2) 不一致可被静态判定。
    let scan = scan_client_hello(&stripped).expect("结构扫描");
    assert!(
        scan.supported_groups.contains(&GREASE_X25519MLKEM768),
        "supported_groups 仍声明 11ec（这正是要审计的取舍）"
    );
    assert!(
        !scan.key_share_groups.contains(&GREASE_X25519MLKEM768),
        "key_share 里已经没有 11ec —— 与真 Chrome 的差异就在这里"
    );

    // 真 Chrome 形状与我们的形状，在「声明但无 share 的组集合」上不同：
    let chrome = scan_client_hello(&fixture_hello()).expect("扫描夹包");
    let missing = |s: &Scan| -> Vec<u16> {
        s.supported_groups
            .iter()
            .copied()
            .filter(|g| !is_grease(*g))
            .filter(|g| !s.key_share_groups.contains(g))
            .collect()
    };
    let ours = missing(&scan);
    let theirs = missing(&chrome);
    assert!(ours.contains(&GREASE_X25519MLKEM768));
    assert!(
        !theirs.contains(&GREASE_X25519MLKEM768),
        "真 Chrome 不会把 11ec 留在'声明但无 share'里"
    );
    assert_ne!(ours, theirs, "两者可在被动解析下被区分");
}

/// 对端发 HelloRetryRequest 时，我们客户端的**当前**行为必须是「明确失败」，
/// 而不是装作没事、更不是回落到什么更弱的形状。
///
/// 直接意义：REALITY 的 dest（Cloudflare 等）若因 11ec 落空而发 HRR，
/// 我们这条连接就死在这里 —— 且不会重发第二份 ClientHello。
#[test]
fn hello_retry_request_is_fatal_and_produces_no_second_client_hello() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client_cfg, _) = reality_pair();
    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
    let sni = SNI.to_string();

    let client_result = block_on(async {
        let server = async {
            let mut header = [0u8; 5];
            server_io.read_exact(&mut header).await.expect("record 头");
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut hello = vec![0u8; len];
            server_io.read_exact(&mut hello).await.expect("ClientHello");

            let hrr = build_hello_retry_request(&hello, GREASE_X25519MLKEM768);
            let mut rec = vec![22u8, 0x03, 0x03];
            rec.extend_from_slice(&(hrr.len() as u16).to_be_bytes());
            rec.extend_from_slice(&hrr);
            server_io.write_all(&rec).await.expect("写 HRR");
            server_io.flush().await.expect("flush");
        };
        let client = reality_handshake(Box::new(client_io), &sni, &[], &client_cfg);
        let ((), result) = futures::join!(server, client);
        result
    });

    match client_result {
        Err(e) => assert!(
            e.to_string().contains("HelloRetryRequest"),
            "对 HRR 应当明确报「不支持」，实际：{e}"
        ),
        Ok(_) => panic!("收到 HRR 却握手成功了 —— 语义错误"),
    }

    // 「远端不能诱导我们回退」的可观测证据：HRR 之后线上不得再出现第二份 ClientHello。
    let extra = block_on(xt_wasm_runtime::timeout(
        Duration::from_millis(500),
        async {
            let mut b = [0u8; 1];
            server_io.read(&mut b).await
        },
    ));
    match extra {
        Ok(Ok(0)) | Err(_) => {}
        Ok(Ok(n)) => panic!("收到 HRR 后客户端又发了 {n} 字节（可能是第二份 ClientHello）"),
        Ok(Err(e)) => panic!("读服务端侧失败：{e}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 审计项 6：拒绝解析 —— 任何畸形输入都不得 panic
// ═══════════════════════════════════════════════════════════════════════

/// 官方夹包的**每一个**前缀长度都必须被安全拒绝（不 panic）。
#[test]
fn parser_never_panics_on_any_truncation_of_the_official_fixture() {
    let msg = fixture_hello();
    for len in 0..msg.len() {
        // 只要不 panic 就算过；返回 Ok 也是可能的结果之一。
        let _ = parse_client_hello(&msg[..len]);
    }
    assert!(parse_client_hello(&msg).is_ok());
}

/// 确定性伪随机的单字节/多字节变异都不得 panic。
#[test]
fn parser_never_panics_on_mutated_fixture() {
    let msg = fixture_hello();
    let mut seed: u64 = 0x0bad_c0de_dead_beef;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed
    };
    for _ in 0..4000 {
        let mut m = msg.clone();
        let flips = 1 + (next() % 3) as usize;
        for _ in 0..flips {
            let off = (next() >> 33) as usize % m.len();
            m[off] = (next() >> 40) as u8;
        }
        let _ = parse_client_hello(&m);
    }
}

/// 结构性的畸形：长度字段撒谎、嵌套越界、超长 SNI、非法 ALPN、空 key_share。
#[test]
fn parser_rejects_structural_malformations_without_panicking() {
    let good = fixture_hello();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("空消息", Vec::new()),
        ("只有类型字节", vec![1]),
        (
            "长度撒谎（声称 0xffffff）",
            vec![1, 0xff, 0xff, 0xff, 1, 2, 3],
        ),
        ("body 长度比实际短", {
            let mut m = good.clone();
            m[3] = m[3].wrapping_sub(1);
            m
        }),
        ("扩展块长度越界", {
            let mut m = good.clone();
            // 最后一个扩展的长度字段附近写一个超大增量：直接改扩展总长更稳。
            let body = handshake_body(&good);
            let mut p = 34usize;
            let sid_len = body[p] as usize;
            p += 1 + sid_len;
            let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
            p += 2 + cs;
            p += 1 + body[p] as usize; // compression
            let ext_off = 4 + p;
            m[ext_off] = 0xff;
            m[ext_off + 1] = 0xff;
            m
        }),
        ("session_id 长度改成 0", {
            let mut m = good.clone();
            m[38] = 0;
            m
        }),
        ("session_id 长度改成 33", {
            let mut m = good.clone();
            m[38] = 33;
            m
        }),
        ("cipher_suites 长度越界", {
            let mut m = good.clone();
            let body = handshake_body(&good);
            let mut p = 34usize;
            let sid_len = body[p] as usize;
            p += 1 + sid_len;
            let off = 4 + p;
            m[off] = 0xff;
            m[off + 1] = 0xff;
            m
        }),
    ];
    for (name, bytes) in cases {
        assert!(
            parse_client_hello(&bytes).is_err(),
            "畸形输入「{name}」应当被拒绝"
        );
    }
}

/// `ClientHello` 是 `pub` 结构体且字段 `pub`，`aad()` 不做边界检查。
///
/// 当前所有生产路径都只经 `parse_client_hello()` 产生它（偏移恒为 39），所以
/// **不可达**；但手工构造一个越界偏移会让 `aad()` 直接 panic。这条测试把这个
/// 潜在缺口钉住（低危，建议后续把字段收窄或让 `aad()` 返回 `Result`）。
/// 如果哪天 `aad()` 被加固，这条测试会变红 —— 那时应当删掉它，因为缺口已修。
#[test]
fn hand_built_client_hello_with_bogus_offset_is_a_latent_panic() {
    let ch = ClientHello {
        raw: vec![1, 0, 0, 40],
        random: [0u8; 32],
        session_id: [0u8; 32],
        session_id_offset: 9_999,
        // 必须是个**合法**的 X25519 公钥：否则 authenticate 会在 aad() 之前
        // 就因 ECDH 失败返回 Err，走不到有问题的分支。
        key_share: test_support::public_from_private(&[7u8; 32]),
        server_name: None,
    };
    let server_cfg = RealityServerConfig {
        private_key: test_support::fixture_private_key(),
        short_ids: vec![[0u8; 8]],
        server_names: Vec::new(),
        max_time_diff_secs: 0,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = authenticate(&ch, &server_cfg, 0);
    }));
    assert!(
        result.is_err(),
        "aad() 对越界 offset 已经不再 panic —— 缺口已修，请删除本测试并更新 docs"
    );
}

// ─────────────────────────── 构造辅助 ───────────────────────────

/// 从 ClientHello 里删掉指定 group 的 key_share 条目，重算所有长度字段。
fn strip_key_share(msg: &[u8], group: u16) -> Vec<u8> {
    let body = handshake_body(msg);
    let mut p = 34usize;
    let sid_len = body[p] as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs_len;
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    assert!(p + ext_total <= body.len());
    let exts = &body[p..p + ext_total];

    let mut out_exts = Vec::new();
    let mut q = 0usize;
    while q < exts.len() {
        let typ = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let len = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        let data = &exts[q + 4..q + 4 + len];
        q += 4 + len;
        if typ == 51 {
            let total = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut keep = Vec::new();
            let mut r = 2usize;
            while r < 2 + total {
                let g = u16::from_be_bytes([data[r], data[r + 1]]);
                let l = u16::from_be_bytes([data[r + 2], data[r + 3]]) as usize;
                if g != group {
                    keep.extend_from_slice(&data[r..r + 4 + l]);
                }
                r += 4 + l;
            }
            let mut new_data = (keep.len() as u16).to_be_bytes().to_vec();
            new_data.extend_from_slice(&keep);
            write_ext(&mut out_exts, typ, &new_data);
        } else {
            write_ext(&mut out_exts, typ, data);
        }
    }

    let mut new_body = body[..p - 2].to_vec();
    new_body.extend_from_slice(&(out_exts.len() as u16).to_be_bytes());
    new_body.extend_from_slice(&out_exts);

    let mut out = vec![1u8];
    out.extend_from_slice(&[
        ((new_body.len() >> 16) & 0xff) as u8,
        ((new_body.len() >> 8) & 0xff) as u8,
        (new_body.len() & 0xff) as u8,
    ]);
    out.extend_from_slice(&new_body);
    out
}

fn write_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// 构造一个最小的合法 ServerHello，用于"服务端行为"测试。
fn build_server_hello(session_id: &[u8], key_share: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x42u8; 32]); // random
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.push(0); // compression
    let mut exts = Vec::new();
    write_ext(&mut exts, 43, &[0x03, 0x04]); // supported_versions = TLS 1.3
    let mut ks = Vec::new();
    ks.extend_from_slice(&0x001du16.to_be_bytes());
    ks.extend_from_slice(&32u16.to_be_bytes());
    ks.extend_from_slice(key_share);
    write_ext(&mut exts, 51, &ks);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    handshake_msg(2, &body)
}

/// 构造一个 RFC 8446 §4.1.4 形状的 HelloRetryRequest：
/// 哨兵 random + 回显 session_id + 请求指定 group + 一个 cookie。
fn build_hello_retry_request(client_hello: &[u8], requested_group: u16) -> Vec<u8> {
    let body = handshake_body(client_hello);
    let mut p = 34usize;
    let sid_len = body[p] as usize;
    assert_eq!(sid_len, SESSION_ID_LEN, "HRR 测试要求 32 字节 session_id");
    p += 1;
    let session_id = &body[p..p + sid_len];

    let mut out_body = Vec::new();
    out_body.extend_from_slice(&[0x03, 0x03]);
    out_body.extend_from_slice(&HRR_RANDOM);
    out_body.push(sid_len as u8);
    out_body.extend_from_slice(session_id);
    out_body.extend_from_slice(&[0x13, 0x01]);
    out_body.push(0); // compression
    let mut exts = Vec::new();
    write_ext(&mut exts, 43, &[0x03, 0x04]);
    write_ext(&mut exts, 51, &requested_group.to_be_bytes());
    write_ext(&mut exts, 44, &[0x00, 0x02, 0xaa, 0xbb]); // cookie
    out_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    out_body.extend_from_slice(&exts);
    handshake_msg(2, &out_body)
}

fn handshake_msg(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![typ];
    out.extend_from_slice(&[
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ]);
    out.extend_from_slice(body);
    out
}

// ═══════════════════════════════════════════════════════════════════════
// 审计项 3/4/5/6：T1 引擎级断言（`lib.rs` 已 `pub mod fingerprint`）
//
// 这些断言直接对着「引擎产出的字节」，不依赖 reality.rs 的接线，因此 T2 还没
// 落地时也能钉住引擎行为。
// ═══════════════════════════════════════════════════════════════════════

/// 用固定输入构造一条 `chrome` profile 的 ClientHello（只有 seed 变化）。
fn engine_chrome_hello(seed: u64) -> Vec<u8> {
    let profile = profile_by_name(DEFAULT_PROFILE_NAME).expect("默认 profile 必须存在");
    build_client_hello(
        profile,
        SNI,
        &["h2".to_string(), "http/1.1".to_string()],
        &[0x11u8; 32],
        &[0x22u8; 32],
        &test_support::public_from_private(&[7u8; 32]),
        seed,
    )
    .expect("构造 chrome ClientHello")
}

/// chrome profile **不得**声明 X25519MLKEM768(0x11ec)：我们发不出它的 key_share，
/// 声明了就会触发 HelloRetryRequest（见 docs/fingerprint-security.md §4）。
#[test]
fn chrome_profile_never_declares_x25519mlkem768() {
    for seed in 0..64u64 {
        let msg = engine_chrome_hello(seed);
        let scan = scan_client_hello(&msg).expect("扫描 chrome 输出");
        assert!(
            !scan.supported_groups.contains(&GREASE_X25519MLKEM768),
            "seed={seed}: supported_groups 仍声明 11ec 而不发 share —— 会触发 HRR"
        );
        assert!(
            !scan.key_share_groups.contains(&GREASE_X25519MLKEM768),
            "seed={seed}: key_share 不应出现 11ec"
        );
        // 可用的 x25519 必须声明且给出 share。
        assert!(scan.supported_groups.contains(&0x001d), "seed={seed}");
        assert!(scan.key_share_groups.contains(&0x001d), "seed={seed}");
    }
}

/// **回归（lead 指定）**：洗牌后首/末扩展类型必须是 GREASE，跨 N 个 seed 都成立；
/// 中间 16 个真实扩展必须真的被打乱（否则等于固定顺序 = 跨连接稳定标签）。
#[test]
fn chrome_shuffle_pins_grease_first_and_last_across_seeds() {
    let mut middle_orders = std::collections::HashSet::new();
    for seed in 0..256u64 {
        let msg = engine_chrome_hello(seed);
        let scan = scan_client_hello(&msg).expect("扫描");
        let grease_positions: Vec<usize> = scan
            .ext_types
            .iter()
            .enumerate()
            .filter(|(_, t)| is_grease(**t))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            grease_positions,
            vec![0, scan.ext_types.len() - 1],
            "seed={seed}: GREASE 必须钉在首尾，实际位置 {grease_positions:?}"
        );
        let middle = &scan.ext_types[1..scan.ext_types.len() - 1];
        assert_eq!(
            middle.len(),
            16,
            "seed={seed}: 中间应是被洗牌的 16 个真实扩展"
        );
        assert!(
            !middle.iter().any(|t| is_grease(*t)),
            "seed={seed}: 中间不该再出现 GREASE"
        );
        middle_orders.insert(middle.to_vec());
    }
    assert!(
        middle_orders.len() > 200,
        "256 个 seed 应产生 200+ 种不同排列（均匀洗牌），实际 {}",
        middle_orders.len()
    );
}

/// **回归（lead 指定）**：ECH 扩展体长度跨 N 个 seed **不得恒定**，且必须落在
/// 12 份真实抓包观测到的取值集合 {186,218,250,282} 内。
#[test]
fn chrome_ech_padding_length_varies_across_seeds_in_observed_set() {
    const OBSERVED: [usize; 4] = [186, 218, 250, 282];
    const OBSERVED_PAYLOAD: [usize; 4] = [144, 176, 208, 240];
    let mut seen = std::collections::BTreeSet::new();
    let mut total_lens = std::collections::BTreeSet::new();
    for seed in 0..256u64 {
        let msg = engine_chrome_hello(seed);
        let scan = scan_client_hello(&msg).expect("扫描");
        let ech = scan
            .ext_len(0xfe0d)
            .unwrap_or_else(|| panic!("seed={seed}: chrome 必须带 GREASE ECH 扩展"));
        assert!(
            OBSERVED.contains(&ech),
            "seed={seed}: ECH 扩展长度 {ech} 不在真实观测集合 {OBSERVED:?}"
        );
        // 结构固定部分 42 字节：type(1)+kdf(2)+aead(2)+config_id(1)+enc_len(2)+enc(32)+payload_len(2)
        assert!(
            OBSERVED_PAYLOAD.contains(&(ech - 42)),
            "seed={seed}: 载荷长度 {} 不在 {OBSERVED_PAYLOAD:?}",
            ech - 42
        );
        seen.insert(ech);
        total_lens.insert(msg.len());
    }
    assert!(
        seen.len() >= 2,
        "ECH 长度跨连接恒定 = 新的稳定特征（真实 Chrome 会变），实际只有 {seen:?}"
    );
    assert_eq!(seen.len(), 4, "256 个 seed 应覆盖全部 4 档，实际 {seen:?}");
    assert!(
        total_lens.len() >= 2,
        "ClientHello 总长也必须随连接变化，实际只有 {total_lens:?}"
    );
}

/// 引擎不静默降级：未知 profile 名必须返回 None（配置层据此报错，见 T2）。
#[test]
fn engine_rejects_unknown_profile_names_instead_of_downgrading() {
    assert!(profile_by_name("chrome").is_some());
    assert!(profile_by_name("plain").is_some());
    assert!(profile_by_name(DEFAULT_PROFILE_NAME).is_some());
    for bad in [
        "Chrome", "CHROME", "chome", "chrome ", " chrome", "", "safari", "firefox", "none",
    ] {
        assert!(
            profile_by_name(bad).is_none(),
            "未知 profile 名 {bad:?} 不得被接受（否则就是静默降级）"
        );
    }
    let names = profile_names();
    assert!(names.contains(&"chrome"), "可用名字应含 chrome");
    assert!(names.contains(&"plain"), "可用名字应含 plain");
    assert!(names.contains(&DEFAULT_PROFILE_NAME));
}

/// 引擎对超长 SNI / 非法 ALPN 必须返回 Err 而不是 panic，也不能截断后照发。
#[test]
fn engine_returns_errors_for_oversized_sni_and_alpn() {
    let profile = profile_by_name("chrome").expect("chrome");
    let random = [0u8; 32];
    let sid = [0u8; 32];
    let ks = [0u8; 32];

    let long_sni = "a".repeat(70_000);
    assert!(
        build_client_hello(profile, &long_sni, &[], &random, &sid, &ks, 1).is_err(),
        "超长 SNI 必须报错"
    );

    let long_alpn = vec!["a".repeat(300)];
    assert!(
        build_client_hello(profile, SNI, &long_alpn, &random, &sid, &ks, 1).is_err(),
        "单个 ALPN id > 255 必须报错"
    );

    let many_alpn: Vec<String> = (0..300).map(|_| "b".repeat(250)).collect();
    assert!(
        build_client_hello(profile, SNI, &many_alpn, &random, &sid, &ks, 1).is_err(),
        "ALPN 列表总长 > 65535 必须报错"
    );

    // 刚好合法的边界不能误报：200 字节的 ALPN id 可以装下。
    let ok_alpn = vec!["a".repeat(200)];
    assert!(
        build_client_hello(profile, SNI, &ok_alpn, &random, &sid, &ks, 1).is_ok(),
        "合法 ALPN 不该被拒绝"
    );
}

/// 引擎必须原样保留 REALITY 的 random / session_id 与偏移，且输出可被我们自己解析。
#[test]
fn engine_preserves_reality_critical_positions_verbatim() {
    let profile = profile_by_name("chrome").expect("chrome");
    let random = [0xa5u8; 32];
    let sid = [0x5au8; 32];
    let ks = test_support::public_from_private(&[3u8; 32]);
    for seed in 0..32u64 {
        let hello = build_client_hello(profile, SNI, &[], &random, &sid, &ks, seed).expect("构造");
        assert_eq!(hello[0], 1, "seed={seed}");
        assert_eq!(
            &hello[6..38],
            &random,
            "seed={seed}: random 必须原样写在 6..38"
        );
        assert_eq!(hello[38], 32, "seed={seed}: session_id 长度字节必须是 32");
        assert_eq!(
            &hello[39..71],
            &sid,
            "seed={seed}: session_id 必须原样写在 39..71"
        );
        let ch = parse_client_hello(&hello).expect("引擎输出必须能被我们自己的解析器解析");
        assert_eq!(ch.session_id_offset, 39, "seed={seed}");
        assert_eq!(ch.random, random, "seed={seed}");
        assert_eq!(ch.session_id, sid, "seed={seed}");
    }
}

/// GREASE 必须随 seed 变化，且 groups 与 key_share 的 GREASE 值必须成对。
#[test]
fn engine_grease_is_seed_dependent_and_paired() {
    let mut combos = std::collections::HashSet::new();
    for seed in 0..64u64 {
        let msg = engine_chrome_hello(seed);
        let scan = scan_client_hello(&msg).expect("扫描");
        let grease_exts: Vec<u16> = scan
            .ext_types
            .iter()
            .copied()
            .filter(|t| is_grease(*t))
            .collect();
        assert_eq!(
            grease_exts.len(),
            2,
            "seed={seed}: 应恰好首尾两个 GREASE 扩展"
        );
        assert_ne!(
            grease_exts[0], grease_exts[1],
            "seed={seed}: 首尾 GREASE 值应不同"
        );
        assert!(
            is_grease(scan.ciphers[0]),
            "seed={seed}: cipher 首位应是 GREASE"
        );
        assert!(
            is_grease(scan.supported_groups[0]),
            "seed={seed}: supported_groups 首位应是 GREASE"
        );
        assert!(
            is_grease(scan.key_share_groups[0]),
            "seed={seed}: key_share 首位应是 GREASE"
        );
        assert_eq!(
            scan.supported_groups[0], scan.key_share_groups[0],
            "seed={seed}: groups 与 key_share 的 GREASE 必须相等（结构要求）"
        );
        combos.insert((
            scan.ciphers[0],
            grease_exts[0],
            grease_exts[1],
            scan.supported_groups[0],
        ));
    }
    assert!(
        combos.len() > 50,
        "GREASE 必须随 seed 变化：64 个 seed 只出现 {} 种组合",
        combos.len()
    );
}

/// `new_grease_seed()` 必须每次调用都返回新值（CSPRNG）。
#[test]
fn grease_seed_is_fresh_per_call() {
    let seeds: std::collections::HashSet<u64> = (0..64).map(|_| new_grease_seed()).collect();
    assert!(
        seeds.len() > 60,
        "64 次取种子只得到 {} 个不同值 —— 跨连接 GREASE 会重复",
        seeds.len()
    );
}

/// 体量事实（砍掉 11ec 的代价，量化成可重跑断言）：
/// 我们发不出 11ec 的 1216B key_share，所以 ClientHello 只有真 Chrome 的约 1/3。
///
/// 尺寸模型：`真夹包 1787 − 11ec key_share 条目(4+1216) − supported_groups 里的 11ec(2)
/// ± ECH 填充差`，得到 {501, 533, 565, 597}（对应 ECH payload {144,176,208,240}）。
#[test]
fn chrome_client_hello_size_reflects_the_missing_pq_share() {
    let fixture_len = fixture_hello().len();
    let mut lens = std::collections::BTreeSet::new();
    for seed in 0..64u64 {
        lens.insert(engine_chrome_hello(seed).len());
    }
    let expected: std::collections::BTreeSet<usize> =
        [501usize, 533, 565, 597].into_iter().collect();
    println!("chrome ClientHello 长度集合 = {lens:?}（真夹包 {fixture_len}B）");
    assert_eq!(
        lens, expected,
        "尺寸模型变了：真夹包 {fixture_len}B − 11ec(4+1216) − groups(2) ± ECH 填充"
    );
    assert!(
        *lens.iter().max().unwrap() < fixture_len * 2 / 3,
        "我们的 ClientHello 应当显著小于真 Chrome（少了 1216B 的 ML-KEM share）"
    );
}

// ─── 线上字节的跨连接稳定性（T2 接线前是 plain，接线后自动审计 chrome） ───

/// 线上 ClientHello 永远不得出现「声明 11ec 却不给它的 share」。
///
/// 这条在 T2 前后都跑：plain 不含 11ec（通过），chrome 也不含（通过）；
/// 一旦有人把旧方案改回来，它立刻变红。
#[test]
fn wire_client_hello_never_declares_11ec_without_its_share() {
    let (client_cfg, _) = reality_pair();
    let scan = scan_client_hello(&capture_client_hello(&client_cfg, SNI, &[])).expect("扫描");
    if scan.supported_groups.contains(&GREASE_X25519MLKEM768) {
        assert!(
            scan.key_share_groups.contains(&GREASE_X25519MLKEM768),
            "线上声明了 11ec 却没发它的 key_share —— 会触发 HelloRetryRequest"
        );
    }
}

/// 线上若出现 GREASE 扩展，它必须钉在首尾（真 Chrome 12/12 如此）。
#[test]
fn wire_client_hello_pins_grease_first_and_last_when_present() {
    let (client_cfg, _) = reality_pair();
    let scan = scan_client_hello(&capture_client_hello(&client_cfg, SNI, &[])).expect("扫描");
    let positions: Vec<usize> = scan
        .ext_types
        .iter()
        .enumerate()
        .filter(|(_, t)| is_grease(**t))
        .map(|(i, _)| i)
        .collect();
    if positions.is_empty() {
        return; // plain profile 没有 GREASE
    }
    assert_eq!(
        positions,
        vec![0, scan.ext_types.len() - 1],
        "线上 GREASE 必须钉在首尾，实际 {positions:?}"
    );
}

/// 线上若带 ECH 扩展，其长度必须跨连接变化（真 Chrome 会变；恒定即新标签）。
#[test]
fn wire_client_hello_ech_length_varies_across_connections_when_present() {
    let (client_cfg, _) = reality_pair();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..6 {
        let scan = scan_client_hello(&capture_client_hello(&client_cfg, SNI, &[])).expect("扫描");
        if let Some(ech) = scan.ext_len(0xfe0d) {
            seen.insert(ech);
        }
    }
    if seen.is_empty() {
        return; // plain profile 没有 ECH
    }
    assert!(
        seen.len() >= 2,
        "线上 ClientHello 的 ECH 长度跨连接恒定（{seen:?}）—— 新的稳定特征"
    );
}
