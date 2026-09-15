//! REALITY **服务端**（入站）—— 阶段 1：ClientHello 解析 + 认证解密 + 证书伪造。
//!
//! # 这个方向在做什么
//!
//! 客户端是「明文 → REALITY」（封装）；这里是「REALITY → 明文」（解封装）：
//! 接住连接、解开握手、验证对方确实持有共享密钥，然后把隧道里的明文交给上层。
//!
//! # 认证是怎么成立的（与 `reality.rs` 的客户端严格对称）
//!
//! ```text
//! 客户端                                           服务端
//! ─────────────────────────────────────────────   ─────────────────────────────────────
//! ecdhe_priv = ClientHello 的 key_share 私钥
//! AuthKey = ECDH(ecdhe_priv, server_pubkey)   ──▶  AuthKey = ECDH(server_privkey, 客户端 key_share)
//! AuthKey = HKDF-SHA256(AuthKey,
//!             salt = ClientHello.random[:20],
//!             info = "REALITY")
//! session_id = AES-256-GCM.Seal(              ──▶  plaintext = AES-256-GCM.Open(
//!     nonce     = random[20:32],                       nonce     = random[20:32],
//!     plaintext = [ver(3) 0 ts(4) shortId(8)],         ct        = session_id,
//!     aad       = session_id 置零的 ClientHello)        aad       = 同上)
//!                                                  → 拿到 ver / 时间戳 / shortId 并校验
//! ```
//!
//! **AAD 的细节是易错点**：两侧都必须用「session_id 字段被置零」的那份 ClientHello，
//! 而不是收到的原始字节。客户端在校验时也是这么做的（见 `reality.rs` 的对应单测）。
//!
//! # 为什么服务端要伪造证书
//!
//! 客户端不校验 CA 链，它校验的是：
//!
//! ```text
//! HMAC-SHA512(AuthKey, 证书里的 ed25519 公钥) == 证书的「签名」字段
//! ```
//!
//! 所以服务端必须**每连接现生成一张临时 ed25519 证书，并把签名字段换成这个 HMAC**。
//! 这不是偷懒，而是 REALITY 的核心：只有真正持有服务端私钥的一方才算得出这个 HMAC，
//! 而中间人即使有合法 CA 证书也过不了这一关。
//!
//! # 阶段说明
//!
//! 本文件目前只做**认证 + 证书**。完整服务端还需要 TLS 1.3 服务端握手、
//! VLESS 解码与 `dest` 回退，见 README 的「REALITY 入站」一节。

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use ed25519_dalek::{Signer, SigningKey};
use hmac::Mac;
use rand::RngCore;
use tokio::io::AsyncWriteExt;

use crate::reality::{
    clamp_x25519_private, finished_verify_data, hkdf_sha256, read_record, wrap_plain_record,
    x25519, x25519_public_from_private, ApplicationKeys, CipherSuite, HandshakeKeys, HmacSha512,
    RealityTlsStream, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO,
    HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO, TLS_AES_128_GCM_SHA256,
    TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};
use crate::{Result, Stream, TransportError};

/// `supported_groups` / `key_share` 里的 X25519。
const GROUP_X25519: u16 = 0x001d;

/// session_id 字段固定 32 字节（REALITY 强制）。
const SESSION_ID_LEN: usize = 32;

/// 扩展类型。
const EXT_SERVER_NAME: u16 = 0;
const EXT_KEY_SHARE: u16 = 51;

/// 服务端配置。
#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    /// 服务端 X25519 私钥（与 `xray x25519` 的 PrivateKey 对应）。
    pub private_key: [u8; 32],
    /// 允许的 shortId 列表。空列表表示不接受任何客户端（安全默认）。
    pub short_ids: Vec<[u8; 8]>,
    /// 允许的 SNI。客户端发的 SNI 必须在这个列表里。
    pub server_names: Vec<String>,
    /// 允许的客户端时钟偏差（秒）。0 表示不校验。
    pub max_time_diff_secs: u64,
}

/// 解析出来的 ClientHello 关键字段。
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// **完整握手消息**（含 4 字节头）。AAD 要用它，不要用 body。
    pub raw: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    /// session_id 在 `raw` 中的偏移。按 RFC 恒为 39，这里算出来而不是写死。
    pub session_id_offset: usize,
    /// 客户端 key_share 里的 X25519 公钥。
    pub key_share: [u8; 32],
    pub server_name: Option<String>,
}

impl ClientHello {
    /// 用于 AES-GCM 的附加数据：**session_id 字段置零**的完整握手消息。
    ///
    /// 客户端封 session_id 时的 AAD 就是这个状态（那时字段还是全零）。
    /// 用收到的原始字节会解密失败——这是最容易踩的一个坑。
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = self.raw.clone();
        for b in &mut aad[self.session_id_offset..self.session_id_offset + SESSION_ID_LEN] {
            *b = 0;
        }
        aad
    }
}

/// 逐字节游标：所有读取都做边界检查，畸形输入只会返回错误，不会 panic。
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| malformed("长度溢出"))?;
        if end > self.buf.len() {
            return Err(malformed("字段超出 ClientHello 长度"));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

fn malformed(what: &str) -> TransportError {
    TransportError::Tls(format!("Reality server: ClientHello 畸形 —— {what}"))
}

/// 解析 ClientHello 握手消息。
///
/// 输入是**握手消息**（`type || len24 || body`），不是 TLS record。
pub fn parse_client_hello(msg: &[u8]) -> Result<ClientHello> {
    // 先原样留一份：AAD 需要完整消息（含头）。
    let raw = msg.to_vec();

    let mut c = Cursor::new(msg);
    if c.u8()? != HS_CLIENT_HELLO {
        return Err(malformed("不是 ClientHello"));
    }
    let body_len = {
        let b = c.take(3)?;
        ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
    };
    if body_len != c.remaining() {
        return Err(malformed("握手体长度与实际不符"));
    }

    let _legacy_version = c.u16()?;
    let random: [u8; 32] = c.take(32)?.try_into().expect("长度已校验");

    let sid_len = c.u8()? as usize;
    let session_id_offset = c.pos;
    if sid_len != SESSION_ID_LEN {
        return Err(malformed("session_id 长度不是 32（REALITY 要求固定 32）"));
    }
    let session_id: [u8; 32] = c.take(SESSION_ID_LEN)?.try_into().expect("长度已校验");

    // cipher_suites
    let cs_len = c.u16()? as usize;
    c.take(cs_len)?;
    // compression_methods
    let comp_len = c.u8()? as usize;
    c.take(comp_len)?;

    // extensions
    let exts_len = c.u16()? as usize;
    let exts = c.take(exts_len)?;

    let mut key_share = None;
    let mut server_name = None;
    let mut ec = Cursor::new(exts);
    while ec.remaining() > 0 {
        let ext_type = ec.u16()?;
        let ext_len = ec.u16()? as usize;
        let data = ec.take(ext_len)?;

        match ext_type {
            EXT_KEY_SHARE => key_share = Some(parse_key_share(data)?),
            EXT_SERVER_NAME => server_name = parse_server_name(data)?,
            _ => {}
        }
    }

    Ok(ClientHello {
        raw,
        random,
        session_id,
        session_id_offset,
        key_share: key_share.ok_or_else(|| malformed("没有 key_share 扩展"))?,
        server_name,
    })
}

/// `key_share` 扩展里取 X25519 那一条。
///
/// 结构：`client_shares_len(2)` 然后若干 `group(2) len(2) data`。
fn parse_key_share(data: &[u8]) -> Result<[u8; 32]> {
    let mut c = Cursor::new(data);
    let _total = c.u16()?;
    while c.remaining() > 0 {
        let group = c.u16()?;
        let len = c.u16()? as usize;
        let share = c.take(len)?;
        if group == GROUP_X25519 {
            if share.len() != 32 {
                return Err(malformed("X25519 key_share 不是 32 字节"));
            }
            return Ok(share.try_into().expect("长度已校验"));
        }
    }
    Err(malformed("key_share 里没有 X25519"))
}

/// `server_name` 扩展里取第一个 host_name。
fn parse_server_name(data: &[u8]) -> Result<Option<String>> {
    let mut c = Cursor::new(data);
    let _list_len = c.u16()?;
    while c.remaining() > 0 {
        let name_type = c.u8()?;
        let len = c.u16()? as usize;
        let name = c.take(len)?;
        if name_type == 0 {
            return Ok(Some(String::from_utf8_lossy(name).into_owned()));
        }
    }
    Ok(None)
}

/// 认证通过后得到的信息。
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// 服务端侧算出的 AuthKey（与客户端一致）。后续伪造证书要用它。
    pub auth_key: [u8; 32],
    pub client_version: [u8; 3],
    /// 客户端上报的 unix 时间戳（秒）。
    pub client_time: u32,
    pub short_id: [u8; 8],
}

/// 校验 ClientHello 里的 REALITY 认证载荷。
///
/// `now_unix` 由调用方传入，便于测试固定时间。
pub fn authenticate(
    ch: &ClientHello,
    cfg: &RealityServerConfig,
    now_unix: u64,
) -> Result<Authenticated> {
    // ── 1) ECDH + HKDF，得到与客户端一致的 AuthKey ──
    let shared = x25519(&cfg.private_key, &ch.key_share)?;
    let auth_key_vec = hkdf_sha256(&shared, &ch.random[..20], b"REALITY", 32);
    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&auth_key_vec);

    // ── 2) AES-256-GCM 解开 session_id ──
    let cipher = Aes256Gcm::new_from_slice(&auth_key)
        .map_err(|e| TransportError::Tls(format!("Reality server: AES-GCM key: {e}")))?;
    let (ct, tag) = ch.session_id.split_at(16);
    let mut plain = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&ch.random[20..32]),
            &ch.aad(),
            &mut plain,
            Tag::from_slice(tag),
        )
        // 解密失败就是「不持有共享密钥」——这正是抗主动探测的判据。
        .map_err(|_| {
            TransportError::Tls("Reality server: session_id 解密失败（非授权客户端）".into())
        })?;

    let client_version = [plain[0], plain[1], plain[2]];
    let client_time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plain[8..16]);

    // ── 3) 校验 shortId / 时钟窗口 / SNI ──
    if !cfg.short_ids.contains(&short_id) {
        return Err(TransportError::Tls(
            "Reality server: shortId 不在允许列表".into(),
        ));
    }
    if cfg.max_time_diff_secs > 0 {
        let diff = (now_unix as i64 - client_time as i64).unsigned_abs();
        if diff > cfg.max_time_diff_secs {
            return Err(TransportError::Tls(format!(
                "Reality server: 客户端时钟偏差 {diff}s 超出允许的 {}s",
                cfg.max_time_diff_secs
            )));
        }
    }
    if !cfg.server_names.is_empty() {
        let sni = ch.server_name.as_deref().unwrap_or("");
        if !cfg.server_names.iter().any(|n| n == sni) {
            return Err(TransportError::Tls(format!(
                "Reality server: SNI {sni:?} 不在允许列表"
            )));
        }
    }

    Ok(Authenticated {
        auth_key,
        client_version,
        client_time,
        short_id,
    })
}

/// 生成「签名字段被 HMAC 冒充」的临时 ed25519 证书。
///
/// 客户端只做一件事：`HMAC-SHA512(AuthKey, 证书公钥) == 证书签名字段`。
/// 所以这里用 HMAC 填 `signatureValue`，而不是真的去签名。
///
/// # 为什么必须是一张**结构完整**的 X.509
///
/// 第一版为了省事，issuer / validity / signatureAlgorithm 都写成空 SEQUENCE，
/// 结果：**我们自己的客户端能过，官方客户端直接回 `bad_certificate` 告警**。
/// 原因是我们客户端的解析器只按位置取 SPKI，而官方客户端用的是 Go 真正的
/// `x509.ParseCertificate` —— 空 Name、空 Validity、空 AlgorithmIdentifier
/// 都不是合法 DER，它解析失败就退回 CA 链校验，必然失败。
///
/// 教训：**能被自己解析 ≠ 是合法的编码**。所以这里老老实实拼一份完整的证书。
pub fn forge_certificate(auth_key: &[u8; 32], ed25519_pubkey: &[u8; 32]) -> Vec<u8> {
    let signature = {
        let mut mac =
            <HmacSha512 as Mac>::new_from_slice(auth_key).expect("HMAC-SHA512 接受任意长度密钥");
        mac.update(ed25519_pubkey);
        mac.finalize().into_bytes().to_vec()
    };

    // AlgorithmIdentifier：Ed25519（OID 1.3.101.112，无参数）
    let alg_id = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));

    // Name：单个 RDN，CN=<名字>。issuer 与 subject 用同一个。
    let cn = der(0x0c, b"reality"); // UTF8String
    let atv = der(0x30, &[der(0x06, &[0x55, 0x04, 0x03]), cn].concat()); // 2.5.4.3 = CN
    let name = der(0x30, &der(0x31, &atv)); // SEQUENCE OF SET

    // Validity：notBefore / notAfter（UTCTime）。客户端不校验有效期，
    // 但字段本身必须存在且格式合法。
    let validity = der(
        0x30,
        &[der(0x17, b"250101000000Z"), der(0x17, b"350101000000Z")].concat(),
    );

    // SubjectPublicKeyInfo：SEQUENCE { AlgorithmIdentifier, BIT STRING(pubkey) }
    let mut spki_bits = vec![0u8]; // 未使用位数
    spki_bits.extend_from_slice(ed25519_pubkey);
    let mut spki_body = alg_id.clone();
    spki_body.extend_from_slice(&der(0x03, &spki_bits));
    let spki = der(0x30, &spki_body);

    // TBSCertificate 子项顺序有讲究：客户端按 children[base + 5] 取 SPKI，
    // 所以顺序必须与 RFC 5280 一致。见 `aad_zeroes_the_session_id_field` 同族的用例。
    let mut tbs_body = Vec::new();
    tbs_body.extend_from_slice(&der(0xa0, &der(0x02, &[0x02]))); // version = v3
    tbs_body.extend_from_slice(&der(0x02, &[0x01])); // serialNumber
    tbs_body.extend_from_slice(&alg_id); // signature
    tbs_body.extend_from_slice(&name); // issuer
    tbs_body.extend_from_slice(&validity); // validity
    tbs_body.extend_from_slice(&name); // subject
    tbs_body.extend_from_slice(&spki); // subjectPublicKeyInfo
    let tbs = der(0x30, &tbs_body);

    let mut sig_bits = vec![0u8];
    sig_bits.extend_from_slice(&signature);

    let mut cert_body = tbs;
    cert_body.extend_from_slice(&alg_id); // 外层 signatureAlgorithm
    cert_body.extend_from_slice(&der(0x03, &sig_bits));
    der(0x30, &cert_body)
}

/// 最小的 DER 编码：`tag || len || value`。
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .expect("长度非零时必有非零字节");
        let trimmed = &bytes[first..];
        out.push(0x80 | trimmed.len() as u8);
        out.extend_from_slice(trimmed);
    }
    out.extend_from_slice(value);
    out
}

// ───────────────────────── TLS 1.3 服务端握手 ─────────────────────────
//
// TLS 1.3 的握手在服务端这一侧要构造四个消息，且顺序固定：
//   ServerHello（明文） → EncryptedExtensions → Certificate → CertificateVerify → Finished
// 后四个一起放在**一条加密记录**里发出。
//
// 有个与直觉相反的细节值得写下来：**应用密钥两侧都是用「到 server Finished 为止」
// 的 transcript 派生的**（RFC 8446 §7.1），客户端的 Finished 不参与。
// 所以服务端发完自己的 Finished 就可以立刻派生应用密钥，不必等客户端回话。

/// 服务端握手的结果。
pub enum HandshakeOutcome {
    /// 认证通过。后续用 `stream` 收发（已经是解密后的明文）。
    Authenticated {
        stream: RealityTlsStream,
        auth: Authenticated,
    },
    /// 未通过认证。调用方应当把 `buffered` 以及之后读到的所有字节
    /// **原样转发**给 `dest`，让主动探测者看到真实网站。
    Fallback {
        /// 已经从客户端读走、必须补发给 `dest` 的原始字节（含 TLS record 头）。
        buffered: Vec<u8>,
        server_name: Option<String>,
    },
}

/// 完成一次 REALITY 服务端握手。
pub async fn reality_server_handshake(
    mut inner: Box<dyn Stream>,
    cfg: &RealityServerConfig,
) -> Result<HandshakeOutcome> {
    // ── 1) 读第一条记录：ClientHello（明文）──
    let record = read_record(&mut inner).await?.ok_or_else(|| {
        TransportError::Tls("Reality server: 还没读到 ClientHello 连接就断了".into())
    })?;

    // 认证失败时要原样转发，所以先把原始字节留一份（含 5 字节 record 头）。
    let mut buffered = record.header.to_vec();
    buffered.extend_from_slice(&record.payload);

    if record.typ != TLS_RECORD_HANDSHAKE {
        return Ok(HandshakeOutcome::Fallback {
            buffered,
            server_name: None,
        });
    }

    // 解析或认证失败都走回退，而不是报错断开 —— 报错会让探测者一眼看出这不是普通网站。
    let ch = match parse_client_hello(&record.payload) {
        Ok(ch) => ch,
        Err(_) => {
            return Ok(HandshakeOutcome::Fallback {
                buffered,
                server_name: None,
            })
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Tls(format!("Reality server: 系统时钟早于 1970：{e}")))?
        .as_secs();

    let auth = match authenticate(&ch, cfg, now) {
        Ok(a) => a,
        Err(_) => {
            return Ok(HandshakeOutcome::Fallback {
                buffered,
                server_name: ch.server_name.clone(),
            })
        }
    };

    // ── 2) 服务端临时 X25519 密钥 ──
    let mut server_priv = rand::random::<[u8; 32]>();
    clamp_x25519_private(&mut server_priv);
    let server_pub = x25519_public_from_private(&server_priv);
    let shared = x25519(&server_priv, &ch.key_share)?;

    let mut server_random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut server_random);

    // ── 3) ServerHello（明文发出）──
    let server_hello = build_server_hello(&ch.session_id, &server_random, &server_pub);
    inner
        .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &server_hello)?)
        .await?;
    inner.flush().await?;

    // ── 4) 握手密钥 ──
    let cipher = CipherSuite::try_from(TLS_AES_128_GCM_SHA256)?;
    let mut transcript = Vec::with_capacity(4096);
    transcript.extend_from_slice(&ch.raw);
    transcript.extend_from_slice(&server_hello);
    let hs = HandshakeKeys::derive(cipher, &shared, &transcript);
    let mut server_hs = hs.server;
    let mut client_hs = hs.client;

    // ── 5) 伪造证书 + 加密飞行包 ──
    //
    // 每连接现生成一把 ed25519 密钥：证书的「签名域」是 HMAC 而不是真签名，
    // 但 CertificateVerify 必须是一份**真签名**（官方客户端会验它）。
    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let ed_pub = signing_key.verifying_key().to_bytes();
    let cert = forge_certificate(&auth.auth_key, &ed_pub);

    let mut flight = Vec::new();

    let ee = handshake_message(HS_ENCRYPTED_EXTENSIONS, &[0, 0]); // 空扩展列表
    transcript.extend_from_slice(&ee);
    flight.extend_from_slice(&ee);

    let cert_msg = build_certificate(&cert);
    transcript.extend_from_slice(&cert_msg);
    flight.extend_from_slice(&cert_msg);

    let cv = build_certificate_verify(&signing_key, &transcript);
    transcript.extend_from_slice(&cv);
    flight.extend_from_slice(&cv);

    let server_finished = handshake_message(
        HS_FINISHED,
        &finished_verify_data(&hs.server_secret, &transcript),
    );
    transcript.extend_from_slice(&server_finished);
    flight.extend_from_slice(&server_finished);

    inner
        .write_all(&server_hs.seal(TLS_RECORD_HANDSHAKE, &flight)?)
        .await?;
    inner.flush().await?;

    // ── 6) 应用密钥 ──
    // 注意：transcript 停在 server Finished —— 两侧的 c ap / s ap traffic 都是这么派生的。
    let app = ApplicationKeys::derive(cipher, &hs.master_secret, &transcript);

    // ── 7) 读并校验客户端 Finished ──
    let (typ, body) = read_encrypted_handshake(&mut inner, &mut client_hs, HS_FINISHED).await?;
    let expected = finished_verify_data(&hs.client_secret, &transcript);
    if expected != body {
        return Err(TransportError::Tls(
            "Reality server: 客户端 Finished 校验失败".into(),
        ));
    }
    let _ = typ;

    // 服务端读客户端、写客户端 —— 与客户端的读写密钥正好相反
    let stream = RealityTlsStream::from_keys(inner, app.client, app.server);
    Ok(HandshakeOutcome::Authenticated { stream, auth })
}

/// 读一条**加密的**握手消息，跳过中间的 ChangeCipherSpec。
async fn read_encrypted_handshake(
    inner: &mut Box<dyn Stream>,
    key: &mut crate::reality::RecordKey,
    expected: u8,
) -> Result<(u8, Vec<u8>)> {
    for _ in 0..8 {
        let record = read_record(inner).await?.ok_or_else(|| {
            TransportError::Tls("Reality server: 等客户端 Finished 时连接断了".into())
        })?;
        // TLS 1.3 允许中间盒兼容用的明文 CCS，直接跳过
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_APPLICATION_DATA {
            return Err(TransportError::Tls(format!(
                "Reality server: 期望加密记录，收到类型 {}",
                record.typ
            )));
        }
        let (inner_type, plaintext) = key.open(&record.header, &record.payload)?;
        if inner_type == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if plaintext.len() < 4 {
            return Err(TransportError::Tls(format!(
                "Reality server: 解密后的握手消息过短（{} 字节，inner_type={inner_type}，record_type={}，head={:02x?}）",
                plaintext.len(),
                record.typ,
                &plaintext[..plaintext.len().min(16)]
            )));
        }
        let typ = plaintext[0];
        let len = ((plaintext[1] as usize) << 16)
            | ((plaintext[2] as usize) << 8)
            | plaintext[3] as usize;
        if plaintext.len() != 4 + len {
            return Err(TransportError::Tls(
                "Reality server: 握手消息长度与实际不符".into(),
            ));
        }
        if typ != expected {
            return Err(TransportError::Tls(format!(
                "Reality server: 期望握手消息 {expected}，收到 {typ}"
            )));
        }
        return Ok((typ, plaintext[4..].to_vec()));
    }
    Err(TransportError::Tls(
        "Reality server: 连续的 CCS 记录过多".into(),
    ))
}

/// 拼一条握手消息：`type || len24 || body`。
fn handshake_message(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(typ);
    crate::reality::put_u24(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// 构造 ServerHello。
///
/// **`session_id` 必须原样回显客户端的** —— 客户端会拿它跟自己发出去的比对，
/// 不一致就直接拒（REALITY 用这个字段携带认证载荷，回显是它的一部分语义）。
fn build_server_hello(session_id: &[u8; 32], random: &[u8; 32], key_share: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(random);
    body.push(32); // session_id 长度
    body.extend_from_slice(session_id); // 回显
    crate::reality::put_u16(TLS_AES_128_GCM_SHA256, &mut body);
    body.push(0); // compression_method

    let mut exts = Vec::new();
    // supported_versions = TLS 1.3
    push_ext(&mut exts, 43, &[0x03, 0x04]);
    // key_share = X25519
    let mut ks = Vec::with_capacity(36);
    crate::reality::put_u16(GROUP_X25519, &mut ks);
    crate::reality::put_u16(32, &mut ks);
    ks.extend_from_slice(key_share);
    push_ext(&mut exts, 51, &ks);

    crate::reality::put_u16(exts.len() as u16, &mut body);
    body.extend_from_slice(&exts);
    handshake_message(HS_SERVER_HELLO, &body)
}

/// 构造 Certificate 消息（单张证书，无 OCSP、无 SCT）。
fn build_certificate(cert_der: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(cert_der.len() + 8);
    crate::reality::put_u24(cert_der.len(), &mut entry);
    entry.extend_from_slice(cert_der);
    crate::reality::put_u16(0, &mut entry); // 每证书的扩展列表，空

    let mut list = Vec::with_capacity(entry.len() + 3);
    crate::reality::put_u24(entry.len(), &mut list);
    list.extend_from_slice(&entry);

    let mut body = Vec::with_capacity(list.len() + 4);
    body.push(0); // certificate_request_context 长度 = 0
    body.extend_from_slice(&list);
    handshake_message(HS_CERTIFICATE, &body)
}

/// 构造 CertificateVerify。
///
/// 签名内容按 RFC 8446 §4.4.3：
/// `0x20 × 64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash`。
/// **官方客户端会验这个签名**，所以必须用真 ed25519 私钥签，不能糊弄。
fn build_certificate_verify(signing_key: &SigningKey, transcript: &[u8]) -> Vec<u8> {
    let transcript_hash = <sha2::Sha256 as sha2::Digest>::digest(transcript);

    let mut to_sign = Vec::with_capacity(64 + 33 + 1 + 32);
    to_sign.extend_from_slice(&[0x20u8; 64]);
    to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    to_sign.push(0);
    to_sign.extend_from_slice(&transcript_hash);

    let signature = signing_key.sign(&to_sign).to_bytes();

    let mut body = Vec::with_capacity(4 + 64);
    crate::reality::put_u16(0x0807, &mut body); // ed25519
    crate::reality::put_u16(signature.len() as u16, &mut body);
    body.extend_from_slice(&signature);
    handshake_message(HS_CERTIFICATE_VERIFY, &body)
}

/// 追加一个 TLS 扩展：`type(2) len(2) data`。
fn push_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    crate::reality::put_u16(typ, out);
    crate::reality::put_u16(data.len() as u16, out);
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::{
        build_reality_client_hello, clamp_x25519_private, verify_reality_certificate,
        x25519_public_from_private,
    };
    use crate::RealityConfig;

    const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const SNI: &str = "www.cloudflare.com";

    /// 当前 unix 秒。
    ///
    /// 测试里不能用写死的时间：`build_reality_client_hello` 内部取的是
    /// `SystemTime::now()`，写死会让服务端的时钟窗口校验理所当然地拒绝
    /// （这其实是**校验正常工作的证据**，但会让用例本身失效）。
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时钟晚于 1970")
            .as_secs()
    }

    /// 造一对服务端/客户端密钥，并生成一份**真实由客户端构造**的 ClientHello。
    ///
    /// 用真实客户端构造而不是手搓字节：这样测试覆盖的是两侧真正会对上的东西。
    fn make_client_hello(short_id: [u8; 8]) -> (RealityServerConfig, ClientHello, [u8; 32]) {
        // 服务端长期密钥
        let mut server_priv = [0x42u8; 32];
        clamp_x25519_private(&mut server_priv);
        let server_pub = x25519_public_from_private(&server_priv);

        // 客户端临时密钥
        let mut client_priv = [0x17u8; 32];
        clamp_x25519_private(&mut client_priv);
        let client_pub = x25519_public_from_private(&client_priv);

        // 两侧各自算出的共享密钥必须一致
        let shared = x25519(&client_priv, &server_pub).unwrap();
        assert_eq!(shared, x25519(&server_priv, &client_pub).unwrap());

        let reality = RealityConfig {
            public_key: server_pub,
            short_id,
            client_version: [26, 3, 27],
        };
        let random = [0x5au8; 32];
        let (msg, _) =
            build_reality_client_hello(SNI, &[], &random, &client_pub, &shared, &reality)
                .expect("构造 ClientHello");

        let ch = parse_client_hello(&msg).expect("解析 ClientHello");
        let cfg = RealityServerConfig {
            private_key: server_priv,
            short_ids: vec![SHORT_ID],
            server_names: vec![SNI.to_string()],
            max_time_diff_secs: 60,
        };
        (cfg, ch, shared)
    }

    #[test]
    fn parses_real_client_hello() {
        let (_cfg, ch, _) = make_client_hello(SHORT_ID);
        assert_eq!(ch.random, [0x5au8; 32]);
        assert_eq!(ch.server_name.as_deref(), Some(SNI));
        assert_eq!(ch.session_id_offset, 39, "session_id 偏移按 RFC 恒为 39");
        // 客户端的 key_share 应当是个合法的 X25519 公钥（非全零）
        assert_ne!(ch.key_share, [0u8; 32]);
    }

    /// **核心用例**：服务端能从真实客户端构造的 ClientHello 里解出认证载荷。
    #[test]
    fn authenticates_real_client_hello() {
        let now = now();
        let (cfg, ch, _) = make_client_hello(SHORT_ID);
        let auth = authenticate(&ch, &cfg, now).expect("认证应当通过");

        assert_eq!(auth.client_version, [26, 3, 27], "版本应被还原");
        assert_eq!(auth.short_id, SHORT_ID, "shortId 应被还原");
        // 客户端刚生成的，允许跨秒边界
        assert!(
            (auth.client_time as i64 - now as i64).abs() <= 2,
            "时间戳应被还原，实际 {} vs {now}",
            auth.client_time
        );
    }

    /// 私钥不对 → session_id 解不开。这正是「抗主动探测」的判据。
    #[test]
    fn rejects_wrong_server_key() {
        let (mut cfg, ch, _) = make_client_hello(SHORT_ID);
        cfg.private_key = [0x99u8; 32];
        let err = authenticate(&ch, &cfg, now()).unwrap_err();
        assert!(
            err.to_string().contains("解密失败"),
            "应以解密失败拒绝，实际：{err}"
        );
    }

    #[test]
    fn rejects_unknown_short_id() {
        let (cfg, ch, _) = make_client_hello([9, 9, 9, 9, 9, 9, 9, 9]);
        let err = authenticate(&ch, &cfg, now()).unwrap_err();
        assert!(err.to_string().contains("shortId"), "实际：{err}");
    }

    #[test]
    fn rejects_clock_skew_outside_window() {
        let (cfg, ch, _) = make_client_hello(SHORT_ID);
        // 服务端时间比客户端晚 10 分钟，超出 60s 窗口
        let err = authenticate(&ch, &cfg, now() + 600).unwrap_err();
        assert!(err.to_string().contains("时钟偏差"), "实际：{err}");
    }

    #[test]
    fn rejects_disallowed_sni() {
        let (mut cfg, ch, _) = make_client_hello(SHORT_ID);
        cfg.server_names = vec!["other.example".to_string()];
        let err = authenticate(&ch, &cfg, now()).unwrap_err();
        assert!(err.to_string().contains("SNI"), "实际：{err}");
    }

    /// AAD 必须用「session_id 置零」的那份，用原始字节会解不开。
    #[test]
    fn aad_zeroes_the_session_id_field() {
        let (_cfg, ch, _) = make_client_hello(SHORT_ID);
        let aad = ch.aad();
        assert_eq!(aad.len(), ch.raw.len());
        assert!(
            aad[39..71].iter().all(|&b| b == 0),
            "AAD 里 session_id 字段必须是 0"
        );
        assert_eq!(&aad[..39], &ch.raw[..39], "其余部分应保持不变");
        assert_eq!(&aad[71..], &ch.raw[71..], "其余部分应保持不变");
    }

    /// **关键回环**：服务端伪造的证书，必须能被**我们自己的客户端**接受。
    #[test]
    fn forged_certificate_passes_our_own_client_verifier() {
        let (cfg, ch, _) = make_client_hello(SHORT_ID);
        let auth = authenticate(&ch, &cfg, now()).unwrap();

        let ed_pub = [0x33u8; 32];
        let cert = forge_certificate(&auth.auth_key, &ed_pub);

        // 用客户端那套校验逻辑验一遍
        verify_reality_certificate(&cert, &auth.auth_key)
            .expect("我们自己的客户端必须接受这张伪造证书");
    }

    /// 换个 authKey 就必须验不过 —— 防中间人属性。
    #[test]
    fn forged_certificate_fails_under_a_different_auth_key() {
        let (cfg, ch, _) = make_client_hello(SHORT_ID);
        let auth = authenticate(&ch, &cfg, now()).unwrap();
        let cert = forge_certificate(&auth.auth_key, &[0x33u8; 32]);
        assert!(verify_reality_certificate(&cert, &[0x77u8; 32]).is_err());
    }

    // ─── 畸形输入：解析器不得 panic ──────────────────────────────────

    #[test]
    fn parser_rejects_malformed_input_without_panicking() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![2],           // 不是 ClientHello
            vec![1],           // 头都不全
            vec![1, 0, 0, 10], // 声称 10 字节但没有
            vec![1, 0, 0, 0],  // 空 body
            {
                let mut v = vec![1, 0, 0, 40];
                v.extend_from_slice(&[3, 3]);
                v.extend_from_slice(&[0u8; 32]);
                v.push(32); // 声明 32 字节 session_id 但后面没了
                v
            },
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(
                parse_client_hello(c).is_err(),
                "第 {i} 个畸形输入应当被拒绝"
            );
        }
    }

    #[test]
    fn parser_rejects_non_32_byte_session_id() {
        // 真实 ClientHello 但把 session_id 长度改成 31
        let (_, ch, _) = make_client_hello(SHORT_ID);
        let mut msg = ch.raw.clone();
        msg[38] = 31;
        assert!(parse_client_hello(&msg).is_err());
    }

    // ─── 互通夹具：官方 Xray 客户端真实发出的 ClientHello ──────────────────
    //
    // 上面那些用例用的是**我们自己客户端**构造的 ClientHello（很精简）。
    // 官方客户端在 `fingerprint: chrome` 下发的是另一回事：1787 字节、
    // 带 GREASE、三份 key_share（其中 X25519MLKEM768 占 1216 字节）。
    // 只对着自己的输出测，是测不出解析器能不能吃下真实流量的。

    /// 官方 Xray 客户端（fingerprint: chrome）真实发出的 ClientHello 握手消息。
    ///
    /// 抓包方式：起一个裸 TCP 监听，让官方客户端连过来，抓下它发的第一条记录，
    /// 去掉 5 字节 TLS record 头。详见 `docs/verification-log.md` V18。
    const XRAY_CLIENT_HELLO_HEX: &str = include_str!("testdata/xray-clienthello.hex");

    /// 为了抓这份夹包**专门构造**的测试私钥（`[0x42; 32]` 做 X25519 clamp）。
    ///
    /// 它不保护任何东西 —— 只是让夹具可复现，且一眼能看出不是真密钥。
    /// 对应公钥：`EyxEK-AQ-9V-cmAzKKp25x_MwVA6riGTJ9FNnJmT9HI`。
    const FIXTURE_PRIVATE_KEY: [u8; 32] = [
        0x40, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];
    const FIXTURE_SHORT_ID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
    const FIXTURE_SNI: &str = "www.cloudflare.com";

    fn fixture_hello() -> Vec<u8> {
        let hex = XRAY_CLIENT_HELLO_HEX.trim();
        assert!(hex.len().is_multiple_of(2), "夹具 hex 长度应为偶数");
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("夹具应为合法 hex"))
            .collect()
    }

    fn fixture_config() -> RealityServerConfig {
        RealityServerConfig {
            private_key: FIXTURE_PRIVATE_KEY,
            short_ids: vec![FIXTURE_SHORT_ID],
            server_names: vec![FIXTURE_SNI.to_string()],
            // 夹具的时间戳是抓包那一刻的，不能拿"现在"去校验；时钟校验另有单测覆盖。
            max_time_diff_secs: 0,
        }
    }

    /// 我们的解析器必须吃得下官方客户端真实发的 ClientHello。
    #[test]
    fn parses_official_xray_client_hello() {
        let msg = fixture_hello();
        assert_eq!(msg.len(), 1787, "官方 chrome 指纹的 ClientHello 就是这么大");
        assert_eq!(msg[0], HS_CLIENT_HELLO);

        let ch = parse_client_hello(&msg).expect("必须能解析官方客户端的 ClientHello");
        assert_eq!(ch.server_name.as_deref(), Some(FIXTURE_SNI));
        assert_eq!(ch.session_id_offset, 39, "session_id 偏移仍是 39");
        assert_eq!(ch.raw.len(), msg.len());
        // key_share 里有三份（GREASE / MLKEM768 / X25519），要挑出纯 X25519 那份
        assert_ne!(ch.key_share, [0u8; 32], "应挑出 X25519 的公钥");
    }

    /// **跨实现认证**：用官方客户端真实发出的 ClientHello，我们的服务端必须认证成功。
    ///
    /// 这是阶段 1 最有价值的证据 —— 它证明的不是「我们的客户端与我们的服务端自洽」，
    /// 而是「我们的服务端能认出**官方客户端**」。
    #[test]
    fn authenticates_official_xray_client_hello() {
        let ch = parse_client_hello(&fixture_hello()).expect("解析夹具");
        let auth = authenticate(&ch, &fixture_config(), 0).expect("官方客户端必须认证通过");

        assert_eq!(auth.short_id, FIXTURE_SHORT_ID, "shortId 应被还原");
        assert_eq!(auth.client_version, [26, 3, 27], "官方客户端版本应被还原");
        assert!(
            auth.client_time > 1_700_000_000,
            "时间戳应是个合理的 unix 秒，实际 {}",
            auth.client_time
        );
    }

    /// 私钥不对时，官方客户端的 ClientHello 同样应当被拒。
    #[test]
    fn official_xray_client_hello_rejected_with_wrong_key() {
        let ch = parse_client_hello(&fixture_hello()).expect("解析夹具");
        let mut cfg = fixture_config();
        cfg.private_key = [0x99u8; 32];
        assert!(authenticate(&ch, &cfg, 0).is_err());
    }

    /// 官方客户端的 ClientHello 也应当能伪造出被客户端接受的证书。
    #[test]
    fn forged_cert_for_official_client_hello_verifies() {
        let ch = parse_client_hello(&fixture_hello()).expect("解析夹具");
        let auth = authenticate(&ch, &fixture_config(), 0).expect("认证");
        let cert = forge_certificate(&auth.auth_key, &[0x33u8; 32]);
        verify_reality_certificate(&cert, &auth.auth_key).expect("伪造证书必须能过客户端校验");
    }

    // ─── 自环：我们的客户端 ↔ 我们的服务端，完整 TLS 1.3 ──────────────────
    //
    // 这是阶段 2 的核心验证。前面那些用例只测到「认证」这一层；
    // 这里跑的是**完整的握手**：ServerHello、密钥调度、伪造证书、
    // CertificateVerify、双方 Finished，以及握手之后的应用数据收发。
    //
    // 用内存管道而不是真实 socket：协议与传输无关，而且这样测试不需要网络、
    // 不需要线程（wasip2 上没有线程，测试写法必须与目标平台一致）。

    /// 造一对匹配的服务端 / 客户端配置。
    fn keypair_configs() -> (RealityServerConfig, RealityConfig) {
        let mut server_priv = [0x42u8; 32];
        clamp_x25519_private(&mut server_priv);
        let server_pub = x25519_public_from_private(&server_priv);
        (
            RealityServerConfig {
                private_key: server_priv,
                short_ids: vec![SHORT_ID],
                server_names: vec![SNI.to_string()],
                max_time_diff_secs: 60,
            },
            RealityConfig {
                public_key: server_pub,
                short_id: SHORT_ID,
                client_version: [26, 3, 27],
            },
        )
    }

    /// **核心用例**：我们自己的客户端与自己的服务端完成完整握手，并能双向传数据。
    #[test]
    fn our_client_completes_full_handshake_against_our_server() {
        use crate::reality::reality_handshake;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xt_wasm_runtime::block_on;

        let (server_cfg, client_cfg) = keypair_configs();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        // ── 握手 ──
        let (srv, cli) = block_on(async {
            futures::join!(
                reality_server_handshake(Box::new(server_io), &server_cfg),
                reality_handshake(Box::new(client_io), SNI, &[], &client_cfg),
            )
        });

        let mut server_stream = match srv.expect("服务端握手必须成功") {
            HandshakeOutcome::Authenticated { stream, auth } => {
                // 服务端应当认出这是授权客户端（而不是走 dest 回退）
                assert_eq!(auth.short_id, SHORT_ID);
                assert_eq!(auth.client_version, [26, 3, 27]);
                stream
            }
            HandshakeOutcome::Fallback { .. } => {
                panic!("本体应当认证通过，却走了 dest 回退")
            }
        };
        let mut client_stream = cli.expect("客户端握手必须成功");

        // ── 应用数据双向 ──
        //
        // 顺序收发而不是并发：内存管道有 64KB 缓冲，这点数据写下去不会阻塞，
        // 而并发需要同时可变借用两个流，反而绕。这里要验的是「两侧应用密钥一致」。
        block_on(async {
            client_stream
                .write_all(b"ping from client")
                .await
                .expect("客户端写");
            client_stream.flush().await.expect("客户端 flush");

            let mut buf = [0u8; 64];
            let n = server_stream.read(&mut buf).await.expect("服务端读");
            assert_eq!(&buf[..n], b"ping from client", "服务端应收到客户端明文");

            server_stream
                .write_all(b"pong from server")
                .await
                .expect("服务端写");
            server_stream.flush().await.expect("服务端 flush");

            let n = client_stream.read(&mut buf).await.expect("客户端读");
            assert_eq!(
                &buf[..n],
                b"pong from server",
                "客户端应收到服务端明文（说明两侧应用密钥一致）"
            );
        });
    }

    /// 错私钥的客户端连过来时，服务端应当走 **dest 回退**而不是报错断开。
    ///
    /// 断开会让主动探测者一眼看出这不是普通网站；回退才是 REALITY 的正确行为。
    #[test]
    fn wrong_key_client_falls_back_instead_of_erroring() {
        use crate::reality::reality_handshake;
        use xt_wasm_runtime::block_on;

        let (server_cfg, mut client_cfg) = keypair_configs();
        // 客户端拿一个别的服务端公钥（模拟探测者 / 非授权客户端）
        let mut other_priv = [0x99u8; 32];
        clamp_x25519_private(&mut other_priv);
        client_cfg.public_key = x25519_public_from_private(&other_priv);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let (srv, _cli) = block_on(async {
            futures::join!(
                reality_server_handshake(Box::new(server_io), &server_cfg),
                async {
                    // 客户端握手会失败（服务端不回 ServerHello），忽略结果
                    let _ = reality_handshake(Box::new(client_io), SNI, &[], &client_cfg).await;
                }
            )
        });

        match srv.expect("服务端不应报错") {
            HandshakeOutcome::Fallback { buffered, .. } => {
                assert!(
                    !buffered.is_empty(),
                    "回退时必须把已读到的原始字节带出来，否则没法转发给 dest"
                );
            }
            HandshakeOutcome::Authenticated { .. } => {
                panic!("错私钥的客户端不该被认证通过")
            }
        }
    }
}
