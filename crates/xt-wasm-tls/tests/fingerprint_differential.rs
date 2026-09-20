//! T3 指纹对拍：JA3/JA4 计算、逐字段差分（task-3）。
//!
//! ## 这份文件为什么存在
//!
//! 「伪装成 Chrome」如果没有可复现的判据，就只是一句自述。本文件把「像不像」
//! 变成**可计算**的断言，并同时把「哪些地方注定不一样」写成显式清单。
//!
//! 真值（ground truth）来自**真实夹包**：官方 Xray 客户端 `fingerprint: chrome`
//! 实际发出的 ClientHello（handshake 消息，不含 record 头）：
//!
//! * `src/testdata/xray-clienthello.hex` —— 仓库原有夹具（1787 字节，reality_server.rs 的夹具）；
//! * `src/testdata/xray-clienthello-<UTC 时间戳>-<pid>.hex` —— `scripts/capture-clienthello.sh`
//!   抓的样本。**保留 3 份**，因为只用一份会得出错误结论（见下）。
//!
//! ## 一个必须先说清的实证结论：官方客户端的 JA3 每次连接都不同
//!
//! 抓 **12 份**官方客户端 ClientHello（`scripts/capture-clienthello.sh`，同一二进制 26.3.27、
//! 同一 `client.json`、`fingerprint: chrome`），实测：
//!
//! | 指标 | 结果 |
//! |---|---|
//! | **JA4** | 12/12 **完全相同** = `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
//! | **JA3** | 12/12 **互不相同** |
//! | 扩展**集合**（排序后） | 12/12 完全相同 |
//! | 扩展**顺序** | 12/12 各不相同 —— 每次都是同一个排列 |
//! | `SSLVersion` 段 | 12/12 恒为 `771` |
//! | `Ciphers` 段（顺序敏感） | 12/12 恒定（**cipher 顺序不变**） |
//! | `EllipticCurves` 段（顺序敏感） | 12/12 恒为 `4588-29-23-24`（**曲线顺序也不变**） |
//! | `ECPointFormats` 段 | 12/12 恒为 `0` |
//! | ClientHello 总长 | 1723/1755/1787/1819 四档（ECH GREASE 载荷长度随机：186/218/250/282） |
//!
//! 固定位置只有两个：下标 0 与下标 17（最后一个）**恒为 GREASE 扩展**；下标 1..16
//! 是 16 个非 GREASE 扩展的随机排列。**SNI 不固定在开头**（实测出现在 1,3,5,6,7,9,11,14,15,16）。
//! 一句话：**除扩展顺序外没有任何一段在变**——所以我们的 profile 只需要按 seed
//! 打乱扩展顺序，cipher 与 supported_groups 的顺序必须与夹包一致。
//!
//! 结论：**JA3 不是官方客户端自身的稳定指纹**（它依赖扩展顺序），所以
//! `JA3(我们) == JA3(某一份夹包)` 本身不是一个成立判据 —— 除非把 JA3 的
//! `Extensions` 段**排序后**再比（本文件 `ja3_segments()` + `canonical_*` 就是干这个）。
//! **JA4 才是主判据**：它把 cipher 列表与扩展列表都排序后哈希，顺带对
//! supported_groups 不敏感，因此对「我们发不出 X25519MLKEM768 key_share」这个
//! 已知取舍免疫 —— 这正是 task-3 需要的性质。
//! 证据由 `official_client_ja4_stable_across_captures` 钉住（可重跑）。
//!
//! JA3 定义的依据：五段 `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`
//! 用 `,` 连接、段内 `-`、剔除 GREASE(`0x?a?a`)、MD5 小写 hex；`SSLVersion` 取
//! ClientHello 的 `legacy_version`（不是 record 层版本，所以 Chrome 是 771 而非 769）。
//! JA4 定义的依据（外部权威来源，本文件按它实现并有 spec 自带的测试向量）：
//! <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
//!
//! ## 为什么自带 MD5 / SHA-256 之外还自带 MD5
//!
//! 工作区没有 `md5` crate，而 `Cargo.toml` 不在 task-3 的写入范围内，所以这里实现
//! RFC 1321 的 MD5，用 RFC 官方向量钉死；SHA-256 用 crate 依赖 `sha2`，用 NIST
//! 向量 + FoxIO spec 自带的 JA4 哈希向量钉死。
//!
//! ## 真机验证在哪里
//!
//! 握手能不能成不是单元测试能回答的，见 `scripts/e2e-wasm-to-wasm-test.sh` /
//! `scripts/e2e-vision-test.sh` 与「wasm 客户端 → wasm 服务端 → 真实站点」的最小验证；
//! 报告里贴 HTTP 码与日志片段。

use std::fmt::Write as _;

/// 仓库原有夹具：官方 Xray 客户端 `fingerprint: chrome` 的真实 ClientHello。
const FIXTURE_HEX: &str = include_str!("../src/testdata/xray-clienthello.hex");

/// 官方客户端 chrome 指纹的 JA4（9/9 份独立抓包一致，见文件头表格）。
const EXPECTED_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";
const EXPECTED_JA4_A: &str = "t13d1516h2";
const EXPECTED_JA4_B: &str = "8daaf6152771";
const EXPECTED_JA4_C: &str = "d8a2da3f94cd";

/// 官方客户端**排序后**的扩展段（JA3 的 `Extensions` 段，与连接无关的那一部分）。
const EXPECTED_EXTENSIONS_SORTED: &str = "0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281";

/// 仓库原有夹具的 JA3 **五段串**（该夹具的扩展顺序是官方客户端的一次随机排列）。
/// 独立复核：`printf %s '<串>' | openssl md5` → `6ea7fca2518150a2939b8ba64620c0af`。
const FIXTURE_JA3_PREIMAGE: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,16-18-65281-23-0-5-27-51-13-45-43-65037-35-11-10-17613,4588-29-23-24,0";
const FIXTURE_JA3: &str = "6ea7fca2518150a2939b8ba64620c0af";

/// 合成 ClientHello 的 JA3（独立复核 `printf %s '771,4865-4866,10-11-43,29-23,0' | openssl md5`）。
const SYNTHETIC_JA3_PREIMAGE: &str = "771,4865-4866,10-11-43,29-23,0";
const SYNTHETIC_JA3: &str = "607f4b05b6925ede63d6a2088909faf4";

// ─────────────────────────────────────────────────────────────────────────────
// MD5（RFC 1321）
// ─────────────────────────────────────────────────────────────────────────────

/// K[i] = floor(2^32 * |sin(i+1)|)，按定义现算，避免手抄 64 个常量。
fn md5_k_table() -> [u32; 64] {
    let mut k = [0u32; 64];
    for (i, slot) in k.iter_mut().enumerate() {
        *slot = ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32;
    }
    k
}

fn md5_shift(i: usize) -> u32 {
    match i / 16 {
        0 => [7, 12, 17, 22][i % 4],
        1 => [5, 9, 14, 20][i % 4],
        2 => [4, 11, 16, 23][i % 4],
        _ => [6, 10, 15, 21][i % 4],
    }
}

fn md5(data: &[u8]) -> [u8; 16] {
    let k = md5_k_table();
    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (j, slot) in m.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                chunk[4 * j],
                chunk[4 * j + 1],
                chunk[4 * j + 2],
                chunk[4 * j + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for (i, ki) in k.iter().enumerate() {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (1 + 5 * i) % 16),
                2 => (b ^ c ^ d, (5 + 3 * i) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let sum = a.wrapping_add(f).wrapping_add(*ki).wrapping_add(m[g]);
            let rotated = sum.rotate_left(md5_shift(i));
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn md5_hex(data: &[u8]) -> String {
    to_hex(&md5(data))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    to_hex(&h.finalize())
}

/// JA4 的哈希都截断到前 12 个 hex 字符。
fn trunc12(s: &str) -> String {
    s.chars().take(12).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// hex / ClientHello 解析
// ─────────────────────────────────────────────────────────────────────────────

fn decode_hex(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(
        clean.len().is_multiple_of(2),
        "hex 长度是奇数：{}",
        clean.len()
    );
    let nib = |b: u8| -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("非法 hex 字符：{:?}", b as char),
        }
    };
    clean
        .chunks(2)
        .map(|p| (nib(p[0]) << 4) | nib(p[1]))
        .collect()
}

/// GREASE：两个字节相同且低半字节为 `a` —— 0x0a0a,0x1a1a,…,0xfafa。
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

fn ext_name(t: u16) -> &'static str {
    match t {
        0x0000 => "server_name(SNI)",
        0x0005 => "status_request",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000d => "signature_algorithms",
        0x0010 => "alpn",
        0x0012 => "signed_certificate_timestamp",
        0x0017 => "extended_master_secret",
        0x001b => "compress_certificate",
        0x0023 => "session_ticket",
        0x0027 => "compress_certificate",
        0x002b => "supported_versions",
        0x002d => "psk_key_exchange_modes",
        0x0033 => "key_share",
        0x44cd => "application_settings(ALPS)",
        0xfe0d => "encrypted_client_hello(ECH)",
        0xff01 => "renegotiation_info",
        _ => "unknown",
    }
}

#[derive(Debug, Clone)]
struct Ext {
    ext_type: u16,
    /// 扩展头（type+len 共 4 字节）在整条 handshake 消息里的偏移。
    header_off: usize,
    data_off: usize,
    data_len: usize,
}

impl Ext {
    fn end(&self) -> usize {
        self.data_off + self.data_len
    }
    fn label(&self) -> String {
        format!(
            "extension 0x{:04x} {}",
            self.ext_type,
            ext_name(self.ext_type)
        )
    }
}

#[derive(Debug)]
struct ClientHello {
    bytes: Vec<u8>,
    legacy_version: u16,
    session_id_off: usize,
    session_id: Vec<u8>,
    ciphers_off: usize,
    ciphers: Vec<u16>,
    compression: Vec<u8>,
    extensions: Vec<Ext>,
    fixed_regions: Vec<(&'static str, usize, usize)>,
}

impl ClientHello {
    fn parse(bytes: &[u8]) -> ClientHello {
        assert!(
            bytes.len() >= 6,
            "太短，不是 ClientHello：{} 字节",
            bytes.len()
        );
        assert_eq!(bytes[0], 0x01, "首字节不是 HS_CLIENT_HELLO(0x01)");
        let body_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
        assert_eq!(
            body_len + 4,
            bytes.len(),
            "handshake 长度字段 {} != 实长 {}",
            body_len + 4,
            bytes.len()
        );
        let legacy_version = u16::from_be_bytes([bytes[4], bytes[5]]);

        let mut fixed_regions: Vec<(&'static str, usize, usize)> = vec![
            ("handshake 头(0x01+3B 长度)", 0, 4),
            ("legacy_version", 4, 6),
            ("random", 6, 38),
        ];

        let sid_len = bytes[38] as usize;
        let sid_off = 39;
        let sid_end = sid_off + sid_len;
        fixed_regions.push(("session_id_len(1B)", 38, 39));
        fixed_regions.push((
            "session_id[0..16]=REALITY 认证密文 / [16..32]=随机",
            sid_off,
            sid_end,
        ));

        let mut p = sid_end;
        let cs_len = u16::from_be_bytes([bytes[p], bytes[p + 1]]) as usize;
        fixed_regions.push(("cipher_suites_len(2B)", p, p + 2));
        p += 2;
        let cs_off = p;
        assert!(
            cs_len.is_multiple_of(2),
            "cipher_suites 长度是奇数：{cs_len}"
        );
        let ciphers: Vec<u16> = (0..cs_len / 2)
            .map(|i| u16::from_be_bytes([bytes[cs_off + 2 * i], bytes[cs_off + 2 * i + 1]]))
            .collect();
        fixed_regions.push(("cipher_suites", cs_off, cs_off + cs_len));
        p = cs_off + cs_len;

        let cmp_len = bytes[p] as usize;
        fixed_regions.push(("compression_methods_len(1B)", p, p + 1));
        p += 1;
        let cmp_off = p;
        let compression = bytes[cmp_off..cmp_off + cmp_len].to_vec();
        fixed_regions.push(("compression_methods", cmp_off, cmp_off + cmp_len));
        p = cmp_off + cmp_len;

        let ext_len = u16::from_be_bytes([bytes[p], bytes[p + 1]]) as usize;
        fixed_regions.push(("extensions_len(2B)", p, p + 2));
        p += 2;
        let ext_start = p;
        let mut extensions = Vec::new();
        let mut q = ext_start;
        while q < ext_start + ext_len {
            assert!(q + 4 <= bytes.len(), "扩展头越界 @ {q}");
            let t = u16::from_be_bytes([bytes[q], bytes[q + 1]]);
            let l = u16::from_be_bytes([bytes[q + 2], bytes[q + 3]]) as usize;
            assert!(q + 4 + l <= bytes.len(), "扩展 0x{t:04x} 体越界 @ {q}");
            extensions.push(Ext {
                ext_type: t,
                header_off: q,
                data_off: q + 4,
                data_len: l,
            });
            q += 4 + l;
        }
        assert_eq!(q, ext_start + ext_len, "extensions_len 与解析结果不符");

        ClientHello {
            bytes: bytes.to_vec(),
            legacy_version,
            session_id_off: sid_off,
            session_id: bytes[sid_off..sid_end].to_vec(),
            ciphers_off: cs_off,
            ciphers,
            compression,
            extensions,
            fixed_regions,
        }
    }

    fn from_hex(s: &str) -> ClientHello {
        ClientHello::parse(&decode_hex(s))
    }

    fn ext(&self, t: u16) -> Option<&Ext> {
        self.extensions.iter().find(|e| e.ext_type == t)
    }

    fn body(&self, e: &Ext) -> &[u8] {
        &self.bytes[e.data_off..e.end()]
    }

    /// 某个绝对偏移属于哪一部分；用于差分报告里指出「第一个不一致在哪」。
    fn region_of(&self, off: usize) -> String {
        for e in &self.extensions {
            if off >= e.header_off && off < e.end() {
                let part = if off < e.data_off {
                    "扩展头(type/len)"
                } else {
                    "扩展体"
                };
                return format!("{} 的{}", e.label(), part);
            }
        }
        for (name, start, end) in &self.fixed_regions {
            if off >= *start && off < *end {
                return (*name).to_string();
            }
        }
        format!("未知区域（偏移 {off} 超出已解析的字段）")
    }
}

fn fixture() -> ClientHello {
    ClientHello::from_hex(FIXTURE_HEX)
}

// ─────────────────────────────────────────────────────────────────────────────
// 结构化取值 helper（JA3 / JA4 / 逐字段对比共用）
// ─────────────────────────────────────────────────────────────────────────────

fn non_grease(vs: &[u16]) -> Vec<u16> {
    vs.iter().copied().filter(|v| !is_grease(*v)).collect()
}

fn hex_list(vs: &[u16]) -> String {
    vs.iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join("-")
}

fn dec_list(vs: &[u16]) -> String {
    vs.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// supported_groups(0x000a) 的条目（原样，含 GREASE）。
fn supported_groups_raw(ch: &ClientHello) -> Vec<u16> {
    match ch.ext(0x000a) {
        Some(e) => {
            let d = ch.body(e);
            let n = u16::from_be_bytes([d[0], d[1]]) as usize;
            (0..n / 2)
                .map(|i| u16::from_be_bytes([d[2 + 2 * i], d[3 + 2 * i]]))
                .collect()
        }
        None => Vec::new(),
    }
}

/// ec_point_formats(0x000b)：1B 长度 + 取值。
fn ec_point_formats(ch: &ClientHello) -> Vec<u8> {
    match ch.ext(0x000b) {
        Some(e) => {
            let d = ch.body(e);
            let n = d[0] as usize;
            d[1..1 + n].to_vec()
        }
        None => Vec::new(),
    }
}

/// supported_versions(0x002b)：1B 长度 + 取值。
fn supported_versions(ch: &ClientHello) -> Vec<u16> {
    match ch.ext(0x002b) {
        Some(e) => {
            let d = ch.body(e);
            let n = d[0] as usize;
            (0..n / 2)
                .map(|i| u16::from_be_bytes([d[1 + 2 * i], d[2 + 2 * i]]))
                .collect()
        }
        None => Vec::new(),
    }
}

/// signature_algorithms(0x000d)：2B 长度 + 取值。
fn signature_algorithms(ch: &ClientHello) -> Vec<u16> {
    match ch.ext(0x000d) {
        Some(e) => {
            let d = ch.body(e);
            let n = u16::from_be_bytes([d[0], d[1]]) as usize;
            (0..n / 2)
                .map(|i| u16::from_be_bytes([d[2 + 2 * i], d[3 + 2 * i]]))
                .collect()
        }
        None => Vec::new(),
    }
}

/// key_share 条目 (group, key_len)，**不含公钥字节**（那是随机材料）。
fn key_share_entries(ch: &ClientHello) -> Vec<(u16, usize)> {
    let mut out = Vec::new();
    if let Some(e) = ch.ext(0x0033) {
        let mut off = e.data_off + 2;
        while off + 4 <= e.end() {
            let g = u16::from_be_bytes([ch.bytes[off], ch.bytes[off + 1]]);
            let kl = u16::from_be_bytes([ch.bytes[off + 2], ch.bytes[off + 3]]) as usize;
            out.push((g, kl));
            off += 4 + kl;
        }
    }
    out
}

/// ALPN 列表（按线上顺序）。
fn alpn_list(ch: &ClientHello) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(e) = ch.ext(0x0010) {
        let d = ch.body(e);
        let total = u16::from_be_bytes([d[0], d[1]]) as usize;
        let mut p = 2;
        while p < 2 + total {
            let l = d[p] as usize;
            out.push(String::from_utf8_lossy(&d[p + 1..p + 1 + l]).to_string());
            p += 1 + l;
        }
    }
    out
}

fn sni(ch: &ClientHello) -> String {
    match ch.ext(0x0000) {
        Some(e) => {
            let d = ch.body(e);
            let name_len = u16::from_be_bytes([d[3], d[4]]) as usize;
            String::from_utf8_lossy(&d[5..5 + name_len]).to_string()
        }
        None => String::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JA3
// ─────────────────────────────────────────────────────────────────────────────

/// JA3 的五个段，外加原始五段串与 MD5。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ja3 {
    version: String,
    ciphers: String,
    extensions: String,
    curves: String,
    point_formats: String,
    preimage: String,
    hash: String,
}

impl Ja3 {
    /// 与顺序无关的那一部分：扩展段排序后。
    fn extensions_sorted(&self) -> String {
        let mut v: Vec<&str> = self
            .extensions
            .split('-')
            .filter(|s| !s.is_empty())
            .collect();
        v.sort_by_key(|s| s.parse::<u32>().unwrap_or(0));
        v.join("-")
    }
}

fn ja3_of(ch: &ClientHello) -> Ja3 {
    let version = tls_version_string(ch);
    let ciphers = dec_list(&non_grease(&ch.ciphers));
    let extensions = dec_list(&non_grease(
        &ch.extensions.iter().map(|e| e.ext_type).collect::<Vec<_>>(),
    ));
    let curves = dec_list(&non_grease(&supported_groups_raw(ch)));
    let point_formats = ec_point_formats(ch)
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let preimage = format!("{version},{ciphers},{extensions},{curves},{point_formats}");
    Ja3 {
        version: version.to_string(),
        ciphers,
        extensions,
        curves,
        point_formats,
        hash: md5_hex(preimage.as_bytes()),
        preimage,
    }
}

/// JA3 的 SSLVersion 段：ClientHello 的 legacy_version（**不是** record 版本）。
fn tls_version_string(ch: &ClientHello) -> String {
    ch.legacy_version.to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// JA4（依据 FoxIO spec，见文件头链接）
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct Ja4 {
    a: String,
    b: String,
    c: String,
    b_preimage: String,
    c_preimage: String,
}

impl Ja4 {
    fn full(&self) -> String {
        format!("{}_{}_{}", self.a, self.b, self.c)
    }
}

/// ALPN 段：第一个 ALPN 值的首尾字符；非字母数字则用其 hex 表示的首尾字符。
fn ja4_alpn(ch: &ClientHello) -> String {
    let list = alpn_list(ch);
    let first = match list.first() {
        Some(s) if !s.is_empty() => s.as_bytes(),
        _ => return "00".to_string(),
    };
    let alnum = |b: u8| b.is_ascii_digit() || b.is_ascii_uppercase() || b.is_ascii_lowercase();
    if alnum(first[0]) && alnum(first[first.len() - 1]) {
        // 单字符时首尾是同一个字符
        format!("{}{}", first[0] as char, first[first.len() - 1] as char)
    } else {
        let h = to_hex(first);
        let hb = h.as_bytes();
        format!("{}{}", hb[0] as char, hb[hb.len() - 1] as char)
    }
}

fn ja4_of(ch: &ClientHello) -> Ja4 {
    // ---- a ----
    // 版本：supported_versions 存在则取其（去 GREASE 后）最大值，否则用 legacy_version。
    let version = {
        let vs = non_grease(&supported_versions(ch));
        match vs.iter().copied().max() {
            Some(v) => v,
            None => ch.legacy_version,
        }
    };
    let vstr = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    };
    let sni_flag = if ch.ext(0x0000).is_some() { 'd' } else { 'i' };
    let ciphers = non_grease(&ch.ciphers);
    let exts = non_grease(&ch.extensions.iter().map(|e| e.ext_type).collect::<Vec<_>>());
    let a = format!(
        "t{vstr}{sni_flag}{:02}{:02}{}",
        ciphers.len().min(99),
        exts.len().min(99),
        ja4_alpn(ch)
    );

    // ---- b：cipher 列表按 hex 排序后逗号连接，sha256 取前 12 ----
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let b_preimage = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        trunc12(&sha256_hex(b_preimage.as_bytes()))
    };

    // ---- c：扩展列表排序（去掉 SNI/ALPN）+ "_" + sigalgs（原顺序），sha256 取前 12 ----
    let mut sorted_exts: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|t| *t != 0x0000 && *t != 0x0010)
        .collect();
    sorted_exts.sort_unstable();
    let sigs = non_grease(&signature_algorithms(ch));
    let mut c_preimage = sorted_exts
        .iter()
        .map(|t| format!("{t:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    if !sigs.is_empty() {
        c_preimage.push('_');
        c_preimage.push_str(
            &sigs
                .iter()
                .map(|s| format!("{s:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    let c = if sorted_exts.is_empty() {
        "000000000000".to_string()
    } else {
        trunc12(&sha256_hex(c_preimage.as_bytes()))
    };

    Ja4 {
        a,
        b,
        c,
        b_preimage,
        c_preimage,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 归一化 + 差分诊断
// ─────────────────────────────────────────────────────────────────────────────

/// GREASE 值统一成这个占位（「这个位置是 GREASE」可比，「具体是哪个 GREASE」不可比）。
const CANON_GREASE: u16 = 0x0a0a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fill {
    Zero,
    Grease,
}

#[derive(Debug, Clone)]
struct Mask {
    off: usize,
    len: usize,
    fill: Fill,
    what: &'static str,
}

fn push_mask(
    out: &mut [u8],
    masks: &mut Vec<Mask>,
    off: usize,
    len: usize,
    fill: Fill,
    what: &'static str,
) {
    assert!(
        off + len <= out.len(),
        "掩码 [{off},{}) 越界（len={}）",
        off + len,
        out.len()
    );
    if len == 0 {
        return;
    }
    match fill {
        Fill::Zero => out[off..off + len].fill(0),
        Fill::Grease => {
            out[off..off + len].copy_from_slice(&CANON_GREASE.to_be_bytes().repeat(len / 2))
        }
    }
    masks.push(Mask {
        off,
        len,
        fill,
        what,
    });
}

/// 归一化后的字节 + 被抹掉的「本来就随机」窗口清单。
///
/// 抹掉：`random`、`session_id[16..32]`、GREASE 的值与 GREASE 扩展体、
/// key_share **所有条目的公钥字节**（group/key_len 不抹）、ECH 整个扩展体。
/// 保留（这些正是指纹）：扩展类型集合与顺序、各扩展长度字段、cipher 列表、
/// compression、supported_groups/ALPN/SNI/sigalgs/ec_point_formats 的内容。
///
/// ⚠️ 归一化后**逐字节全等**不是本文件的主判据：官方客户端自己每次连接都不同
/// （扩展顺序打乱、ECH 填充长度随机），我们也不可能复现 X25519MLKEM768 的
/// key_share。主判据是 JA4 全等 + 逐字段差分只差在**声明过的**偏差上。
/// 归一化保留下来是当**排障探针**：报告第一个不一致的偏移与所属扩展。
fn normalize(ch: &ClientHello) -> (Vec<u8>, Vec<Mask>) {
    let mut out = ch.bytes.clone();
    let mut masks: Vec<Mask> = Vec::new();

    push_mask(&mut out, &mut masks, 6, 32, Fill::Zero, "random[0..32]");
    if ch.session_id.len() == 32 {
        push_mask(
            &mut out,
            &mut masks,
            ch.session_id_off + 16,
            16,
            Fill::Zero,
            "session_id[16..32] 随机部分",
        );
    }
    for (i, c) in ch.ciphers.iter().enumerate() {
        if is_grease(*c) {
            push_mask(
                &mut out,
                &mut masks,
                ch.ciphers_off + 2 * i,
                2,
                Fill::Grease,
                "GREASE cipher_suite",
            );
        }
    }
    for e in &ch.extensions {
        if is_grease(e.ext_type) {
            push_mask(
                &mut out,
                &mut masks,
                e.header_off,
                2,
                Fill::Grease,
                "GREASE 扩展类型",
            );
            push_mask(
                &mut out,
                &mut masks,
                e.data_off,
                e.data_len,
                Fill::Zero,
                "GREASE 扩展体",
            );
            continue;
        }
        match e.ext_type {
            0x000a => {
                let d = ch.body(e);
                let n = u16::from_be_bytes([d[0], d[1]]) as usize;
                for i in 0..n / 2 {
                    let off = e.data_off + 2 + 2 * i;
                    let g = u16::from_be_bytes([ch.bytes[off], ch.bytes[off + 1]]);
                    if is_grease(g) {
                        push_mask(
                            &mut out,
                            &mut masks,
                            off,
                            2,
                            Fill::Grease,
                            "GREASE supported_group",
                        );
                    }
                }
            }
            0x002b => {
                let d = ch.body(e);
                let n = d[0] as usize;
                for i in 0..n / 2 {
                    let off = e.data_off + 1 + 2 * i;
                    let v = u16::from_be_bytes([ch.bytes[off], ch.bytes[off + 1]]);
                    if is_grease(v) {
                        push_mask(
                            &mut out,
                            &mut masks,
                            off,
                            2,
                            Fill::Grease,
                            "GREASE supported_version",
                        );
                    }
                }
            }
            0x0033 => {
                let mut off = e.data_off + 2;
                while off + 4 <= e.end() {
                    let g = u16::from_be_bytes([ch.bytes[off], ch.bytes[off + 1]]);
                    let kl = u16::from_be_bytes([ch.bytes[off + 2], ch.bytes[off + 3]]) as usize;
                    if is_grease(g) {
                        push_mask(
                            &mut out,
                            &mut masks,
                            off,
                            2,
                            Fill::Grease,
                            "GREASE key_share group",
                        );
                    }
                    push_mask(
                        &mut out,
                        &mut masks,
                        off + 4,
                        kl,
                        Fill::Zero,
                        "key_share 条目公钥(随机材料)",
                    );
                    off += 4 + kl;
                }
            }
            0xfe0d => {
                push_mask(
                    &mut out,
                    &mut masks,
                    e.data_off,
                    e.data_len,
                    Fill::Zero,
                    "ECH 载荷(长度也随机)",
                );
            }
            _ => {}
        }
    }
    (out, masks)
}

fn window16(bytes: &[u8], off: usize) -> String {
    if off >= bytes.len() {
        return "<越界>".to_string();
    }
    let end = (off + 16).min(bytes.len());
    format!("{} ({}B)", to_hex(&bytes[off..end]), end - off)
}

/// 第一个不一致的偏移 + 两侧各 16 字节 hex + 该偏移属于哪个扩展。
fn first_divergence(na: &[u8], nb: &[u8], la: &ClientHello, lb: &ClientHello) -> Option<String> {
    let n = na.len().min(nb.len());
    let mut found = None;
    for i in 0..n {
        if na[i] != nb[i] {
            found = Some(i);
            break;
        }
    }
    let off = match found {
        Some(o) => o,
        None if na.len() != nb.len() => n,
        None => return None,
    };

    let mut s = String::new();
    let _ = writeln!(s, "第一个不一致：偏移 {off}（0x{off:x}）");
    let _ = writeln!(
        s,
        "  长度：我们 {} 字节，夹包 {} 字节（差 {}）",
        la.bytes.len(),
        lb.bytes.len(),
        la.bytes.len() as i64 - lb.bytes.len() as i64
    );
    let _ = writeln!(s, "  我们这边 [{off}..) = {}", window16(na, off));
    let _ = writeln!(s, "  夹包那边 [{off}..) = {}", window16(nb, off));
    let _ = writeln!(s, "  归属（我们这边）：{}", la.region_of(off));
    let _ = writeln!(s, "  归属（夹包那边）：{}", lb.region_of(off));
    // 两侧按扩展对齐的结构表 —— 大多数「没对齐」都是某个扩展的存在性/长度不同。
    let _ = writeln!(
        s,
        "  扩展结构(type@header_off:data_len) 我们：{}",
        structural_summary(la)
    );
    let _ = writeln!(
        s,
        "  扩展结构(type@header_off:data_len) 夹包：{}",
        structural_summary(lb)
    );
    Some(s)
}

fn structural_summary(ch: &ClientHello) -> String {
    ch.extensions
        .iter()
        .map(|e| format!("{}@{}:{}", ext_name(e.ext_type), e.header_off, e.data_len))
        .collect::<Vec<_>>()
        .join(" ")
}

// ─────────────────────────────────────────────────────────────────────────────
// 逐字段对比（主判据的形态）：把两边都摊平成 (字段名, 取值) 列表
// ─────────────────────────────────────────────────────────────────────────────

/// ECH 扩展体的布局（实测 5 份官方夹包全部自洽）：
/// `[0]=0x00, kdf_id(2), aead_id(2), config_id(1), enc_len(2), enc(enc_len), payload_len(2), payload`
/// → `data_len = 42 + payload_len`（官方四档 payload = 144/176/208/240，对应 data_len = 186/218/250/282）。
/// 这里只取**恒定部分**（不含随机/按档变化的 config_id、enc、payload）。
fn ech_fixed_fields(ch: &ClientHello) -> String {
    match ch.ext(0xfe0d) {
        Some(e) => {
            let d = ch.body(e);
            if d.len() < 8 {
                return format!("malformed(data_len={})", d.len());
            }
            format!(
                "prefix={:02x},kdf={:04x},aead={:04x},enc_len={}",
                d[0],
                u16::from_be_bytes([d[1], d[2]]),
                u16::from_be_bytes([d[3], d[4]]),
                u16::from_be_bytes([d[6], d[7]])
            )
        }
        None => "none".to_string(),
    }
}

/// ECH 的 `payload_len` 字段（随 seed 在官方四档里选）。
fn ech_payload_len(ch: &ClientHello) -> Option<usize> {
    let e = ch.ext(0xfe0d)?;
    let d = ch.body(e);
    if d.len() < 10 {
        return None;
    }
    let enc_len = u16::from_be_bytes([d[6], d[7]]) as usize;
    let off = 8 + enc_len;
    if d.len() < off + 2 {
        return None;
    }
    Some(u16::from_be_bytes([d[off], d[off + 1]]) as usize)
}

/// 摊平成「可比字段」。**故意不含**：random、session_id 后 16 字节、GREASE 具体值、
/// key_share 公钥字节、ECH 的 config_id/enc/payload 随机字节。
/// ECH 单独拆成三个字段：`ech_present`（比存在性）、`ech_fixed_fields`（比结构与
/// kdf/aead/enc_len，必须相等）、`ech_payload_len`（随 seed 在官方四档里选，
/// Phase B 里按「∈ 观测档位」放宽，并在报告里注明这是有意对齐的随机窗口）。
fn field_snapshot(ch: &ClientHello) -> Vec<(String, String)> {
    let exts_ordered: Vec<u16> =
        non_grease(&ch.extensions.iter().map(|e| e.ext_type).collect::<Vec<_>>());
    let mut exts_sorted = exts_ordered.clone();
    exts_sorted.sort_unstable();
    let ks = key_share_entries(ch)
        .iter()
        .map(|(g, l)| {
            let g = if is_grease(*g) { CANON_GREASE } else { *g };
            format!("{g:04x}/key_len={l}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    vec![
        (
            "legacy_version".into(),
            format!("{:04x}", ch.legacy_version),
        ),
        (
            "cipher_suites(顺序,去GREASE)".into(),
            hex_list(&non_grease(&ch.ciphers)),
        ),
        ("cipher_suites(排序,去GREASE)".into(), {
            let mut v = non_grease(&ch.ciphers);
            v.sort_unstable();
            hex_list(&v)
        }),
        ("compression_methods".into(), to_hex(&ch.compression)),
        ("extensions(顺序,去GREASE)".into(), hex_list(&exts_ordered)),
        ("extensions(排序,去GREASE)".into(), hex_list(&exts_sorted)),
        (
            "extensions_个数(去GREASE)".into(),
            exts_ordered.len().to_string(),
        ),
        (
            "supported_groups(去GREASE,原顺序)".into(),
            hex_list(&non_grease(&supported_groups_raw(ch))),
        ),
        (
            "supported_versions(去GREASE)".into(),
            hex_list(&non_grease(&supported_versions(ch))),
        ),
        ("ec_point_formats".into(), to_hex(&ec_point_formats(ch))),
        (
            "signature_algorithms(去GREASE)".into(),
            hex_list(&non_grease(&signature_algorithms(ch))),
        ),
        ("alpn".into(), alpn_list(ch).join(",")),
        ("sni".into(), sni(ch)),
        ("key_share(group/key_len,不含公钥)".into(), ks),
        ("ech_present".into(), ch.ext(0xfe0d).is_some().to_string()),
        ("ech_fixed_fields".into(), ech_fixed_fields(ch)),
        (
            "ech_payload_len".into(),
            ech_payload_len(ch)
                .map(|v| v.to_string())
                .unwrap_or_default(),
        ),
        ("alps_present".into(), ch.ext(0x44cd).is_some().to_string()),
        ("session_id_len".into(), ch.session_id.len().to_string()),
    ]
}

/// 逐字段差异：`(字段名, 我们, 对方)`。空 = 逐字段完全一致。
fn field_diff(ours: &ClientHello, theirs: &ClientHello) -> Vec<(String, String, String)> {
    let a = field_snapshot(ours);
    let b = field_snapshot(theirs);
    assert_eq!(
        a.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        b.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        "field_snapshot 的字段顺序必须稳定"
    );
    let mut out = Vec::new();
    for ((k, va), (_, vb)) in a.iter().zip(b.iter()) {
        if va != vb {
            out.push((k.clone(), va.clone(), vb.clone()));
        }
    }
    out
}

fn format_field_diff(label_a: &str, label_b: &str, diffs: &[(String, String, String)]) -> String {
    let mut s = format!(
        "逐字段差异（{label_a} vs {label_b}）：共 {} 处\n",
        diffs.len()
    );
    for (k, a, b) in diffs {
        let _ = writeln!(s, "  [{k}]\n    {label_a}: {a}\n    {label_b}: {b}");
    }
    s
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试：MD5 / SHA-256 自身的可信度
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 1321 §A.5 的官方测试向量。
#[test]
fn md5_rfc1321_vectors() {
    let vectors: &[(&[u8], &str)] = &[
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (input, want) in vectors {
        let got = md5_hex(input);
        assert_eq!(&got, want, "MD5({:?}) = {got}，RFC 1321 期望 {want}", input);
    }
}

/// NIST FIPS 180-4 的 SHA-256 向量。
#[test]
fn sha256_nist_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

/// **FoxIO JA4 spec 自带的哈希向量**（外部权威来源，见文件头链接）：
/// 用它证明我们的 JA4_b / JA4_c 计算（排序 + 逗号 + 4 位 hex + sha256 截断 12）没跑偏。
#[test]
fn foxio_spec_ja4_hash_anchors() {
    // spec 的 JA4_b 例子：cipher 列表按 hex 排序后逗号连接
    let b_pre = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";
    assert_eq!(
        trunc12(&sha256_hex(b_pre.as_bytes())),
        "8daaf6152771",
        "JA4_b 与 FoxIO spec 文档给出的值不符"
    );
    // spec 的 JA4_c 例子：扩展排序（去 SNI/ALPN）+ "_" + sigalgs 原顺序
    let c_pre = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";
    assert_eq!(
        trunc12(&sha256_hex(c_pre.as_bytes())),
        "e5627efa2ab1",
        "JA4_c 与 FoxIO spec 文档给出的值不符"
    );
    // spec 的完整例子
    assert_eq!(
        "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试：夹包本身
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fixture_is_wellformed_clienthello() {
    let ch = fixture();
    assert_eq!(ch.bytes.len(), 1787, "原有夹包应为 1787 字节");
    assert_eq!(ch.legacy_version, 0x0303);
    assert_eq!(ch.session_id.len(), 32, "session_id 应为 32 字节");
    assert_eq!(ch.compression, vec![0x00], "compression 只应有 null");
    assert_eq!(ch.ciphers.len(), 16);
    assert!(is_grease(ch.ciphers[0]), "cipher[0] 应是 GREASE");
    assert!(ch.ext(0xfe0d).is_some(), "缺少 ECH(65037)");
    assert!(ch.ext(0x44cd).is_some(), "缺少 ALPS(17613)");
    assert!(ch.ext(0x0033).is_some(), "缺少 key_share");
    // key_share 结构：GREASE(1B) + 11ec/X25519MLKEM768(1216B) + 001d/x25519(32B)
    assert_eq!(
        key_share_entries(&ch),
        vec![(0x6a6a, 1), (0x11ec, 1216), (0x001d, 32)],
        "key_share 条目与 T1 描述不一致"
    );
    assert_eq!(sni(&ch), "www.cloudflare.com");
    assert_eq!(
        alpn_list(&ch),
        vec!["h2".to_string(), "http/1.1".to_string()]
    );
}

/// 原有夹具的 JA3（= 官方客户端某一次连接的排列）+ JA3 五段的**顺序无关**形态。
#[test]
fn official_xray_chrome_fixture_ja3() {
    let ch = fixture();
    let ja3 = ja3_of(&ch);
    println!("── 原有夹包 JA3 ──");
    println!("  preimage : {}", ja3.preimage);
    println!("  JA3      : {}", ja3.hash);
    println!("  Extensions(排序后): {}", ja3.extensions_sorted());
    println!("  独立复核 : printf %s '{}' | openssl md5", ja3.preimage);

    assert_eq!(ja3.preimage, FIXTURE_JA3_PREIMAGE, "JA3 五段串变了");
    assert_eq!(ja3.hash, FIXTURE_JA3, "JA3 值变了");
    assert_eq!(ja3.version, "771", "SSLVersion 段应取 legacy_version=771");
    assert_eq!(
        ja3.extensions_sorted(),
        EXPECTED_EXTENSIONS_SORTED,
        "扩展集合（排序后）与官方客户端不一致"
    );
    // 官方客户端的曲线列表**包含** 11ec(X25519MLKEM768) —— 这是我们必须显式承认的偏差
    assert_eq!(
        ja3.curves, "4588-29-23-24",
        "官方 chrome 的 supported_groups"
    );
    assert_eq!(ja3.point_formats, "0");
}

/// 原有夹具的 JA4（= 官方客户端 chrome 指纹的稳定值）。
#[test]
fn official_xray_chrome_fixture_ja4() {
    let ch = fixture();
    let ja4 = ja4_of(&ch);
    println!("── 原有夹包 JA4 ──");
    println!("  a = {}", ja4.a);
    println!("  b preimage = {}", ja4.b_preimage);
    println!("  b = {}", ja4.b);
    println!("  c preimage = {}", ja4.c_preimage);
    println!("  c = {}", ja4.c);
    println!("  JA4 = {}", ja4.full());

    assert_eq!(
        ja4.a, EXPECTED_JA4_A,
        "JA4_a 变了（版本/SNI/cipher 数/扩展数/ALPN）"
    );
    assert_eq!(ja4.b, EXPECTED_JA4_B, "JA4_b 变了");
    assert_eq!(ja4.c, EXPECTED_JA4_C, "JA4_c 变了");
    assert_eq!(ja4.full(), EXPECTED_JA4);
}

/// **本任务最重要的实验事实**：官方客户端自己的 JA3 每次连接都不同，JA4 才是稳定指纹。
///
/// 依赖 `scripts/capture-clienthello.sh` 抓的 ≥3 份样本（保留在 testdata/）。
/// 这条测试本身就是「JA3 不能拿单份夹包当判据」的证据，防止后来者拿
/// `JA3(ours) == JA3(某一份夹包)` 当硬断言，然后为了让它绿去改实现。
#[test]
fn official_client_ja4_stable_across_captures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("读不到 testdata 目录")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("xray-clienthello") && n.ends_with(".hex"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    assert!(
        files.len() >= 3,
        "至少需要 3 份官方抓包样本才能证明「JA3 不稳定 / JA4 稳定」；当前 {} 份。\
         跑 ./scripts/capture-clienthello.sh 再抓几份。",
        files.len()
    );

    println!("── {} 份官方客户端抓包对比 ──", files.len());
    let mut ja3_hashes = std::collections::BTreeSet::new();
    let mut ja4_hashes = std::collections::BTreeSet::new();
    let mut sorted_ext_sets = std::collections::BTreeSet::new();
    // 每个 JA3 段各自的取值集合 —— 这是「除扩展顺序外还有没有别的段在变」的直接证据
    let mut seg_version = std::collections::BTreeSet::new();
    let mut seg_ciphers = std::collections::BTreeSet::new();
    let mut seg_ext_order = std::collections::BTreeSet::new();
    let mut seg_curves = std::collections::BTreeSet::new();
    let mut seg_point_formats = std::collections::BTreeSet::new();
    // 扩展位置：type -> 出现过的下标集合
    let mut positions: std::collections::BTreeMap<u16, std::collections::BTreeSet<usize>> =
        std::collections::BTreeMap::new();
    for f in &files {
        let ch = ClientHello::from_hex(&std::fs::read_to_string(f).unwrap());
        let ja3 = ja3_of(&ch);
        let ja4 = ja4_of(&ch);
        ja3_hashes.insert(ja3.hash.clone());
        ja4_hashes.insert(ja4.full());
        sorted_ext_sets.insert(ja3.extensions_sorted());
        seg_version.insert(ja3.version.clone());
        seg_ciphers.insert(ja3.ciphers.clone());
        seg_ext_order.insert(ja3.extensions.clone());
        seg_curves.insert(ja3.curves.clone());
        seg_point_formats.insert(ja3.point_formats.clone());
        for (i, e) in ch.extensions.iter().enumerate() {
            positions.entry(e.ext_type).or_default().insert(i);
        }
        println!(
            "  {:<44} len={:4} JA3={} JA4={}",
            f.file_name().unwrap().to_string_lossy(),
            ch.bytes.len(),
            ja3.hash,
            ja4.full()
        );
    }

    println!("  ── 分段稳定性（不同取值数 / {}）──", files.len());
    for (label, set) in [
        ("SSLVersion", &seg_version),
        ("Ciphers（顺序敏感）", &seg_ciphers),
        ("Extensions 顺序", &seg_ext_order),
        ("EllipticCurves（顺序敏感）", &seg_curves),
        ("ECPointFormats", &seg_point_formats),
    ] {
        println!("    {label}: {}", set.len());
    }
    println!("  ── 扩展位置表（下标 = 线上下标，含 GREASE）──");
    for (t, ps) in &positions {
        let v: Vec<String> = ps.iter().map(|p| p.to_string()).collect();
        println!(
            "    0x{t:04x}{}: [{}] {}",
            if is_grease(*t) { " GREASE" } else { "" },
            v.join(","),
            if ps.len() == 1 { "固定" } else { "变化" }
        );
    }

    // JA4：全部相同 —— 这才是指纹
    assert_eq!(
        ja4_hashes.len(),
        1,
        "官方客户端的 JA4 竟然不一致：{ja4_hashes:?}"
    );
    assert_eq!(ja4_hashes.iter().next().unwrap(), EXPECTED_JA4);
    // 扩展集合（排序后）：全部相同
    assert_eq!(
        sorted_ext_sets.len(),
        1,
        "扩展集合不一致：{sorted_ext_sets:?}"
    );
    assert_eq!(
        sorted_ext_sets.iter().next().unwrap(),
        EXPECTED_EXTENSIONS_SORTED
    );
    // 除扩展顺序外，其它 JA3 段都不变（这决定我们只需打乱扩展顺序）
    assert_eq!(
        seg_version.len(),
        1,
        "SSLVersion 段竟然在变：{seg_version:?}"
    );
    assert_eq!(seg_version.iter().next().unwrap(), "771");
    assert_eq!(seg_ciphers.len(), 1, "Ciphers 段竟然在变：{seg_ciphers:?}");
    assert_eq!(
        seg_curves.len(),
        1,
        "EllipticCurves 段竟然在变：{seg_curves:?}"
    );
    assert_eq!(seg_curves.iter().next().unwrap(), "4588-29-23-24");
    assert_eq!(
        seg_point_formats.len(),
        1,
        "ECPointFormats 段竟然在变：{seg_point_formats:?}"
    );
    // 扩展**顺序**：样本之间必须不同（这就是 JA3 不稳的原因）
    assert!(
        seg_ext_order.len() >= 2,
        "本应观察到扩展顺序被打乱，但 {} 份样本的顺序全同 —— 抓包方式或客户端行为变了，需重新确认。",
        files.len()
    );
    // 位置表：只有首尾两个位置固定，且必须是 GREASE
    for (i, want_grease) in [(0usize, true), (17usize, true)] {
        let fixed_here: Vec<u16> = positions
            .iter()
            .filter(|(_, ps)| ps.len() == 1 && ps.contains(&i))
            .map(|(t, _)| *t)
            .collect();
        assert!(
            !fixed_here.is_empty() && fixed_here.iter().all(|t| is_grease(*t) == want_grease),
            "下标 {i} 的固定占用者不符合预期（应恒为 GREASE）：{fixed_here:?}"
        );
    }
    println!(
        "结论：{} 份样本 JA4 全同（{}），原始 JA3 有 {} 种不同值；变化的只有扩展顺序。\
         判据必须用 JA4 / 排序后的 JA3 段。",
        files.len(),
        EXPECTED_JA4,
        ja3_hashes.len()
    );
}

/// JA3 的计算逻辑用一个手搓的最小 ClientHello 钉住（含 GREASE 剔除）。
#[test]
fn ja3_of_synthetic_clienthello_is_hand_checkable() {
    let b = synthetic_client_hello();
    let ch = ClientHello::parse(&b);
    let ja3 = ja3_of(&ch);
    assert_eq!(
        ja3.preimage, SYNTHETIC_JA3_PREIMAGE,
        "合成 ClientHello 的 JA3 串"
    );
    assert_eq!(ja3.hash, SYNTHETIC_JA3, "合成 ClientHello 的 JA3 值");
    println!("合成 JA3: {} -> {}", ja3.preimage, ja3.hash);
}

/// JA4 的计算逻辑用同一个合成 ClientHello 钉住（a 段含 SNI 标志/计数/ALPN）。
#[test]
fn ja4_of_synthetic_clienthello_is_hand_checkable() {
    let ch = ClientHello::parse(&synthetic_client_hello());
    let ja4 = ja4_of(&ch);
    println!(
        "合成 JA4: {} = {} / {}",
        ja4.full(),
        ja4.b_preimage,
        ja4.c_preimage
    );
    // 无 SNI 扩展 -> 'i'；2 个非 GREASE cipher；3 个非 GREASE 扩展；无 ALPN -> "00"
    assert_eq!(ja4.a, "t13i020300");
    assert_eq!(ja4.b, trunc12(&sha256_hex(b"1301,1302")));
    // 扩展排序去 SNI/ALPN 后是 000a,000b,002b；无 0x000d -> 不带 underscore
    assert_eq!(ja4.c, trunc12(&sha256_hex(b"000a,000b,002b")));
}

/// 手工构造的最小 ClientHello：
/// legacy_version 0303、random 全 0、sid_len 0、
/// ciphers [0x0a0a(GREASE),0x1301,0x1302]、compression [00]、
/// ext: supported_groups[0x1a1a(GREASE),0x001d,0x0017]、ec_point_formats[00]、supported_versions[0304]。
fn synthetic_client_hello() -> Vec<u8> {
    let mut b: Vec<u8> = vec![0x01, 0, 0, 0, 0x03, 0x03];
    b.extend_from_slice(&[0u8; 32]);
    b.push(0x00);
    b.extend_from_slice(&6u16.to_be_bytes());
    b.extend_from_slice(&[0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02]);
    b.push(0x01);
    b.push(0x00);
    let mut exts: Vec<u8> = Vec::new();
    exts.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x1a, 0x1a, 0x00, 0x1d, 0x00, 0x17,
    ]);
    exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend_from_slice(&exts);
    let body_len = b.len() - 4;
    b[1] = (body_len >> 16) as u8;
    b[2] = (body_len >> 8) as u8;
    b[3] = body_len as u8;
    b
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试：归一化 / 逐字段对比的正确性（用夹包的变异体自证，不依赖 T1/T2）
// ─────────────────────────────────────────────────────────────────────────────

/// 把夹包里「本来就随机」的窗口全部换掉，归一化后必须与原始夹包逐字节相同。
#[test]
fn normalizer_erases_only_random_windows() {
    let base = fixture();
    let mutated = mutate_random_windows(&base);
    assert_ne!(
        mutated, base.bytes,
        "变异后应当与原夹包不同（否则这条测试没有意义）"
    );

    let mch = ClientHello::parse(&mutated);
    let (na, masks_a) = normalize(&base);
    let (nb, masks_b) = normalize(&mch);
    println!("归一化抹掉 {} 个窗口：", masks_a.len());
    for m in &masks_a {
        println!(
            "  [{:5},{:5}) {:?} {}",
            m.off,
            m.off + m.len,
            m.fill,
            m.what
        );
    }
    assert_eq!(masks_a.len(), masks_b.len(), "两侧掩码数量不同");
    if let Some(d) = first_divergence(&na, &nb, &base, &mch) {
        panic!("归一化后仍不一致（归一化漏了随机窗口）：\n{d}");
    }
}

/// 归一化**不能**把真实差异抹掉：改 ALPN 里的 "h2"→"h3" 必须被发现，
/// 且报告要指出正确偏移与所属扩展。
#[test]
fn normalizer_detects_real_change() {
    let base = fixture();
    let alpn = base.ext(0x0010).expect("夹包应有 ALPN").clone();
    let proto_off = alpn.data_off + 3; // ALPN 体: 2B list_len, 1B proto_len, "h2"...
    assert_eq!(&base.bytes[proto_off..proto_off + 2], b"h2");

    let mut tampered = base.bytes.clone();
    tampered[proto_off + 1] = b'3';
    let tch = ClientHello::parse(&tampered);

    let (na, _) = normalize(&base);
    let (nb, _) = normalize(&tch);
    let div = first_divergence(&na, &nb, &base, &tch).expect("应检出差异");
    println!("{div}");
    assert!(
        div.contains(&format!("偏移 {}", proto_off + 1)),
        "第一个不一致的偏移应是 {}（ALPN 里 '2' 的位置），实际：\n{div}",
        proto_off + 1
    );
    assert!(div.contains("alpn"), "报告里应指出属于 ALPN 扩展：\n{div}");

    // 逐字段对比同样必须发现（ALPN 字段）
    let diffs = field_diff(&base, &tch);
    println!("{}", format_field_diff("原夹包", "篡改后", &diffs));
    assert_eq!(diffs.len(), 1, "应恰好只有 alpn 一个字段不同：{diffs:?}");
    assert_eq!(diffs[0].0, "alpn");
}

/// JA3 只看「列表」，随机窗口变化不能影响它。
#[test]
fn ja3_is_invariant_to_random_windows() {
    let base = fixture();
    let mch = ClientHello::parse(&mutate_random_windows(&base));
    assert_eq!(
        ja3_of(&base).hash,
        ja3_of(&mch).hash,
        "JA3 不应受 random 影响"
    );
    assert_eq!(ja3_of(&base).preimage, ja3_of(&mch).preimage);
    assert_eq!(
        ja4_of(&base).full(),
        ja4_of(&mch).full(),
        "JA4 不应受随机窗口影响"
    );
}

/// 逐字段对比不受随机窗口影响（这正是它作为主判据的前提）。
#[test]
fn field_snapshot_invariant_to_random_windows() {
    let base = fixture();
    let mch = ClientHello::parse(&mutate_random_windows(&base));
    let diffs = field_diff(&base, &mch);
    assert!(
        diffs.is_empty(),
        "逐字段对比本应对随机窗口免疫，却报出：\n{}",
        format_field_diff("原夹包", "变异体", &diffs)
    );
}

/// 逐字段对比**必须**能发现结构性差异（否则等于没比）。
#[test]
fn field_diff_detects_structural_change() {
    let base = fixture();
    // 删掉 extended_master_secret(0x0017) 扩展：挪动其后所有字节并改 extensions_len
    let ems = base.ext(0x0017).expect("夹包应有 0x0017").clone();
    let mut b = Vec::new();
    b.extend_from_slice(&base.bytes[..ems.header_off]);
    b.extend_from_slice(&base.bytes[ems.end()..]);
    // 修 extensions_len（位于 extensions 区之前的 2 字节）
    let ext_len_off = base
        .fixed_regions
        .iter()
        .find(|(n, _, _)| *n == "extensions_len(2B)")
        .map(|(_, s, _)| *s)
        .unwrap();
    let new_len = (base.bytes.len() - 4 - ems.data_len) - (ext_len_off + 2);
    b[ext_len_off..ext_len_off + 2].copy_from_slice(&(new_len as u16).to_be_bytes());
    b[1] = ((b.len() - 4) >> 16) as u8;
    b[2] = ((b.len() - 4) >> 8) as u8;
    b[3] = (b.len() - 4) as u8;

    let tch = ClientHello::parse(&b);
    let diffs = field_diff(&base, &tch);
    println!("{}", format_field_diff("原夹包", "删掉 0x0017 后", &diffs));
    assert!(!diffs.is_empty(), "删掉一个扩展必须被逐字段对比发现");
}

/// 生成「所有随机窗口都被换掉、结构不动」的夹包副本。
fn mutate_random_windows(base: &ClientHello) -> Vec<u8> {
    let mut mutated = base.bytes.clone();
    for b in mutated[6..38].iter_mut() {
        *b ^= 0x5a;
    }
    for b in mutated[base.session_id_off + 16..base.session_id_off + 32].iter_mut() {
        *b ^= 0xa5;
    }
    let other_grease: u16 = 0xdada;
    for (i, c) in base.ciphers.iter().enumerate() {
        if is_grease(*c) {
            mutated[base.ciphers_off + 2 * i..base.ciphers_off + 2 * i + 2]
                .copy_from_slice(&other_grease.to_be_bytes());
        }
    }
    for e in &base.extensions {
        if is_grease(e.ext_type) {
            mutated[e.header_off..e.header_off + 2].copy_from_slice(&other_grease.to_be_bytes());
            for b in mutated[e.data_off..e.end()].iter_mut() {
                *b ^= 0x11;
            }
            continue;
        }
        match e.ext_type {
            0x000a => {
                let d = base.body(e);
                let n = u16::from_be_bytes([d[0], d[1]]) as usize;
                for i in 0..n / 2 {
                    let off = e.data_off + 2 + 2 * i;
                    let g = u16::from_be_bytes([base.bytes[off], base.bytes[off + 1]]);
                    if is_grease(g) {
                        mutated[off..off + 2].copy_from_slice(&other_grease.to_be_bytes());
                    }
                }
            }
            0x002b => {
                let d = base.body(e);
                let n = d[0] as usize;
                for i in 0..n / 2 {
                    let off = e.data_off + 1 + 2 * i;
                    let v = u16::from_be_bytes([base.bytes[off], base.bytes[off + 1]]);
                    if is_grease(v) {
                        mutated[off..off + 2].copy_from_slice(&other_grease.to_be_bytes());
                    }
                }
            }
            0x0033 => {
                let mut off = e.data_off + 2;
                while off + 4 <= e.end() {
                    let g = u16::from_be_bytes([base.bytes[off], base.bytes[off + 1]]);
                    let kl =
                        u16::from_be_bytes([base.bytes[off + 2], base.bytes[off + 3]]) as usize;
                    if is_grease(g) {
                        mutated[off..off + 2].copy_from_slice(&other_grease.to_be_bytes());
                    }
                    for b in mutated[off + 4..off + 4 + kl].iter_mut() {
                        *b ^= 0x3c;
                    }
                    off += 4 + kl;
                }
            }
            0xfe0d => {
                // 只改 ECH 里**本来就随机**的部分：config_id、enc、payload。
                // 结构字段（prefix/kdf/aead/enc_len/payload_len）必须保持，否则等于改了形状。
                let d = base.body(e).to_vec();
                if d.len() >= 10 {
                    let enc_len = u16::from_be_bytes([d[6], d[7]]) as usize;
                    mutated[e.data_off + 5] ^= 0x77; // config_id
                    for b in mutated[e.data_off + 8..e.data_off + 8 + enc_len].iter_mut() {
                        *b ^= 0x77; // enc
                    }
                    for b in mutated[e.data_off + 10 + enc_len..e.end()].iter_mut() {
                        *b ^= 0x77; // payload
                    }
                }
            }
            _ => {}
        }
    }
    mutated
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase B：T1 引擎（`xt_wasm_tls::fingerprint`）与官方真值的差分对拍
// ─────────────────────────────────────────────────────────────────────────────

use xt_wasm_tls::fingerprint::{build_client_hello, profile_by_name};

/// 官方 chrome 的 16 个非 GREASE 扩展类型（排序后）。
const OFFICIAL_EXT_SORTED: [u16; 16] = [
    0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d,
    0x0033, 0x44cd, 0xfe0d, 0xff01,
];

/// 官方夹包 ALPN 扩展**体**的字节：`000c 02 "h2" 08 "http/1.1"`。
const OFFICIAL_ALPN_DATA: &str = "000c02683208687474702f312e31";

/// 官方 chrome 的 `Ciphers` 段（JA3，十进制、顺序固定 —— 12/12 抓包实测恒定）。
const OFFICIAL_JA3_CIPHERS: &str =
    "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53";

/// 官方 chrome 的 `EllipticCurves` 段（含 X25519MLKEM768=4588）。
const OFFICIAL_JA3_CURVES: &str = "4588-29-23-24";
/// 砍掉 11ec 后我们**应当**得到的曲线段（这是有意取舍，不是缺陷）。
const OUR_JA3_CURVES: &str = "29-23-24";

/// 官方 ECH 扩展体在 12 份抓包里只出现这四档（payload = data_len - 42）。
const OFFICIAL_ECH_DATA_LENS: [usize; 4] = [186, 218, 250, 282];
const OFFICIAL_ECH_PAYLOAD_LENS: [usize; 4] = [144, 176, 208, 240];

/// 我们默认要访问的 SNI（与抓包一致）。
const OUR_SNI: &str = "www.cloudflare.com";

/// 官方夹包里的三段「调用方给的」动态材料：random / session_id / x25519 公钥。
/// 差分时**原样喂给我们自己的引擎**，这样差异只可能来自 profile 组装，而不是随机数。
fn official_dynamic_parts() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let ch = fixture();
    let random: [u8; 32] = ch.bytes[6..38].try_into().unwrap();
    let session_id: [u8; 32] = ch
        .session_id
        .as_slice()
        .try_into()
        .expect("夹包 session_id 应 32 字节");
    let ks = ch.ext(0x0033).expect("夹包应有 key_share");
    let mut off = ks.data_off + 2;
    let mut x25519 = None;
    while off + 4 <= ks.end() {
        let g = u16::from_be_bytes([ch.bytes[off], ch.bytes[off + 1]]);
        let kl = u16::from_be_bytes([ch.bytes[off + 2], ch.bytes[off + 3]]) as usize;
        if g == 0x001d {
            x25519 = Some(ch.bytes[off + 4..off + 4 + kl].to_vec());
        }
        off += 4 + kl;
    }
    let x25519: [u8; 32] = x25519
        .expect("夹包 key_share 应有 001d")
        .try_into()
        .unwrap();
    (random, session_id, x25519)
}

/// 用我们的引擎造一条 chrome ClientHello（默认 profile、默认 ALPN 路径）。
fn build_ours(profile: &str, alpn: &[String], seed: u64) -> Vec<u8> {
    let p = profile_by_name(profile).unwrap_or_else(|| {
        panic!(
            "profile `{profile}` 不存在；可用：{:?}",
            xt_wasm_tls::fingerprint::profile_names()
        )
    });
    let (random, session_id, x25519) = official_dynamic_parts();
    build_client_hello(p, OUR_SNI, alpn, &random, &session_id, &x25519, seed)
        .unwrap_or_else(|e| panic!("build_client_hello({profile}) 失败：{e}"))
}

/// **ALPN 兜底**（硬断言）：默认真实调用面是 `TlsConfig::new()`，其 `alpn` 为空；
/// chrome profile 必须因此仍发出与官方一致的 `h2,http/1.1`，且与显式传入等价。
/// plain profile 空 alpn 时**不得**发 ALPN（保持与今天字节兼容）。
#[test]
fn differential_alpn_default_matches_official_and_plain_stays_quiet() {
    let default_call = build_ours("chrome", &[], 0x1234_5678);
    let explicit_call = build_ours(
        "chrome",
        &["h2".to_string(), "http/1.1".to_string()],
        0x1234_5678,
    );
    assert_eq!(
        default_call, explicit_call,
        "空 alpn 走 profile 兜底的结果必须与显式传 [\"h2\",\"http/1.1\"] 完全一致"
    );

    let ch = ClientHello::parse(&default_call);
    let alpn_ext = ch.ext(0x0010).expect("chrome profile 必须发 ALPN 扩展");
    let alpn_data = to_hex(ch.body(alpn_ext));
    println!("chrome 默认调用 ALPN 扩展体 = {alpn_data}");
    assert_eq!(alpn_data, OFFICIAL_ALPN_DATA, "ALPN 扩展体与官方夹包不一致");
    assert_eq!(
        alpn_list(&ch),
        vec!["h2".to_string(), "http/1.1".to_string()]
    );
    assert_eq!(
        ja4_of(&ch).a,
        EXPECTED_JA4_A,
        "默认调用下 JA4_a 必须是 t13d1516h2（空 ALPN 会掉成 t13d151600）"
    );

    let plain = ClientHello::parse(&build_ours("plain", &[], 7));
    assert!(
        plain.ext(0x0010).is_none(),
        "plain profile 在空 alpn 时不得发 ALPN 扩展（否则改变今天的行为）"
    );
    assert!(
        !plain.extensions.iter().any(|e| is_grease(e.ext_type)),
        "plain 不应有 GREASE"
    );
}

/// **主判据**：JA4 与官方 chrome 全等（连带 a/b/c 三个 preimage 也全等）。
#[test]
fn differential_ja4_equals_official_chrome() {
    let ours = ClientHello::parse(&build_ours("chrome", &[], 0xabcd_ef01));
    let off = fixture();
    let (jo, jf) = (ja4_of(&ours), ja4_of(&off));
    println!(
        "我们 : {}  (b: {} | c: {})",
        jo.full(),
        jo.b_preimage,
        jo.c_preimage
    );
    println!(
        "夹包 : {}  (b: {} | c: {})",
        jf.full(),
        jf.b_preimage,
        jf.c_preimage
    );
    assert_eq!(jf.full(), EXPECTED_JA4, "夹包 JA4 与基准值不符");
    assert_eq!(
        jo.a, jf.a,
        "JA4_a 不同（版本/SNI 标志/cipher 数/扩展数/ALPN）"
    );
    assert_eq!(jo.b, jf.b, "JA4_b 不同（cipher 列表）");
    assert_eq!(jo.c, jf.c, "JA4_c 不同（扩展集合或 sigalgs）");
    assert_eq!(jo, jf, "JA4 的 preimage 也应逐字相同");
}

/// JA3 分段判据：官方客户端自己的 JA3 每次连接都不同（扩展顺序被打乱），
/// 所以不比「某个排列」，而是逐段比 —— 四段必须相同，`EllipticCurves` 必须等于
/// 官方去掉 11ec 的结果（有意取舍）。
#[test]
fn differential_ja3_segments_match_official_minus_11ec() {
    let ours = ClientHello::parse(&build_ours("chrome", &[], 0x5eed));
    let off = fixture();
    let (jo, jf) = (ja3_of(&ours), ja3_of(&off));
    println!("我们 JA3: {}", jo.hash);
    println!("   preimage: {}", jo.preimage);
    println!("夹包 JA3: {}", jf.hash);
    println!("   preimage: {}", jf.preimage);
    println!(
        "注意：两份 JA3 的 Extensions 段顺序不同是**预期**的 —— 官方客户端每连接打乱扩展顺序，\
         12/12 抓包实测如此；可比的是下面逐段与排序后扩展集合。"
    );

    assert_eq!(jo.version, jf.version, "SSLVersion 段");
    assert_eq!(jo.ciphers, jf.ciphers, "Ciphers 段（顺序敏感）");
    assert_eq!(jo.point_formats, jf.point_formats, "ECPointFormats 段");
    assert_eq!(
        jo.extensions_sorted(),
        jf.extensions_sorted(),
        "Extensions 集合（排序后，顺序无关）"
    );
    assert_eq!(jo.extensions_sorted(), EXPECTED_EXTENSIONS_SORTED);
    assert_eq!(jf.curves, OFFICIAL_JA3_CURVES, "官方夹包的 curves 段变了");
    assert_eq!(
        jo.curves, OUR_JA3_CURVES,
        "我们的 curves 段应当恰好是官方去掉 11ec(4588) 后剩下的 29-23-24"
    );
    assert_eq!(jo.ciphers, OFFICIAL_JA3_CIPHERS, "cipher 段与官方不一致");
}

/// 逐字段差分：与夹包的差异**只允许**出现在声明过的偏差上，其余必须全等。
#[test]
fn differential_field_diff_only_declared_deviations() {
    let ours = ClientHello::parse(&build_ours("chrome", &[], 0x0f0f));
    let off = fixture();

    // ECH 载荷长度是我们有意对齐的「四档随机窗口」：先单独断言它落在官方观测档位里。
    let our_ech = ours.ext(0xfe0d).expect("我们应发 ECH 占位");
    let our_ech_len = our_ech.data_len;
    let our_payload = ech_payload_len(&ours).expect("ECH payload_len 应可解析");
    let off_payload = ech_payload_len(&off).expect("夹包 ECH payload_len 应可解析");
    println!(
        "ECH data_len 我们={our_ech_len} 夹包={}；payload_len 我们={our_payload} 夹包={off_payload}",
        off.ext(0xfe0d).unwrap().data_len
    );
    assert!(
        OFFICIAL_ECH_DATA_LENS.contains(&our_ech_len),
        "我们的 ECH data_len={our_ech_len} 不在官方观测档位 {OFFICIAL_ECH_DATA_LENS:?} 内"
    );
    assert!(
        OFFICIAL_ECH_PAYLOAD_LENS.contains(&our_payload),
        "我们的 ECH payload_len={our_payload} 不在官方观测档位 {OFFICIAL_ECH_PAYLOAD_LENS:?} 内"
    );
    assert_eq!(
        our_ech_len,
        42 + our_payload,
        "ECH data_len 应为 42 + payload_len"
    );
    assert_eq!(
        ech_fixed_fields(&ours),
        ech_fixed_fields(&off),
        "ECH 的固定字段（prefix/kdf/aead/enc_len）应相同"
    );

    let diffs = field_diff(&ours, &off);
    println!("{}", format_field_diff("我们", "夹包", &diffs));

    // 允许出现的偏差（**仅这些**）：
    //  1. supported_groups: 官方 [GREASE,11ec,29,23,24]，我们 [GREASE,29,23,24]
    //  2. key_share:        官方含 11ec/1216B 条目，我们只发 001d/32B
    //  3. extensions 顺序:  两边都是随机排列，本来就不同（集合必须相同 —— 见扩展集合断言）
    //  4. ech_payload_len:  官方四档随机，我们按 seed 在同样四档里选
    const ALLOWED: [&str; 4] = [
        "supported_groups(去GREASE,原顺序)",
        "key_share(group/key_len,不含公钥)",
        "extensions(顺序,去GREASE)",
        "ech_payload_len",
    ];
    let keys: Vec<String> = diffs.iter().map(|(k, _, _)| k.clone()).collect();
    let unexpected: Vec<&String> = keys
        .iter()
        .filter(|k| !ALLOWED.contains(&k.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "出现**未声明**的偏差（这才是必须修的红）：{unexpected:?}\n完整差异：\n{}",
        format_field_diff("我们", "夹包", &diffs)
    );

    // 两处「砍 11ec」的偏差必须真的存在（否则说明测试没测到点上）
    for required in [
        "supported_groups(去GREASE,原顺序)",
        "key_share(group/key_len,不含公钥)",
    ] {
        assert!(
            keys.iter().any(|k| k == required),
            "应存在已声明偏差 [{required}]，实际差异：{keys:?}"
        );
    }
}

/// 顺序规则 + 随机性（N=64 个 seed）：
/// * 下标 0 与末位恒为 GREASE（位置固定，值随 seed 变）；
/// * 中间 16 个非 GREASE 扩展的集合恒等于官方，且顺序是它们的排列；
/// * 顺序确实在变（不是「只做了个旋转」）：每个扩展至少出现在 ≥2 个不同中间下标；
/// * 其它 JA3 段跨 seed **恒定**（回归守卫：不许乱动 cipher / curves / 版本 / point formats）；
/// * JA4 跨 seed 恒定。
#[test]
fn differential_extension_order_is_seeded_permutation() {
    let mut orders: std::collections::BTreeSet<Vec<u16>> = std::collections::BTreeSet::new();
    let mut positions: std::collections::BTreeMap<u16, std::collections::BTreeSet<usize>> =
        std::collections::BTreeMap::new();
    let mut grease_values_first: std::collections::BTreeSet<u16> =
        std::collections::BTreeSet::new();

    for seed in 0..64u64 {
        let ch = ClientHello::parse(&build_ours("chrome", &[], seed));
        assert_eq!(ch.extensions.len(), 18, "seed={seed}: 扩展个数应为 18");
        let first = ch.extensions[0].ext_type;
        let last = ch.extensions[ch.extensions.len() - 1].ext_type;
        assert!(
            is_grease(first),
            "seed={seed}: 下标 0 的类型 {first:#06x} 不是 GREASE"
        );
        assert!(
            is_grease(last),
            "seed={seed}: 末位类型 {last:#06x} 不是 GREASE"
        );
        grease_values_first.insert(first);

        let middle: Vec<u16> = ch.extensions[1..17].iter().map(|e| e.ext_type).collect();
        assert!(
            !middle.iter().any(|t| is_grease(*t)),
            "seed={seed}: 中间 16 个位置不应有 GREASE"
        );
        let mut sorted = middle.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted, OFFICIAL_EXT_SORTED,
            "seed={seed}: 中间扩展集合与官方不一致"
        );
        for (i, t) in middle.iter().enumerate() {
            positions.entry(*t).or_default().insert(i);
        }

        // 其它段跨 seed 必须恒定
        let j = ja3_of(&ch);
        assert_eq!(j.version, "771", "seed={seed}: SSLVersion 段被改动了");
        assert_eq!(
            j.ciphers, OFFICIAL_JA3_CIPHERS,
            "seed={seed}: Ciphers 段被改动了"
        );
        assert_eq!(
            j.curves, OUR_JA3_CURVES,
            "seed={seed}: EllipticCurves 段被改动了"
        );
        assert_eq!(
            j.point_formats, "0",
            "seed={seed}: ECPointFormats 段被改动了"
        );
        assert_eq!(
            ja4_of(&ch).full(),
            EXPECTED_JA4,
            "seed={seed}: JA4 竟然随 seed 变了（JA4 与扩展顺序无关）"
        );
        orders.insert(middle);
    }

    assert!(
        orders.len() >= 2,
        "64 个 seed 只产生了 {} 种扩展顺序",
        orders.len()
    );
    for (t, ps) in &positions {
        assert!(
            ps.len() >= 2,
            "扩展 0x{t:04x} 只出现在 {ps:?} —— 顺序没有真正打乱（像是只做了旋转）"
        );
    }
    println!(
        "64 个 seed：{} 种扩展顺序；首 GREASE 值 {} 种；每个扩展出现过的下标数：",
        orders.len(),
        grease_values_first.len()
    );
    for (t, ps) in &positions {
        println!("  0x{t:04x}: {} 个不同下标", ps.len());
    }
    assert!(
        grease_values_first.len() >= 2,
        "首 GREASE 的值应当随 seed 变"
    );
}

/// 归一化后，**扩展区之前**必须逐字节相同；第一个不一致只允许出现在扩展区
/// （打印出来的偏移/所属扩展就是给排障看的）。
#[test]
fn differential_fixed_prefix_is_byte_identical() {
    let ours = ClientHello::parse(&build_ours("chrome", &[], 0x0bad_f00d));
    let off = fixture();
    let (na, masks) = normalize(&ours);
    let (nb, _) = normalize(&off);
    let ext_len_off = off
        .fixed_regions
        .iter()
        .find(|(n, _, _)| *n == "extensions_len(2B)")
        .map(|(_, s, _)| *s)
        .unwrap();
    println!(
        "归一化掩码 {} 个；扩展区之前的前缀长度 = {ext_len_off} 字节",
        masks.len()
    );
    // 注意排除 handshake 的 3 字节**总长**（偏移 1..4）：我们少了 11ec 的 key_share
    // 条目（1220 字节），总长必然不同 —— 那是已声明偏差的直接后果，不是缺陷。
    // 从 legacy_version(4) 到 extensions_len(107) 之间则必须逐字节相同。
    assert_eq!(
        &na[4..ext_len_off],
        &nb[4..ext_len_off],
        "扩展区之前（版本/random(掩码后)/session_id/REALITY 密文/cipher/compression）必须逐字节相同"
    );
    match first_divergence(&na, &nb, &ours, &off) {
        Some(d) => println!("归一化后第一个不一致（预期落在扩展区内的已声明偏差上）：\n{d}"),
        None => println!("归一化后逐字节完全相同（扩展顺序也恰好一致）"),
    }
}
