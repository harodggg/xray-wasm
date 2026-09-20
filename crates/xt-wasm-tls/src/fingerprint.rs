//! ClientHello 指纹 profile 引擎。
//!
//! 本模块只做一件事：把「一个浏览器 profile + 调用方给的动态字段」拼成一条
//! TLS 1.3 ClientHello **握手消息**字节（首字节 `HS_CLIENT_HELLO(0x01)`，随后 3
//! 字节长度；不含 5 字节 TLS record 头）。它是纯函数：同样入参必然得到同样字节。
//!
//! # 唯一权威对照
//!
//! `testdata/xray-clienthello.hex` 是官方 Xray 客户端 `fingerprint: chrome`
//! 真实发出的一条 ClientHello（1787 字节，抓法见 `docs/verification-log.md` V18）。
//! `chrome` profile 的 cipher 列表、18 个扩展的**集合与各自取值**逐字段对齐它，
//! **只有下面「显式偏差清单」里的两处不同**；本文件末尾的单测会逐字段比对
//! （扩展顺序无关，因为线上顺序每次都打乱，见下），并在出现第三处偏差时直接
//! 失败。不要凭记忆改这里任何一个常量 —— 先改夹包，再改代码。
//!
//! # 扩展顺序每连接打乱（chrome）
//!
//! 官方客户端 9 次抓包的实测：JA3 9/9 互不相同，JA4 9/9 完全相同，扩展**集合**
//! 9/9 相同而**顺序**每次被 uTLS 打乱。因此 `chrome` profile 固定会被
//! [`shuffle_extensions`] 按 `grease_seed` 做一次 Fisher–Yates：同 seed 可复现，
//! 不同 seed 顺序不同；只重排，不增删、不改任何扩展内容。`plain` 保持固定顺序
//! （回归基准）。若固定一个排列，我们跨连接的 JA3 会完全一样，反而比不伪装更
//! 好识别 —— 这是跨连接特征，不是单次指纹问题。
//!
//! # 默认 ALPN（chrome）
//!
//! 调用方没给 ALPN（空列表）时用 `Profile::default_alpn`：`chrome` 是
//! `["h2", "http/1.1"]`，`plain` 是空。有效 ALPN 列表为空才不发 ALPN 扩展。
//! 这样 `TlsConfig::new()` 的默认空 `alpn` 也能得到真 Chrome 的 `t13…h2`
//! JA4_a 形态；用户显式设置的 ALPN 永远优先。
//!
//! # 显式偏差清单（有意，有代价；不是过渡状态）
//!
//! 1. `supported_groups`：夹包是 `[GREASE, 0x11ec, 0x001d, 0x0017, 0x0018]`，
//!    我们发 `[GREASE, 0x001d, 0x0017, 0x0018]` —— **少了 X25519MLKEM768(0x11ec)**。
//! 2. `key_share`：夹包是 `[{GREASE,1B}, {0x11ec,1216B}, {0x001d,32B}]`，
//!    我们发 `[{GREASE,1B}, {0x001d,32B}]` —— 同样少了 11ec 条目
//!    （随之整体偏移与总长度变化，不能按绝对偏移比对）。
//! 3. 以下位置本来就每次连接不同，不参与比对：`random`、`session_id[16..32]`
//!    （前 16 字节是 REALITY 密文，必须原样保留并比对）、6 个 GREASE 值、
//!    x25519 公钥、ECH 的 config_id/enc/payload 以及**载荷长度本身**（4 档，
//!    见下）。另外 16 个非 GREASE 扩展的**顺序**每连接被打乱（见下）。
//!
//! 为什么必须砍掉 11ec（不是「为了少 1216 字节」）：RFC 8446 §4.1.1 规定，凡是
//! 在 `supported_groups` 里声明、却没给出对应 `key_share` 的组，服务端 **MUST**
//! 回 HelloRetryRequest；而 `reality.rs` 明确把 HRR 判为握手失败，我们也没有
//! ML-KEM 实现。security 实测（cloudflare.com 等 5 个 SNI，5/5）：声明
//! `11ec` 而不给 share 全部触发 HRR → 连接直接失败；砍掉后 5/5 正常。
//! 砍掉后得到的是一个**自洽**的形状：等价于「PQ 尚未默认开启的 Chrome」。
//! **不要**为了让字节数与夹包一致去补一段随机字节冒充 11ec 的 key share ——
//! 对端一旦选中它就算不出共享密钥，握手会以更隐蔽的方式失败。
//!
//! # 另一处「发了但不可用」（代价照写）
//!
//! ECH(`0xfe0d`) 只发**结构合法的 GREASE ECH 占位**（type/kdf/aead 固定，
//! config_id、enc、payload 由 seed 派生），真实 ECH 我们也发不了。代价：
//! 强制要求真实 ECH 的对端会拒绝；收益是扩展集合与长度与 Chrome 一致。
//! 验证方式见 T3/T4（对端观测 + 真实握手回归），本模块不声称它可用。
//!
//! # GREASE 规则
//!
//! Chrome 一轮 ClientHello 里 GREASE 值出现在 6 个位置，且**每次连接不同**：
//! cipher 首位、扩展 `0x0A0A`、`supported_groups` 首位、`key_share` 首位
//! （必须与 `supported_groups` 的那个相等，否则结构非法）、
//! `supported_versions` 首位、末尾扩展 `0x9A9A`。全部由调用方传入的
//! `grease_seed` 派生（[`new_grease_seed`] 提供 CSPRNG 种子），**没有任何写死的
//! GREASE 常量**。夹包实测（`capture_grease_positions` 单测）：cipher=`0x3a3a`
//! 与扩展 `0x0A0A` 的值**并不相等**，真正必须成对的是 groups 与 key_share
//! （夹包里都是 `0x6a6a`）；本实现据此派生 5 个互不相同的值，
//! key_share 复用 groups 的那个。
//!
//! # REALITY 认证依赖的字节位置（不得改动语义）
//!
//! `reality.rs` 用 `hello[6..26]`（random 字段前 20 字节）参与 HKDF，并把
//! REALITY 认证密文写进 `session_id`（`hello[39..71]`，前 16 字节密文 + 16 字节
//! GCM tag）。因此本模块：
//!
//! * `random` 原样写在 `hello[6..38]`，不重排、不置零；
//! * `session_id` 由调用方传入并**原样**写在 `hello[39..71]`，不清零、不随机化；
//! * `legacy_version` 固定 `0x0303`（JA3 用的是它）、`session_id_len` 固定 32、
//!   压缩方式固定 `01 00`（长度 1 + null），这三处是 JA3 的 SSLVersion 段，
//!   不要为了「扩展对齐」而忽略它们。
//!
//! 拼接顺序固定为 legacy_version / random / session_id_len / session_id /
//! cipher 列表 / 压缩方式 / 扩展块，保证上述偏移恒成立。

use thiserror::Error;

/// 默认 profile 名。调用方在「未配置」时用它，本模块不替调用方兜底。
pub const DEFAULT_PROFILE_NAME: &str = "chrome";

/// 全部可用 profile 名，顺序稳定、无重复，且包含 [`DEFAULT_PROFILE_NAME`]。
pub fn profile_names() -> &'static [&'static str] {
    PROFILE_NAMES
}

const PROFILE_NAMES: &[&str] = &["chrome", "plain"];

const HS_CLIENT_HELLO: u8 = 0x01;
const SESSION_ID_LEN: u8 = 32;
const LEGACY_VERSION_TLS12: u16 = 0x0303;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

// GREASE ECH 占位的固定部分与长度。32 字节 enc + 载荷档位抄自官方抓包：
// 总长 1723/1755/1787/1819 对应载荷 144/176/208/240，粒度 32。Chrome 改版可能
// 漂移，改动前先重新抓包（见模块文档「唯一权威对照」）。
const ECH_KDF_ID: u16 = 0x0001;
const ECH_AEAD_ID: u16 = 0x0001;
const ECH_ENC_LEN: usize = 32;
const ECH_PAYLOAD_MIN: usize = 144;
const ECH_PAYLOAD_STEP: usize = 32;
const ECH_PAYLOAD_BUCKETS: usize = 4;

/// `build_client_hello` 的失败原因。全部是「调用方入参装不进线上长度字段」。
#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("SNI 太长：{0} 字节，上限 65535")]
    ServerNameTooLong(usize),
    #[error("ALPN 协议名太长：{0} 字节，上限 255")]
    AlpnIdTooLong(usize),
    #[error("ALPN 列表太长：{0} 字节，上限 65535")]
    AlpnListTooLong(usize),
    #[error("扩展 {ext:#06x} 的数据太长：{len} 字节，上限 65535")]
    ExtensionDataTooLong { ext: u16, len: usize },
    #[error("扩展块太长：{0} 字节，上限 65535")]
    ExtensionsTooLong(usize),
    #[error("ClientHello 太长：{0} 字节，超过 24 位长度字段上限")]
    ClientHelloTooLong(usize),
}

/// 一个 ClientHello 指纹 profile。
///
/// 字段私有：语义只能通过 [`profile_by_name`] 与 [`Profile::name`] 观察，
/// 免得调用方拿它当可变配置用。
pub struct Profile {
    name: &'static str,
    legacy_version: u16,
    ciphers: &'static [CipherSlot],
    extension_order: &'static [Ext],
    signature_algorithms: &'static [u16],
    supported_groups: &'static [u16],
    supported_versions: &'static [u16],
    ec_point_formats: &'static [u8],
    /// 调用方没给 ALPN（空列表）时用的默认值。有效 ALPN 列表为空时才不发
    /// ALPN 扩展；因此 `chrome` 默认一定带 ALPN，`plain` 保持旧形状。
    default_alpn: &'static [&'static str],
    /// `true`：每次连接按 `grease_seed` 打乱扩展顺序（Chrome/uTLS 行为）；
    /// `false`：固定用 `extension_order`（`plain` 回归基准）。
    shuffle_extension_order: bool,
    /// `true`：`supported_versions` 列表首位加一个 GREASE 版本。
    grease_supported_versions: bool,
    /// `true`：`supported_groups` 列表首位加一个 GREASE 组。
    grease_supported_groups: bool,
    /// `true`：`key_share` 首位加一个 GREASE 条目（组号与 supported_groups 的那个相同）。
    grease_key_share: bool,
}

impl Profile {
    /// profile 名，与 [`profile_by_name`] 接受的字符串完全一致。
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// profile 自带的默认 ALPN；空切片 = 不注入默认（`plain`）。
    ///
    /// 只描述 profile 自带的那份：调用方显式传了 ALPN 时以调用方为准
    /// （[`build_client_hello`] 里才有这个优先级判断）。
    pub fn default_alpn(&self) -> &'static [&'static str] {
        self.default_alpn
    }
}

/// cipher 列表里的一项：可能是 GREASE 占位，也可能是真 cipher suite。
#[derive(Clone, Copy)]
enum CipherSlot {
    Grease,
    Suite(u16),
}

/// 扩展模板。顺序由 [`Profile::extension_order`] 给出，即线上顺序。
#[derive(Clone, Copy)]
enum Ext {
    /// 类型为 GREASE 的首位空扩展（夹包里是 `0x0A0A`）。
    GreaseEmpty,
    Alpn,
    SctEmpty,
    RenegotiationInfo,
    ExtendedMasterSecret,
    ServerName,
    StatusRequest,
    CompressCertificate,
    KeyShare,
    SignatureAlgorithms,
    PskKeyExchangeModes,
    SupportedVersions,
    /// GREASE ECH 占位（`0xfe0d`），见模块文档。
    GreaseEch,
    SessionTicketEmpty,
    EcPointFormats,
    SupportedGroups,
    /// ALPS(`0x44cd`)，内容固定 `h2`（抄自夹包）。
    ApplicationSettings,
    /// 类型为 GREASE 的末尾扩展（夹包里是 `0x9A9A`），数据 1 字节 `0x00`。
    GreaseTrailing,
}

/// `chrome`：逐字段对齐 `testdata/xray-clienthello.hex`，
/// 只差模块文档「显式偏差清单」里的 11ec 两处（有意）。
static CHROME: Profile = Profile {
    name: "chrome",
    legacy_version: LEGACY_VERSION_TLS12,
    ciphers: &[
        CipherSlot::Grease,
        CipherSlot::Suite(TLS_AES_128_GCM_SHA256),
        CipherSlot::Suite(0x1302),
        CipherSlot::Suite(0x1303),
        CipherSlot::Suite(0xc02b),
        CipherSlot::Suite(0xc02f),
        CipherSlot::Suite(0xc02c),
        CipherSlot::Suite(0xc030),
        CipherSlot::Suite(0xcca9),
        CipherSlot::Suite(0xcca8),
        CipherSlot::Suite(0xc013),
        CipherSlot::Suite(0xc014),
        CipherSlot::Suite(0x009c),
        CipherSlot::Suite(0x009d),
        CipherSlot::Suite(0x002f),
        CipherSlot::Suite(0x0035),
    ],
    extension_order: &[
        Ext::GreaseEmpty,
        Ext::Alpn,
        Ext::SctEmpty,
        Ext::RenegotiationInfo,
        Ext::ExtendedMasterSecret,
        Ext::ServerName,
        Ext::StatusRequest,
        Ext::CompressCertificate,
        Ext::KeyShare,
        Ext::SignatureAlgorithms,
        Ext::PskKeyExchangeModes,
        Ext::SupportedVersions,
        Ext::GreaseEch,
        Ext::SessionTicketEmpty,
        Ext::EcPointFormats,
        Ext::SupportedGroups,
        Ext::ApplicationSettings,
        Ext::GreaseTrailing,
    ],
    signature_algorithms: &[
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ],
    // 夹包这里是 [0x11ec, 0x001d, 0x0017, 0x0018]；11ec 被有意砍掉，见模块文档。
    supported_groups: &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
    supported_versions: &[0x0304, 0x0303],
    ec_point_formats: &[0x00],
    default_alpn: &["h2", "http/1.1"],
    shuffle_extension_order: true,
    grease_supported_versions: true,
    grease_supported_groups: true,
    grease_key_share: true,
};

/// `plain`：reality.rs 里那套精简形状（1 个 cipher、无 GREASE），
/// 作为「不想伪装」的选项与旧行为的回归基准。
static PLAIN: Profile = Profile {
    name: "plain",
    legacy_version: LEGACY_VERSION_TLS12,
    ciphers: &[CipherSlot::Suite(TLS_AES_128_GCM_SHA256)],
    extension_order: &[
        Ext::ServerName,
        Ext::SupportedGroups,
        Ext::EcPointFormats,
        Ext::SignatureAlgorithms,
        Ext::Alpn,
        Ext::SessionTicketEmpty,
        Ext::SupportedVersions,
        Ext::PskKeyExchangeModes,
        Ext::KeyShare,
    ],
    signature_algorithms: &[0x0807, 0x0403, 0x0804, 0x0805],
    supported_groups: &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
    supported_versions: &[0x0304, 0x0303],
    ec_point_formats: &[0x00],
    default_alpn: &[],
    shuffle_extension_order: false,
    grease_supported_versions: false,
    grease_supported_groups: false,
    grease_key_share: false,
};

/// 按名字取 profile：**大小写敏感的精确匹配**，未知名字返回 `None`。
///
/// `None`/`""` 到默认 profile 的映射是调用方的事（[`DEFAULT_PROFILE_NAME`] 只
/// 提供那个名字），本函数不兜底、不做别名猜测。
pub fn profile_by_name(name: &str) -> Option<&'static Profile> {
    match name {
        "chrome" => Some(&CHROME),
        "plain" => Some(&PLAIN),
        _ => None,
    }
}

/// 取一个来自 CSPRNG 的 GREASE 种子，供 [`build_client_hello`] 的 `grease_seed` 用。
///
/// 每次调用都应产生新值：GREASE 的全部意义就是「每次连接不同」。
pub fn new_grease_seed() -> u64 {
    rand::random::<u64>()
}

/// 组装 handshake 消息（不含 5 字节 TLS record 头）。
///
/// * `random` / `session_id` 原样使用：`session_id` 前 16 字节是调用方填好的
///   REALITY 认证密文，本函数不清零、不随机化、不重排；后 16 字节（GCM tag）
///   也由调用方给出。调用方若要随机化后 16 字节，请在**调用前**做好。
/// * `key_share_x25519` 是调用方持有的 x25519 公钥；`chrome` profile 会把它放进
///   `key_share` 的 `0x001d` 条目（`0x11ec` 条目故意缺席，见模块文档）。
/// * `grease_seed` 决定全部 GREASE 值与 GREASE ECH 占位的填充字节：同 seed 同
///   输出（可复现），不同 seed 不同输出。
pub fn build_client_hello(
    profile: &Profile,
    server_name: &str,
    alpn: &[String],
    random: &[u8; 32],
    session_id: &[u8; 32],
    key_share_x25519: &[u8; 32],
    grease_seed: u64,
) -> Result<Vec<u8>, FingerprintError> {
    let grease = Grease::from_seed(grease_seed);

    // 偏移是契约：random 必须在 hello[6..38]，session_id 必须在 hello[39..71]。
    let mut body = Vec::with_capacity(600);
    body.extend_from_slice(&profile.legacy_version.to_be_bytes());
    body.extend_from_slice(random);
    body.push(SESSION_ID_LEN);
    body.extend_from_slice(session_id);

    let mut ciphers = Vec::with_capacity(profile.ciphers.len() * 2);
    for slot in profile.ciphers {
        match slot {
            CipherSlot::Grease => put_u16(grease.cipher, &mut ciphers),
            CipherSlot::Suite(id) => put_u16(*id, &mut ciphers),
        }
    }
    put_u16(ciphers.len() as u16, &mut body);
    body.extend_from_slice(&ciphers);

    // compression_methods：长度 1 + null。
    body.push(0x01);
    body.push(0x00);

    // 有效 ALPN：调用方给了就用调用方的；没给则用 profile 默认值。有效列表为空时
    // 才不发 ALPN 扩展 —— chrome 默认非空，plain 默认空（保持 reality.rs 旧形状）。
    let mut effective_alpn: Vec<&str> = Vec::new();
    if alpn.is_empty() {
        effective_alpn.extend_from_slice(profile.default_alpn);
    } else {
        effective_alpn.extend(alpn.iter().map(String::as_str));
    }

    // 先逐条构造 (类型, 数据)，再按 profile 决定是否打乱顺序，最后统一写长度。
    let mut extensions: Vec<(u16, Vec<u8>)> = Vec::with_capacity(profile.extension_order.len());
    for ext in profile.extension_order {
        match ext {
            Ext::GreaseEmpty => extensions.push((grease.leading_ext, Vec::new())),
            Ext::Alpn => {
                if !effective_alpn.is_empty() {
                    extensions.push((EXT_ALPN, alpn_ext(&effective_alpn)?));
                }
            }
            Ext::SctEmpty => extensions.push((EXT_SCT, Vec::new())),
            Ext::RenegotiationInfo => extensions.push((EXT_RENEGOTIATION_INFO, vec![0x00])),
            Ext::ExtendedMasterSecret => extensions.push((EXT_EXTENDED_MASTER_SECRET, Vec::new())),
            Ext::ServerName => extensions.push((EXT_SERVER_NAME, server_name_ext(server_name)?)),
            Ext::StatusRequest => extensions.push((
                EXT_STATUS_REQUEST,
                // status_type=ocsp(1) + 空 responder_id_list + 空 request_extensions。
                vec![0x01, 0x00, 0x00, 0x00, 0x00],
            )),
            Ext::CompressCertificate => {
                // algorithms<1..2^8-1>：列表长 2，一个 0x0002(brotli)。
                extensions.push((EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]))
            }
            Ext::KeyShare => extensions.push((
                EXT_KEY_SHARE,
                key_share_ext(profile, &grease, key_share_x25519),
            )),
            Ext::SignatureAlgorithms => extensions.push((
                EXT_SIGNATURE_ALGORITHMS,
                u16_list_ext(profile.signature_algorithms),
            )),
            Ext::PskKeyExchangeModes => {
                // 长度 1 + psk_dhe_ke(1)。
                extensions.push((EXT_PSK_KEY_EXCHANGE_MODES, vec![0x01, 0x01]))
            }
            Ext::SupportedVersions => {
                let mut list = Vec::new();
                if profile.grease_supported_versions {
                    put_u16(grease.versions, &mut list);
                }
                for version in profile.supported_versions {
                    put_u16(*version, &mut list);
                }
                let mut data = Vec::with_capacity(1 + list.len());
                data.push(list.len() as u8);
                data.extend_from_slice(&list);
                extensions.push((EXT_SUPPORTED_VERSIONS, data));
            }
            Ext::GreaseEch => extensions.push((EXT_ECH, grease_ech_ext(grease_seed))),
            Ext::SessionTicketEmpty => extensions.push((EXT_SESSION_TICKET, Vec::new())),
            Ext::EcPointFormats => {
                let mut data = Vec::with_capacity(1 + profile.ec_point_formats.len());
                data.push(profile.ec_point_formats.len() as u8);
                data.extend_from_slice(profile.ec_point_formats);
                extensions.push((EXT_EC_POINT_FORMATS, data));
            }
            Ext::SupportedGroups => {
                let mut list = Vec::new();
                if profile.grease_supported_groups {
                    put_u16(grease.groups, &mut list);
                }
                for group in profile.supported_groups {
                    put_u16(*group, &mut list);
                }
                extensions.push((EXT_SUPPORTED_GROUPS, u16_list_bytes(&list)));
            }
            Ext::ApplicationSettings => {
                // ALPS：列表长 3，一个 "h2"。Chrome 的 ALPS 只带 h2，与 ALPN 无关。
                extensions.push((EXT_APPLICATION_SETTINGS, vec![0x00, 0x03, 0x02, b'h', b'2']))
            }
            Ext::GreaseTrailing => extensions.push((grease.trailing_ext, vec![0x00])),
        }
    }

    if profile.shuffle_extension_order {
        shuffle_extensions(&mut extensions, grease_seed);
    }

    let mut exts = Vec::with_capacity(512);
    for (typ, data) in &extensions {
        push_ext(&mut exts, *typ, data)?;
    }
    if exts.len() > u16::MAX as usize {
        return Err(FingerprintError::ExtensionsTooLong(exts.len()));
    }
    put_u16(exts.len() as u16, &mut body);
    body.extend_from_slice(&exts);

    if body.len() > 0x00ff_ffff {
        return Err(FingerprintError::ClientHelloTooLong(body.len()));
    }
    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(HS_CLIENT_HELLO);
    put_u24(body.len(), &mut hello);
    hello.extend_from_slice(&body);
    Ok(hello)
}

/// 判定一个 16 位值是不是 RFC 8701 的 GREASE 值（两字节相同、低半字节 0xA）。
fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && (hi & 0x0f) == 0x0a
}

/// 由 seed 决定的扩展顺序打乱。
///
/// 12 份官方抓包（testing 统计）显示：下标 0 恒为 GREASE 扩展、最后一个恒为
/// GREASE 扩展，中间那 16 个非 GREASE 扩展每次连接随机排列；cipher 列表、
/// `supported_groups` 列表内部顺序都不打乱。所以这里只洗中间段、GREASE 钉首尾。
/// 只重排，不增删、不改任何扩展内容。用与 [`Grease::from_seed`] 不同的 domain
/// 常量，避免洗牌结果与 GREASE 取值相关。
fn shuffle_extensions(extensions: &mut Vec<(u16, Vec<u8>)>, seed: u64) {
    let (mut grease, mut middle): (Vec<_>, Vec<_>) =
        extensions.drain(..).partition(|(typ, _)| is_grease(*typ));

    if middle.len() > 1 {
        let mut rng = SplitMix64::new(seed ^ 0x7368_7566_666c_655f); // "shuffle_"
        for i in (1..middle.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            middle.swap(i, j);
        }
    }

    if grease.len() == 2 {
        // 规范顺序里第一个是首位 GREASE（空数据），最后一个是末尾 GREASE（1 字节）。
        let trailing = grease.pop().expect("len 已判");
        let leading = grease.pop().expect("len 已判");
        extensions.push(leading);
        extensions.extend(middle);
        extensions.push(trailing);
    } else {
        // 没有「首尾各一个 GREASE」结构的 profile：退化成整体 FIFO，不丢数据。
        extensions.extend(grease);
        extensions.extend(middle);
    }
}

// ─── GREASE ───────────────────────────────────────────────────────────────

/// 一轮 ClientHello 用到的 5 个（+1 个复用的）GREASE 16 位值。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Grease {
    /// cipher 列表首位。
    cipher: u16,
    /// 首位空扩展的**类型**。
    leading_ext: u16,
    /// `supported_groups` 首位；`key_share` 首位复用它（结构要求相等）。
    groups: u16,
    /// `supported_versions` 首位。
    versions: u16,
    /// 末尾扩展的**类型**。
    trailing_ext: u16,
}

impl Grease {
    /// 由 seed 派生：对 16 个 GREASE 值做一次由 seed 决定的 Fisher–Yates 洗牌，
    /// 取前 5 个当成 5 个互不相同的槽位。没有写死常量。
    fn from_seed(seed: u64) -> Self {
        let mut rng = SplitMix64::new(seed);
        let mut pool: [u8; 16] = core::array::from_fn(|i| i as u8);
        for i in (1..pool.len()).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            pool.swap(i, j);
        }
        let value = |slot: u8| -> u16 {
            let byte = (slot << 4) | 0x0a; // 0x0a,0x1a,…,0xfa
            u16::from_be_bytes([byte, byte])
        };
        Self {
            cipher: value(pool[0]),
            leading_ext: value(pool[1]),
            groups: value(pool[2]),
            versions: value(pool[3]),
            trailing_ext: value(pool[4]),
        }
    }

    /// 观测用：5 个槽位的值，按声明顺序。
    #[cfg(test)]
    fn slots(self) -> [u16; 5] {
        [
            self.cipher,
            self.leading_ext,
            self.groups,
            self.versions,
            self.trailing_ext,
        ]
    }
}

/// SplitMix64：小而确定的 PRNG，只为让 seed → 字节的映射可复现。
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
}

// ─── 扩展构造 ─────────────────────────────────────────────────────────────

fn key_share_ext(profile: &Profile, grease: &Grease, public_key: &[u8; 32]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(64);
    if profile.grease_key_share {
        // GREASE 条目：1 字节的占位 key exchange（夹包里是 0x00）。
        put_u16(grease.groups, &mut entries);
        put_u16(1, &mut entries);
        entries.push(0x00);
    }
    // 只有真的能用的 x25519。11ec 故意不发：声明了却不给 share 会触发 HRR，
    // 而 reality.rs 把 HRR 判为失败（见模块文档）。
    put_u16(GROUP_X25519, &mut entries);
    put_u16(public_key.len() as u16, &mut entries);
    entries.extend_from_slice(public_key);

    u16_list_bytes(&entries)
}

/// GREASE ECH 占位。结构：type(1) / kdf(2) / aead(2) / config_id(1) / enc / payload。
///
/// 载荷长度由 seed 在 4 档里选（32 字节粒度）：官方 12 份抓包的总长在
/// 1723/1755/1787/1819 之间跳，正好差 32 的整数倍，对应载荷 144/176/208/240。
/// 让总长也随连接变化，避免「记录长度恒定」这个 TCP 层弱特征。
fn grease_ech_ext(seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed ^ 0x6563_685f_6772_6561); // "ech_grea"
    let payload_len =
        ECH_PAYLOAD_MIN + (rng.next_u64() % ECH_PAYLOAD_BUCKETS as u64) as usize * ECH_PAYLOAD_STEP;
    let mut out = Vec::with_capacity(1 + 2 + 2 + 1 + 2 + ECH_ENC_LEN + 2 + payload_len);
    out.push(0x00); // ClientHelloOuter
    put_u16(ECH_KDF_ID, &mut out);
    put_u16(ECH_AEAD_ID, &mut out);
    out.push(rng.next_byte()); // config_id
    put_u16(ECH_ENC_LEN as u16, &mut out);
    for _ in 0..ECH_ENC_LEN {
        out.push(rng.next_byte());
    }
    put_u16(payload_len as u16, &mut out);
    for _ in 0..payload_len {
        out.push(rng.next_byte());
    }
    out
}

fn server_name_ext(server_name: &str) -> Result<Vec<u8>, FingerprintError> {
    if server_name.len() > u16::MAX as usize {
        return Err(FingerprintError::ServerNameTooLong(server_name.len()));
    }
    // server_name_list<2> = [type(0)=host_name, name<2>, bytes]
    let list_len = 1 + 2 + server_name.len();
    let mut out = Vec::with_capacity(2 + list_len);
    put_u16(list_len as u16, &mut out);
    out.push(0x00);
    put_u16(server_name.len() as u16, &mut out);
    out.extend_from_slice(server_name.as_bytes());
    Ok(out)
}

fn alpn_ext<T: AsRef<str>>(alpn: &[T]) -> Result<Vec<u8>, FingerprintError> {
    let mut list = Vec::new();
    for protocol in alpn {
        let bytes = protocol.as_ref().as_bytes();
        if bytes.len() > u8::MAX as usize {
            return Err(FingerprintError::AlpnIdTooLong(bytes.len()));
        }
        list.push(bytes.len() as u8);
        list.extend_from_slice(bytes);
    }
    if list.len() > u16::MAX as usize {
        return Err(FingerprintError::AlpnListTooLong(list.len()));
    }
    Ok(u16_list_bytes(&list))
}

/// `u16` 长度前缀 + 原始列表字节。
fn u16_list_bytes(list: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + list.len());
    put_u16(list.len() as u16, &mut out);
    out.extend_from_slice(list);
    out
}

/// `u16` 长度前缀 + `u16` 列表（长度按字节数写）。
fn u16_list_ext(values: &[u16]) -> Vec<u8> {
    let mut list = Vec::with_capacity(values.len() * 2);
    for value in values {
        put_u16(*value, &mut list);
    }
    u16_list_bytes(&list)
}

fn push_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) -> Result<(), FingerprintError> {
    if data.len() > u16::MAX as usize {
        return Err(FingerprintError::ExtensionDataTooLong {
            ext: typ,
            len: data.len(),
        });
    }
    put_u16(typ, out);
    put_u16(data.len() as u16, out);
    out.extend_from_slice(data);
    Ok(())
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u24(value: usize, out: &mut Vec<u8>) {
    out.push((value >> 16) as u8);
    out.push((value >> 8) as u8);
    out.push(value as u8);
}

// ─── 测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 夹包：唯一权威对照。测试直接 include_str!，不复制第二份。
    const CAPTURE_HEX: &str = include_str!("testdata/xray-clienthello.hex");

    /// X25519MLKEM768。夹包在 supported_groups 与 key_share 里都有，
    /// 我们两处都**有意**不发（见模块文档「显式偏差清单」）。
    const GROUP_X25519_MLKEM768: u16 = 0x11ec;

    // 归一化占位符：每个 GREASE 站点一个**不同的**值，这样把 GREASE 放错位置
    // 也会被抓到（不能所有站点都归成同一个值）。
    const CANON_CIPHER_GREASE: u16 = 0x0a0a;
    const CANON_EXT_GREASE: u16 = 0x1a1a;
    const CANON_GROUP_GREASE: u16 = 0x2a2a;
    const CANON_VERSION_GREASE: u16 = 0x3a3a;
    const CANON_KEY_SHARE_GREASE: u16 = 0x4a4a;
    /// 归一化时 ECH 载荷统一成这个长度（夹包的值），因为真实长度每连接随机。
    const ECH_PAYLOAD_PLACEHOLDER: usize = 208;

    fn capture_bytes() -> Vec<u8> {
        let hex: String = CAPTURE_HEX
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        assert_eq!(hex.len() % 2, 0, "夹包 hex 字符数必须是偶数");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("夹包必须是纯 hex"))
            .collect()
    }

    /// 测试用严格解析器：任何一个长度字段与实际不符都会 panic。
    struct Cur<'a> {
        b: &'a [u8],
        p: usize,
    }

    impl<'a> Cur<'a> {
        fn new(b: &'a [u8]) -> Self {
            Self { b, p: 0 }
        }

        fn u8(&mut self) -> u8 {
            let v = self.b[self.p];
            self.p += 1;
            v
        }

        fn u16(&mut self) -> u16 {
            let v = u16::from_be_bytes([self.b[self.p], self.b[self.p + 1]]);
            self.p += 2;
            v
        }

        fn take(&mut self, n: usize) -> &'a [u8] {
            let s = &self.b[self.p..self.p + n];
            self.p += n;
            s
        }

        fn remaining(&self) -> usize {
            self.b.len() - self.p
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Parsed {
        legacy_version: u16,
        random: [u8; 32],
        session_id: [u8; 32],
        ciphers: Vec<u16>,
        compression: Vec<u8>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn parse_hello(bytes: &[u8]) -> Parsed {
        let mut c = Cur::new(bytes);
        assert_eq!(c.u8(), HS_CLIENT_HELLO, "首字节必须是 ClientHello");
        let body_len = ((c.u8() as usize) << 16) | ((c.u8() as usize) << 8) | c.u8() as usize;
        assert_eq!(body_len, c.remaining(), "握手体长度字段与实际不符");

        let legacy_version = c.u16();
        let random: [u8; 32] = c.take(32).try_into().expect("32 字节");
        let sid_len = c.u8();
        assert_eq!(sid_len, 32, "session_id 长度必须是 32");
        let session_id: [u8; 32] = c.take(32).try_into().expect("32 字节");

        let cs_len = c.u16() as usize;
        assert_eq!(cs_len % 2, 0);
        let mut ciphers = Vec::with_capacity(cs_len / 2);
        for _ in 0..cs_len / 2 {
            ciphers.push(c.u16());
        }

        let comp_len = c.u8() as usize;
        let compression = c.take(comp_len).to_vec();

        let exts_len = c.u16() as usize;
        let mut ext_cur = Cur::new(c.take(exts_len));
        let mut extensions = Vec::new();
        while ext_cur.remaining() > 0 {
            let id = ext_cur.u16();
            let len = ext_cur.u16() as usize;
            extensions.push((id, ext_cur.take(len).to_vec()));
        }
        assert_eq!(c.remaining(), 0, "扩展块之后还有多余字节");

        Parsed {
            legacy_version,
            random,
            session_id,
            ciphers,
            compression,
            extensions,
        }
    }

    fn ext_data(parsed: &Parsed, id: u16) -> &[u8] {
        &parsed
            .extensions
            .iter()
            .find(|(ext_id, _)| *ext_id == id)
            .unwrap_or_else(|| panic!("没有扩展 {id:#06x}"))
            .1
    }

    /// GREASE 扩展的类型本身是随机的：比对时统一成占位值。
    fn canon_ext_id(id: u16) -> u16 {
        if is_grease(id) {
            CANON_EXT_GREASE
        } else {
            id
        }
    }

    /// 夹包里的扩展顺序，即 `chrome` 的规范顺序（testing 的 12 份抓包确认：非
    /// GREASE 扩展每次都重排，所以这里只是「一个规范排列」，用来做顺序无关比对）。
    const CANONICAL_EXT_ORDER: [u16; 18] = [
        0x0a0a, // 首位 GREASE
        0x0010, 0x0012, 0xff01, 0x0017, 0x0000, 0x0005, 0x001b, 0x0033, 0x000d, 0x002d, 0x002b,
        0xfe0d, 0x0023, 0x000b, 0x000a, 0x44cd, 0x9a9a, // 末尾 GREASE
    ];

    /// 扩展在规范顺序里的位置。GREASE 扩展下标 0/17 固定：首位是空数据，末尾是
    /// 1 字节 `0x00`（靠数据区分，因为两者的类型都是随机的 GREASE 值）。
    fn extension_rank((id, data): &(u16, Vec<u8>)) -> usize {
        if is_grease(*id) {
            return if data.is_empty() { 0 } else { 17 };
        }
        CANONICAL_EXT_ORDER
            .iter()
            .position(|known| known == id)
            .unwrap_or_else(|| panic!("规范顺序里没有扩展 {id:#06x}"))
    }

    /// 把扩展按规范顺序排好，便于与夹包做顺序无关的比对。
    fn sort_to_canonical(mut parsed: Parsed) -> Parsed {
        parsed.extensions.sort_by_key(extension_rank);
        parsed
    }

    /// 解析 key_share 扩展的条目：(组号, key exchange 字节)。
    fn key_share_entries(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut c = Cur::new(data);
        let total = c.u16() as usize;
        assert_eq!(
            total,
            c.remaining(),
            "key_share client_shares 长度字段与实际不符"
        );
        let mut entries = Vec::new();
        while c.remaining() > 0 {
            let group = c.u16();
            let len = c.u16() as usize;
            entries.push((group, c.take(len).to_vec()));
        }
        entries
    }

    /// 解析 `u16` 长度前缀的 u16 列表。
    fn u16_list(data: &[u8]) -> Vec<u16> {
        let mut c = Cur::new(data);
        let total = c.u16() as usize;
        assert_eq!(total, c.remaining(), "u16 列表长度字段与实际不符");
        let mut values = Vec::new();
        while c.remaining() > 0 {
            values.push(c.u16());
        }
        values
    }

    /// ECH 占位声明的载荷长度（每连接 4 档随机，见 `grease_ech_ext`）。
    fn ech_payload_len(data: &[u8]) -> usize {
        let enc_len = u16::from_be_bytes([data[6], data[7]]) as usize;
        u16::from_be_bytes([data[8 + enc_len], data[8 + enc_len + 1]]) as usize
    }

    /// 把「本来就随机」的位置归一化掉，并重算长度字段；返回可直接比对的字节。
    ///
    /// * GREASE 值：按站点换成互不相同的占位值（放错位置会被抓到）。
    /// * x25519 / 11ec 的 key exchange 字节：清零（那本来就是随机公钥材料）。
    /// * ECH：config_id/enc/payload 清零，载荷长度也归一成占位长度；
    ///   type/kdf/aead/enc 长度保留。
    /// * 其它扩展：原样。
    ///
    /// 归一化**不**抹掉「11ec 缺席」这件事 —— 它是显式偏差，单独断言（见
    /// `chrome_matches_capture_except_documented_deviations`）。
    fn canonicalize_ext_data(id: u16, data: &[u8]) -> Vec<u8> {
        match id {
            EXT_KEY_SHARE => {
                let mut entries = Vec::new();
                for (group, key) in key_share_entries(data) {
                    let group = if is_grease(group) {
                        CANON_KEY_SHARE_GREASE
                    } else {
                        group
                    };
                    put_u16(group, &mut entries);
                    put_u16(key.len() as u16, &mut entries);
                    entries.extend_from_slice(&vec![0u8; key.len()]);
                }
                u16_list_bytes(&entries)
            }
            EXT_SUPPORTED_GROUPS => {
                let values = u16_list(data)
                    .into_iter()
                    .map(|value| {
                        if is_grease(value) {
                            CANON_GROUP_GREASE
                        } else {
                            value
                        }
                    })
                    .collect::<Vec<u16>>();
                u16_list_ext(&values)
            }
            EXT_SUPPORTED_VERSIONS => {
                let list_len = data[0] as usize;
                assert_eq!(
                    list_len,
                    data.len() - 1,
                    "supported_versions 长度字节与实际不符"
                );
                let mut list = Vec::new();
                let mut p = 1;
                while p < data.len() {
                    let value = u16::from_be_bytes([data[p], data[p + 1]]);
                    p += 2;
                    put_u16(
                        if is_grease(value) {
                            CANON_VERSION_GREASE
                        } else {
                            value
                        },
                        &mut list,
                    );
                }
                let mut out = vec![list.len() as u8];
                out.extend_from_slice(&list);
                out
            }
            EXT_ECH => {
                assert!(data.len() >= 8, "ECH 占位太短");
                let enc_len = u16::from_be_bytes([data[6], data[7]]) as usize;
                let payload_off = 8 + enc_len;
                assert!(payload_off + 2 <= data.len(), "ECH enc 长度字段越界");
                let payload_len =
                    u16::from_be_bytes([data[payload_off], data[payload_off + 1]]) as usize;
                assert_eq!(
                    payload_off + 2 + payload_len,
                    data.len(),
                    "ECH payload 长度字段与实际不符"
                );
                // type/kdf/aead 是固定值，保留比对；config_id/enc 清零；payload 的
                // **长度**本身也每连接随机（4 档），先统一成占位长度再清零。
                let mut out = data[..8].to_vec();
                out[5] = 0; // config_id
                out.extend_from_slice(&vec![0u8; enc_len]);
                out.extend_from_slice(&(ECH_PAYLOAD_PLACEHOLDER as u16).to_be_bytes());
                out.extend_from_slice(&vec![0u8; ECH_PAYLOAD_PLACEHOLDER]);
                out
            }
            _ => data.to_vec(),
        }
    }

    /// 对整条消息做归一化：cipher 首位与 GREASE 扩展类型换成占位值，每个扩展的
    /// 内容走 [`canonicalize_ext_data`]。random / session_id 保留原样（调用方传的是
    /// 夹包里的那份，所以这里同时验证了「原样写入」）。
    fn canonicalize_parsed(mut parsed: Parsed) -> Parsed {
        for cipher in &mut parsed.ciphers {
            if is_grease(*cipher) {
                *cipher = CANON_CIPHER_GREASE;
            }
        }
        for (id, data) in &mut parsed.extensions {
            let original = *id;
            *data = canonicalize_ext_data(original, data);
            *id = canon_ext_id(original);
        }
        parsed
    }

    /// 把两边的 11ec 都拿掉（groups 列表里的值 + key_share 条目），返回是否真的
    /// 拿掉了东西；之后整条消息应能逐字节相等。
    fn drop_mlkem(parsed: &mut Parsed) -> bool {
        let mut dropped = false;
        for (id, data) in &mut parsed.extensions {
            match *id {
                EXT_SUPPORTED_GROUPS => {
                    let kept: Vec<u16> = u16_list(data)
                        .into_iter()
                        .filter(|value| {
                            let keep = *value != GROUP_X25519_MLKEM768;
                            dropped |= !keep;
                            keep
                        })
                        .collect();
                    *data = u16_list_ext(&kept);
                }
                EXT_KEY_SHARE => {
                    let mut entries = Vec::new();
                    for (group, key) in key_share_entries(data) {
                        if group == GROUP_X25519_MLKEM768 {
                            dropped = true;
                            continue;
                        }
                        put_u16(group, &mut entries);
                        put_u16(key.len() as u16, &mut entries);
                        entries.extend_from_slice(&key);
                    }
                    *data = u16_list_bytes(&entries);
                }
                _ => {}
            }
        }
        dropped
    }

    /// 用归一化结构重新序列化，长度字段全部重算。
    fn serialize(parsed: &Parsed) -> Vec<u8> {
        let mut body = Vec::new();
        put_u16(parsed.legacy_version, &mut body);
        body.extend_from_slice(&parsed.random);
        body.push(32);
        body.extend_from_slice(&parsed.session_id);
        put_u16((parsed.ciphers.len() * 2) as u16, &mut body);
        for cipher in &parsed.ciphers {
            put_u16(*cipher, &mut body);
        }
        body.push(parsed.compression.len() as u8);
        body.extend_from_slice(&parsed.compression);
        let mut exts = Vec::new();
        for (id, data) in &parsed.extensions {
            put_u16(*id, &mut exts);
            put_u16(data.len() as u16, &mut exts);
            exts.extend_from_slice(data);
        }
        put_u16(exts.len() as u16, &mut body);
        body.extend_from_slice(&exts);

        let mut hello = Vec::new();
        hello.push(HS_CLIENT_HELLO);
        put_u24(body.len(), &mut hello);
        hello.extend_from_slice(&body);
        hello
    }

    fn test_alpn() -> Vec<String> {
        vec!["h2".to_string(), "http/1.1".to_string()]
    }

    fn test_session_id() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    fn build(profile_name: &str, seed: u64) -> Vec<u8> {
        build_client_hello(
            profile_by_name(profile_name).expect("profile 存在"),
            "www.cloudflare.com",
            &test_alpn(),
            &[0x11u8; 32],
            &test_session_id(),
            &[0x22u8; 32],
            seed,
        )
        .expect("构造成功")
    }

    /// 验收 2（lead 改版）：逐字段比对夹包，只允许「显式偏差清单」里的差异。
    ///
    /// 允许的偏差只有两处：supported_groups 少 11ec、key_share 少 11ec 条目。
    /// 任何第三处差异都会让这个测试失败。
    #[test]
    fn chrome_matches_capture_except_documented_deviations() {
        let capture = capture_bytes();
        let cap = parse_hello(&capture);

        let x25519: [u8; 32] = key_share_entries(ext_data(&cap, EXT_KEY_SHARE))
            .into_iter()
            .find(|(group, _)| *group == GROUP_X25519)
            .expect("夹包里应有 x25519 key_share")
            .1
            .try_into()
            .expect("x25519 公钥 32 字节");

        let seed = 0x0123_4567_89ab_cdef;
        let ours = build_client_hello(
            profile_by_name("chrome").expect("chrome"),
            "www.cloudflare.com",
            &test_alpn(),
            &cap.random,
            &cap.session_id,
            &x25519,
            seed,
        )
        .expect("构造成功");
        let our = parse_hello(&ours);

        // 夹包 1787 字节。我们少了 11ec 的 key_share 条目（4+1216=1220）与
        // supported_groups 里的 2 字节组号（-1222）；ECH 载荷长度每连接在
        // 144/176/208/240 四档里随机（夹包是 208）。
        assert_eq!(capture.len(), 1787);
        let cap_payload = ech_payload_len(ext_data(&cap, EXT_ECH));
        let our_payload = ech_payload_len(ext_data(&our, EXT_ECH));
        assert_eq!(cap_payload, 208, "夹包 ECH 载荷长度");
        assert!(
            (144..=240).contains(&our_payload) && (our_payload - 144).is_multiple_of(32),
            "ECH 载荷长度必须是 144/176/208/240 之一，实际 {our_payload}"
        );
        assert_eq!(
            ours.len(),
            capture.len() - 1222 - cap_payload + our_payload,
            "总长 = 夹包 - 11ec 两处 - ECH 载荷长度差"
        );

        // ── 固定字段 ──
        assert_eq!(our.legacy_version, cap.legacy_version);
        assert_eq!(our.legacy_version, 0x0303, "JA3 的 SSLVersion 段");
        // JA3 的三处单独断言（lead 点的对齐点）。
        assert_eq!(ours[38], 32, "session_id_len");
        assert_eq!(&ours[105..107], &[0x01, 0x00], "compression_methods");
        // 偏移契约 + 原样写入：random 在 6..38，session_id 在 39..71。
        assert_eq!(
            &ours[6..38],
            &cap.random,
            "random 必须原样写入 hello[6..38]"
        );
        assert_eq!(
            &ours[39..71],
            &cap.session_id,
            "session_id 必须原样写入 hello[39..71]（前 16 字节是 REALITY 密文）"
        );
        assert_eq!(our.compression, cap.compression);

        // ── cipher 列表：首位 GREASE（值随机），其余逐个相同 ──
        assert_eq!(our.ciphers.len(), cap.ciphers.len());
        assert_eq!(our.ciphers.len(), 16);
        assert!(is_grease(our.ciphers[0]) && is_grease(cap.ciphers[0]));
        assert_eq!(&our.ciphers[1..], &cap.ciphers[1..]);

        // ── 扩展：数量、类型集合、以及每个扩展的内容（顺序无关） ──
        // 线上顺序每次连接被打乱（testing 12 份抓包：非 GREASE 扩展 12/12 全不同），
        // 所以先按规范顺序排好再逐项比对；顺序本身由 shuffle 单测断言。
        assert_eq!(our.extensions.len(), 18);
        assert_eq!(our.extensions.len(), cap.extensions.len());
        let cap_canon = sort_to_canonical(canonicalize_parsed(parse_hello(&capture)));
        let our_canon = sort_to_canonical(canonicalize_parsed(parse_hello(&ours)));

        // 逐个扩展比对归一化后的内容；差异只允许出现在这两个扩展上。
        let mut deviations = Vec::new();
        for (index, ((our_id, our_data), (cap_id, cap_data))) in our_canon
            .extensions
            .iter()
            .zip(cap_canon.extensions.iter())
            .enumerate()
        {
            assert_eq!(our_id, cap_id, "规范排序后第 {index} 个扩展的类型不一致");
            if our_data == cap_data {
                continue;
            }
            deviations.push(*our_id);
            match *our_id {
                EXT_SUPPORTED_GROUPS => {
                    let ours_list = u16_list(our_data);
                    let cap_list: Vec<u16> = u16_list(cap_data)
                        .into_iter()
                        .filter(|value| *value != GROUP_X25519_MLKEM768)
                        .collect();
                    assert_eq!(ours_list, cap_list, "supported_groups 只允许少 11ec");
                }
                EXT_KEY_SHARE => {
                    let ours_groups: Vec<u16> = key_share_entries(our_data)
                        .into_iter()
                        .map(|(group, _)| group)
                        .collect();
                    let cap_groups: Vec<u16> = key_share_entries(cap_data)
                        .into_iter()
                        .map(|(group, _)| group)
                        .filter(|group| *group != GROUP_X25519_MLKEM768)
                        .collect();
                    assert_eq!(ours_groups, cap_groups, "key_share 只允许少 11ec 条目");
                }
                other => panic!("偏差清单之外的第 {index} 处差异：扩展 {other:#06x}"),
            }
        }
        assert_eq!(
            deviations,
            vec![EXT_KEY_SHARE, EXT_SUPPORTED_GROUPS],
            "偏差清单必须恰好是这两处（按规范顺序）"
        );

        // ── 显式偏差 1：supported_groups 少了 11ec ──
        let cap_groups: Vec<u16> = u16_list(ext_data(&cap, EXT_SUPPORTED_GROUPS));
        let our_groups: Vec<u16> = u16_list(ext_data(&our, EXT_SUPPORTED_GROUPS));
        assert_eq!(cap_groups[1], GROUP_X25519_MLKEM768);
        assert!(is_grease(cap_groups[0]), "夹包首位是 GREASE 组");
        assert!(
            is_grease(our_groups[0]),
            "我们首位同样是 GREASE 组（值随机）"
        );
        assert_eq!(
            our_groups[1..],
            cap_groups[2..],
            "supported_groups 其余项与顺序不变"
        );
        assert!(
            !our_groups.contains(&GROUP_X25519_MLKEM768),
            "11ec 不得出现在 supported_groups（声明了却不给 share 会触发 HRR）"
        );

        // ── 显式偏差 2：key_share 少了 11ec 条目 ──
        let cap_ks = key_share_entries(ext_data(&cap, EXT_KEY_SHARE));
        let our_ks = key_share_entries(ext_data(&our, EXT_KEY_SHARE));
        assert_eq!(cap_ks.len(), 3);
        assert_eq!(our_ks.len(), 2);
        assert_eq!(cap_ks[1].0, GROUP_X25519_MLKEM768);
        assert_eq!(cap_ks[1].1.len(), 1216);
        assert!(
            our_ks
                .iter()
                .all(|(group, _)| *group != GROUP_X25519_MLKEM768),
            "11ec 不得出现在 key_share（我们发不出，见模块文档）"
        );
        assert!(is_grease(our_ks[0].0));
        assert_eq!(our_ks[1].0, GROUP_X25519);
        assert_eq!(our_ks[1].1.as_slice(), &x25519);

        // ── 兜底：两边都按规范顺序排好、拿掉 11ec 后，整条消息逐字节一致 ──
        let mut cap_without_mlkem = sort_to_canonical(canonicalize_parsed(parse_hello(&capture)));
        let mut our_without_mlkem = sort_to_canonical(canonicalize_parsed(parse_hello(&ours)));
        assert!(drop_mlkem(&mut cap_without_mlkem), "夹包确实含 11ec");
        assert!(!drop_mlkem(&mut our_without_mlkem), "我们本来就不该有 11ec");
        assert_eq!(
            serialize(&our_without_mlkem),
            serialize(&cap_without_mlkem),
            "除掉 11ec 两处偏差后必须与夹包逐字节一致"
        );
    }

    /// 夹包本身的 GREASE 位置证据：cipher 与 ext 0x0A0A 的值并不相等，
    /// 必须成对的是 groups 与 key_share。
    #[test]
    fn capture_grease_positions() {
        let cap = parse_hello(&capture_bytes());
        assert_eq!(cap.ciphers[0], 0x3a3a);
        assert_eq!(cap.extensions[0].0, 0x0a0a);
        let groups = ext_data(&cap, EXT_SUPPORTED_GROUPS);
        assert_eq!(u16::from_be_bytes([groups[2], groups[3]]), 0x6a6a);
        let key_share = key_share_entries(ext_data(&cap, EXT_KEY_SHARE));
        assert_eq!(key_share[0].0, 0x6a6a);
        assert_eq!(cap.extensions[17].0, 0x9a9a);
        let versions = ext_data(&cap, EXT_SUPPORTED_VERSIONS);
        assert_eq!(u16::from_be_bytes([versions[1], versions[2]]), 0x2a2a);
        assert_ne!(cap.ciphers[0], cap.extensions[0].0, "cipher 与首扩展不相等");
        assert_eq!(key_share[0].0, 0x6a6a, "groups 与 key_share 必须相等");
    }

    /// 验收 3：GREASE 随 seed 变化、同 seed 可复现、groups 与 key_share 成对。
    #[test]
    fn grease_is_seed_dependent_and_paired() {
        let seed = 0xdead_beef_cafe_babe;

        // 同 seed 可复现。
        assert_eq!(build("chrome", seed), build("chrome", seed));

        // 5 个槽位互不相同（Chrome 夹包里 5 个值也确实互不相同）。
        let grease = Grease::from_seed(seed);
        let slots = grease.slots();
        for (i, a) in slots.iter().enumerate() {
            assert!(is_grease(*a), "槽位 {i} 不是 GREASE 值: {a:#06x}");
            for b in &slots[i + 1..] {
                assert_ne!(a, b, "槽位值重复: {a:#06x}");
            }
        }

        // 不同 seed 必不同（对下面这组 seed 逐个验证）。
        let mut seen: Vec<[u16; 5]> = Vec::new();
        for candidate in [
            0u64,
            1,
            2,
            42,
            0xdead_beef_cafe_babe,
            0xdead_beef_cafe_babf,
            u64::MAX,
        ] {
            let slots = Grease::from_seed(candidate).slots();
            assert!(
                !seen.contains(&slots),
                "seed {candidate:#x} 与更早的 seed 产生了相同 GREASE 元组"
            );
            seen.push(slots);
        }

        // 线上位置与配对：cipher 首位 GREASE、首扩展类型 GREASE、
        // supported_versions 首位 GREASE、groups 首位 == key_share 首位。
        let parsed = parse_hello(&build("chrome", seed));
        assert!(is_grease(parsed.ciphers[0]));
        assert!(is_grease(parsed.extensions[0].0));
        let groups = u16_list(ext_data(&parsed, EXT_SUPPORTED_GROUPS));
        assert!(is_grease(groups[0]));
        let key_share = key_share_entries(ext_data(&parsed, EXT_KEY_SHARE));
        assert_eq!(key_share[0].0, groups[0], "groups 与 key_share 必须成对");
        let versions = ext_data(&parsed, EXT_SUPPORTED_VERSIONS);
        assert!(is_grease(u16::from_be_bytes([versions[1], versions[2]])));
        assert!(is_grease(parsed.extensions[17].0));

        // 不同 seed 的线上字节必须不同（GREASE 与 ECH 占位都变）。
        assert_ne!(build("chrome", seed), build("chrome", seed.wrapping_add(1)));
    }

    /// 追加要求：chrome 每连接按 seed 打乱扩展顺序（GREASE 钉首尾，中间 16 个
    /// 非 GREASE 扩展重排）；plain 固定顺序。
    #[test]
    fn chrome_shuffles_extension_order_per_seed() {
        // 同 seed 可复现。
        assert_eq!(build("chrome", 7), build("chrome", 7));

        let canonical: Vec<u16> = CANONICAL_EXT_ORDER.to_vec();
        let mut middle_sorted: Vec<u16> = canonical[1..17].to_vec();
        middle_sorted.sort_unstable();

        // 归一化排序后的基准：除顺序外的一切都必须与它一致。
        let baseline = serialize(&sort_to_canonical(canonicalize_parsed(parse_hello(
            &build("chrome", 0),
        ))));

        let mut orders: Vec<Vec<u16>> = Vec::new();
        for seed in 0u64..32 {
            let hello = build("chrome", seed);
            let parsed = parse_hello(&hello);
            let ids: Vec<u16> = parsed.extensions.iter().map(|(id, _)| *id).collect();
            assert_eq!(ids.len(), 18, "seed {seed}");
            // testing 12 份抓包：GREASE 类型恒在下标 0 与 17。
            assert!(
                is_grease(ids[0]) && is_grease(ids[17]),
                "seed {seed}: GREASE 必须钉在首尾，实际首={:#06x} 尾={:#06x}",
                ids[0],
                ids[17]
            );
            // 中间 16 个必须是规范集合的一个置换：不增删、不改内容。
            let mut middle = ids[1..17].to_vec();
            middle.sort_unstable();
            assert_eq!(
                middle, middle_sorted,
                "seed {seed}: 中间段必须是规范集合的排列"
            );
            let current = serialize(&sort_to_canonical(canonicalize_parsed(parse_hello(&hello))));
            assert_eq!(current, baseline, "seed {seed}: 除顺序外内容不得变");

            orders.push(ids);
        }

        // 32 个 seed 不得全部同序；且至少有一个与夹包规范顺序不同。
        let first = &orders[0];
        assert!(
            orders.iter().any(|order| order != first),
            "32 个 seed 全同序 = 没在打乱"
        );
        assert!(
            orders.iter().any(|order| order != &canonical),
            "至少要有一个顺序与夹包规范顺序不同"
        );
        let mut distinct: Vec<&Vec<u16>> = Vec::new();
        for order in &orders {
            if !distinct.contains(&order) {
                distinct.push(order);
            }
        }
        // 洗牌统计（报告里要用）。
        println!(
            "chrome shuffle: {} 个 seed → {} 种不同扩展顺序",
            orders.len(),
            distinct.len()
        );
        assert!(distinct.len() >= 2, "不同 seed 必须产生不同顺序");

        // plain 不打乱：32 个 seed 顺序恒定且与 reality.rs 旧形状一致。
        let plain_order = vec![
            EXT_SERVER_NAME,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_ALPN,
            EXT_SESSION_TICKET,
            EXT_SUPPORTED_VERSIONS,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_KEY_SHARE,
        ];
        for seed in 0u64..32 {
            let plain = parse_hello(&build("plain", seed));
            assert_eq!(
                plain
                    .extensions
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<u16>>(),
                plain_order,
                "seed {seed}: plain 顺序必须固定"
            );
        }
    }

    /// P2：ECH 载荷长度 4 档、由 seed 选，跨连接总长不再恒定。
    #[test]
    fn chrome_ech_payload_length_varies_per_seed() {
        let mut counts: std::collections::BTreeMap<usize, usize> =
            std::collections::BTreeMap::new();
        for seed in 0u64..32 {
            let parsed = parse_hello(&build("chrome", seed));
            let len = ech_payload_len(ext_data(&parsed, EXT_ECH));
            assert!(
                matches!(len, 144 | 176 | 208 | 240),
                "seed {seed}: ECH 载荷长度 {len} 不在四档内"
            );
            *counts.entry(len).or_insert(0) += 1;
        }
        println!("ECH payload buckets / 32 seeds: {counts:?}");
        assert_eq!(counts.len(), 4, "四个档位都应该出现过");
    }

    /// plain 与 seed 无关：没有 GREASE，就应该完全一致。
    #[test]
    fn plain_ignores_grease_seed() {
        assert_eq!(build("plain", 0), build("plain", u64::MAX));
    }

    /// 验收 4：plain 输出仍是合法 ClientHello（reality_server 解析器认可），
    /// 且保持 reality.rs 的旧形状（1 个 cipher、无 GREASE、扩展顺序不变）。
    #[test]
    fn plain_is_parseable_and_matches_reality_shape() {
        let hello = build("plain", 0);
        let parsed = crate::reality_server::parse_client_hello(&hello)
            .expect("plain profile 必须产出合法 ClientHello");
        assert_eq!(parsed.random, [0x11u8; 32]);
        assert_eq!(parsed.session_id, test_session_id());
        assert_eq!(parsed.session_id_offset, 39);
        assert_eq!(parsed.key_share, [0x22u8; 32]);
        assert_eq!(parsed.server_name.as_deref(), Some("www.cloudflare.com"));

        let shape = parse_hello(&hello);
        assert_eq!(shape.legacy_version, 0x0303);
        assert_eq!(shape.compression, vec![0x00]);
        assert_eq!(shape.ciphers, vec![TLS_AES_128_GCM_SHA256]);
        assert_eq!(
            shape
                .extensions
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<u16>>(),
            vec![
                EXT_SERVER_NAME,
                EXT_SUPPORTED_GROUPS,
                EXT_EC_POINT_FORMATS,
                EXT_SIGNATURE_ALGORITHMS,
                EXT_ALPN,
                EXT_SESSION_TICKET,
                EXT_SUPPORTED_VERSIONS,
                EXT_PSK_KEY_EXCHANGE_MODES,
                EXT_KEY_SHARE,
            ]
        );
        assert_eq!(
            u16_list(ext_data(&shape, EXT_SUPPORTED_GROUPS)),
            vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
        );
        assert!(
            !shape.ciphers.iter().any(|cipher| is_grease(*cipher))
                && !shape.extensions.iter().any(|(id, _)| is_grease(*id)),
            "plain 不应含任何 GREASE"
        );
    }

    /// profile 查找：精确、大小写敏感、无别名、空串不兜底；名字表稳定。
    #[test]
    fn profile_lookup_is_exact() {
        assert_eq!(profile_names(), &["chrome", "plain"]);
        assert!(profile_names().contains(&DEFAULT_PROFILE_NAME));
        assert_eq!(DEFAULT_PROFILE_NAME, "chrome");
        assert_eq!(profile_by_name("chrome").expect("chrome").name(), "chrome");
        assert_eq!(profile_by_name("plain").expect("plain").name(), "plain");
        for unknown in ["", "Chrome", "CHROME", "none", "raw", "firefox", "chrome "] {
            assert!(profile_by_name(unknown).is_none(), "{unknown:?} 不应被接受");
        }
    }

    /// ALPN 兜底：调用方给空列表时用 profile 默认（chrome=`h2,http/1.1`，
    /// plain=空）；有效列表为空才不发 ALPN 扩展；用户显式 ALPN 永远优先。
    #[test]
    fn alpn_default_and_override_per_profile() {
        let build_alpn = |name: &str, alpn: &[String]| {
            build_client_hello(
                profile_by_name(name).expect("profile 存在"),
                "example.com",
                alpn,
                &[0x11u8; 32],
                &test_session_id(),
                &[0x22u8; 32],
                7,
            )
            .expect("构造成功")
        };
        let h2_only = vec!["http/1.1".to_string()];

        // profile 自带的默认值（design 的 --help / 自检要打印它）。
        assert_eq!(
            profile_by_name("chrome").expect("chrome").default_alpn(),
            &["h2", "http/1.1"]
        );
        assert!(profile_by_name("plain")
            .expect("plain")
            .default_alpn()
            .is_empty());

        // chrome + 调用方空 → profile 默认 ["h2","http/1.1"]。
        let chrome = parse_hello(&build_alpn("chrome", &[]));
        assert_eq!(
            ext_data(&chrome, EXT_ALPN),
            &[0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );

        // 显式 ALPN 优先：只发调用方给的那一个。
        let chrome_explicit = parse_hello(&build_alpn("chrome", &h2_only));
        assert_eq!(
            ext_data(&chrome_explicit, EXT_ALPN),
            &[0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );

        // plain + 空 → 不发 ALPN（reality.rs 旧形状）；显式给了就发。
        let plain = parse_hello(&build_alpn("plain", &[]));
        assert!(
            !plain.extensions.iter().any(|(id, _)| *id == EXT_ALPN),
            "plain 默认 ALPN 为空，不应发 ALPN"
        );
        let plain_explicit = parse_hello(&build_alpn("plain", &h2_only));
        assert_eq!(
            ext_data(&plain_explicit, EXT_ALPN),
            &[0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );
    }
}
