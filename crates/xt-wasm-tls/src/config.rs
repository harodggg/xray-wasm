// Ported from meow-rs <https://github.com/meow-rs/meow-rs>, analysed revision
// a2be4de1c315daa22e53ad1118538936241d592f (crates/meow-transport/src/tls.rs:56-157).
// MIT licensed, Copyright (c) 2026 Max Lv. See LICENSE.meow-rs in this crate.
//
// Modified for the wasm32-wasip2 port: only the runtime-free config types were
// taken (`TlsBackend` / `TlsLayer` / the BoringSSL backend were dropped), and the
// never-read `RealityConfig::support_x25519_mlkem768` field was deleted.

//! TLS / REALITY configuration types.
//!
//! These are the upstream `meow-transport` config structs, unchanged apart from
//! the deletion of the unused ML-KEM toggle and the documented contract of
//! [`TlsConfig::fingerprint`] (which upstream left unimplemented). They carry no
//! runtime dependency.

/// Source of the ECH config list.
///
/// DNS-sourced ECH (`ech-opts.enable = true` without `ech-opts.config`) is
/// deferred until `meow-dns` gains SVCB/HTTPS record support.
#[derive(Debug, Clone)]
pub enum EchOpts {
    /// Inline ECH config list bytes, base64-decoded by the caller before
    /// this struct is constructed.
    ///
    /// YAML key: `ech-opts.config`
    Config(Vec<u8>),
}

/// REALITY client authentication parameters for TLS-based outbound proxies.
///
/// Built by the config layer from `reality-opts:`. The public key is the
/// server's X25519 public key, and `short_id` is the decoded, zero-padded
/// short id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],

    /// REALITY `ClientVer` 三元组（major, minor, patch）。
    ///
    /// **这不是装饰性的：服务端真的会校验它。** 见 `xtls/reality/tls.go`：
    ///
    /// ```go
    /// (config.MinClientVer == nil || Value(ClientVer) >= Value(MinClientVer)) &&
    /// (config.MaxClientVer == nil || Value(ClientVer) <= Value(MaxClientVer)) &&
    /// ```
    ///
    /// 两个配置项默认都为空（不校验），所以**沿用固定的小版本号在本机测试时
    /// 完全看不出问题**；但只要部署方设了 `minClientVer`（例如要求较新的客户端），
    /// 版本过低的握手就会被当作探测流量转发给 `dest`，表现为「握手失败」。
    /// 这是典型的「本地通过、上线失败」，所以这里做成可配置。
    pub client_version: [u8; 3],
}

impl RealityConfig {
    /// 默认上报的客户端版本：与本工程端到端验证过的 Xray 版本对齐。
    ///
    /// 默认取较新版本的理由：`minClientVer`（要求客户端足够新）在实践中远比
    /// `maxClientVer`（限制客户端不能太新）常见，取新版本能通过更多部署。
    /// 服务端若设了 `maxClientVer`，用 `--client-ver` 下调。
    ///
    /// 上游 meow-rs / sing-box 硬编码 `[1, 8, 1]`，其代码注释称「服务端不校验这三个
    /// 字节」—— 那个说法**与 `xtls/reality` 的实际实现不符**（见上面字段文档），
    /// 因此这里不沿用。
    pub const DEFAULT_CLIENT_VERSION: [u8; 3] = [26, 3, 27];

    /// 用默认版本构造。
    pub fn new(public_key: [u8; 32], short_id: [u8; 8]) -> Self {
        Self {
            public_key,
            short_id,
            client_version: Self::DEFAULT_CLIENT_VERSION,
        }
    }
}

/// TLS layer configuration, built from YAML by the caller and passed into
/// [`crate::RealityTlsLayer::new`]. This struct never sees YAML directly.
///
/// Corresponds to the `tls:`, `skip-cert-verify:`, `alpn:`,
/// `client-fingerprint:`, and `ech-opts:` keys in a proxy entry.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether TLS is enabled.  If `false`, no layer should be
    /// constructed; this field is a convenience for config-side logic.
    pub enabled: bool,

    /// Effective SNI, resolved by config before construction (see module doc).
    /// Must be `Some` when `enabled = true`.
    pub sni: Option<String>,

    /// ALPN protocol IDs offered in the ClientHello.
    /// Empty slice → no ALPN extension.
    pub alpn: Vec<String>,

    /// Disable server certificate verification.  Emits a `warn!` once.
    pub skip_cert_verify: bool,

    /// Optional mutual-TLS client certificate (PEM-encoded).
    pub client_cert: Option<ClientCert>,

    /// `client-fingerprint` YAML value：用哪个 ClientHello profile。
    ///
    /// **语义定稿**（profile 表见 `crate::fingerprint`，接线见 `crate::reality`）：
    ///
    /// * `None` 或 `Some("")`（k8s 里没填的字段常是空串）→ 默认 profile
    ///   [`crate::fingerprint::DEFAULT_PROFILE_NAME`]（`chrome`）；
    /// * 未知名字 → **配置错误**（`TransportError::Config`），启动即失败；
    ///   **绝不静默回退**到 `plain` —— 静默降级会让用户以为在伪装、其实没有。
    ///   错误文本里会列出可用名字（来自 `fingerprint::profile_names()`）；
    /// * 名字**大小写敏感**，不做别名猜测。
    ///
    /// 能力边界（**不要读成「实现了 Chrome 指纹」**）：profile 只对齐真 Chrome 的
    /// **可观测字段**（legacy_version / cipher 列表 / 扩展集合与顺序 /
    /// `ec_point_formats` / ALPN / `sigalgs` / GREASE 模式 / compression），而且对齐的是
    /// 一个**有版本年代的**形状（约 Chrome 114）。`supported_groups` 里**不声明**
    /// X25519MLKEM768(11ec)：声明却不给它的 key_share 会触发 HelloRetryRequest，
    /// 而本工程不支持 HRR ⇒ 握手直接失败（T4 实测 5/5）。真实 ECH 也只发 GREASE 占位。
    /// 已知不一致点与代价见 `docs/fingerprint-plan.md`。
    ///
    /// 指纹只改外观，**不改 REALITY 认证**：HKDF 的输入仍是 ClientHello 的
    /// `random`（握手消息偏移 6..26），认证密文仍占 `session_id[0..16]`。
    pub fingerprint: Option<String>,

    /// Extra CA certificates (DER-encoded) added to the root store in
    /// addition to `webpki-roots`.  Used in tests with self-signed certs;
    /// production deployments leave this empty.
    pub additional_roots: Vec<Vec<u8>>,

    /// ECH config source.
    ///
    /// `Some(EchOpts::Config(bytes))` → inline ECH config list.
    /// DNS-sourced ECH is deferred; see [`EchOpts`].
    ///
    /// **真实 ECH 不做**：REALITY 路径直接拒绝 `Some(_)`（配置错误
    /// `reality-opts cannot be combined with ech-opts`，见 `reality.rs`）。
    /// 指纹 profile 在 ClientHello 里为「形状」发出的 ECH 相关内容是
    /// **GREASE 占位**，不是真 ECH，也不读取这里的配置 ——
    /// 能力边界与代价见 `docs/fingerprint-plan.md` §3.2。
    pub ech: Option<EchOpts>,

    /// REALITY authentication options. When present, TLS uses the dedicated
    /// REALITY TLS 1.3 path because the ClientHello session_id must be computed
    /// from this connection's X25519 key share before it is written.
    pub reality: Option<RealityConfig>,
}

impl TlsConfig {
    /// Convenience constructor: TLS enabled, SNI set, all other fields default.
    pub fn new(sni: impl Into<String>) -> Self {
        Self {
            enabled: true,
            sni: Some(sni.into()),
            alpn: Vec::new(),
            skip_cert_verify: false,
            client_cert: None,
            fingerprint: None,
            additional_roots: Vec::new(),
            ech: None,
            reality: None,
        }
    }
}

/// Optional mutual-TLS client certificate (PEM-encoded key and certificate).
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// PEM-encoded X.509 certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key (PKCS#8 or RSA).
    pub key_pem: Vec<u8>,
}
