// Ported from meow-rs <https://github.com/meow-rs/meow-rs> @ a2be4de1c315daa22e53ad1118538936241d592f
// (crates/meow-proxy/src/vless/{mod,header,conn,vision}.rs and
//  crates/meow-common/src/{conn,error,metadata}.rs).
// MIT licensed, Copyright (c) 2026 Max Lv. See LICENSE.meow-rs.
//
// Modified for the wasm32-wasip2 port:
//   * the `meow-common` shims live here and are reduced to the TCP surface
//     (`ProxyConn`, `MeowError`, `Result`, `Metadata`, `AddrDisplay`);
//   * `SmolStr` → `String` everywhere (drops the `smol_str` dependency,
//     port-map §8.5);
//   * the upstream blanket impl of `ProxyConn` for tokio's `TcpStream` is
//     deleted — tokio's `net` feature is a hard `compile_error!` on wasm
//     (port-map §8.3);
//   * UDP-over-TCP (`VlessPacketConn`), Mux.Cool, the adapter layer and the
//     post-quantum encryption module are out of scope and absent.

//! VLESS request header + XTLS-Vision flow, ported to `wasm32-wasip2`.
//!
//! This crate carries the TCP-only slice of meow-rs' VLESS client:
//!
//! * [`vless::header`] — VLESS request header encoding and address encoding.
//! * [`vless::conn::VlessConn`] — TCP passthrough connection wrapping a
//!   transport-layer [`xt_wasm_tls::Stream`]; the request header can be sent
//!   eagerly or deferred so a Vision wrapper can pad it with the first payload.
//! * [`vless::vision::VisionConn`] — the XTLS-Vision padding/splice wrapper.
//!
//! The `meow-common` types the ported code depended on are re-created here:
//! [`ProxyConn`], [`MeowError`], [`Result`], [`Metadata`] and [`AddrDisplay`].

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite};

// ─── ProxyConn (meow-common/src/conn.rs:6-16) ────────────────────────────────
//
// The upstream blanket impl of `ProxyConn` for tokio's `TcpStream`
// (conn.rs:13) is deleted: tokio's `net` feature is a hard compile error on
// wasm.  The port's own socket wrapper (`xt_wasm_runtime::NonBlockingStream`)
// implements `AsyncRead` / `AsyncWrite`, so the blanket impl over `Stream`
// covers it.

/// A proxy-level connection: an object-safe duplex byte stream.
pub trait ProxyConn: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn remote_destination(&self) -> String {
        String::new()
    }
}

// Impl for Box<dyn ProxyConn>
impl<T: ProxyConn + ?Sized> ProxyConn for Box<T> {}

// ─── MeowError (meow-common/src/error.rs:1-33) ───────────────────────────────
//
// Copied verbatim.  Only `Io`, `Config`, `Proxy` and `NotSupported` are
// reachable in the TCP-only port set; the rest are kept so the shim stays
// byte-for-byte compatible with upstream for future layers.

/// Errors produced by the proxy layer (`meow_common::MeowError`).
#[derive(thiserror::Error, Debug)]
pub enum MeowError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Config error: {0}")]
    Config(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("Proxy error: {0}")]
    Proxy(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("proxy authentication failed")]
    ProxyAuthFailed,
    #[error("HTTP CONNECT failed with status {0}")]
    HttpConnectFailed(u16),
    #[error("SOCKS5 connect failed with reply code {0:#04x}")]
    Socks5ConnectFailed(u8),
    #[error("SOCKS5: no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("no proxy available")]
    NoProxyAvailable,
    #[error("relay chain failed at hop {hop}: {source}")]
    RelayHopFailed { hop: usize, source: Box<MeowError> },
    #[error("UDP not supported by this relay chain")]
    UdpNotSupported,
    #[error("{0}")]
    Other(String),
}

/// Crate-level `Result` alias (`meow_common::Result`).
pub type Result<T> = std::result::Result<T, MeowError>;

// ─── Metadata (reduced — meow-common/src/metadata.rs) ────────────────────────
//
// Reduced to the three fields the TCP port set consumes (`host`, `dst_ip`,
// `dst_port`) plus `AddrDisplay`.  This deletes `serde`, `smol_str`,
// `Network`, `ConnType`, `DnsMode` and `CompactAddrBuf` entirely.

/// Connection metadata: destination address and the sniffed/derived host.
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    /// Domain name, if known.  Was `SmolStr` upstream.
    pub host: String,
    /// Resolved destination IP, if known.
    pub dst_ip: Option<IpAddr>,
    /// Destination port.
    pub dst_port: u16,
}

/// Display adapter for a [`Metadata`] remote address.
///
/// Prefers the host name, falls back to the resolved IP, then to a bare port.
pub struct AddrDisplay<'a> {
    host: &'a str,
    ip: Option<IpAddr>,
    port: u16,
}

impl fmt::Debug for AddrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for AddrDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.host.is_empty() {
            write!(f, "{}:{}", self.host, self.port)
        } else if let Some(ip) = self.ip {
            fmt::Display::fmt(&SocketAddr::new(ip, self.port), f)
        } else {
            write!(f, ":{}", self.port)
        }
    }
}

impl Metadata {
    /// The remote destination as a displayable address.
    pub fn remote_address(&self) -> AddrDisplay<'_> {
        AddrDisplay {
            host: &self.host,
            ip: self.dst_ip,
            port: self.dst_port,
        }
    }
}

pub mod vless;

pub use vless::{
    addr_from_metadata, decode_request, serve_inbound, serve_inbound_with_events, Cmd,
    InboundConfig, InboundEvent, InboundOutcome, Request as VlessRequest, VisionConn, VlessAddr,
    VlessConn,
};
