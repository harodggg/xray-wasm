// Ported from meow-rs <https://github.com/meow-rs/meow-rs>, analysed revision
// a2be4de1c315daa22e53ad1118538936241d592f (crates/meow-transport/src/lib.rs:81-117
// and the crates/meow-transport/src/{error.rs,lib.rs} shims).
// MIT licensed, Copyright (c) 2026 Max Lv. See LICENSE.meow-rs in this crate.
//
// Modified for the wasm32-wasip2 port: the shared shim types (`TransportError`,
// `Result`, `Stream`, `Transport`) now live in `xt-wasm-runtime` and are only
// re-exported here; the REALITY passthrough helpers are unconditional (the
// upstream `#[cfg(feature = "tls", feature = "reality")]` gates are dropped).

//! Hand-rolled TLS 1.3 + REALITY client, ported to `wasm32-wasip2`.
//!
//! The protocol core is a verbatim port of `meow-transport`'s `reality_tls.rs`:
//! the record layer, the X25519 / HKDF / AES-GCM crypto, the REALITY ClientHello
//! builder and the certificate-HMAC gate are all in-tree and pure Rust, with no
//! BoringSSL anywhere. The only runtime dependency upstream was the tokio
//! timeout around the handshake, which is replaced here by a `SystemTime`
//! deadline (see [`reality`]).
//!
//! Public entry points:
//!
//! * [`RealityTlsLayer`] / [`reality_handshake`] — perform the REALITY
//!   handshake over an already-connected [`Stream`].
//! * [`enable_raw_passthrough`] and friends — flip a [`RealityTlsStream`] into
//!   raw splice mode for XTLS-Vision's DIRECT path.

pub use xt_wasm_runtime::{Result, Stream, Transport, TransportError};

mod config;
mod reality;
mod reality_server;

pub use config::{ClientCert, EchOpts, RealityConfig, TlsConfig};
pub use reality::{reality_handshake, RealityTlsLayer, RealityTlsStream};
pub use reality_server::{
    authenticate, forge_certificate, parse_client_hello, reality_public_key,
    reality_server_handshake, Authenticated, ClientHello, HandshakeOutcome, RealityServerConfig,
};

/// Enable raw (unframed) passthrough in **both** directions if `stream` is a
/// [`RealityTlsStream`].  Returns `true` when the stream was recognised.
///
/// Ported from `meow-transport/src/lib.rs:81-88`, with the upstream feature
/// gate removed.
pub fn enable_raw_passthrough(stream: &mut dyn Stream) -> bool {
    let read = enable_raw_read_passthrough(stream);
    let write = enable_raw_write_passthrough(stream);
    read || write
}

/// Enable raw passthrough on the read side.  Returns `true` when `stream` is a
/// [`RealityTlsStream`].
///
/// Ported from `meow-transport/src/lib.rs:90-101`.  The `as_any_mut()`
/// downcast shape is load-bearing: XTLS-Vision's DIRECT splice depends on it.
pub fn enable_raw_read_passthrough(stream: &mut dyn Stream) -> bool {
    if let Some(reality) = stream.as_any_mut().downcast_mut::<RealityTlsStream>() {
        reality.enable_raw_read_passthrough();
        return true;
    }
    false
}

/// Enable raw passthrough on the write side.  Returns `true` when `stream` is a
/// [`RealityTlsStream`].
///
/// Ported from `meow-transport/src/lib.rs:103-117`.
pub fn enable_raw_write_passthrough(stream: &mut dyn Stream) -> bool {
    if let Some(reality) = stream.as_any_mut().downcast_mut::<RealityTlsStream>() {
        reality.enable_raw_write_passthrough();
        return true;
    }
    false
}

/// 跨 crate 测试用的夹具工具。
///
/// 只为测试存在：让别的 crate 的集成测试能造出一对匹配的
/// REALITY 服务端 / 客户端密钥，而不必各自重写一遍 X25519 调用。
#[doc(hidden)]
pub mod test_support {
    use crate::reality::{clamp_x25519_private, x25519_public_from_private};

    /// 固定的测试私钥（`[0x42; 32]` 做 X25519 clamp）—— 它不保护任何东西。
    pub fn fixture_private_key() -> [u8; 32] {
        let mut k = [0x42u8; 32];
        clamp_x25519_private(&mut k);
        k
    }

    /// 由私钥推出公钥。
    pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
        x25519_public_from_private(private)
    }
}
