// Ported from meow-rs <https://github.com/meow-rs/meow-rs> @ a2be4de1c315daa22e53ad1118538936241d592f
// (crates/meow-proxy/src/vless/mod.rs).
// MIT licensed, Copyright (c) 2026 Max Lv. See LICENSE.meow-rs.
//
// Modified for the wasm32-wasip2 port: the `vless-encryption` module is out of
// scope and absent.

//! VLESS protocol sub-modules.

pub mod conn;
pub mod header;
pub mod server;
pub mod vision;

pub use conn::VlessConn;
pub use header::{addr_from_metadata, Cmd, VlessAddr};
pub use server::{
    decode_request, serve_inbound, serve_inbound_with_events, InboundConfig, InboundEvent,
    InboundOutcome, InboundReport, Request,
};
pub use vision::VisionConn;
