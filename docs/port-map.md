# Port Map — meow-rs → `xray-wasm` (VLESS + XTLS-Vision + REALITY, TCP only, `wasm32-wasip2`)

**Subject:** `github.com/meow-rs/meow-rs`
**Revision analysed:** `main` @ `a2be4de1c315daa22e53ad1118538936241d592f` (2026-09-14T16:12:35Z, *"fix(proxy): health-check load-balance groups so url/interval/lazy take effect (#485) (#521)"*)
**Method:** every file fetched with `curl` from `https://raw.githubusercontent.com/meow-rs/meow-rs/main/<path>`; paths discovered with `https://api.github.com/repos/meow-rs/meow-rs/git/trees/main?recursive=1`. All line numbers below refer to the files **at that revision**.
**Local mirror of the fetched sources:** `/Users/xbtg-/deepseek-harness/.scratch/portmap/src/`

SHA-256 of every analysed file (so the porting engineer can prove they have the same bytes):

| file | sha256 |
|---|---|
| `crates/meow-transport/src/reality_tls.rs` | `ba6a434594e40cd07feacaa799c6cd8e701248b257232a1cbdead8ab27d286a4` |
| `crates/meow-transport/src/tls.rs` | `c1fa5584ce493fac81a7ae17589c61626405d4bedf33fa3214f96ce2a2b069eb` |
| `crates/meow-transport/src/lib.rs` | `3cf6d34895a66e051e1c98fcb0a43136e496d750431e9cb874be5c5d0cfdeb23` |
| `crates/meow-transport/src/error.rs` | `0794443085d05cd18f8aec184e38230b8edc6cd287e982fab418492bb6d01927` |
| `crates/meow-transport/Cargo.toml` | `6e8c280cdbf724c4f951541d6e3aac6b24bbe8397477f7c4efdd757f1f430874` |
| `crates/meow-proxy/src/vless/mod.rs` | `6689f400f4e6f0402902c8d2e05c8a1ed25d0e2cf98759dc9b81c1d91c12c27d` |
| `crates/meow-proxy/src/vless/header.rs` | `a95547d97ae8220d7f68a375ee294cd53bb03531df25d3109217e5ecd3b58686` |
| `crates/meow-proxy/src/vless/vision.rs` | `ec36ca03c55509a585e3026e69daf6369f1b5e98d6db7b46ca2015d35a77a38d` |
| `crates/meow-proxy/src/vless/conn.rs` | `ad272029a42ce168bb1e949f3bafa74c8cb1975cd44fff0008734c589472a339` |
| `crates/meow-proxy/Cargo.toml` | `cb20d9b2d6443053abfed0abde19bb77b17f4d76408997bc743ce7f694842e81` |
| `crates/meow-common/Cargo.toml` | `56ad4c37e184e74789c55562bf5b9d2233556e292121d11d7654c73a29d12779` |
| `crates/meow-common/src/lib.rs` | `50e11b2d4360a0555413c5cac8310c00a420cbb371197b1d9dd93eac97c89440` |
| `crates/meow-common/src/conn.rs` | `918394c57846837c0fc94c87596021a0c4c4a58fa75bda0ac7c5649d591d54f6` |
| `crates/meow-common/src/error.rs` | `a4c23eb48a3df377f0be72a102e8dfc6370ca139e0f068f133d92d7214fbf882` |
| `crates/meow-common/src/metadata.rs` | `8c1bc9a4a75ba65e5179fa53c9e4156a4617f95a3750bb59ff26484137883b1d` |
| `LICENSE` | `b7a39018faacfd98597da373045fbacf2c3f134fd755e553894a6a9adad38db5` |

---

## 0. Bottom line

| metric | value |
|---|---|
| Distinct third-party crates referenced by the **listed port set** | **12** |
| … of which are needed for the **REALITY/TLS core alone** | **9** |
| … needed for the **TCP-only port** (REALITY + VLESS TCP + Vision, `Metadata` reduced to 3 fields) | **11** |
| Resolved transitive crate closure, REALITY core | **56** external crates |
| Resolved transitive crate closure, full set incl. VLESS/Vision + `smol_str` | **62** external crates |
| BoringSSL / C++ / `mio` / `epoll` dependencies in the REALITY path | **0** |
| tokio uses classified **(a) `tokio::io`-only — safe** | **31** (10 production, 21 test-only) |
| tokio uses classified **(b) runtime-dependent — must be replaced** | **65** (6 production, **59 test-only**) |
| … **(b) production hits that survive a TCP-only scope** | **1** — `reality_tls.rs:130` |
| `#[cfg(test)]` tests in `reality_tls.rs` that need **no** runtime | **16 of 19** |
| `#[cfg(test)]` tests in `header.rs` that need **no** runtime | **10 of 11** |
| `#[cfg(test)]` tests in `vision.rs` that need **no** runtime | **6 of 6** |
| **Verdict** | **Tractable.** The REALITY/TLS/VLESS/Vision code is already written as poll-driven, progress-storing state machines with zero BoringSSL and (in the TCP-only scope) exactly one runtime call. The work is a socket/executor bridge, not a protocol port. |

---

## 1. Scope decisions taken while reading

* **TCP only.** `VlessPacketConn` (UDP-over-TCP) is out of scope, so `crates/meow-proxy/src/vless/conn.rs:329-586` plus its 10 UDP tests (`conn.rs:942-1332`) and `meow-common/src/conn.rs:19-29` (`ProxyPacketConn`, `UdpPacket`) are **not ported**. This single decision removes 5 of the 6 production category-(b) tokio hits.
* **`features = ["tls"]` BoringSSL half is not ported.** `crates/meow-transport/src/tls.rs` is used only as a *source of config type definitions* (`EchOpts`, `RealityConfig`, `TlsConfig`, `ClientCert`). Its `mod boring_backend;` (line 50), `TlsBackend` (161-165), `TlsLayer` (169-233) and `impl Transport for TlsLayer` (235-244) are dropped. See §8.2.
* **`meow-proxy/src/vless_adapter.rs` and `transport_chain.rs` are not part of the listed port set** but were fetched to establish the call graph (§4). They drag in `ProxyAdapter`/`ProxyHealth`/`parking_lot`/`MuxClient`/`TcpDialer`; the port should not take them.

---

## 2. Dependency surface (per file)

Notation: **`EXT`** = third-party crate, **`WS`** = workspace crate (`meow-*`), **`LOCAL`** = same file, **`REL`** = sibling module in the same crate.

### 2.1 `crates/meow-transport/src/reality_tls.rs` — 2203 lines

Imports (verbatim, verbatim line numbers):

```rust
// reality_tls.rs:1-7   (std — all wasip2-safe)
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// reality_tls.rs:9-12  EXT
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce, Tag,
};
// reality_tls.rs:13    EXT
use hmac::{Hmac, Mac};
// reality_tls.rs:14    EXT
use sha2::{Digest, Sha256, Sha512};
// reality_tls.rs:15    EXT
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

// reality_tls.rs:17-20 REL + EXT(TransportError via crate root)
use crate::{
    tls::{RealityConfig, TlsConfig},
    Result, Stream, Transport, TransportError,
};
```

| item imported from outside the file | origin | wasip2 verdict |
|---|---|---|
| `VecDeque`, `io`, `Pin`, `Context`, `Poll`, `Duration`, `SystemTime`, `UNIX_EPOCH` | `std` | ✅ `SystemTime::now()` works on wasip2 (`wasi:clocks/wall-clock`). `Duration` is inert. No `Instant`. |
| `AeadInPlace`, `KeyInit`, `Aes128Gcm`, `Aes256Gcm`, `Nonce`, `Tag` | `aes-gcm` 0.10 (EXT) | ✅ pure Rust (RustCrypto), soft backend on wasm |
| `Hmac`, `Mac` | `hmac` 0.12 (EXT) | ✅ pure Rust |
| `Digest`, `Sha256`, `Sha512` | `sha2` 0.10 (EXT) | ✅ pure Rust |
| `AsyncRead`, `AsyncReadExt`, `AsyncWrite`, `AsyncWriteExt`, `ReadBuf` | `tokio::io` (EXT) | ✅ category (a) — compiles on `wasm32-wasip2` (verified, §2.11) |
| `RealityConfig`, `TlsConfig` | `crate::tls` (`tls.rs`) | config types only (§8.2) |
| `Result`, `Stream`, `Transport`, `TransportError` | `crate::` (`lib.rs`, `error.rs`) | shim, §3 |
| `x25519_dalek::x25519`, `x25519_dalek::X25519_BASEPOINT_BYTES` | `x25519-dalek` 2 (EXT) | ✅ pure Rust; **no `use` statement** — fully qualified at `:1361` and `:1365` |
| `rand::random::<[u8; 32]>()` | `rand` 0.9 (EXT) | ✅ via `getrandom 0.3` → `wasip2` crate (needs rustc ≥ 1.87); fully qualified, no `use` |
| `tracing::{debug!, warn!}` | `tracing` 0.1 (EXT) | ✅ no subscriber required, no-op without one |
| `async_trait::async_trait` | `async-trait` 0.1 (EXT) | ✅ proc-macro only; applied at `:127` |
| `tokio::time::timeout` | `tokio` (EXT) | ❌ **category (b)**, `:130` |

**No problem imports in this file.** No `boring`, no `tokio-boring`, no `tokio::net`, no `parking_lot`, no `libc`, no sockets, no filesystem, no threads.

### 2.2 `crates/meow-transport/src/tls.rs` — 244 lines

```rust
// tls.rs:45  EXT
use async_trait::async_trait;
// tls.rs:46  EXT
use tracing::warn;
// tls.rs:48  REL
use crate::{Result, Stream, Transport};
// tls.rs:50  REL — PRIVATE MODULE, BoringSSL. DROP.
mod boring_backend;
// tls.rs:52  REL — DROP.
use boring_backend::{BoringInner, LazyBoringInner};
```

| item | origin | verdict |
|---|---|---|
| `async_trait` | EXT | ✅ but only the dropped half (`:235`) needs it |
| `warn!` | `tracing` (EXT) | ✅ |
| `Result`, `Stream`, `Transport` | `crate::` | shim |
| `BoringInner::validate` (`:222`), `LazyBoringInner::new` (`:230`) | `crate::tls::boring_backend` | ❌ **BoringSSL — DROP** |
| `crate::reality_tls::RealityTlsLayer` (`:163`, `:207`) | REL | ✅ keep (`reality` feature path) |

**Verdict: this file is a *config-type donor*, not a port target.** Keep only lines **56-157** (`EchOpts`, `RealityConfig`, `TlsConfig`, `impl TlsConfig::new`, `ClientCert`). Everything from `159` down references `boring_backend` and cannot compile on wasip2.

### 2.3 `crates/meow-transport/src/lib.rs` — 130 lines

```rust
// lib.rs:23  std
use std::any::Any;
// lib.rs:25  EXT
use tokio::io::{AsyncRead, AsyncWrite};
// lib.rs:27  REL
pub use error::TransportError;
// lib.rs:29  REL
mod error;
// lib.rs:31-59  feature-gated modules — KEEP ONLY tls + reality_tls
#[cfg(feature = "tls")]         pub mod tls;                  // :31-32
#[cfg(all(feature = "tls", feature = "reality"))] mod reality_tls;  // :34-35
#[cfg(feature = "ws")]          pub mod ws;                   // :37-38
#[cfg(any(feature = "grpc", feature = "h2", feature = "xhttp"))] pub mod h2_common; // :40-41
#[cfg(feature = "grpc")]        pub mod grpc;                 // :43-44
#[cfg(feature = "h2")]          pub mod h2;                   // :46-47
#[cfg(feature = "httpupgrade")] pub mod httpupgrade;          // :49-50
#[cfg(feature = "xhttp")]       pub mod xhttp;                // :52-53
#[cfg(feature = "simple-obfs")] pub mod simple_obfs;          // :58-59
```

Also defines (all LOCAL, needed): `Stream` (`:71-79`), `enable_raw_passthrough`/`enable_raw_read_passthrough`/`enable_raw_write_passthrough` (`:81-117`), `Transport` (`:123-127`), `Result` (`:130`).

Problem imports: **none in the kept lines.** `tokio::io` is category (a). The dropped `ws`/`grpc`/`h2`/`xhttp`/`httpupgrade`/`simple_obfs` modules are the ones that pull `tokio-tungstenite`, `h2`, `http`, `httparse`, `base64`, `futures-util` — omit them and the dependency graph stays clean.

### 2.4 `crates/meow-transport/src/error.rs` — 36 lines

```rust
// error.rs:10  EXT
#[derive(Debug, thiserror::Error)]
```

**Zero imports.** Depends on `thiserror` 2 (EXT, proc-macro, ✅) and `std::io::Error` (`#[from]` at `:14`). Fully portable verbatim.

### 2.5 `crates/meow-proxy/src/vless/mod.rs` — 22 lines

No imports at all. Only module wiring:

```rust
pub(crate) mod conn;      // :9
pub(crate) mod header;    // :10
#[cfg(feature = "vless-vision")]
pub(crate) mod vision;    // :12-13
#[cfg(feature = "vless-encryption")]
pub mod encryption;       // :15-16   ← DROP (ml-kem/blake3/aes-ctr stack)
pub(crate) use conn::{VlessConn, VlessPacketConn};   // :18
pub(crate) use header::{addr_from_metadata, Cmd};    // :19
#[cfg(feature = "vless-vision")]
pub(crate) use vision::VisionConn;                   // :21-22
```

Portable as-is minus the `encryption` line. **No wasip2 issues.**

### 2.6 `crates/meow-proxy/src/vless/header.rs` — 442 lines

```rust
// header.rs:33  EXT
use bytes::{BufMut, BytesMut};
// header.rs:34  WS
use meow_common::Metadata;
```

| item | origin | verdict |
|---|---|---|
| `BufMut`, `BytesMut` | `bytes` 1 (EXT) | ✅ pure Rust |
| `Metadata` | `meow_common` (WS) | shim — used **only** by `addr_from_metadata(&Metadata)` (`:69-80`) which reads `m.host` and `m.dst_ip` |
| `smol_str::SmolStr` | `smol_str` 0.3 (EXT) | ✅ pure Rust, **but note the MSRV trap**: `smol_str 0.3.6` requires rustc **1.89** (cargo reports it), and `wasip2 1.0.4` (via `getrandom 0.3`) requires rustc **1.87**. Fully qualified at `:45, :62, :78` — no `use` statement. Trivially replaceable with `String`. |
| `tokio::io::AsyncReadExt::read_exact`, `tokio::io::AsyncWriteExt`, `tokio::io::duplex` | `tokio::io` (EXT) | ✅ category (a), **test-only** (`:403-436`) |
| `std::net::IpAddr` | `std` | ✅ (`:74-75`) |

**No problem imports.** 10 of 11 tests are plain `#[test]`.

### 2.7 `crates/meow-proxy/src/vless/vision.rs` — 698 lines

```rust
// vision.rs:3-6  std
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
// vision.rs:8  WS
use meow_common::ProxyConn;
// vision.rs:9  EXT
use rand::RngCore;
// vision.rs:10 EXT
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
// vision.rs:12 REL
use super::conn::VlessConn;
```

| item | origin | verdict |
|---|---|---|
| `VecDeque`, `io`, `Pin`, `Context`, `Poll` | `std` | ✅ |
| `ProxyConn` | `meow_common` (WS) | shim (§3.7) — needed for `impl ProxyConn for VisionConn {}` at `:588` |
| `RngCore`, `rand::rng()` (`:284`) | `rand` 0.9 (EXT) | ✅ `ThreadRng` on wasip2 (single-threaded thread-local, seeded from `getrandom`) |
| `AsyncRead`, `AsyncWrite`, `ReadBuf` | `tokio::io` (EXT) | ✅ category (a) — **traits only, no `*Ext`, no runtime** |
| `VlessConn` | `super::conn` (REL) | keep |
| `tracing::{debug!}` | `tracing` (EXT) | ✅ (`:120, :156, :197, :379, :517`) |

**This file has zero runtime dependency and zero `tokio::net`/`spawn`/`time`.** It is portable essentially verbatim. Biggest obstacle here is only its `inner: VlessConn` field, which by value couples it to `conn.rs`.

### 2.8 `crates/meow-proxy/src/vless/conn.rs` — 1333 lines

```rust
// conn.rs:10-12  std
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
// conn.rs:14  EXT
use bytes::{BufMut, Bytes, BytesMut};
// conn.rs:15  WS
use meow_common::{MeowError, ProxyConn, ProxyPacketConn, Result};
// conn.rs:16  WS
use meow_transport::Stream;
// conn.rs:17  EXT
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
// conn.rs:19-20 REL (cfg mux — DROP for TCP-only)
#[cfg(feature = "mux")]
use super::header::encode_mux_request;
// conn.rs:21  REL
use super::header::{encode_request, Cmd, VlessAddr};
```

| item | origin | verdict |
|---|---|---|
| `io`, `Pin`, `ready!`, `Context`, `Poll` | `std` | ✅ |
| `BufMut`, `Bytes`, `BytesMut` | `bytes` (EXT) | ✅ |
| `MeowError`, `ProxyConn`, `ProxyPacketConn`, `Result` | `meow_common` (WS) | shim. `ProxyPacketConn` is **UDP-only** → droppable |
| `Stream` | `meow_transport` (WS) | shim (§3.3) |
| `AsyncRead`, `AsyncWrite`, `AsyncWriteExt`, `ReadBuf` | `tokio::io` (EXT) | ✅ category (a). `AsyncWriteExt` used at `:69-70`, `:125-126`, `:530-531` |
| `meow_transport::enable_raw_read_passthrough` / `enable_raw_write_passthrough` | `meow_transport` (WS) | `:218`, `:223` — shim (§3.5) |
| `crate::check_not_desynced` | `meow-proxy/src/lib.rs:121` | ❌ **UDP-only** (`:546, :550, :571`) → drop with `VlessPacketConn` |
| `crate::PoisonOnIncomplete::new` | `meow-proxy/src/lib.rs:99` | ❌ **UDP-only** (`:554`) → drop |
| `tokio::sync::Mutex`, `tokio::io::ReadHalf`/`WriteHalf` | `tokio` (EXT) | ❌ category (b) per the requested taxonomy, but **UDP-only** (`:353-354, :364, :380, :535-536`) and in fact runtime-independent (see §3 caveat in §3.5) |
| `tokio::io::split` | `tokio::io` (EXT) | ✅ category (a), `:533` — but UDP-only |
| `tracing::{debug!, warn!}` | `tracing` (EXT) | ✅ `:68, :71, :296, :425` |
| `async_trait::async_trait` | `async-trait` (EXT) | ✅ `:542` — UDP-only |

**`VlessConn` (TCP, `:25-327`) has no runtime dependency at all.** All its `tokio::io` uses are category (a).

### 2.9 `crates/meow-common/src/**` — only the referenced items

Grep-driven: the port set references exactly **`MeowError`, `Result`, `ProxyConn`, `ProxyPacketConn`, `Metadata`** (plus, transitively through `Metadata`, `Network`, `ConnType`, `DnsMode`, `SmolStr`, `serde`).

| file | imports | verdict |
|---|---|---|
| `meow-common/src/lib.rs` (54 lines) | re-export facade; 18 `pub mod`s and 40 re-exports. **Only lines 30 (`conn::{ProxyConn, ProxyPacketConn, UdpPacket}`), 33 (`error::{MeowError, Result}`), 35 (`metadata::{AddrDisplay, Metadata}`) matter.** | Take the 3 re-exports, drop the other 15 modules — they pull `parking_lot`, `ipnet`, `subtle`, `httparse`, `socket2`, `libc`, `libproc`, `windows-sys`, `time`, `serde_json`, `tokio::net`, `time` |
| `meow-common/src/conn.rs` (29 lines) | `crate::error::Result`; **EXT `bytes::Bytes`**; `std::net::SocketAddr`; **EXT `tokio::io::{AsyncRead, AsyncWrite}`**; **EXT `async_trait::async_trait`**; **`tokio::net::TcpStream` at `:13`** | ⚠️ **`impl ProxyConn for tokio::net::TcpStream {}` (`:13`) uses `tokio::net`, which is a hard `compile_error!` on wasm. Must be deleted.** `ProxyPacketConn` (`:18-24`) and `UdpPacket` (`:26-29`) are UDP-only → drop (drops the `bytes` + `async_trait` deps too) |
| `meow-common/src/error.rs` (33 lines) | **EXT `thiserror::Error`** | ✅ verbatim; only `Io`, `Config`, `Proxy`, `NotSupported` are used by the port set |
| `meow-common/src/metadata.rs` (243 lines) | `crate::{ConnType, DnsMode, Network}`; **EXT `serde::{Deserialize, Serialize}`**; **EXT `smol_str::SmolStr`**; `std::fmt`; `std::net::{IpAddr, SocketAddr}` | ⚠️ Only `host: SmolStr` (`:26`), `dst_ip: Option<IpAddr>` (`:21`), `dst_port: u16` (`:25`) and `remote_address()`/`AddrDisplay` (`:88-156`) are used. Port a 4-field struct + `remote_address()` to delete `serde` + `smol_str` + `Network`/`ConnType`/`DnsMode` entirely |
| `meow-common/src/adapter_type.rs` | `serde`, `std::fmt` | only via `Metadata.conn_type` → droppable |
| `meow-common/src/network.rs` | `serde`, `std::fmt` | only via `Metadata.network` → droppable |
| `meow-common/src/dns_mode.rs` | `serde`, `std::fmt` | only via `Metadata.dns_mode` → droppable |
| `meow-common/src/adapter.rs` | `async_trait`, `serde`, `std::time::SystemTime`, `std::sync::{Arc, RwLock}`, `std::collections::VecDeque`, `crate::conn`, `crate::metadata`; `time::OffsetDateTime` in the `rfc3339_system_time` submodule | ❌ **NOT NEEDED.** `ProxyAdapter`/`Proxy`/`ProxyHealth`/`DelayHistory` are only used by `vless_adapter.rs`, which the port should not take |
| `meow-common/src/atomic.rs`, `auth.rs`, `dial.rs`, `health_check.rs`, `home_dir.rs`, `outbound_iface.rs`, `process_lookup.rs`, `rule.rs`, `sniffer/*`, `socket_protect.rs`, `tunnel_mode.rs` | — | ❌ **NOT NEEDED** — not reachable from the port set. (`dial.rs` pulls `tokio::time::Instant`; `socket_protect.rs`/`process_lookup.rs` are OS-specific) |

### 2.10 Cargo manifests

**`crates/meow-transport/Cargo.toml` (159 lines).** Only these lines matter for the port:

```toml
# Cargo.toml:76-84
[dependencies]
async-trait = { workspace = true }   # pure Rust, wasip2 OK
thiserror   = { workspace = true }   # pure Rust, wasip2 OK
tracing     = { workspace = true }   # pure Rust, wasip2 OK
tokio       = { workspace = true }   # ⚠ wasm: only sync/macros/io-util/rt/time
bytes       = { workspace = true }   # pure Rust, wasip2 OK
aes-gcm     = { workspace = true }   # pure Rust, wasip2 OK
hmac        = { workspace = true }   # pure Rust, wasip2 OK
sha2        = { workspace = true }   # pure Rust, wasip2 OK
# Cargo.toml:100  reality feature
x25519-dalek = { workspace = true, optional = true }  # pure Rust, wasip2 OK
# Cargo.toml:94   grpc/h2/xhttp feature
rand = { workspace = true, optional = true }          # wasip2 OK via getrandom 0.3
```

**Cargo.toml:24-30** — the `tls` feature pulls the problem deps; **do not enable it**:

```toml
tls = [
    "dep:boring",            # ❌ BoringSSL, C++ (cmake + C++ toolchain)
    "dep:tokio-boring",      # ❌ BoringSSL
    "dep:boring-sys",        # ❌ vendored BoringSSL
    "dep:rand",
    "dep:webpki-root-certs", # ❌ CA DER blobs (harmless but unneeded)
]
```
Other problem feature blocks: `ws` (`:44-48`, tokio-tungstenite/futures-util/base64), `grpc`/`h2`/`xhttp` (`:49-66`, h2/http), `httpupgrade` (`:59-61`, httparse), `simple-obfs` (`:74`, base64). `reality` (`:39-43`) is clean — the comment there says it explicitly: *"the record layer, the X25519 / HKDF / AES-GCM crypto and the ClientHello builder are all in-tree (`reality_tls.rs`) on top of the always-present aes-gcm/hmac/sha2 deps, so this does not touch BoringSSL at all."*
**Dev-dependencies (`:118-132`) are irrelevant to the port** except as a warning: `tokio-rustls`, `rustls`, `rcgen`, `md5`, `tracing-subscriber`, `regex` are all test-only.

**`crates/meow-proxy/Cargo.toml` (114 lines).** Baseline deps (`:51-96`) are largely irrelevant once the port drops `vless_adapter.rs`; the ones the VLESS port itself needs are `meow-common`, `meow-transport`, `tokio`, `tracing`, `bytes`, `rand`, `smol_str`. Problem entries: `meow-dns` (`:53`, unused by the port set), `quiche`/`boring` (`:62, :65`, hysteria2), `shadowsocks`/`argon2` (`:69-70`), `socket2`/`libc` (`:81-82`), `h2`/`yamux`/`tokio-util` (`:56-58`, mux). The `vless` feature (`:15`) is empty and clean; `vless-vision = ["vless"]` (`:17`) is clean; `mux` (`:45`) is not needed; `vless-encryption` (`:22-31`) pulls `blake3`/`ml-kem`/`ctr`/`chacha20poly1305` and is dropped.

**`crates/meow-common/Cargo.toml` (57 lines).** `[dependencies]` lists 13 crates (`:12-24`); for the port subset only `tokio`, `serde`, `smol_str`, `async-trait`, `thiserror`, `bytes` appear in the ported files — and if `Metadata` is reduced to 3 fields, only `tokio` + `thiserror` survive. Problem entries that must **not** come along: `parking_lot`, `serde_json`, `time`, `httparse`, `ipnet`, `subtle`, and the four target-specific `socket2`/`libc`/`libproc`/`windows-sys` blocks (`:26-43`).

### 2.11 External crate table + wasip2 verdict (with empirical evidence)

| # | crate | version (workspace) | pure Rust | wasip2 | how used in port set |
|---|---|---|---|---|---|
| 1 | `aes-gcm` | 0.10 | ✅ | ✅ compiles | `reality_tls.rs` GCM for TLS records + REALITY session_id seal |
| 2 | `hmac` | 0.12 | ✅ | ✅ compiles | HKDF-SHA256 + HMAC-SHA512 REALITY cert auth |
| 3 | `sha2` | 0.10 | ✅ | ✅ compiles | transcript hashing, HKDF |
| 4 | `x25519-dalek` | 2 (`static_secrets`) | ✅ | ✅ compiles | ECDH key share + REALITY auth key |
| 5 | `rand` | 0.9 | ✅ | ✅ compiles; **runtime verified in `PLAN.md` §1.3** | `rand::random()` client keys/random, `rand::rng()` Vision padding |
| 6 | `tokio` | 1.53.1 | ✅ | ⚠️ **partial** | `tokio::io` traits (a) + `tokio::time`/`sync` (b) |
| 7 | `async-trait` | 0.1 | ✅ | ✅ compiles | `Transport`, `ProxyAdapter`, `ProxyPacketConn` |
| 8 | `thiserror` | 2 | ✅ | ✅ compiles | `TransportError`, `MeowError` |
| 9 | `tracing` | 0.1 | ✅ | ✅ compiles | `debug!`/`warn!` only; no subscriber needed |
| 10 | `bytes` | 1 | ✅ | ✅ compiles | `BytesMut`/`BufMut` VLESS header + `Bytes` deferred header |
| 11 | `smol_str` | 0.3 | ✅ | ✅ compiles, **but 0.3.6 needs rustc ≥ 1.89** | only `VlessAddr::Domain` and `Metadata.host` |
| 12 | `serde` | 1 (derive) | ✅ | ✅ compiles | only `Metadata`'s derives |

**Problem crates referenced by *neighbouring* meow code (must never enter the port's dependency graph):**
`boring`, `tokio-boring`, `boring-sys` (C++ BoringSSL, cmake), `webpki-root-certs`, `mio` (`os-poll` epoll/kqueue), `quiche`, `shadowsocks`, `argon2`, `blake3`, `ml-kem`, `ctr`, `chacha20poly1305`, `md-5`, `crc32fast`, `tokio-tungstenite`, `futures-util` (pulls `futures`), `h2`, `http`, `yamux`, `tokio-util`, `httparse`, `parking_lot`, `socket2`, `libc`, `libproc`, `windows-sys`, `ipnet`, `subtle`, `time`, `serde_json`, `zstd`, `maxminddb`, `hickory-proto`, `criterion`, `dhat`.

#### Empirical verification performed for this map

A scratch crate in `/Users/xbtg-/deepseek-harness/.scratch/portmap/core-probe/` declares the full crypto + async set and was checked against the real target:

```
cargo check --target wasm32-wasip2        # rustc 1.85.0-nightly, tokio 1.53.1
    Finished `dev` profile ... EXIT 0
```

It exercises, in one crate: `Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any` with the blanket impl, `#[async_trait] trait Transport { async fn connect(...) }`, `#[derive(thiserror::Error)] enum TransportError`, `Aes128Gcm`/`Aes256Gcm` `encrypt_in_place_detached`/`decrypt_in_place_detached`, `Hmac<Sha256>`/`Hmac<Sha512>`, `Sha256::digest`, `x25519_dalek::x25519`, `rand::random()` + `rand::rng()`, `tracing`, `bytes`, `ReadBuf`, `AsyncReadExt::read`, `AsyncWriteExt::write_all/flush`, `tokio::io::duplex`, `tokio::io::split`, `ReadHalf`/`WriteHalf`, `tokio::sync::Mutex`, `tokio::time::timeout`, `std::time::SystemTime::now()`. **All of it compiles.**

The two hard constraints discovered:

1. `tokio` with the **`net`** feature is a **hard compile error** on wasm. Verbatim from `tokio-1.53.1/src/lib.rs:479`:
   ```
   error: Only features sync,macros,io-util,rt,time are supported on wasm.
     --> .../tokio-1.53.1/src/lib.rs:479:1
     479 | compile_error!("Only features sync,macros,io-util,rt,time are supported on wasm.");
   ```
   (doc comment at `tokio-1.53.1/src/lib.rs:425-443`; the guard at `:467-479` triggers on `fs`, `io-std`, `net`, `process`, `rt-multi-thread`, `signal`.)
2. `getrandom 0.3`'s wasip2 backend is the `wasip2` crate, which **requires rustc ≥ 1.87**; `smol_str 0.3.6` requires **≥ 1.89**. On an older toolchain you must either upgrade rustc or pass `--ignore-rust-version`. The toolchain in this workspace (rustup `nightly-aarch64-apple-darwin`, rustc 1.85.0-nightly) needs `--ignore-rust-version`.

`std` support on `wasm32-wasip2` (from `library/std/src/sys/pal/wasip2/mod.rs`): `net.rs` is real (sockets via `libc`/poll shims), `set_nonblocking` **is implemented** (`net.rs:315-318`, `ioctl(FIONBIO)`), but `process` and `pipe` map to `unsupported/`, and `thread.rs:124-125` makes `std::thread::spawn` → `unsupported()`. So: **sockets yes, threads no, processes no.**

---

## 3. Minimal shim list

Everything below must exist for the ported code to compile standalone. Definitions are copied verbatim from meow-rs.

### 3.1 `TransportError` — `crates/meow-transport/src/error.rs:1-36` (verbatim, all 8 variants)

```rust
/// All errors produced by `meow-transport` layers.
///
/// `#[non_exhaustive]` ensures that adding new variants in future minor
/// versions is not a breaking change for downstream matchers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls handshake: {0}")]
    Tls(String),

    #[error("websocket handshake: {0}")]
    WebSocket(String),

    #[error("grpc framing: {0}")]
    Grpc(String),

    #[error("h2: {0}")]
    H2(String),

    #[error("http upgrade: {0}")]
    HttpUpgrade(String),

    #[error("xhttp: {0}")]
    Xhttp(String),

    #[error("invalid config: {0}")]
    Config(String),
}
```

### 3.2 `Result` — `crates/meow-transport/src/lib.rs:129-130`

```rust
/// Crate-level `Result` alias.  Errors are always [`TransportError`].
pub type Result<T> = std::result::Result<T, TransportError>;
```

### 3.3 `Stream` — `crates/meow-transport/src/lib.rs:61-79` (verbatim, **note the `Any` supertrait and the `Sync` requirement**)

```rust
/// A duplex byte stream — the currency passed between transport layers.
///
/// Blanket-implemented for every `T: AsyncRead + AsyncWrite + Unpin + Send + Sync`,
/// so `TcpStream`, `TlsStream<…>`, `WebSocketStream<…>`, etc. all qualify.
///
/// `Sync` is required (in addition to ADR-0001's `Send`) so that a
/// `Box<dyn Stream>` can satisfy `ProxyConn` in `meow-proxy`, which
/// requires `Sync` for connection-table access.  All concrete stream types
/// we use (`TcpStream`, `TlsStream`, `WsStream`) are `Sync`; the bound
/// adds no real restriction in practice.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + Any> Stream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
```

(`use std::any::Any;` at `lib.rs:23`.) **Consequences the porting engineer must respect:**
* `Stream` is object-safe but `dyn Stream` does **not** itself implement `Stream` (the blanket impl has an implicit `Sized` bound), so every wrapper stores `Box<dyn Stream>` **by value**; that is exactly what `RealityConnected.inner` (`reality_tls.rs:145`), `RealityTlsStream.inner` (`:271`) and `VlessConn.inner` (`conn.rs:31`) do.
* The `Any` supertrait is what makes the REALITY raw-passthrough downcast work (§3.5).

### 3.4 `Transport` — `crates/meow-transport/src/lib.rs:119-127` (verbatim)

```rust
/// A transport layer that wraps an inner [`Stream`] and produces a new one.
///
/// Implementations are cheap to clone (typically an `Arc<Config>` inside).
/// The trait is object-safe: `Box<dyn Transport>` is valid.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Wrap `inner` with this transport layer and return the upgraded stream.
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}
```

**`async-trait` cannot be dropped** unless you hand-write the desugared signature, because `TransportChain` stores `Vec<Box<dyn Transport>>` (`transport_chain.rs:26`) and native `async fn` in traits is not dyn-compatible. If the port avoids `Box<dyn Transport>` it could use native `async fn` (Rust ≥ 1.75) and drop `async-trait` everywhere except `ProxyConn`/`ProxyPacketConn` (which have no async methods and are not `async_trait`-annotated for `ProxyConn`).

### 3.5 REALITY raw passthrough helpers — `crates/meow-transport/src/lib.rs:81-117` (verbatim)

```rust
pub fn enable_raw_passthrough(stream: &mut dyn Stream) -> bool {
    let read = enable_raw_read_passthrough(stream);
    let write = enable_raw_write_passthrough(stream);
    read || write
}

pub fn enable_raw_read_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(all(feature = "tls", feature = "reality"))]
    {
        if let Some(reality) = stream
            .as_any_mut()
            .downcast_mut::<reality_tls::RealityTlsStream>()
        {
            reality.enable_raw_read_passthrough();
            return true;
        }
    }

    let _ = stream;
    false
}

pub fn enable_raw_write_passthrough(stream: &mut dyn Stream) -> bool {
    #[cfg(all(feature = "tls", feature = "reality"))]
    {
        if let Some(reality) = stream
            .as_any_mut()
            .downcast_mut::<reality_tls::RealityTlsStream>()
        {
            reality.enable_raw_write_passthrough();
            return true;
        }
    }

    let _ = stream;
    false
}
```

For the port these can be simplified to a single unconditional block (no feature gate), but keep the `as_any_mut().downcast_mut::<RealityTlsStream>()` shape — Vision depends on it (`vision.rs:114, :187, :191` → `conn.rs:218, :223`).

### 3.6 Transport config types — `crates/meow-transport/src/tls.rs:56-157` (verbatim)

```rust
/// Source of the ECH config list.
///
/// DNS-sourced ECH (`ech-opts.enable = true` without `ech-opts.config`) is
/// deferred until `meow-dns` gains SVCB/HTTPS record support.
#[derive(Debug, Clone)]
pub enum EchOpts {
    /// Inline ECH config list bytes, base64-decoded by `meow-config` before
    /// this struct is constructed.
    ///
    /// YAML key: `ech-opts.config`
    Config(Vec<u8>),
}

/// REALITY client authentication parameters for TLS-based outbound proxies.
///
/// Built by `meow-config` from `reality-opts:`. The public key is the server's
/// X25519 public key, and `short_id` is the decoded, zero-padded short id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub support_x25519_mlkem768: bool,
}

/// TLS layer configuration, built by `meow-config` from YAML and passed
/// into [`TlsLayer::new`].  This struct never sees YAML directly.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether TLS is enabled. ...
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

    /// `client-fingerprint` YAML value.
    pub fingerprint: Option<String>,

    /// Extra CA certificates (DER-encoded) added to the root store ...
    pub additional_roots: Vec<Vec<u8>>,

    /// ECH config source.
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
```

**Field-by-field portability audit of `TlsConfig`** (from where each is read in `reality_tls.rs`):

| field | read at | port action |
|---|---|---|
| `sni` | `reality_tls.rs:94` | **required** |
| `reality` | `reality_tls.rs:99` | **required** |
| `alpn` | `reality_tls.rs:121`, used at `:601-602` | **required** |
| `ech` | `reality_tls.rs:103` (rejects non-`None`) | keep or drop (only a validation branch) |
| `client_cert` | `reality_tls.rs:108` (rejects non-`None`) | keep or drop |
| `skip_cert_verify` | `reality_tls.rs:113` (warn only) | keep or drop |
| `enabled`, `fingerprint`, `additional_roots` | **never read** by `reality_tls.rs` | deletable |
| `RealityConfig::support_x25519_mlkem768` | **never read anywhere in the port set** (only assigned `false` in tests at `:1422, :1739, :2122`) | deletable / inert — do not implement ML-KEM |

### 3.7 `ProxyConn` — `crates/meow-common/src/conn.rs:1-16` (verbatim, **with the wasip2 landmine at `:13`**)

```rust
use crate::error::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyConn: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn remote_destination(&self) -> String {
        String::new()
    }
}

// Blanket impl for TcpStream etc.
impl ProxyConn for tokio::net::TcpStream {}          // ← conn.rs:13  MUST BE DELETED (tokio::net)

// Impl for Box<dyn ProxyConn>
impl<T: ProxyConn + ?Sized> ProxyConn for Box<T> {}
```

`Result` here is `meow_common::Result<T> = std::result::Result<T, MeowError>` (unused by the trait itself). Port action: keep the trait and the `Box<T>` impl, **delete line 13**, delete everything from `:19` down.

### 3.8 `MeowError` — `crates/meow-common/src/error.rs:1-33` (verbatim; only 4 variants are reachable)

```rust
use thiserror::Error;

#[derive(Error, Debug)]
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

pub type Result<T> = std::result::Result<T, MeowError>;
```

Reachable variants in the TCP-only port set: `Io` (`conn.rs:69, :70`), `Config` (`vless_adapter.rs:291`), `Proxy` (`conn.rs:415, :430`), `NotSupported` (`conn.rs:577`). The `#[from] std::io::Error` impl is what makes `.map_err(MeowError::Io)` work.

### 3.9 `ProxyPacketConn` + `UdpPacket` — **NOT NEEDED** (UDP-only)

`crates/meow-common/src/conn.rs:18-29`:

```rust
#[async_trait::async_trait]
pub trait ProxyPacketConn: Send + Sync {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn close(&self) -> Result<()>;
}

pub struct UdpPacket {
    pub data: Bytes,
    pub addr: SocketAddr,
}
```
Only `VlessPacketConn` implements it (`conn.rs:542-586`). Drop both, and `async-trait` + `bytes` stop being needed by the shim crate.

### 3.10 `Metadata` (reduced) — derived from `crates/meow-common/src/metadata.rs`

The port set touches exactly four members:

```rust
// consumed by header.rs:69-80
m.host           // metadata.rs:26   pub host: SmolStr
m.dst_ip         // metadata.rs:21   pub dst_ip: Option<IpAddr>
// consumed by vless_adapter.rs:270, :312, :359
metadata.remote_address()   // metadata.rs:150-156
metadata.dst_port           // metadata.rs:25   pub dst_port: u16
```

Verbatim originals:

```rust
// metadata.rs:149-156
impl Metadata {
    pub fn remote_address(&self) -> AddrDisplay<'_> {
        AddrDisplay {
            host: &self.host,
            ip: self.dst_ip,
            port: self.dst_port,
        }
    }
```

```rust
// metadata.rs:88-98, 137-147
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
```

**Recommended port shape** (deletes `serde`, `smol_str`, `Network`, `ConnType`, `DnsMode`, `CompactAddrBuf`, `PartialEq<&str>`, `source_address`, `pure`, `lower_host`, `rule_host`, `resolved`):

```rust
pub struct Metadata {
    pub host: String,          // was SmolStr
    pub dst_ip: Option<std::net::IpAddr>,
    pub dst_port: u16,
}
```

If you instead want `Metadata` verbatim you must also port `network.rs` (18 lines), `adapter_type.rs` (88 lines), `dns_mode.rs` (30 lines), `CompactAddrBuf` (`metadata.rs:109-135`), and accept `serde` + `smol_str` as deps. The `Default` impl (`:62-86`) and `Display` (`:213-243`) are otherwise self-contained.

### 3.11 `AddrDisplay` — see §3.10.

### 3.12 `check_not_desynced` + `PoisonOnIncomplete` — **NOT NEEDED** (UDP-only)

`crates/meow-proxy/src/lib.rs:91-130`, verbatim for the record:

```rust
#[cfg(any(feature = "trojan", feature = "vless"))]
pub(crate) struct PoisonOnIncomplete<'a> {
    flag: &'a std::sync::atomic::AtomicBool,
    pub(crate) complete: bool,
}

#[cfg(any(feature = "trojan", feature = "vless"))]
impl<'a> PoisonOnIncomplete<'a> {
    pub(crate) fn new(flag: &'a std::sync::atomic::AtomicBool) -> Self {
        Self {
            flag,
            complete: false,
        }
    }
}

#[cfg(any(feature = "trojan", feature = "vless"))]
impl Drop for PoisonOnIncomplete<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[cfg(any(feature = "trojan", feature = "vless"))]
pub(crate) fn check_not_desynced(
    flag: &std::sync::atomic::AtomicBool,
) -> Result<(), meow_common::MeowError> {
    if flag.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(meow_common::MeowError::Proxy(
            "udp-over-tcp: connection desynced by an earlier incomplete frame".into(),
        ));
    }
    Ok(())
}
```

Referenced only at `conn.rs:546, :550, :554, :571` — all inside `VlessPacketConn`. Drop with UDP. (`std::sync::atomic::AtomicBool` itself is perfectly wasip2-safe, but nothing else needs it.)

### 3.13 Shim inventory summary

| # | shim | source | must be written by hand? |
|---|---|---|---|
| 1 | `TransportError` (8 variants) | `meow-transport/error.rs` | copy verbatim |
| 2 | `type Result<T>` (meow-transport) | `meow-transport/lib.rs:130` | copy |
| 3 | `trait Stream` + blanket impl | `meow-transport/lib.rs:71-79` | copy |
| 4 | `trait Transport` (`async_trait`) | `meow-transport/lib.rs:123-127` | copy |
| 5 | `enable_raw_{read,write}_passthrough` | `meow-transport/lib.rs:81-117` | copy, drop the `#[cfg]` |
| 6 | `EchOpts`, `RealityConfig`, `TlsConfig`, `ClientCert` | `meow-transport/tls.rs:56-157` | copy, drop `enabled`/`fingerprint`/`additional_roots`/`support_x25519_mlkem768` |
| 7 | `trait ProxyConn` + `Box<T>` impl | `meow-common/conn.rs:6-16` | copy, **delete `:13`** |
| 8 | `MeowError` + `Result` | `meow-common/error.rs` | copy (or trim to 4 variants) |
| 9 | `Metadata` (3 fields) + `AddrDisplay` | `meow-common/metadata.rs` | hand-write ~40 lines |
| 10 | type alias `Result<T> = Result<T, MeowError>` inside `conn.rs` scope | `meow-common/error.rs:33` | copy |
| — | `ProxyPacketConn`, `UdpPacket`, `check_not_desynced`, `PoisonOnIncomplete`, `ProxyAdapter`, `ProxyHealth`, `TransportChain` | — | **not needed** (UDP / adapter-layer / optional) |

**Total hand-written shim surface: ~120 lines.** Everything else is copied.

---

## 4. Call graph / entry point

### 4.1 The public entry point for "connect through REALITY"

`RealityTlsLayer` is **not** publicly reachable: `reality_tls` is a *private* module (`lib.rs:35`: `mod reality_tls;`, no `pub`) and `RealityTlsLayer` is `pub(crate)` (`reality_tls.rs:86`). The public entry is the `TlsLayer` facade plus the `Transport` trait. Verbatim:

```rust
// reality_tls.rs:85-90
#[derive(Clone)]
pub(crate) struct RealityTlsLayer {
    server_name: String,
    alpn: Vec<String>,
    reality: RealityConfig,
}

// reality_tls.rs:92-125
impl RealityTlsLayer {
    pub(crate) fn new(config: &TlsConfig) -> Result<Self> { /* ... */ }
}

// reality_tls.rs:127-142
#[async_trait::async_trait]
impl Transport for RealityTlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let state = tokio::time::timeout(                       // ← :130  THE one production (b) hit
            REALITY_HANDSHAKE_TIMEOUT,
            reality_handshake(inner, &self.server_name, &self.alpn, &self.reality),
        )
        .await
        .map_err(|_| {
            TransportError::Tls(format!(
                "Reality TLS: handshake did not complete within {REALITY_HANDSHAKE_TIMEOUT:?}"
            ))
        })??;
        Ok(spawn_reality_stream(state))
    }
}
```

```rust
// tls.rs:178-233  (the public facade; only its REALITY arm is portable)
impl TlsLayer {
    pub fn new(config: &TlsConfig) -> Result<Self> { /* ... dispatches to reality_tls::RealityTlsLayer::new at :207 ... */ }
}

// tls.rs:235-244
#[async_trait]
impl Transport for TlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        match &self.backend {
            #[cfg(feature = "reality")]
            TlsBackend::Reality(r) => r.connect(inner).await,
            TlsBackend::Boring(lazy) => lazy.connect(inner).await,   // ← DROP
        }
    }
}
```

**Recommended port entry point** (drops the `TlsLayer`/`TlsBackend` enum entirely):

```rust
// shim crate (e.g. xt-wasm-tls)
pub struct RealityTlsLayer { server_name: String, alpn: Vec<String>, reality: RealityConfig }
impl RealityTlsLayer {
    pub fn new(config: &TlsConfig) -> Result<Self>;                 // ::new is `pub(crate)` upstream — make it `pub`
}
#[async_trait::async_trait]
impl Transport for RealityTlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}
```

### 4.2 The handshake core — verbatim signature

```rust
// reality_tls.rs:144-155
struct RealityConnected {
    inner: Box<dyn Stream>,
    read_key: RecordKey,
    write_key: RecordKey,
}

async fn reality_handshake(
    mut inner: Box<dyn Stream>,
    server_name: &str,
    alpn: &[String],
    reality: &RealityConfig,
) -> Result<RealityConnected>
```

```rust
// reality_tls.rs:270-279
pub(crate) struct RealityTlsStream {
    inner: Box<dyn Stream>,
    read_key: RecordKey,
    write_key: RecordKey,
    read_raw_passthrough: bool,
    write_raw_passthrough: bool,
    read_plain: VecDeque<u8>,
    read_state: StreamReadState,
    write_pending: Option<StreamPendingWrite>,
}

// reality_tls.rs:547-561
fn spawn_reality_stream(state: RealityConnected) -> Box<dyn Stream>
```

`RealityTlsStream` implements `AsyncRead` (`:344-477`) and `AsyncWrite` (`:479-545`) as **fully poll-driven, progress-storing state machines** — every `Poll::Pending` writes the partial progress back into `self.read_state` / `self.write_pending` first (`:374, :384, :416, :425-431, :436-441, :474`, and `:516`). This is the single most port-friendly property of the whole codebase: **the REALITY stream needs no runtime, only an executor that polls it and a `Stream` whose `poll_read`/`poll_write` actually park-and-wake.**

### 4.3 End-to-end path

```
VlessAdapter::dial_tcp(&Metadata)                                  [vless_adapter.rs:267]
  │
  ├─ self.dialer.dial(&self.server, self.port)                     [vless_adapter.rs:221-225]
  │     → Box<dyn meow_transport::Stream>   (raw TCP)              ← THE SOCKET
  │
  ├─ self.transport.connect(stream).await                          [vless_adapter.rs:226; transport_chain.rs:49-58]
  │     │
  │     └─ for each Box<dyn Transport> layer, layer.connect(stream).await
  │           └─ TlsLayer::connect  → TlsBackend::Reality
  │                 └─ RealityTlsLayer::connect                    [reality_tls.rs:128-142]
  │                       ├─ tokio::time::timeout(REALITY_HANDSHAKE_TIMEOUT, …)   ◀── BLOCKING POINT #0 (the only runtime use)
  │                       └─ reality_handshake(inner, server_name, alpn, reality)  [reality_tls.rs:150]
  │                             ├─ rand::random ×2, x25519 pubkey, ECDH auth_key       [:156-159]
  │                             ├─ build_reality_client_hello(…)                      [:162; def :567-656]
  │                             ├─ inner.write_all(wrap_plain_record(…)).await        [:170-172] ◀── BLOCKING POINT #1
  │                             ├─ inner.flush().await                                [:173]     ◀── BLOCKING POINT #2
  │                             ├─ read_plain_handshake(&mut inner, HS_SERVER_HELLO)   [:178; def :730-757] ◀── BLOCKING POINT #3
  │                             ├─ x25519(client_private, server key_share)           [:190]
  │                             ├─ HandshakeKeys::derive(…)                           [:194; def :1144-1164]
  │                             ├─ loop { fill_decrypted_handshake(&mut inner, …) }   [:203-241; def :759-794] ◀── BLOCKING POINT #4
  │                             │     └─ ServerFlightGuard::admit + parse_leaf_certificate
  │                             ├─ verify_reality_certificate(leaf, auth_key)         [:245; def :1015-1032]  ← anti-MITM gate
  │                             ├─ ApplicationKeys::derive(…)                          [:248; def :1171-1181]
  │                             ├─ client_hs.seal(HS_FINISHED, …)                      [:255; def :1211-1232]
  │                             ├─ inner.write_all(&encrypted_finished).await         [:256] ◀── BLOCKING POINT #5
  │                             └─ inner.flush().await                                [:257]
  │
  ├─ addr_from_metadata(metadata)  → VlessAddr                     [vless_adapter.rs:282; header.rs:69-80]
  │
  ├─ if flow == xtls-rprx-vision:
  │     VlessConn::new_deferred(stream, uuid, flow_str, Cmd::Tcp, metadata.dst_port, &addr).await   [vless_adapter.rs:307-315; conn.rs:88-107]
  │       └─ encode_request(&mut BytesMut, …)  [header.rs:101-141]  (header NOT written yet — deferred)
  │     VisionConn::new(vless, self.uuid_bytes)                    [vless_adapter.rs:316; vision.rs:68-85]
  │       → Box<dyn ProxyConn>
  │
  └─ else:
        VlessConn::new(stream, uuid, flow_str, Cmd::Tcp, metadata.dst_port, &addr).await  [vless_adapter.rs:319-327; conn.rs:57-82]
          ├─ encode_request(&mut BytesMut, …)  [header.rs:101]
          ├─ stream.write_all(&buf).await    [:69]  ◀── BLOCKING POINT #6
          └─ stream.flush().await            [:70]  ◀── BLOCKING POINT #7
        StreamConn(Box::new(conn))       → Box<dyn ProxyConn>       [vless_adapter.rs:328]
```

**Then, on first use:**

* `VlessConn::poll_read` (`conn.rs:230-299`) lazily consumes the 2-byte response header `[version][addon_length]` + addon bytes with persistent progress (`response_buf`/`response_pos`/`response_addon`), then delegates to the inner stream. Error paths: version ≠ 0 → `InvalidData` (`:262-267`); EOF before the header → `UnexpectedEof` (`:249-252`); EOF mid-addon → `UnexpectedEof` (`:282-285`).
* `VlessConn::poll_write` (`conn.rs:303-310`) → `poll_write_deferred` (`:164-198`): prepends the buffered header to the caller's first payload, coalescing into one `poll_write` on the inner stream so the VLESS request rides **inside the first Vision-padded record**.
* `VisionConn::poll_write` (`vision.rs:534-565`) frames `uuid ‖ command ‖ content_len_be ‖ padding_len_be ‖ content ‖ padding` in `build_padding_frame` (`vision.rs:277-309`), chunking at 16 KiB (`:557`) so the `u16` length fields can't wrap. `VisionConn::poll_read` (`vision.rs:312-530`) unwraps the same framing and runs `ServerHelloFilter` (`vision.rs:207-259`) over the first ≤8 packets to detect TLS 1.3, which then flips `write_direct_enabled` (`:194-199`) and — on a `COMMAND_PADDING_DIRECT` frame — calls `enable_inner_raw_read/write_passthrough` (`:511-518`, `:113-121`) to switch the REALITY layer to raw splice.

### 4.4 Where the port's real work is

`REALITY_HANDSHAKE_TIMEOUT` (`reality_tls.rs:83`) is `Duration::from_secs(10)`. Replacing `tokio::time::timeout` at `:130` is a **one-line** change (e.g. a manual deadline check, or a `futures::future::select` against a timer, or `SO_RCVTIMEO` on the socket). The handshake is strictly sequential request/response (`:170-257`), so it never needs concurrent read+write and can be driven by a single-threaded executor even with a blocking socket.

The **full-duplex data path** after the handshake is the actual bridge problem: `VisionConn`/`RealityTlsStream` poll both directions independently and park on `Poll::Pending`. Over a blocking-socket `AsyncRead`/`AsyncWrite` shim, a parked `poll_read` blocks the only thread, so writes cannot progress. The port needs `set_nonblocking(true)` + a poll-based reactor (or `wasi:io/poll`) that returns `Poll::Pending` and registers wakers. Evidence this is available: `std`'s `wasip2` net pal implements `set_nonblocking` (`library/std/src/sys/pal/wasip2/net.rs:315-318`, `ioctl(FIONBIO)`), and `std::thread::spawn` is **not** available (`sys/pal/wasi/thread.rs:124-125` → `unsupported()`; `sys/pal/wasip2/mod.rs` maps `process` and `pipe` to `unsupported/`).

### 4.5 Signatures the port will call, verbatim

```rust
// conn.rs:57-64
pub async fn new(
    mut stream: Box<dyn Stream>,
    uuid_bytes: &[u8; 16],
    flow: Option<&str>,
    cmd: Cmd,
    dst_port: u16,
    addr: &VlessAddr,
) -> Result<Self>

// conn.rs:87-95   (cfg(any(feature = "mux", feature = "vless-vision")))
pub async fn new_deferred(
    stream: Box<dyn Stream>,
    uuid_bytes: &[u8; 16],
    flow: Option<&str>,
    cmd: Cmd,
    dst_port: u16,
    addr: &VlessAddr,
) -> Result<Self>

// vision.rs:68
pub fn new(inner: VlessConn, user_uuid: [u8; UUID_LEN]) -> Self

// header.rs:101-108
pub(crate) fn encode_request(
    dst: &mut BytesMut,
    uuid_bytes: &[u8; 16],
    flow: Option<&str>,
    cmd: Cmd,
    dst_port: u16,
    addr: &VlessAddr,
)

// header.rs:69
pub(crate) fn addr_from_metadata(m: &Metadata) -> VlessAddr

// header.rs:54
pub(crate) fn domain(s: &str) -> std::result::Result<Self, String>   // VlessAddr::domain

// transport_chain.rs:49
pub async fn connect(&self, raw: Box<dyn Stream>) -> Result<Box<dyn Stream>>

// vless_adapter.rs:267
async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>>
```

Also needed by the port (verbatim from `conn.rs`):

```rust
// conn.rs:217-224
pub(crate) fn enable_raw_read_passthrough(&mut self) -> bool {
    meow_transport::enable_raw_read_passthrough(&mut *self.inner)
}
pub(crate) fn enable_raw_write_passthrough(&mut self) -> bool {
    meow_transport::enable_raw_write_passthrough(&mut *self.inner)
}

// reality_tls.rs:282-290
pub(crate) fn enable_raw_read_passthrough(&mut self) {
    self.read_raw_passthrough = true;
    tracing::debug!("Reality TLS raw read passthrough enabled");
}
pub(crate) fn enable_raw_write_passthrough(&mut self) {
    self.write_raw_passthrough = true;
    tracing::debug!("Reality TLS raw write passthrough enabled");
}
```

---

## 5. tokio usage inventory

### 5.1 Category (b) — runtime-dependent, **must be replaced** (65 hits)

**Production (6).** Only the first survives a TCP-only scope:

| file:line | code | note |
|---|---|---|
| `crates/meow-transport/src/reality_tls.rs:130` | `tokio::time::timeout(` | **THE only production (b) hit in the TCP-only port.** Wraps `reality_handshake`. Needs a runtime time driver → must become a manual deadline / `SO_RCVTIMEO` / futures-timer. |
| `crates/meow-proxy/src/vless/conn.rs:353` | `reader: tokio::sync::Mutex<VlessUdpReader>,` | **UDP-only** (`VlessPacketConn`). *Factual caveat: `tokio::sync::Mutex` needs no runtime and compiles on wasip2 — it is listed here only because the task taxonomy puts `tokio::sync` in (b).* |
| `crates/meow-proxy/src/vless/conn.rs:354` | `writer: tokio::sync::Mutex<tokio::io::WriteHalf<Box<dyn Stream>>>,` | UDP-only; same caveat |
| `crates/meow-proxy/src/vless/conn.rs:535` | `reader: tokio::sync::Mutex::new(VlessUdpReader::new(reader)),` | UDP-only; same caveat |
| `crates/meow-proxy/src/vless/conn.rs:536` | `writer: tokio::sync::Mutex::new(writer),` | UDP-only; same caveat |
| `crates/meow-common/src/conn.rs:13` | `impl ProxyConn for tokio::net::TcpStream {}` | ❌ **`tokio::net` is a hard `compile_error!` on wasm.** Delete the line; replace with nothing (the port's own socket wrapper implements `ProxyConn` directly). |

**Test-only (59).** All inside `#[cfg(test)] mod tests`.

`crates/meow-transport/src/reality_tls.rs` — 8:
`:1615` `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`;
`:1648`, `:1677`, `:1705`, `:2125` `tokio::spawn`;
`:1880` `tokio::runtime::Builder::new_current_thread()`;
`:2114` `#[tokio::test]`;
`:2186` `tokio::time::timeout`.

`crates/meow-proxy/src/vless/header.rs` — 1:
`:403` `#[tokio::test]`.

`crates/meow-proxy/src/vless/conn.rs` — 50:
`#[tokio::test]` ×18 → `:675, :703, :733, :760, :787, :828, :863, :898, :942, :1009, :1049, :1086, :1119, :1165, :1212, :1240, :1266, :1293`;
`tokio::spawn` ×18 → `:650, :706, :736, :792, :832, :866, :901, :951, :978, :1014, :1053, :1090, :1123, :1169, :1215, :1243, :1269, :1296`;
`tokio::time::*` ×8 → `:946` (`use tokio::time::timeout;`), `:1143, :1152, :1190, :1199, :1313` (`timeout(…)`), `:985, :1301` (`sleep(…)`). *(Two further calls at `:989` and `:994` use the imported `timeout` unqualified, so they do not show up in a `tokio::` grep.)*;
`tokio::sync::oneshot` ×6 → `:648, :649, :1052, :1089, :1122, :1168`.

**Replacement cost per class:**
* `#[tokio::test]` → `#[test]` + `futures::executor::block_on(async { … })`. **`tokio::io::duplex` is an in-memory pipe with no runtime dependency**, so tests that only use `duplex` + `read_exact`/`write_all` port by changing the attribute and replacing `tokio::spawn(server)` with a polled-join (e.g. `futures::join!`, or `futures::executor::block_on` around a `join`).
* `tokio::spawn` ×18 in `conn.rs` → `futures::join!`/`select!`; the mock servers are all sequential request/response.
* `tokio::time::timeout`/`sleep` in tests → a wall-clock deadline loop or simply the harness's own timeout (wasmtime has `--timeout`).
* `tokio::runtime::Builder` at `:1880` → `futures::executor::block_on` (the `PendingOnce` mock self-wakes via `cx.waker().wake_by_ref()` at `:1830`, which works under any executor).
* `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]` at `:1615` → **cannot** be reproduced on wasip2 (no threads); either drop the test or rewrite as a single-threaded interleaved-drive test.

### 5.2 Category (a) — pure `tokio::io` trait/utility usage, **fine on wasip2** (31 hits)

**Production (10):**
`reality_tls.rs:15` `use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};`
`lib.rs:25` `use tokio::io::{AsyncRead, AsyncWrite};`
`vision.rs:10` `use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};`
`conn.rs:17` `use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};`
`conn.rs:354` `tokio::io::WriteHalf` (UDP-only)
`conn.rs:364`, `conn.rs:380` `tokio::io::ReadHalf` (UDP-only)
`conn.rs:402` `use tokio::io::AsyncReadExt;` (UDP-only)
`conn.rs:533` `tokio::io::split(stream)` (UDP-only)
`meow-common/conn.rs:4` `use tokio::io::{AsyncRead, AsyncWrite};`

**Test-only (21):**
`reality_tls.rs:1617, :2117` `tokio::io::duplex`; `:1649, :1678, :1706, :1876` `use tokio::io::{AsyncReadExt, AsyncWriteExt}`; `:1673` `tokio::io::split`; `:2116` `tokio::io::DuplexStream`;
`header.rs:405` `duplex`, `:406` `AsyncWriteExt`, `:424, :433` `AsyncReadExt::read_exact`;
`conn.rs:595, :598, :762, :789, :830, :887, :923, :1011`.

**Rule for the porting engineer:** the *only* tokio features the ported code needs are **`io-util`** (`AsyncRead`, `AsyncWrite`, `ReadBuf`, `AsyncReadExt`, `AsyncWriteExt`, `split`, `ReadHalf`, `WriteHalf`, `duplex`, `DuplexStream`) and — for the tests — **`macros`** (`#[tokio::test]`, if you keep them). Drop **`net`**, **`process`**, **`fs`**, **`signal`**, **`rt-multi-thread`**. If you replace the timeout at `:130`, drop **`time`** too. `tokio = { version = "1", default-features = false, features = ["io-util"] }` compiles for `wasm32-wasip2` (tokio 1.53.1) — the probe verified `io-util` + `sync` + `macros` together, and tokio's own doc comment at `lib.rs:425-431` lists `io-util` as supported.

---

## 6. Test inventory

### 6.1 `crates/meow-transport/src/reality_tls.rs` — `#[cfg(test)] mod tests` at `:1413-2203` (19 tests)

| # | test (line) | runtime? | what it proves | port? |
|---|---|---|---|---|
| 1 | `reality_client_hello_writes_32_byte_session_id` (`:1417`) | none (`#[test]`) | `hello[0] == HS_CLIENT_HELLO`, `hello[38] == 32` (32-byte session_id length field), `hello[39..71] != 0` | **✅ as-is** |
| 2 | `hkdf_expand_label_finished_len` (`:1441`) | none | `hkdf_expand_label(secret, b"finished", &[], 32)` → 32 bytes (RFC 8446 §7.1 label struct) | **✅ as-is** |
| 3 | `record_key_seal_open_round_trips_and_sequences` (`:1454`) | none | two `RecordKey`s from one secret round-trip **two** records and both nonce counters advance to 2 | **✅ as-is — high value** |
| 4 | `record_key_open_rejects_tampered_ciphertext` (`:1476`) | none | flipping the last GCM tag byte makes `open` fail (authenticity of the record layer) | **✅ as-is — high value** |
| 5 | `verify_reality_certificate_accepts_matching_hmac` (`:1551`) | none | a synthetic X.509 Ed25519 leaf whose `signature` equals `HMAC-SHA512(auth_key, pubkey)` verifies | **✅ as-is — high value** |
| 6 | `verify_reality_certificate_rejects_wrong_hmac` (`:1560`) | none | garbage signature rejected **and** correct cert under the wrong auth key rejected — the anti-MITM property | **✅ as-is — highest value security test** |
| 7 | `verify_reality_certificate_rejects_non_ed25519_leaf` (`:1576`) | none | SPKI OID ≠ 1.3.101.112 → `extract_ed25519_spki` returns `None` | **✅ as-is** |
| 8 | `split_concurrent_read_write_preserves_data` (`:1615`) | **`#[tokio::test(flavor="multi_thread", worker_threads=4)]`** + `duplex` (512 KiB) + `tokio::spawn` ×3 + `tokio::io::split` | 2000 deterministic chunks echo byte-exact through the REALITY record layer under concurrent split polling (would catch the mux stored-future corruption class) | ⚠️ **rewrite**: threads unavailable on wasip2. Replacing with a single-threaded interleaved drive still gives most of the value |
| 9 | `reality_client_hello_session_id_decrypts_to_auth_payload` (`:1734`) | none | **decrypts the 32-byte session_id under the *server-reconstructed* key/nonce/AAD** and asserts plaintext `[1,8,1,0] ‖ BE32(unix) ‖ short_id` | **✅ as-is — THE most valuable correctness check for the port** |
| 10 | `der_read_rejects_truncated_and_overlong_length` (`:1783`) | none | DER parser refuses truncated and 5-byte length-of-length | **✅ as-is** |
| 11 | `parse_server_hello_rejects_malformed_input` (`:1793`) | none | `<42` bytes, wrong handshake type → `Err` | **✅ as-is** |
| 12 | `poll_write_reports_new_chunk_len_after_pending_drain` (`:1856`) | `tokio::runtime::Builder::new_current_thread()` + `rt.block_on` | after a `Pending` drain the *second* `poll_write` reports the **new** buffer's length, not the old record's (the changed-buffer hazard from PR #413) | ⚠️ **port with `futures::executor::block_on`** — the `PendingOnce` mock is pure `AsyncRead`/`AsyncWrite` + `wake_by_ref`, no runtime needed. High value |
| 13 | `server_flight_guard_accepts_well_formed_flight` (`:1920`) | none | EE→Cert→CertVerify accepted in order; transcript equals the 3 framed messages concatenated | **✅ as-is** |
| 14 | `server_flight_guard_rejects_duplicate_encrypted_extensions` (`:1953`) | none | duplicate EE rejected | **✅ as-is** |
| 15 | `server_flight_guard_rejects_certificate_before_encrypted_extensions` (`:1972`) | none | ordering enforced | **✅ as-is** |
| 16 | `server_flight_guard_rejects_certificate_verify_before_certificate` (`:1982`) | none | ordering enforced | **✅ as-is** |
| 17 | `server_flight_guard_enforces_message_count_cap` (`:2008`) | none | `MAX_PRE_AUTH_HS_MESSAGES` (32) cap | **✅ as-is** |
| 18 | `server_flight_guard_enforces_transcript_byte_cap` (`:2027`) | none | `MAX_PRE_AUTH_TRANSCRIPT_LEN` (64 KiB) cap | **✅ as-is** |
| 19 | `reality_handshake_rejects_unbounded_encrypted_extensions_flood` (`:2114`) | **`#[tokio::test]`** + `duplex` + `tokio::spawn` + `tokio::time::timeout(10s)` | drives the **real `reality_handshake`** end-to-end against a fake server that does a genuine X25519 ECDH, derives matching `HandshakeKeys`, then floods 16 KiB `EncryptedExtensions` forever; asserts the client errors with *"unexpected EncryptedExtensions"* instead of accumulating | ⚠️ **must be ported** (it is the only test that exercises the real handshake state machine). Needs an in-memory duplex pair polled by one executor; no threads required |

**16 of 19 need no runtime at all.** The two you must invest in are **#9** (session_id semantics) and **#19** (real handshake end-to-end); **#12** is a cheap third.

Also note the test helpers that come free and are worth keeping: `der()` (`:1494-1508`), `build_test_ed25519_cert()` (`:1513-1543`), `reality_cert_hmac()` (`:1545-1549`), `handshake_message()` (`:1913-1918`), `extract_client_key_share()` (`:2047-2075`), `build_fake_server_hello()` (`:2081-2105`), `chunk()` (`:1597-1605`), `PendingOnce` (`:1807-1844`).

### 6.2 `crates/meow-proxy/src/vless/header.rs` — `mod tests` at `:182-442` (11 tests)

| # | test (line) | runtime? | proves | port? |
|---|---|---|---|---|
| 1 | `header_encode_version_byte_is_zero` (`:197`) | none | byte 0 is `0x00` (vs VMess `0x01`) | ✅ |
| 2 | `header_encode_tcp_ipv4_plain` (`:215`) | none | exact 26-byte layout: `ver,uuid×16,addon_len=0,cmd=1,port BE,atype=1,ip×4` | ✅ |
| 3 | `header_encode_tcp_domain_plain` (`:250`) | none | **port BEFORE addr_type**, domain `0x02` + len + bytes | ✅ |
| 4 | `header_encode_tcp_ipv6_plain` (`:277`) | none | `0x03` + 16 bytes at offset 21 | ✅ |
| 5 | `header_encode_udp_command` (`:298`) | none | `buf[18] == 0x02` for UDP | ✅ (cheap, keep) |
| 6 | `header_encode_addon_empty_for_plain_flow` (`:317`) | none | `addon_length == 0`, cmd follows immediately | ✅ |
| 7 | `header_encode_addon_vision_exact_bytes` (`:342`) | none | `addon_length == 18`, `0x0A 0x10` + `"xtls-rprx-vision"`, cmd at offset 36 | ✅ **high value** |
| 8 | `header_addr_domain_max_255_encodes` (`:365`) | none | 255-byte domain accepted | ✅ |
| 9 | `header_addr_domain_over_255_errors_at_build_time` (`:378`) | none | 256 bytes → `Err` (no silent truncation) | ✅ |
| 10 | `header_addr_idn_not_punycoded` (`:389`) | none | `"例え.jp"` appears as raw UTF-8 | ✅ |
| 11 | `header_encode_full_round_trip_via_decode` (`:403`) | **`#[tokio::test]`** + `tokio::io::duplex` | writes a request header, checks a `[0x00,0x00]` response header round-trips | ⚠️ trivial; either port with `futures::executor::block_on` or replace with a direct byte assertion |

**10 of 11 need no runtime** and are byte-exact wire-format pins — port all of them.

### 6.3 `crates/meow-proxy/src/vless/vision.rs` — `mod tests` at `:590-698` (6 tests)

| # | test (line) | runtime? | proves | port? |
|---|---|---|---|---|
| 1 | `padding_frame_with_uuid_matches_mihomo_layout` (`:596`) | none | the **real** 21-byte header: `UUID(16) ‖ cmd(1) ‖ content_len_be(2) ‖ padding_len_be(2)`, content at offset 21, total `= 21 + content + padding`, and (with `padding_tls=true`, `content.len() = 6`) `padding ≥ 900-6` and `< 1400-6` | ✅ **high value — this test is the authoritative Vision framing pin** |
| 2 | `padding_frame_without_uuid_uses_short_header` (`:620`) | none | continuation frames drop the UUID: 5-byte header, `padding < 256` | ✅ |
| 3 | `detects_client_hello_inside_vless_prefixed_payload` (`:635`) | none | `contains_tls_client_hello` scans with a 6-byte window for `16 03 xx .. 01` | ✅ |
| 4 | `server_hello_filter_detects_tls13` (`:644`) | none | `0x1301` + `00 2b 00 02 03 04` → true | ✅ |
| 5 | `server_hello_filter_handles_fragmented_record_header` (`:651`) | none | observes `hello[..3]` then `hello[3..]` → true (fragmentation tolerance) | ✅ |
| 6 | `server_hello_filter_rejects_non_tls13_cipher` (`:660`) | none | `0xc02f` (TLS 1.2) → false | ✅ |

**All 6 need no runtime.** Port all of them. Helper `tls13_server_hello(cipher_suite)` at `:667-697`.

### 6.4 `crates/meow-proxy/src/vless/conn.rs` — `mod tests` at `:590-1333` (18 tests, **all `#[tokio::test]`**)

TCP (relevant to the port):

| # | test (line) | proves | port? |
|---|---|---|---|
| 1 | `vless_conn_writes_request_header_on_connect` (`:675`) | 26-byte header written eagerly by `VlessConn::new`; mock captures it; `hdr[0]==0`,`hdr[1..17]==UUID` | ✅ port (`duplex` + `futures::join!`) |
| 2 | `deferred_header_handles_one_byte_partial_writes` (`:703`, cfg mux\|vision) | `new_deferred` + a `ChunkedStream` with `max_write = 1` still lands the header and payload correctly, and reads the server's first byte | ✅ **high value** (exercises the `poll_write_deferred` partial-write paths at `:186-195`) |
| 3 | `deferred_header_is_flushed_before_server_first_read` (`:733`, cfg mux\|vision) | server-first protocols: the deferred header is flushed before the first read (`poll_flush_deferred_header`, `:203-213`) | ✅ **high value** |
| 4 | `vless_conn_tcp_payload_round_trips` (`:760`) | 1 KiB payload echoes | ✅ |
| 5 | `vless_conn_reads_and_discards_response_header` (`:787`) | `[0x00,0x00]` is consumed; the first read returns the payload | ✅ |
| 6 | `vless_conn_response_with_nonzero_addon_length` (`:828`) | `[0x00,0x03,0xAA,0xBB,0xCC,0x42]` → first read yields `0x42` | ✅ |
| 7 | `vless_conn_version_mismatch_tears_down` (`:863`) | response version `0x01` → read error mentioning "version"/"mismatch" | ✅ |
| 8 | `vless_conn_server_eof_after_header` (`:898`) | server drops after the request → read error with a diagnostic (not a hang) | ✅ |

UDP (out of scope — drop, but listed for completeness): `vless_packet_conn_write_proceeds_while_read_parked` (`:942`), `vless_packet_conn_handles_lazy_response_header` (`:1009`), `vless_packet_conn_cmd_byte_is_0x02` (`:1049`), `udp_read_survives_cancellation_mid_response` (`:1119`), `udp_read_survives_cancellation_mid_payload` (`:1165`), `udp_response_version_mismatch_errors` (`:1212`), `udp_response_addon_is_discarded` (`:1240`), `udp_truncated_response_errors` (`:1266`), `udp_cancelled_write_poisons_conn` (`:1293`). Mux-only: `vless_mux_request_omits_port_and_address` (`:1086`).

Reusable test scaffolding: `ChunkedStream { inner: tokio::io::DuplexStream, max_write: usize }` (`:597-630`), `TEST_UUID` (`:633-636`), `spawn_mock(header_len, server_side) -> oneshot::Receiver<Vec<u8>>` (`:645-671`). All three port with only the spawn mechanism replaced.

### 6.5 Tests that are *not* worth porting

`crates/meow-proxy/tests/vless_integration.rs` and `crates/meow-transport/tests/*` are integration harnesses that need a real tokio runtime and (for TLS) BoringSSL/rustls loopback servers. Out of scope.

### 6.6 Recommended minimal port test set

1. `reality_client_hello_session_id_decrypts_to_auth_payload` (`reality_tls.rs:1734`) — **the interop test**.
2. `verify_reality_certificate_accepts_matching_hmac` + `..._rejects_wrong_hmac` (`:1551`, `:1560`) — **the anti-MITM test**.
3. `record_key_seal_open_round_trips_and_sequences` + `..._rejects_tampered_ciphertext` (`:1454`, `:1476`) — record layer.
4. `reality_handshake_rejects_unbounded_encrypted_extensions_flood` (`:2114`) — real handshake state machine end-to-end.
5. `header_encode_addon_vision_exact_bytes` (`header.rs:342`) and `padding_frame_with_uuid_matches_mihomo_layout` (`vision.rs:596`) — Vision framing pins.
6. All 6 `ServerFlightGuard` tests (`:1920-2040`) — cheap, pure, cover the pre-auth DoS bounds.
7. `poll_write_reports_new_chunk_len_after_pending_drain` (`:1856`) — AsyncWrite contract.

---

## 7. Licensing

### 7.1 Repository root

* **There is exactly one root license file: `LICENSE`.** The recursive tree contains only `LICENSE`, `crates/meow-anytls/LICENSE` (the vendored anytls fork) and `crates/meow-lwip/COPYING` (the vendored lwIP fork). There is **no `NOTICE`, no `COPYING` at root, no `AUTHORS`**.
* **Declaration in `Cargo.toml`** (workspace root, `[workspace.package]`): `license = "MIT"` — inherited by every crate via `license.workspace = true` (`crates/meow-transport/Cargo.toml:8`, `crates/meow-proxy/Cargo.toml:7`, `crates/meow-common/Cargo.toml:7`).
* **Declaration in `README.md:471-473`:**
  ```markdown
  ## License

  MIT — Copyright (c) 2026 Max Lv. See [LICENSE](LICENSE).
  ```

* **Exact LICENSE text** — MIT, 1057 bytes, 6 newlines, sha256 `b7a39018faacfd98597da373045fbacf2c3f134fd755e553894a6a9adad38db5`. **Note: it contains U+201C/U+201D curly quotation marks** (`“Software”`), i.e. it is not ASCII — reproduce byte-exactly:

```
Copyright (c) 2026 Max Lv

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

**Copyright line: `Copyright (c) 2026 Max Lv`.**
No `SPDX-License-Identifier` anywhere.

### 7.2 Per-file license headers in the port set

**None.** A case-insensitive scan of every file in the port set for `copyright`, `SPDX`, `Licensed under`, `license` returned **zero** matches (`crates/meow-transport/{reality_tls.rs,tls.rs,lib.rs,error.rs}`, `crates/meow-proxy/src/vless/{mod.rs,header.rs,vision.rs,conn.rs}`, `crates/meow-common/src/{lib.rs,conn.rs,metadata.rs,error.rs,adapter.rs,adapter_type.rs,network.rs,atomic.rs,dial.rs}`). All licensing is repository-level: `LICENSE` + the `license = "MIT"` manifest field.

### 7.3 Compliance action for the port

MIT requires the copyright notice and permission notice to be retained in "all copies or substantial portions of the Software". Because a port copies ~2,509 lines of production code verbatim (`reality_tls.rs:1-1412` = 1412 lines + `vision.rs:1-589` = 589 + `header.rs:1-181` = 181 + `conn.rs:1-327` = 327) plus a further ~1,150 lines of in-file tests, the port must:

1. Ship a `LICENSE` (or `LICENSE-MIT`) at the crate/workspace root containing the **byte-exact** text above (preserve the curly quotes and the `2026 Max Lv` line).
2. Add a per-file header naming the origin + copyright, e.g.:
   ```rust
   // Ported from meow-rs <https://github.com/meow-rs/meow-rs> @ a2be4de1c315daa22e53ad1118538936241d592f
   // crates/meow-transport/src/reality_tls.rs — MIT, Copyright (c) 2026 Max Lv. See LICENSE.
   ```
   (meow-rs itself has no per-file headers, so this is an addition, not a preservation — it is the safest way to satisfy "retain the notice in substantial portions".)
3. Record the upstream revision + file hashes (§0 table) so the divergence point is auditable.
4. `LICENSE` text is MIT with curly quotes — if you retype it, you change the bytes. Copy the file.

---

## 8. Files that are NOT needed, and other traps

### 8.1 Explicit "not needed" list

| file | verdict |
|---|---|
| `docs/vision.md` | ❌ **NOT RELEVANT.** Despite the name, it is the meow-rs *product vision / roadmap* (goals, non-goals, "Current state (2026-04-11 snapshot)", principles). It contains **nothing** about the XTLS-Vision protocol. It mentions "Vision" only as a project title and "Reality, ShadowTLS, SMUX" in an out-of-scope list (`:54`, `:61`, `:539` in the sibling `transport-layer.md`). Zero porting value. |
| `docs/specs/proxy-vless.md` | ⚠️ **Useful for the VLESS header wire format** (§ around `:187`: `"xtls-rprx-vision"` → addon_length 18, `0x0A 0x10` + 16 bytes). **But its `## XTLS-Vision` section (`:230-298`) is STALE/WRONG** — see §8.4. |
| `crates/meow-transport/src/tls/boring_backend.rs` | ❌ BoringSSL C++ backend. Not in the port set; never read. |
| `crates/meow-transport/src/{ws,grpc,h2,h2_common,httpupgrade,xhttp,simple_obfs/*}.rs` | ❌ not in scope; pull tokio-tungstenite/h2/http/httparse/base64. |
| `crates/meow-proxy/src/vless/encryption/**` | ❌ `mlkem768x25519plus`; pulls `blake3`/`ml-kem`/`ctr`/`aes`/`chacha20poly1305`. Excluded by `#[cfg(feature = "vless-encryption")]` (`vless/mod.rs:15-16`). |
| `crates/meow-proxy/src/vless_adapter.rs` | ❌ not in the listed port set. Pulls `ProxyAdapter`, `ProxyHealth`, `AdapterType`, `MuxClient`, `StreamConn`, `TcpDialer`, `parking_lot`, `smol_str`. Replace with a ~40-line `reality_vless_connect()`. See §4.3 for what it does. |
| `crates/meow-proxy/src/transport_chain.rs` | ⚠️ only 59 lines and dependency-free (`meow_common`, `meow_transport`); **optional convenience** — the port can inline a 6-line loop instead. |
| `crates/meow-proxy/src/lib.rs` | ⚠️ only `:82-130` (`PoisonOnIncomplete`, `check_not_desynced`) and `:146-148` (`transport_to_proxy_err`) are port-set-adjacent, and both are UDP/adapter concerns. **Not needed** for TCP-only. |
| `crates/meow-common/src/adapter.rs` | ❌ not needed (`ProxyAdapter`, `Proxy`, `ProxySelection`, `ProxyHealth`, `DelayHistory`, `ProxyState`). Pulls `parking_lot`, `serde`, `std::time::SystemTime`, `time::OffsetDateTime`. |
| `crates/meow-common/src/{atomic,auth,dial,health_check,home_dir,outbound_iface,process_lookup,rule,sniffer/*,socket_protect,tunnel_mode}.rs` | ❌ not reachable. `dial.rs` imports `tokio::time::Instant` (would be a category-(b) hit if it came along); `socket_protect.rs`/`process_lookup.rs`/`outbound_iface.rs` are OS-specific (`libc`, `socket2`, `libproc`, `windows-sys`). |
| `crates/meow-common/src/conn.rs:18-29` (`ProxyPacketConn`, `UdpPacket`) | ❌ UDP-only. |
| `crates/meow-proxy/src/{mux/*, tasked_duplex.rs, stream_conn.rs, dialer.rs, direct.rs, group/*, ...}` | ❌ not in scope. |
| `crates/meow-*/tests/*` | ❌ all need a tokio runtime and, for TLS, BoringSSL/rustls loopback servers. |

### 8.2 `tls.rs` cannot be taken as a file

`tls.rs:50` unconditionally declares `mod boring_backend;` and `tls.rs:52` imports from it, so **the file as a whole does not compile without BoringSSL**. Take lines **56-157** (the four config types + `impl TlsConfig::new`) into a new file and drop `async_trait`, `tracing::warn`, `TlsBackend`, `TlsLayer`, and the `Transport for TlsLayer` impl.

### 8.3 `meow-common/src/conn.rs:13` is a hard wasm compile error

```rust
impl ProxyConn for tokio::net::TcpStream {}   // conn.rs:13
```
`tokio::net` is gated behind the `net` feature, which triggers `compile_error!("Only features sync,macros,io-util,rt,time are supported on wasm.")` at `tokio-1.53.1/src/lib.rs:479`. Delete the line (the port's socket wrapper implements `ProxyConn` directly).

### 8.4 `docs/specs/proxy-vless.md` §XTLS-Vision describes a DIFFERENT, OBSOLETE padding layout

The doc (`:272-289`) says the Vision padding header is a **5-byte** record:
```
0x17 0x03 0x03 len_be(2)   then  padding_payload = 0x00 + random(N)
```
**The implemented code does not do this.** `vision.rs:14-15` and `:294-308` define the real layout, which is the mihomo/xray one:
```
PADDING_HEADER_LEN = UUID_LEN + 1 + 2 + 2 = 21
frame = [user_uuid: 16]                       (omitted on continuation frames → 5 bytes)
      ‖ command: u8                            (0x00 CONTINUE | 0x01 END | 0x02 DIRECT)
      ‖ content_len:  u16 BE
      ‖ padding_len:  u16 BE
      ‖ content
      ‖ zero padding
padding_len = if content.len() < 900 {
                  if padding_tls { rng()%500 + 900 - content.len() }   // note: usize arithmetic, see below
                  else           { rng()%256 }
              } else { 0 }
```
The doc's "Vision mode algorithm" (`:245-269`) — read 5 bytes, second `read_exact(body_length)`, decide splice before writing — is also **not** what the code does: `vision.rs` never peeks; it scans each write for a ClientHello with a 6-byte window (`contains_tls_client_hello`, `:202-205`), sets `write_seen_tls`, and only *then* emits `COMMAND_PADDING_END`/`DIRECT` on the first TLS **application-data** record (`:138-148`). The read side decides DIRECT from a `ServerHelloFilter` over the first ≤8 packets (`:207-259`, `TLS_FILTER_PACKETS = 8`).

**→ Port the code, not the doc.** The three `vision.rs` unit tests (§6.3) are the authoritative framing spec.

Two further notes on `build_padding_frame` (`vision.rs:283-292`): the `padding_tls` arm computes `(rng.next_u32() as usize % 500) + 900 - content.len()`. Since this arm is only entered when `content.len() < 900`, the result is in `[900 - len, 1399 - len]`, matching `padding_frame_with_uuid_matches_mihomo_layout` (`:616-617`). It is `usize` arithmetic with no `checked_*`; the `content.len() < 900` guard is what makes it safe — do not "simplify" it.

### 8.5 Other traps

* **`support_x25519_mlkem768` is dead** in the port set (never read outside test constructors). If meow later adds ML-KEM-768 key shares, `key_share_ext` (`reality_tls.rs:700-710`) would need a hybrid entry — the port does not, and should hardcode the X25519-only shape that the tests pin.
* **`SystemTime::now()` at `reality_tls.rs:622`** feeds the REALITY `session_id` timestamp (`reality_plain[4..8]`). If `SystemTime::now()` misbehaves under the chosen runner, the server's ±clock-skew window will reject the ClientHello. Verified importable; validate at runtime early.
* **`client_hello[39..71]`** (`reality_tls.rs:185`, `:654`, `:2134`) is a hardcoded session_id *offset* into the ClientHello. It is only valid because `build_reality_client_hello` (`:575-580`) emits exactly `legacy_version(2) ‖ random(32) ‖ session_id_len(1) ‖ session_id(32)` = 67 bytes, so the session_id starts at `4 + 2 + 32 + 1 = 39`. Any change to the ClientHello layout silently breaks REALITY auth. Keep `reality_client_hello_writes_32_byte_session_id` (`:1417`) as a guard.
* **`RecordKey::open` unbuffers the inner type** by scanning backwards for the last non-zero byte (`:1244-1251`) and then `truncate(pos)` — i.e. it strips *all* trailing zeros from the plaintext, not just the type byte. This is TLS-1.3-conformant for the record framing but is worth knowing if you ever feed it a payload that legitimately ends in `0x00`.
* **`read_record` caps a record at 18 KiB** (`:810`, and the streaming reader at `:393`) and **`wrap_plain_record` rejects payloads > `u16::MAX`** (`:719`). `ServerFlightGuard` assumes ≤ 3 flight messages; `MAX_PRE_AUTH_TRANSCRIPT_LEN = 64 KiB` is the binding limit (documented at `:55-74`).
* **`tokio::io::ReadHalf`/`WriteHalf`** are used only by `VlessPacketConn`. The TCP path never splits the stream, so the port needs no split primitive at all.
* **`async-trait` + `Box<dyn Stream>` + `Any`** interact: `Stream: Any` makes `Box<dyn Stream>`'s vtable carry `Any`, which is why `enable_raw_read_passthrough` can downcast. If you replace `Stream` with a simpler trait, keep the `as_any_mut` hook — Vision's DIRECT splice depends on it (`vision.rs:187, :191`).

---

## 9. Suggested port order

1. **`xt-wasm-tls` skeleton**: copy shims §3.1-3.6, then `reality_tls.rs` verbatim. Replace `reality_tls.rs:130` (`tokio::time::timeout`) with a deadline-checked future or drop the timeout and rely on the socket's `SO_RCVTIMEO`. Make `RealityTlsLayer::new`/`RealityTlsStream` `pub`. Compile with `tokio = { version = "1", default-features = false, features = ["io-util"] }` — **do not enable `net`**.
2. **Port the 16 runtime-free `reality_tls.rs` tests first** (§6.1 #1-7, #9-11, #13-18). They are the regression net and they prove the port preserved the wire semantics. Then add #19 with an in-memory duplex.
3. **Build the socket bridge** (`xt-wasm-runtime`): a `Stream` impl over `std::net::TcpStream` with `set_nonblocking(true)` + a poll reactor returning `Poll::Pending`/wakers (or `wasi:io/poll`), plus an executor entry point. This is the only genuinely new subsystem. Verify full duplex with a loopback echo before touching VLESS.
4. **`xt-wasm-vless`**: copy `header.rs` verbatim (swap `SmolStr`→`String`), copy `vision.rs` verbatim, copy `conn.rs:1-327` only. Port the 10 runtime-free `header.rs` tests + all 6 `vision.rs` tests; then the 8 TCP `conn.rs` tests with `futures::executor::block_on` + `join!`.
5. **Wire it up**: `reality_handshake` → `VlessConn::new_deferred` → `VisionConn::new`. Validate against a local Xray REALITY server per `PLAN.md` §6, and byte-compare the ClientHello against upstream Xray.
6. **Never** add `boring`, `tokio-boring`, `boring-sys`, `mio`, `tokio`'s `net`/`fs`/`process`/`signal`/`rt-multi-thread` features, `parking_lot`, `socket2`, `libc`-for-anything-but-nonblocking-poll, or any `tokio::time` use outside tests.

### Reproduction of the wasip2 evidence in this document

```bash
# scratch probes live in .scratch/portmap/{tokio-probe,core-probe,depcount,depcount2}
cd /Users/xbtg-/deepseek-harness/.scratch/portmap/core-probe
env PATH="/Users/xbtg-/.cargo/bin:$PATH" \
    CARGO_HOME=/Users/xbtg-/deepseek-harness/.cargo \
    CARGO_TARGET_DIR=/Users/xbtg-/deepseek-harness/.cargo-target/probe \
    cargo check --target wasm32-wasip2 --ignore-rust-version
# => Finished `dev` profile ... EXIT 0
```
