//! Pure-Rust DTLS 1.2 (VSF TR-06 optional security layer), feature-gated behind
//! `--features dtls`.
//!
//! DTLS is **deferred and optional**: libRIST has no DTLS (its Main-profile
//! security is EAP-SRP + PSK-AES-CTR, in [`crate::eap`]/[`crate::crypto`]), so this
//! is not an interop gate against libRIST — the bar is OpenSSL
//! `s_server`/`s_client -dtls1_2`. It is a faithful port of ristgo's
//! `internal/dtls`, supporting the full TR-06-2 §6.2 mandatory cipher-suite set
//! plus the PSK suite RIST uses:
//!
//! - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`0xC02B`, RFC 5289).
//! - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (`0xC02C`, RFC 5289).
//! - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (`0xC02F`, RFC 5289).
//! - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (`0xC030`, RFC 5289).
//! - `TLS_RSA_WITH_NULL_SHA256` (`0x003B`, RFC 5246) — integrity only, NO
//!   confidentiality; OFF by default (reachable only via `allow_null_cipher`).
//! - `TLS_PSK_WITH_AES_128_GCM_SHA256` (`0x00A8`, RFC 5487) — pre-shared key.
//!
//! The PRF / transcript hash is parametrized per suite (SHA-256 or SHA-384), AES-128
//! and AES-256 GCM are both wired, certificates may be ECDSA P-256 or RSA, and the
//! key exchange is ECDHE-P256, RSA key transport (with the Bleichenbacher
//! countermeasure), or PSK.
//!
//! The implementation is layered: the deterministic record/PRF/cipher/replay
//! primitives carry no I/O; the handshake state machines and the connection type
//! (which wrap a caller-supplied datagram transport) build on them.
//!
//! # Module map
//! - [`suites`] — cipher-suite, signature-scheme, and extension constants.
//! - [`suiteinfo`] — the per-suite descriptor table (kx / auth / hash / key sizes).
//! - [`prf`] — the TLS 1.2 PRF (`P_SHA256` / `P_SHA384`) and key schedule.
//! - [`record`] — the 13-byte DTLS record header (epoch + 48-bit sequence).
//! - [`cipher`] — AES-128/256-GCM AEAD and NULL-cipher-with-HMAC record protection.
//! - [`replay`] — the per-epoch anti-replay sliding window.

pub mod cert;
pub mod cipher;
pub mod conn;
pub mod handshake;
pub mod keyexchange;
pub mod messages;
pub mod prf;
pub mod record;
pub mod replay;
pub mod suiteinfo;
pub mod suites;
pub mod vec;

pub use conn::{Config, Conn, Transport};

use thiserror::Error;

/// An error from the DTLS layer.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DtlsError {
    /// A record, handshake message, or extension was shorter than required or
    /// otherwise malformed.
    #[error("rist: dtls: malformed {0}")]
    Malformed(&'static str),
    /// A record's protocol version was not DTLS 1.2 (or 1.0 where permitted).
    #[error("rist: dtls: unsupported protocol version")]
    BadVersion,
    /// AEAD decryption failed (bad tag, wrong key, or a tampered record).
    #[error("rist: dtls: record authentication failed")]
    DecryptFailed,
    /// A record was a replay (already-seen or too-old sequence number).
    #[error("rist: dtls: replayed record")]
    Replay,
    /// Peer certificate verification failed (bad chain, signature, or pin).
    #[error("rist: dtls: certificate verification failed")]
    BadCertificate,
}
