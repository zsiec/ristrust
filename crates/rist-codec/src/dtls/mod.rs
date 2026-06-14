//! Pure-Rust DTLS 1.2 (VSF TR-06 optional security layer), feature-gated behind
//! `--features dtls`.
//!
//! DTLS is **deferred and optional**: libRIST has no DTLS (its Main-profile
//! security is EAP-SRP + PSK-AES-CTR, in [`crate::eap`]/[`crate::crypto`]), so this
//! is not an interop gate against libRIST — the bar is OpenSSL
//! `s_server`/`s_client -dtls1_2`. It is a faithful port of ristgo's
//! `internal/dtls`, supporting exactly two cipher suites, both AES-128-GCM with the
//! SHA-256 PRF:
//!
//! - `TLS_PSK_WITH_AES_128_GCM_SHA256` (`0x00A8`, RFC 5487) — pre-shared key.
//! - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`0xC02B`, RFC 5289) — ephemeral
//!   P-256 ECDH with an ECDSA P-256 certificate.
//!
//! The implementation is layered: the deterministic record/PRF/cipher/replay
//! primitives carry no I/O; the handshake state machines and the connection type
//! (which wrap a caller-supplied datagram transport) build on them.
//!
//! # Module map
//! - [`suites`] — cipher-suite and extension constants.
//! - [`prf`] — the TLS 1.2 PRF (`P_SHA256`) and key schedule.
//! - [`record`] — the 13-byte DTLS record header (epoch + 48-bit sequence).
//! - [`cipher`] — AES-128-GCM AEAD record protection.
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
