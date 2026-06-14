//! The TLS 1.2 pseudo-random function and key schedule (RFC 5246 §5, ristgo
//! `prf.go`). All DTLS suites here use `P_SHA256`, so the PRF is fixed to
//! HMAC-SHA256.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The master-secret derivation label (RFC 5246 §8.1).
pub const LABEL_MASTER_SECRET: &str = "master secret";
/// The extended-master-secret derivation label (RFC 7627 §4).
pub const LABEL_EXTENDED_MASTER_SECRET: &str = "extended master secret";
/// The key-block expansion label (RFC 5246 §6.3).
pub const LABEL_KEY_EXPANSION: &str = "key expansion";
/// The client Finished `verify_data` label (RFC 5246 §7.4.9).
pub const LABEL_CLIENT_FINISHED: &str = "client finished";
/// The server Finished `verify_data` label.
pub const LABEL_SERVER_FINISHED: &str = "server finished";

/// HMAC-SHA256 of the concatenated `parts` under `key`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// `P_SHA256(secret, seed)` truncated to `length` bytes (RFC 5246 §5):
/// `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`, output =
/// `HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || …`.
fn p_hash(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let mut a = hmac_sha256(secret, &[seed]); // A(1)
    while out.len() < length {
        let block = hmac_sha256(secret, &[&a, seed]);
        let take = (length - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        a = hmac_sha256(secret, &[&a]); // A(i+1)
    }
    out
}

/// The TLS 1.2 PRF: `P_SHA256(secret, label || seed)`, `length` bytes.
#[must_use]
pub fn prf(secret: &[u8], label: &str, seed: &[u8], length: usize) -> Vec<u8> {
    let mut labeled = Vec::with_capacity(label.len() + seed.len());
    labeled.extend_from_slice(label.as_bytes());
    labeled.extend_from_slice(seed);
    p_hash(secret, &labeled, length)
}

/// Derives the 48-byte master secret from the premaster and the two randoms
/// (RFC 5246 §8.1): `PRF(premaster, "master secret", client_random ||
/// server_random, 48)`.
#[must_use]
pub fn master_secret(
    pre_master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    fixed48(&prf(pre_master, LABEL_MASTER_SECRET, &seed, 48))
}

/// Derives the 48-byte extended master secret (RFC 7627 §4):
/// `PRF(premaster, "extended master secret", session_hash, 48)`, where
/// `session_hash` is the handshake transcript hash through ClientKeyExchange.
#[must_use]
pub fn extended_master_secret(pre_master: &[u8], session_hash: &[u8]) -> [u8; 48] {
    fixed48(&prf(
        pre_master,
        LABEL_EXTENDED_MASTER_SECRET,
        session_hash,
        48,
    ))
}

/// Computes a 12-byte Finished `verify_data` (RFC 5246 §7.4.9):
/// `PRF(master, label, SHA-256(transcript), 12)`.
#[must_use]
pub fn finished_verify_data(
    master: &[u8; 48],
    label: &str,
    transcript_hash: &[u8; 32],
) -> [u8; 12] {
    let v = prf(master, label, transcript_hash, 12);
    let mut d = [0u8; 12];
    d.copy_from_slice(&v);
    d
}

/// Truncates a PRF output (always ≥ 48 bytes here) into a fixed master secret.
fn fixed48(v: &[u8]) -> [u8; 48] {
    let mut m = [0u8; 48];
    m.copy_from_slice(&v[..48]);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical TLS 1.2 `P_SHA256` PRF known-answer test (the IETF TLS WG
    /// vector reproduced across implementations): secret/seed/label → 100 bytes.
    #[test]
    fn prf_sha256_known_answer() {
        let secret = [
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
            0xdb, 0x35,
        ];
        let seed = [
            0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5,
            0x19, 0x8c,
        ];
        let want = [
            0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c,
            0xd4, 0x53, 0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4,
            0xe6, 0x1e, 0xdb, 0x5a, 0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4,
            0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf, 0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
            0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab, 0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d,
            0xef, 0x9b, 0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba, 0xa4, 0x80, 0x82, 0xd1,
            0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01, 0x87, 0x34,
            0x7b, 0x66,
        ];
        assert_eq!(prf(&secret, "test label", &seed, 100), want);
    }

    #[test]
    fn master_secret_is_48_bytes_and_deterministic() {
        let pm = [0x11u8; 32];
        let cr = [0x22u8; 32];
        let sr = [0x33u8; 32];
        let a = master_secret(&pm, &cr, &sr);
        let b = master_secret(&pm, &cr, &sr);
        assert_eq!(a, b);
        // Swapping the randoms changes the secret (seed order matters).
        assert_ne!(master_secret(&pm, &sr, &cr), a);
    }

    #[test]
    fn finished_data_is_12_bytes_and_label_sensitive() {
        let master = [0x44u8; 48];
        let th = [0x55u8; 32];
        let client = finished_verify_data(&master, LABEL_CLIENT_FINISHED, &th);
        let server = finished_verify_data(&master, LABEL_SERVER_FINISHED, &th);
        assert_ne!(
            client, server,
            "the label must distinguish the two Finisheds"
        );
    }
}
