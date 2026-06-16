//! Record protection and the key-block schedule (RFC 6347 §4.1.2.1 + RFC 5246
//! §6.3, ristgo `cipher.go`). Two schemes are supported, selected by the negotiated
//! suite:
//!
//! - **AES-GCM** (RFC 5288) — the AEAD used by every GCM suite (AES-128 or
//!   AES-256). The 12-byte nonce is `fixed_iv(4) || seqAndEpoch(8)`; the 8-byte
//!   `seqAndEpoch` is also written on the wire as the explicit nonce. The additional
//!   authenticated data is `seqAndEpoch(8) || type(1) || version(2) ||
//!   plaintext_len(2)`.
//! - **NULL cipher with HMAC** (RFC 5246 §6.2.3.1) — for `TLS_RSA_WITH_NULL_SHA256`:
//!   the fragment is `plaintext || HMAC(mac_key, aad || plaintext)`. Integrity only,
//!   NO confidentiality.

// The `expect`s on AES key construction are infallible by construction: keys are
// always exactly 16 or 32 bytes, and AES-GCM `encrypt` only errors on multi-gigabyte
// plaintext (a DTLS record is ≤ 2^14 bytes). There is no reachable panic.
#![allow(clippy::missing_panics_doc)]

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use subtle::ConstantTimeEq;

use super::DtlsError;
use super::prf::{LABEL_KEY_EXPANSION, PrfHash, prf};
use super::record::{ContentType, seq_and_epoch};
use super::suiteinfo::SuiteInfo;

/// The per-direction fixed IV (salt) length.
pub const GCM_FIXED_IV_LEN: usize = 4;
/// The explicit (on-the-wire) nonce length.
pub const GCM_EXPLICIT_NONCE_LEN: usize = 8;
/// The GCM authentication tag length.
pub const GCM_TAG_LEN: usize = 16;
/// The per-record AEAD overhead: explicit nonce + tag.
pub const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + GCM_TAG_LEN;

/// Builds the 13-byte record additional-data block (RFC 6347 §4.1.2.1):
/// `seq_num(8) || type(1) || version(2) || length(2)`. It is the AEAD AAD for GCM
/// and the MAC-input prefix for the NULL suite.
fn aead_aad(
    epoch: u16,
    seq: u64,
    typ: ContentType,
    version: [u8; 2],
    plaintext_len: usize,
) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq_and_epoch(epoch, seq).to_be_bytes());
    aad[8] = typ.as_u8();
    aad[9] = version[0];
    aad[10] = version[1];
    let len = u16::try_from(plaintext_len).unwrap_or(u16::MAX);
    aad[11..].copy_from_slice(&len.to_be_bytes());
    aad
}

/// Encrypts `plaintext` under an AES-GCM `key` (16 or 32 bytes) with `nonce` and
/// `aad`, returning `ciphertext || tag`.
fn gcm_encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let nonce = Nonce::from_slice(nonce);
    if key.len() == 32 {
        Aes256Gcm::new_from_slice(key)
            .expect("32-byte AES-256 key")
            .encrypt(nonce, payload)
            .expect("AES-GCM seal never fails for record-sized plaintext")
    } else {
        Aes128Gcm::new_from_slice(key)
            .expect("16-byte AES-128 key")
            .encrypt(nonce, payload)
            .expect("AES-GCM seal never fails for record-sized plaintext")
    }
}

/// Decrypts an AES-GCM `ciphertext` (`ct || tag`) under `key` with `nonce`/`aad`.
fn gcm_decrypt(key: &[u8], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, DtlsError> {
    let payload = Payload { msg: ct, aad };
    let nonce = Nonce::from_slice(nonce);
    let r = if key.len() == 32 {
        Aes256Gcm::new_from_slice(key)
            .expect("32-byte AES-256 key")
            .decrypt(nonce, payload)
    } else {
        Aes128Gcm::new_from_slice(key)
            .expect("16-byte AES-128 key")
            .decrypt(nonce, payload)
    };
    r.map_err(|_| DtlsError::DecryptFailed)
}

/// One direction's record protection: AES-GCM (with the bulk key + 4-byte salt) or
/// the NULL cipher with an HMAC (with the MAC key + suite hash).
#[derive(Debug, Clone)]
pub enum HalfConn {
    /// AES-GCM AEAD (AES-128 with a 16-byte key, AES-256 with a 32-byte key).
    Gcm {
        /// The 16- or 32-byte AES key.
        key: Vec<u8>,
        /// The 4-byte fixed IV (salt), the implicit part of the GCM nonce.
        salt: [u8; GCM_FIXED_IV_LEN],
    },
    /// NULL cipher with an appended HMAC — integrity only (no encryption).
    NullMac {
        /// The HMAC key for this direction.
        mac_key: Vec<u8>,
        /// The HMAC hash (SHA-256 for `RSA_WITH_NULL_SHA256`).
        hash: PrfHash,
        /// The HMAC output length appended to each record.
        mac_len: usize,
    },
}

impl HalfConn {
    /// Builds an AES-GCM half from a 16- or 32-byte key and 4-byte salt.
    #[must_use]
    pub fn gcm(key: &[u8], salt: [u8; GCM_FIXED_IV_LEN]) -> HalfConn {
        HalfConn::Gcm {
            key: key.to_vec(),
            salt,
        }
    }

    /// Protects `plaintext` into a record fragment. For GCM the fragment is
    /// `explicit_nonce(8) || ciphertext || tag`; for the NULL suite it is
    /// `plaintext || HMAC`.
    #[must_use]
    pub fn seal(
        &self,
        epoch: u16,
        seq: u64,
        typ: ContentType,
        version: [u8; 2],
        plaintext: &[u8],
    ) -> Vec<u8> {
        match self {
            HalfConn::Gcm { key, salt } => {
                let se = seq_and_epoch(epoch, seq);
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&se.to_be_bytes());
                let aad = aead_aad(epoch, seq, typ, version, plaintext.len());
                let ct = gcm_encrypt(key, &nonce, plaintext, &aad);
                let mut out = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + ct.len());
                out.extend_from_slice(&se.to_be_bytes());
                out.extend_from_slice(&ct);
                out
            }
            HalfConn::NullMac { mac_key, hash, .. } => {
                let aad = aead_aad(epoch, seq, typ, version, plaintext.len());
                let mac = hash.hmac(mac_key, &[&aad, plaintext]);
                let mut out = Vec::with_capacity(plaintext.len() + mac.len());
                out.extend_from_slice(plaintext);
                out.extend_from_slice(&mac);
                out
            }
        }
    }

    /// Recovers the plaintext of one record `fragment`, authenticating against
    /// `(epoch, seq, typ, version)`.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] if the fragment is shorter than its overhead, or
    /// [`DtlsError::DecryptFailed`] on a bad tag / MAC (wrong key or tampered
    /// record). The failure is deliberately uniform (no short-vs-mismatch
    /// distinction) to avoid an oracle.
    pub fn open(
        &self,
        epoch: u16,
        seq: u64,
        typ: ContentType,
        version: [u8; 2],
        fragment: &[u8],
    ) -> Result<Vec<u8>, DtlsError> {
        match self {
            HalfConn::Gcm { key, salt } => {
                if fragment.len() < GCM_OVERHEAD {
                    return Err(DtlsError::Malformed("gcm record"));
                }
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&fragment[..GCM_EXPLICIT_NONCE_LEN]);
                let ct = &fragment[GCM_EXPLICIT_NONCE_LEN..];
                let plaintext_len = ct.len() - GCM_TAG_LEN;
                let aad = aead_aad(epoch, seq, typ, version, plaintext_len);
                gcm_decrypt(key, &nonce, ct, &aad)
            }
            HalfConn::NullMac {
                mac_key,
                hash,
                mac_len,
            } => {
                if fragment.len() < *mac_len {
                    return Err(DtlsError::Malformed("null-mac record"));
                }
                let split = fragment.len() - *mac_len;
                let body = &fragment[..split];
                let got = &fragment[split..];
                let aad = aead_aad(epoch, seq, typ, version, body.len());
                let want = hash.hmac(mac_key, &[&aad, body]);
                if got.ct_eq(&want).unwrap_u8() != 1 {
                    return Err(DtlsError::DecryptFailed);
                }
                Ok(body.to_vec())
            }
        }
    }
}

/// The directional record-protection keys: the client-write half (client seals,
/// server opens) and the server-write half (server seals, client opens).
#[derive(Debug, Clone)]
pub struct ConnKeys {
    /// The half the client encrypts/MACs with and the server opens with.
    pub client_write: HalfConn,
    /// The half the server encrypts/MACs with and the client opens with.
    pub server_write: HalfConn,
}

/// Expands the master secret into both directions' record-protection halves for the
/// negotiated `suite` (RFC 5246 §6.3). The key-block seed is `server_random ||
/// client_random` (the reverse of the master-secret seed). The block layout is
/// `client_MAC || server_MAC || client_key || server_key || client_IV || server_IV`,
/// where the MAC keys are empty for an AEAD suite and the enc keys + IVs are empty
/// for the NULL suite.
#[must_use]
pub fn derive_keys(
    suite: SuiteInfo,
    master: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ConnKeys {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);

    let mac_len = suite.mac_len;
    let enc_len = suite.key_len;
    let iv_len = if suite.aead { GCM_FIXED_IV_LEN } else { 0 };
    let block_len = 2 * mac_len + 2 * enc_len + 2 * iv_len;
    let kb = prf(suite.hash, master, LABEL_KEY_EXPANSION, &seed, block_len);

    let mut off = 0;
    let mut take = |n: usize| {
        let s = kb[off..off + n].to_vec();
        off += n;
        s
    };
    let client_mac = take(mac_len);
    let server_mac = take(mac_len);
    let client_key = take(enc_len);
    let server_key = take(enc_len);
    let client_iv = take(iv_len);
    let server_iv = take(iv_len);

    if suite.aead {
        let mut cwi = [0u8; GCM_FIXED_IV_LEN];
        cwi.copy_from_slice(&client_iv);
        let mut swi = [0u8; GCM_FIXED_IV_LEN];
        swi.copy_from_slice(&server_iv);
        ConnKeys {
            client_write: HalfConn::gcm(&client_key, cwi),
            server_write: HalfConn::gcm(&server_key, swi),
        }
    } else {
        ConnKeys {
            client_write: HalfConn::NullMac {
                mac_key: client_mac,
                hash: suite.hash,
                mac_len,
            },
            server_write: HalfConn::NullMac {
                mac_key: server_mac,
                hash: suite.hash,
                mac_len,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::record::VERSION_DTLS_1_2;
    use super::super::suiteinfo::lookup_suite;
    use super::super::suites::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_NULL_SHA256,
    };
    use super::*;

    fn suite(id: u16) -> SuiteInfo {
        lookup_suite(id).expect("known suite")
    }

    #[test]
    fn aes128_seal_open_round_trip() {
        let h = HalfConn::gcm(&[0x42; 16], [1, 2, 3, 4]);
        let pt = b"the quick brown fox";
        let frag = h.seal(1, 7, ContentType::ApplicationData, VERSION_DTLS_1_2, pt);
        assert_eq!(frag.len(), GCM_EXPLICIT_NONCE_LEN + pt.len() + GCM_TAG_LEN);
        let back = h
            .open(1, 7, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag)
            .unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn aes256_seal_open_round_trip() {
        let h = HalfConn::gcm(&[0x37; 32], [9, 8, 7, 6]);
        let pt = b"jackdaws love my big sphinx of quartz";
        let frag = h.seal(2, 3, ContentType::Handshake, VERSION_DTLS_1_2, pt);
        assert_eq!(frag.len(), GCM_EXPLICIT_NONCE_LEN + pt.len() + GCM_TAG_LEN);
        let back = h
            .open(2, 3, ContentType::Handshake, VERSION_DTLS_1_2, &frag)
            .unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn null_mac_authenticates_without_encrypting() {
        let h = HalfConn::NullMac {
            mac_key: vec![0x55; 32],
            hash: PrfHash::Sha256,
            mac_len: 32,
        };
        let pt = b"cleartext-but-authenticated";
        let frag = h.seal(1, 0, ContentType::ApplicationData, VERSION_DTLS_1_2, pt);
        // NULL cipher: the plaintext rides in the clear, followed by the 32-byte MAC.
        assert_eq!(frag.len(), pt.len() + 32);
        assert_eq!(&frag[..pt.len()], pt, "the NULL suite does not encrypt");
        let back = h
            .open(1, 0, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag)
            .unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn null_mac_rejects_tampered_body() {
        let h = HalfConn::NullMac {
            mac_key: vec![0x11; 32],
            hash: PrfHash::Sha256,
            mac_len: 32,
        };
        let mut frag = h.seal(1, 1, ContentType::Handshake, VERSION_DTLS_1_2, b"data");
        frag[0] ^= 0x01; // flip a plaintext bit → MAC no longer matches
        assert_eq!(
            h.open(1, 1, ContentType::Handshake, VERSION_DTLS_1_2, &frag),
            Err(DtlsError::DecryptFailed)
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let h = HalfConn::gcm(&[0x42; 16], [1, 2, 3, 4]);
        let mut frag = h.seal(1, 1, ContentType::Handshake, VERSION_DTLS_1_2, b"secret");
        let last = frag.len() - 1;
        frag[last] ^= 0x01; // flip a tag bit
        assert_eq!(
            h.open(1, 1, ContentType::Handshake, VERSION_DTLS_1_2, &frag),
            Err(DtlsError::DecryptFailed)
        );
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let h = HalfConn::gcm(&[0x42; 16], [1, 2, 3, 4]);
        let frag = h.seal(1, 1, ContentType::Handshake, VERSION_DTLS_1_2, b"data");
        assert_eq!(
            h.open(1, 1, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag),
            Err(DtlsError::DecryptFailed)
        );
        assert_eq!(
            h.open(1, 2, ContentType::Handshake, VERSION_DTLS_1_2, &frag),
            Err(DtlsError::DecryptFailed)
        );
    }

    #[test]
    fn derive_keys_aes128_splits_into_distinct_halves() {
        let keys = derive_keys(
            suite(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            &[0x11; 48],
            &[0x22; 32],
            &[0x33; 32],
        );
        let frag =
            keys.client_write
                .seal(1, 0, ContentType::ApplicationData, VERSION_DTLS_1_2, b"x");
        assert!(
            keys.client_write
                .open(1, 0, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag)
                .is_ok()
        );
        // The server-write half must NOT open a client-write record.
        assert!(
            keys.server_write
                .open(1, 0, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag)
                .is_err()
        );
    }

    #[test]
    fn derive_keys_aes256_round_trips_across_endpoints() {
        let s = suite(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        let a = derive_keys(s, &[0x44; 48], &[0x01; 32], &[0x02; 32]);
        let b = derive_keys(s, &[0x44; 48], &[0x01; 32], &[0x02; 32]);
        let frag =
            a.client_write
                .seal(1, 5, ContentType::ApplicationData, VERSION_DTLS_1_2, b"abc");
        // The AES-256 key must be 32 bytes (SHA-384 suite).
        if let HalfConn::Gcm { key, .. } = &a.client_write {
            assert_eq!(key.len(), 32);
        } else {
            panic!("AES-256 suite must derive a GCM half");
        }
        let back = b
            .client_write // a second endpoint with the same inputs opens the same direction
            .open(1, 5, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag);
        assert_eq!(back.unwrap(), b"abc");
    }

    #[test]
    fn derive_keys_null_suite_is_mac_only() {
        let keys = derive_keys(
            suite(TLS_RSA_WITH_NULL_SHA256),
            &[0x66; 48],
            &[0x07; 32],
            &[0x08; 32],
        );
        assert!(
            matches!(keys.client_write, HalfConn::NullMac { .. }),
            "the NULL suite must derive a MAC-only half"
        );
        let frag = keys.client_write.seal(
            1,
            0,
            ContentType::ApplicationData,
            VERSION_DTLS_1_2,
            b"plain",
        );
        assert_eq!(&frag[..5], b"plain", "NULL suite carries cleartext");
        assert!(
            keys.client_write
                .open(1, 0, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag)
                .is_ok()
        );
    }
}
