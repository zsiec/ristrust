//! AES-128-GCM AEAD record protection and the key-block schedule (RFC 6347
//! §4.1.2.1 + RFC 5246 §6.3, ristgo `cipher.go`).
//!
//! The 12-byte GCM nonce is `fixed_iv(4) || seqAndEpoch(8)`; the 8-byte
//! `seqAndEpoch` is also written on the wire as the explicit nonce. The additional
//! authenticated data is `seqAndEpoch(8) || type(1) || version(2) ||
//! plaintext_len(2)`.

// The `expect`s here are infallible by construction: the AES-128 key is always a
// fixed 16 bytes, and AES-GCM `encrypt` only errors on multi-gigabyte plaintext
// (a DTLS record is ≤ 2^14 bytes). There is no reachable panic to document.
#![allow(clippy::missing_panics_doc)]

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};

use super::DtlsError;
use super::prf::{LABEL_KEY_EXPANSION, prf};
use super::record::{ContentType, seq_and_epoch};

/// AES-128 key length.
pub const AES_GCM_KEY_LEN: usize = 16;
/// The per-direction fixed IV (salt) length.
pub const GCM_FIXED_IV_LEN: usize = 4;
/// The explicit (on-the-wire) nonce length.
pub const GCM_EXPLICIT_NONCE_LEN: usize = 8;
/// The GCM authentication tag length.
pub const GCM_TAG_LEN: usize = 16;
/// The per-record AEAD overhead: explicit nonce + tag.
pub const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + GCM_TAG_LEN;
/// The key-block length: two 16-byte keys plus two 4-byte fixed IVs.
pub const KEY_BLOCK_LEN: usize = 2 * AES_GCM_KEY_LEN + 2 * GCM_FIXED_IV_LEN;

/// Builds the 13-byte AEAD additional authenticated data for one record.
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

/// One direction's AEAD key material: the AES-128 key and the 4-byte fixed IV.
#[derive(Debug, Clone)]
pub struct HalfConn {
    key: [u8; AES_GCM_KEY_LEN],
    salt: [u8; GCM_FIXED_IV_LEN],
}

impl HalfConn {
    /// Builds a half-connection from a 16-byte key and 4-byte salt.
    #[must_use]
    pub fn new(key: [u8; AES_GCM_KEY_LEN], salt: [u8; GCM_FIXED_IV_LEN]) -> HalfConn {
        HalfConn { key, salt }
    }

    /// Encrypts `plaintext` into a record fragment: `explicit_nonce(8) ||
    /// ciphertext || tag`.
    #[must_use]
    pub fn seal(
        &self,
        epoch: u16,
        seq: u64,
        typ: ContentType,
        version: [u8; 2],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let se = seq_and_epoch(epoch, seq);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&se.to_be_bytes());
        let aad = aead_aad(epoch, seq, typ, version, plaintext.len());
        let cipher = Aes128Gcm::new_from_slice(&self.key).expect("16-byte AES-128 key");
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("AES-GCM seal never fails for record-sized plaintext");
        let mut out = Vec::with_capacity(GCM_EXPLICIT_NONCE_LEN + ct.len());
        out.extend_from_slice(&se.to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypts one record `fragment` (`explicit_nonce(8) || ciphertext || tag`)
    /// back to plaintext, authenticating against `(epoch, seq, typ, version)`.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] if the fragment is shorter than the AEAD overhead,
    /// or [`DtlsError::DecryptFailed`] on a bad tag (wrong key or tampered record).
    pub fn open(
        &self,
        epoch: u16,
        seq: u64,
        typ: ContentType,
        version: [u8; 2],
        fragment: &[u8],
    ) -> Result<Vec<u8>, DtlsError> {
        if fragment.len() < GCM_OVERHEAD {
            return Err(DtlsError::Malformed("gcm record"));
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&fragment[..GCM_EXPLICIT_NONCE_LEN]);
        let ct = &fragment[GCM_EXPLICIT_NONCE_LEN..];
        let plaintext_len = ct.len() - GCM_TAG_LEN;
        let aad = aead_aad(epoch, seq, typ, version, plaintext_len);
        let cipher = Aes128Gcm::new_from_slice(&self.key).expect("16-byte AES-128 key");
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| DtlsError::DecryptFailed)
    }
}

/// The directional AEAD keys: the client-write half (client seals, server opens)
/// and the server-write half (server seals, client opens).
#[derive(Debug, Clone)]
pub struct ConnKeys {
    /// The half the client encrypts with and the server decrypts with.
    pub client_write: HalfConn,
    /// The half the server encrypts with and the client decrypts with.
    pub server_write: HalfConn,
}

/// Expands the master secret into the directional AEAD keys (RFC 5246 §6.3): the
/// key-block seed is `server_random || client_random` (the reverse of the master
/// secret's seed), sliced into client/server write keys then client/server IVs.
#[must_use]
pub fn derive_keys(
    master: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ConnKeys {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    let kb = prf(master, LABEL_KEY_EXPANSION, &seed, KEY_BLOCK_LEN);

    let mut cwk = [0u8; 16];
    cwk.copy_from_slice(&kb[0..16]);
    let mut swk = [0u8; 16];
    swk.copy_from_slice(&kb[16..32]);
    let mut cwi = [0u8; 4];
    cwi.copy_from_slice(&kb[32..36]);
    let mut swi = [0u8; 4];
    swi.copy_from_slice(&kb[36..40]);

    ConnKeys {
        client_write: HalfConn::new(cwk, cwi),
        server_write: HalfConn::new(swk, swi),
    }
}

#[cfg(test)]
mod tests {
    use super::super::record::VERSION_DTLS_1_2;
    use super::*;

    fn half() -> HalfConn {
        HalfConn::new([0x42; 16], [1, 2, 3, 4])
    }

    #[test]
    fn seal_open_round_trip() {
        let h = half();
        let pt = b"the quick brown fox";
        let frag = h.seal(1, 7, ContentType::ApplicationData, VERSION_DTLS_1_2, pt);
        // explicit nonce (8) + ciphertext (len) + tag (16)
        assert_eq!(frag.len(), GCM_EXPLICIT_NONCE_LEN + pt.len() + GCM_TAG_LEN);
        let back = h
            .open(1, 7, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag)
            .unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let h = half();
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
        let h = half();
        let frag = h.seal(1, 1, ContentType::Handshake, VERSION_DTLS_1_2, b"data");
        // Same fragment, but authenticated as application_data → AAD mismatch.
        assert_eq!(
            h.open(1, 1, ContentType::ApplicationData, VERSION_DTLS_1_2, &frag),
            Err(DtlsError::DecryptFailed)
        );
        // Wrong sequence number also fails (nonce + AAD mismatch).
        assert_eq!(
            h.open(1, 2, ContentType::Handshake, VERSION_DTLS_1_2, &frag),
            Err(DtlsError::DecryptFailed)
        );
    }

    #[test]
    fn derive_keys_splits_block_into_distinct_halves() {
        let keys = derive_keys(&[0x11; 48], &[0x22; 32], &[0x33; 32]);
        // A record sealed by the client half opens with the same half (a round
        // trip), and the two directions use independent key material.
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
}
