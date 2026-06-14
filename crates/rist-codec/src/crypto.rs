//! PSK key derivation and ciphers for the Main and Advanced profiles.
//!
//! The pre-shared-key key schedule is PBKDF2-HMAC-SHA256 over the passphrase,
//! salted by the 4-byte GRE/Advanced nonce, with libRIST's 1024 iterations. The
//! derived key feeds AES-CTR (and, spec-only, the AEAD modes) — those ciphers land
//! in Phase 3/4. This module currently ships the key-derivation primitive, which
//! anchors the whole crypto stack and validates the RustCrypto dependency chain.

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// libRIST's PBKDF2 iteration count for PSK key derivation.
pub const PBKDF2_ITERATIONS: u32 = 1024;

/// The AES key size, restricted to the two widths RIST signals via the GRE H bit.
///
/// libRIST also supports 192-bit keys; ristrust matches ristgo in offering only
/// 128 and 256 (documented divergence — see the WP3 binding in `ORCHESTRATION.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeyBits {
    /// 128-bit key (16 bytes).
    Aes128,
    /// 256-bit key (32 bytes).
    Aes256,
}

impl AesKeyBits {
    /// The key length in bytes (16 or 32).
    #[must_use]
    pub fn bytes(self) -> usize {
        match self {
            AesKeyBits::Aes128 => 16,
            AesKeyBits::Aes256 => 32,
        }
    }
}

/// Derives a `key_len`-byte key from `passphrase` and `salt` via
/// PBKDF2-HMAC-SHA256 with [`PBKDF2_ITERATIONS`] iterations.
///
/// `passphrase` must already be in libRIST's wire form: truncated at the first NUL
/// byte and capped at 127 bytes. That preprocessing (and the 4-byte-nonce salt) is
/// applied by the Main/Advanced session layer when it lands (WP3); this function
/// is the pure primitive.
#[must_use]
pub fn derive_key(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_hmac_sha256_known_answer() {
        // Standard PBKDF2-HMAC-SHA256 vector: P="password", S="salt", c=1, dkLen=32.
        let mut out = [0u8; 32];
        pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        let expected = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(
            out, expected,
            "PBKDF2-HMAC-SHA256 chain produced wrong output"
        );
    }

    #[test]
    fn derive_key_is_deterministic_and_salt_sensitive() {
        let a = derive_key(b"mainprofile", b"\x01\x02\x03\x04", 32);
        let b = derive_key(b"mainprofile", b"\x01\x02\x03\x04", 32);
        let c = derive_key(b"mainprofile", b"\x09\x09\x09\x09", 32);
        assert_eq!(a, b, "same inputs must derive the same key");
        assert_ne!(a, c, "a different salt must derive a different key");
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn aes_key_bits_lengths() {
        assert_eq!(AesKeyBits::Aes128.bytes(), 16);
        assert_eq!(AesKeyBits::Aes256.bytes(), 32);
        assert_eq!(
            derive_key(b"k", b"salt", AesKeyBits::Aes128.bytes()).len(),
            16
        );
    }
}
