//! The RIST Main-profile pre-shared-key (PSK) payload encryption: PBKDF2-HMAC-
//! SHA256 key derivation salted by the 4-byte GRE nonce, followed by AES-CTR over
//! the GRE payload. Byte-exact with libRIST v0.2.18-rc1, ported from ristgo
//! `internal/crypto`.
//!
//! Sans-I/O and deterministic in the host's hands: this module never reads a
//! clock, opens a socket, or spawns a task. The only non-determinism is nonce
//! generation, which draws from the OS CSPRNG at construction and on key rotation;
//! everything else (key derivation, IV construction, the AES-CTR keystream) is a
//! pure function of its inputs and is unit-tested in isolation.
//!
//! Wire facts (confirmed against libRIST):
//!
//! - Key derivation is PBKDF2-HMAC-SHA256 over the passphrase, salted by the
//!   4-byte GRE nonce, with 1024 iterations and a derived length of `key_bits/8`.
//! - The 16-byte AES-CTR IV is the 32-bit GRE sequence number, big-endian, in
//!   bytes `[0:4]`, then twelve zero bytes. The per-packet seq sits high so the
//!   block counter (the low bytes) never collides with the next packet.
//! - Encrypt and decrypt are the identical AES-CTR XOR-stream operation.
//! - The 4-byte nonce is a random non-zero `u32`; bit 7 of `nonce[0]` marks the
//!   odd/even passphrase. A zero nonce is never emitted or accepted.
//! - The key rotates — fresh nonce, re-derived key — at the `key_rotation`
//!   threshold of encrypted packets (or never, when 0). A receiver re-derives
//!   whenever the inbound nonce differs from the one it last keyed on.

// Justification: the AES-CTR helper selects the cipher by key length (16/32 bytes
// from `derive_key`); those bounds hold by construction.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use aes::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// AES-CTR with a 128-bit big-endian counter — the full 16-byte IV is the
/// counter, incremented per block, matching libRIST's `BuildIV` layout.
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Errors returned by the PSK crypto layer. `Display` strings are prefixed
/// `"rist: crypto: "`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The passphrase was empty.
    #[error("rist: crypto: empty passphrase")]
    EmptyPassword,
    /// The nonce salt was not exactly [`NONCE_SIZE`] bytes.
    #[error("rist: crypto: nonce must be 4 bytes")]
    InvalidNonceLength,
    /// The inbound GRE nonce was zero — never from a legitimate sender.
    #[error("rist: crypto: zero nonce rejected")]
    ZeroNonce,
    /// The AES key-reuse limit was exhausted under one unchanging nonce.
    #[error("rist: crypto: AES key reuse limit exhausted")]
    KeyReuseExhausted,
    /// The OS CSPRNG was unavailable during nonce generation (fail closed).
    #[error("rist: crypto: CSPRNG unavailable")]
    Csprng,
}

/// libRIST's PBKDF2 iteration count for PSK key derivation
/// (`RIST_PBKDF2_HMAC_SHA256_ITERATIONS`).
pub const PBKDF2_ITERATIONS: u32 = 1024;

/// The length in bytes of the GRE nonce that salts key derivation.
pub const NONCE_SIZE: usize = 4;

/// One AES block: the AES-CTR IV length.
const IV_SIZE: usize = 16;

/// libRIST's effective PBKDF2 passphrase bound (`sizeof(password)-1`): the
/// passphrase is truncated at the first NUL and capped at 127 bytes.
const MAX_PASSWORD_LEN: usize = 127;

/// Bit 7 of `nonce[0]`: the odd/even passphrase marker.
const NONCE_B_BIT_MASK: u8 = 1 << 7;

/// The AES key size, restricted to the two widths RIST signals via the GRE H bit.
///
/// libRIST also supports 192-bit keys, but it can never be signalled (the single
/// H bit selects 128 or 256); ristrust matches ristgo in offering only these two.
/// Making it an enum renders an invalid key size unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeyBits {
    /// 128-bit key (16 bytes); GRE H bit clear.
    Aes128,
    /// 256-bit key (32 bytes); GRE H bit set.
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

    /// The key length in bits (128 or 256).
    #[must_use]
    pub fn bits(self) -> u16 {
        match self {
            AesKeyBits::Aes128 => 128,
            AesKeyBits::Aes256 => 256,
        }
    }

    /// The key size the GRE H bit indicates (`true` => 256, `false` => 128).
    #[must_use]
    pub fn from_h_bit(h: bool) -> AesKeyBits {
        if h {
            AesKeyBits::Aes256
        } else {
            AesKeyBits::Aes128
        }
    }
}

/// libRIST's effective PBKDF2 passphrase: the bytes up to the first NUL, then
/// capped at [`MAX_PASSWORD_LEN`].
fn bound_password(password: &[u8]) -> &[u8] {
    let end = password
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(password.len());
    &password[..end.min(MAX_PASSWORD_LEN)]
}

/// Derives an AES key from a passphrase and the 4-byte GRE nonce salt via
/// PBKDF2-HMAC-SHA256 with RIST's fixed 1024 iterations. The passphrase is bound
/// to libRIST's wire form (NUL-truncated, ≤127 bytes) so an embedded NUL or an
/// over-long passphrase derives the identical key libRIST would. The returned
/// vector has length `bits.bytes()`.
pub fn derive_key(
    password: &[u8],
    nonce4: &[u8],
    bits: AesKeyBits,
) -> Result<Vec<u8>, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    if nonce4.len() != NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLength);
    }
    let mut key = vec![0u8; bits.bytes()];
    pbkdf2_hmac::<Sha256>(
        bound_password(password),
        nonce4,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    Ok(key)
}

/// Constructs the 16-byte AES-CTR IV for a GRE sequence number: the sequence
/// big-endian in `[0:4]`, then twelve zero bytes. AES-CTR increments the low
/// bytes, so the per-packet seq in the high bytes gives every packet a disjoint
/// keystream window.
#[must_use]
pub fn build_iv(seq: u32) -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    iv[0..4].copy_from_slice(&seq.to_be_bytes());
    iv
}

/// Applies AES-CTR (symmetric: encrypt == decrypt) over `buf` in place, with the
/// `derive_key`-produced `key` (16 or 32 bytes) and the 16-byte `iv`.
fn aes_ctr_apply(key: &[u8], iv: &[u8; IV_SIZE], buf: &mut [u8]) {
    if key.len() == 32 {
        Aes256Ctr::new(key.into(), iv.into()).apply_keystream(buf);
    } else {
        // `derive_key` only ever yields a 16- or 32-byte key.
        Aes128Ctr::new(key.into(), iv.into()).apply_keystream(buf);
    }
}

/// One-shot decryption (or encryption — AES-CTR is symmetric): derives the key
/// from `password` and `nonce`, then applies AES-CTR over `src` for `seq`,
/// returning the result. A zero nonce is rejected. Prefer [`Decryptor`] for a
/// receive path that processes many packets, so the key is re-derived only on
/// nonce changes.
pub fn decrypt(
    password: &[u8],
    bits: AesKeyBits,
    nonce: [u8; NONCE_SIZE],
    seq: u32,
    src: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if is_zero_nonce(nonce) {
        return Err(CryptoError::ZeroNonce);
    }
    let key = derive_key(password, &nonce, bits)?;
    let mut out = src.to_vec();
    aes_ctr_apply(&key, &build_iv(seq), &mut out);
    Ok(out)
}

/// A stateful PSK encryptor for one direction of a Main-profile flow. It owns the
/// current nonce, the key derived from it, and the count of packets encrypted
/// under it, rotating the nonce and re-deriving when the rotation threshold is
/// reached. Not safe for concurrent use; the host serializes the send path.
// Justification: `key`/`key_rotation` are the natural names for the AES key and
// its rotation threshold; the "Key" prefix is the domain term, not noise.
#[allow(clippy::struct_field_names)]
#[derive(Debug)]
pub struct Key {
    password: Vec<u8>,
    bits: AesKeyBits,
    /// 0 selects "rotate only at the reuse-limit ceiling" (the library default).
    key_rotation: u32,
    odd: bool,
    nonce: [u8; NONCE_SIZE],
    key: Vec<u8>,
    used_times: u32,
}

impl Key {
    /// Constructs a `Key`, generating an initial non-zero nonce with the correct
    /// odd/even B-bit and deriving the first AES key. `key_rotation` is the number
    /// of packets to encrypt under one nonce before rotating (0 = rotate only at
    /// the reuse ceiling). `odd` selects which of the two passphrase keys this is.
    pub fn new(
        password: &[u8],
        bits: AesKeyBits,
        key_rotation: u32,
        odd: bool,
    ) -> Result<Key, CryptoError> {
        if password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        let mut k = Key {
            password: password.to_vec(),
            bits,
            key_rotation,
            odd,
            nonce: [0; NONCE_SIZE],
            key: Vec::new(),
            used_times: 0,
        };
        k.rekey()?;
        Ok(k)
    }

    /// The 4-byte GRE nonce currently in force; the host writes it into the GRE
    /// Key/Nonce field of every packet this key produces.
    #[must_use]
    pub fn nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce
    }

    /// Generates a fresh non-zero nonce with the correct B-bit, re-derives the
    /// key, and resets the used-times counter.
    fn rekey(&mut self) -> Result<(), CryptoError> {
        self.nonce = generate_nonce(self.odd)?;
        self.key = derive_key(&self.password, &self.nonce, self.bits)?;
        self.used_times = 0;
        Ok(())
    }

    /// Whether the next encrypt must rotate first: the user's rotation threshold
    /// (when positive) has been reached, or the counter would exhaust `u32`.
    fn rotate_due(&self) -> bool {
        self.used_times == u32::MAX
            || (self.key_rotation > 0 && self.used_times >= self.key_rotation)
    }

    /// Encrypts `plaintext` for GRE sequence `seq` under the current (or freshly
    /// rotated) key, returning the ciphertext. Read the nonce in force via
    /// [`Key::nonce`] after the call.
    pub fn encrypt(&mut self, seq: u32, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.rotate_due() {
            self.rekey()?;
        }
        let mut out = plaintext.to_vec();
        aes_ctr_apply(&self.key, &build_iv(seq), &mut out);
        self.used_times += 1;
        Ok(out)
    }
}

/// The receive-side counterpart of [`Key`]: a stateful PSK decryptor that
/// re-derives the AES key whenever the inbound GRE nonce differs from the one it
/// last keyed on. It holds no rotation policy — the sender drives rotation. Not
/// safe for concurrent use.
#[derive(Debug)]
pub struct Decryptor {
    password: Vec<u8>,
    bits: AesKeyBits,
    nonce: [u8; NONCE_SIZE],
    key: Vec<u8>,
    has_nonce: bool,
    used_times: u64,
}

impl Decryptor {
    /// Constructs a `Decryptor`. It derives no key until the first packet arrives;
    /// the inbound nonce on that packet selects the key.
    pub fn new(password: &[u8], bits: AesKeyBits) -> Result<Decryptor, CryptoError> {
        if password.is_empty() {
            return Err(CryptoError::EmptyPassword);
        }
        Ok(Decryptor {
            password: password.to_vec(),
            bits,
            nonce: [0; NONCE_SIZE],
            key: Vec::new(),
            has_nonce: false,
            used_times: 0,
        })
    }

    /// Sets the AES key size for subsequent decryptions (the size the GRE H bit
    /// indicates), forcing a re-derivation if it changed. A peer's configured
    /// `aes-type` need not match this side's — libRIST keys off the H bit.
    pub fn set_key_bits(&mut self, bits: AesKeyBits) {
        if bits != self.bits {
            self.bits = bits;
            self.has_nonce = false; // force re-derivation at the new size
        }
    }

    /// Decrypts `src` carried under the inbound `nonce` and sequence `seq`,
    /// returning the plaintext. A zero nonce is rejected; a changed nonce
    /// re-derives the key first.
    pub fn decrypt(
        &mut self,
        nonce: [u8; NONCE_SIZE],
        seq: u32,
        src: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if is_zero_nonce(nonce) {
            return Err(CryptoError::ZeroNonce);
        }
        if !self.has_nonce || nonce != self.nonce {
            self.nonce = nonce;
            self.key = derive_key(&self.password, &self.nonce, self.bits)?;
            self.has_nonce = true;
            self.used_times = 0;
        }
        if self.used_times > u64::from(u32::MAX) {
            return Err(CryptoError::KeyReuseExhausted);
        }
        let mut out = src.to_vec();
        aes_ctr_apply(&self.key, &build_iv(seq), &mut out);
        self.used_times += 1;
        Ok(out)
    }
}

/// Draws a random non-zero 32-bit nonce from the OS CSPRNG and stamps the
/// odd/even B-bit into bit 7 of `nonce[0]`. A zero draw is retried; persistent
/// failure surfaces [`CryptoError::Csprng`] (fail closed).
fn generate_nonce(odd: bool) -> Result<[u8; NONCE_SIZE], CryptoError> {
    for _ in 0..8 {
        let mut nonce = [0u8; NONCE_SIZE];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::Csprng)?;
        // Check the raw draw for zero before applying the marker bit, matching
        // libRIST's order (it checks the value before setting the bit).
        if u32::from_be_bytes(nonce) != 0 {
            nonce[0] &= !NONCE_B_BIT_MASK;
            if odd {
                nonce[0] |= NONCE_B_BIT_MASK;
            }
            return Ok(nonce);
        }
    }
    Err(CryptoError::Csprng)
}

/// Whether all four nonce bytes are zero.
fn is_zero_nonce(nonce: [u8; NONCE_SIZE]) -> bool {
    u32::from_be_bytes(nonce) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `n` bytes 0x00, 0x01, … — deterministic plaintext (ristgo `seqBytes`),
    /// wrapping at 256 like the Go `byte(i)` conversion.
    #[allow(clippy::cast_possible_truncation)] // deliberate low-byte fill
    fn seq_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    #[test]
    fn pbkdf2_hmac_sha256_rfc7914_vector() {
        // RFC 7914 §11: P="passwd", S="salt", c=1, dkLen=64.
        let mut out = [0u8; 64];
        pbkdf2_hmac::<Sha256>(b"passwd", b"salt", 1, &mut out);
        let want = hex(
            "55ac046e56e3089fec1691c22544b605 f94185216dde0465e68b9d57c20dacbc \
             49ca9cccf179b645991664b39d77ef31 7c71b845b1e30bd509112041d3a19783",
        );
        assert_eq!(out.as_slice(), want.as_slice());
    }

    #[test]
    fn derive_key_128_is_prefix_of_256() {
        let pw = b"ristgo-test-passphrase";
        let nonce = [0x12, 0x34, 0x56, 0x78];
        let k128 = derive_key(pw, &nonce, AesKeyBits::Aes128).unwrap();
        let k256 = derive_key(pw, &nonce, AesKeyBits::Aes256).unwrap();
        assert_eq!(k128, k256[..16]);
    }

    #[test]
    fn derive_key_validates_inputs() {
        assert_eq!(
            derive_key(b"", &[1, 2, 3, 4], AesKeyBits::Aes128),
            Err(CryptoError::EmptyPassword)
        );
        assert_eq!(
            derive_key(b"p", &[1, 2, 3], AesKeyBits::Aes128),
            Err(CryptoError::InvalidNonceLength)
        );
        assert_eq!(
            derive_key(b"p", &[1, 2, 3, 4, 5], AesKeyBits::Aes128),
            Err(CryptoError::InvalidNonceLength)
        );
    }

    struct Golden {
        name: &'static str,
        bits: AesKeyBits,
        want_key: &'static str,
        want_ct: &'static str,
    }

    /// The full PSK path (PBKDF2 → IV → AES-CTR) pinned to OpenSSL-anchored
    /// ciphertext (ristgo `goldenPSK`): password "ristgo-test-passphrase", nonce
    /// 0x12345678, seq 0x0A0B0C0D, plaintext 0x00..0x2F.
    fn goldens() -> Vec<Golden> {
        vec![
            Golden {
                name: "aes128",
                bits: AesKeyBits::Aes128,
                want_key: "e71c678c592282b5027e918d8407948a",
                want_ct: "f5883ed25bbc57d8a9bbb46bff8bae35 \
                          d5d6ee5a1f7453b4e8bddf96e962fce2 \
                          b7c5dd350c40b4ee9ec04565e1657a19",
            },
            Golden {
                name: "aes256",
                bits: AesKeyBits::Aes256,
                want_key: "e71c678c592282b5027e918d8407948a \
                           7f7dffaaf8cb34055f75dbfd144c2101",
                want_ct: "a9d99869d41be7d0c8528f49613572a9 \
                          7658cccac65cb2f15bb8fa6d82dca66d \
                          c2aa610fc2c3a34b84c67262d3a2dd1e",
            },
        ]
    }

    #[test]
    fn golden_psk_byte_exact() {
        let password = b"ristgo-test-passphrase";
        let nonce = [0x12, 0x34, 0x56, 0x78];
        let seq = 0x0A0B_0C0D;
        let plaintext = seq_bytes(48);
        for g in goldens() {
            let want_key = hex(g.want_key);
            let want_ct = hex(g.want_ct);

            // Derived key matches the frozen value.
            assert_eq!(
                derive_key(password, &nonce, g.bits).unwrap(),
                want_key,
                "{} key",
                g.name
            );

            // Encrypt(plaintext) == golden ciphertext (anchored to OpenSSL).
            let ct = decrypt(password, g.bits, nonce, seq, &plaintext).unwrap();
            assert_eq!(ct, want_ct, "{} ciphertext", g.name);

            // One-shot and Decryptor both recover the plaintext (CTR symmetric).
            assert_eq!(
                decrypt(password, g.bits, nonce, seq, &want_ct).unwrap(),
                plaintext
            );
            let mut d = Decryptor::new(password, g.bits).unwrap();
            assert_eq!(
                d.decrypt(nonce, seq, &want_ct).unwrap(),
                plaintext,
                "{} decryptor",
                g.name
            );
        }
    }

    #[test]
    fn build_iv_layout() {
        let cases: &[(u32, [u8; 16])] = &[
            (0, [0; 16]),
            (1, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (
                0x0A0B_0C0D,
                [0x0A, 0x0B, 0x0C, 0x0D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            (
                0xFFFF_FFFF,
                [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
        ];
        for &(seq, want) in cases {
            assert_eq!(build_iv(seq), want, "seq {seq:#x}");
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        for bits in [AesKeyBits::Aes128, AesKeyBits::Aes256] {
            for odd in [false, true] {
                let mut k = Key::new(b"round-trip-secret", bits, 0, odd).unwrap();
                let mut d = Decryptor::new(b"round-trip-secret", bits).unwrap();
                for n in [0usize, 1, 7, 16, 17, 188, 1316] {
                    for seq in [0u32, 1, 0x1234_5678, 0xFFFF_FFFF] {
                        let pt = seq_bytes(n);
                        let ct = k.encrypt(seq, &pt).unwrap();
                        if n >= 16 {
                            assert_ne!(ct, pt, "ciphertext == plaintext for n={n}");
                        }
                        let got = d.decrypt(k.nonce(), seq, &ct).unwrap();
                        assert_eq!(
                            got,
                            pt,
                            "round trip bits={} n={n} seq={seq:#x}",
                            bits.bits()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn zero_nonce_rejected() {
        let zero = [0u8; NONCE_SIZE];
        assert_eq!(
            decrypt(b"p", AesKeyBits::Aes128, zero, 1, b"data"),
            Err(CryptoError::ZeroNonce)
        );
        let mut d = Decryptor::new(b"p", AesKeyBits::Aes128).unwrap();
        assert_eq!(d.decrypt(zero, 1, b"data"), Err(CryptoError::ZeroNonce));
    }

    #[test]
    fn nonce_b_bit_marks_odd_even() {
        for odd in [false, true] {
            for _ in 0..64 {
                let k = Key::new(b"bbit", AesKeyBits::Aes128, 0, odd).unwrap();
                let n = k.nonce();
                assert_eq!(n[0] & NONCE_B_BIT_MASK != 0, odd, "nonce[0]={:#x}", n[0]);
                assert!(!is_zero_nonce(n));
            }
        }
    }

    #[test]
    fn key_rotates_at_threshold() {
        const ROTATION: u32 = 4;
        let mut k = Key::new(b"rotate", AesKeyBits::Aes128, ROTATION, false).unwrap();
        let first = k.nonce();
        for i in 0..ROTATION {
            k.encrypt(i, b"payload").unwrap();
            assert_eq!(k.nonce(), first, "rotated early after {} packets", i + 1);
        }
        k.encrypt(ROTATION, b"payload").unwrap();
        assert_ne!(k.nonce(), first, "did not rotate at the threshold");
    }

    #[test]
    fn decryptor_rekeys_on_nonce_change() {
        let pw = b"rekey-secret";
        let mut d = Decryptor::new(pw, AesKeyBits::Aes256).unwrap();
        let nonce_a = [0x01, 0x02, 0x03, 0x04];
        let nonce_b = [0x11, 0x22, 0x33, 0x44];
        let pt = seq_bytes(100);
        let seq = 0xABCD_EF01;
        let ct_a = decrypt(pw, AesKeyBits::Aes256, nonce_a, seq, &pt).unwrap();
        let ct_b = decrypt(pw, AesKeyBits::Aes256, nonce_b, seq, &pt).unwrap();
        assert_ne!(ct_a, ct_b, "different nonces gave identical ciphertext");
        assert_eq!(d.decrypt(nonce_a, seq, &ct_a).unwrap(), pt);
        assert_eq!(d.decrypt(nonce_b, seq, &ct_b).unwrap(), pt, "rekey failed");
        assert_eq!(
            d.decrypt(nonce_a, seq, &ct_a).unwrap(),
            pt,
            "rekey back failed"
        );
    }
}
