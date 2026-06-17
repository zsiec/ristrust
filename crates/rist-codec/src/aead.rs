//! Authenticated AEAD encryption for the RIST Advanced Profile PSK modes
//! (TR-06-3 §8), ported from ristgo `internal/crypto/aead.go`.
//!
//! libRIST v0.2.18-rc1 implements only the Main-compatible AES-CTR mode (PSK mode 1)
//! for the Advanced profile. The three authenticated modes here are a ristgo extension
//! (ristgo↔ristrust only, no libRIST interop):
//!
//! - mode 3 [`PSK_AES_CTR_HMAC`]: AES-CTR + HMAC-SHA256;
//! - mode 4 [`PSK_AES_GCM`]: AES-GCM;
//! - mode 5 [`PSK_CHACHA20_POLY`]: ChaCha20-Poly1305.
//!
//! The cipher primitives (AES-GCM, ChaCha20-Poly1305, AES-CTR, HMAC-SHA256) are
//! standard RustCrypto; the RIST framing around them — the 12-byte AEAD nonce, the AAD
//! scope, the encrypt-then-MAC HMAC key — is **INTERPRETED** (TR-06-3 §8 does not
//! specify a 12-byte AEAD nonce), so it is interop-unvalidated and matched byte-for-byte
//! to ristgo, against which the KATs are pinned.
//!
//! Sans-I/O: every function is a pure transform of its inputs; no clock, socket, or
//! CSPRNG draw happens here (the nonce/IV come from the caller).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::adv::{PSK_AES_CTR_HMAC, PSK_AES_GCM, PSK_CHACHA20_POLY};
use crate::crypto::{self, AesKeyBits, CryptoError, NONCE_SIZE};

type HmacSha256 = Hmac<Sha256>;

/// The length of the Advanced PSK Hash field: 16 bytes. It carries the GCM tag, the
/// Poly1305 tag, or the truncated HMAC depending on the mode.
pub const HASH_SIZE: usize = 16;

/// The standard 96-bit AEAD nonce length (GCM and ChaCha20-Poly1305).
const AEAD_NONCE_SIZE: usize = 12;

/// The HKDF-Expand-style label that domain-separates the AES-CTR-HMAC authentication
/// key from the encryption key.
const MAC_KEY_LABEL: &[u8] = b"rist-adv-aes-ctr-hmac-auth-key";

/// Builds the INTERPRETED 12-byte AEAD nonce: the 4-byte PSK nonce (the key epoch) in
/// `[0:4]`, the 4-byte IV field big-endian in `[4:8]`, then four zero bytes. Folding
/// the PSK nonce into the AEAD nonce — not only into the key derivation — keeps every
/// key epoch structurally distinct, so two epochs can never share a `(key, nonce)` pair
/// even if their per-packet IV ranges overlap; within an epoch the IV field supplies
/// uniqueness ([`AdvancedSealer`] refuses to let it wrap).
fn aead_nonce(nonce4: [u8; NONCE_SIZE], iv4: u32) -> [u8; AEAD_NONCE_SIZE] {
    let mut n = [0u8; AEAD_NONCE_SIZE];
    n[0..NONCE_SIZE].copy_from_slice(&nonce4);
    n[NONCE_SIZE..NONCE_SIZE + 4].copy_from_slice(&iv4.to_be_bytes());
    n
}

/// Encrypts `plaintext` under the given Advanced PSK `mode` (3/4/5), returning the wire
/// ciphertext (no appended tag) and the 16-byte PSK Hash-field value.
///
/// The key is derived from `password` and the 4-byte PSK `nonce4` via PBKDF2-HMAC-SHA256
/// (the configured-`Secret` path; matching ristgo's `DeriveKey`). `iv4` is the per-packet
/// IV field forming the AEAD nonce / AES-CTR IV. `aad` is the authenticated-not-encrypted
/// region (the cleartext header bytes with the Hash field zeroed). For modes 4/5 the hash
/// is the AEAD tag; for mode 3 the ciphertext is the AES-CTR output and the hash is
/// `HMAC-SHA256(aad || ciphertext)` truncated to 16 bytes (encrypt-then-MAC).
///
/// # Errors
/// [`CryptoError::ZeroNonce`] for a zero `nonce4`, [`CryptoError::ChaChaKeySize`] for
/// mode 5 with a non-256-bit key, [`CryptoError::UnknownPskMode`] for any other mode, or
/// a key-derivation error.
pub fn seal_advanced(
    mode: u8,
    password: &[u8],
    bits: AesKeyBits,
    nonce4: [u8; NONCE_SIZE],
    iv4: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; HASH_SIZE]), CryptoError> {
    if u32::from_be_bytes(nonce4) == 0 {
        return Err(CryptoError::ZeroNonce);
    }
    let key = derive_aead_key(mode, password, nonce4, bits)?;
    match mode {
        PSK_AES_CTR_HMAC => {
            let mac_key = derive_mac_key(&key);
            let mut ct = plaintext.to_vec();
            crypto::aes_ctr_apply(&key, &crypto::build_iv(iv4), &mut ct);
            let hash = hmac_tag(&mac_key, aad, &ct);
            Ok((ct, hash))
        }
        PSK_AES_GCM => seal_aead(&key, &aead_nonce(nonce4, iv4), aad, plaintext),
        PSK_CHACHA20_POLY => seal_chacha(&key, &aead_nonce(nonce4, iv4), aad, plaintext),
        _ => Err(CryptoError::UnknownPskMode),
    }
}

/// Reverses [`seal_advanced`]: re-derives the key(s), verifies the tag/HMAC in constant
/// time, and only then returns the plaintext. On any authentication failure it returns
/// [`CryptoError::AuthFailed`] and never leaks the recovered bytes.
///
/// `hash` is the 16-byte value read from the PSK Hash field; `aad` must be identical to
/// the sender's (the header bytes with the Hash field zeroed).
///
/// # Errors
/// [`CryptoError::AuthFailed`] on a tag/HMAC mismatch, plus the same input errors as
/// [`seal_advanced`].
// Mirrors ristgo's `OpenAdvanced` signature one-for-one (mode, password, key bits, PSK
// nonce, IV, AAD, ciphertext, hash); collapsing these into a struct would obscure the
// direct correspondence with the reference and the wire fields they map to.
#[allow(clippy::too_many_arguments)]
pub fn open_advanced(
    mode: u8,
    password: &[u8],
    bits: AesKeyBits,
    nonce4: [u8; NONCE_SIZE],
    iv4: u32,
    aad: &[u8],
    ciphertext: &[u8],
    hash: [u8; HASH_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    if u32::from_be_bytes(nonce4) == 0 {
        return Err(CryptoError::ZeroNonce);
    }
    let key = derive_aead_key(mode, password, nonce4, bits)?;
    match mode {
        PSK_AES_CTR_HMAC => {
            // Encrypt-then-MAC: verify the HMAC over the ciphertext before decrypting.
            let mac_key = derive_mac_key(&key);
            let want = hmac_tag(&mac_key, aad, ciphertext);
            if want.ct_eq(&hash).unwrap_u8() != 1 {
                return Err(CryptoError::AuthFailed);
            }
            let mut pt = ciphertext.to_vec();
            crypto::aes_ctr_apply(&key, &crypto::build_iv(iv4), &mut pt);
            Ok(pt)
        }
        PSK_AES_GCM => open_aead(&key, &aead_nonce(nonce4, iv4), aad, ciphertext, hash),
        PSK_CHACHA20_POLY => open_chacha(&key, &aead_nonce(nonce4, iv4), aad, ciphertext, hash),
        _ => Err(CryptoError::UnknownPskMode),
    }
}

/// A stateful, single-epoch wrapper around [`seal_advanced`] that owns the per-packet IV
/// field and makes the `(key, nonce)`-uniqueness requirement structural: it issues a
/// fresh monotonically increasing IV per seal and refuses with [`CryptoError::IvExhausted`]
/// once the 32-bit IV field would wrap within the current PSK nonce — so a repeated nonce
/// (catastrophic under GCM/ChaCha) cannot happen silently. Construct one per PSK-nonce
/// epoch; on exhaustion the host rotates the nonce (re-derives the key) and builds a new
/// sealer. Not safe for concurrent use; the host serializes its single send path.
#[derive(Debug)]
pub struct AdvancedSealer {
    mode: u8,
    password: Vec<u8>,
    bits: AesKeyBits,
    nonce4: [u8; NONCE_SIZE],
    iv: u32,
    exhausted: bool,
}

impl AdvancedSealer {
    /// Creates a sealer for one PSK-nonce epoch, issuing `start_iv`, `start_iv + 1`, ….
    #[must_use]
    pub fn new(
        mode: u8,
        password: &[u8],
        bits: AesKeyBits,
        nonce4: [u8; NONCE_SIZE],
        start_iv: u32,
    ) -> AdvancedSealer {
        AdvancedSealer {
            mode,
            password: password.to_vec(),
            bits,
            nonce4,
            iv: start_iv,
            exhausted: false,
        }
    }

    /// The PSK nonce this sealer keys on (the host writes it into the packet header).
    #[must_use]
    pub fn nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce4
    }

    /// Encrypts `plaintext` with the next IV field, returning the wire ciphertext, the
    /// 16-byte Hash value, and the IV used (which the codec writes into the header so the
    /// receiver can [`open_advanced`]).
    ///
    /// # Errors
    /// [`CryptoError::IvExhausted`] once the IV field is spent (the host must rotate the
    /// PSK nonce and build a new sealer), or any [`seal_advanced`] error.
    pub fn seal(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; HASH_SIZE], u32), CryptoError> {
        if self.exhausted {
            return Err(CryptoError::IvExhausted);
        }
        let iv4 = self.iv;
        let (ct, hash) = seal_advanced(
            self.mode,
            &self.password,
            self.bits,
            self.nonce4,
            iv4,
            aad,
            plaintext,
        )?;
        if self.iv == u32::MAX {
            self.exhausted = true;
        } else {
            self.iv += 1;
        }
        Ok((ct, hash, iv4))
    }
}

/// Derives the symmetric key for `mode` from the passphrase and PSK nonce. ChaCha20-
/// Poly1305 (mode 5) requires a 256-bit key; the AES modes accept 128 or 256.
fn derive_aead_key(
    mode: u8,
    password: &[u8],
    nonce4: [u8; NONCE_SIZE],
    bits: AesKeyBits,
) -> Result<Vec<u8>, CryptoError> {
    if mode == PSK_CHACHA20_POLY && bits != AesKeyBits::Aes256 {
        return Err(CryptoError::ChaChaKeySize);
    }
    crypto::derive_key(password, &nonce4, bits)
}

/// Derives the independent HMAC key for AES-CTR-HMAC by expanding the AES key with a
/// distinct label (key separation: the cipher key and the MAC key never coincide).
fn derive_mac_key(enc_key: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(enc_key).expect("HMAC accepts any key length");
    mac.update(MAC_KEY_LABEL);
    mac.finalize().into_bytes().to_vec()
}

/// `HMAC-SHA256(aad || ciphertext)` keyed by the MAC key, truncated to 16 bytes.
fn hmac_tag(mac_key: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; HASH_SIZE] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(aad);
    mac.update(ciphertext);
    let full = mac.finalize().into_bytes();
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&full[..HASH_SIZE]);
    hash
}

/// Seals with AES-GCM (16/32-byte key) or ChaCha20-Poly1305 (32-byte key), splitting the
/// 16-byte tag out into the Hash field (RIST carries the tag in the header, not appended).
fn seal_aead(
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; HASH_SIZE]), CryptoError> {
    let mut sealed = aead_encrypt(key, nonce, aad, plaintext)?;
    let ct_len = sealed.len() - HASH_SIZE;
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&sealed[ct_len..]);
    sealed.truncate(ct_len);
    Ok((sealed, hash))
}

/// Opens an AES-GCM / ChaCha20-Poly1305 packet: re-joins the wire ciphertext and the tag
/// from the Hash field, then verifies-and-decrypts. A tag mismatch maps to `AuthFailed`.
fn open_aead(
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    hash: [u8; HASH_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let mut sealed = Vec::with_capacity(ciphertext.len() + HASH_SIZE);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(&hash);
    aead_decrypt(key, nonce, aad, &sealed)
}

/// Dispatches AEAD encryption by key length: ChaCha20-Poly1305 / AES-256-GCM for a
/// 32-byte key, AES-128-GCM for a 16-byte key. The mode-vs-key-size invariant is enforced
/// by [`derive_aead_key`], so a 32-byte key for an AES mode still selects AES-256-GCM.
fn aead_encrypt(
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let out = if key.len() == 32 {
        Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::AuthFailed)?
            .encrypt(nonce.into(), payload)
    } else {
        Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::AuthFailed)?
            .encrypt(nonce.into(), payload)
    };
    out.map_err(|_| CryptoError::AuthFailed)
}

fn aead_decrypt(
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let payload = Payload { msg: sealed, aad };
    let out = if key.len() == 32 {
        Aes256Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::AuthFailed)?
            .decrypt(nonce.into(), payload)
    } else {
        Aes128Gcm::new_from_slice(key)
            .map_err(|_| CryptoError::AuthFailed)?
            .decrypt(nonce.into(), payload)
    };
    out.map_err(|_| CryptoError::AuthFailed)
}

/// ChaCha20-Poly1305 seal: split the 16-byte Poly1305 tag out into the Hash field.
fn seal_chacha(
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; HASH_SIZE]), CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::ChaChaKeySize)?;
    let mut sealed = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    let ct_len = sealed.len() - HASH_SIZE;
    let mut hash = [0u8; HASH_SIZE];
    hash.copy_from_slice(&sealed[ct_len..]);
    sealed.truncate(ct_len);
    Ok((sealed, hash))
}

/// ChaCha20-Poly1305 open: re-join ciphertext + tag, verify-and-decrypt.
fn open_chacha(
    key: &[u8],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    hash: [u8; HASH_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::ChaChaKeySize)?;
    let mut sealed = Vec::with_capacity(ciphertext.len() + HASH_SIZE);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(&hash);
    cipher
        .decrypt(nonce.into(), Payload { msg: &sealed, aad })
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string into bytes (test fixtures only; panics on bad input).
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd-length hex");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn nonce12(bytes: &[u8]) -> [u8; AEAD_NONCE_SIZE] {
        let mut n = [0u8; AEAD_NONCE_SIZE];
        n.copy_from_slice(bytes);
        n
    }

    // NIST SP 800-38D AES-GCM test case 4 (the case with non-empty AAD, matching the
    // RIST shape). Anchors the GCM primitive against a published standard vector.
    #[test]
    fn aes_gcm_nist_tc4_kat() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = nonce12(&hex("cafebabefacedbaddecaf888"));
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let want_ct = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let want_tag = hex("5bc94fbc3221a5db94fae95ae7121a47");

        let (ct, hash) = seal_aead(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(ct, want_ct, "NIST GCM TC4 ciphertext");
        assert_eq!(&hash[..], &want_tag[..], "NIST GCM TC4 tag");

        let got = open_aead(&key, &nonce, &aad, &ct, hash).unwrap();
        assert_eq!(got, pt, "openGCM round-trip");
    }

    // RFC 8439 §2.8.2 worked example. Anchors the ChaCha20-Poly1305 primitive.
    #[test]
    fn chacha20_poly1305_rfc8439_kat() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = nonce12(&hex("070000004041424344454647"));
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        let want_ct = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let want_tag = hex("1ae10b594f09e26a7e902ecbd0600691");

        let (ct, hash) = seal_chacha(&key, &nonce, &aad, &pt).unwrap();
        assert_eq!(ct, want_ct, "RFC 8439 ciphertext");
        assert_eq!(&hash[..], &want_tag[..], "RFC 8439 tag");

        let got = open_chacha(&key, &nonce, &aad, &ct, hash).unwrap();
        assert_eq!(got, pt, "openChaCha round-trip");
    }

    // Frozen AES-CTR-HMAC (mode 3) output for a fixed (key, IV, aad, plaintext), so a
    // regression in the AES-CTR keystream or the encrypt-then-MAC HMAC is caught
    // byte-for-byte. Ported from ristgo; the HMAC is keyed directly by `key` here (the
    // primitive test), independent of the deriveMACKey wrapper.
    #[test]
    fn aes_ctr_hmac_golden() {
        let key = hex("000102030405060708090a0b0c0d0e0f");
        let iv4: u32 = 0x0000_0001;
        let aad = b"rist-adv-aad-header";
        let pt = b"Advanced Profile AES-CTR-HMAC golden plaintext!!";
        let want_ct = hex(
            "d46795c34a394e801cc80682987281fbde5bd7beabb25238d431051d917aff280fe59892ba9fc38b539128bdafdfcead",
        );
        let want_hash = hex("2b4c358f0f14d0878731d04fd884980d");

        let mut ct = pt.to_vec();
        crypto::aes_ctr_apply(&key, &crypto::build_iv(iv4), &mut ct);
        assert_eq!(ct, want_ct, "AES-CTR-HMAC ciphertext");

        let hash = hmac_tag(&key, aad, &ct);
        assert_eq!(&hash[..], &want_hash[..], "AES-CTR-HMAC HMAC");
        assert_eq!(ct.len(), pt.len(), "mode 3 ciphertext is tag-free");
    }

    // SealAdvanced -> OpenAdvanced for every authenticated mode/key-size, deriving the
    // key from a passphrase + nonce exactly as the wire path does.
    #[test]
    fn seal_open_round_trip_all_modes() {
        let password = b"ristrust-advanced-passphrase";
        let nonce4 = [0x12u8, 0x34, 0x56, 0x78];
        let iv4: u32 = 0xDEAD_BEEF;
        let aad = b"cleartext header bytes with hash zeroed";
        let pt = b"the quick brown fox jumps over the lazy dog, twice over";
        let cases: &[(u8, AesKeyBits)] = &[
            (PSK_AES_CTR_HMAC, AesKeyBits::Aes128),
            (PSK_AES_CTR_HMAC, AesKeyBits::Aes256),
            (PSK_AES_GCM, AesKeyBits::Aes128),
            (PSK_AES_GCM, AesKeyBits::Aes256),
            (PSK_CHACHA20_POLY, AesKeyBits::Aes256),
        ];
        for &(mode, bits) in cases {
            let (ct, hash) = seal_advanced(mode, password, bits, nonce4, iv4, aad, pt).unwrap();
            assert_eq!(ct.len(), pt.len(), "mode {mode} tag-free wire ciphertext");
            assert_ne!(&ct[..], &pt[..], "mode {mode} ciphertext != plaintext");
            assert_ne!(hash, [0u8; HASH_SIZE], "mode {mode} hash is non-zero");
            let got = open_advanced(mode, password, bits, nonce4, iv4, aad, &ct, hash).unwrap();
            assert_eq!(got, pt, "mode {mode} round-trip");
        }
    }

    // Zero-length payload (still authenticated over the AAD) round-trips without panic.
    #[test]
    fn seal_open_empty_plaintext() {
        let password = b"pw";
        let nonce4 = [1u8, 2, 3, 4];
        let aad = b"header";
        for mode in [PSK_AES_CTR_HMAC, PSK_AES_GCM, PSK_CHACHA20_POLY] {
            let (ct, hash) =
                seal_advanced(mode, password, AesKeyBits::Aes256, nonce4, 7, aad, &[]).unwrap();
            assert_eq!(ct.len(), 0, "mode {mode} empty ciphertext");
            let got = open_advanced(
                mode,
                password,
                AesKeyBits::Aes256,
                nonce4,
                7,
                aad,
                &ct,
                hash,
            )
            .unwrap();
            assert_eq!(got.len(), 0, "mode {mode} empty recovered");
        }
    }

    // Any single-bit tamper of the ciphertext, hash, or AAD must fail authentication
    // with AuthFailed and never leak plaintext.
    #[test]
    fn tamper_is_rejected() {
        let password = b"pw";
        let nonce4 = [9u8, 8, 7, 6];
        let aad = b"aad";
        let pt = b"sensitive media payload";
        for mode in [PSK_AES_CTR_HMAC, PSK_AES_GCM, PSK_CHACHA20_POLY] {
            let (ct, hash) =
                seal_advanced(mode, password, AesKeyBits::Aes256, nonce4, 3, aad, pt).unwrap();

            let mut bad_ct = ct.clone();
            bad_ct[0] ^= 0x01;
            assert!(matches!(
                open_advanced(
                    mode,
                    password,
                    AesKeyBits::Aes256,
                    nonce4,
                    3,
                    aad,
                    &bad_ct,
                    hash
                ),
                Err(CryptoError::AuthFailed)
            ));

            let mut bad_hash = hash;
            bad_hash[0] ^= 0x01;
            assert!(matches!(
                open_advanced(
                    mode,
                    password,
                    AesKeyBits::Aes256,
                    nonce4,
                    3,
                    aad,
                    &ct,
                    bad_hash
                ),
                Err(CryptoError::AuthFailed)
            ));

            assert!(matches!(
                open_advanced(
                    mode,
                    password,
                    AesKeyBits::Aes256,
                    nonce4,
                    3,
                    b"AAD",
                    &ct,
                    hash
                ),
                Err(CryptoError::AuthFailed)
            ));
        }
    }

    // The sealer issues monotonic IVs and refuses to wrap within an epoch.
    #[test]
    fn sealer_refuses_iv_wrap() {
        let mut s = AdvancedSealer::new(
            PSK_AES_GCM,
            b"pw",
            AesKeyBits::Aes256,
            [1, 0, 0, 0],
            u32::MAX,
        );
        let (_, _, iv) = s.seal(b"aad", b"data").unwrap();
        assert_eq!(iv, u32::MAX, "issued the last representable IV");
        assert!(matches!(
            s.seal(b"aad", b"data"),
            Err(CryptoError::IvExhausted)
        ));
    }

    #[test]
    fn sealer_issues_monotonic_ivs() {
        let mut s = AdvancedSealer::new(
            PSK_CHACHA20_POLY,
            b"pw",
            AesKeyBits::Aes256,
            [2, 0, 0, 0],
            100,
        );
        for expect in 100..105u32 {
            let (_, _, iv) = s.seal(b"aad", b"x").unwrap();
            assert_eq!(iv, expect);
        }
    }

    #[test]
    fn zero_nonce_is_rejected() {
        assert!(matches!(
            seal_advanced(
                PSK_AES_GCM,
                b"pw",
                AesKeyBits::Aes256,
                [0, 0, 0, 0],
                1,
                b"a",
                b"b"
            ),
            Err(CryptoError::ZeroNonce)
        ));
    }

    #[test]
    fn chacha_requires_256_bit_key() {
        assert!(matches!(
            seal_advanced(
                PSK_CHACHA20_POLY,
                b"pw",
                AesKeyBits::Aes128,
                [1, 0, 0, 0],
                1,
                b"a",
                b"b"
            ),
            Err(CryptoError::ChaChaKeySize)
        ));
    }

    #[test]
    fn unknown_mode_is_rejected() {
        assert!(matches!(
            seal_advanced(1, b"pw", AesKeyBits::Aes256, [1, 0, 0, 0], 1, b"a", b"b"),
            Err(CryptoError::UnknownPskMode)
        ));
    }
}
