//! Ephemeral ECDH over P-256 for the ECDHE suites (RFC 4492) and RSA key transport
//! for `RSA_WITH_NULL_SHA256` (RFC 5246 §7.4.7.1, ristgo `keyexchange.go`), plus the
//! CSPRNG adapter the elliptic-curve crates need.

use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{CryptoRng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use super::DtlsError;
use super::record::VERSION_DTLS_1_2;

/// A CSPRNG adapter exposing the OS entropy source through the `rand_core` traits
/// the `p256` key generators require.
#[derive(Debug)]
pub struct OsCsprng;

impl RngCore for OsCsprng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS CSPRNG unavailable");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for OsCsprng {}

/// Generates an ephemeral P-256 key pair, returning the secret and its
/// uncompressed public point (`0x04 || X || Y`, 65 bytes).
#[must_use]
pub fn generate_ecdhe() -> (EphemeralSecret, Vec<u8>) {
    let secret = EphemeralSecret::random(&mut OsCsprng);
    let point = secret.public_key().to_encoded_point(false);
    (secret, point.as_bytes().to_vec())
}

/// Computes the ECDHE premaster secret — the shared X-coordinate (32 bytes for
/// P-256) — from our ephemeral secret and the peer's uncompressed public point.
///
/// # Errors
/// [`DtlsError::Malformed`] if the peer point is not a valid P-256 point.
pub fn ecdhe_premaster(secret: &EphemeralSecret, peer_point: &[u8]) -> Result<Vec<u8>, DtlsError> {
    let peer = PublicKey::from_sec1_bytes(peer_point)
        .map_err(|_| DtlsError::Malformed("ecdhe peer point"))?;
    let shared = secret.diffie_hellman(&peer);
    Ok(shared.raw_secret_bytes().to_vec())
}

/// The fixed RSA key-transport pre-master length: 2-byte `client_version` || 46
/// random bytes (RFC 5246 §7.4.7.1).
pub const RSA_PREMASTER_LEN: usize = 48;

/// Generates an RSA-key-transport pre-master secret: the `client_version` this
/// client offered (DTLS 1.2) in the first two bytes followed by 46 random bytes (RFC
/// 5246 §7.4.7.1). The echoed version lets the server detect a version rollback.
///
/// # Errors
/// [`DtlsError::DecryptFailed`] if the OS CSPRNG is unavailable.
pub fn new_rsa_premaster() -> Result<Vec<u8>, DtlsError> {
    let mut pms = [0u8; RSA_PREMASTER_LEN];
    getrandom::fill(&mut pms[2..]).map_err(|_| DtlsError::DecryptFailed)?;
    pms[0] = VERSION_DTLS_1_2[0];
    pms[1] = VERSION_DTLS_1_2[1];
    Ok(pms.to_vec())
}

/// RSA-PKCS#1-v1.5-encrypts the pre-master to the server's RSA public key — the
/// ClientKeyExchange body for the RSA-key-transport suite.
///
/// # Errors
/// [`DtlsError::DecryptFailed`] if encryption fails (e.g. a too-small modulus).
pub fn encrypt_rsa_premaster(pub_key: &RsaPublicKey, pms: &[u8]) -> Result<Vec<u8>, DtlsError> {
    pub_key
        .encrypt(&mut OsCsprng, Pkcs1v15Encrypt, pms)
        .map_err(|_| DtlsError::DecryptFailed)
}

/// Recovers the RSA-key-transport pre-master from a ClientKeyExchange, applying the
/// Bleichenbacher countermeasure (RFC 5246 §7.4.7.1): on ANY decryption / padding
/// failure, a length mismatch, OR a mismatched embedded `client_version` (a
/// rollback), it returns a RANDOM pre-master rather than an error, so a padding
/// oracle cannot distinguish a malformed ciphertext from a valid one — the handshake
/// then fails identically at Finished. The version check and selection are
/// constant-time; the residual decrypt-path timing is the accepted `rsa`-crate
/// sidechannel (RUSTSEC-2023-0071, see `deny.toml`).
///
/// # Errors
/// [`DtlsError::DecryptFailed`] only if the OS CSPRNG (for the fallback) is
/// unavailable — never to signal a decryption failure (that path is silent).
pub fn decrypt_rsa_premaster(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, DtlsError> {
    // A random fallback whose version bytes already match, so a decrypt failure
    // yields a valid-looking-but-wrong pre-master.
    let mut out = [0u8; RSA_PREMASTER_LEN];
    getrandom::fill(&mut out).map_err(|_| DtlsError::DecryptFailed)?;
    out[0] = VERSION_DTLS_1_2[0];
    out[1] = VERSION_DTLS_1_2[1];

    if let Ok(pt) = key.decrypt(Pkcs1v15Encrypt, ciphertext)
        && pt.len() == RSA_PREMASTER_LEN
    {
        // Copy the decrypted pre-master into the output only when its embedded
        // client_version matches — a constant-time selection over the whole buffer.
        let version_ok = pt[0].ct_eq(&VERSION_DTLS_1_2[0]) & pt[1].ct_eq(&VERSION_DTLS_1_2[1]);
        for (o, p) in out.iter_mut().zip(pt.iter()) {
            o.conditional_assign(p, version_ok);
        }
    }
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdhe_round_trip_agrees() {
        // Two parties derive the same shared secret from each other's points.
        let (a_secret, a_point) = generate_ecdhe();
        let (b_secret, b_point) = generate_ecdhe();
        assert_eq!(a_point.len(), 65, "uncompressed P-256 point is 65 bytes");
        assert_eq!(a_point[0], 0x04, "point is uncompressed");
        let a_shared = ecdhe_premaster(&a_secret, &b_point).unwrap();
        let b_shared = ecdhe_premaster(&b_secret, &a_point).unwrap();
        assert_eq!(a_shared, b_shared, "ECDH must agree");
        assert_eq!(a_shared.len(), 32);
    }

    #[test]
    fn ecdhe_rejects_bad_point() {
        let (secret, _) = generate_ecdhe();
        assert!(ecdhe_premaster(&secret, &[0u8; 65]).is_err());
        assert!(ecdhe_premaster(&secret, &[0x04]).is_err());
    }

    #[test]
    fn rsa_key_transport_round_trips() {
        let key = RsaPrivateKey::new(&mut OsCsprng, 2048).expect("rsa keygen");
        let pub_key = RsaPublicKey::from(&key);
        let pms = new_rsa_premaster().unwrap();
        assert_eq!(pms.len(), RSA_PREMASTER_LEN);
        assert_eq!(
            &pms[..2],
            &VERSION_DTLS_1_2,
            "premaster echoes client_version"
        );
        let ct = encrypt_rsa_premaster(&pub_key, &pms).unwrap();
        let got = decrypt_rsa_premaster(&key, &ct).unwrap();
        assert_eq!(got, pms, "valid RSA key transport recovers the pre-master");
    }

    #[test]
    fn rsa_decrypt_garbage_yields_random_not_error() {
        let key = RsaPrivateKey::new(&mut OsCsprng, 2048).expect("rsa keygen");
        // A bogus ciphertext must NOT error (no padding oracle) and must NOT recover a
        // usable pre-master — the countermeasure returns a random one whose version
        // bytes are forced to match, so the handshake fails uniformly at Finished.
        let bogus = vec![0u8; 256];
        let got = decrypt_rsa_premaster(&key, &bogus).unwrap();
        assert_eq!(got.len(), RSA_PREMASTER_LEN);
        assert_eq!(&got[..2], &VERSION_DTLS_1_2);
    }
}
