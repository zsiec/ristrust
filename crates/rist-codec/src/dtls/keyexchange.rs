//! Ephemeral ECDH over P-256 for the ECDHE_ECDSA suite (RFC 4492, ristgo
//! `keyexchange.go`), plus the CSPRNG adapter the elliptic-curve crates need.

use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{CryptoRng, RngCore};

use super::DtlsError;

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
}
