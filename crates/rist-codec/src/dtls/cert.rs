//! Self-signed certificate generation, parsing, and handshake signing/verification
//! for the certificate-authenticated suites (ristgo `cert.go`). The leaf key may be
//! ECDSA P-256 (the `ECDHE_ECDSA_*` suites) or RSA (the `ECDHE_RSA_*` and
//! `RSA_WITH_NULL_SHA256` suites).
//!
//! The server presents a self-signed leaf; the client extracts its public key from
//! the SubjectPublicKeyInfo and verifies the ServerKeyExchange signature with it.
//! Verification policy is either `insecure_skip` (accept any leaf) or a SHA-256
//! fingerprint pin — there is no built-in trust store (libRIST has no DTLS PKI).

use core::time::Duration;
use std::str::FromStr;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;
use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Decode, Encode};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

use super::DtlsError;
use super::keyexchange::OsCsprng;
use super::suiteinfo::AuthMethod;
use super::suites::{
    HASH_ALG_SHA256, HASH_ALG_SHA384, SIG_ALG_ECDSA, SIG_ALG_RSA, SIG_SCHEME_ECDSA_P256_SHA256,
    SIG_SCHEME_RSA_PKCS1_SHA256,
};

/// The modulus size of a generated self-signed RSA key.
const RSA_SELF_SIGNED_BITS: usize = 2048;

/// A leaf signing key: ECDSA P-256 or RSA.
#[derive(Debug, Clone)]
enum PrivKey {
    /// An ECDSA P-256 signing key.
    Ecdsa(SigningKey),
    /// An RSA private key (used for both signing and key-transport decryption).
    Rsa(Box<RsaPrivateKey>),
}

/// A self-signed identity: its DER leaf certificate and signing key (ECDSA P-256 or
/// RSA).
#[derive(Debug, Clone)]
pub struct Identity {
    der: Vec<u8>,
    key: PrivKey,
}

impl Identity {
    /// Generates a fresh self-signed ECDSA P-256 certificate for `common_name`,
    /// valid for one year — the credential for the `ECDHE_ECDSA_*` suites.
    ///
    /// # Errors
    /// [`DtlsError::BadCertificate`] if certificate construction or signing fails.
    pub fn generate(common_name: &str) -> Result<Identity, DtlsError> {
        let signing_key = SigningKey::random(&mut OsCsprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let spki_der = verifying_key
            .to_public_key_der()
            .map_err(|_| DtlsError::BadCertificate)?;
        let der = build_self_signed(common_name, spki_der.as_bytes(), &signing_key)?;
        Ok(Identity {
            der,
            key: PrivKey::Ecdsa(signing_key),
        })
    }

    /// Generates a fresh self-signed RSA (2048-bit) certificate for `common_name`,
    /// valid for one year — the credential for the `ECDHE_RSA_*` and
    /// `RSA_WITH_NULL_SHA256` suites.
    ///
    /// # Errors
    /// [`DtlsError::BadCertificate`] if key generation, certificate construction, or
    /// signing fails.
    pub fn generate_rsa(common_name: &str) -> Result<Identity, DtlsError> {
        let priv_key = RsaPrivateKey::new(&mut OsCsprng, RSA_SELF_SIGNED_BITS)
            .map_err(|_| DtlsError::BadCertificate)?;
        let spki_der = RsaPublicKey::from(&priv_key)
            .to_public_key_der()
            .map_err(|_| DtlsError::BadCertificate)?;
        let signer = RsaSigningKey::<Sha256>::new(priv_key.clone());
        let der = build_self_signed_rsa(common_name, spki_der.as_bytes(), &signer)?;
        Ok(Identity {
            der,
            key: PrivKey::Rsa(Box::new(priv_key)),
        })
    }

    /// The DER-encoded leaf certificate.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The authentication method this identity serves (ECDSA or RSA).
    #[must_use]
    pub fn auth_method(&self) -> AuthMethod {
        match self.key {
            PrivKey::Ecdsa(_) => AuthMethod::Ecdsa,
            PrivKey::Rsa(_) => AuthMethod::Rsa,
        }
    }

    /// The RSA private key, when this is an RSA identity — used to decrypt the RSA
    /// key-transport ClientKeyExchange.
    #[must_use]
    pub fn rsa_private_key(&self) -> Option<&RsaPrivateKey> {
        match &self.key {
            PrivKey::Rsa(k) => Some(k),
            PrivKey::Ecdsa(_) => None,
        }
    }
}

/// The self-signed leaf parameters (SPKI, serial, one-year validity, subject) the
/// certificate builder consumes — the part independent of the signing key type.
type CertParams = (SubjectPublicKeyInfoOwned, SerialNumber, Validity, Name);

/// Builds the common self-signed leaf parameters for `common_name` over `spki_der`.
fn cert_params(common_name: &str, spki_der: &[u8]) -> Result<CertParams, DtlsError> {
    let spki =
        SubjectPublicKeyInfoOwned::from_der(spki_der).map_err(|_| DtlsError::BadCertificate)?;
    let serial = SerialNumber::from(1u32);
    let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600))
        .map_err(|_| DtlsError::BadCertificate)?;
    let subject =
        Name::from_str(&format!("CN={common_name}")).map_err(|_| DtlsError::BadCertificate)?;
    Ok((spki, serial, validity, subject))
}

/// Builds a one-year self-signed leaf for an ECDSA signing key over `spki_der`.
fn build_self_signed(
    common_name: &str,
    spki_der: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, DtlsError> {
    let (spki, serial, validity, subject) = cert_params(common_name, spki_der)?;
    let builder =
        CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, signing_key)
            .map_err(|_| DtlsError::BadCertificate)?;
    let cert = builder
        .build::<DerSignature>()
        .map_err(|_| DtlsError::BadCertificate)?;
    cert.to_der().map_err(|_| DtlsError::BadCertificate)
}

/// Builds a one-year self-signed leaf for an RSA signing key over `spki_der`.
fn build_self_signed_rsa(
    common_name: &str,
    spki_der: &[u8],
    signer: &RsaSigningKey<Sha256>,
) -> Result<Vec<u8>, DtlsError> {
    let (spki, serial, validity, subject) = cert_params(common_name, spki_der)?;
    let builder = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, signer)
        .map_err(|_| DtlsError::BadCertificate)?;
    let cert = builder
        .build::<rsa::pkcs1v15::Signature>()
        .map_err(|_| DtlsError::BadCertificate)?;
    cert.to_der().map_err(|_| DtlsError::BadCertificate)
}

/// A peer's leaf public key: ECDSA P-256 or RSA.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PeerKey {
    /// An ECDSA P-256 verifying key.
    Ecdsa(VerifyingKey),
    /// An RSA public key (also the encryption key for RSA key transport).
    Rsa(Box<RsaPublicKey>),
}

impl PeerKey {
    /// The authentication method this key represents (ECDSA or RSA).
    #[must_use]
    pub fn auth_method(&self) -> AuthMethod {
        match self {
            PeerKey::Ecdsa(_) => AuthMethod::Ecdsa,
            PeerKey::Rsa(_) => AuthMethod::Rsa,
        }
    }

    /// The RSA public key, when this is an RSA peer — used to encrypt the RSA
    /// key-transport pre-master secret.
    #[must_use]
    pub fn rsa_public_key(&self) -> Option<&RsaPublicKey> {
        match self {
            PeerKey::Rsa(k) => Some(k),
            PeerKey::Ecdsa(_) => None,
        }
    }
}

/// Signs `msg` under `identity`'s key, returning the TLS 1.2 signature scheme used
/// and the signature. It always signs with SHA-256 (a valid choice for every
/// supported suite), choosing ECDSA or RSA-PKCS#1-v1.5 by the key type. Used for the
/// ECDHE ServerKeyExchange.
///
/// # Errors
/// [`DtlsError::BadCertificate`] if the RSA key cannot produce a signature (e.g. a
/// degenerate or too-small modulus on a caller-supplied identity) — surfaced rather
/// than emitting an empty signature the peer would reject opaquely.
pub fn sign_handshake(identity: &Identity, msg: &[u8]) -> Result<(u16, Vec<u8>), DtlsError> {
    match &identity.key {
        PrivKey::Ecdsa(key) => {
            let sig: Signature = key.sign(msg);
            Ok((
                SIG_SCHEME_ECDSA_P256_SHA256,
                sig.to_der().as_bytes().to_vec(),
            ))
        }
        PrivKey::Rsa(key) => {
            let digest = Sha256::digest(msg);
            let sig = key
                .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                .map_err(|_| DtlsError::BadCertificate)?;
            Ok((SIG_SCHEME_RSA_PKCS1_SHA256, sig))
        }
    }
}

/// Verifies a handshake signature over `msg` under `key` for the received TLS 1.2
/// `sig_scheme`. Accepts ECDSA-P256 and RSA-PKCS#1-v1.5 over SHA-256 or SHA-384, so a
/// peer signing under either suite's hash interoperates. Returns `false` on any
/// unsupported scheme, key-type mismatch, or bad signature — never panics.
#[must_use]
pub fn verify_handshake_signature(key: &PeerKey, sig_scheme: u16, msg: &[u8], sig: &[u8]) -> bool {
    #[allow(clippy::cast_possible_truncation)] // scheme is two bytes by construction
    let hash_alg = (sig_scheme >> 8) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let sig_alg = sig_scheme as u8;
    let digest = match hash_alg {
        HASH_ALG_SHA256 => Sha256::digest(msg).to_vec(),
        HASH_ALG_SHA384 => Sha384::digest(msg).to_vec(),
        _ => return false,
    };
    match (sig_alg, key) {
        (SIG_ALG_ECDSA, PeerKey::Ecdsa(pk)) => match Signature::from_der(sig) {
            Ok(s) => pk.verify_prehash(&digest, &s).is_ok(),
            Err(_) => false,
        },
        (SIG_ALG_RSA, PeerKey::Rsa(pk)) => {
            let scheme = if hash_alg == HASH_ALG_SHA256 {
                Pkcs1v15Sign::new::<Sha256>()
            } else {
                Pkcs1v15Sign::new::<Sha384>()
            };
            pk.verify(scheme, &digest, sig).is_ok()
        }
        _ => false, // algorithm / key-type mismatch
    }
}

/// Extracts the leaf public key (ECDSA P-256 or RSA) from a DER certificate's
/// SubjectPublicKeyInfo.
///
/// # Errors
/// [`DtlsError::BadCertificate`] if the certificate or its public key is malformed
/// or of an unsupported type.
pub fn leaf_public_key(cert_der: &[u8]) -> Result<PeerKey, DtlsError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| DtlsError::BadCertificate)?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| DtlsError::BadCertificate)?;
    if let Ok(k) = VerifyingKey::from_public_key_der(&spki_der) {
        return Ok(PeerKey::Ecdsa(k));
    }
    if let Ok(k) = RsaPublicKey::from_public_key_der(&spki_der) {
        return Ok(PeerKey::Rsa(Box::new(k)));
    }
    Err(DtlsError::BadCertificate)
}

/// The SHA-256 fingerprint of a DER certificate.
#[must_use]
pub fn fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(cert_der);
    let mut o = [0u8; 32];
    o.copy_from_slice(&d);
    o
}

/// Verifies a peer certificate chain and returns its leaf public key. With
/// `insecure_skip`, any (supported) leaf is accepted; with a `pin`, only a leaf
/// whose SHA-256 fingerprint matches; otherwise verification fails.
///
/// # Errors
/// [`DtlsError::BadCertificate`] if the chain is empty, the leaf is malformed or an
/// unsupported key type, or no verification policy accepts it.
pub fn verify_peer(
    chain: &[Vec<u8>],
    insecure_skip: bool,
    pin: Option<[u8; 32]>,
) -> Result<PeerKey, DtlsError> {
    let leaf = chain.first().ok_or(DtlsError::BadCertificate)?;
    let key = leaf_public_key(leaf)?;
    if insecure_skip {
        return Ok(key);
    }
    if let Some(pin) = pin
        && fingerprint(leaf).ct_eq(&pin).unwrap_u8() == 1
    {
        return Ok(key);
    }
    Err(DtlsError::BadCertificate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_self_signed_cert_round_trips() {
        let id = Identity::generate("ristrust-test").unwrap();
        assert_eq!(id.auth_method(), AuthMethod::Ecdsa);
        let parsed = leaf_public_key(id.der()).unwrap();
        assert_eq!(parsed.auth_method(), AuthMethod::Ecdsa);
    }

    #[test]
    fn rsa_self_signed_cert_round_trips() {
        let id = Identity::generate_rsa("ristrust-rsa-test").unwrap();
        assert_eq!(id.auth_method(), AuthMethod::Rsa);
        assert!(id.rsa_private_key().is_some());
        let parsed = leaf_public_key(id.der()).unwrap();
        assert_eq!(parsed.auth_method(), AuthMethod::Rsa);
        assert!(parsed.rsa_public_key().is_some());
    }

    #[test]
    fn ecdsa_sign_verify_round_trips() {
        let id = Identity::generate("signer").unwrap();
        let key = leaf_public_key(id.der()).unwrap();
        let msg = b"server key exchange params";
        let (scheme, sig) = sign_handshake(&id, msg).unwrap();
        assert_eq!(scheme, SIG_SCHEME_ECDSA_P256_SHA256);
        assert!(verify_handshake_signature(&key, scheme, msg, &sig));
        assert!(
            !verify_handshake_signature(&key, scheme, b"tampered", &sig),
            "wrong message must not verify"
        );
    }

    #[test]
    fn rsa_sign_verify_round_trips() {
        let id = Identity::generate_rsa("rsa-signer").unwrap();
        let key = leaf_public_key(id.der()).unwrap();
        let msg = b"server key exchange params";
        let (scheme, sig) = sign_handshake(&id, msg).unwrap();
        assert_eq!(scheme, SIG_SCHEME_RSA_PKCS1_SHA256);
        assert!(verify_handshake_signature(&key, scheme, msg, &sig));
        assert!(!verify_handshake_signature(&key, scheme, b"tampered", &sig));
    }

    #[test]
    fn signature_rejects_key_type_mismatch() {
        let ecdsa = Identity::generate("e").unwrap();
        let rsa = Identity::generate_rsa("r").unwrap();
        let ecdsa_key = leaf_public_key(ecdsa.der()).unwrap();
        let msg = b"params";
        // An RSA signature presented under an ECDSA key (or vice versa) must fail.
        let (rsa_scheme, rsa_sig) = sign_handshake(&rsa, msg).unwrap();
        assert!(!verify_handshake_signature(
            &ecdsa_key, rsa_scheme, msg, &rsa_sig
        ));
    }

    #[test]
    fn verify_peer_policies() {
        let id = Identity::generate("peer").unwrap();
        let chain = vec![id.der().to_vec()];
        assert!(verify_peer(&chain, true, None).is_ok());
        let fp = fingerprint(id.der());
        assert!(verify_peer(&chain, false, Some(fp)).is_ok());
        assert!(verify_peer(&chain, false, Some([0u8; 32])).is_err());
        assert!(verify_peer(&chain, false, None).is_err());
    }
}
