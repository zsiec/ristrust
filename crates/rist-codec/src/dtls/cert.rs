//! Self-signed ECDSA P-256 certificate generation, parsing, and verification for
//! the ECDHE_ECDSA suite (ristgo `cert.go`).
//!
//! The server presents a self-signed leaf certificate; the client extracts its
//! P-256 public key from the SubjectPublicKeyInfo and verifies the
//! ServerKeyExchange signature with it. Verification policy is either
//! `insecure_skip` (accept any leaf) or a SHA-256 fingerprint pin — there is no
//! built-in trust store.

use core::time::Duration;
use std::str::FromStr;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};
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

/// A self-signed ECDSA P-256 identity: its DER leaf certificate and signing key.
#[derive(Debug, Clone)]
pub struct Identity {
    der: Vec<u8>,
    signing_key: SigningKey,
}

impl Identity {
    /// Generates a fresh self-signed ECDSA P-256 certificate for `common_name`,
    /// valid for one year.
    ///
    /// # Errors
    /// [`DtlsError::BadCertificate`] if certificate construction or signing fails.
    pub fn generate(common_name: &str) -> Result<Identity, DtlsError> {
        let signing_key = SigningKey::random(&mut OsCsprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let spki_der = verifying_key
            .to_public_key_der()
            .map_err(|_| DtlsError::BadCertificate)?;
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())
            .map_err(|_| DtlsError::BadCertificate)?;
        let serial = SerialNumber::from(1u32);
        let validity = Validity::from_now(Duration::from_secs(365 * 24 * 3600))
            .map_err(|_| DtlsError::BadCertificate)?;
        let subject =
            Name::from_str(&format!("CN={common_name}")).map_err(|_| DtlsError::BadCertificate)?;
        let builder =
            CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signing_key)
                .map_err(|_| DtlsError::BadCertificate)?;
        let cert = builder
            .build::<DerSignature>()
            .map_err(|_| DtlsError::BadCertificate)?;
        let der = cert.to_der().map_err(|_| DtlsError::BadCertificate)?;
        Ok(Identity { der, signing_key })
    }

    /// The DER-encoded leaf certificate.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The ECDSA signing key.
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// Signs `msg` with ECDSA-P256-SHA256, returning the ASN.1 DER signature.
#[must_use]
pub fn sign(key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(msg);
    sig.to_der().as_bytes().to_vec()
}

/// Verifies an ASN.1 DER ECDSA-P256-SHA256 signature over `msg`.
#[must_use]
pub fn verify(key: &VerifyingKey, msg: &[u8], sig_der: &[u8]) -> bool {
    match Signature::from_der(sig_der) {
        Ok(sig) => key.verify(msg, &sig).is_ok(),
        Err(_) => false,
    }
}

/// Extracts the P-256 public key from a DER leaf certificate's SubjectPublicKeyInfo.
///
/// # Errors
/// [`DtlsError::BadCertificate`] if the certificate or its public key is malformed
/// or not P-256.
pub fn leaf_public_key(cert_der: &[u8]) -> Result<VerifyingKey, DtlsError> {
    let cert = Certificate::from_der(cert_der).map_err(|_| DtlsError::BadCertificate)?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| DtlsError::BadCertificate)?;
    VerifyingKey::from_public_key_der(&spki_der).map_err(|_| DtlsError::BadCertificate)
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
/// `insecure_skip`, any leaf is accepted; with a `pin`, only a leaf whose SHA-256
/// fingerprint matches; otherwise verification fails.
///
/// # Errors
/// [`DtlsError::BadCertificate`] if the chain is empty, the leaf is malformed, or
/// no verification policy accepts it.
pub fn verify_peer(
    chain: &[Vec<u8>],
    insecure_skip: bool,
    pin: Option<[u8; 32]>,
) -> Result<VerifyingKey, DtlsError> {
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
    fn self_signed_cert_round_trips() {
        let id = Identity::generate("ristrust-test").unwrap();
        // The leaf public key parses out, and equals the signing key's public key.
        let parsed = leaf_public_key(id.der()).unwrap();
        assert_eq!(parsed, VerifyingKey::from(id.signing_key()));
    }

    #[test]
    fn sign_verify_round_trips() {
        let id = Identity::generate("signer").unwrap();
        let key = leaf_public_key(id.der()).unwrap();
        let msg = b"server key exchange params";
        let sig = sign(id.signing_key(), msg);
        assert!(verify(&key, msg, &sig));
        assert!(
            !verify(&key, b"tampered", &sig),
            "wrong message must not verify"
        );
    }

    #[test]
    fn verify_peer_policies() {
        let id = Identity::generate("peer").unwrap();
        let chain = vec![id.der().to_vec()];
        // insecure_skip accepts any leaf.
        assert!(verify_peer(&chain, true, None).is_ok());
        // A matching pin accepts; a wrong pin rejects.
        let fp = fingerprint(id.der());
        assert!(verify_peer(&chain, false, Some(fp)).is_ok());
        assert!(verify_peer(&chain, false, Some([0u8; 32])).is_err());
        // No policy rejects.
        assert!(verify_peer(&chain, false, None).is_err());
    }
}
