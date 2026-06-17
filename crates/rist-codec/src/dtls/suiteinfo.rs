//! The cipher-suite descriptor table (ristgo `suiteinfo.go`): the data the
//! handshake drivers consult instead of branching on the raw suite id, so adding a
//! suite is a table row plus the key-exchange / record-protection code its `(kx,
//! aead)` pair needs — not a new branch in every transcript / PRF / Finished
//! consumer.
//!
//! The supported set is exactly TR-06-2 §6.2's mandatory five plus the PSK suite
//! RIST itself uses:
//!
//! - `0xC02C` `ECDHE_ECDSA_AES_256_GCM_SHA384` (RFC 5289)
//! - `0xC030` `ECDHE_RSA_AES_256_GCM_SHA384` (RFC 5289)
//! - `0xC02B` `ECDHE_ECDSA_AES_128_GCM_SHA256` (RFC 5289)
//! - `0xC02F` `ECDHE_RSA_AES_128_GCM_SHA256` (RFC 5289)
//! - `0x00A8` `PSK_WITH_AES_128_GCM_SHA256` (RFC 5487)
//! - `0x003B` `RSA_WITH_NULL_SHA256` (RFC 5246) — integrity only, no confidentiality

use super::prf::PrfHash;
use super::suites::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_PSK_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_NULL_SHA256,
};

/// A key-exchange method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyExchange {
    /// Ephemeral ECDH on P-256 (forward secret).
    Ecdhe,
    /// RSA key transport (the client encrypts the pre-master under the server's key).
    Rsa,
    /// Pre-shared key.
    Psk,
}

/// How the server (and optionally the client) authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    /// PSK: the shared key is the authenticator (no certificate).
    None,
    /// ECDSA P-256 certificate.
    Ecdsa,
    /// RSA certificate.
    Rsa,
}

/// One cipher suite's parameters: its key-exchange and authentication methods, the
/// bulk-cipher key length, the PRF/transcript hash, and (for the NULL suite) the
/// MAC length.
#[derive(Debug, Clone, Copy)]
pub struct SuiteInfo {
    /// The IANA cipher-suite id.
    pub id: u16,
    /// The key-exchange method.
    pub kx: KeyExchange,
    /// The authentication method.
    pub auth: AuthMethod,
    /// The bulk-cipher key length: 16 (AES-128), 32 (AES-256), or 0 (NULL).
    pub key_len: usize,
    /// The HMAC output/key length for a MAC-only (NULL) suite (32 for SHA-256); 0
    /// for an AEAD suite, which carries no separate MAC key.
    pub mac_len: usize,
    /// Whether record protection is AES-GCM (`true`) or NULL-cipher-with-HMAC
    /// (`false`). With NULL, records are authenticated by an appended HMAC but not
    /// encrypted.
    pub aead: bool,
    /// The suite's hash, for the PRF (`P_hash`), the transcript hash, the Finished
    /// `verify_data`, and extended master secret.
    pub hash: PrfHash,
}

/// The supported cipher suites in server-preference order (strongest / forward
/// secret first; the NULL integrity-only suite last). Suite selection and the
/// client's offered list both derive from this table, filtered by what the config
/// can do and what the user has not disabled.
pub const SUITE_TABLE: [SuiteInfo; 6] = [
    SuiteInfo {
        id: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        kx: KeyExchange::Ecdhe,
        auth: AuthMethod::Ecdsa,
        key_len: 32,
        mac_len: 0,
        aead: true,
        hash: PrfHash::Sha384,
    },
    SuiteInfo {
        id: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        kx: KeyExchange::Ecdhe,
        auth: AuthMethod::Rsa,
        key_len: 32,
        mac_len: 0,
        aead: true,
        hash: PrfHash::Sha384,
    },
    SuiteInfo {
        id: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        kx: KeyExchange::Ecdhe,
        auth: AuthMethod::Ecdsa,
        key_len: 16,
        mac_len: 0,
        aead: true,
        hash: PrfHash::Sha256,
    },
    SuiteInfo {
        id: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        kx: KeyExchange::Ecdhe,
        auth: AuthMethod::Rsa,
        key_len: 16,
        mac_len: 0,
        aead: true,
        hash: PrfHash::Sha256,
    },
    SuiteInfo {
        id: TLS_PSK_WITH_AES_128_GCM_SHA256,
        kx: KeyExchange::Psk,
        auth: AuthMethod::None,
        key_len: 16,
        mac_len: 0,
        aead: true,
        hash: PrfHash::Sha256,
    },
    SuiteInfo {
        id: TLS_RSA_WITH_NULL_SHA256,
        kx: KeyExchange::Rsa,
        auth: AuthMethod::Rsa,
        key_len: 0,
        mac_len: 32,
        aead: false,
        hash: PrfHash::Sha256,
    },
];

/// Returns the descriptor for a suite id, or `None` if unsupported.
#[must_use]
pub fn lookup_suite(id: u16) -> Option<SuiteInfo> {
    SUITE_TABLE.iter().copied().find(|s| s.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_finds_every_table_entry_and_rejects_unknown() {
        for s in SUITE_TABLE {
            assert_eq!(lookup_suite(s.id).map(|d| d.id), Some(s.id));
        }
        assert!(lookup_suite(0x0000).is_none());
    }

    #[test]
    fn null_suite_is_last_and_integrity_only() {
        let last = SUITE_TABLE[SUITE_TABLE.len() - 1];
        assert_eq!(last.id, TLS_RSA_WITH_NULL_SHA256);
        assert!(!last.aead, "the NULL suite must not be an AEAD");
        assert_eq!(last.key_len, 0, "the NULL suite encrypts nothing");
        assert_eq!(last.mac_len, 32, "the NULL suite is HMAC-SHA256 protected");
    }

    #[test]
    fn sha384_suites_use_aes256() {
        for s in SUITE_TABLE {
            if matches!(s.hash, PrfHash::Sha384) {
                assert_eq!(s.key_len, 32, "*_SHA384 suites are AES-256-GCM");
            }
        }
    }
}
