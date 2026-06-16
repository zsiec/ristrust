//! DTLS 1.2 cipher-suite and extension wire constants (ristgo `suites.go`).

/// `TLS_PSK_WITH_AES_128_GCM_SHA256` (RFC 5487): pre-shared key, AES-128-GCM.
pub const TLS_PSK_WITH_AES_128_GCM_SHA256: u16 = 0x00A8;
/// `TLS_RSA_WITH_NULL_SHA256` (RFC 5246): RSA key transport, NULL cipher with an
/// HMAC-SHA256 — integrity only, NO confidentiality (off by default).
pub const TLS_RSA_WITH_NULL_SHA256: u16 = 0x003B;
/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289): ephemeral P-256 ECDH with
/// an ECDSA P-256 certificate, AES-128-GCM, SHA-256 PRF.
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (RFC 5289): ephemeral P-256 ECDH with
/// an ECDSA P-256 certificate, AES-256-GCM, SHA-384 PRF.
pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;
/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (RFC 5289): ephemeral P-256 ECDH with an
/// RSA certificate, AES-128-GCM, SHA-256 PRF.
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;
/// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (RFC 5289): ephemeral P-256 ECDH with an
/// RSA certificate, AES-256-GCM, SHA-384 PRF.
pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xC030;

/// `supported_groups` extension (RFC 8422).
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
/// `ec_point_formats` extension.
pub const EXT_EC_POINT_FORMATS: u16 = 11;
/// `signature_algorithms` extension.
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
/// `extended_master_secret` extension (RFC 7627).
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// `renegotiation_info` extension (RFC 5746).
pub const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;

/// Named group `secp256r1` (P-256).
pub const NAMED_GROUP_SECP256R1: u16 = 23;
/// EC point format: uncompressed (`0x04 || X || Y`).
pub const EC_POINT_UNCOMPRESSED: u8 = 0;
/// Signature scheme `ecdsa_secp256r1_sha256` (`{sha256(4), ecdsa(3)}`).
pub const SIG_SCHEME_ECDSA_P256_SHA256: u16 = 0x0403;
/// Signature scheme `ecdsa_secp256r1_sha384` (`{sha384(5), ecdsa(3)}`).
pub const SIG_SCHEME_ECDSA_P256_SHA384: u16 = 0x0503;
/// Signature scheme `rsa_pkcs1_sha256` (`{sha256(4), rsa(1)}`).
pub const SIG_SCHEME_RSA_PKCS1_SHA256: u16 = 0x0401;
/// Signature scheme `rsa_pkcs1_sha384` (`{sha384(5), rsa(1)}`).
pub const SIG_SCHEME_RSA_PKCS1_SHA384: u16 = 0x0501;

/// `SignatureAndHashAlgorithm` hash id for SHA-256 (RFC 5246 §7.4.1.4.1).
pub const HASH_ALG_SHA256: u8 = 4;
/// `SignatureAndHashAlgorithm` hash id for SHA-384.
pub const HASH_ALG_SHA384: u8 = 5;
/// `SignatureAndHashAlgorithm` signature id for RSA (PKCS#1 v1.5).
pub const SIG_ALG_RSA: u8 = 1;
/// `SignatureAndHashAlgorithm` signature id for ECDSA.
pub const SIG_ALG_ECDSA: u8 = 3;

/// The `signature_algorithms` extension this side offers (RFC 5246 §7.4.1.4.1):
/// ECDSA and RSA (PKCS#1 v1.5) over both SHA-256 and SHA-384, so a peer may
/// authenticate with an ECDSA-P256 or RSA certificate and sign under either
/// suite's hash.
pub const OFFERED_SIGNATURE_ALGORITHMS: [u16; 4] = [
    SIG_SCHEME_ECDSA_P256_SHA256,
    SIG_SCHEME_ECDSA_P256_SHA384,
    SIG_SCHEME_RSA_PKCS1_SHA256,
    SIG_SCHEME_RSA_PKCS1_SHA384,
];

/// Compression method: null (none).
pub const COMPRESSION_NULL: u8 = 0;
/// The length of a ClientHello/ServerHello `random`.
pub const RANDOM_LEN: usize = 32;
