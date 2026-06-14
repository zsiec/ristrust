//! DTLS 1.2 cipher-suite and extension wire constants (ristgo `suites.go`).

/// `TLS_PSK_WITH_AES_128_GCM_SHA256` (RFC 5487): pre-shared key, AES-128-GCM.
pub const TLS_PSK_WITH_AES_128_GCM_SHA256: u16 = 0x00A8;
/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289): ephemeral P-256 ECDH with
/// an ECDSA P-256 certificate, AES-128-GCM.
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;

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
/// Signature scheme `ecdsa_secp256r1_sha256`.
pub const SIG_SCHEME_ECDSA_P256_SHA256: u16 = 0x0403;
/// Compression method: null (none).
pub const COMPRESSION_NULL: u8 = 0;
/// The length of a ClientHello/ServerHello `random`.
pub const RANDOM_LEN: usize = 32;
