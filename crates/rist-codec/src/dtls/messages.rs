//! DTLS 1.2 handshake message types and their TLS-vector wire encoding (RFC 5246
//! §7.4 + RFC 6347, ristgo `messages.go`). Each message exposes `marshal_body`
//! (the body *without* the 12-byte handshake fragment header, which
//! [`super::handshake`] adds) and a `parse` over a body slice.

use super::DtlsError;
use super::suites::{
    COMPRESSION_NULL, EXT_EC_POINT_FORMATS, EXT_EXTENDED_MASTER_SECRET, EXT_RENEGOTIATION_INFO,
    EXT_SIGNATURE_ALGORITHMS, EXT_SUPPORTED_GROUPS, RANDOM_LEN,
};
use super::vec::{Reader, Writer};

/// A DTLS handshake message type (RFC 5246 §7.4 + RFC 6347 §4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// `hello_request` (0).
    HelloRequest = 0,
    /// `client_hello` (1).
    ClientHello = 1,
    /// `server_hello` (2).
    ServerHello = 2,
    /// `hello_verify_request` (3, DTLS-specific).
    HelloVerifyRequest = 3,
    /// `certificate` (11).
    Certificate = 11,
    /// `server_key_exchange` (12).
    ServerKeyExchange = 12,
    /// `certificate_request` (13).
    CertificateRequest = 13,
    /// `server_hello_done` (14).
    ServerHelloDone = 14,
    /// `certificate_verify` (15).
    CertificateVerify = 15,
    /// `client_key_exchange` (16).
    ClientKeyExchange = 16,
    /// `finished` (20).
    Finished = 20,
}

impl HandshakeType {
    /// The wire byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a handshake-type byte.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<HandshakeType> {
        Some(match b {
            0 => HandshakeType::HelloRequest,
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            3 => HandshakeType::HelloVerifyRequest,
            11 => HandshakeType::Certificate,
            12 => HandshakeType::ServerKeyExchange,
            13 => HandshakeType::CertificateRequest,
            14 => HandshakeType::ServerHelloDone,
            15 => HandshakeType::CertificateVerify,
            16 => HandshakeType::ClientKeyExchange,
            20 => HandshakeType::Finished,
            _ => return None,
        })
    }
}

/// A ClientHello (RFC 5246 §7.4.1.2 with the DTLS cookie and the extensions this
/// implementation negotiates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// The offered protocol version.
    pub version: [u8; 2],
    /// The 32-byte client random.
    pub random: [u8; RANDOM_LEN],
    /// The session ID (usually empty).
    pub session_id: Vec<u8>,
    /// The HelloVerifyRequest cookie (empty in the first flight).
    pub cookie: Vec<u8>,
    /// The offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Whether the `extended_master_secret` extension is offered.
    pub ext_master_secret: bool,
    /// The offered `supported_groups` (empty ⇒ extension omitted).
    pub supported_groups: Vec<u16>,
    /// The offered `ec_point_formats`.
    pub point_formats: Vec<u8>,
    /// Whether the `ec_point_formats` extension is present.
    pub point_formats_offered: bool,
    /// The offered `signature_algorithms` (empty ⇒ extension omitted).
    pub signature_algorithms: Vec<u16>,
    /// Whether the empty `renegotiation_info` extension is offered (RFC 5746).
    pub secure_renegotiation: bool,
}

impl ClientHello {
    /// Encodes the ClientHello body.
    #[must_use]
    pub fn marshal_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.version);
        w.bytes(&self.random);
        w.u8_vec(|w| w.bytes(&self.session_id));
        w.u8_vec(|w| w.bytes(&self.cookie));
        w.u16_vec(|w| {
            for cs in &self.cipher_suites {
                w.u16(*cs);
            }
        });
        w.u8_vec(|w| w.u8(COMPRESSION_NULL));
        w.u16_vec(|w| self.marshal_extensions(w));
        w.into_bytes()
    }

    /// Encodes the extension block.
    fn marshal_extensions(&self, w: &mut Writer) {
        if self.ext_master_secret {
            w.u16(EXT_EXTENDED_MASTER_SECRET);
            w.u16_vec(|_| {});
        }
        if !self.supported_groups.is_empty() {
            w.u16(EXT_SUPPORTED_GROUPS);
            w.u16_vec(|w| {
                w.u16_vec(|w| {
                    for g in &self.supported_groups {
                        w.u16(*g);
                    }
                });
            });
        }
        if self.point_formats_offered {
            w.u16(EXT_EC_POINT_FORMATS);
            w.u16_vec(|w| {
                w.u8_vec(|w| {
                    for f in &self.point_formats {
                        w.u8(*f);
                    }
                });
            });
        }
        if !self.signature_algorithms.is_empty() {
            w.u16(EXT_SIGNATURE_ALGORITHMS);
            w.u16_vec(|w| {
                w.u16_vec(|w| {
                    for s in &self.signature_algorithms {
                        w.u16(*s);
                    }
                });
            });
        }
        if self.secure_renegotiation {
            w.u16(EXT_RENEGOTIATION_INFO);
            w.u16_vec(|w| w.u8_vec(|_| {}));
        }
    }

    /// Decodes a ClientHello body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation or a bad random length.
    pub fn parse(body: &[u8]) -> Result<ClientHello, DtlsError> {
        let mut r = Reader::new(body);
        let version = [r.u8()?, r.u8()?];
        let random: [u8; RANDOM_LEN] = r
            .bytes(RANDOM_LEN)?
            .try_into()
            .map_err(|_| DtlsError::Malformed("client random"))?;
        let session_id = r.u8_vec()?.to_vec();
        let cookie = r.u8_vec()?.to_vec();
        let cipher_suites = parse_u16_list(r.u16_vec()?)?;
        let _compression = r.u8_vec()?;

        let mut ch = ClientHello {
            version,
            random,
            session_id,
            cookie,
            cipher_suites,
            ext_master_secret: false,
            supported_groups: Vec::new(),
            point_formats: Vec::new(),
            point_formats_offered: false,
            signature_algorithms: Vec::new(),
            secure_renegotiation: false,
        };
        // Extensions are optional in DTLS (and absent in some HelloVerifyRequest
        // flows), so a missing extension block is not an error.
        if !r.is_empty() {
            let exts = r.u16_vec()?;
            ch.parse_extensions(exts)?;
        }
        Ok(ch)
    }

    /// Parses the extension block into the relevant fields.
    fn parse_extensions(&mut self, exts: &[u8]) -> Result<(), DtlsError> {
        let mut er = Reader::new(exts);
        while !er.is_empty() {
            let typ = er.u16()?;
            let data = er.u16_vec()?;
            match typ {
                EXT_EXTENDED_MASTER_SECRET => self.ext_master_secret = true,
                EXT_SUPPORTED_GROUPS => {
                    self.supported_groups = parse_u16_list(Reader::new(data).u16_vec()?)?;
                }
                EXT_EC_POINT_FORMATS => {
                    self.point_formats_offered = true;
                    self.point_formats = Reader::new(data).u8_vec()?.to_vec();
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    self.signature_algorithms = parse_u16_list(Reader::new(data).u16_vec()?)?;
                }
                EXT_RENEGOTIATION_INFO => self.secure_renegotiation = true,
                _ => {} // ignore unknown extensions
            }
        }
        Ok(())
    }
}

/// A HelloVerifyRequest (RFC 6347 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    /// The server's version (DTLS 1.0 per the spec).
    pub version: [u8; 2],
    /// The stateless cookie.
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Encodes the body.
    #[must_use]
    pub fn marshal_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.version);
        w.u8_vec(|w| w.bytes(&self.cookie));
        w.into_bytes()
    }

    /// Decodes the body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn parse(body: &[u8]) -> Result<HelloVerifyRequest, DtlsError> {
        let mut r = Reader::new(body);
        let version = [r.u8()?, r.u8()?];
        let cookie = r.u8_vec()?.to_vec();
        Ok(HelloVerifyRequest { version, cookie })
    }
}

/// A ServerHello (RFC 5246 §7.4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// The selected protocol version.
    pub version: [u8; 2],
    /// The 32-byte server random.
    pub random: [u8; RANDOM_LEN],
    /// The session ID.
    pub session_id: Vec<u8>,
    /// The selected cipher suite.
    pub cipher_suite: u16,
    /// Whether `extended_master_secret` is confirmed.
    pub ext_master_secret: bool,
    /// Whether `ec_point_formats` is echoed.
    pub point_formats: bool,
    /// Whether `renegotiation_info` is echoed.
    pub secure_renegotiation: bool,
}

impl ServerHello {
    /// Encodes the body.
    #[must_use]
    pub fn marshal_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.version);
        w.bytes(&self.random);
        w.u8_vec(|w| w.bytes(&self.session_id));
        w.u16(self.cipher_suite);
        w.u8(COMPRESSION_NULL);
        w.u16_vec(|w| {
            if self.ext_master_secret {
                w.u16(EXT_EXTENDED_MASTER_SECRET);
                w.u16_vec(|_| {});
            }
            if self.point_formats {
                w.u16(EXT_EC_POINT_FORMATS);
                w.u16_vec(|w| w.u8_vec(|w| w.u8(0)));
            }
            if self.secure_renegotiation {
                w.u16(EXT_RENEGOTIATION_INFO);
                w.u16_vec(|w| w.u8_vec(|_| {}));
            }
        });
        w.into_bytes()
    }

    /// Decodes the body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation or a bad random length.
    pub fn parse(body: &[u8]) -> Result<ServerHello, DtlsError> {
        let mut r = Reader::new(body);
        let version = [r.u8()?, r.u8()?];
        let random: [u8; RANDOM_LEN] = r
            .bytes(RANDOM_LEN)?
            .try_into()
            .map_err(|_| DtlsError::Malformed("server random"))?;
        let session_id = r.u8_vec()?.to_vec();
        let cipher_suite = r.u16()?;
        let _compression = r.u8()?;
        let mut sh = ServerHello {
            version,
            random,
            session_id,
            cipher_suite,
            ext_master_secret: false,
            point_formats: false,
            secure_renegotiation: false,
        };
        if !r.is_empty() {
            let exts = r.u16_vec()?;
            let mut er = Reader::new(exts);
            while !er.is_empty() {
                let typ = er.u16()?;
                let _data = er.u16_vec()?;
                match typ {
                    EXT_EXTENDED_MASTER_SECRET => sh.ext_master_secret = true,
                    EXT_EC_POINT_FORMATS => sh.point_formats = true,
                    EXT_RENEGOTIATION_INFO => sh.secure_renegotiation = true,
                    _ => {}
                }
            }
        }
        Ok(sh)
    }
}

/// A Certificate message: a chain of DER certificates, leaf first (RFC 5246
/// §7.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMsg {
    /// The DER-encoded certificate chain (leaf first).
    pub chain: Vec<Vec<u8>>,
}

impl CertificateMsg {
    /// Encodes the body.
    #[must_use]
    pub fn marshal_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u24_vec(|w| {
            for cert in &self.chain {
                w.u24_vec(|w| w.bytes(cert));
            }
        });
        w.into_bytes()
    }

    /// Decodes the body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn parse(body: &[u8]) -> Result<CertificateMsg, DtlsError> {
        let mut r = Reader::new(body);
        let list = r.u24_vec()?;
        let mut lr = Reader::new(list);
        let mut chain = Vec::new();
        while !lr.is_empty() {
            chain.push(lr.u24_vec()?.to_vec());
        }
        Ok(CertificateMsg { chain })
    }
}

/// A ServerKeyExchange for the ECDHE_ECDSA suite (RFC 4492 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKeyExchange {
    /// The named curve (23 = secp256r1).
    pub curve: u16,
    /// The server's ephemeral public point (uncompressed, `0x04 || X || Y`).
    pub public_key: Vec<u8>,
    /// The signature scheme (0x0403 = ecdsa_secp256r1_sha256).
    pub sig_scheme: u16,
    /// The ECDSA signature (ASN.1 DER) over the signed params.
    pub signature: Vec<u8>,
}

impl ServerKeyExchange {
    /// The bytes that are signed: `curve_type(1=named) || named_curve(2) ||
    /// point(u8-length-prefixed)`.
    #[must_use]
    pub fn signed_params(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(3); // curve_type = named_curve
        w.u16(self.curve);
        w.u8_vec(|w| w.bytes(&self.public_key));
        w.into_bytes()
    }

    /// Encodes the body.
    #[must_use]
    pub fn marshal_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.signed_params());
        w.u16(self.sig_scheme);
        w.u16_vec(|w| w.bytes(&self.signature));
        w.into_bytes()
    }

    /// Decodes the body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation or a non-named-curve type.
    pub fn parse(body: &[u8]) -> Result<ServerKeyExchange, DtlsError> {
        let mut r = Reader::new(body);
        if r.u8()? != 3 {
            return Err(DtlsError::Malformed("ske curve type"));
        }
        let curve = r.u16()?;
        let public_key = r.u8_vec()?.to_vec();
        let sig_scheme = r.u16()?;
        let signature = r.u16_vec()?.to_vec();
        Ok(ServerKeyExchange {
            curve,
            public_key,
            sig_scheme,
            signature,
        })
    }
}

/// A CertificateVerify (RFC 5246 §7.4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    /// The signature scheme.
    pub sig_scheme: u16,
    /// The signature (ASN.1 DER) over the handshake transcript.
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Encodes the body.
    #[must_use]
    pub fn marshal_body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.sig_scheme);
        w.u16_vec(|w| w.bytes(&self.signature));
        w.into_bytes()
    }

    /// Decodes the body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn parse(body: &[u8]) -> Result<CertificateVerify, DtlsError> {
        let mut r = Reader::new(body);
        let sig_scheme = r.u16()?;
        let signature = r.u16_vec()?.to_vec();
        Ok(CertificateVerify {
            sig_scheme,
            signature,
        })
    }
}

/// Encodes a PSK ClientKeyExchange body: a `u16`-length-prefixed identity (RFC
/// 4279 §2).
#[must_use]
pub fn client_key_exchange_psk(identity: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16_vec(|w| w.bytes(identity));
    w.into_bytes()
}

/// Decodes a PSK ClientKeyExchange identity.
///
/// # Errors
/// [`DtlsError::Malformed`] on truncation.
pub fn parse_client_key_exchange_psk(body: &[u8]) -> Result<Vec<u8>, DtlsError> {
    Ok(Reader::new(body).u16_vec()?.to_vec())
}

/// Encodes an ECDHE ClientKeyExchange body: a `u8`-length-prefixed point (RFC 4492
/// §5.7).
#[must_use]
pub fn client_key_exchange_ecdhe(public_key: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8_vec(|w| w.bytes(public_key));
    w.into_bytes()
}

/// Decodes an ECDHE ClientKeyExchange point.
///
/// # Errors
/// [`DtlsError::Malformed`] on truncation.
pub fn parse_client_key_exchange_ecdhe(body: &[u8]) -> Result<Vec<u8>, DtlsError> {
    Ok(Reader::new(body).u8_vec()?.to_vec())
}

/// Encodes an RSA-key-transport ClientKeyExchange body: a `u16`-length-prefixed
/// `EncryptedPreMasterSecret` (RFC 5246 §7.4.7.1, TLS 1.2's explicit length).
#[must_use]
pub fn client_key_exchange_rsa(encrypted_premaster: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16_vec(|w| w.bytes(encrypted_premaster));
    w.into_bytes()
}

/// Decodes an RSA-key-transport ClientKeyExchange's `EncryptedPreMasterSecret`.
///
/// # Errors
/// [`DtlsError::Malformed`] on truncation.
pub fn parse_client_key_exchange_rsa(body: &[u8]) -> Result<Vec<u8>, DtlsError> {
    Ok(Reader::new(body).u16_vec()?.to_vec())
}

/// The fixed CertificateRequest body this implementation sends: `certificate_types
/// = [ecdsa_sign(64)]`, `supported_signature_algorithms = [ecdsa_secp256r1_sha256]`,
/// no certificate authorities (RFC 5246 §7.4.4).
#[must_use]
pub fn certificate_request_body() -> Vec<u8> {
    let mut w = Writer::new();
    w.u8_vec(|w| w.u8(64)); // certificate_types = [ecdsa_sign]
    w.u16_vec(|w| w.u16(super::suites::SIG_SCHEME_ECDSA_P256_SHA256));
    w.u16_vec(|_| {}); // certificate_authorities = empty
    w.into_bytes()
}

/// Parses a `u16`-length list as `u16`s.
fn parse_u16_list(b: &[u8]) -> Result<Vec<u16>, DtlsError> {
    let mut r = Reader::new(b);
    let mut out = Vec::with_capacity(b.len() / 2);
    while !r.is_empty() {
        out.push(r.u16()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::record::VERSION_DTLS_1_2;
    use super::super::suites::{
        NAMED_GROUP_SECP256R1, SIG_SCHEME_ECDSA_P256_SHA256, TLS_PSK_WITH_AES_128_GCM_SHA256,
    };
    use super::*;

    #[test]
    fn handshake_type_round_trips() {
        for t in [
            HandshakeType::ClientHello,
            HandshakeType::ServerHello,
            HandshakeType::HelloVerifyRequest,
            HandshakeType::Finished,
        ] {
            assert_eq!(HandshakeType::from_u8(t.as_u8()), Some(t));
        }
        assert_eq!(HandshakeType::from_u8(200), None);
    }

    #[test]
    fn client_hello_round_trips() {
        let ch = ClientHello {
            version: VERSION_DTLS_1_2,
            random: [7u8; 32],
            session_id: Vec::new(),
            cookie: vec![1, 2, 3, 4],
            cipher_suites: vec![TLS_PSK_WITH_AES_128_GCM_SHA256, 0xC02B],
            ext_master_secret: true,
            supported_groups: vec![NAMED_GROUP_SECP256R1],
            point_formats: vec![0],
            point_formats_offered: true,
            signature_algorithms: vec![SIG_SCHEME_ECDSA_P256_SHA256],
            secure_renegotiation: true,
        };
        assert_eq!(ClientHello::parse(&ch.marshal_body()).unwrap(), ch);
    }

    #[test]
    fn client_hello_psk_only_omits_ec_extensions() {
        let ch = ClientHello {
            version: VERSION_DTLS_1_2,
            random: [0u8; 32],
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: vec![TLS_PSK_WITH_AES_128_GCM_SHA256],
            ext_master_secret: true,
            supported_groups: Vec::new(),
            point_formats: Vec::new(),
            point_formats_offered: false,
            signature_algorithms: Vec::new(),
            secure_renegotiation: true,
        };
        let back = ClientHello::parse(&ch.marshal_body()).unwrap();
        assert!(back.supported_groups.is_empty());
        assert!(!back.point_formats_offered);
        assert_eq!(back, ch);
    }

    #[test]
    fn server_hello_round_trips() {
        let sh = ServerHello {
            version: VERSION_DTLS_1_2,
            random: [9u8; 32],
            session_id: vec![1, 2],
            cipher_suite: TLS_PSK_WITH_AES_128_GCM_SHA256,
            ext_master_secret: true,
            point_formats: false,
            secure_renegotiation: true,
        };
        assert_eq!(ServerHello::parse(&sh.marshal_body()).unwrap(), sh);
    }

    #[test]
    fn hello_verify_request_round_trips() {
        let hvr = HelloVerifyRequest {
            version: super::super::record::VERSION_DTLS_1_0,
            cookie: vec![0xAB; 20],
        };
        assert_eq!(HelloVerifyRequest::parse(&hvr.marshal_body()).unwrap(), hvr);
    }

    #[test]
    fn certificate_chain_round_trips() {
        let c = CertificateMsg {
            chain: vec![vec![1, 2, 3], vec![4, 5, 6, 7]],
        };
        assert_eq!(CertificateMsg::parse(&c.marshal_body()).unwrap(), c);
    }

    #[test]
    fn server_key_exchange_round_trips() {
        let ske = ServerKeyExchange {
            curve: NAMED_GROUP_SECP256R1,
            public_key: vec![0x04; 65],
            sig_scheme: SIG_SCHEME_ECDSA_P256_SHA256,
            signature: vec![0xDE; 70],
        };
        let back = ServerKeyExchange::parse(&ske.marshal_body()).unwrap();
        assert_eq!(back, ske);
        // signed_params is a prefix-independent view used for the signature.
        assert_eq!(back.signed_params(), ske.signed_params());
    }

    #[test]
    fn client_key_exchange_helpers_round_trip() {
        let psk = client_key_exchange_psk(b"identity");
        assert_eq!(parse_client_key_exchange_psk(&psk).unwrap(), b"identity");
        let ecdhe = client_key_exchange_ecdhe(&[0x04; 65]);
        assert_eq!(
            parse_client_key_exchange_ecdhe(&ecdhe).unwrap(),
            vec![0x04; 65]
        );
    }
}
