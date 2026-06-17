//! RIST Main-profile EAP-SRP-SHA256 authentication framing and state machine,
//! byte-exact with libRIST v0.2.18-rc1. Ported from ristgo `internal/eap`.
//!
//! EAP frames ride inside a GRE EAPOL frame (protocol type 0x888E,
//! [`crate::gre::PROTO_EAPOL`]); the SRP-6a math is delegated to [`crate::srp`].
//! This module owns only the EAP-over-EAPOL framing and the
//! authenticatee/authenticator handshake sequencing.
//!
//! # Wire framing
//!
//! Three nested headers precede every EAP-SRP body:
//!
//! ```text
//! EAPOL header (4 bytes):  eapversion(1) eaptype(1) length(2 BE)
//! EAP header   (4 bytes):  code(1) identifier(1) length(2 BE)
//! EAP-SRP hdr  (2 bytes):  type(1)=19 subtype(1)
//! ```
//!
//! The IDENTITY messages do not carry the SRP subtype header: their EAP body is a
//! single type byte EAP_TYPE_IDENTITY (1) optionally followed by the username.
//!
//! # State machine
//!
//! ```text
//! Authenticatee (client): UNAUTH
//!   --(recv IDENTITY REQUEST)-->  send IDENTITY RESPONSE(username)
//!   --(recv CHALLENGE)-->         create srp::Client, send CLIENT_KEY(A)
//!   --(recv SERVER_KEY B)-->      srp compute_key, send CLIENT_VALIDATOR(M1)
//!   --(recv SERVER_VALIDATOR M2)->srp verify_m2 -> SUCCESS (else FAILURE)
//!
//! Authenticator (server): UNAUTH -> send IDENTITY REQUEST
//!   --(recv IDENTITY RESPONSE)--> lookup(verifier,salt), create srp::Server,
//!                                 send CHALLENGE(salt)
//!   --(recv CLIENT_KEY A)-->      srp handle_a, send SERVER_KEY(B)
//!   --(recv CLIENT_VALIDATOR M1)->srp verify_m1 -> send SERVER_VALIDATOR(M2)
//!                                 + SUCCESS (else FAILURE)
//! ```
//!
//! EAPOL frames are never encrypted, even under a PSK (libRIST excludes EAPOL from
//! payload encryption), so this module deals only in plaintext frames.
//!
//! Sans-I/O, like the flow core: the host hands received EAPOL payloads to
//! [`Authenticatee::recv`] / [`Authenticator::recv`] and transmits whatever frames
//! they return. It never reads a clock, opens a socket, or spawns a task.

// Justification: the framing reads/writes fixed big-endian length fields, and EAP
// packets are bounded well under 64 KiB so the usize->u16 length casts cannot
// truncate; the slice indexing is bounds-checked up front. Error/panic docs are
// covered by the module prose.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use crate::srp::{self, HASH_LEN};

/// Errors returned by the EAP layer. User-facing `Display` strings are prefixed
/// `"rist: eap: "`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EapError {
    /// The input is too short to hold the EAPOL/EAP/SRP headers or an announced
    /// field.
    #[error("rist: eap: short buffer")]
    ShortBuffer,
    /// An EAPOL or EAP length field is inconsistent with the buffer.
    #[error("rist: eap: inconsistent length field")]
    BadLength,
    /// An EAPOL type or EAP-SRP type byte this implementation does not handle.
    #[error("rist: eap: unsupported type")]
    UnsupportedType,
    /// A frame arrived in a state where the role does not expect it.
    #[error("rist: eap: unexpected frame for state")]
    Unexpected,
    /// The verifier lookup reported no verifier for the requested username.
    #[error("rist: eap: no verifier for user")]
    NoVerifier,
    /// An SRP-layer failure surfaced from [`crate::srp`].
    #[error("rist: eap: srp failure: {0}")]
    Srp(#[from] srp::SrpError),
    /// Authentication definitively failed: the peer's proof did not verify.
    #[error("rist: eap: authentication failed")]
    AuthFailed,
    /// The username or password was empty.
    #[error("rist: eap: empty username or password")]
    EmptyCredentials,
    /// The username or password exceeded 255 bytes (libRIST bounds both at 1..255).
    #[error("rist: eap: username or password too long")]
    CredentialsTooLong,
    /// A CHALLENGE carried an explicit (g, N) rather than the default 2048-bit
    /// group; only the default group is supported.
    #[error("rist: eap: non-default SRP group unsupported")]
    UnsupportedGroup,
}

// EAPOL types (802.1X-2010 §11).
const EAPOL_TYPE_EAP: u8 = 0;
const EAPOL_TYPE_START: u8 = 1;
const EAPOL_TYPE_LOGOFF: u8 = 2;

// EAP method types.
const EAP_TYPE_IDENTITY: u8 = 1;
const EAP_TYPE_SRP_SHA1: u8 = 19;

// EAP-SRP subtypes. Values 1 and 2 are reused across the REQUEST/RESPONSE
// directions; the EAP code disambiguates them.
const SRP_SUBTYPE_CHALLENGE: u8 = 1; // REQUEST: server CHALLENGE; RESPONSE: client A
const SRP_SUBTYPE_SERVER_KEY: u8 = 2; // REQUEST: server B; RESPONSE: client M1
const SRP_SUBTYPE_SERVER_VAL: u8 = 3; // server validator (M2)
const SRP_SUBTYPE_PASSWORD: u8 = 0x10;

// Passphrase-RESPONSE (subtype 0x10) flag bits.
const PP_FLAG_USE_KEY: u8 = 1 << 7; // use the SRP session key K as the passphrase
const PP_FLAG_AES256: u8 = 1 << 6; // the embedded passphrase is AES-256 encrypted

/// The EAPOL version this implementation emits: 3 signals RFC 5054 PAD-compliant
/// SRP hashing. libRIST 0.2.16+ always uses 3 for new contexts.
const EAP_VERSION_3: u8 = 3;

const EAPOL_HDR_SIZE: usize = 4;
const EAP_HDR_SIZE: usize = 4;
const SRP_HDR_SIZE: usize = 2;
const VALIDATOR_FLAGS_LEN: usize = 4;

/// An EAP packet's code field (RFC 3748).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Code {
    /// EAP Request (code 1). Also the default for bodyless START/LOGOFF frames.
    #[default]
    Request,
    /// EAP Response (code 2).
    Response,
    /// EAP Success (code 3).
    Success,
    /// EAP Failure (code 4).
    Failure,
}

impl Code {
    fn to_u8(self) -> u8 {
        match self {
            Code::Request => 1,
            Code::Response => 2,
            Code::Success => 3,
            Code::Failure => 4,
        }
    }

    fn from_u8(b: u8) -> Option<Code> {
        match b {
            1 => Some(Code::Request),
            2 => Some(Code::Response),
            3 => Some(Code::Success),
            4 => Some(Code::Failure),
            _ => None,
        }
    }
}

/// The logical EAP-SRP message kind, abstracting over the code/subtype encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    /// An EAP body parsed structurally but not acted on (e.g. password push).
    #[default]
    Unknown,
    /// EAPOL-START (opens the handshake from the client).
    Start,
    /// EAPOL-LOGOFF (tears the handshake down).
    Logoff,
    /// An IDENTITY REQUEST (server → client).
    IdentityRequest,
    /// An IDENTITY RESPONSE carrying the username (client → server).
    IdentityResponse,
    /// A CHALLENGE carrying the salt (server → client).
    Challenge,
    /// CLIENT-KEY carrying A (client → server).
    ClientKey,
    /// SERVER-KEY carrying B (server → client).
    ServerKey,
    /// CLIENT-VALIDATOR carrying M1 (client → server).
    ClientValidator,
    /// SERVER-VALIDATOR carrying M2 (server → client).
    ServerValidator,
    /// A passphrase REQUEST (subtype 0x10, REQUEST): asks the peer to push the
    /// data-channel passphrase after SRP succeeds (TR-06-2 key negotiation).
    PassphraseRequest,
    /// A passphrase RESPONSE (subtype 0x10, RESPONSE): pushes the data-channel
    /// passphrase. `pp_use_key` selects "use the SRP session key K"; otherwise
    /// `passphrase` holds the bytes AES-CTR-encrypted under K.
    PassphraseResponse,
    /// EAP-SUCCESS.
    Success,
    /// EAP-FAILURE.
    Failure,
}

/// A decoded EAPOL frame carrying an EAP-SRP message — the normalized form
/// [`Frame::parse`] produces and [`Frame::append_to`] encodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    /// The EAPOL version byte (2 or 3).
    pub version: u8,
    /// The EAP code (meaningful only when the EAPOL type is EAP).
    pub code: Code,
    /// The EAP request/response correlation id.
    pub identifier: u8,
    /// The classified message.
    pub kind: Kind,
    /// Set for IDENTITY-RESPONSE (may be empty for the request).
    pub username: String,
    /// The CHALLENGE salt.
    pub salt: Vec<u8>,
    /// The CHALLENGE generator (empty for the default group).
    pub gen_g: Vec<u8>,
    /// The CHALLENGE modulus (empty for the default group).
    pub gen_n: Vec<u8>,
    /// A (CLIENT-KEY) or B (SERVER-KEY).
    pub public: Vec<u8>,
    /// M1 (CLIENT-VALIDATOR) or M2 (SERVER-VALIDATOR).
    pub proof: Vec<u8>,
    /// The 4-byte flags word of a validator message (zero here).
    pub flags: [u8; VALIDATOR_FLAGS_LEN],
    /// A passphrase RESPONSE's "use the SRP session key K" flag (subtype 0x10 bit
    /// 7). When set, `passphrase` is empty and both ends use K.
    pub pp_use_key: bool,
    /// A passphrase RESPONSE's encrypted passphrase bytes (subtype 0x10), AES-CTR
    /// encrypted under K. Empty when `pp_use_key` is set.
    pub passphrase: Vec<u8>,
}

/// The EAPOL-START frame that opens the handshake from the client side.
fn start_frame() -> Frame {
    Frame {
        version: EAP_VERSION_3,
        kind: Kind::Start,
        ..Frame::default()
    }
}

impl Frame {
    /// Encodes the frame in EAPOL/EAP/EAP-SRP wire form and appends it to `dst`.
    /// The EAPOL length and EAP length fields both carry the EAP packet length. An
    /// unknown kind appends nothing.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        let version = if self.version == 0 {
            EAP_VERSION_3
        } else {
            self.version
        };

        // START and LOGOFF are bare EAPOL frames with a zero-length body.
        if let Kind::Start | Kind::Logoff = self.kind {
            let typ = if self.kind == Kind::Logoff {
                EAPOL_TYPE_LOGOFF
            } else {
                EAPOL_TYPE_START
            };
            dst.extend_from_slice(&[version, typ, 0, 0]);
            return;
        }

        let body = self.encode_body();
        let eap_len = (EAP_HDR_SIZE + body.len()) as u16;
        // EAPOL header: version, type EAP, length = EAP packet length.
        dst.push(version);
        dst.push(EAPOL_TYPE_EAP);
        dst.extend_from_slice(&eap_len.to_be_bytes());
        // EAP header: code, identifier, length = EAP packet length.
        dst.push(self.code.to_u8());
        dst.push(self.identifier);
        dst.extend_from_slice(&eap_len.to_be_bytes());
        dst.extend_from_slice(&body);
    }

    /// The EAP body (everything after the EAP header), including the EAP-SRP
    /// subtype header where applicable.
    fn encode_body(&self) -> Vec<u8> {
        match self.kind {
            Kind::IdentityRequest => vec![EAP_TYPE_IDENTITY],
            Kind::IdentityResponse => {
                let mut out = vec![EAP_TYPE_IDENTITY];
                out.extend_from_slice(self.username.as_bytes());
                out
            }
            Kind::Challenge => {
                let mut out = vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_CHALLENGE];
                out.extend_from_slice(&0u16.to_be_bytes()); // name length: no server name
                out.extend_from_slice(&(self.salt.len() as u16).to_be_bytes());
                out.extend_from_slice(&self.salt);
                if self.gen_g.is_empty() {
                    out.extend_from_slice(&0u16.to_be_bytes()); // default group: gen_len 0
                } else {
                    out.extend_from_slice(&(self.gen_g.len() as u16).to_be_bytes());
                    out.extend_from_slice(&self.gen_g);
                    out.extend_from_slice(&self.gen_n);
                }
                out
            }
            Kind::ClientKey => {
                // CLIENT_KEY rides on subtype CHALLENGE in the RESPONSE direction.
                let mut out = vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_CHALLENGE];
                out.extend_from_slice(&self.public);
                out
            }
            Kind::ServerKey => {
                let mut out = vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_SERVER_KEY];
                out.extend_from_slice(&self.public);
                out
            }
            Kind::ClientValidator => {
                // CLIENT_VALIDATOR rides on subtype SERVER_KEY in the RESPONSE dir.
                let mut out = vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_SERVER_KEY];
                out.extend_from_slice(&self.flags);
                out.extend_from_slice(&self.proof);
                out
            }
            Kind::ServerValidator => {
                let mut out = vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_SERVER_VAL];
                out.extend_from_slice(&self.flags);
                out.extend_from_slice(&self.proof);
                out
            }
            Kind::PassphraseRequest => vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_PASSWORD],
            Kind::PassphraseResponse => {
                let mut out = vec![EAP_TYPE_SRP_SHA1, SRP_SUBTYPE_PASSWORD];
                if self.pp_use_key {
                    out.push(PP_FLAG_USE_KEY);
                } else {
                    out.push(PP_FLAG_AES256);
                    out.extend_from_slice(&self.passphrase);
                }
                out
            }
            // The v3 EAP-SUCCESS body is a zeroed eap_srp_hdr (two zero bytes).
            Kind::Success => vec![0, 0],
            Kind::Failure | Kind::Unknown | Kind::Start | Kind::Logoff => Vec::new(),
        }
    }

    /// The number of bytes [`Frame::append_to`] writes.
    #[must_use]
    pub fn marshal_size(&self) -> usize {
        match self.kind {
            Kind::Start | Kind::Logoff => EAPOL_HDR_SIZE,
            _ => EAPOL_HDR_SIZE + EAP_HDR_SIZE + self.encode_body().len(),
        }
    }

    /// Decodes one EAPOL frame from `b`. It validates framing only (the
    /// EAPOL/EAP length fields, the SRP type byte, and per-message body lengths),
    /// never enforcing role expectations. The returned frame does not alias `b`.
    pub fn parse(b: &[u8]) -> Result<Frame, EapError> {
        if b.len() < EAPOL_HDR_SIZE {
            return Err(EapError::ShortBuffer);
        }
        let version = b[0];
        let eapol_type = b[1];
        let body_len = u16::from_be_bytes([b[2], b[3]]) as usize;
        if body_len + EAPOL_HDR_SIZE > b.len() {
            return Err(EapError::BadLength);
        }
        match eapol_type {
            EAPOL_TYPE_START => Ok(Frame {
                version,
                kind: Kind::Start,
                ..Frame::default()
            }),
            EAPOL_TYPE_LOGOFF => Ok(Frame {
                version,
                kind: Kind::Logoff,
                ..Frame::default()
            }),
            EAPOL_TYPE_EAP => parse_eap(version, &b[EAPOL_HDR_SIZE..EAPOL_HDR_SIZE + body_len]),
            _ => Err(EapError::UnsupportedType),
        }
    }
}

/// Decodes the EAP packet (header + body).
fn parse_eap(version: u8, eap_pkt: &[u8]) -> Result<Frame, EapError> {
    if eap_pkt.len() < EAP_HDR_SIZE {
        return Err(EapError::ShortBuffer);
    }
    let code = eap_pkt[0];
    let identifier = eap_pkt[1];
    let length = u16::from_be_bytes([eap_pkt[2], eap_pkt[3]]) as usize;
    if length != eap_pkt.len() {
        return Err(EapError::BadLength);
    }
    let body = &eap_pkt[EAP_HDR_SIZE..];
    let code = Code::from_u8(code).ok_or(EapError::UnsupportedType)?;
    let mut f = Frame {
        version,
        code,
        identifier,
        ..Frame::default()
    };
    match code {
        Code::Request | Code::Response => parse_method(f, code, body),
        Code::Success => {
            f.kind = Kind::Success;
            Ok(f)
        }
        Code::Failure => {
            f.kind = Kind::Failure;
            Ok(f)
        }
    }
}

/// Decodes the EAP method body of a REQUEST or RESPONSE.
fn parse_method(mut f: Frame, code: Code, body: &[u8]) -> Result<Frame, EapError> {
    let Some((&m_type, rest)) = body.split_first() else {
        return Err(EapError::ShortBuffer);
    };
    match m_type {
        EAP_TYPE_IDENTITY => {
            if code == Code::Request {
                f.kind = Kind::IdentityRequest;
            } else {
                f.kind = Kind::IdentityResponse;
                f.username = String::from_utf8_lossy(rest).into_owned();
            }
            Ok(f)
        }
        EAP_TYPE_SRP_SHA1 => {
            if body.len() < SRP_HDR_SIZE {
                return Err(EapError::ShortBuffer);
            }
            parse_srp(f, code, body[1], &body[SRP_HDR_SIZE..])
        }
        _ => Err(EapError::UnsupportedType),
    }
}

/// Decodes the EAP-SRP body after the 2-byte subtype header.
fn parse_srp(mut f: Frame, code: Code, subtype: u8, payload: &[u8]) -> Result<Frame, EapError> {
    match (subtype, code) {
        (SRP_SUBTYPE_CHALLENGE, Code::Request) => parse_challenge(f, payload),
        (SRP_SUBTYPE_CHALLENGE, Code::Response) => {
            f.kind = Kind::ClientKey;
            f.public = payload.to_vec();
            Ok(f)
        }
        (SRP_SUBTYPE_SERVER_KEY, Code::Request) => {
            f.kind = Kind::ServerKey;
            f.public = payload.to_vec();
            Ok(f)
        }
        (SRP_SUBTYPE_SERVER_KEY, Code::Response) => {
            parse_validator(f, Kind::ClientValidator, payload)
        }
        (SRP_SUBTYPE_SERVER_VAL, _) => {
            // On the RESPONSE side libRIST treats subtype 3 as a bodyless
            // server-validator acknowledgement; surface it so the host completes
            // the handshake on it.
            if code == Code::Response && payload.len() < VALIDATOR_FLAGS_LEN + HASH_LEN {
                f.kind = Kind::ServerValidator;
                return Ok(f);
            }
            parse_validator(f, Kind::ServerValidator, payload)
        }
        (SRP_SUBTYPE_PASSWORD, Code::Request) => {
            f.kind = Kind::PassphraseRequest;
            Ok(f)
        }
        (SRP_SUBTYPE_PASSWORD, Code::Response) => {
            f.kind = Kind::PassphraseResponse;
            if let Some((&flags, rest)) = payload.split_first() {
                f.pp_use_key = flags & PP_FLAG_USE_KEY != 0;
                if !f.pp_use_key {
                    f.passphrase = rest.to_vec();
                }
            }
            Ok(f)
        }
        _ => Err(EapError::UnsupportedType),
    }
}

/// Decodes the CHALLENGE TLVs: name_len|name|salt_len|salt|gen_len[|g|N].
fn parse_challenge(mut f: Frame, p: &[u8]) -> Result<Frame, EapError> {
    let mut off = 0;
    let name_len = read_u16(p, &mut off)?;
    if name_len > p.len() - off {
        return Err(EapError::BadLength);
    }
    off += name_len; // name ignored

    let salt_len = read_u16(p, &mut off)?;
    if salt_len > p.len() - off {
        return Err(EapError::BadLength);
    }
    let salt = p[off..off + salt_len].to_vec();
    off += salt_len;

    let gen_len = read_u16(p, &mut off)?;
    f.kind = Kind::Challenge;
    f.salt = salt;
    if gen_len != 0 {
        if gen_len > p.len() - off {
            return Err(EapError::BadLength);
        }
        f.gen_g = p[off..off + gen_len].to_vec();
        off += gen_len;
        f.gen_n = p[off..].to_vec(); // N runs to the end
    }
    Ok(f)
}

/// Decodes a validator body: a 4-byte flags word followed by the 32-byte proof.
fn parse_validator(mut f: Frame, kind: Kind, p: &[u8]) -> Result<Frame, EapError> {
    if p.len() < VALIDATOR_FLAGS_LEN + HASH_LEN {
        return Err(EapError::ShortBuffer);
    }
    f.kind = kind;
    f.flags.copy_from_slice(&p[..VALIDATOR_FLAGS_LEN]);
    f.proof = p[VALIDATOR_FLAGS_LEN..VALIDATOR_FLAGS_LEN + HASH_LEN].to_vec();
    Ok(f)
}

/// Reads a 2-byte big-endian value at `*off`, advancing it by 2.
fn read_u16(b: &[u8], off: &mut usize) -> Result<usize, EapError> {
    if *off + 2 > b.len() {
        return Err(EapError::ShortBuffer);
    }
    let v = u16::from_be_bytes([b[*off], b[*off + 1]]) as usize;
    *off += 2;
    Ok(v)
}

/// The host-supplied callback the [`Authenticator`] uses to find a user's SRP
/// verifier and salt. Returns `None` when the username is unknown.
pub type VerifierLookup = Box<dyn Fn(&str) -> Option<(Vec<u8>, Vec<u8>)> + Send>;

/// A [`VerifierLookup`] that serves a single configured `(username, verifier,
/// salt)` tuple — the common host configuration.
#[must_use]
pub fn static_verifier(user: &str, verifier: Vec<u8>, salt: Vec<u8>) -> VerifierLookup {
    let user = user.to_string();
    Box::new(move |u: &str| {
        if u == user {
            Some((verifier.clone(), salt.clone()))
        } else {
            None
        }
    })
}

/// The SRP group a CHALLENGE selects. Only the default 2048-bit group
/// (`gen_len == 0`) is supported.
fn challenge_group(f: &Frame) -> Result<srp::Group, EapError> {
    if f.gen_g.is_empty() {
        Ok(srp::default_group())
    } else {
        Err(EapError::UnsupportedGroup)
    }
}

/// The EAPOL version to emit in reply to `req`: the peer's legacy version 2 when it
/// advertises it, otherwise the current version 3. libRIST drives both the on-wire
/// version byte and the SRP hashing mode from the authenticator's advertised
/// version, so a reply must echo it.
fn negotiated_version(req: &Frame) -> u8 {
    if req.version == 2 { 2 } else { EAP_VERSION_3 }
}

/// Builds a passphrase RESPONSE (subtype 0x10) that pushes "use the SRP session key
/// K" — the no-explicit-passphrase data-channel key negotiation. After
/// authentication the host sends this (unsolicited, and in reply to a passphrase
/// REQUEST) so the peer sets its receive passphrase to K and decrypts media.
#[must_use]
pub fn passphrase_push(identifier: u8) -> Frame {
    Frame {
        version: EAP_VERSION_3,
        code: Code::Response,
        identifier,
        kind: Kind::PassphraseResponse,
        pp_use_key: true,
        ..Frame::default()
    }
}

/// An EAP-SUCCESS frame echoing `identifier` (acknowledges a passphrase push).
fn success_ack(identifier: u8) -> Frame {
    Frame {
        version: EAP_VERSION_3,
        code: Code::Success,
        identifier,
        kind: Kind::Success,
        ..Frame::default()
    }
}

/// The EAP authentication state of a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    /// The initial state: no handshake completed.
    #[default]
    Unauth,
    /// The handshake has begun but not yet succeeded or failed.
    InProgress,
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failed,
}

/// The outcome of feeding one frame to a role: the frame to transmit in reply (if
/// any) and a terminal error (if the frame arrived in a bad state or auth failed).
/// Both may be present: a server that rejects a client proof emits an EAP-FAILURE
/// frame *and* signals [`EapError::AuthFailed`].
#[derive(Debug, Default)]
pub struct Reply {
    /// The frame to transmit, if any.
    pub frame: Option<Frame>,
    /// A terminal error, if any.
    pub error: Option<EapError>,
}

impl Reply {
    fn none() -> Reply {
        Reply::default()
    }
    fn frame(f: Frame) -> Reply {
        Reply {
            frame: Some(f),
            error: None,
        }
    }
    fn err(e: EapError) -> Reply {
        Reply {
            frame: None,
            error: Some(e),
        }
    }
    fn frame_err(f: Frame, e: EapError) -> Reply {
        Reply {
            frame: Some(f),
            error: Some(e),
        }
    }
}

/// The EAP-SRP client role (the side being authenticated, e.g. a RIST sender).
/// Sans-I/O and single-use; not safe for concurrent use.
#[derive(Debug)]
pub struct Authenticatee {
    username: String,
    password: String,
    state: State,
    id: u8,
    /// Whether `id` reflects an adopted in-flight request. Until the first request
    /// is processed there is nothing to gate a subsequent request's identifier
    /// against, so the opening IDENTITY_REQUEST bootstraps the sequence.
    id_valid: bool,
    client: Option<srp::Client>,
    salt: Vec<u8>,
    session: Option<[u8; HASH_LEN]>,
    use_key_passphrase: bool,
    /// The last inbound frame processed and the reply it produced. A byte-identical
    /// re-arrival (a peer retransmit under loss) replays the cached reply instead of
    /// re-running the state machine, which would recompute a fresh SRP ephemeral `a`
    /// and desync. See [`Authenticatee::recv`].
    last_rx: Option<Vec<u8>>,
    last_reply: Option<Frame>,
}

impl Authenticatee {
    /// Creates an EAP-SRP client for the given credentials (each 1..255 bytes).
    pub fn new(username: &str, password: &str) -> Result<Authenticatee, EapError> {
        if username.is_empty() || password.is_empty() {
            return Err(EapError::EmptyCredentials);
        }
        if username.len() > 255 || password.len() > 255 {
            return Err(EapError::CredentialsTooLong);
        }
        Ok(Authenticatee {
            username: username.to_string(),
            password: password.to_string(),
            state: State::Unauth,
            id: 0,
            id_valid: false,
            client: None,
            salt: Vec::new(),
            session: None,
            use_key_passphrase: true,
            last_rx: None,
            last_reply: None,
        })
    }

    /// Selects how the role answers a peer's passphrase request: push "use the SRP
    /// session key K" (pure SRP, the default), or stay silent so the peer keeps its
    /// configured PSK secret (combined PSK + SRP mode).
    pub fn set_use_key_passphrase(&mut self, use_key: bool) {
        self.use_key_passphrase = use_key;
    }

    /// The current authentication state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the handshake has reached a terminal state.
    #[must_use]
    pub fn done(&self) -> bool {
        matches!(self.state, State::Success | State::Failed)
    }

    /// Whether authentication succeeded.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.state == State::Success
    }

    /// The SRP session key K derived during a successful handshake, or `None`.
    #[must_use]
    pub fn session_key(&self) -> Option<[u8; HASH_LEN]> {
        self.session
    }

    /// The EAPOL-START frame that opens the handshake from the client side.
    pub fn start(&mut self) -> Frame {
        if self.state == State::Unauth {
            self.state = State::InProgress;
        }
        start_frame()
    }

    /// Resets the client to the unauthenticated state so a fresh handshake can re-run
    /// (EAP re-authentication — e.g. after a NAT source-port rebind). Credentials and
    /// the `use_key_passphrase` keying mode are preserved, so a successful re-auth
    /// *rolls* the data-channel keys rather than resetting them; the host re-emits the
    /// EAPOL-START after calling this.
    pub fn restart(&mut self) {
        self.state = State::Unauth;
        self.id = 0; // the next IDENTITY REQUEST re-bootstraps it; a stale value widens the gate
        self.id_valid = false;
        self.client = None;
        self.salt = Vec::new();
        self.session = None;
        // Drop the retransmit-replay cache: a fresh handshake must not replay a reply
        // from the previous one.
        self.last_rx = None;
        self.last_reply = None;
    }

    /// Processes one received EAPOL frame and returns the reply to transmit (and
    /// any terminal error). Never panics on arbitrary input.
    ///
    /// An exact byte-for-byte duplicate of the last processed frame — a peer
    /// retransmitting under loss — replays the cached reply without re-running the
    /// state machine, so a retransmitted CHALLENGE does not rebuild the SRP client
    /// with a fresh ephemeral `a` (which would desync the handshake). This makes the
    /// handshake recoverable when datagrams are dropped.
    pub fn recv(&mut self, payload: &[u8]) -> Reply {
        if !payload.is_empty() && self.last_rx.as_deref() == Some(payload) {
            return match &self.last_reply {
                Some(f) => Reply::frame(f.clone()),
                None => Reply::none(),
            };
        }
        let reply = match Frame::parse(payload) {
            Ok(f) => self.handle(f),
            Err(e) => return Reply::err(e),
        };
        // Cache only a clean step; a terminal error is never retransmit-replayed.
        if reply.error.is_none() {
            self.last_rx = Some(payload.to_vec());
            self.last_reply.clone_from(&reply.frame);
        }
        reply
    }

    // Justification: the frame is consumed conditionally per match arm (each arm
    // owns the credentials/salt/proof it needs), so it is taken by value; the arm
    // count makes the function long but it is one flat state transition table.
    #[allow(
        clippy::too_many_lines,
        clippy::needless_pass_by_value,
        clippy::match_same_arms
    )]
    fn handle(&mut self, f: Frame) -> Reply {
        if f.kind == Kind::Failure {
            // Honor a FAILURE only while a handshake is actually in flight (InProgress)
            // and only when its identifier matches the in-flight request. In Success a
            // FAILURE is stale or forged — a live session is re-proven via a fresh
            // IDENTITY REQUEST (the Success gate below), never torn down by an injected
            // FAILURE, so a replay echoing the last identifier cannot knock us out of
            // Success. (Unauth has no exchange to fail; Failed is already terminal.)
            if self.state != State::InProgress || f.identifier != self.id {
                return Reply::none();
            }
            self.state = State::Failed;
            return Reply::err(EapError::AuthFailed);
        }
        // Re-authentication gate: a re-auth MUST begin with a fresh IDENTITY REQUEST.
        // Once Success has been reached, a CHALLENGE/SERVER_KEY/SERVER_VALIDATOR with
        // no intervening IDENTITY REQUEST is stale or forged — ignore it so a replayed
        // frame cannot knock a live session out of Success and restart its SRP state. A
        // genuine IDENTITY REQUEST in Success is the authenticator driving a re-auth:
        // reset to a clean slate so the re-auth runs (and `done`/`authenticated` report
        // it in progress) rather than answering from stale state while still in Success.
        if self.state == State::Success {
            match f.kind {
                Kind::IdentityRequest => self.restart(),
                Kind::Challenge | Kind::ServerKey | Kind::ServerValidator => return Reply::none(),
                _ => {}
            }
        }
        // Identifier gate: the authenticator drives the SRP exchange with a fresh,
        // per-request incrementing identifier (IDENTITY_REQUEST → CHALLENGE →
        // SERVER_KEY → SERVER_VALIDATOR), so each successive server-driven request
        // carries `id + 1`, and a retransmit repeats `id`. Once an in-flight request
        // has been adopted, ignore (and so refuse to adopt) any out-of-sequence
        // server-driven SRP request — an off-path injected frame could otherwise
        // poison `self.id` and prime a spoofed-FAILURE handshake DoS. The opening
        // IDENTITY_REQUEST is exempt: it bootstraps the sequence (libRIST accepts
        // any identifier there). The SRP key agreement itself is unaffected — a
        // forged validator fails M2 verification regardless.
        if self.id_valid
            && matches!(
                f.kind,
                Kind::Challenge | Kind::ServerKey | Kind::ServerValidator
            )
            && f.identifier != self.id
            && f.identifier != self.id.wrapping_add(1)
        {
            return Reply::none();
        }
        // The request identifier is adopted into `self.id` only inside the cases
        // that legitimately process a request, never in the prologue.
        match f.kind {
            Kind::IdentityRequest => {
                self.id = f.identifier;
                self.id_valid = true;
                if self.state == State::Unauth {
                    self.state = State::InProgress;
                }
                Reply::frame(Frame {
                    version: negotiated_version(&f),
                    code: Code::Response,
                    identifier: f.identifier,
                    kind: Kind::IdentityResponse,
                    username: self.username.clone(),
                    ..Frame::default()
                })
            }
            Kind::Challenge => {
                if let Err(e) = challenge_group(&f) {
                    self.state = State::Failed;
                    return Reply::err(e);
                }
                if f.salt.is_empty() {
                    self.state = State::Failed;
                    return Reply::err(EapError::BadLength);
                }
                let grp = srp::default_group();
                // The challenge's version selects the SRP hashing mode.
                let client = if negotiated_version(&f) == 2 {
                    srp::Client::new_legacy(&grp, &f.salt)
                } else {
                    srp::Client::new(&grp, &f.salt)
                };
                let client = match client {
                    Ok(c) => c,
                    Err(e) => {
                        self.state = State::Failed;
                        return Reply::err(EapError::Srp(e));
                    }
                };
                self.id = f.identifier;
                self.id_valid = true;
                let a = client.a();
                self.client = Some(client);
                self.salt.clone_from(&f.salt);
                self.state = State::InProgress;
                Reply::frame(Frame {
                    version: negotiated_version(&f),
                    code: Code::Response,
                    identifier: f.identifier,
                    kind: Kind::ClientKey,
                    public: a,
                    ..Frame::default()
                })
            }
            Kind::ServerKey => {
                if self.client.is_none() {
                    self.state = State::Failed;
                    return Reply::err(EapError::Unexpected);
                }
                self.id = f.identifier;
                self.id_valid = true;
                let res = self.client.as_mut().unwrap().compute_key(
                    &f.public,
                    &self.username,
                    &self.password,
                );
                if let Err(e) = res {
                    self.state = State::Failed;
                    return Reply::err(EapError::Srp(e));
                }
                let m1 = self.client.as_ref().unwrap().m1().unwrap_or_default();
                Reply::frame(Frame {
                    version: negotiated_version(&f),
                    code: Code::Response,
                    identifier: f.identifier,
                    kind: Kind::ClientValidator,
                    proof: m1.to_vec(),
                    ..Frame::default()
                })
            }
            Kind::ServerValidator => {
                if self.client.is_none() || f.proof.is_empty() {
                    self.state = State::Failed;
                    return Reply::err(EapError::AuthFailed);
                }
                self.id = f.identifier;
                self.id_valid = true;
                if !self.client.as_ref().unwrap().verify_m2(&f.proof) {
                    self.state = State::Failed;
                    return Reply::err(EapError::AuthFailed);
                }
                self.session = self.client.as_ref().unwrap().session_key();
                self.state = State::Success;
                // Acknowledge with the closing v3 EAP-SUCCESS; this drives the
                // authenticator to its terminal SUCCESS.
                Reply::frame(Frame {
                    version: negotiated_version(&f),
                    code: Code::Success,
                    identifier: f.identifier,
                    kind: Kind::Success,
                    ..Frame::default()
                })
            }
            // The peer asks for our data-channel passphrase. In pure-SRP mode push
            // "use K"; with a configured PSK secret stay silent so the peer keeps
            // its secret (we never override it with K).
            Kind::PassphraseRequest if self.use_key_passphrase => {
                Reply::frame(passphrase_push(f.identifier))
            }
            Kind::PassphraseRequest => Reply::none(),
            // The peer pushed its passphrase (the host keys the channel out of band);
            // acknowledge so the peer's exchange completes.
            Kind::PassphraseResponse => Reply::frame(success_ack(f.identifier)),
            // The authenticatee normally sends the closing SUCCESS; tolerate a
            // received SUCCESS as a no-op.
            Kind::Success => Reply::none(),
            _ => Reply::err(EapError::Unexpected),
        }
    }
}

/// The EAP-SRP server role (the side verifying a peer, e.g. a RIST listener).
/// Sans-I/O and single-use; not safe for concurrent use.
// The flags (`verified`/`use_key_passphrase`/`ever_authed`/`legacy`) are independent
// per-handshake state, not a state enum; folding them would obscure the protocol.
#[allow(clippy::struct_excessive_bools)]
pub struct Authenticator {
    lookup: VerifierLookup,
    state: State,
    id: u8,
    server: Option<srp::Server>,
    username: String,
    session: Option<[u8; HASH_LEN]>,
    verified: bool,
    use_key_passphrase: bool,
    /// Records that this authenticator reached `Success` at least once. Once true, a
    /// spoofed EAPOL-LOGOFF can no longer tear the exchange down even while a re-auth
    /// is in progress (an established session is only re-proven, never reset).
    ever_authed: bool,
    /// Legacy (pre-0.2.16, libRIST `srp-compat=1`) mode: advertise EAPOL version 2 and
    /// use the unpadded-k/u SRP hashing ([`srp::Server::new_legacy`]). The authenticatee
    /// echoes the advertised version and switches to matching legacy math, so the whole
    /// handshake runs in legacy mode for interop with old peers.
    legacy: bool,
    /// The last inbound frame processed and the reply it produced; a byte-identical
    /// re-arrival replays the cached reply rather than rebuilding the SRP server with a
    /// fresh ephemeral `B`. See [`Authenticator::recv`].
    last_rx: Option<Vec<u8>>,
    last_reply: Option<Frame>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("state", &self.state)
            .field("id", &self.id)
            .field("username", &self.username)
            .field("verified", &self.verified)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// Creates an EAP-SRP server that resolves verifiers via `lookup` (the libRIST
    /// 0.2.16+ default, EAPOL version 3, RFC 5054 PAD-compliant hashing).
    #[must_use]
    pub fn new(lookup: VerifierLookup) -> Authenticator {
        Authenticator::with_mode(lookup, false)
    }

    /// Creates an EAP-SRP server in the legacy (pre-0.2.16, libRIST `srp-compat=1`)
    /// compatibility mode: it advertises EAPOL version 2 and uses the unpadded-k/u SRP
    /// hashing, driving the authenticatee into the matching legacy math. Use only to
    /// interoperate with a legacy peer.
    #[must_use]
    pub fn new_legacy(lookup: VerifierLookup) -> Authenticator {
        Authenticator::with_mode(lookup, true)
    }

    fn with_mode(lookup: VerifierLookup, legacy: bool) -> Authenticator {
        Authenticator {
            lookup,
            state: State::Unauth,
            id: 0,
            server: None,
            username: String::new(),
            session: None,
            verified: false,
            use_key_passphrase: true,
            ever_authed: false,
            legacy,
            last_rx: None,
            last_reply: None,
        }
    }

    /// The EAPOL version this authenticator advertises: 2 in legacy mode, else 3.
    fn version(&self) -> u8 {
        if self.legacy { 2 } else { EAP_VERSION_3 }
    }

    /// Resets the server to the unauthenticated state for a fresh handshake (EAP
    /// re-authentication). The verifier lookup, advertised version, and keying mode
    /// are preserved; the EAP identifier advances so the re-auth's requests are
    /// distinct on the wire. A subsequent [`start`](Self::start) re-opens the
    /// exchange. A failed re-auth is non-fatal at the host: the previously installed
    /// keys remain until a new Success rolls them.
    pub fn restart(&mut self) {
        self.state = State::Unauth;
        self.server = None;
        self.session = None;
        self.verified = false;
        self.id = self.id.wrapping_add(1);
        // Drop the retransmit-replay cache: a fresh re-auth must not replay a reply
        // from the previous handshake.
        self.last_rx = None;
        self.last_reply = None;
    }

    /// Selects how the role answers a peer's passphrase request: push "use the SRP
    /// session key K" (pure SRP, the default), or stay silent so the peer keeps its
    /// configured PSK secret (combined PSK + SRP mode).
    pub fn set_use_key_passphrase(&mut self, use_key: bool) {
        self.use_key_passphrase = use_key;
    }

    /// Sets the initial EAP identifier the authenticator issues. Pass a CSPRNG byte
    /// before [`Authenticator::start`] to match libRIST's unpredictable identifier;
    /// no effect once the handshake has begun.
    pub fn seed_identifier(&mut self, id: u8) {
        if self.state == State::Unauth {
            self.id = id;
        }
    }

    /// The current authentication state.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the handshake has reached a terminal state.
    #[must_use]
    pub fn done(&self) -> bool {
        matches!(self.state, State::Success | State::Failed)
    }

    /// Whether the peer authenticated successfully.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.state == State::Success
    }

    /// The SRP session key K derived during a successful handshake, or `None`.
    #[must_use]
    pub fn session_key(&self) -> Option<[u8; HASH_LEN]> {
        self.session
    }

    /// The EAP IDENTITY REQUEST that opens the handshake from the server side.
    pub fn start(&mut self) -> Frame {
        if self.state == State::Unauth {
            self.state = State::InProgress;
        }
        Frame {
            version: self.version(),
            code: Code::Request,
            identifier: self.id,
            kind: Kind::IdentityRequest,
            ..Frame::default()
        }
    }

    /// Processes one received EAPOL frame and returns the reply to transmit (and
    /// any terminal error). Never panics on arbitrary input.
    ///
    /// An exact byte-for-byte duplicate of the last processed frame — a peer
    /// retransmitting under loss — replays the cached reply without re-running the
    /// state machine, so a retransmitted IDENTITY_RESPONSE does not rebuild the SRP
    /// server with a fresh ephemeral `B` (which would desync the handshake).
    pub fn recv(&mut self, payload: &[u8]) -> Reply {
        if !payload.is_empty() && self.last_rx.as_deref() == Some(payload) {
            return match &self.last_reply {
                Some(f) => Reply::frame(f.clone()),
                None => Reply::none(),
            };
        }
        let reply = match Frame::parse(payload) {
            Ok(f) => self.handle(f),
            Err(e) => return Reply::err(e),
        };
        // Cache only a clean step; a terminal error / FAILURE frame is not replayed.
        if reply.error.is_none() {
            self.last_rx = Some(payload.to_vec());
            self.last_reply.clone_from(&reply.frame);
        }
        reply
    }

    // Justification: as the authenticatee handler — the frame is consumed
    // conditionally per arm, and the arm count is one flat state transition table.
    #[allow(
        clippy::too_many_lines,
        clippy::needless_pass_by_value,
        clippy::match_same_arms
    )]
    fn handle(&mut self, f: Frame) -> Reply {
        // Reject a RESPONSE/FAILURE whose identifier does not match the request we
        // last issued. START/LOGOFF open/close the exchange, and the passphrase
        // exchange carries its own identifiers (and may be unsolicited), so all are
        // exempt.
        if self.state != State::Unauth
            && !matches!(
                f.kind,
                Kind::Start | Kind::Logoff | Kind::PassphraseRequest | Kind::PassphraseResponse
            )
            && f.identifier != self.id
        {
            return Reply::none();
        }
        match f.kind {
            Kind::Start => {
                // Ignore a further START while a handshake is in progress, so a
                // spoofed mid-handshake START cannot reset the live exchange. From a
                // terminal state (Success, or Failed after a prior Success — an
                // abandoned/failed re-auth) a START is a legitimate re-authentication:
                // re-run from a clean slate. A forger cannot complete the re-auth (it
                // fails M1 verification) and a failed re-auth is non-fatal at the host,
                // so neither a spoofed START nor a failed re-prove tears the session
                // down; accepting a START from Failed lets the genuine peer recover.
                if self.state == State::InProgress {
                    return Reply::none();
                }
                if self.state != State::Unauth {
                    self.restart();
                }
                Reply::frame(self.start())
            }
            Kind::Logoff => {
                // Refuse LOGOFF once the session is established (or terminated) or has
                // ever authenticated (so it cannot abort an in-progress re-auth
                // either): an injected EAPOL-LOGOFF must not tear down an authenticated
                // session. libRIST honors LOGOFF only during the initial open
                // handshake; only an in-progress, never-authed exchange is reset here.
                if matches!(self.state, State::Success | State::Failed) || self.ever_authed {
                    return Reply::none();
                }
                self.state = State::Unauth;
                self.server = None;
                self.session = None;
                self.verified = false;
                Reply::none()
            }
            Kind::IdentityResponse => {
                let Some((verifier, salt)) = (self.lookup)(&f.username) else {
                    self.state = State::Failed;
                    return Reply::err(EapError::NoVerifier);
                };
                let grp = srp::default_group();
                // Legacy mode (version 2) uses the unpadded-k/u SRP math; the version
                // byte on the Challenge drives the authenticatee into the same mode.
                let built = if self.legacy {
                    srp::Server::new_legacy(&grp, &verifier, &salt)
                } else {
                    srp::Server::new(&grp, &verifier, &salt)
                };
                let server = match built {
                    Ok(s) => s,
                    Err(e) => {
                        self.state = State::Failed;
                        return Reply::err(EapError::Srp(e));
                    }
                };
                self.server = Some(server);
                self.username.clone_from(&f.username);
                self.state = State::InProgress;
                self.id = self.id.wrapping_add(1);
                Reply::frame(Frame {
                    version: self.version(),
                    code: Code::Request,
                    identifier: self.id,
                    kind: Kind::Challenge,
                    salt,
                    ..Frame::default()
                })
            }
            Kind::ClientKey => {
                if self.server.is_none() {
                    self.state = State::Failed;
                    return Reply::err(EapError::Unexpected);
                }
                if let Err(e) = self.server.as_mut().unwrap().handle_a(&f.public) {
                    self.state = State::Failed;
                    return Reply::err(EapError::Srp(e));
                }
                self.id = self.id.wrapping_add(1);
                let b = self.server.as_ref().unwrap().b();
                Reply::frame(Frame {
                    version: self.version(),
                    code: Code::Request,
                    identifier: self.id,
                    kind: Kind::ServerKey,
                    public: b,
                    ..Frame::default()
                })
            }
            Kind::ClientValidator => {
                if self.server.is_none() {
                    self.state = State::Failed;
                    return Reply::err(EapError::Unexpected);
                }
                let username = self.username.clone();
                if !self.server.as_mut().unwrap().verify_m1(&username, &f.proof) {
                    self.state = State::Failed;
                    return Reply::frame_err(
                        Frame {
                            version: self.version(),
                            code: Code::Failure,
                            identifier: self.id,
                            kind: Kind::Failure,
                            ..Frame::default()
                        },
                        EapError::AuthFailed,
                    );
                }
                self.session = self.server.as_ref().unwrap().session_key();
                // M1 verified, but defer terminal SUCCESS until the client's ack.
                self.verified = true;
                self.id = self.id.wrapping_add(1);
                let m2 = self.server.as_ref().unwrap().m2().unwrap_or_default();
                Reply::frame(Frame {
                    version: self.version(),
                    code: Code::Request,
                    identifier: self.id,
                    kind: Kind::ServerValidator,
                    proof: m2.to_vec(),
                    ..Frame::default()
                })
            }
            Kind::ServerValidator | Kind::Success => {
                // The client acknowledges the SERVER_VALIDATOR; only now, gated on
                // the verified M1, does the authenticator reach terminal SUCCESS.
                if self.verified {
                    self.state = State::Success;
                    self.ever_authed = true;
                    self.id = self.id.wrapping_add(1);
                }
                Reply::none()
            }
            // The peer asks for our data-channel passphrase. In pure-SRP mode push
            // "use K"; with a configured PSK secret stay silent so the peer keeps
            // its secret.
            Kind::PassphraseRequest if self.use_key_passphrase => {
                Reply::frame(passphrase_push(f.identifier))
            }
            Kind::PassphraseRequest => Reply::none(),
            // The peer pushed its passphrase (the host keys the channel out of band);
            // acknowledge so the peer's exchange completes.
            Kind::PassphraseResponse => Reply::frame(success_ack(f.identifier)),
            Kind::Failure => {
                // Honor a FAILURE only while a handshake is in flight. In Success it is
                // stale or forged (EAPOL is unencrypted) and must not tear a live
                // session down — re-auth is driven by a START/IDENTITY exchange, never
                // by an injected FAILURE. (The identifier gate above already drops a
                // mismatched-id FAILURE; this also closes the matching-id FAILURE that
                // the id-advance on Success would otherwise admit.)
                if self.state != State::InProgress {
                    return Reply::none();
                }
                self.state = State::Failed;
                Reply::err(EapError::AuthFailed)
            }
            _ => Reply::err(EapError::Unexpected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Golden {
        name: &'static str,
        f: Frame,
        want: Vec<u8>,
    }

    #[allow(clippy::similar_names, clippy::too_many_lines)] // parallel golden builders
    fn goldens() -> Vec<Golden> {
        let salt = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let pub_v = vec![0x01, 0x02, 0x03];
        let proof = vec![0x5A; HASH_LEN];
        let frame = |kind, code, id, f: fn(&mut Frame)| {
            let mut fr = Frame {
                version: 3,
                code,
                identifier: id,
                kind,
                ..Frame::default()
            };
            f(&mut fr);
            fr
        };
        let id_resp = {
            let mut fr = frame(Kind::IdentityResponse, Code::Response, 0x11, |_| {});
            fr.username = "rist".into();
            fr
        };
        let challenge = {
            let mut fr = frame(Kind::Challenge, Code::Request, 0x22, |_| {});
            fr.salt.clone_from(&salt);
            fr
        };
        let client_key = {
            let mut fr = frame(Kind::ClientKey, Code::Response, 0x22, |_| {});
            fr.public.clone_from(&pub_v);
            fr
        };
        let server_key = {
            let mut fr = frame(Kind::ServerKey, Code::Request, 0x23, |_| {});
            fr.public.clone_from(&pub_v);
            fr
        };
        let client_val = {
            let mut fr = frame(Kind::ClientValidator, Code::Response, 0x23, |_| {});
            fr.proof.clone_from(&proof);
            fr
        };
        let server_val = {
            let mut fr = frame(Kind::ServerValidator, Code::Request, 0x24, |_| {});
            fr.proof.clone_from(&proof);
            fr
        };
        let mut id_resp_want = vec![0x03, 0x00, 0x00, 0x09, 0x02, 0x11, 0x00, 0x09, 0x01];
        id_resp_want.extend_from_slice(b"rist");
        let chal_body = vec![
            0x13, 0x01, 0x00, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00,
        ];
        let chal_want = {
            let l = (4 + chal_body.len()) as u8;
            let mut w = vec![0x03, 0x00, 0x00, l, 0x01, 0x22, 0x00, l];
            w.extend_from_slice(&chal_body);
            w
        };
        let ck_want = {
            let mut body = vec![0x13, 0x01];
            body.extend_from_slice(&pub_v);
            let l = (4 + body.len()) as u8;
            let mut w = vec![0x03, 0x00, 0x00, l, 0x02, 0x22, 0x00, l];
            w.extend_from_slice(&body);
            w
        };
        let sk_want = {
            let mut body = vec![0x13, 0x02];
            body.extend_from_slice(&pub_v);
            let l = (4 + body.len()) as u8;
            let mut w = vec![0x03, 0x00, 0x00, l, 0x01, 0x23, 0x00, l];
            w.extend_from_slice(&body);
            w
        };
        let cv_want = {
            let mut body = vec![0x13, 0x02, 0, 0, 0, 0];
            body.extend_from_slice(&proof);
            let l = (4 + body.len()) as u8;
            let mut w = vec![0x03, 0x00, 0x00, l, 0x02, 0x23, 0x00, l];
            w.extend_from_slice(&body);
            w
        };
        let sv_want = {
            let mut body = vec![0x13, 0x03, 0, 0, 0, 0];
            body.extend_from_slice(&proof);
            let l = (4 + body.len()) as u8;
            let mut w = vec![0x03, 0x00, 0x00, l, 0x01, 0x24, 0x00, l];
            w.extend_from_slice(&body);
            w
        };
        vec![
            Golden {
                name: "start",
                f: Frame {
                    version: 3,
                    kind: Kind::Start,
                    ..Frame::default()
                },
                want: vec![0x03, 0x01, 0x00, 0x00],
            },
            Golden {
                name: "logoff",
                f: Frame {
                    version: 3,
                    kind: Kind::Logoff,
                    ..Frame::default()
                },
                want: vec![0x03, 0x02, 0x00, 0x00],
            },
            Golden {
                name: "identity-request",
                f: frame(Kind::IdentityRequest, Code::Request, 0x11, |_| {}),
                want: vec![0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x05, 0x01],
            },
            Golden {
                name: "identity-response",
                f: id_resp,
                want: id_resp_want,
            },
            Golden {
                name: "challenge",
                f: challenge,
                want: chal_want,
            },
            Golden {
                name: "client-key",
                f: client_key,
                want: ck_want,
            },
            Golden {
                name: "server-key",
                f: server_key,
                want: sk_want,
            },
            Golden {
                name: "client-validator",
                f: client_val,
                want: cv_want,
            },
            Golden {
                name: "server-validator",
                f: server_val,
                want: sv_want,
            },
            Golden {
                name: "failure",
                f: frame(Kind::Failure, Code::Failure, 0x24, |_| {}),
                want: vec![0x03, 0x00, 0x00, 0x04, 0x04, 0x24, 0x00, 0x04],
            },
        ]
    }

    #[test]
    fn golden_bytes() {
        for g in goldens() {
            let mut got = Vec::new();
            g.f.append_to(&mut got);
            assert_eq!(got, g.want, "{} append", g.name);
            assert_eq!(g.f.marshal_size(), g.want.len(), "{} size", g.name);
        }
    }

    #[test]
    fn round_trip_byte_stable() {
        for g in goldens() {
            let mut wire = Vec::new();
            g.f.append_to(&mut wire);
            let got = Frame::parse(&wire).unwrap();
            let mut re = Vec::new();
            got.append_to(&mut re);
            assert_eq!(re, wire, "{} re-encode stable", g.name);
            assert_eq!(got.kind, g.f.kind, "{} kind", g.name);
            assert_eq!(got.username, g.f.username, "{} username", g.name);
            assert_eq!(got.salt, g.f.salt, "{} salt", g.name);
            assert_eq!(got.public, g.f.public, "{} public", g.name);
            assert_eq!(got.proof, g.f.proof, "{} proof", g.name);
        }
    }

    const KAT_SALT: &str = "72F9D5383B7EB7599FB63028F47475B60A55F313D40E0BE023E026C97C0A2C32";

    /// Drives an in-memory client<->server EAP-SRP handshake, returning the final
    /// roles and the kind transcript.
    fn drive(authee: &mut Authenticatee, auth: &mut Authenticator) -> Vec<Kind> {
        let mut cur = authee.start();
        let mut transcript = vec![cur.kind];
        let mut server_turn = true; // the server receives START first
        for _ in 0..12 {
            let mut wire = Vec::new();
            cur.append_to(&mut wire);
            let reply = if server_turn {
                auth.recv(&wire)
            } else {
                authee.recv(&wire)
            };
            assert!(reply.error.is_none(), "unexpected error: {:?}", reply.error);
            let Some(out) = reply.frame else { break };
            transcript.push(out.kind);
            cur = out;
            server_turn = !server_turn;
        }
        transcript
    }

    #[test]
    fn handshake_success() {
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();

        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt));
        let _transcript = drive(&mut authee, &mut auth);

        assert!(authee.authenticated(), "authenticatee");
        assert!(auth.authenticated(), "authenticator");
        assert!(authee.done() && auth.done());
        let ck = authee.session_key().unwrap();
        assert_eq!(ck, auth.session_key().unwrap(), "session keys agree");
    }

    /// The wire bytes of a reply frame, or `None`.
    fn reply_bytes(r: &Reply) -> Option<Vec<u8>> {
        r.frame.as_ref().map(|f| {
            let mut w = Vec::new();
            f.append_to(&mut w);
            w
        })
    }

    #[test]
    fn retransmitted_frames_replay_idempotently() {
        // Drive the full handshake, but deliver EVERY frame twice (a peer retransmit
        // under loss). The duplicate must replay a byte-identical reply — proving the
        // state machine does not recompute fresh SRP ephemerals on a retransmit — and
        // the handshake must still complete with agreeing session keys.
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();
        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt));

        let mut cur = authee.start();
        let mut server_turn = true; // the authenticator receives START first
        for _ in 0..16 {
            let mut wire = Vec::new();
            cur.append_to(&mut wire);
            let (first, dup) = if server_turn {
                (auth.recv(&wire), auth.recv(&wire))
            } else {
                (authee.recv(&wire), authee.recv(&wire))
            };
            assert!(first.error.is_none() && dup.error.is_none(), "no error");
            assert_eq!(
                reply_bytes(&first),
                reply_bytes(&dup),
                "a retransmitted frame must replay the identical reply"
            );
            let Some(out) = first.frame else { break };
            cur = out;
            server_turn = !server_turn;
        }

        assert!(
            authee.authenticated(),
            "authenticatee authenticated under retransmits"
        );
        assert!(
            auth.authenticated(),
            "authenticator authenticated under retransmits"
        );
        assert_eq!(
            authee.session_key().unwrap(),
            auth.session_key().unwrap(),
            "session keys agree despite duplicated frames"
        );
    }

    #[test]
    fn legacy_handshake_success() {
        // A legacy (srp-compat) authenticator advertises EAPOL version 2; the
        // authenticatee auto-negotiates the legacy unpadded-k/u math from that byte and
        // both reach Success with matching session keys.
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();

        // A legacy authenticator advertises EAPOL version 2 in its IDENTITY REQUEST.
        let mut probe =
            Authenticator::new_legacy(static_verifier(user, verifier.clone(), salt.clone()));
        assert_eq!(
            probe.start().version,
            2,
            "legacy authenticator advertises v2"
        );

        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new_legacy(static_verifier(user, verifier, salt));
        let transcript = drive(&mut authee, &mut auth);
        assert!(
            authee.authenticated() && auth.authenticated(),
            "legacy handshake"
        );
        assert_eq!(
            authee.session_key().unwrap(),
            auth.session_key().unwrap(),
            "legacy session keys agree"
        );
        assert!(
            transcript.contains(&Kind::ServerValidator),
            "full exchange ran"
        );
    }

    #[test]
    fn logoff_after_success_is_refused() {
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();
        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt));
        drive(&mut authee, &mut auth);
        assert!(auth.authenticated());

        // An injected EAPOL-LOGOFF after success must NOT deauthenticate the session.
        let mut logoff = Vec::new();
        Frame {
            version: EAP_VERSION_3,
            kind: Kind::Logoff,
            ..Frame::default()
        }
        .append_to(&mut logoff);
        let _ = auth.recv(&logoff);
        assert!(
            auth.authenticated(),
            "LOGOFF after success must be refused (off-path deauth)"
        );
    }

    /// A session can re-authenticate after Success: the client `restart`s and re-opens
    /// with EAPOL-START, the server (already Success) accepts it as a re-auth and
    /// re-runs the exchange, and both reach Success again with a FRESH session key (the
    /// replay-proof identity proof the NAT-rebind re-association relies on).
    #[test]
    fn reauth_after_success_rolls_the_session_key() {
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();
        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt));
        drive(&mut authee, &mut auth);
        assert!(
            authee.authenticated() && auth.authenticated(),
            "first handshake"
        );
        let k1 = authee.session_key().unwrap();

        authee.restart();
        drive(&mut authee, &mut auth);
        assert!(
            authee.authenticated() && auth.authenticated(),
            "re-auth must re-authenticate both roles"
        );
        let k2 = authee.session_key().unwrap();
        assert_eq!(
            k2,
            auth.session_key().unwrap(),
            "re-auth session keys agree"
        );
        assert_ne!(
            k1, k2,
            "re-auth must roll the session key (fresh SRP nonces)"
        );
    }

    /// The re-auth gate: an authenticatee in Success ignores a CHALLENGE arriving with
    /// no fresh IDENTITY REQUEST (a replay must not knock a live session out of
    /// Success), while a genuine IDENTITY REQUEST resets it cleanly for a re-auth.
    #[test]
    fn authenticatee_rejects_stale_reauth_frames() {
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();
        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt.clone()));
        drive(&mut authee, &mut auth);
        assert!(authee.authenticated(), "setup");

        // An in-window CHALLENGE injected into Success must be ignored.
        let mut stale = Vec::new();
        Frame {
            version: EAP_VERSION_3,
            code: Code::Request,
            identifier: authee.id.wrapping_add(1),
            kind: Kind::Challenge,
            salt,
            ..Frame::default()
        }
        .append_to(&mut stale);
        let r = authee.recv(&stale);
        assert!(
            r.frame.is_none() && r.error.is_none(),
            "stale CHALLENGE must be ignored"
        );
        assert!(
            authee.authenticated(),
            "stale CHALLENGE knocked us out of Success"
        );

        // A genuine IDENTITY REQUEST is a re-auth: reset and answered with a RESPONSE.
        let mut req = Vec::new();
        Frame {
            version: EAP_VERSION_3,
            code: Code::Request,
            identifier: 9,
            kind: Kind::IdentityRequest,
            ..Frame::default()
        }
        .append_to(&mut req);
        let r = authee.recv(&req);
        assert!(
            matches!(&r.frame, Some(f) if f.kind == Kind::IdentityResponse),
            "re-auth IDENTITY REQUEST must be answered with an IDENTITY RESPONSE"
        );
        assert!(!authee.authenticated(), "re-auth must leave Success");
    }

    /// A replayed/forged EAP-FAILURE cannot knock a live session out of Success for
    /// EITHER role, even echoing the last identifier — EAPOL is unencrypted, so a
    /// FAILURE is trivially forgeable.
    #[test]
    fn replayed_failure_cannot_tear_down_success() {
        let (user, pass) = ("rist", "mainprofile");
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, pass, &salt).unwrap();
        let mut authee = Authenticatee::new(user, pass).unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt));
        drive(&mut authee, &mut auth);
        assert!(authee.authenticated() && auth.authenticated(), "setup");

        let fail = |id: u8| {
            let mut w = Vec::new();
            Frame {
                version: EAP_VERSION_3,
                code: Code::Failure,
                identifier: id,
                kind: Kind::Failure,
                ..Frame::default()
            }
            .append_to(&mut w);
            w
        };
        for id in [
            authee.id,
            authee.id.wrapping_add(1),
            authee.id.wrapping_sub(1),
        ] {
            assert!(authee.recv(&fail(id)).frame.is_none());
            assert!(
                authee.authenticated(),
                "authenticatee torn down by FAILURE(id={id})"
            );
        }
        for id in [auth.id, auth.id.wrapping_add(1), auth.id.wrapping_sub(1)] {
            assert!(auth.recv(&fail(id)).frame.is_none());
            assert!(
                auth.authenticated(),
                "authenticator torn down by FAILURE(id={id})"
            );
        }
    }

    #[test]
    fn authenticatee_ignores_out_of_sequence_request() {
        let mut authee = Authenticatee::new("rist", "mainprofile").unwrap();
        // Bootstrap the identifier sequence with an IDENTITY_REQUEST (id = 7).
        let mut id_req = Vec::new();
        Frame {
            version: EAP_VERSION_3,
            code: Code::Request,
            identifier: 7,
            kind: Kind::IdentityRequest,
            ..Frame::default()
        }
        .append_to(&mut id_req);
        assert!(
            authee.recv(&id_req).frame.is_some(),
            "identity request answered"
        );
        assert_eq!(authee.state(), State::InProgress);

        // An injected CHALLENGE with an out-of-sequence identifier must be ignored:
        // no reply, no error, and no state change — it cannot poison the identifier
        // or prime a spoofed-FAILURE DoS.
        let mut bad = Vec::new();
        Frame {
            version: EAP_VERSION_3,
            code: Code::Request,
            identifier: 99,
            kind: Kind::Challenge,
            salt: vec![1u8; 32],
            public: vec![2u8; 256],
            ..Frame::default()
        }
        .append_to(&mut bad);
        let reply = authee.recv(&bad);
        assert!(
            reply.frame.is_none() && reply.error.is_none(),
            "out-of-sequence challenge must be silently ignored"
        );
        assert_eq!(
            authee.state(),
            State::InProgress,
            "the injected frame must not change state"
        );
    }

    #[test]
    fn handshake_wrong_password() {
        let user = "rist";
        let salt = hx(KAT_SALT);
        let verifier = srp::make_verifier(&srp::default_group(), user, "rightpass", &salt).unwrap();
        let mut authee = Authenticatee::new(user, "wrongpass").unwrap();
        let mut auth = Authenticator::new(static_verifier(user, verifier, salt));

        let mut cur = authee.start();
        let mut server_turn = true;
        let mut fail_seen = false;
        for _ in 0..12 {
            let mut wire = Vec::new();
            cur.append_to(&mut wire);
            let reply = if server_turn {
                auth.recv(&wire)
            } else {
                authee.recv(&wire)
            };
            if reply.error.is_some() {
                fail_seen = true;
                // Deliver the server's EAP-FAILURE to the client too.
                if let Some(out) = reply.frame {
                    let mut w = Vec::new();
                    out.append_to(&mut w);
                    authee.recv(&w);
                }
                break;
            }
            let Some(out) = reply.frame else { break };
            cur = out;
            server_turn = !server_turn;
        }
        assert!(fail_seen, "expected an auth failure");
        assert_eq!(auth.state(), State::Failed);
        assert!(!auth.authenticated());
        assert!(!authee.authenticated());
        assert!(auth.session_key().is_none());
    }

    #[test]
    fn handshake_unknown_user() {
        let mut auth = Authenticator::new(static_verifier("known", vec![1], vec![2]));
        let mut authee = Authenticatee::new("stranger", "pw").unwrap();
        let start = authee.start();
        let mut w = Vec::new();
        start.append_to(&mut w);
        let id_req = auth.recv(&w).frame.expect("id request");
        let mut w = Vec::new();
        id_req.append_to(&mut w);
        let id_resp = authee.recv(&w).frame.expect("id response");
        let mut w = Vec::new();
        id_resp.append_to(&mut w);
        let reply = auth.recv(&w);
        assert_eq!(reply.error, Some(EapError::NoVerifier));
        assert_eq!(auth.state(), State::Failed);
    }

    #[test]
    fn parse_rejects_truncated() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x03],
            &[0x03, 0x00, 0x00, 0x05], // claims 5 body bytes, none present
            &[0x03, 0x00, 0x00, 0x02, 0x01, 0x11],
            &[0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x09, 0x01], // eap len mismatch
            &[0x03, 0x09, 0x00, 0x00],                               // unknown eapol type
            &[0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x05, 0x13], // srp truncated
            &[0x03, 0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x05, 0x07], // unknown method
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(Frame::parse(c).is_err(), "case {i} must error");
        }
    }

    #[test]
    fn parse_challenge_bounds() {
        // name_len overruns the buffer.
        let wire = wrap_srp(Code::Request, 0x01, &[0x13, 0x01, 0xFF, 0xFF]);
        assert!(Frame::parse(&wire).is_err());
        // Valid name_len=0 but salt_len overruns.
        let wire = wrap_srp(Code::Request, 0x01, &[0x13, 0x01, 0x00, 0x00, 0x00, 0x10]);
        assert!(Frame::parse(&wire).is_err());
    }

    fn wrap_srp(code: Code, id: u8, body: &[u8]) -> Vec<u8> {
        let eap_len = (EAP_HDR_SIZE + body.len()) as u16;
        let mut out = vec![0x03, 0x00];
        out.extend_from_slice(&eap_len.to_be_bytes());
        out.push(code.to_u8());
        out.push(id);
        out.extend_from_slice(&eap_len.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn parse_does_not_alias() {
        let f = Frame {
            version: 3,
            code: Code::Response,
            identifier: 1,
            kind: Kind::IdentityResponse,
            username: "abc".into(),
            ..Frame::default()
        };
        let mut wire = Vec::new();
        f.append_to(&mut wire);
        let got = Frame::parse(&wire).unwrap();
        wire.fill(0);
        assert_eq!(got.username, "abc");
    }

    #[test]
    fn challenge_group_rejects_explicit() {
        let f = Frame {
            kind: Kind::Challenge,
            salt: vec![1, 2, 3, 4],
            gen_g: vec![2],
            gen_n: vec![0xFF; 256],
            ..Frame::default()
        };
        assert_eq!(challenge_group(&f).unwrap_err(), EapError::UnsupportedGroup);
    }

    #[test]
    fn empty_and_long_credentials_rejected() {
        assert_eq!(
            Authenticatee::new("", "p").err(),
            Some(EapError::EmptyCredentials)
        );
        assert_eq!(
            Authenticatee::new("u", "").err(),
            Some(EapError::EmptyCredentials)
        );
        let long = "x".repeat(256);
        assert_eq!(
            Authenticatee::new(&long, "p").err(),
            Some(EapError::CredentialsTooLong)
        );
    }
}
