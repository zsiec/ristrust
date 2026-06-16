//! RIST Advanced Profile (VSF TR-06-3:2024) tunnel packet header codec, byte-exact
//! with libRIST v0.2.18-rc1. Ported from ristgo `internal/adv`.
//!
//! An Advanced Profile packet is a standard RTP packet (a fixed 12-byte header with
//! payload type 127 and a 1 MHz timestamp clock), optionally followed by a classic
//! RFC 3550 RTP header extension (present only when the RTP X bit is set), then the
//! ALWAYS-PRESENT four-byte profile-defined extension:
//!
//! ```text
//! seq_ext (16, big-endian) | flags (8) | params (8)
//! ```
//!
//! The flags byte carries F (first fragment), L (last fragment), E (expedite),
//! R (retransmit), I (flow id present), P (PFD present), H (RIST header extension
//! present), and the most-significant bit of the 3-bit PSK field. The params byte
//! carries the low two bits of the PSK field, the 2-bit LPC mode, and the 4-bit
//! encapsulation Type. Optional fixed fields follow in a strict order:
//!
//! ```text
//! Flow ID (4 B, if I=1) -> PSK Hash (16 B) -> PSK Nonce (4 B) -> PSK IV (4 B)
//!   [each per the PSK mode] -> Payload Compression (4 B, if LPC==3) ->
//!   Payload Format Descriptor (4 B, if P=1) -> RIST Header Extension
//!   (variable, if H=1) -> Payload.
//! ```
//!
//! This codec frames and deframes the header and carries the (already processed)
//! payload only. The PSK Hash/Nonce/IV and the Compression field are opaque
//! pass-through bytes: encryption ([`crypto`](crate::crypto)) and compression
//! ([`lpc`](crate::lpc)) are performed by other modules. The 32-bit sequence number
//! is split across the RTP seq (low 16) and seq_ext (high 16); SSRC parity marks
//! protected (even) versus unprotected (odd) flows.
//!
//! All multi-byte fields are big-endian. Decoding arbitrary bytes returns an error
//! and never panics. [`Parse`](parse)d optional fields alias the input [`Bytes`]
//! (zero-copy).

// Justification: the codec reads/writes fixed-width big-endian fields and packed
// bit subfields (PSK/LPC/Type, the 12-bit inner flow id, the 28-bit PFD value);
// those casts are deliberate and bounded by the field widths.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use bytes::Bytes;

/// Errors returned by the Advanced header codec. `Display` strings are prefixed
/// `"rist: adv: "`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdvError {
    /// The input is too short for the fixed RTP+extension header or an announced
    /// optional field.
    #[error("rist: adv: short buffer: {got} < {need} bytes")]
    ShortBuffer {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// The RTP version field is not 2.
    #[error("rist: adv: RTP version is not 2 (flags {0:#04x})")]
    InvalidVersion(u8),
    /// The RTP payload type is neither 127 nor a dynamic type ≥ 96.
    #[error("rist: adv: RTP payload type {0} not 127 and below 96")]
    InvalidPayloadType(u8),
    /// `enc_type`, `psk_mode`, or `lpc_mode` does not fit its wire field.
    #[error("rist: adv: field out of range: {0}")]
    FieldRange(&'static str),
    /// A control payload or body is too short for its sub-header or fixed fields.
    #[error("rist: adv: short control message: {got} < {need} bytes")]
    ShortControl {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },
}

/// Keep-alive capability bit: Advanced Profile capable (bit 31).
pub const KEEPALIVE_CAP_I: u32 = 1 << 31;
/// Keep-alive capability bit: GRE key-rotation capable (bit 30).
pub const KEEPALIVE_CAP_G: u32 = 1 << 30;
/// Keep-alive capability bit: compression capable (bit 29).
pub const KEEPALIVE_CAP_C: u32 = 1 << 29;

/// The NACK bitmask/range body size: SSRC(4) + PSS(4) + BLP|NALP(4).
const NACK_BODY_SIZE: usize = 12;
/// The RTT echo body size: SSRC(4) + TS MSW(4) + TS LSW(4) + delay(4).
const RTT_ECHO_BODY_SIZE: usize = 16;
/// The keep-alive body size: MAC(6) + Capabilities(4).
const KEEPALIVE_BODY_SIZE: usize = 10;
/// The PSK future-nonce body size: Nonce(4) + KeySize(2) + Reserved(2).
const PSK_NONCE_BODY_SIZE: usize = 8;

/// Bounds the sequences a single range NACK expands to on decode, mirroring
/// libRIST's recovery cap so a corrupt NALP cannot force an unbounded allocation.
const MAX_NACK_DECODE_RANGE: u32 = 10_000;

/// The RTP payload type carried when SDP is not in use: 127 (TR-06-3 §5.2.1).
pub const PAYLOAD_TYPE: u8 = 127;

/// The default RTP timestamp frequency, 1 MHz (TR-06-3 §5.2.1).
pub const CLOCK_HZ: u32 = 1_000_000;

/// The default RTP first byte: V=2, P=0, X=0, CC=0.
const RTP_FLAGS: u8 = 0x80;

/// The lowest dynamic RTP payload type accepted when SDP is in use.
const DYNAMIC_PT_MIN: u8 = 96;

// Flag bits of the profile-defined extension flags byte (bit 7 is the MSB).
/// First-fragment flag.
pub const FLAG_F: u8 = 0x80;
/// Last-fragment flag.
pub const FLAG_L: u8 = 0x40;
/// Expedite flag.
pub const FLAG_E: u8 = 0x20;
/// Retransmit flag.
pub const FLAG_R: u8 = 0x10;
/// Flow-ID-present flag.
pub const FLAG_I: u8 = 0x08;
/// Payload-Format-Descriptor-present flag.
pub const FLAG_P: u8 = 0x04;
/// RIST-Header-Extension-present flag.
pub const FLAG_H: u8 = 0x02;
/// The MSB of the 3-bit PSK field, carried in the flags byte.
const FLAG_PSK2: u8 = 0x01;

// Bit-field layout of the params byte: PSK[1:0] in bits 7-6, LPC[1:0] in bits 5-4,
// Type[3:0] in bits 3-0.
const PSK10_SHIFT: u8 = 6;
const PSK10_MASK: u8 = 0xC0;
const LPC_SHIFT: u8 = 4;
const LPC_MASK: u8 = 0x30;
const TYPE_MASK: u8 = 0x0F;

// Encapsulation Type values (TR-06-3 §5.2.3).
/// Reserved encapsulation type.
pub const TYPE_RESERVED: u8 = 0;
/// IPv4 encapsulation.
pub const TYPE_IPV4: u8 = 1;
/// IPv6 encapsulation.
pub const TYPE_IPV6: u8 = 2;
/// Reduced-overhead UDP encapsulation.
pub const TYPE_REDUCED_UDP: u8 = 3;
/// Control message (Type=4).
pub const TYPE_CONTROL: u8 = 4;
/// Direct media payload (Type=5).
pub const TYPE_DIRECT: u8 = 5;
/// Layer-2 frame encapsulation.
pub const TYPE_LAYER2: u8 = 6;
/// RFC 2784 GRE encapsulation.
pub const TYPE_GRE_RFC2784: u8 = 7;
/// Main-profile GRE encapsulation (the handshake substrate).
pub const TYPE_GRE_MAIN: u8 = 8;

// Pre-shared-key mode values for the PSK[2:0] field (TR-06-3 §5.2.3).
/// No encryption.
pub const PSK_NONE: u8 = 0;
/// AES-CTR, Main-profile compatible.
pub const PSK_AES_CTR: u8 = 1;
/// HMAC-SHA256, no encryption.
pub const PSK_HMAC_SHA256: u8 = 2;
/// AES-CTR + HMAC-SHA256.
pub const PSK_AES_CTR_HMAC: u8 = 3;
/// AES-GCM (spec-only; libRIST rejects).
pub const PSK_AES_GCM: u8 = 4;
/// ChaCha20-Poly1305 (spec-only; libRIST rejects).
pub const PSK_CHACHA20_POLY: u8 = 5;
/// User-defined, no hash.
pub const PSK_USER_NO_HASH: u8 = 6;
/// User-defined, with hash.
pub const PSK_USER_HASH: u8 = 7;
const PSK_MAX_INCL: u8 = 7;

/// The PSK hash field size.
pub const PSK_HASH_SIZE: usize = 16;
/// The PSK nonce field size.
pub const PSK_NONCE_SIZE: usize = 4;
/// The PSK IV field size.
pub const PSK_IV_SIZE: usize = 4;

// Payload-compression mode values for the LPC[1:0] field (TR-06-3 §5.2.3).
/// No compression.
pub const LPC_NONE: u8 = 0;
/// LZ4 compression.
pub const LPC_LZ4: u8 = 1;
/// Reserved compression mode.
pub const LPC_RESERVED: u8 = 2;
/// Compression field present.
pub const LPC_FIELD_PRESENT: u8 = 3;
const LPC_MAX_INCL: u8 = 3;

// Control Index values carried in a Type-Control packet's sub-header (TR-06-3 §5.3).
/// Bitmask NACK control index.
pub const CI_NACK_BITMASK: u16 = 0x0000;
/// Range NACK control index.
pub const CI_NACK_RANGE: u16 = 0x0001;
/// Global Link Quality Message control index.
pub const CI_LQM_GLOBAL: u16 = 0x0002;
/// Per-link Link Quality Message control index.
pub const CI_LQM_LINK_SPECIFIC: u16 = 0x0003;
/// RTT echo request control index.
pub const CI_RTT_ECHO_REQ: u16 = 0x0010;
/// RTT echo response control index.
pub const CI_RTT_ECHO_RESP: u16 = 0x0011;
/// SMPTE ST 2022-5 row FEC control index (in-band Advanced FEC carriage, TR-06-3
/// §5.3.5).
pub const CI_FEC_2022_5_ROW: u16 = 0x0020;
/// SMPTE ST 2022-5 column FEC control index.
pub const CI_FEC_2022_5_COL: u16 = 0x0021;
/// SMPTE ST 2022-1 row FEC control index.
pub const CI_FEC_2022_1_ROW: u16 = 0x0022;
/// SMPTE ST 2022-1 column FEC control index.
pub const CI_FEC_2022_1_COL: u16 = 0x0023;
/// Keepalive control index.
pub const CI_KEEPALIVE: u16 = 0x8000;
/// Flow-attributes control index.
pub const CI_FLOW_ATTR: u16 = 0x8001;
/// SRP-auth control index.
pub const CI_SRP_AUTH: u16 = 0x8010;
/// PSK-nonce control index.
pub const CI_PSK_NONCE: u16 = 0x8011;
/// Unsupported control index.
pub const CI_UNSUPPORTED: u16 = 0x8020;

/// The standard RTP header size.
pub const RTP_SIZE: usize = 12;
/// The profile-defined extension size.
pub const EXT_SIZE: usize = 4;
/// The minimum Advanced Profile header: RTP (12) + ext (4).
pub const HEADER_MIN: usize = RTP_SIZE + EXT_SIZE;
/// The Flow ID field size.
pub const FLOW_ID_SIZE: usize = 4;
/// The Payload Compression field size.
pub const COMPRESSION_SIZE: usize = 4;
/// The Payload Format Descriptor size.
pub const PFD_SIZE: usize = 4;
/// The control-message sub-header size: Control Index (2) + Length (2).
pub const CTRL_HDR_SIZE: usize = 4;

/// The 4-byte header of an RFC 3550 / RIST header extension: 16-bit profile +
/// 16-bit length in 32-bit words.
const RTP_EXT_HDR_SIZE: usize = 4;

/// Whether the given PSK mode carries a 16-byte hash field (modes 2, 3, 4, 5, 7).
#[must_use]
pub fn psk_has_hash(psk: u8) -> bool {
    matches!(
        psk,
        PSK_HMAC_SHA256 | PSK_AES_CTR_HMAC | PSK_AES_GCM | PSK_CHACHA20_POLY | PSK_USER_HASH
    )
}

/// Whether the given PSK mode carries a 4-byte nonce field (any mode ≥ 1).
#[must_use]
pub fn psk_has_nonce(psk: u8) -> bool {
    psk >= PSK_AES_CTR
}

/// Whether the given PSK mode carries a 4-byte IV field (mode 1, or any mode ≥ 3).
#[must_use]
pub fn psk_has_iv(psk: u8) -> bool {
    psk == PSK_AES_CTR || psk >= PSK_AES_CTR_HMAC
}

/// The total number of PSK header bytes (hash + nonce + IV) for the given mode.
#[must_use]
pub fn psk_hdr_size(psk: u8) -> usize {
    let mut sz = 0;
    if psk_has_hash(psk) {
        sz += PSK_HASH_SIZE;
    }
    if psk_has_nonce(psk) {
        sz += PSK_NONCE_SIZE;
    }
    if psk_has_iv(psk) {
        sz += PSK_IV_SIZE;
    }
    sz
}

/// Whether an SSRC denotes a protected (ARQ-eligible) flow: even is protected.
#[must_use]
pub fn ssrc_is_protected(ssrc: u32) -> bool {
    ssrc & 1 == 0
}

/// `ssrc` with its least-significant bit cleared (the protected, even form).
#[must_use]
pub fn ssrc_protected(ssrc: u32) -> u32 {
    ssrc & !1
}

/// `ssrc` with its least-significant bit set (the unprotected, odd form).
#[must_use]
pub fn ssrc_unprotected(ssrc: u32) -> u32 {
    ssrc | 1
}

/// The low-16 and high-16 halves of a 32-bit sequence: low → RTP seq, high →
/// seq_ext.
#[must_use]
pub fn split_seq(seq: u32) -> (u16, u16) {
    (seq as u16, (seq >> 16) as u16)
}

/// Reconstructs a 32-bit sequence from the seq_ext (high 16) and RTP seq (low 16).
#[must_use]
pub fn join_seq(high: u16, low: u16) -> u32 {
    u32::from(high) << 16 | u32::from(low)
}

/// The 4-byte Flow ID field (TR-06-3 §5.2.4): a 16-bit Outer Flow ID, a 12-bit
/// Inner Flow ID, and a 4-bit Inner Flow Sub-ID.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowId {
    /// The 16-bit Outer Flow ID.
    pub outer: u16,
    /// The 12-bit Inner Flow ID (only the low 12 bits are encoded).
    pub inner: u16,
    /// The 4-bit Inner Flow Sub-ID (only the low 4 bits are encoded).
    pub sub: u8,
}

impl FlowId {
    fn append_to(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.outer.to_be_bytes());
        dst.push(((self.inner >> 4) & 0xFF) as u8);
        dst.push(((self.inner & 0x0F) << 4) as u8 | (self.sub & 0x0F));
    }

    fn parse(b: &[u8]) -> FlowId {
        let inner_hi = b[2];
        let inner_lo_sub = b[3];
        FlowId {
            outer: u16::from_be_bytes([b[0], b[1]]),
            inner: u16::from(inner_hi) << 4 | u16::from(inner_lo_sub >> 4),
            sub: inner_lo_sub & 0x0F,
        }
    }
}

/// The 4-byte Payload Format Descriptor (TR-06-3 §5.2.7): a 4-bit ID Type followed
/// by a 28-bit ID Value, packed big-endian.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pfd {
    /// The 4-bit ID Type.
    pub id_type: u8,
    /// The 28-bit ID Value (only the low 28 bits are encoded).
    pub id_value: u32,
}

impl Pfd {
    fn append_to(self, dst: &mut Vec<u8>) {
        let v = u32::from(self.id_type & 0x0F) << 28 | (self.id_value & 0x0FFF_FFFF);
        dst.extend_from_slice(&v.to_be_bytes());
    }

    fn parse(b: &[u8]) -> Pfd {
        let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        Pfd {
            id_type: (v >> 28) as u8,
            id_value: v & 0x0FFF_FFFF,
        }
    }
}

/// Whether the fragment flags denote a complete, unfragmented packet (F and L set).
#[must_use]
pub fn is_unfragmented(flags: u8) -> bool {
    flags & (FLAG_F | FLAG_L) == (FLAG_F | FLAG_L)
}

/// Whether the flags denote a fragment of a larger packet (not unfragmented).
#[must_use]
pub fn is_fragmented(flags: u8) -> bool {
    !is_unfragmented(flags)
}

/// Whether the flags denote a first fragment (F set, L clear).
#[must_use]
pub fn is_first_fragment(flags: u8) -> bool {
    flags & FLAG_F != 0 && flags & FLAG_L == 0
}

/// Whether the flags denote a last fragment (F clear, L set).
#[must_use]
pub fn is_last_fragment(flags: u8) -> bool {
    flags & FLAG_F == 0 && flags & FLAG_L != 0
}

/// The input model for [`build`]. Optional fields are `None`/empty to omit, except
/// the PSK fields, whose presence is derived from `psk_mode` (a `None` field that
/// the mode requires is written as zero bytes).
// Justification: F/L/E/R and the optional-field presence flags are independent
// wire bits, a faithful 1:1 model of the header — not a collapsible state enum.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct Params {
    /// The full 32-bit sequence number (split into RTP seq + seq_ext).
    pub seq: u32,
    /// The 32-bit RTP timestamp (1 MHz clock).
    pub timestamp: u32,
    /// The flow SSRC; even = protected, odd = unprotected.
    pub ssrc: u32,
    /// The 4-bit encapsulation Type (a `TYPE_*` constant).
    pub enc_type: u8,
    /// The 3-bit PSK mode (a `PSK_*` constant).
    pub psk_mode: u8,
    /// The 2-bit payload-compression mode (an `LPC_*` constant).
    pub lpc_mode: u8,
    /// Sets the F flag.
    pub first_frag: bool,
    /// Sets the L flag.
    pub last_frag: bool,
    /// Sets the E flag.
    pub expedite: bool,
    /// Sets the R flag.
    pub retransmit: bool,
    /// When set, encoded and sets the I flag.
    pub flow_id: Option<FlowId>,
    /// Opaque PSK hash bytes; emitted (zero-filled when `None`) when the mode carries
    /// a hash.
    pub psk_hash: Option<[u8; PSK_HASH_SIZE]>,
    /// Opaque PSK nonce bytes; emitted when the mode carries a nonce.
    pub psk_nonce: Option<[u8; PSK_NONCE_SIZE]>,
    /// Opaque PSK IV bytes; emitted when the mode carries an IV.
    pub psk_iv: Option<[u8; PSK_IV_SIZE]>,
    /// Opaque Payload Compression bytes; emitted when `lpc_mode == LPC_FIELD_PRESENT`.
    pub compression: Option<[u8; COMPRESSION_SIZE]>,
    /// When set, encoded and sets the P flag.
    pub pfd: Option<Pfd>,
    /// The RIST Header Extension copied verbatim (sets the H flag); empty to omit.
    pub hdr_ext: Vec<u8>,
}

/// The output model for [`parse`]. Optional slice fields alias the input [`Bytes`]
/// and are `None` when the corresponding field is absent.
// Justification: as `Params` — a faithful 1:1 model of the header's independent bits.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The full 32-bit sequence number.
    pub seq: u32,
    /// The 32-bit RTP timestamp.
    pub timestamp: u32,
    /// The flow SSRC.
    pub ssrc: u32,
    /// The RTP X bit: an RFC 3550 header extension preceded the profile extension.
    pub rtp_ext_present: bool,
    /// The RTP P bit.
    pub rtp_padding: bool,
    /// The F flag.
    pub first_frag: bool,
    /// The L flag.
    pub last_frag: bool,
    /// The E flag.
    pub expedite: bool,
    /// The R flag.
    pub retransmit: bool,
    /// The parsed 3-bit PSK mode.
    pub psk_mode: u8,
    /// The parsed 2-bit LPC mode.
    pub lpc_mode: u8,
    /// The parsed 4-bit encapsulation Type.
    pub enc_type: u8,
    /// The decoded Flow ID, when the I flag was set.
    pub flow_id: Option<FlowId>,
    /// The PSK hash field, aliasing the input, when the mode carries it.
    pub psk_hash: Option<Bytes>,
    /// The PSK nonce field, aliasing the input, when the mode carries it.
    pub psk_nonce: Option<Bytes>,
    /// The PSK IV field, aliasing the input, when the mode carries it.
    pub psk_iv: Option<Bytes>,
    /// The Payload Compression field, aliasing the input, when `lpc_mode == 3`.
    pub compression: Option<Bytes>,
    /// The decoded Payload Format Descriptor, when the P flag was set.
    pub pfd: Option<Pfd>,
    /// The RIST Header Extension (including its 4-byte header), aliasing the input,
    /// when the H flag was set.
    pub hdr_ext: Option<Bytes>,
    /// The remaining payload bytes, aliasing the input.
    pub payload: Bytes,
}

/// The number of header bytes [`build`] will write for `params`, excluding the
/// payload.
#[must_use]
pub fn header_size(params: &Params) -> usize {
    let mut sz = HEADER_MIN;
    if params.flow_id.is_some() {
        sz += FLOW_ID_SIZE;
    }
    sz += psk_hdr_size(params.psk_mode);
    if params.lpc_mode == LPC_FIELD_PRESENT {
        sz += COMPRESSION_SIZE;
    }
    if params.pfd.is_some() {
        sz += PFD_SIZE;
    }
    sz + params.hdr_ext.len()
}

/// Appends `b` (when `Some`) or `size` zero bytes (when `None`) to `dst`.
fn append_or_zero(dst: &mut Vec<u8>, b: Option<&[u8]>, size: usize) {
    match b {
        Some(b) => dst.extend_from_slice(b),
        None => dst.resize(dst.len() + size, 0),
    }
}

/// Appends a complete Advanced Profile packet (header + payload) to `dst`. The RTP
/// header always carries V=2, PT=127, the 1 MHz timestamp and SSRC; the
/// profile-defined extension carries the split sequence number, the F/L/E/R flags,
/// and the PSK/LPC/Type fields. Optional fields are emitted in spec order.
#[allow(clippy::too_many_lines)] // one flat header-emission sequence
pub fn build(dst: &mut Vec<u8>, params: &Params, payload: &[u8]) -> Result<(), AdvError> {
    if params.enc_type > TYPE_MASK {
        return Err(AdvError::FieldRange("enc_type exceeds 4-bit field"));
    }
    if params.psk_mode > PSK_MAX_INCL {
        return Err(AdvError::FieldRange("psk_mode exceeds 3-bit field"));
    }
    if params.lpc_mode > LPC_MAX_INCL {
        return Err(AdvError::FieldRange("lpc_mode exceeds 2-bit field"));
    }

    let (low, high) = split_seq(params.seq);

    // RTP header (12 bytes): flags, PT, seq(low), timestamp, ssrc.
    dst.push(RTP_FLAGS);
    dst.push(PAYLOAD_TYPE);
    dst.extend_from_slice(&low.to_be_bytes());
    dst.extend_from_slice(&params.timestamp.to_be_bytes());
    dst.extend_from_slice(&params.ssrc.to_be_bytes());

    // Profile-defined extension (4 bytes): seq_ext, flags, params.
    dst.extend_from_slice(&high.to_be_bytes());

    let mut flags = 0u8;
    if params.first_frag {
        flags |= FLAG_F;
    }
    if params.last_frag {
        flags |= FLAG_L;
    }
    if params.expedite {
        flags |= FLAG_E;
    }
    if params.retransmit {
        flags |= FLAG_R;
    }
    if params.flow_id.is_some() {
        flags |= FLAG_I;
    }
    if params.pfd.is_some() {
        flags |= FLAG_P;
    }
    if !params.hdr_ext.is_empty() {
        flags |= FLAG_H;
    }
    flags |= (params.psk_mode >> 2) & FLAG_PSK2;
    dst.push(flags);

    let pb = (params.psk_mode & 0x03) << PSK10_SHIFT
        | (params.lpc_mode & 0x03) << LPC_SHIFT
        | (params.enc_type & TYPE_MASK);
    dst.push(pb);

    // Optional fields in spec order.
    if let Some(f) = params.flow_id {
        f.append_to(dst);
    }
    if psk_has_hash(params.psk_mode) {
        append_or_zero(
            dst,
            params
                .psk_hash
                .as_ref()
                .map(<[u8; PSK_HASH_SIZE]>::as_slice),
            PSK_HASH_SIZE,
        );
    }
    if psk_has_nonce(params.psk_mode) {
        append_or_zero(
            dst,
            params
                .psk_nonce
                .as_ref()
                .map(<[u8; PSK_NONCE_SIZE]>::as_slice),
            PSK_NONCE_SIZE,
        );
    }
    if psk_has_iv(params.psk_mode) {
        append_or_zero(
            dst,
            params.psk_iv.as_ref().map(<[u8; PSK_IV_SIZE]>::as_slice),
            PSK_IV_SIZE,
        );
    }
    if params.lpc_mode == LPC_FIELD_PRESENT {
        append_or_zero(
            dst,
            params
                .compression
                .as_ref()
                .map(<[u8; COMPRESSION_SIZE]>::as_slice),
            COMPRESSION_SIZE,
        );
    }
    if let Some(p) = params.pfd {
        p.append_to(dst);
    }
    if !params.hdr_ext.is_empty() {
        dst.extend_from_slice(&params.hdr_ext);
    }
    dst.extend_from_slice(payload);
    Ok(())
}

/// Decodes an Advanced Profile packet from `buf`. It validates the RTP version and
/// payload type, skips any CSRC list and RFC 3550 RTP header extension, decodes the
/// profile-defined extension, then consumes the optional fixed fields in spec
/// order, leaving the remainder as `payload`. All optional slice fields alias `buf`.
#[allow(clippy::too_many_lines)] // one flat header-parsing sequence
pub fn parse(buf: &Bytes) -> Result<Parsed, AdvError> {
    let b = buf.as_ref();
    let short = |need: usize| AdvError::ShortBuffer { got: b.len(), need };
    if b.len() < HEADER_MIN {
        return Err(short(HEADER_MIN));
    }

    let flags0 = b[0];
    if flags0 & 0xC0 != 0x80 {
        return Err(AdvError::InvalidVersion(flags0));
    }
    let pt = b[1] & 0x7F;
    if pt != PAYLOAD_TYPE && pt < DYNAMIC_PT_MIN {
        return Err(AdvError::InvalidPayloadType(pt));
    }

    let mut out = Parsed {
        rtp_padding: flags0 & 0x20 != 0,
        rtp_ext_present: flags0 & 0x10 != 0,
        timestamp: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        ssrc: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        ..Parsed::default()
    };
    let rtp_seq = u16::from_be_bytes([b[2], b[3]]);
    let cc = usize::from(flags0 & 0x0F);

    let mut offset = RTP_SIZE + cc * 4;
    if offset > b.len() {
        return Err(short(offset));
    }

    if out.rtp_ext_present {
        if offset + RTP_EXT_HDR_SIZE > b.len() {
            return Err(short(offset + RTP_EXT_HDR_SIZE));
        }
        let ext_words = usize::from(u16::from_be_bytes([b[offset + 2], b[offset + 3]]));
        offset += RTP_EXT_HDR_SIZE + ext_words * 4;
        if offset > b.len() {
            return Err(short(offset));
        }
    }

    if offset + EXT_SIZE > b.len() {
        return Err(short(offset + EXT_SIZE));
    }
    let seq_ext = u16::from_be_bytes([b[offset], b[offset + 1]]);
    let ext_flags = b[offset + 2];
    let ext_params = b[offset + 3];
    offset += EXT_SIZE;

    out.seq = join_seq(seq_ext, rtp_seq);
    out.first_frag = ext_flags & FLAG_F != 0;
    out.last_frag = ext_flags & FLAG_L != 0;
    out.expedite = ext_flags & FLAG_E != 0;
    out.retransmit = ext_flags & FLAG_R != 0;
    let has_flow_id = ext_flags & FLAG_I != 0;
    let has_pfd = ext_flags & FLAG_P != 0;
    let has_hdr_ext = ext_flags & FLAG_H != 0;

    out.psk_mode = (ext_flags & FLAG_PSK2) << 2 | (ext_params & PSK10_MASK) >> PSK10_SHIFT;
    out.lpc_mode = (ext_params & LPC_MASK) >> LPC_SHIFT;
    out.enc_type = ext_params & TYPE_MASK;

    if has_flow_id {
        if offset + FLOW_ID_SIZE > b.len() {
            return Err(short(offset + FLOW_ID_SIZE));
        }
        out.flow_id = Some(FlowId::parse(&b[offset..offset + FLOW_ID_SIZE]));
        offset += FLOW_ID_SIZE;
    }

    let mut take = |out_field: &mut Option<Bytes>, size: usize| -> Result<(), AdvError> {
        if offset + size > b.len() {
            return Err(AdvError::ShortBuffer {
                got: b.len(),
                need: offset + size,
            });
        }
        *out_field = Some(buf.slice(offset..offset + size));
        offset += size;
        Ok(())
    };

    if psk_has_hash(out.psk_mode) {
        take(&mut out.psk_hash, PSK_HASH_SIZE)?;
    }
    if psk_has_nonce(out.psk_mode) {
        take(&mut out.psk_nonce, PSK_NONCE_SIZE)?;
    }
    if psk_has_iv(out.psk_mode) {
        take(&mut out.psk_iv, PSK_IV_SIZE)?;
    }
    if out.lpc_mode == LPC_FIELD_PRESENT {
        take(&mut out.compression, COMPRESSION_SIZE)?;
    }

    if has_pfd {
        if offset + PFD_SIZE > b.len() {
            return Err(short(offset + PFD_SIZE));
        }
        out.pfd = Some(Pfd::parse(&b[offset..offset + PFD_SIZE]));
        offset += PFD_SIZE;
    }

    if has_hdr_ext {
        if offset + RTP_EXT_HDR_SIZE > b.len() {
            return Err(short(offset + RTP_EXT_HDR_SIZE));
        }
        let hdr_words = usize::from(u16::from_be_bytes([b[offset + 2], b[offset + 3]]));
        let total = RTP_EXT_HDR_SIZE + hdr_words * 4;
        if offset + total > b.len() {
            return Err(short(offset + total));
        }
        out.hdr_ext = Some(buf.slice(offset..offset + total));
        offset += total;
    }

    out.payload = buf.slice(offset..);
    Ok(out)
}

// ---- Type=4 control messages (TR-06-3 §5.3) ----
//
// Every control message travels inside a Type=Control packet whose payload is a
// 4-byte sub-header `| Control Index (16) | Length (16) | body... |` followed by a
// per-index body. The Length field counts the body only. libRIST emits exactly one
// entry per NACK datagram and reads only the first 12-byte entry, so the NACK
// encoders return a slice of single-entry messages (one datagram each).

/// Appends one control message — the CI(2) + Length(2) sub-header followed by
/// `body` — to `dst`. Length is set to `body.len()`.
pub fn build_control(dst: &mut Vec<u8>, ci: u16, body: &[u8]) {
    dst.extend_from_slice(&ci.to_be_bytes());
    dst.extend_from_slice(&(body.len() as u16).to_be_bytes());
    dst.extend_from_slice(body);
}

/// Frames a Control Message Unsupported Response (`CI_UNSUPPORTED`, TR-06-3
/// §5.3.10): the 16-byte body is Responder SSRC(4), the unrecognized incoming CI(2),
/// Reserved(2), the first 48 bits of the offending body (`head`, zero-padded), and
/// Padding(2). (libRIST under-stamps its Length field as 12 while writing 16 bytes;
/// ristrust stamps the honest 16 via [`build_control`], which libRIST still parses.)
pub fn build_unsupported(dst: &mut Vec<u8>, responder_ssrc: u32, incoming_ci: u16, head: [u8; 6]) {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&responder_ssrc.to_be_bytes());
    body.extend_from_slice(&incoming_ci.to_be_bytes());
    body.extend_from_slice(&[0, 0]); // reserved
    body.extend_from_slice(&head);
    body.extend_from_slice(&[0, 0]); // padding to a 32-bit boundary
    build_control(dst, CI_UNSUPPORTED, &body);
}

/// Decodes a Type=4 control payload's sub-header, returning the control index and
/// the body (aliasing `payload`). A Length exceeding the available bytes is an
/// error; a Length shorter than the trailing bytes is tolerated (the body is
/// trimmed), accepting libRIST's Unsupported-message length quirk.
pub fn parse_control(payload: &Bytes) -> Result<(u16, Bytes), AdvError> {
    let b = payload.as_ref();
    if b.len() < CTRL_HDR_SIZE {
        return Err(AdvError::ShortControl {
            got: b.len(),
            need: CTRL_HDR_SIZE,
        });
    }
    let ci = u16::from_be_bytes([b[0], b[1]]);
    let body_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
    if CTRL_HDR_SIZE + body_len > b.len() {
        return Err(AdvError::ShortControl {
            got: b.len(),
            need: CTRL_HDR_SIZE + body_len,
        });
    }
    Ok((ci, payload.slice(CTRL_HDR_SIZE..CTRL_HDR_SIZE + body_len)))
}

/// A NACK Bitmask control body (TR-06-3 §5.3.2): a media SSRC, a start sequence
/// (PSS), and a 32-bit lost bitmask (BLP) where bit i marks PSS+1+i missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NackBitmask {
    /// The media stream the missing sequences belong to.
    pub media_ssrc: u32,
    /// The always-requested packet start sequence (full 32-bit).
    pub pss: u32,
    /// The bitmask of additional lost packets: bit i marks PSS+1+i.
    pub blp: u32,
}

impl NackBitmask {
    fn append_body(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.media_ssrc.to_be_bytes());
        dst.extend_from_slice(&self.pss.to_be_bytes());
        dst.extend_from_slice(&self.blp.to_be_bytes());
    }

    /// The sorted list of missing sequences this requests: PSS plus PSS+1+i for
    /// each set bit i.
    #[must_use]
    pub fn missing(self) -> Vec<u32> {
        let mut out = Vec::with_capacity(33);
        out.push(self.pss);
        for i in 0..32u32 {
            if self.blp & (1 << i) != 0 {
                out.push(self.pss.wrapping_add(1 + i));
            }
        }
        out
    }

    /// Decodes a NACK Bitmask body (≥ 12 bytes; trailing bytes ignored).
    pub fn parse(body: &[u8]) -> Result<NackBitmask, AdvError> {
        if body.len() < NACK_BODY_SIZE {
            return Err(AdvError::ShortControl {
                got: body.len(),
                need: NACK_BODY_SIZE,
            });
        }
        Ok(NackBitmask {
            media_ssrc: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            pss: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            blp: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        })
    }
}

/// A NACK Range control body (TR-06-3 §5.3.3): a media SSRC, a start sequence
/// (PSS), and a count of additional lost packets (NALP), covering PSS..=PSS+NALP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NackRange {
    /// The media stream the missing sequences belong to.
    pub media_ssrc: u32,
    /// The first missing sequence number (full 32-bit).
    pub pss: u32,
    /// The number of additional consecutive missing packets after PSS.
    pub nalp: u32,
}

impl NackRange {
    fn append_body(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.media_ssrc.to_be_bytes());
        dst.extend_from_slice(&self.pss.to_be_bytes());
        dst.extend_from_slice(&self.nalp.to_be_bytes());
    }

    /// The sorted list PSS..=PSS+NALP, clamped to libRIST's recovery cap.
    #[must_use]
    pub fn missing(self) -> Vec<u32> {
        let count = self.nalp.min(MAX_NACK_DECODE_RANGE);
        (0..=count).map(|i| self.pss.wrapping_add(i)).collect()
    }

    /// Decodes a NACK Range body (≥ 12 bytes; trailing bytes ignored).
    pub fn parse(body: &[u8]) -> Result<NackRange, AdvError> {
        if body.len() < NACK_BODY_SIZE {
            return Err(AdvError::ShortControl {
                got: body.len(),
                need: NACK_BODY_SIZE,
            });
        }
        Ok(NackRange {
            media_ssrc: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            pss: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            nalp: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        })
    }
}

/// Sorts a missing-sequence list in ascending circular (wrap-aware) order: by the
/// signed 32-bit distance from the first element, so a window straddling the 2^32
/// wrap stays one consecutive run.
fn sort_seqs_wrap(s: &mut [u32]) {
    if let Some(&pivot) = s.first() {
        // The signed wrap is the point: ordering by the i32 distance from the pivot
        // keeps a window straddling the 2^32 wrap as one ascending run.
        #[allow(clippy::cast_possible_wrap)]
        s.sort_by_key(|&x| x.wrapping_sub(pivot) as i32);
    }
}

/// Packs a missing-sequence list into NACK Bitmask entries (one datagram each),
/// each covering a 33-sequence window [PSS, PSS+32]. `missing` need not be sorted;
/// duplicates are tolerated.
#[must_use]
pub fn encode_bitmask_nack(media_ssrc: u32, missing: &[u32]) -> Vec<NackBitmask> {
    if missing.is_empty() {
        return Vec::new();
    }
    let mut s = missing.to_vec();
    sort_seqs_wrap(&mut s);
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let pss = s[i];
        let mut blp = 0u32;
        let mut j = i + 1;
        while j < s.len() {
            let delta = s[j].wrapping_sub(pss);
            if delta == 0 {
                j += 1; // duplicate of PSS
                continue;
            }
            if delta > 32 {
                break;
            }
            blp |= 1 << (delta - 1);
            j += 1;
        }
        out.push(NackBitmask {
            media_ssrc,
            pss,
            blp,
        });
        i = j;
    }
    out
}

/// Packs a missing-sequence list into NACK Range entries (one datagram each), one
/// per maximal run of consecutive sequences. A run longer than the recovery cap is
/// split so the peer recovers every sequence.
#[must_use]
pub fn encode_range_nack(media_ssrc: u32, missing: &[u32]) -> Vec<NackRange> {
    if missing.is_empty() {
        return Vec::new();
    }
    let mut s = missing.to_vec();
    sort_seqs_wrap(&mut s);
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let pss = s[i];
        let mut j = i;
        while j + 1 < s.len() {
            let next = s[j + 1];
            if next == s[j] {
                j += 1; // duplicate
                continue;
            }
            if next != s[j].wrapping_add(1) {
                break; // gap: run ends
            }
            // Break at >= cap so the emitted NALP stays at cap-1 (a libRIST receiver
            // recovers only while i < MAX_NACK_DECODE_RANGE).
            if next.wrapping_sub(pss) >= MAX_NACK_DECODE_RANGE {
                break;
            }
            j += 1;
        }
        out.push(NackRange {
            media_ssrc,
            pss,
            nalp: s[j].wrapping_sub(pss),
        });
        i = j + 1;
    }
    out
}

/// The body shared by the RTT Echo Request and Response (TR-06-3 §5.3.4): the
/// requester's SSRC, a 64-bit timestamp (split into MSW/LSW), and a processing
/// delay in microseconds (zero in a request).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttEcho {
    /// The SSRC of the peer that issued the request.
    pub requester_ssrc: u32,
    /// The high 32 bits of the originator's 64-bit timestamp.
    pub timestamp_msw: u32,
    /// The low 32 bits of the originator's 64-bit timestamp.
    pub timestamp_lsw: u32,
    /// The responder's request-to-response delay in microseconds (zero in a request).
    pub processing_delay: u32,
}

impl RttEcho {
    /// The originator's 64-bit timestamp (MSW<<32 | LSW).
    #[must_use]
    pub fn timestamp(self) -> u64 {
        u64::from(self.timestamp_msw) << 32 | u64::from(self.timestamp_lsw)
    }

    /// Builds an [`RttEcho`] from a 64-bit timestamp.
    #[must_use]
    pub fn from_timestamp(requester_ssrc: u32, ts: u64, processing_delay: u32) -> RttEcho {
        RttEcho {
            requester_ssrc,
            timestamp_msw: (ts >> 32) as u32,
            timestamp_lsw: ts as u32,
            processing_delay,
        }
    }

    fn append_body(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.requester_ssrc.to_be_bytes());
        dst.extend_from_slice(&self.timestamp_msw.to_be_bytes());
        dst.extend_from_slice(&self.timestamp_lsw.to_be_bytes());
        dst.extend_from_slice(&self.processing_delay.to_be_bytes());
    }

    /// Decodes a 16-byte RTT echo body (request or response).
    pub fn parse(body: &[u8]) -> Result<RttEcho, AdvError> {
        if body.len() < RTT_ECHO_BODY_SIZE {
            return Err(AdvError::ShortControl {
                got: body.len(),
                need: RTT_ECHO_BODY_SIZE,
            });
        }
        Ok(RttEcho {
            requester_ssrc: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            timestamp_msw: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            timestamp_lsw: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
            processing_delay: u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
        })
    }
}

/// A keep-alive control body (TR-06-3 §5.3.6): a 6-byte MAC and a 32-bit capability
/// word (`KEEPALIVE_CAP_*`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Keepalive {
    /// The originator's 6-byte hardware address (informational).
    pub mac: [u8; 6],
    /// The capability bitmask.
    pub caps: u32,
}

impl Keepalive {
    fn append_body(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.mac);
        dst.extend_from_slice(&self.caps.to_be_bytes());
    }

    /// Decodes a keep-alive body (≥ 10 bytes).
    pub fn parse(body: &[u8]) -> Result<Keepalive, AdvError> {
        if body.len() < KEEPALIVE_BODY_SIZE {
            return Err(AdvError::ShortControl {
                got: body.len(),
                need: KEEPALIVE_BODY_SIZE,
            });
        }
        let mut k = Keepalive {
            caps: u32::from_be_bytes([body[6], body[7], body[8], body[9]]),
            ..Keepalive::default()
        };
        k.mac.copy_from_slice(&body[0..6]);
        Ok(k)
    }
}

/// A PSK future-nonce announcement (TR-06-3 §5.3.9): the 4-byte nonce a sender will
/// rotate to and the AES key size in bits, letting the receiver pre-derive the
/// PBKDF2 key before the first data packet with the new nonce arrives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PskNonce {
    /// The 4-byte future nonce.
    pub nonce: [u8; 4],
    /// The AES key size in bits (128 or 256).
    pub key_bits: u16,
}

impl PskNonce {
    fn append_body(self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.nonce);
        dst.extend_from_slice(&self.key_bits.to_be_bytes());
        dst.extend_from_slice(&[0, 0]); // reserved
    }

    /// Decodes an 8-byte PSK future-nonce body.
    pub fn parse(body: &[u8]) -> Result<PskNonce, AdvError> {
        if body.len() < PSK_NONCE_BODY_SIZE {
            return Err(AdvError::ShortControl {
                got: body.len(),
                need: PSK_NONCE_BODY_SIZE,
            });
        }
        let mut p = PskNonce {
            key_bits: u16::from_be_bytes([body[4], body[5]]),
            ..PskNonce::default()
        };
        p.nonce.copy_from_slice(&body[0..4]);
        Ok(p)
    }
}

/// Frames a NACK Bitmask control payload.
pub fn build_nack_bitmask(dst: &mut Vec<u8>, n: NackBitmask) {
    let mut body = Vec::new();
    n.append_body(&mut body);
    build_control(dst, CI_NACK_BITMASK, &body);
}

/// Frames a NACK Range control payload.
pub fn build_nack_range(dst: &mut Vec<u8>, n: NackRange) {
    let mut body = Vec::new();
    n.append_body(&mut body);
    build_control(dst, CI_NACK_RANGE, &body);
}

/// Frames an RTT Echo Request control payload.
pub fn build_rtt_echo_request(dst: &mut Vec<u8>, e: RttEcho) {
    let mut body = Vec::new();
    e.append_body(&mut body);
    build_control(dst, CI_RTT_ECHO_REQ, &body);
}

/// Frames an RTT Echo Response control payload.
pub fn build_rtt_echo_response(dst: &mut Vec<u8>, e: RttEcho) {
    let mut body = Vec::new();
    e.append_body(&mut body);
    build_control(dst, CI_RTT_ECHO_RESP, &body);
}

/// Frames a keep-alive control payload.
pub fn build_keepalive(dst: &mut Vec<u8>, k: Keepalive) {
    let mut body = Vec::new();
    k.append_body(&mut body);
    build_control(dst, CI_KEEPALIVE, &body);
}

/// Frames a PSK future-nonce control payload.
pub fn build_psk_nonce(dst: &mut Vec<u8>, p: PskNonce) {
    let mut body = Vec::new();
    p.append_body(&mut body);
    build_control(dst, CI_PSK_NONCE, &body);
}

/// Frames a Flow Attribute control payload (TR-06-3 §5.3.7): a UTF-8 JSON body
/// copied verbatim.
pub fn build_flow_attr(dst: &mut Vec<u8>, json: &[u8]) {
    build_control(dst, CI_FLOW_ATTR, json);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Golden {
        name: &'static str,
        params: Params,
        payload: &'static [u8],
        wire: &'static [u8],
    }

    fn goldens() -> Vec<Golden> {
        vec![
            Golden {
                // seq=0x12345678 -> rtp seq 0x5678, seq_ext 0x1234. ts=1000000.
                // ssrc=0xAABBCC00 (even). flags F|L = 0xC0. params Type=DIRECT(5).
                name: "basic-direct",
                params: Params {
                    seq: 0x1234_5678,
                    timestamp: 1_000_000,
                    ssrc: 0xAABB_CC00,
                    enc_type: TYPE_DIRECT,
                    first_frag: true,
                    last_frag: true,
                    ..Params::default()
                },
                payload: &[0xDE, 0xAD],
                wire: &[
                    0x80, 0x7F, 0x56, 0x78, 0x00, 0x0F, 0x42, 0x40, 0xAA, 0xBB, 0xCC, 0x00, 0x12,
                    0x34, 0xC0, 0x05, 0xDE, 0xAD,
                ],
            },
            Golden {
                // PSK mode 1 (AES-CTR): nonce + IV, no hash. PSK2 stays clear.
                name: "psk-aes-ctr",
                params: Params {
                    seq: 0x0000_0001,
                    timestamp: 0,
                    ssrc: 0x0000_0010,
                    enc_type: TYPE_DIRECT,
                    psk_mode: PSK_AES_CTR,
                    first_frag: true,
                    last_frag: true,
                    psk_nonce: Some([0x11, 0x11, 0x11, 0x11]),
                    psk_iv: Some([0x22, 0x22, 0x22, 0x22]),
                    ..Params::default()
                },
                payload: &[0x42],
                wire: &[
                    0x80, 0x7F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
                    0x00, 0xC0, 0x45, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x42,
                ],
            },
        ]
    }

    #[test]
    fn golden_build() {
        for g in goldens() {
            let mut got = Vec::new();
            build(&mut got, &g.params, g.payload).unwrap();
            assert_eq!(got, g.wire, "{} build", g.name);
            assert_eq!(
                header_size(&g.params),
                g.wire.len() - g.payload.len(),
                "{} size",
                g.name
            );
        }
    }

    #[test]
    fn golden_parse() {
        for g in goldens() {
            let p = parse(&Bytes::copy_from_slice(g.wire)).unwrap();
            assert_eq!(p.seq, g.params.seq, "{} seq", g.name);
            assert_eq!(p.timestamp, g.params.timestamp, "{} ts", g.name);
            assert_eq!(p.ssrc, g.params.ssrc, "{} ssrc", g.name);
            assert_eq!(p.enc_type, g.params.enc_type, "{} type", g.name);
            assert_eq!(p.psk_mode, g.params.psk_mode, "{} psk", g.name);
            assert!(p.first_frag && p.last_frag, "{} flags", g.name);
            assert_eq!(p.payload.as_ref(), g.payload, "{} payload", g.name);
        }
    }

    #[test]
    fn flags_round_trip() {
        let params = Params {
            seq: 0xFFFF_0001,
            ssrc: 0x0000_0002, // even
            enc_type: TYPE_CONTROL,
            expedite: true,
            retransmit: true,
            first_frag: true,
            ..Params::default()
        };
        let mut wire = Vec::new();
        build(&mut wire, &params, &[0x01, 0x02, 0x03]).unwrap();
        let p = parse(&Bytes::from(wire)).unwrap();
        assert_eq!(p.seq, 0xFFFF_0001);
        assert!(p.first_frag && !p.last_frag);
        assert!(p.expedite && p.retransmit);
        assert_eq!(p.enc_type, TYPE_CONTROL);
    }

    #[test]
    fn flow_id_and_pfd_round_trip() {
        let params = Params {
            seq: 7,
            ssrc: 0x10,
            enc_type: TYPE_DIRECT,
            first_frag: true,
            last_frag: true,
            flow_id: Some(FlowId {
                outer: 0x1234,
                inner: 0xABC,
                sub: 0x5,
            }),
            pfd: Some(Pfd {
                id_type: 0x3,
                id_value: 0x0AB_CDEF,
            }),
            ..Params::default()
        };
        let mut wire = Vec::new();
        build(&mut wire, &params, &[0xAA]).unwrap();
        let p = parse(&Bytes::from(wire)).unwrap();
        assert_eq!(
            p.flow_id,
            Some(FlowId {
                outer: 0x1234,
                inner: 0xABC,
                sub: 0x5
            })
        );
        assert_eq!(
            p.pfd,
            Some(Pfd {
                id_type: 0x3,
                id_value: 0x0AB_CDEF
            })
        );
        assert_eq!(p.payload.as_ref(), &[0xAA]);
    }

    #[test]
    fn psk_field_presence_table() {
        // (mode, hash, nonce, iv, total)
        let cases: &[(u8, bool, bool, bool, usize)] = &[
            (PSK_NONE, false, false, false, 0),
            (PSK_AES_CTR, false, true, true, 8),
            (PSK_HMAC_SHA256, true, true, false, 20),
            (PSK_AES_CTR_HMAC, true, true, true, 24),
            (PSK_AES_GCM, true, true, true, 24),
            (PSK_CHACHA20_POLY, true, true, true, 24),
            (PSK_USER_NO_HASH, false, true, true, 8),
            (PSK_USER_HASH, true, true, true, 24),
        ];
        for &(mode, hash, nonce, iv, total) in cases {
            assert_eq!(psk_has_hash(mode), hash, "hash {mode}");
            assert_eq!(psk_has_nonce(mode), nonce, "nonce {mode}");
            assert_eq!(psk_has_iv(mode), iv, "iv {mode}");
            assert_eq!(psk_hdr_size(mode), total, "size {mode}");
        }
    }

    #[test]
    fn seq_and_ssrc_helpers() {
        let (low, high) = split_seq(0x1234_5678);
        assert_eq!((low, high), (0x5678, 0x1234));
        assert_eq!(join_seq(0x1234, 0x5678), 0x1234_5678);
        assert!(ssrc_is_protected(0xAABB_CC00));
        assert!(!ssrc_is_protected(0xAABB_CC01));
        assert_eq!(ssrc_protected(0x11), 0x10);
        assert_eq!(ssrc_unprotected(0x10), 0x11);
    }

    #[test]
    fn fragment_flag_helpers() {
        assert!(is_unfragmented(FLAG_F | FLAG_L));
        assert!(!is_fragmented(FLAG_F | FLAG_L));
        assert!(is_first_fragment(FLAG_F));
        assert!(is_last_fragment(FLAG_L));
        assert!(!is_first_fragment(FLAG_F | FLAG_L));
    }

    #[test]
    fn parse_rejects_bad_input() {
        // Too short.
        assert!(matches!(
            parse(&Bytes::from_static(&[0x80, 0x7F])),
            Err(AdvError::ShortBuffer { .. })
        ));
        // Wrong version (V=1).
        let mut wire = vec![0x40, 0x7F];
        wire.extend_from_slice(&[0u8; 14]);
        assert!(matches!(
            parse(&Bytes::from(wire)),
            Err(AdvError::InvalidVersion(_))
        ));
        // Bad PT (< 96, not 127).
        let mut wire = vec![0x80, 0x21];
        wire.extend_from_slice(&[0u8; 14]);
        assert!(matches!(
            parse(&Bytes::from(wire)),
            Err(AdvError::InvalidPayloadType(_))
        ));
    }

    #[test]
    fn build_rejects_out_of_range_fields() {
        let mut dst = Vec::new();
        assert!(matches!(
            build(
                &mut dst,
                &Params {
                    enc_type: 16,
                    ..Params::default()
                },
                &[]
            ),
            Err(AdvError::FieldRange(_))
        ));
        assert!(matches!(
            build(
                &mut dst,
                &Params {
                    psk_mode: 8,
                    ..Params::default()
                },
                &[]
            ),
            Err(AdvError::FieldRange(_))
        ));
        assert!(matches!(
            build(
                &mut dst,
                &Params {
                    lpc_mode: 4,
                    ..Params::default()
                },
                &[]
            ),
            Err(AdvError::FieldRange(_))
        ));
    }

    #[test]
    fn round_trip_with_rtp_ext_skipped() {
        // X bit set: an RFC 3550 header extension precedes the profile extension and
        // must be skipped on parse.
        let mut wire = vec![0x90, 0x7F]; // V=2, X=1
        wire.extend_from_slice(&0x0001u16.to_be_bytes()); // rtp seq
        wire.extend_from_slice(&5u32.to_be_bytes()); // ts
        wire.extend_from_slice(&0x10u32.to_be_bytes()); // ssrc
        // RFC 3550 ext header: profile 0xBEDE, length 1 word, then 4 bytes.
        wire.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD]);
        // profile-defined ext: seq_ext 0, flags F|L, params Type=5.
        wire.extend_from_slice(&[0x00, 0x00, 0xC0, 0x05]);
        wire.push(0x99); // payload
        let p = parse(&Bytes::from(wire)).unwrap();
        assert!(p.rtp_ext_present);
        assert_eq!(p.seq, 1);
        assert_eq!(p.enc_type, TYPE_DIRECT);
        assert_eq!(p.payload.as_ref(), &[0x99]);
    }

    #[test]
    fn control_sub_header_golden() {
        let mut dst = Vec::new();
        build_control(&mut dst, CI_NACK_RANGE, &[0xAA, 0xBB]);
        assert_eq!(dst, [0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB]);
        let (ci, body) = parse_control(&Bytes::from(dst)).unwrap();
        assert_eq!(ci, CI_NACK_RANGE);
        assert_eq!(body.as_ref(), &[0xAA, 0xBB]);
    }

    #[test]
    fn control_length_quirk_and_short() {
        // Length shorter than the trailing bytes is tolerated (libRIST's quirk).
        let wire = Bytes::from_static(&[
            0x80, 0x20, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ]);
        let (ci, body) = parse_control(&wire).unwrap();
        assert_eq!(ci, CI_UNSUPPORTED);
        assert_eq!(body.len(), 12);
        // A Length exceeding the buffer errors.
        let bad = Bytes::from_static(&[0x00, 0x01, 0x00, 0x10, 1, 2]);
        assert!(matches!(
            parse_control(&bad),
            Err(AdvError::ShortControl { .. })
        ));
        assert!(matches!(
            parse_control(&Bytes::from_static(&[0x00])),
            Err(AdvError::ShortControl { .. })
        ));
    }

    #[test]
    fn nack_bitmask_round_trip_and_missing() {
        let n = NackBitmask {
            media_ssrc: 0x0ACE_0AC0,
            pss: 1000,
            blp: 0b101,
        };
        let mut dst = Vec::new();
        build_nack_bitmask(&mut dst, n);
        let (ci, body) = parse_control(&Bytes::from(dst)).unwrap();
        assert_eq!(ci, CI_NACK_BITMASK);
        let got = NackBitmask::parse(&body).unwrap();
        assert_eq!(got, n);
        // bit 0 -> 1001 (pss+1), bit 2 -> 1003 (pss+3); pss always.
        assert_eq!(got.missing(), vec![1000, 1001, 1003]);
    }

    #[test]
    fn nack_range_round_trip_and_missing() {
        let n = NackRange {
            media_ssrc: 0x10,
            pss: 500,
            nalp: 3,
        };
        let mut dst = Vec::new();
        build_nack_range(&mut dst, n);
        let got = NackRange::parse(&parse_control(&Bytes::from(dst)).unwrap().1).unwrap();
        assert_eq!(got, n);
        assert_eq!(got.missing(), vec![500, 501, 502, 503]);
    }

    #[test]
    fn nack_encoders_pack_and_recover() {
        // Consecutive run + an isolated gap; range encodes one run + one single.
        let missing = vec![10, 11, 12, 13, 20];
        let ranges = encode_range_nack(0x1, &missing);
        let mut recovered: Vec<u32> = ranges.iter().flat_map(|r| r.missing()).collect();
        recovered.sort_unstable();
        assert_eq!(recovered, missing);

        let bms = encode_bitmask_nack(0x1, &missing);
        let mut recovered: Vec<u32> = bms.iter().flat_map(|b| b.missing()).collect();
        recovered.sort_unstable();
        recovered.dedup();
        assert_eq!(recovered, missing);
    }

    #[test]
    fn nack_wrap_aware_sort() {
        // A run straddling the 32-bit wrap stays one range, not two.
        let missing = vec![0xFFFF_FFFE, 0xFFFF_FFFF, 0x0000_0000, 0x0000_0001];
        let ranges = encode_range_nack(0x1, &missing);
        assert_eq!(ranges.len(), 1, "wrap-straddling run must be one range");
        assert_eq!(ranges[0].pss, 0xFFFF_FFFE);
        assert_eq!(ranges[0].nalp, 3);
    }

    #[test]
    fn rtt_echo_round_trip() {
        let e = RttEcho::from_timestamp(0x1234_5678, 0xDEAD_BEEF_CAFE_0001, 250);
        assert_eq!(e.timestamp(), 0xDEAD_BEEF_CAFE_0001);
        let mut dst = Vec::new();
        build_rtt_echo_request(&mut dst, e);
        let (ci, body) = parse_control(&Bytes::from(dst)).unwrap();
        assert_eq!(ci, CI_RTT_ECHO_REQ);
        assert_eq!(RttEcho::parse(&body).unwrap(), e);
    }

    #[test]
    fn keepalive_and_psk_nonce_round_trip() {
        let k = Keepalive {
            mac: [1, 2, 3, 4, 5, 6],
            caps: KEEPALIVE_CAP_I | KEEPALIVE_CAP_C,
        };
        let mut dst = Vec::new();
        build_keepalive(&mut dst, k);
        assert_eq!(
            Keepalive::parse(&parse_control(&Bytes::from(dst)).unwrap().1).unwrap(),
            k
        );

        let p = PskNonce {
            nonce: [0xAB, 0xCD, 0xEF, 0x01],
            key_bits: 256,
        };
        let mut dst = Vec::new();
        build_psk_nonce(&mut dst, p);
        let (ci, body) = parse_control(&Bytes::from(dst)).unwrap();
        assert_eq!(ci, CI_PSK_NONCE);
        assert_eq!(body.len(), PSK_NONCE_BODY_SIZE);
        assert_eq!(PskNonce::parse(&body).unwrap(), p);
    }
}
