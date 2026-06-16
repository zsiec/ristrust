//! RIST Main-profile GRE-over-UDP framing (VSF TR-06-2), byte-exact with libRIST
//! v0.2.18-rc1. Ported from ristgo `internal/gre`.
//!
//! RIST tunnels its media and control traffic in a stripped-down GRE (RFC 2784)
//! header carried directly inside UDP. The header is always at least four bytes —
//! two flag octets and a big-endian 16-bit protocol type — optionally followed by
//! a 4-byte key/nonce and a 4-byte sequence number. On the data channel a 4-byte
//! "reduced overhead" header (a 16-bit virtual source/destination port pair)
//! follows the GRE header and precedes the RTP payload. Keep-alive control packets
//! carry a 6-byte MAC and two capability octets.
//!
//! This module encodes and parses header *bytes* only. It never reads a clock,
//! opens a socket, or performs any encryption: which bytes get encrypted (and with
//! what key) is the [`crypto`](crate::crypto) layer's responsibility. When libRIST
//! encrypts a REDUCED data packet it encrypts the reduced-overhead header together
//! with the RTP payload — the region beginning immediately after the GRE sequence
//! number. Callers building encrypted data packets must therefore encrypt the bytes
//! this module places after the GRE header, not just the RTP payload.
//!
//! All multi-byte fields are big-endian (network order). Decoding arbitrary bytes
//! returns an error and never panics. Encoding uses append-style methods that grow
//! caller-provided buffers, matching [`rtp`](crate::rtp) and [`rtcp`](crate::rtcp).

// Justification: the codec reads/writes fixed-width big-endian fields and the
// 1-/3-bit flag subfields; the slice indexing is bounds-checked up front and the
// shifts are bounded by the field widths. Error/panic docs are covered by the
// module-level wire-format prose.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

/// Errors returned by the GRE codec. User-facing `Display` strings are prefixed
/// `"rist: gre: "` to match the rest of the stack.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GreError {
    /// The input is too short to hold the fixed header or an optional field the
    /// header announces.
    #[error("rist: gre: short buffer: {got} < {need} bytes")]
    ShortBuffer {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },

    /// A reserved bit that libRIST requires to be zero is set: flags1 bit 6, or
    /// any of the low three bits of flags2 (the RFC 2784 GRE-version bit and the
    /// two bits above it). libRIST drops such packets as "non conformant main
    /// profile".
    #[error(
        "rist: gre: non-conformant main-profile header: flags1={flags1:#04x} flags2={flags2:#04x}"
    )]
    NonConformant {
        /// The first flag octet as read off the wire.
        flags1: u8,
        /// The second flag octet as read off the wire.
        flags2: u8,
    },

    /// The VSF protocol type field is not RIST (0x0000); libRIST logs and drops
    /// such packets.
    #[error("rist: gre: unsupported VSF protocol type {0:#06x}")]
    UnsupportedVsfProto(u16),

    /// The GRE version does not fit the 3-bit RVer field (i.e. is greater than 7).
    #[error("rist: gre: version {0} does not fit the 3-bit RVer field")]
    VersionTooLarge(u8),
}

/// GRE protocol type for RIST keep-alive control packets
/// (`RIST_GRE_PROTOCOL_TYPE_KEEPALIVE`).
pub const PROTO_KEEPALIVE: u16 = 0x88B5;

/// GRE protocol type for reduced-overhead data packets
/// (`RIST_GRE_PROTOCOL_TYPE_REDUCED`).
pub const PROTO_REDUCED: u16 = 0x88B6;

/// GRE protocol type for full IP payloads carried out-of-band
/// (`RIST_GRE_PROTOCOL_TYPE_FULL`, 0x0800 = ETHERTYPE_IP).
pub const PROTO_FULL: u16 = 0x0800;

/// GRE protocol type for EAP-over-LAN authentication frames
/// (`RIST_GRE_PROTOCOL_TYPE_EAPOL`). EAPOL traffic is never encrypted.
pub const PROTO_EAPOL: u16 = 0x888E;

/// GRE protocol type for the version >= 2 VSF ethertype wrapper
/// (`RIST_GRE_PROTOCOL_TYPE_VSF`). When this is the protocol type a 4-byte
/// [`VsfProto`] header follows the GRE header and carries the true sub-protocol.
pub const PROTO_VSF: u16 = 0xCCE0;

/// Whether `prot_type` is a GRE protocol type RIST reserves for its own framing
/// (reduced-overhead media/control, keepalive, EAPOL, or the VSF wrapper). An
/// out-of-band datagram must use a non-reserved EtherType — [`PROTO_FULL`] (0x0800,
/// libRIST's out-of-band data) by default, or any other — so the receiver's demux
/// routes it to OOB delivery rather than the media/keepalive/EAP/VSF paths.
#[must_use]
pub fn is_reserved(prot_type: u16) -> bool {
    matches!(
        prot_type,
        PROTO_REDUCED | PROTO_KEEPALIVE | PROTO_EAPOL | PROTO_VSF
    )
}

/// The only defined VSF protocol type (`RIST_VSF_PROTOCOL_TYPE_RIST`); any other
/// value is rejected on parse.
pub const VSF_TYPE_RIST: u16 = 0x0000;

/// VSF subtype wrapping a reduced-overhead data packet
/// (`RIST_VSF_PROTOCOL_SUBTYPE_REDUCED`).
pub const VSF_SUBTYPE_REDUCED: u16 = 0x0000;

/// VSF subtype wrapping a keep-alive control packet
/// (`RIST_VSF_PROTOCOL_SUBTYPE_KEEPALIVE`).
pub const VSF_SUBTYPE_KEEPALIVE: u16 = 0x8000;

/// VSF subtype reserving the flow-attribute / future-nonce extension
/// (`RIST_VSF_PROTOCOL_SUBTYPE_FUTURE_NONCE`); libRIST does not parse its body.
pub const VSF_SUBTYPE_FUTURE_NONCE: u16 = 0x8001;

/// VSF subtype wrapping a buffer-negotiation control message
/// (`RIST_VSF_PROTOCOL_SUBTYPE_BUFFER_NEGOTIATION`).
pub const VSF_SUBTYPE_BUFFER_NEGOTIATION: u16 = 0x8002;

/// The minimum and default RIST GRE version (`RIST_GRE_VERSION_MIN`). At this
/// version protocol types are written directly into the protocol-type field with
/// no VSF wrapper.
pub const VERSION_MIN: u8 = 1;

/// The highest RIST GRE version this implementation understands
/// (`RIST_GRE_VERSION_CUR`). At version >= 2, REDUCED/KEEPALIVE/BUFFER_NEGOTIATION
/// are carried under the VSF ethertype wrapper.
pub const VERSION_CUR: u8 = 2;

/// The default reduced-overhead source port (`RIST_DEFAULT_VIRT_SRC_PORT`).
pub const DEFAULT_VIRT_SRC_PORT: u16 = 1971;

/// The default reduced-overhead destination port (`RIST_DEFAULT_VIRT_DST_PORT`).
pub const DEFAULT_VIRT_DST_PORT: u16 = 1968;

/// The size of the fixed GRE header: flags1, flags2, and the 16-bit protocol type.
pub const BASE_HEADER_SIZE: usize = 4;

/// The size of the reduced-overhead header: a virtual source/destination port pair.
pub const REDUCED_HEADER_SIZE: usize = 4;

/// The size of the version >= 2 VSF wrapper: a 16-bit type and a 16-bit subtype.
pub const VSF_PROTO_SIZE: usize = 4;

/// The size of the fixed keep-alive body: a 6-byte MAC and two capability octets.
pub const KEEPALIVE_SIZE: usize = 8;

/// The size of the optional Advanced-profile extended-capabilities block that may
/// follow the keep-alive body (TR-06-3 §5.3.6).
pub const ADV_EXT_SIZE: usize = 4;

/// The wire size of a buffer-negotiation message body: three 16-bit fields.
pub const BUFFER_NEGOTIATION_SIZE: usize = 6;

/// The size of the optional key/nonce field.
const NONCE_SIZE: usize = 4;

/// The size of the optional 32-bit sequence number.
const SEQ_SIZE: usize = 4;

// Bit positions within the two flag octets, in C bit numbering where bit 7 is the
// most significant bit (matching libRIST's SET_BIT/CHECK_BIT).
const BIT_CHECKSUM: u8 = 7; // C: checksum present. libRIST never sets it.
const BIT_RESERVED: u8 = 6; // reserved; receiver rejects when set.
const BIT_KEY: u8 = 5; // K: key/nonce present.
const BIT_SEQ: u8 = 4; // S: sequence number present.
const BIT_H: u8 = 6; // H (flags2): AES key length (0 => 128-bit, 1 => 256-bit).
const FLAGS2_RVER_SHIFT: u8 = 3; // RVer occupies bits 5,4,3.
const FLAGS2_RVER_MASK: u8 = 0x7;
/// The low three bits of flags2 (RFC 2784 GRE version bit plus the two reserved
/// bits above it); the receiver requires them to be zero.
const FLAGS2_LOW_MASK: u8 = 0x7;

/// A parsed RIST GRE base header: the fixed four bytes plus the optional key/nonce
/// and sequence-number fields whose presence the K and S flag bits announce.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    /// The 3-bit RIST GRE version (RVer field). [`VERSION_MIN`] is the default;
    /// [`VERSION_CUR`] selects the VSF ethertype wrapper.
    pub version: u8,
    /// The K bit: a 4-byte key/nonce follows the base header. libRIST sets it when
    /// transmitting encrypted data.
    pub has_key: bool,
    /// The S bit: a 4-byte sequence number follows the base header (and the
    /// key/nonce, if present). libRIST always sets it.
    pub has_seq: bool,
    /// The H bit: the AES key is 256-bit when set, 128-bit when clear. Meaningful
    /// only when `has_key` is set.
    pub key_size_256: bool,
    /// The 4-byte key/nonce, network byte order. Meaningful only when `has_key`.
    pub nonce: [u8; NONCE_SIZE],
    /// The 32-bit GRE sequence number. Meaningful only when `has_seq`. It becomes
    /// the high 4 bytes of the AES IV.
    pub seq: u32,
    /// The GRE protocol type (one of the `PROTO_*` constants). At version >= 2 with
    /// a wrapped sub-protocol this is [`PROTO_VSF`].
    pub prot_type: u16,
}

impl Header {
    /// The number of bytes [`Header::append_to`] writes: the four base bytes plus
    /// the optional key/nonce and sequence-number fields.
    #[must_use]
    pub fn size(&self) -> usize {
        let mut n = BASE_HEADER_SIZE;
        if self.has_key {
            n += NONCE_SIZE;
        }
        if self.has_seq {
            n += SEQ_SIZE;
        }
        n
    }

    /// Appends the serialized base header (flags + protocol type, then the optional
    /// nonce and sequence number) to `dst`. The field order matches libRIST: nonce
    /// at offset 4, sequence number immediately after.
    pub fn append_to(&self, dst: &mut Vec<u8>) -> Result<(), GreError> {
        if self.version > FLAGS2_RVER_MASK {
            return Err(GreError::VersionTooLarge(self.version));
        }
        let mut flags1: u8 = 0;
        let mut flags2: u8 = (self.version & FLAGS2_RVER_MASK) << FLAGS2_RVER_SHIFT;
        if self.has_seq {
            flags1 |= 1 << BIT_SEQ;
        }
        if self.has_key {
            flags1 |= 1 << BIT_KEY;
            if self.key_size_256 {
                flags2 |= 1 << BIT_H;
            }
        }
        dst.push(flags1);
        dst.push(flags2);
        dst.extend_from_slice(&self.prot_type.to_be_bytes());
        if self.has_key {
            dst.extend_from_slice(&self.nonce);
        }
        if self.has_seq {
            dst.extend_from_slice(&self.seq.to_be_bytes());
        }
        Ok(())
    }

    /// Decodes a RIST GRE base header from `b`, returning the header and the byte
    /// offset at which the payload (or, for [`PROTO_VSF`], the [`VsfProto`] header)
    /// begins — the number of header bytes consumed. It validates the reserved bits
    /// exactly as libRIST's receiver does and requires enough bytes for every
    /// optional field the flags announce.
    pub fn parse(b: &[u8]) -> Result<(Header, usize), GreError> {
        if b.len() < BASE_HEADER_SIZE {
            return Err(GreError::ShortBuffer {
                got: b.len(),
                need: BASE_HEADER_SIZE,
            });
        }
        let flags1 = b[0];
        let flags2 = b[1];

        // Reject non-conformant headers: flags1 bit 6 reserved, and the low three
        // bits of flags2 (RFC 2784 GRE version + reserved) must be zero.
        if flags1 & (1 << BIT_RESERVED) != 0 || flags2 & FLAGS2_LOW_MASK != 0 {
            return Err(GreError::NonConformant { flags1, flags2 });
        }

        let mut h = Header {
            version: (flags2 >> FLAGS2_RVER_SHIFT) & FLAGS2_RVER_MASK,
            has_key: flags1 & (1 << BIT_KEY) != 0,
            has_seq: flags1 & (1 << BIT_SEQ) != 0,
            prot_type: u16::from_be_bytes([b[2], b[3]]),
            ..Header::default()
        };
        // The H bit selects AES key length and is meaningful only alongside the key
        // bit (libRIST reads it inside the has_key path); decoding it only then keeps
        // the struct a round-trip-stable model of the wire.
        if h.has_key {
            h.key_size_256 = flags2 & (1 << BIT_H) != 0;
        }
        let has_checksum = flags1 & (1 << BIT_CHECKSUM) != 0;

        // Length check up front, matching libRIST.
        let mut need = BASE_HEADER_SIZE;
        if has_checksum {
            need += 4;
        }
        if h.has_key {
            need += NONCE_SIZE;
        }
        if h.has_seq {
            need += SEQ_SIZE;
        }
        if b.len() < need {
            return Err(GreError::ShortBuffer { got: b.len(), need });
        }

        // A checksum is never emitted by libRIST, but the receiver skips four bytes
        // when the C bit is set.
        let mut off = BASE_HEADER_SIZE;
        if has_checksum {
            off += 4;
        }
        if h.has_key {
            h.nonce.copy_from_slice(&b[off..off + NONCE_SIZE]);
            off += NONCE_SIZE;
        }
        if h.has_seq {
            h.seq = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
            off += SEQ_SIZE;
        }
        Ok((h, off))
    }
}

/// The reduced-overhead data-channel header: a virtual source/destination port
/// pair that scopes a media flow within a Main-profile multiplex. It follows the
/// GRE header (and the VSF wrapper, if any) on REDUCED data packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReducedHeader {
    /// The virtual source port ([`DEFAULT_VIRT_SRC_PORT`] by default).
    pub src_port: u16,
    /// The virtual destination port ([`DEFAULT_VIRT_DST_PORT`] by default).
    pub dst_port: u16,
}

impl Default for ReducedHeader {
    fn default() -> Self {
        ReducedHeader {
            src_port: DEFAULT_VIRT_SRC_PORT,
            dst_port: DEFAULT_VIRT_DST_PORT,
        }
    }
}

impl ReducedHeader {
    /// Appends the 4-byte reduced-overhead header to `dst`. The wire order is
    /// source port then destination port.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.src_port.to_be_bytes());
        dst.extend_from_slice(&self.dst_port.to_be_bytes());
    }

    /// Decodes a reduced-overhead header from `b`, returning it and the number of
    /// bytes consumed (always [`REDUCED_HEADER_SIZE`]).
    pub fn parse(b: &[u8]) -> Result<(ReducedHeader, usize), GreError> {
        if b.len() < REDUCED_HEADER_SIZE {
            return Err(GreError::ShortBuffer {
                got: b.len(),
                need: REDUCED_HEADER_SIZE,
            });
        }
        Ok((
            ReducedHeader {
                src_port: u16::from_be_bytes([b[0], b[1]]),
                dst_port: u16::from_be_bytes([b[2], b[3]]),
            },
            REDUCED_HEADER_SIZE,
        ))
    }
}

/// The version >= 2 VSF ethertype wrapper that follows the GRE header when the
/// protocol type is [`PROTO_VSF`]. The 16-bit type is always [`VSF_TYPE_RIST`]; the
/// subtype names the inner RIST protocol (one of the `VSF_SUBTYPE_*` constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsfProto {
    /// The VSF protocol type; only [`VSF_TYPE_RIST`] is defined.
    pub ty: u16,
    /// The inner RIST sub-protocol (`VSF_SUBTYPE_*` constant).
    pub subtype: u16,
}

impl VsfProto {
    /// Appends the 4-byte VSF wrapper to `dst`.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.ty.to_be_bytes());
        dst.extend_from_slice(&self.subtype.to_be_bytes());
    }

    /// Decodes a VSF wrapper from `b`, returning it and the number of bytes
    /// consumed (always [`VSF_PROTO_SIZE`]). Rejects any type other than
    /// [`VSF_TYPE_RIST`], matching the receiver.
    pub fn parse(b: &[u8]) -> Result<(VsfProto, usize), GreError> {
        if b.len() < VSF_PROTO_SIZE {
            return Err(GreError::ShortBuffer {
                got: b.len(),
                need: VSF_PROTO_SIZE,
            });
        }
        let v = VsfProto {
            ty: u16::from_be_bytes([b[0], b[1]]),
            subtype: u16::from_be_bytes([b[2], b[3]]),
        };
        if v.ty != VSF_TYPE_RIST {
            return Err(GreError::UnsupportedVsfProto(v.ty));
        }
        Ok((v, VSF_PROTO_SIZE))
    }
}

// Keep-alive capability bit positions, in C bit numbering (bit 7 is the MSB). The
// first capability octet carries N, L, E, P, A, B, R, X (bits 0..7); the second
// carries F, J, V, T, D in bits 3..7.
const CAP_N: u8 = 0; // Null-packet deletion.
const CAP_L: u8 = 1; // Pair-split (sender split mode active).
const CAP_E: u8 = 2; // SMPTE 2022-7 (multipath bonding redundancy).
const CAP_P: u8 = 3;
const CAP_A: u8 = 4;
const CAP_B: u8 = 5; // Bonding.
const CAP_R: u8 = 6;
const CAP_X: u8 = 7;
const CAP_F: u8 = 3;
const CAP_J: u8 = 4;
const CAP_V: u8 = 5; // Reduced-overhead header support.
const CAP_T: u8 = 6;
const CAP_D: u8 = 7;

// Advanced-profile extended-capability bit positions in the first octet of the
// optional 4-byte extended block (TR-06-3 §5.3.6).
const ADV_I: u8 = 7; // Advanced Profile capable.
const ADV_G: u8 = 6; // GRE key rotation capable.
const ADV_C: u8 = 5; // Compression capable.

/// The decoded keep-alive capability bits. The field names mirror libRIST's
/// `rist_keepalive_info` booleans.
// Justification: this is a faithful one-to-one model of 13 distinct on-wire
// capability bits; collapsing them into a bitfield would obscure the mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Null-packet deletion (capabilities1 bit 0).
    pub n: bool,
    /// Pair-split (capabilities1 bit 1).
    pub l: bool,
    /// SMPTE 2022-7 (capabilities1 bit 2).
    pub e: bool,
    /// capabilities1 bit 3.
    pub p: bool,
    /// capabilities1 bit 4.
    pub a: bool,
    /// Bonding (capabilities1 bit 5).
    pub b: bool,
    /// capabilities1 bit 6.
    pub r: bool,
    /// capabilities1 bit 7.
    pub x: bool,
    /// capabilities2 bit 3.
    pub f: bool,
    /// capabilities2 bit 4.
    pub j: bool,
    /// Reduced-overhead support (capabilities2 bit 5).
    pub v: bool,
    /// capabilities2 bit 6.
    pub t: bool,
    /// capabilities2 bit 7.
    pub d: bool,
}

impl Capabilities {
    /// The capability set libRIST's sender advertises by default: null-packet
    /// deletion (N), SMPTE 2022-7 (E), bonding (B), and reduced-overhead support
    /// (V). The pair-split bit (L) is set only when split mode is active and is left
    /// clear here; callers may set it explicitly.
    #[must_use]
    pub fn standard() -> Capabilities {
        Capabilities {
            n: true,
            e: true,
            b: true,
            v: true,
            ..Capabilities::default()
        }
    }

    /// The two capability octets (capabilities1, capabilities2) in the receiver's
    /// bit layout.
    #[must_use]
    pub fn encode(&self) -> (u8, u8) {
        let mut c1: u8 = 0;
        let mut c2: u8 = 0;
        for (cond, bit) in [
            (self.n, CAP_N),
            (self.l, CAP_L),
            (self.e, CAP_E),
            (self.p, CAP_P),
            (self.a, CAP_A),
            (self.b, CAP_B),
            (self.r, CAP_R),
            (self.x, CAP_X),
        ] {
            if cond {
                c1 |= 1 << bit;
            }
        }
        for (cond, bit) in [
            (self.f, CAP_F),
            (self.j, CAP_J),
            (self.v, CAP_V),
            (self.t, CAP_T),
            (self.d, CAP_D),
        ] {
            if cond {
                c2 |= 1 << bit;
            }
        }
        (c1, c2)
    }

    /// Decodes the two capability octets into a [`Capabilities`].
    #[must_use]
    pub fn decode(c1: u8, c2: u8) -> Capabilities {
        let bit = |byte: u8, pos: u8| byte & (1 << pos) != 0;
        Capabilities {
            n: bit(c1, CAP_N),
            l: bit(c1, CAP_L),
            e: bit(c1, CAP_E),
            p: bit(c1, CAP_P),
            a: bit(c1, CAP_A),
            b: bit(c1, CAP_B),
            r: bit(c1, CAP_R),
            x: bit(c1, CAP_X),
            f: bit(c2, CAP_F),
            j: bit(c2, CAP_J),
            v: bit(c2, CAP_V),
            t: bit(c2, CAP_T),
            d: bit(c2, CAP_D),
        }
    }
}

/// The optional Advanced-profile extended capability bits carried in the first
/// octet of the 4-byte block after the keep-alive body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdvExtCaps {
    /// Advanced Profile capable (byte 8 bit 7).
    pub i: bool,
    /// GRE key rotation capable (byte 8 bit 6).
    pub g: bool,
    /// Compression capable (byte 8 bit 5).
    pub c: bool,
}

impl AdvExtCaps {
    /// The first octet of the extended-capability block. libRIST emits the I bit as
    /// 0x80 with the remaining three octets zero.
    #[must_use]
    pub fn encode(&self) -> u8 {
        let mut byte: u8 = 0;
        if self.i {
            byte |= 1 << ADV_I;
        }
        if self.g {
            byte |= 1 << ADV_G;
        }
        if self.c {
            byte |= 1 << ADV_C;
        }
        byte
    }

    /// Decodes the first octet of the extended-capability block.
    #[must_use]
    pub fn decode(byte: u8) -> AdvExtCaps {
        AdvExtCaps {
            i: byte & (1 << ADV_I) != 0,
            g: byte & (1 << ADV_G) != 0,
            c: byte & (1 << ADV_C) != 0,
        }
    }
}

/// A parsed RIST keep-alive message body (plus the optional TR-06-3 extended block
/// and JSON payload). It is the GRE payload of a [`PROTO_KEEPALIVE`] packet; the GRE
/// header is handled separately by [`Header`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keepalive {
    /// The 48-bit MAC address identifying the sending node.
    pub mac: [u8; 6],
    /// The negotiated capability bits.
    pub caps: Capabilities,
    /// Whether the optional 4-byte Advanced-profile extended-capability block is
    /// present.
    pub has_adv_ext: bool,
    /// The Advanced-profile extended capabilities; meaningful only when
    /// `has_adv_ext` is set.
    pub adv_ext: AdvExtCaps,
    /// The optional trailing JSON message payload; empty when absent.
    pub json: Vec<u8>,
}

impl Keepalive {
    /// The number of bytes [`Keepalive::append_to`] writes: the fixed body, the
    /// optional 4-byte extended block, and the JSON payload.
    #[must_use]
    pub fn size(&self) -> usize {
        let mut n = KEEPALIVE_SIZE;
        if self.has_adv_ext {
            n += ADV_EXT_SIZE;
        }
        n + self.json.len()
    }

    /// Appends the serialized keep-alive body to `dst`: 6-byte MAC, two capability
    /// octets, then the optional extended-capability block and JSON payload. It
    /// writes only the keep-alive payload; the surrounding GRE header is the
    /// caller's responsibility.
    ///
    /// Round-trip caveat: a `Keepalive` with `has_adv_ext` false and four or more
    /// JSON bytes does not round-trip symmetrically — [`Keepalive::parse`] reads the
    /// first four trailing bytes as the extended-capability block. This is the
    /// format's inherent on-wire ambiguity, faithfully mirrored: libRIST's parser
    /// uses the same "four trailing bytes => extended block" heuristic and its
    /// sender never attaches a JSON payload.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.mac);
        let (c1, c2) = self.caps.encode();
        dst.push(c1);
        dst.push(c2);
        if self.has_adv_ext {
            dst.push(self.adv_ext.encode());
            dst.extend_from_slice(&[0, 0, 0]);
        }
        if !self.json.is_empty() {
            dst.extend_from_slice(&self.json);
        }
    }

    /// Decodes a keep-alive body from `b`: the 6-byte MAC and capability octets, the
    /// optional 4-byte Advanced extended block (present when at least four trailing
    /// bytes follow the fixed body), and any remaining bytes as the JSON payload.
    pub fn parse(b: &[u8]) -> Result<Keepalive, GreError> {
        if b.len() < KEEPALIVE_SIZE {
            return Err(GreError::ShortBuffer {
                got: b.len(),
                need: KEEPALIVE_SIZE,
            });
        }
        let mut k = Keepalive {
            caps: Capabilities::decode(b[6], b[7]),
            ..Keepalive::default()
        };
        k.mac.copy_from_slice(&b[0..6]);

        let rest = &b[KEEPALIVE_SIZE..];
        if rest.len() >= ADV_EXT_SIZE {
            k.has_adv_ext = true;
            k.adv_ext = AdvExtCaps::decode(rest[0]);
            let json = &rest[ADV_EXT_SIZE..];
            if !json.is_empty() {
                k.json = json.to_vec();
            }
        } else if !rest.is_empty() {
            k.json = rest.to_vec();
        }
        Ok(k)
    }
}

/// The VSF buffer-negotiation control message (VSF subtype 0x8002, carried at GRE
/// version 2 and above): each peer advertises the maximum buffer it allows as a
/// sender and the buffer it currently uses as a receiver, so the two ends converge
/// on a recovery-window size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BufferNegotiation {
    /// The maximum buffer (ms) this device allows as a sender; 0 means the device
    /// is not a sender.
    pub sender_max_ms: u16,
    /// This device's current receiver buffer (ms); 0 means the device is not a
    /// receiver.
    pub receiver_cur_ms: u16,
    /// Scopes the negotiation; 0 applies to the whole session.
    pub proto_type: u16,
}

impl BufferNegotiation {
    /// Appends the 6-byte big-endian buffer-negotiation body to `dst`.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.sender_max_ms.to_be_bytes());
        dst.extend_from_slice(&self.receiver_cur_ms.to_be_bytes());
        dst.extend_from_slice(&self.proto_type.to_be_bytes());
    }

    /// Decodes a buffer-negotiation body from `b`.
    pub fn parse(b: &[u8]) -> Result<BufferNegotiation, GreError> {
        if b.len() < BUFFER_NEGOTIATION_SIZE {
            return Err(GreError::ShortBuffer {
                got: b.len(),
                need: BUFFER_NEGOTIATION_SIZE,
            });
        }
        Ok(BufferNegotiation {
            sender_max_ms: u16::from_be_bytes([b[0], b[1]]),
            receiver_cur_ms: u16::from_be_bytes([b[2], b[3]]),
            proto_type: u16::from_be_bytes([b[4], b[5]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_reserved_matches_rist_framing_only() {
        // RIST's own framing types are reserved; OOB EtherTypes (FULL and arbitrary)
        // are not, so the demux routes them to out-of-band delivery.
        for p in [PROTO_REDUCED, PROTO_KEEPALIVE, PROTO_EAPOL, PROTO_VSF] {
            assert!(is_reserved(p), "0x{p:04X} should be reserved");
        }
        for p in [PROTO_FULL, 0x88B7, 0x0000, 0xFFFF] {
            assert!(!is_reserved(p), "0x{p:04X} should not be reserved");
        }
    }

    struct GoldenHeader {
        name: &'static str,
        hdr: Header,
        want: &'static [u8],
    }

    /// Hand-derived wire bytes for every GRE base-header variant (ristgo
    /// `goldenHeaders`).
    fn golden_headers() -> Vec<GoldenHeader> {
        vec![
            GoldenHeader {
                // Unencrypted, seq-only, version 1 (the data default). flags1 has
                // only S (bit 4) -> 0x10; flags2 = (1 & 0x7) << 3 -> 0x08.
                name: "unencrypted-seq-v1-reduced",
                hdr: Header {
                    version: 1,
                    has_seq: true,
                    prot_type: PROTO_REDUCED,
                    seq: 0x0102_0304,
                    ..Header::default()
                },
                want: &[0x10, 0x08, 0x88, 0xB6, 0x01, 0x02, 0x03, 0x04],
            },
            GoldenHeader {
                // Encrypted, key+seq, 128-bit (H=0), version 1. flags1 has K and S
                // -> 0x30; flags2 = 0x08, H clear. nonce at offset 4, seq after.
                name: "encrypted-key-seq-h0-v1",
                hdr: Header {
                    version: 1,
                    has_key: true,
                    has_seq: true,
                    nonce: [0xAA, 0xBB, 0xCC, 0xDD],
                    seq: 0x0102_0304,
                    prot_type: PROTO_REDUCED,
                    ..Header::default()
                },
                want: &[
                    0x30, 0x08, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04,
                ],
            },
            GoldenHeader {
                // Encrypted, key+seq, 256-bit (H=1), version 1. flags2 = 0x08 |
                // (1<<6) = 0x48.
                name: "encrypted-key-seq-h1-v1",
                hdr: Header {
                    version: 1,
                    has_key: true,
                    has_seq: true,
                    key_size_256: true,
                    nonce: [0xAA, 0xBB, 0xCC, 0xDD],
                    seq: 0x0102_0304,
                    prot_type: PROTO_REDUCED,
                },
                want: &[
                    0x30, 0x48, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04,
                ],
            },
            GoldenHeader {
                // Version 2 VSF wrapper, unencrypted seq-only. flags1 = 0x10;
                // flags2 = (2 & 0x7) << 3 = 0x10; prot_type = VSF 0xCCE0.
                name: "vsf-base-v2-seq",
                hdr: Header {
                    version: 2,
                    has_seq: true,
                    prot_type: PROTO_VSF,
                    seq: 0x0102_0304,
                    ..Header::default()
                },
                want: &[0x10, 0x10, 0xCC, 0xE0, 0x01, 0x02, 0x03, 0x04],
            },
        ]
    }

    #[test]
    fn header_append_golden() {
        for tc in golden_headers() {
            let mut got = Vec::new();
            tc.hdr.append_to(&mut got).unwrap();
            assert_eq!(got, tc.want, "{} append", tc.name);
            assert_eq!(tc.hdr.size(), tc.want.len(), "{} size", tc.name);
        }
    }

    #[test]
    fn header_parse_golden() {
        for tc in golden_headers() {
            let (h, off) = Header::parse(tc.want).unwrap();
            assert_eq!(off, tc.want.len(), "{} offset", tc.name);
            assert_eq!(h, tc.hdr, "{} parse", tc.name);
        }
    }

    #[test]
    fn header_round_trip_byte_stable() {
        for tc in golden_headers() {
            let mut wire = Vec::new();
            tc.hdr.append_to(&mut wire).unwrap();
            let (h, off) = Header::parse(&wire).unwrap();
            assert_eq!(off, wire.len(), "{} offset", tc.name);
            assert_eq!(h, tc.hdr, "{} round trip", tc.name);
            let mut wire2 = Vec::new();
            h.append_to(&mut wire2).unwrap();
            assert_eq!(wire2, wire, "{} re-encode byte-stable", tc.name);
        }
    }

    #[test]
    fn reduced_golden() {
        let r = ReducedHeader {
            src_port: DEFAULT_VIRT_SRC_PORT,
            dst_port: DEFAULT_VIRT_DST_PORT,
        };
        let want = [0x07, 0xB3, 0x07, 0xB0];
        let mut got = Vec::new();
        r.append_to(&mut got);
        assert_eq!(got, want);
        let (parsed, n) = ReducedHeader::parse(&got).unwrap();
        assert_eq!(n, REDUCED_HEADER_SIZE);
        assert_eq!(parsed, r);
        assert_eq!(ReducedHeader::default(), r);
    }

    #[test]
    fn vsf_proto_golden() {
        let cases: &[(&str, u16, [u8; 4])] = &[
            ("reduced", VSF_SUBTYPE_REDUCED, [0x00, 0x00, 0x00, 0x00]),
            ("keepalive", VSF_SUBTYPE_KEEPALIVE, [0x00, 0x00, 0x80, 0x00]),
            (
                "buffer-negotiation",
                VSF_SUBTYPE_BUFFER_NEGOTIATION,
                [0x00, 0x00, 0x80, 0x02],
            ),
        ];
        for &(name, subtype, want) in cases {
            let v = VsfProto {
                ty: VSF_TYPE_RIST,
                subtype,
            };
            let mut got = Vec::new();
            v.append_to(&mut got);
            assert_eq!(got, want, "{name} append");
            let (parsed, n) = VsfProto::parse(&got).unwrap();
            assert_eq!(n, VSF_PROTO_SIZE, "{name} consumed");
            assert_eq!(parsed, v, "{name} parse");
        }
    }

    #[test]
    fn vsf_proto_rejects_non_rist_type() {
        let bad = [0x00, 0x01, 0x00, 0x00];
        assert_eq!(
            VsfProto::parse(&bad),
            Err(GreError::UnsupportedVsfProto(0x0001))
        );
    }

    #[test]
    fn keepalive_golden() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let k = Keepalive {
            mac,
            caps: Capabilities::standard(),
            ..Keepalive::default()
        };
        // cap1 with bits 0,2,5 (N|E|B = 0x25), cap2 with bit 5 (V = 0x20).
        let want = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x25, 0x20];
        let mut got = Vec::new();
        k.append_to(&mut got);
        assert_eq!(got, want);

        let parsed = Keepalive::parse(&got).unwrap();
        assert_eq!(parsed.mac, mac);
        assert_eq!(parsed.caps, Capabilities::standard());
        assert!(!parsed.has_adv_ext);
        assert!(parsed.json.is_empty());
    }

    #[test]
    fn keepalive_adv_ext_and_json() {
        let json = br#"{"cname":"ristgo"}"#.to_vec();
        let k = Keepalive {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            caps: Capabilities::standard(),
            has_adv_ext: true,
            adv_ext: AdvExtCaps {
                i: true,
                ..AdvExtCaps::default()
            },
            json: json.clone(),
        };
        let mut wire = Vec::new();
        k.append_to(&mut wire);

        // Byte 8 (first extended octet) must be 0x80 (I bit), bytes 9-11 zero.
        assert_eq!(&wire[8..12], &[0x80, 0x00, 0x00, 0x00]);
        assert_eq!(&wire[12..], json.as_slice());

        let parsed = Keepalive::parse(&wire).unwrap();
        assert!(parsed.has_adv_ext);
        assert!(parsed.adv_ext.i && !parsed.adv_ext.g && !parsed.adv_ext.c);
        assert_eq!(parsed.json, json);
    }

    #[test]
    fn parse_reserved_bit_rejection() {
        let cases: &[(&str, [u8; 2])] = &[
            ("flags1-bit6", [1 << 6, 0x08]),
            ("flags2-bit0", [0x10, 0x08 | 0x01]),
            ("flags2-bit1", [0x10, 0x08 | 0x02]),
            ("flags2-bit2", [0x10, 0x08 | 0x04]),
        ];
        for &(name, flags) in cases {
            let b = [flags[0], flags[1], 0x88, 0xB6, 0, 0, 0, 0];
            assert!(
                matches!(Header::parse(&b), Err(GreError::NonConformant { .. })),
                "{name} must reject"
            );
        }
    }

    #[test]
    fn parse_short_buffer() {
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("three-bytes", &[0x10, 0x08, 0x88]),
            ("seq-truncated", &[0x10, 0x08, 0x88, 0xB6, 0x01]),
            (
                "key-seq-truncated",
                &[0x30, 0x08, 0x88, 0xB6, 0xAA, 0xBB, 0xCC, 0xDD, 0x01],
            ),
        ];
        for &(name, b) in cases {
            assert!(
                matches!(Header::parse(b), Err(GreError::ShortBuffer { .. })),
                "{name} must error"
            );
        }
    }

    #[test]
    fn header_version_too_large_rejected() {
        let h = Header {
            version: 8,
            ..Header::default()
        };
        let mut buf = Vec::new();
        assert_eq!(h.append_to(&mut buf), Err(GreError::VersionTooLarge(8)));
    }

    #[test]
    fn parse_skips_checksum_when_c_bit_set() {
        // C bit (flags1 bit 7) set, S bit set: 0x80 | 0x10 = 0x90. flags2 = 0x08.
        // Four checksum bytes follow the base header, then the 4-byte seq.
        let b = [
            0x90, 0x08, 0x88, 0xB6, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
        ];
        let (h, off) = Header::parse(&b).unwrap();
        assert_eq!(off, b.len());
        assert!(h.has_seq);
        assert_eq!(h.seq, 0x0102_0304);
    }

    #[test]
    fn capabilities_bit_layout_round_trip() {
        let caps = Capabilities {
            n: true,
            l: true,
            e: true,
            p: true,
            a: true,
            b: true,
            r: true,
            x: true,
            f: true,
            j: true,
            v: true,
            t: true,
            d: true,
        };
        let (c1, c2) = caps.encode();
        assert_eq!(c1, 0xFF, "all of capabilities1 set");
        assert_eq!(c2, 0xF8, "capabilities2 bits 3..7 set");
        assert_eq!(Capabilities::decode(c1, c2), caps);
    }

    #[test]
    fn buffer_negotiation_round_trip() {
        let bn = BufferNegotiation {
            sender_max_ms: 1000,
            receiver_cur_ms: 250,
            proto_type: 0,
        };
        let mut got = Vec::new();
        bn.append_to(&mut got);
        assert_eq!(got, [0x03, 0xE8, 0x00, 0xFA, 0x00, 0x00]);
        assert_eq!(BufferNegotiation::parse(&got).unwrap(), bn);
        assert!(matches!(
            BufferNegotiation::parse(&got[..5]),
            Err(GreError::ShortBuffer { .. })
        ));
    }
}
