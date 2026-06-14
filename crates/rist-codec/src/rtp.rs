//! RTP packet codec (RFC 3550 §5.1), trimmed to what RIST needs: the fixed
//! 12-byte header, the CSRC list, the classic RFC 3550 header extension (16-bit
//! profile + 16-bit length in 32-bit words + opaque payload), and trailing
//! padding.
//!
//! RIST specifics handled here:
//!
//! - The header extension is carried as **opaque bytes only**. RIST NPD (the
//!   Simple/Main null-packet-deletion extension, TR-06-2) uses profile 0x5249
//!   ("RI"); its semantics are decoded by [`npd`](crate::npd), never here.
//! - Retransmissions are **not** RFC 4588: a RIST retransmission is the original
//!   RTP packet — same sequence number, timestamp, and payload — with only the
//!   SSRC least-significant bit set. See [`normalize_ssrc`], [`mark_retransmit`],
//!   and [`is_retransmit`].
//!
//! All multi-byte fields are big-endian. Decoding arbitrary bytes returns errors
//! and never panics; the media payload aliases the input [`Bytes`] (zero-copy).
//!
//! Portions ported from [pion/rtp](https://github.com/pion/rtp) (MIT; see
//! `NOTICE.md`). Deviations from pion: only the classic RFC 3550 extension is
//! supported (RFC 8285 one-/two-byte parsing is dropped — every profile,
//! including 0xBEDE, is opaque), marshalling validates the version and CSRC count
//! instead of silently corrupting the first byte, and decode is zero-copy.

// Justification: the codec reads/writes fixed-width big-endian fields; the casts
// between byte slices, the 2-/4-/7-bit header subfields, and word counts are
// deliberate and bounded by the field widths.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_errors_doc
)]

use bytes::Bytes;

/// Errors returned by the RTP codec. User-facing `Display` strings are prefixed
/// `"rist: rtp: "` to match the rest of the stack.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RtpError {
    /// The buffer cannot hold the fixed header plus the CSRC list the CC field
    /// announces (RFC 3550 §5.1).
    #[error("rist: rtp: header too short: {got} < {need} bytes")]
    HeaderTooShort {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },

    /// The X bit is set but the buffer cannot hold the 4-byte extension header
    /// plus the payload length it announces (RFC 3550 §5.3.1).
    #[error("rist: rtp: header extension truncated: {got} < {need} bytes")]
    ExtensionTooShort {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },

    /// The P bit is set but no padding-count octet follows the header.
    #[error("rist: rtp: packet too short: no room for padding count octet")]
    PacketTooShort,

    /// The padding count is zero, larger than the space after the header, or (on
    /// marshal) disagrees with the `padding` flag.
    #[error("rist: rtp: invalid padding: {0}")]
    InvalidPadding(&'static str),

    /// The destination buffer is smaller than the marshal size.
    #[error("rist: rtp: short buffer: {got} < {need} bytes")]
    ShortBuffer {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },

    /// `version` does not fit the 2-bit V field (i.e. is greater than 3).
    #[error("rist: rtp: version {0} does not fit the 2-bit field")]
    InvalidVersion(u8),

    /// More than 15 CSRC entries: the 4-bit CC field cannot express them.
    #[error("rist: rtp: more than 15 CSRC entries: {0}")]
    TooManyCsrc(usize),

    /// The extension payload length is not a multiple of 4 bytes (the RFC 3550
    /// length field counts 32-bit words).
    #[error("rist: rtp: extension payload not a multiple of 4 bytes: {0}")]
    ExtensionNotAligned(usize),

    /// The extension payload exceeds 65535 32-bit words.
    #[error("rist: rtp: extension payload longer than 65535 words: {0}")]
    ExtensionTooLong(usize),
}

/// The RTP version every RIST packet carries in the 2-bit V field.
pub const VERSION: u8 = 2;

/// The size in bytes of the fixed RTP header, before CSRCs or extension.
pub const FIXED_HEADER_SIZE: usize = 12;

/// The maximum number of CSRC entries the 4-bit CC field can express.
pub const MAX_CSRC: usize = 15;

/// The "defined by profile" value of the RIST NPD header extension: 0x5249,
/// ASCII "RI" (TR-06-2). This codec only carries the extension bytes.
pub const EXTENSION_PROFILE_RIST: u16 = 0x5249;

/// The RTP payload type RIST uses for MPEG transport-stream media (33).
pub const PAYLOAD_TYPE_MPEGTS: u8 = 0x21;

/// The RTP timestamp clock rate, in Hz, of the MPEG-TS payload type.
pub const CLOCK_RATE_MPEGTS: u32 = 90_000;

const VERSION_SHIFT: u8 = 6;
const VERSION_MASK: u8 = 0x3;
const PADDING_SHIFT: u8 = 5;
const EXTENSION_SHIFT: u8 = 4;
const CC_MASK: u8 = 0xF;
const MARKER_SHIFT: u8 = 7;
const PT_MASK: u8 = 0x7F;
const CSRC_OFFSET: usize = 12;
const CSRC_LENGTH: usize = 4;
const EXT_HEADER_SIZE: usize = 4;

/// A parsed RTP packet header (RFC 3550 §5.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// The 2-bit V field; always 2 on a valid RIST wire. Decode does not reject
    /// other values (matching pion and libRIST); marshal rejects values above 3.
    pub version: u8,
    /// The P bit: the payload is followed by padding octets, the last of which
    /// counts the padding (see [`Packet::padding_size`]).
    pub padding: bool,
    /// The X bit: exactly one RFC 3550 header extension follows the CSRC list.
    pub extension: bool,
    /// The 4-bit CC field as read off the wire. Decode sets it to `csrc.len()`;
    /// marshal derives the wire field from `csrc.len()` and ignores this.
    pub csrc_count: u8,
    /// The M bit. RIST MPEG-TS media never sets it.
    pub marker: bool,
    /// The 7-bit PT field. RIST media uses [`PAYLOAD_TYPE_MPEGTS`].
    pub payload_type: u8,
    /// The 16-bit RTP sequence number. A retransmission repeats it unchanged.
    pub sequence_number: u16,
    /// The 32-bit RTP timestamp (90 kHz for MPEG-TS).
    pub timestamp: u32,
    /// The RIST flow SSRC. The base flow SSRC is even; an odd SSRC marks a
    /// retransmission (see [`is_retransmit`]).
    pub ssrc: u32,
    /// The contributing-source list (0–15 entries). RIST does not use CSRCs.
    pub csrc: Vec<u32>,
    /// The 16-bit "defined by profile" field. Only meaningful when `extension`.
    pub extension_profile: u16,
    /// The extension body excluding the 4-byte extension header; its length is
    /// always a multiple of 4. Only meaningful when `extension`. After decode it
    /// aliases the input [`Bytes`].
    pub extension_payload: Bytes,
}

impl Header {
    /// Parses a header from `buf`, returning the header and the number of bytes
    /// consumed (fixed header + CSRC list + extension, if present).
    /// `extension_payload` is sliced zero-copy from `buf`.
    pub fn decode(buf: &Bytes) -> Result<(Header, usize), RtpError> {
        let b = buf.as_ref();
        if b.len() < FIXED_HEADER_SIZE {
            return Err(RtpError::HeaderTooShort {
                got: b.len(),
                need: FIXED_HEADER_SIZE,
            });
        }
        let mut h = Header {
            version: (b[0] >> VERSION_SHIFT) & VERSION_MASK,
            padding: (b[0] >> PADDING_SHIFT) & 0x1 != 0,
            extension: (b[0] >> EXTENSION_SHIFT) & 0x1 != 0,
            marker: b[1] >> MARKER_SHIFT != 0,
            payload_type: b[1] & PT_MASK,
            sequence_number: u16::from_be_bytes([b[2], b[3]]),
            timestamp: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ssrc: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            ..Header::default()
        };
        let n_csrc = (b[0] & CC_MASK) as usize;
        h.csrc_count = n_csrc as u8;

        let mut n = CSRC_OFFSET + n_csrc * CSRC_LENGTH;
        if b.len() < n {
            return Err(RtpError::HeaderTooShort {
                got: b.len(),
                need: n,
            });
        }
        h.csrc = (0..n_csrc)
            .map(|i| {
                let o = CSRC_OFFSET + i * CSRC_LENGTH;
                u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
            })
            .collect();

        if h.extension {
            if b.len() < n + EXT_HEADER_SIZE {
                return Err(RtpError::ExtensionTooShort {
                    got: b.len(),
                    need: n + EXT_HEADER_SIZE,
                });
            }
            h.extension_profile = u16::from_be_bytes([b[n], b[n + 1]]);
            let ext_len = u16::from_be_bytes([b[n + 2], b[n + 3]]) as usize * 4;
            n += EXT_HEADER_SIZE;
            if b.len() < n + ext_len {
                return Err(RtpError::ExtensionTooShort {
                    got: b.len(),
                    need: n + ext_len,
                });
            }
            h.extension_payload = buf.slice(n..n + ext_len);
            n += ext_len;
        }

        Ok((h, n))
    }

    /// The number of bytes [`Header::marshal_to`] writes.
    #[must_use]
    pub fn marshal_size(&self) -> usize {
        let mut size = FIXED_HEADER_SIZE + self.csrc.len() * CSRC_LENGTH;
        if self.extension {
            size += EXT_HEADER_SIZE + self.extension_payload.len();
        }
        size
    }

    /// Serializes the header into `buf`, returning the number of bytes written.
    /// The CC field is derived from `csrc.len()`; `csrc_count` is ignored.
    pub fn marshal_to(&self, buf: &mut [u8]) -> Result<usize, RtpError> {
        if self.version > VERSION_MASK {
            return Err(RtpError::InvalidVersion(self.version));
        }
        if self.csrc.len() > MAX_CSRC {
            return Err(RtpError::TooManyCsrc(self.csrc.len()));
        }
        if self.extension {
            if !self.extension_payload.len().is_multiple_of(4) {
                return Err(RtpError::ExtensionNotAligned(self.extension_payload.len()));
            }
            if self.extension_payload.len() / 4 > 0xFFFF {
                return Err(RtpError::ExtensionTooLong(self.extension_payload.len() / 4));
            }
        }
        let size = self.marshal_size();
        if buf.len() < size {
            return Err(RtpError::ShortBuffer {
                got: buf.len(),
                need: size,
            });
        }

        buf[0] = (self.version << VERSION_SHIFT) | (self.csrc.len() as u8);
        if self.padding {
            buf[0] |= 1 << PADDING_SHIFT;
        }
        if self.extension {
            buf[0] |= 1 << EXTENSION_SHIFT;
        }
        buf[1] = self.payload_type & PT_MASK;
        if self.marker {
            buf[1] |= 1 << MARKER_SHIFT;
        }
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut n = CSRC_OFFSET;
        for &csrc in &self.csrc {
            buf[n..n + 4].copy_from_slice(&csrc.to_be_bytes());
            n += CSRC_LENGTH;
        }

        if self.extension {
            buf[n..n + 2].copy_from_slice(&self.extension_profile.to_be_bytes());
            let words = (self.extension_payload.len() / 4) as u16;
            buf[n + 2..n + 4].copy_from_slice(&words.to_be_bytes());
            n += EXT_HEADER_SIZE;
            buf[n..n + self.extension_payload.len()].copy_from_slice(&self.extension_payload);
            n += self.extension_payload.len();
        }

        Ok(n)
    }

    /// Appends the serialized header to `dst`.
    pub fn append_to(&self, dst: &mut Vec<u8>) -> Result<(), RtpError> {
        let start = dst.len();
        dst.resize(start + self.marshal_size(), 0);
        self.marshal_to(&mut dst[start..])?;
        Ok(())
    }
}

/// A parsed RTP packet: header, payload, and trailing padding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    /// The RTP header.
    pub header: Header,
    /// The media payload, excluding any padding. After decode it aliases the
    /// input [`Bytes`] (zero-copy).
    pub payload: Bytes,
    /// The total number of padding octets at the end of the packet, including
    /// the count octet (RFC 3550 §5.1). Non-zero exactly when `header.padding`.
    pub padding_size: u8,
}

impl Packet {
    /// Parses a full RTP packet from `buf`. When the P bit is set, the padding
    /// count is read from the last octet and stripped from `payload`. `payload`
    /// and `header.extension_payload` are sliced from `buf` (zero-copy: they
    /// share its allocation and keep it alive after the caller drops `buf`).
    pub fn decode(buf: &Bytes) -> Result<Packet, RtpError> {
        let (header, n) = Header::decode(buf)?;

        let mut end = buf.len();
        let padding_size = if header.padding {
            if end <= n {
                return Err(RtpError::PacketTooShort);
            }
            let pad = buf[end - 1];
            if pad == 0 {
                return Err(RtpError::InvalidPadding("padding count is zero"));
            }
            if pad as usize > end - n {
                return Err(RtpError::InvalidPadding(
                    "padding count exceeds bytes after header",
                ));
            }
            end -= pad as usize;
            pad
        } else {
            0
        };

        Ok(Packet {
            header,
            payload: buf.slice(n..end),
            padding_size,
        })
    }

    /// The number of bytes [`Packet::marshal_to`] writes.
    #[must_use]
    pub fn marshal_size(&self) -> usize {
        self.header.marshal_size() + self.payload.len() + self.padding_size as usize
    }

    /// Serializes the packet into `buf`. `header.padding` and `padding_size`
    /// must agree: padding is emitted as `padding_size - 1` zero octets followed
    /// by the count octet.
    pub fn marshal_to(&self, buf: &mut [u8]) -> Result<usize, RtpError> {
        if self.header.padding != (self.padding_size > 0) {
            return Err(RtpError::InvalidPadding(
                "padding flag and padding_size disagree",
            ));
        }
        let size = self.marshal_size();
        if buf.len() < size {
            return Err(RtpError::ShortBuffer {
                got: buf.len(),
                need: size,
            });
        }
        let mut n = self.header.marshal_to(buf)?;
        buf[n..n + self.payload.len()].copy_from_slice(&self.payload);
        n += self.payload.len();
        if self.padding_size > 0 {
            let pad = self.padding_size as usize;
            for b in &mut buf[n..n + pad - 1] {
                *b = 0;
            }
            buf[n + pad - 1] = self.padding_size;
            n += pad;
        }
        Ok(n)
    }

    /// Encodes the packet into a freshly allocated buffer.
    pub fn encode(&self) -> Result<Bytes, RtpError> {
        let mut buf = vec![0u8; self.marshal_size()];
        let n = self.marshal_to(&mut buf)?;
        buf.truncate(n);
        Ok(Bytes::from(buf))
    }
}

// ---- RIST retransmission SSRC marking (ssrc.go) ----
//
// RIST does not use RFC 4588 retransmission payloads. A retransmitted packet is
// the ORIGINAL RTP packet — same seq, timestamp, payload — distinguished only by
// the SSRC least-significant bit. The base flow SSRC must be even (libRIST
// rejects odd flow ids and forces the LSB clear with `flow_id &= ~1UL`); the
// sender sets the LSB on a retransmit (`ssrc = flow_id | 0x01`); the receiver
// tests the LSB and clears it to recover the flow SSRC (`flow_id ^= 1UL`).

/// Returns `ssrc` with its least-significant bit cleared, yielding the base flow
/// SSRC. Applying it to a retransmit-marked SSRC recovers the original.
#[must_use]
pub fn normalize_ssrc(ssrc: u32) -> u32 {
    ssrc & !1
}

/// Returns `ssrc` with its least-significant bit set, marking a retransmission.
/// The retransmission carries the original packet unchanged; this bit is the
/// only difference. This is **not** RFC 4588.
#[must_use]
pub fn mark_retransmit(ssrc: u32) -> u32 {
    ssrc | 1
}

/// Reports whether `ssrc` has its least-significant bit set, i.e. whether the
/// packet carrying it is a RIST retransmission.
#[must_use]
pub fn is_retransmit(ssrc: u32) -> bool {
    ssrc & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Golden {
        name: &'static str,
        pkt: Packet,
        wire: &'static [u8],
    }

    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    fn hdr(
        version: u8,
        padding: bool,
        extension: bool,
        csrc_count: u8,
        marker: bool,
        payload_type: u8,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        csrc: Vec<u32>,
        extension_profile: u16,
        extension_payload: &'static [u8],
    ) -> Header {
        Header {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            extension_profile,
            extension_payload: Bytes::from_static(extension_payload),
        }
    }

    #[allow(clippy::too_many_lines)] // a golden table: the vector literal is the bulk
    fn goldens() -> Vec<Golden> {
        vec![
            Golden {
                // Minimal RIST media packet (RTP_MPEGTS_FLAGS 0x80, PT 0x21,
                // even base-flow SSRC). Payload begins with the MPEG-TS sync 0x47.
                name: "mpegts-minimal",
                pkt: Packet {
                    header: hdr(
                        2,
                        false,
                        false,
                        0,
                        false,
                        PAYLOAD_TYPE_MPEGTS,
                        0x1234,
                        0xDEAD_BEEF,
                        0x4D4F_4F56,
                        vec![],
                        0,
                        b"",
                    ),
                    payload: Bytes::from_static(&[0x47, 0x11, 0x22, 0x33]),
                    padding_size: 0,
                },
                wire: &[
                    0x80, 0x21, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 0x4D, 0x4F, 0x4F, 0x56, 0x47,
                    0x11, 0x22, 0x33,
                ],
            },
            Golden {
                // Retransmission: the original packet with only the SSRC LSB set
                // (0x4D4F4F56 | 1 = 0x4D4F4F57). NOT RFC 4588.
                name: "mpegts-retransmit",
                pkt: Packet {
                    header: hdr(
                        2,
                        false,
                        false,
                        0,
                        false,
                        PAYLOAD_TYPE_MPEGTS,
                        0x1234,
                        0xDEAD_BEEF,
                        0x4D4F_4F57,
                        vec![],
                        0,
                        b"",
                    ),
                    payload: Bytes::from_static(&[0x47, 0x11, 0x22, 0x33]),
                    padding_size: 0,
                },
                wire: &[
                    0x80, 0x21, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 0x4D, 0x4F, 0x4F, 0x57, 0x47,
                    0x11, 0x22, 0x33,
                ],
            },
            Golden {
                // Fully loaded: 2 CSRCs, classic extension with RIST NPD profile
                // 0x5249, one word of ext payload, 2 bytes of padding.
                name: "csrc-extension-padding",
                pkt: Packet {
                    header: hdr(
                        2,
                        true,
                        true,
                        2,
                        true,
                        96,
                        0xFFFF,
                        0x0102_0304,
                        0x1122_3344,
                        vec![0x5566_7788, 0x99AA_BBCC],
                        EXTENSION_PROFILE_RIST,
                        &[0x80, 0x00, 0xAB, 0xCD],
                    ),
                    payload: Bytes::from_static(&[0xDE, 0xAD]),
                    padding_size: 2,
                },
                wire: &[
                    0xB2, 0xE0, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0x52, 0x49, 0x00, 0x01, 0x80, 0x00,
                    0xAB, 0xCD, 0xDE, 0xAD, 0x00, 0x02,
                ],
            },
            Golden {
                // Zero-length classic extension (length field counts words, may
                // be zero). Byte 0 = 0x90 (V=2, X=1).
                name: "empty-extension",
                pkt: Packet {
                    header: hdr(
                        2,
                        false,
                        true,
                        0,
                        false,
                        33,
                        0x0001,
                        0x0000_0002,
                        0x0000_0004,
                        vec![],
                        EXTENSION_PROFILE_RIST,
                        b"",
                    ),
                    payload: Bytes::from_static(&[0xAA]),
                    padding_size: 0,
                },
                wire: &[
                    0x90, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x52,
                    0x49, 0x00, 0x00, 0xAA,
                ],
            },
        ]
    }

    #[test]
    fn golden_marshal() {
        for g in goldens() {
            assert_eq!(g.pkt.marshal_size(), g.wire.len(), "{} size", g.name);
            let mut buf = vec![0u8; g.pkt.marshal_size()];
            let n = g.pkt.marshal_to(&mut buf).unwrap();
            assert_eq!(&buf[..n], g.wire, "{} marshal", g.name);
        }
    }

    #[test]
    fn golden_unmarshal() {
        for g in goldens() {
            let got = Packet::decode(&Bytes::copy_from_slice(g.wire)).unwrap();
            assert_eq!(got, g.pkt, "{} unmarshal", g.name);
            assert_eq!(got.header.csrc_count as usize, g.pkt.header.csrc.len());
        }
    }

    #[test]
    fn golden_round_trip_is_byte_stable() {
        for g in goldens() {
            let encoded = g.pkt.encode().unwrap();
            let decoded = Packet::decode(&encoded).unwrap();
            assert_eq!(decoded, g.pkt, "{} decode(encode(x))", g.name);
            let re = decoded.encode().unwrap();
            assert_eq!(re.as_ref(), g.wire, "{} re-encode byte-stable", g.name);
        }
    }

    #[test]
    fn append_to_after_prefix() {
        for g in goldens() {
            let mut out = vec![0x01u8, 0x02, 0x03];
            // Packet has no append_to; build header+payload manually like the host.
            let mut pkt_buf = vec![0u8; g.pkt.marshal_size()];
            let n = g.pkt.marshal_to(&mut pkt_buf).unwrap();
            out.extend_from_slice(&pkt_buf[..n]);
            assert_eq!(&out[..3], &[0x01, 0x02, 0x03]);
            assert_eq!(&out[3..], g.wire, "{} append", g.name);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // a table test: the case array is the bulk
    fn header_round_trip_table() {
        let cases: Vec<(&str, Header)> = vec![
            ("zero-version", Header::default()),
            (
                "version-3",
                Header {
                    version: 3,
                    ..Header::default()
                },
            ),
            (
                "padding-bit-only",
                Header {
                    version: 2,
                    padding: true,
                    ..Header::default()
                },
            ),
            (
                "marker",
                Header {
                    version: 2,
                    marker: true,
                    payload_type: 0x7F,
                    ..Header::default()
                },
            ),
            (
                "seq-max",
                Header {
                    version: 2,
                    sequence_number: 0xFFFF,
                    ..Header::default()
                },
            ),
            (
                "ts-max",
                Header {
                    version: 2,
                    timestamp: 0xFFFF_FFFF,
                    ..Header::default()
                },
            ),
            (
                "ssrc-max",
                Header {
                    version: 2,
                    ssrc: 0xFFFF_FFFF,
                    ..Header::default()
                },
            ),
            (
                "one-csrc",
                Header {
                    version: 2,
                    csrc: vec![42],
                    ..Header::default()
                },
            ),
            (
                "max-csrc",
                Header {
                    version: 2,
                    csrc: vec![0; 15],
                    ..Header::default()
                },
            ),
            (
                "rist-npd-shape",
                Header {
                    version: 2,
                    extension: true,
                    payload_type: PAYLOAD_TYPE_MPEGTS,
                    sequence_number: 0x8000,
                    timestamp: 90_000,
                    ssrc: 0x0000_CCE0,
                    extension_profile: EXTENSION_PROFILE_RIST,
                    extension_payload: Bytes::from_static(&[0xC0, 0x7F, 0x00, 0x01]),
                    ..Header::default()
                },
            ),
            (
                "long-extension",
                Header {
                    version: 2,
                    extension: true,
                    extension_profile: 0xBEDE,
                    extension_payload: Bytes::from(vec![0x5Au8; 64]),
                    ..Header::default()
                },
            ),
        ];
        for (name, h) in cases {
            let mut wire = Vec::new();
            h.append_to(&mut wire).unwrap();
            assert_eq!(wire.len(), h.marshal_size(), "{name} size");
            let (got, n) = Header::decode(&Bytes::copy_from_slice(&wire)).unwrap();
            assert_eq!(n, wire.len(), "{name} consumed");
            // csrc_count is derived on decode; compare the rest by normalizing it.
            let mut want = h.clone();
            want.csrc_count = h.csrc.len() as u8;
            assert_eq!(got, want, "{name} round trip");
            let mut re = Vec::new();
            got.append_to(&mut re).unwrap();
            assert_eq!(re, wire, "{name} re-encode byte-stable");
        }
    }

    #[test]
    fn unmarshal_padding_cases() {
        let ok: &[(&str, &[u8], &[u8], u8)] = &[
            (
                "padding-3",
                &[
                    0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0xEE, 0x00, 0x00, 0x03,
                ],
                &[0xEE],
                3,
            ),
            (
                "padding-consumes-all",
                &[0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0x00, 0x02],
                &[],
                2,
            ),
            (
                "no-padding-bit",
                &[0x80, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0xEE, 0x03],
                &[0xEE, 0x03],
                0,
            ),
        ];
        for (name, wire, payload, pad) in ok {
            let p = Packet::decode(&Bytes::copy_from_slice(wire)).unwrap();
            assert_eq!(p.payload.as_ref(), *payload, "{name} payload");
            assert_eq!(p.padding_size, *pad, "{name} pad");
        }

        let err: &[(&str, &[u8])] = &[
            (
                "padding-no-count-octet",
                &[0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4],
            ),
            (
                "padding-count-zero",
                &[0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0x00],
            ),
            (
                "padding-count-too-large",
                &[0xA0, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0xEE, 0x05],
            ),
        ];
        for (name, wire) in err {
            assert!(
                Packet::decode(&Bytes::copy_from_slice(wire)).is_err(),
                "{name} must error"
            );
        }
    }

    #[test]
    fn short_inputs_error_not_panic() {
        for len in 0..FIXED_HEADER_SIZE {
            assert!(
                Packet::decode(&Bytes::from(vec![0u8; len])).is_err(),
                "len {len}"
            );
        }
        // X bit set but no extension header.
        assert!(
            Packet::decode(&Bytes::from_static(&[
                0x90, 0x21, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4
            ]))
            .is_err()
        );
    }

    #[test]
    fn ssrc_retransmit_marking() {
        let base = 0x4D4F_4F56;
        assert!(!is_retransmit(base));
        let rtx = mark_retransmit(base);
        assert_eq!(rtx, 0x4D4F_4F57);
        assert!(is_retransmit(rtx));
        assert_eq!(normalize_ssrc(rtx), base);
        assert_eq!(normalize_ssrc(base), base);
        // Idempotent: marking twice keeps a single bit; normalizing recovers.
        assert_eq!(mark_retransmit(rtx), rtx);
        assert_eq!(normalize_ssrc(normalize_ssrc(rtx)), base);
    }

    #[test]
    fn marshal_rejects_bad_headers() {
        let mut buf = [0u8; 64];
        assert!(matches!(
            Header {
                version: 4,
                ..Header::default()
            }
            .marshal_to(&mut buf),
            Err(RtpError::InvalidVersion(4))
        ));
        assert!(matches!(
            Header {
                version: 2,
                csrc: vec![0; 16],
                ..Header::default()
            }
            .marshal_to(&mut buf),
            Err(RtpError::TooManyCsrc(16))
        ));
        assert!(matches!(
            Header {
                version: 2,
                extension: true,
                extension_payload: Bytes::from_static(&[0, 0, 0]),
                ..Header::default()
            }
            .marshal_to(&mut buf),
            Err(RtpError::ExtensionNotAligned(3))
        ));
    }
}
