//! The SMPTE ST 2022-1 and ST 2022-5 forward-error-correction header byte layouts
//! (TR-06-2 §8.4, TR-06-3 §5.3.5, SMPTE ST 2022-5:2013 §7.3), byte-exact with
//! libRIST. Ported from ristgo `internal/fec/header.go` + `header2022_5.go`.
//!
//! The XOR matrix logic and the ISN-independent recovery live in
//! [`rist_core::fec`]; this module is only the wire framing. It encodes a parsed
//! [`fec::Packet`] (the narrow waist between the matrix logic and the wire) into the
//! 16-byte FEC header that precedes the recovery payload, and decodes those header
//! bytes back into a [`fec::Packet`] for the decoder. The header carries the group's
//! base sequence (24-bit for ST 2022-1, 16-bit for ST 2022-5 — the decoder widens
//! it), the geometry (`offset`/`na`), and the length/payload-type/timestamp recovery
//! fields.
//!
//! Both variants drive the same XOR matrix; only the layout and field widths differ:
//! ST 2022-5 carries a 16-bit base and 10-bit Offset/NA (raising the matrix ceiling
//! to 1020 per dimension) plus explicit recovery bits for the RTP padding, extension,
//! CSRC-count, and marker fields. RIST media sets none of those, so this module
//! emits them zero and ignores them on parse.

// The codec reads/writes fixed-width big-endian fields and packs the narrow FEC
// geometry fields (8-bit ST 2022-1, 10-bit ST 2022-5); the casts are bounded
// truncations into those widths by construction (the host validates the matrix
// bounds). Error/panic behavior is covered by the module-level wire-format prose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use bytes::Bytes;
use rist_core::fec::{self, Direction, Variant};

/// The size of a SMPTE ST 2022-1 / ST 2022-5 FEC header (both are 16 bytes), which
/// precedes the recovery payload in every FEC packet.
pub const HEADER_SIZE: usize = 16;

/// Errors returned by the FEC header codec. User-facing `Display` strings are
/// prefixed `"rist: fec: "` to match the rest of the stack.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FecHeaderError {
    /// The buffer is smaller than the fixed 16-byte FEC header.
    #[error("rist: fec: buffer shorter than the FEC header")]
    ShortHeader,
}

/// Encode a FEC [`fec::Packet`] to its on-the-wire bytes (the 16-byte header in the
/// requested [`Variant`] followed by the recovery payload).
///
/// The base sequence is truncated to the variant's width (24-bit for ST 2022-1,
/// 16-bit for ST 2022-5); the decoder widens it against its window. For ST 2022-1
/// the `offset`/`na` geometry occupies one byte each (the host validates L,D <= 20),
/// for ST 2022-5 the high 10 bits of an octet pair.
#[must_use]
pub fn encode(packet: &fec::Packet, variant: Variant) -> Bytes {
    let mut out = Vec::with_capacity(HEADER_SIZE + packet.payload.len());
    let mut h = [0u8; HEADER_SIZE];
    match variant {
        Variant::St20221 => {
            // | SNBase(16) | LengthRecovery(16) | E=0 PTRecovery(7) | Mask(24)=0 |
            // | TSRecovery(32) | N=0 D(1) type(3)=0 index(3)=0 | Offset(8) | NA(8) |
            // | SNBaseExt(8) |
            h[0..2].copy_from_slice(&(packet.base as u16).to_be_bytes());
            h[2..4].copy_from_slice(&packet.length_recovery.to_be_bytes());
            h[4] = packet.pt_recovery & 0x7f; // E (bit 7) = 0
            h[8..12].copy_from_slice(&packet.ts_recovery.to_be_bytes());
            h[12] = u8::from(packet.direction == Direction::Row) << 6; // D bit
            h[13] = packet.offset as u8;
            h[14] = packet.na as u8;
            h[15] = (packet.base >> 16) as u8; // SNBaseExt (base bits 16..23)
        }
        Variant::St20225 => {
            // | E=0 R=0 P X CC(4) | M PTRecovery(7) | SNBase(16) | TSRecovery(32) |
            // | LengthRecovery(16) | Reserved(16)=0 | Offset(10)<<6 | NA(10)<<6 |
            // P/X/CC/M (RTP padding/extension/CSRC-count/marker recovery) are unset
            // for RIST media.
            h[1] = packet.pt_recovery & 0x7f; // M (bit 7) = 0
            h[2..4].copy_from_slice(&(packet.base as u16).to_be_bytes());
            h[4..8].copy_from_slice(&packet.ts_recovery.to_be_bytes());
            h[8..10].copy_from_slice(&packet.length_recovery.to_be_bytes());
            h[12..14].copy_from_slice(&((packet.offset & NA10_MAX) << 6).to_be_bytes());
            h[14..16].copy_from_slice(&((packet.na & NA10_MAX) << 6).to_be_bytes());
        }
    }
    out.extend_from_slice(&h);
    out.extend_from_slice(&packet.payload);
    Bytes::from(out)
}

/// The largest value the ST 2022-5 10-bit Offset/NA fields can hold.
const NA10_MAX: u16 = 0x3ff;

/// Decode a FEC header (in the given [`Variant`]) and the recovery payload that
/// follows it into a [`fec::Packet`]. Never panics on short or arbitrary input.
///
/// The recovered `base` is the truncated wire value (the decoder widens it). For
/// ST 2022-5 the header carries no explicit direction bit, so the [`Direction`] is
/// derived from the geometry (`offset == 1` is a row); the decoder relies on
/// `offset`/`na`, not the direction, so this is purely informational.
pub fn decode(buf: &[u8], variant: Variant) -> Result<fec::Packet, FecHeaderError> {
    if buf.len() < HEADER_SIZE {
        return Err(FecHeaderError::ShortHeader);
    }
    let h = &buf[..HEADER_SIZE];
    let payload = Bytes::copy_from_slice(&buf[HEADER_SIZE..]);
    let packet = match variant {
        Variant::St20221 => {
            let sn_base = u16::from_be_bytes([h[0], h[1]]);
            let sn_base_ext = h[15];
            let base = (u32::from(sn_base_ext) << 16) | u32::from(sn_base);
            let direction = if (h[12] >> 6) & 0x1 == 1 {
                Direction::Row
            } else {
                Direction::Column
            };
            fec::Packet {
                direction,
                base,
                offset: u16::from(h[13]),
                na: u16::from(h[14]),
                length_recovery: u16::from_be_bytes([h[2], h[3]]),
                pt_recovery: h[4] & 0x7f,
                ts_recovery: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
                payload,
            }
        }
        Variant::St20225 => {
            let offset = u16::from_be_bytes([h[12], h[13]]) >> 6;
            let na = u16::from_be_bytes([h[14], h[15]]) >> 6;
            let direction = if offset == 1 {
                Direction::Row
            } else {
                Direction::Column
            };
            fec::Packet {
                direction,
                base: u32::from(u16::from_be_bytes([h[2], h[3]])),
                offset,
                na,
                length_recovery: u16::from_be_bytes([h[8], h[9]]),
                pt_recovery: h[1] & 0x7f,
                ts_recovery: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
                payload,
            }
        }
    };
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(direction: Direction, base: u32, offset: u16, na: u16) -> fec::Packet {
        fec::Packet {
            direction,
            base,
            offset,
            na,
            length_recovery: 1316,
            pt_recovery: 96,
            ts_recovery: 0xDEAD_BEEF,
            payload: Bytes::from_static(b"recovery-payload"),
        }
    }

    #[test]
    fn st2022_1_golden_bytes() {
        // Ported from ristgo internal/fec TestHeaderRoundTrip case 1: SNBase 0x1234,
        // SNBaseExt 0x07 (base 0x071234), length 1316, pt 96, ts 0xDEADBEEF, column,
        // offset 10, na 5.
        let p = pkt(Direction::Column, 0x0007_1234, 10, 5);
        let bytes = encode(&p, Variant::St20221);
        assert_eq!(
            &bytes[..HEADER_SIZE],
            &[
                0x12, 0x34, // SNBase
                0x05, 0x24, // LengthRecovery = 1316
                0x60, // PTRecovery 96
                0x00, 0x00, 0x00, // Mask
                0xDE, 0xAD, 0xBE, 0xEF, // TSRecovery
                0x00, // D=0 (column)
                0x0A, // Offset 10
                0x05, // NA 5
                0x07, // SNBaseExt
            ]
        );
        assert_eq!(&bytes[HEADER_SIZE..], b"recovery-payload");
    }

    #[test]
    fn st2022_1_row_golden_bytes() {
        // Ported from ristgo TestHeaderRoundTrip case 2: SNBase 0xFFFF, SNBaseExt 0xFF
        // (base 0xFFFFFF), length 0, pt 0x7F, ts 0, row, offset 1, na 10.
        let mut p = pkt(Direction::Row, 0x00FF_FFFF, 1, 10);
        p.length_recovery = 0;
        p.pt_recovery = 0x7F;
        p.ts_recovery = 0;
        p.payload = Bytes::new();
        let bytes = encode(&p, Variant::St20221);
        assert_eq!(
            &bytes[..],
            &[
                0xFF, 0xFF, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01,
                0x0A, 0xFF,
            ]
        );
    }

    #[test]
    fn st2022_5_golden_bytes() {
        // Ported from ristgo internal/fec TestHeader5RoundTrip case 1: pt 96, SNBase
        // 0x1234, ts 0xDEADBEEF, length 1316, offset 5, na 4.
        let p = pkt(Direction::Column, 0x1234, 5, 4);
        let bytes = encode(&p, Variant::St20225);
        assert_eq!(
            &bytes[..HEADER_SIZE],
            &[
                0x00, // E R P X CC
                0x60, // M=0, PT 96
                0x12, 0x34, // SNBase
                0xDE, 0xAD, 0xBE, 0xEF, // TSRecovery
                0x05, 0x24, // LengthRecovery 1316
                0x00, 0x00, // Reserved
                0x01, 0x40, // Offset 5 << 6
                0x01, 0x00, // NA 4 << 6
            ]
        );
        assert_eq!(&bytes[HEADER_SIZE..], b"recovery-payload");
    }

    #[test]
    fn round_trip_st2022_1() {
        for (dir, base, off, na) in [
            (Direction::Column, 0x0007_1234u32, 10u16, 5u16),
            (Direction::Row, 0x00FF_FFFF, 1, 10),
            (Direction::Column, 0, 20, 20),
        ] {
            let p = pkt(dir, base, off, na);
            let got = decode(&encode(&p, Variant::St20221), Variant::St20221).unwrap();
            assert_eq!(got, p, "ST 2022-1 round-trip");
        }
    }

    #[test]
    fn round_trip_st2022_5() {
        // The base round-trips only within the 16-bit wire width (decode yields the
        // truncated base the decoder widens); use bases that fit 16 bits. ST 2022-5
        // carries no direction bit, so the decode derives it from the geometry
        // (offset == 1 is a row) — set each test packet's direction to match.
        for (base, off, na) in [
            (0x1234u32, 5u16, 4u16),
            (0xFFFF, 1, 20),
            (0x8001, NA10_MAX, NA10_MAX),
        ] {
            let dir = if off == 1 {
                Direction::Row
            } else {
                Direction::Column
            };
            let p = pkt(dir, base, off, na);
            let got = decode(&encode(&p, Variant::St20225), Variant::St20225).unwrap();
            assert_eq!(got, p, "ST 2022-5 round-trip");
        }
    }

    #[test]
    fn st2022_5_reserved_bits_are_ignored_on_decode() {
        // Reserved bits (E/R, the Offset/NA octets' low 6, b[10:12]) must not leak
        // into the decoded geometry (ristgo TestHeader5RoundTrip reserved-bit case).
        let p = pkt(Direction::Column, 7, 5, 4);
        let mut bytes = encode(&p, Variant::St20225).to_vec();
        bytes[0] |= 0xC0; // E, R
        bytes[10] = 0xFF; // Reserved
        bytes[11] = 0xFF;
        bytes[13] |= 0x3F; // Offset's 6 reserved low bits
        bytes[15] |= 0x3F; // NA's 6 reserved low bits
        let got = decode(&bytes, Variant::St20225).unwrap();
        assert_eq!(
            (got.base, got.offset, got.na),
            (7, 5, 4),
            "reserved bits leaked into fields"
        );
    }

    #[test]
    fn short_buffer_is_rejected() {
        assert_eq!(
            decode(&[0u8; HEADER_SIZE - 1], Variant::St20221),
            Err(FecHeaderError::ShortHeader)
        );
        assert_eq!(
            decode(&[0u8; HEADER_SIZE - 1], Variant::St20225),
            Err(FecHeaderError::ShortHeader)
        );
        // Exactly the header with no payload decodes to an empty payload.
        assert!(
            decode(&[0u8; HEADER_SIZE], Variant::St20221)
                .unwrap()
                .payload
                .is_empty()
        );
    }

    #[test]
    fn decode_then_encode_through_the_core_decoder() {
        // The bridge a session uses: a core-encoded Packet -> header bytes -> decode
        // -> the same geometry/recovery fields the core decoder consumes (its base is
        // the truncated wire value, widened by the decoder).
        let p = pkt(Direction::Column, 0x0012_3456, 8, 8);
        let decoded = decode(&encode(&p, Variant::St20221), Variant::St20221).unwrap();
        assert_eq!(decoded.offset, 8);
        assert_eq!(decoded.na, 8);
        assert_eq!(decoded.base & 0x00FF_FFFF, 0x0012_3456 & 0x00FF_FFFF);
        assert_eq!(decoded.length_recovery, p.length_recovery);
        assert_eq!(decoded.ts_recovery, p.ts_recovery);
        assert_eq!(decoded.pt_recovery, p.pt_recovery);
    }
}
