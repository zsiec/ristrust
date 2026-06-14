//! RIST null-packet deletion (NPD) and the RIST RTP header extension that carries
//! it (VSF TR-06-2 §8), byte-exact with libRIST v0.2.18-rc1. Ported from ristgo
//! `internal/npd`.
//!
//! NPD is a Main-profile feature (the Simple profile has no RTP header extension
//! and no NPD) that saves bandwidth on MPEG-TS payloads: a packetized media
//! payload is a whole number of TS packets (each 188 bytes, or 204 when
//! forward-error-correction parity is appended), at most 7 of them. TS null
//! packets — PID 0x1FFF, carrying no media — are removed before transmission and
//! reconstructed identically at the receiver, with a 7-bit bitmap in the RTP
//! header extension recording which positions were nulled.
//!
//! The RTP header extension is the RFC 3550 profile-specific extension (signalled
//! by the RTP X bit) with profile identifier 0x5249 (ASCII "RI", big-endian) and
//! length 1 (one 32-bit word of extension payload). Its eight wire bytes are:
//! identifier(2) + length(2) + flags(1) + npd_bits(1) + seq_ext(2). The flags
//! byte's bit 7 (N) signals NPD is present; npd_bits' bit 7 selects 204- vs
//! 188-byte TS packets and bits 6..0 are the null bitmap; seq_ext carries the high
//! 16 bits of a 32-bit extended sequence number. libRIST populates and reads
//! seq_ext only on the Advanced path, never on Simple/Main, so a Main-profile
//! receiver widens the media sequence by 16-bit rollover instead.
//!
//! # Deliberate deviation from TR-06-2 Figure 15
//!
//! The spec's flags byte is N|E|Size(3 bits)|0 0 0|T, placing the 188/204 size
//! selector (T) in the flags byte (bit 0) and defining an E bit (bit 6) and a
//! 3-bit Size field. libRIST instead encodes the size selector in npd_bits bit 7
//! and emits only flags bit 7 (N), never setting E, Size, or the spec's T bit.
//! This module follows libRIST for interop: [`NPD_SIZE_204`] is npd_bits bit 7,
//! the E and Size fields are intentionally unmodeled, and the null-bitmap ordering
//! (MSB = first packet) matches both.
//!
//! The suppress/expand algorithm is ported from libRIST (`suppress_null_packets` /
//! `expand_null_packets`). This module is pure: it does no I/O, reads no clock, and
//! never panics on malformed input.

// Justification: the codec reads/writes fixed-width big-endian fields and the
// 1-bit flags; the slice indexing is bounds-checked up front. Error/panic docs are
// covered by the module-level wire-format prose.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

/// Errors returned by the NPD codec. User-facing `Display` strings are prefixed
/// `"rist: npd: "` to match the rest of the stack.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NpdError {
    /// The buffer is smaller than the fixed 8-byte RIST RTP header extension.
    #[error("rist: npd: header extension too short")]
    ShortExt,
    /// The extension profile identifier is not 0x5249, the RIST "RI" value.
    #[error("rist: npd: header extension identifier is not 0x5249")]
    BadIdentifier,
    /// The extension length field is not 1, the only value RIST emits.
    #[error("rist: npd: header extension length is not 1")]
    BadLength,
    /// The input is not a whole number of 188- or 204-byte TS packets.
    #[error("rist: npd: payload is not a whole number of 188- or 204-byte TS packets")]
    PayloadSize,
    /// The input holds more than 7 TS packets, the maximum the 7-bit bitmap can
    /// address.
    #[error("rist: npd: more than 7 TS packets")]
    TooManyPackets,
    /// A TS packet does not begin with the 0x47 sync byte.
    #[error("rist: npd: TS packet missing 0x47 sync byte")]
    SyncByte,
    /// The kept-packet input is too short to satisfy the non-null positions the
    /// bitmap describes.
    #[error("rist: npd: input too short for npd bitmap")]
    Truncated,
}

/// The RFC 3550 profile-specific extension identifier of the RIST NPD header
/// extension: 0x5249, ASCII "RI" big-endian.
pub const IDENTIFIER: u16 = 0x5249;

/// The extension length in 32-bit words, always 1: the four extension-payload
/// bytes are flags + npd_bits + seq_ext.
pub const LENGTH: u16 = 1;

/// The size in bytes of the encoded RIST RTP header extension: identifier(2) +
/// length(2) + flags(1) + npd_bits(1) + seq_ext(2).
pub const EXT_SIZE: usize = 8;

/// The bit in the flags byte set when NPD is present.
pub const FLAG_NPD: u8 = 1 << 7;

/// The bit in the npd_bits byte set when the TS packets are 204 bytes rather than
/// 188.
pub const NPD_SIZE_204: u8 = 1 << 7;

/// Masks the low 7 bits of npd_bits: the null-position bitmap (bit 6-i set means TS
/// packet i was a null packet).
pub const NULL_BITMAP_MASK: u8 = 0x7F;

/// The maximum number of TS packets a single NPD payload may hold, bounded by the
/// 7-bit bitmap.
pub const MAX_PACKETS: usize = 7;

/// The standard MPEG-TS packet size in bytes.
pub const SIZE_TS_188: usize = 188;

/// The MPEG-TS packet size in bytes with the 16-byte Reed-Solomon parity trailer.
pub const SIZE_TS_204: usize = 204;

/// The MPEG-TS packet sync byte, the first byte of every TS packet.
pub const SYNC_BYTE: u8 = 0x47;

/// The MPEG-TS null-packet PID, 0x1FFF, occupying the 13-bit PID field of the
/// 16-bit flags1 word.
pub const NULL_PID: u16 = 0x1FFF;

/// The size in bytes of the MPEG-TS packet header libRIST reconstructs for a null
/// packet: syncbyte(1) + flags1(2) + flags2(1).
const TS_HEADER_SIZE: usize = 4;

/// The bit libRIST sets in the fourth MPEG-TS header byte of a reconstructed null
/// packet (the low bit of the adaptation-field-control field, marking payload
/// present).
const FLAGS2_BIT4: u8 = 1 << 4;

/// The RIST RTP header extension. It carries the NPD presence flag, the TS packet
/// size selector, the 7-bit null bitmap, and the high 16 bits of the extended
/// sequence number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ext {
    /// Whether the NPD flag (flags bit 7) is set: the payload has had null packets
    /// removed and `null_bitmap` describes them.
    pub npd: bool,
    /// Whether the TS packets are 204 bytes (npd_bits bit 7) rather than 188.
    pub size204: bool,
    /// The 7-bit null-position map stored in the low 7 bits of npd_bits. Bit (6-i)
    /// set means TS packet i (0..6) was a null packet. Only the low 7 bits are
    /// significant; [`Ext::append_to`] masks the rest.
    pub null_bitmap: u8,
    /// The high 16 bits of a 32-bit extended RTP sequence number. libRIST populates
    /// and consumes this only in the Advanced profile; on the Simple/Main path it is
    /// always 0 and the receiver ignores it, widening by rollover instead.
    pub seq_ext: u16,
}

impl Ext {
    /// Appends the 8-byte wire encoding of the extension to `dst`. The byte order
    /// is: identifier(2, big-endian) + length(2, big-endian) + flags(1) +
    /// npd_bits(1) + seq_ext(2, big-endian). `null_bitmap` is masked to 7 bits.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        let mut flags: u8 = 0;
        if self.npd {
            flags |= FLAG_NPD;
        }
        let mut bits = self.null_bitmap & NULL_BITMAP_MASK;
        if self.size204 {
            bits |= NPD_SIZE_204;
        }
        dst.extend_from_slice(&IDENTIFIER.to_be_bytes());
        dst.extend_from_slice(&LENGTH.to_be_bytes());
        dst.push(flags);
        dst.push(bits);
        dst.extend_from_slice(&self.seq_ext.to_be_bytes());
    }

    /// Decodes the 8-byte RIST RTP header extension at the start of `b`, returning
    /// the parsed `Ext` and the number of bytes consumed (always [`EXT_SIZE`] on
    /// success). The identifier must be 0x5249 and the length must be 1.
    pub fn parse(b: &[u8]) -> Result<(Ext, usize), NpdError> {
        if b.len() < EXT_SIZE {
            return Err(NpdError::ShortExt);
        }
        if u16::from_be_bytes([b[0], b[1]]) != IDENTIFIER {
            return Err(NpdError::BadIdentifier);
        }
        if u16::from_be_bytes([b[2], b[3]]) != LENGTH {
            return Err(NpdError::BadLength);
        }
        let flags = b[4];
        let bits = b[5];
        let e = Ext {
            npd: flags & FLAG_NPD != 0,
            size204: bits & NPD_SIZE_204 != 0,
            null_bitmap: bits & NULL_BITMAP_MASK,
            seq_ext: u16::from_be_bytes([b[6], b[7]]),
        };
        Ok((e, EXT_SIZE))
    }
}

/// Assembles the npd_bits byte (size flag in bit 7, null bitmap in bits 6..0) from
/// a size selector and a 7-bit bitmap. It is the value [`suppress`] returns and
/// [`expand`] consumes.
#[must_use]
pub fn npd_bits(size204: bool, bitmap: u8) -> u8 {
    let mut b = bitmap & NULL_BITMAP_MASK;
    if size204 {
        b |= NPD_SIZE_204;
    }
    b
}

/// The TS packet size encoded by npd_bits bit 7.
fn packet_size(bits: u8) -> usize {
    if bits & NPD_SIZE_204 != 0 {
        SIZE_TS_204
    } else {
        SIZE_TS_188
    }
}

/// Removes MPEG-TS null packets (PID 0x1FFF) from `input`, appending the kept
/// packets to `dst`, and returns `(npd_bits, suppressed_bytes)`: the npd_bits byte
/// to place in an [`Ext`] (size flag in bit 7, null bitmap in bits 6..0) and the
/// number of suppressed bytes. Ports libRIST `suppress_null_packets`.
///
/// `input` must be a whole number of TS packets, each 188 bytes — or 204 if the
/// length is not a multiple of 188 — and at most 7 packets. Each packet must begin
/// with the 0x47 sync byte. When no null packets are found, `suppressed` is 0,
/// `npd_bits` carries only the (possibly set) size bit, and the whole input is
/// copied to `dst` unchanged: NPD is not applied. When `suppressed > 0` the caller
/// sets the [`Ext`] NPD flag and emits `npd_bits`.
pub fn suppress(dst: &mut Vec<u8>, input: &[u8]) -> Result<(u8, usize), NpdError> {
    let mut bits: u8 = 0;
    let mut size = SIZE_TS_188;
    if !input.len().is_multiple_of(size) {
        size = SIZE_TS_204;
        if !input.len().is_multiple_of(size) {
            return Err(NpdError::PayloadSize);
        }
        bits = NPD_SIZE_204;
    }
    let count = input.len() / size;
    if count > MAX_PACKETS {
        return Err(NpdError::TooManyPackets);
    }

    // First pass: validate sync bytes and record the null bitmap. Match libRIST: a
    // bad sync byte fails the whole payload.
    let mut suppressed = 0usize;
    for i in 0..count {
        let off = i * size;
        if input[off] != SYNC_BYTE {
            return Err(NpdError::SyncByte);
        }
        // A null packet has PID 0x1FFF; the whole flags1 word reads 0x1FFF.
        if u16::from_be_bytes([input[off + 1], input[off + 2]]) == NULL_PID {
            bits |= 1 << (6 - i);
            suppressed += 1;
        }
    }

    if suppressed == 0 {
        // No NPD: copy the input through unchanged (the caller will not set the NPD
        // flag). npd_bits still carries only the size bit.
        dst.extend_from_slice(input);
        return Ok((bits, 0));
    }

    // Second pass: copy only the non-null packets.
    for i in 0..count {
        if bits & (1 << (6 - i)) == 0 {
            let off = i * size;
            dst.extend_from_slice(&input[off..off + size]);
        }
    }
    Ok((bits, suppressed * size))
}

/// Reinserts MPEG-TS null packets into the kept-packet payload `input`, appending
/// the reconstructed full payload to `dst`, using `bits` (the size flag and 7-bit
/// null bitmap from an [`Ext`]). Ports libRIST `expand_null_packets`.
///
/// Each reconstructed null packet matches libRIST byte-for-byte: sync byte 0x47,
/// flags1 = 0x1FFF (big-endian), flags2 bit 4 set, and the remaining
/// `packet_size-4` bytes filled with 0xFF. `packet_size` is 204 when npd_bits bit 7
/// is set, else 188. When the bitmap names no nulls, `input` is copied through
/// unchanged. An error is returned (never a panic) when `input` is too short for
/// the non-null positions or when the reconstructed packet count would exceed 7.
pub fn expand(dst: &mut Vec<u8>, input: &[u8], bits: u8) -> Result<(), NpdError> {
    let size = packet_size(bits);
    let ts_count = input.len() / size;
    let bitmap = bits & NULL_BITMAP_MASK;
    let null_count = bitmap.count_ones() as usize;

    if null_count == 0 {
        // No nulls to reinsert: pass the input through unchanged.
        dst.extend_from_slice(input);
        return Ok(());
    }

    // npd_bits only encodes 7 positions, so a reconstructed count over 7 means
    // malformed/hostile input. libRIST no-ops here (delivering the payload
    // un-expanded); ristgo/ristrust instead reject it defensively rather than
    // deliver a wrongly-expanded payload. A conformant sender never produces this.
    let total = ts_count + null_count;
    if total > MAX_PACKETS {
        return Err(NpdError::TooManyPackets);
    }

    let mut in_off = 0usize;
    for i in 0..total {
        if bitmap & (1 << (6 - i)) == 0 {
            // A kept (non-null) packet: copy it from the input.
            if in_off + size > input.len() {
                return Err(NpdError::Truncated);
            }
            dst.extend_from_slice(&input[in_off..in_off + size]);
            in_off += size;
        } else {
            // Reconstruct a null packet.
            append_null_packet(dst, size);
        }
    }
    Ok(())
}

/// Appends a single reconstructed null TS packet of `size` bytes to `dst`, matching
/// libRIST byte-for-byte: 0x47 sync byte, flags1 = 0x1FFF big-endian, flags2 with
/// bit 4 set, then 0xFF fill.
fn append_null_packet(dst: &mut Vec<u8>, size: usize) {
    dst.push(SYNC_BYTE);
    dst.push(0x1F);
    dst.push(0xFF);
    dst.push(FLAGS2_BIT4);
    dst.resize(dst.len() + (size - TS_HEADER_SIZE), 0xFF);
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // synthetic TS PIDs/fills fit u8/u16 by construction
mod tests {
    use super::*;

    /// Builds a synthetic 188- or 204-byte MPEG-TS packet with the given 13-bit PID
    /// (ristgo `tsPacket`).
    fn ts_packet(size: usize, pid: u16, fill: u8) -> Vec<u8> {
        let mut p = vec![fill; size];
        p[0] = SYNC_BYTE;
        p[1] = (pid >> 8) as u8;
        p[2] = pid as u8;
        p[3] = 0x10; // arbitrary flags2 for media packets
        p
    }

    /// Builds a TS null packet exactly as libRIST reconstructs one (ristgo
    /// `nullPacket`): 0x47, 0x1FFF, flags2 bit4, 0xFF fill.
    fn null_packet(size: usize) -> Vec<u8> {
        let mut p = vec![0xFF; size];
        p[0] = SYNC_BYTE;
        p[1] = 0x1F;
        p[2] = 0xFF;
        p[3] = FLAGS2_BIT4;
        p
    }

    #[test]
    fn ext_golden() {
        let cases: &[(&str, Ext, [u8; 8])] = &[
            (
                "npd 188 two nulls",
                Ext {
                    npd: true,
                    size204: false,
                    null_bitmap: 0x50,
                    seq_ext: 0x1234,
                },
                [0x52, 0x49, 0x00, 0x01, 0x80, 0x50, 0x12, 0x34],
            ),
            (
                "npd 204 one null",
                Ext {
                    npd: true,
                    size204: true,
                    null_bitmap: 0x40,
                    seq_ext: 0xABCD,
                },
                [0x52, 0x49, 0x00, 0x01, 0x80, 0xC0, 0xAB, 0xCD],
            ),
            (
                "empty",
                Ext::default(),
                [0x52, 0x49, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                "bitmap masked",
                Ext {
                    npd: true,
                    null_bitmap: 0xFF,
                    seq_ext: 0x0001,
                    ..Ext::default()
                },
                [0x52, 0x49, 0x00, 0x01, 0x80, 0x7F, 0x00, 0x01],
            ),
        ];
        for (name, ext, want) in cases {
            let mut got = Vec::new();
            ext.append_to(&mut got);
            assert_eq!(got, want, "{name} append");
            let (back, n) = Ext::parse(&got).unwrap();
            assert_eq!(n, EXT_SIZE, "{name} consumed");
            let mut want_back = *ext;
            want_back.null_bitmap &= NULL_BITMAP_MASK;
            assert_eq!(back, want_back, "{name} parse");
        }
    }

    #[test]
    fn append_to_preserves_prefix() {
        let mut got = vec![0xDE, 0xAD];
        Ext {
            npd: true,
            seq_ext: 0x0102,
            ..Ext::default()
        }
        .append_to(&mut got);
        assert_eq!(
            got,
            [0xDE, 0xAD, 0x52, 0x49, 0x00, 0x01, 0x80, 0x00, 0x01, 0x02]
        );
    }

    #[test]
    fn parse_ext_errors() {
        let cases: &[(&str, &[u8], NpdError)] = &[
            ("nil", &[], NpdError::ShortExt),
            (
                "short",
                &[0x52, 0x49, 0x00, 0x01, 0x80, 0x00, 0x12],
                NpdError::ShortExt,
            ),
            (
                "bad identifier",
                &[0x52, 0x48, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00],
                NpdError::BadIdentifier,
            ),
            (
                "bad length 0",
                &[0x52, 0x49, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00],
                NpdError::BadLength,
            ),
            (
                "bad length 2",
                &[0x52, 0x49, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00],
                NpdError::BadLength,
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(Ext::parse(input), Err(want.clone()), "{name}");
        }
    }

    #[test]
    fn npd_bits_helper() {
        let cases: &[(bool, u8, u8)] = &[
            (false, 0x00, 0x00),
            (false, 0x40, 0x40),
            (true, 0x40, 0xC0),
            (true, 0x00, 0x80),
            (false, 0xFF, 0x7F),
            (true, 0xFF, 0xFF),
        ];
        for &(size204, bitmap, want) in cases {
            assert_eq!(
                npd_bits(size204, bitmap),
                want,
                "size204={size204} bitmap={bitmap:#x}"
            );
        }
    }

    struct RoundTrip {
        name: &'static str,
        size: usize,
        null_mask: &'static [bool],
        want_supp: usize,
        want_bitmap: u8,
    }

    #[test]
    fn suppress_expand_round_trip() {
        let cases = [
            RoundTrip {
                name: "single media",
                size: SIZE_TS_188,
                null_mask: &[false],
                want_supp: 0,
                want_bitmap: 0x00,
            },
            RoundTrip {
                name: "single null",
                size: SIZE_TS_188,
                null_mask: &[true],
                want_supp: SIZE_TS_188,
                want_bitmap: 0x40,
            },
            RoundTrip {
                name: "two: null,media",
                size: SIZE_TS_188,
                null_mask: &[true, false],
                want_supp: SIZE_TS_188,
                want_bitmap: 0x40,
            },
            RoundTrip {
                name: "two: media,null",
                size: SIZE_TS_188,
                null_mask: &[false, true],
                want_supp: SIZE_TS_188,
                want_bitmap: 0x20,
            },
            RoundTrip {
                name: "seven all media",
                size: SIZE_TS_188,
                null_mask: &[false; 7],
                want_supp: 0,
                want_bitmap: 0x00,
            },
            RoundTrip {
                name: "seven all null",
                size: SIZE_TS_188,
                null_mask: &[true; 7],
                want_supp: 7 * SIZE_TS_188,
                want_bitmap: 0x7F,
            },
            RoundTrip {
                name: "seven mixed",
                size: SIZE_TS_188,
                null_mask: &[false, true, false, true, false, true, false],
                want_supp: 3 * SIZE_TS_188,
                want_bitmap: 0x2A,
            },
            RoundTrip {
                name: "204 single null",
                size: SIZE_TS_204,
                null_mask: &[true],
                want_supp: SIZE_TS_204,
                want_bitmap: 0x80 | 0x40,
            },
            RoundTrip {
                name: "204 mixed",
                size: SIZE_TS_204,
                null_mask: &[true, false, true],
                want_supp: 2 * SIZE_TS_204,
                want_bitmap: 0x80 | 0x40 | 0x10,
            },
        ];
        for c in &cases {
            let mut orig = Vec::new();
            for (i, &is_null) in c.null_mask.iter().enumerate() {
                if is_null {
                    orig.extend_from_slice(&null_packet(c.size));
                } else {
                    orig.extend_from_slice(&ts_packet(c.size, 0x100 + i as u16, i as u8));
                }
            }

            let mut kept = Vec::new();
            let (bits, suppressed) = suppress(&mut kept, &orig).unwrap();
            assert_eq!(suppressed, c.want_supp, "{} suppressed", c.name);
            assert_eq!(bits, c.want_bitmap, "{} npd_bits", c.name);
            assert_eq!(
                kept.len(),
                orig.len() - suppressed,
                "{} kept length",
                c.name
            );

            let mut got = Vec::new();
            expand(&mut got, &kept, bits).unwrap();
            assert_eq!(got, orig, "{} round trip", c.name);
        }
    }

    #[test]
    fn suppress_no_nulls_copies_through() {
        let mut orig = ts_packet(SIZE_TS_188, 0x100, 0x11);
        orig.extend_from_slice(&ts_packet(SIZE_TS_188, 0x200, 0x22));
        let mut out = Vec::new();
        let (bits, suppressed) = suppress(&mut out, &orig).unwrap();
        assert_eq!(suppressed, 0);
        assert_eq!(bits, 0);
        assert_eq!(out, orig);
    }

    #[test]
    fn suppress_errors() {
        let mut sink = Vec::new();
        assert_eq!(suppress(&mut sink, &[0u8; 100]), Err(NpdError::PayloadSize));
        sink.clear();
        assert_eq!(
            suppress(&mut sink, &[0u8; 8 * SIZE_TS_188]),
            Err(NpdError::TooManyPackets)
        );
        sink.clear();
        let mut bad = ts_packet(SIZE_TS_188, 0x100, 0x00);
        bad[0] = 0x48;
        assert_eq!(suppress(&mut sink, &bad), Err(NpdError::SyncByte));
    }

    #[test]
    fn suppress_204_not_multiple_of_188() {
        // 3*204 = 612, which is not a multiple of 188.
        assert_ne!((3 * SIZE_TS_204) % SIZE_TS_188, 0);
        let mut orig = null_packet(SIZE_TS_204);
        orig.extend_from_slice(&ts_packet(SIZE_TS_204, 0x100, 0x33));
        orig.extend_from_slice(&null_packet(SIZE_TS_204));
        let mut out = Vec::new();
        let (bits, suppressed) = suppress(&mut out, &orig).unwrap();
        assert_ne!(bits & NPD_SIZE_204, 0, "size bit not set: {bits:#x}");
        assert_eq!(suppressed, 2 * SIZE_TS_204);
    }

    #[test]
    fn expand_no_nulls_copies_through() {
        let mut input = ts_packet(SIZE_TS_188, 0x100, 0x11);
        input.extend_from_slice(&ts_packet(SIZE_TS_188, 0x200, 0x22));
        let mut got = Vec::new();
        expand(&mut got, &input, 0x00).unwrap();
        assert_eq!(got, input);
    }

    #[test]
    fn expand_truncated() {
        // Bitmap names a kept slot but supplies no kept packet.
        let bits = (1 << 6) | (1 << 4) | (1 << 3);
        let mut got = Vec::new();
        assert_eq!(expand(&mut got, &[], bits), Err(NpdError::Truncated));
    }

    #[test]
    fn expand_rejects_overflow() {
        // 5 kept 188-byte packets plus 3 null bits => 8 > 7.
        let mut input = Vec::new();
        for i in 0..5u16 {
            input.extend_from_slice(&ts_packet(SIZE_TS_188, 0x100 + i, i as u8));
        }
        let bits = (1 << 6) | (1 << 5) | (1 << 4);
        let mut got = Vec::new();
        assert_eq!(
            expand(&mut got, &input, bits),
            Err(NpdError::TooManyPackets)
        );
    }

    #[test]
    fn null_packet_canonical_form() {
        let mut got = Vec::new();
        expand(&mut got, &[], 1 << 6).unwrap(); // one null, no kept
        assert_eq!(got.len(), SIZE_TS_188);
        assert_eq!(&got[..4], &[0x47, 0x1F, 0xFF, 0x10]);
        assert!(got[TS_HEADER_SIZE..].iter().all(|&b| b == 0xFF));
    }
}
