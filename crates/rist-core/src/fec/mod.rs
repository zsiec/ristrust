//! SMPTE ST 2022-1 / ST 2022-5 forward error correction: a pure, deterministic
//! 2-D (row + column) XOR scheme over the protected media packets, the FEC method
//! the VSF TR-06 family adopts (TR-06-2 §8.4, TR-06-3 §5.3.5).
//!
//! The sender clips each media packet into a row group and a column group; when a
//! group fills it emits one FEC packet that is the XOR of the group's packets. The
//! receiver rebuilds any single packet missing from a row or column by XOR-ing the
//! FEC packet with the group's received members, and re-injects the recovered
//! packet into the flow exactly like an ARQ retransmit — FEC is just another source
//! of packets into the one seq-indexed ring. A 2-D matrix recovers any single loss
//! per row and per column and, by cascade ([`Decoder`] re-feeds a recovery into the
//! opposite dimension), many heavier patterns.
//!
//! # Sans-I/O and the codec boundary
//!
//! [`Encoder`] and [`Decoder`] are deterministic and own no clock, socket, or task,
//! so they sit behind the `rist-core` import gate (`bytes` only). They operate on
//! the **parsed** FEC fields — a [`Packet`] carries the group geometry
//! (`base`/`offset`/`na`) and recovery fields, not the on-the-wire header bytes. The
//! ST 2022-1 and ST 2022-5 header *byte* layouts, and the in-band Advanced control
//! indices that carry them, live in `rist-codec`: the host encodes a [`Packet`] to
//! header bytes on send and parses header bytes back into a [`Packet`] on receive.
//! This [`Packet`] is the narrow waist between the XOR matrix logic here and the
//! wire codec there — the same role [`wire`](crate::wire) plays for the flow core.
//!
//! The only wire-format concept the core needs is the base-sequence width, because
//! the decoder widens a truncated wire base against its window: ST 2022-1 truncates
//! the base to 24 bits, ST 2022-5 to 16 (see [`Variant`]). Everything else about the
//! header — the bit packing, the RFC 2733 mask, the 2022-5 padding/extension/CSRC
//! recovery bits — is the codec's concern.
//!
//! Ported from the Go sibling's `internal/fec` (same author, libRIST-interop-proven);
//! the recovery KATs and seeded property tests are ported as Rust fixtures.

// Wrap-aware FEC sequence arithmetic is intentionally modular, and the FEC header
// fields are fixed narrow widths (8/10/16-bit). The casts here and in the encoder
// and decoder are bounded truncations into those widths by construction, mirroring
// `seq.rs`.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

mod decoder;
mod encoder;

pub use decoder::Decoder;
pub use encoder::Encoder;

use crate::seq::Seq32;
use bytes::Bytes;

/// The SMPTE FEC wire format: ST 2022-1 (the default) or the high-bit-rate
/// ST 2022-5. The XOR matrix is identical; only the header layout (in `rist-codec`)
/// and the base-sequence width — which the [`Decoder`] needs to widen a received
/// base — differ.
///
/// Intentionally exhaustive (not `#[non_exhaustive]`), like the [`wire`](crate::wire)
/// enums: a forgotten variant should be a compile error at every `match` that maps
/// the wire format, across the codec and host crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Variant {
    /// SMPTE ST 2022-1: a 24-bit base sequence and 8-bit Offset/NA (TR-06-2 §8.4).
    /// The default and the interoperable Simple/Main carriage.
    #[default]
    St20221,
    /// SMPTE ST 2022-5:2013 §7.3: a 16-bit base sequence and 10-bit Offset/NA,
    /// raising the matrix ceiling to 1020 per dimension (the high bit rate format).
    St20225,
}

impl Variant {
    /// The bit mask of the base sequence number carried on the wire: 24 bits for
    /// ST 2022-1, 16 bits for ST 2022-5. The decoder widens a received base (masked
    /// to this width by the wire header) against its window.
    #[must_use]
    pub const fn base_mask(self) -> u32 {
        match self {
            Variant::St20221 => 0x00FF_FFFF,
            Variant::St20225 => 0x0000_FFFF,
        }
    }

    /// The span of the wire base sequence (`base_mask() + 1`): `1 << 24` for
    /// ST 2022-1, `1 << 16` for ST 2022-5. Used when widening to test the adjacent
    /// eras for the nearest candidate to the window.
    #[must_use]
    pub const fn base_span(self) -> u32 {
        match self {
            Variant::St20221 => 1 << 24,
            Variant::St20225 => 1 << 16,
        }
    }
}

/// The FEC dimension a [`Packet`] protects.
///
/// Intentionally exhaustive (not `#[non_exhaustive]`): a FEC packet is column or
/// row by the definition of 2-D FEC, and the codec maps this to the ST 2022-1
/// direction bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// A column (vertical) FEC packet: it protects D packets spaced L apart
    /// (`offset = L`, `na = D`).
    Column,
    /// A row (horizontal) FEC packet: it protects L consecutive packets
    /// (`offset = 1`, `na = L`).
    Row,
}

/// The FEC matrix configuration: an L-columns by D-rows matrix, optionally
/// column-only (1-D), in the ST 2022-1 or ST 2022-5 wire format.
///
/// The core does not enforce the TR-06 matrix bounds (that is the host's
/// `validate()`); it computes correctly for any `cols >= 1`, `rows >= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// L: the number of columns (the spacing between a column's protected packets).
    pub cols: usize,
    /// D: the number of rows (the number of packets a column FEC packet protects).
    pub rows: usize,
    /// Suppress the row (horizontal) FEC, keeping only column (vertical) FEC,
    /// roughly halving the overhead.
    pub column_only: bool,
    /// The SMPTE FEC wire format (selects the base-sequence width for widening).
    pub variant: Variant,
}

impl Config {
    /// The matrix size `L * D`: the number of media packets one full matrix covers
    /// and the column-base stride.
    #[must_use]
    pub const fn matrix_size(&self) -> usize {
        self.cols * self.rows
    }
}

/// One FEC packet's parsed group geometry and recovery fields, independent of the
/// ST 2022-1 / ST 2022-5 header byte layout (which `rist-codec` encodes/decodes).
///
/// The recovery fields are the XOR of the corresponding fields of the protected
/// media packets, from which the [`Decoder`] reconstructs a single missing member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The dimension this packet protects (column or row).
    pub direction: Direction,
    /// The base (lowest) protected sequence number. The [`Encoder`] emits the full
    /// 32-bit sequence; the wire header truncates it to the [`Variant`]'s width and
    /// the [`Decoder`] widens a received base back against its window.
    pub base: u32,
    /// The spacing between protected packets: L for a column, 1 for a row.
    pub offset: u16,
    /// The number of packets protected: D for a column, L for a row.
    pub na: u16,
    /// The XOR of the protected packets' payload lengths.
    pub length_recovery: u16,
    /// The XOR of the protected packets' 7-bit RTP payload types.
    pub pt_recovery: u8,
    /// The XOR of the protected packets' RTP timestamps.
    pub ts_recovery: u32,
    /// The XOR of the protected packets' payloads (zero-padded to the matrix payload
    /// size).
    pub payload: Bytes,
}

/// A media packet reconstructed by FEC, ready to feed into the flow like an ARQ
/// retransmit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// The recovered media sequence number.
    pub seq: u32,
    /// The recovered RTP timestamp.
    pub timestamp: u32,
    /// The recovered 7-bit RTP payload type.
    pub payload_type: u8,
    /// The SSRC of the group the loss belonged to (its members all share it, carried
    /// through the decoder from a present member rather than a last-seen value).
    pub ssrc: u32,
    /// The recovered payload, trimmed to the recovered length.
    pub payload: Bytes,
}

/// `base + off` in the wrap-aware 32-bit sequence space (ristgo `seqAdd`).
pub(crate) fn seq_add(base: u32, off: i64) -> u32 {
    Seq32::new(base).add(off).value()
}

/// The signed circular distance from `base` to `s` (ristgo `seqDiff`).
pub(crate) fn seq_diff(base: u32, s: u32) -> i64 {
    Seq32::new(base).distance(Seq32::new(s))
}
