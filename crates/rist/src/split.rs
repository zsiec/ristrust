//! Packet split/merge bonding modes (libRIST `split=`/`merge=`), ported from
//! libRIST `rist.c` (the sender split) and `rist-common.c` (the receiver merge).
//!
//! Split/merge spreads one application payload's bytes across two consecutive RIST
//! sequences so a bonded pair of links can each carry half. The **sender** emits two
//! RTP packets with consecutive sequence numbers (the first on an even sequence) and
//! the *same* source time; the **receiver** recombines an even-sequence packet with
//! its `seq+1` partner of identical source time back into the original payload. Unlike
//! the Advanced profile's explicit F/L fragmentation markers, this is a marker-less
//! pairing keyed purely on the even/odd sequence and the shared source time, so it
//! works on the Simple and Main profiles too.
//!
//! This module is the byte-exact algorithmic core — the split point and the merge
//! predicate — kept pure and unit-tested in isolation (it reads no clock and touches
//! no socket). Wiring it into the per-profile send/deliver paths (with sender
//! sequence-parity alignment and the bonded path distribution) is layered on top.
//!
//! # Status
//!
//! The split-point and merge-pairing logic below match libRIST and are tested. The
//! host wiring (sender split with even-sequence alignment, the driver-side merge at
//! the delivery point, the `split=`/`merge=` config/URL knobs, distributing the two
//! halves across bonded peers, and the ristgo mirror + libRIST interop test) is the
//! tracked follow-up; until it lands, configuring a split/merge mode is a no-op.

/// One MPEG-TS packet length (the AUTO split aligns on this boundary).
const TS_PACKET_LEN: usize = 188;
/// The MPEG-TS sync byte that marks a TS-aligned payload.
const TS_SYNC_BYTE: u8 = 0x47;

/// The sender's packet-split strategy (libRIST `split=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitMode {
    /// No splitting — one payload, one sequence (the default).
    #[default]
    Off,
    /// Split on an MPEG-TS packet boundary at the midpoint when the payload is
    /// TS-aligned, otherwise at the byte midpoint.
    Auto,
    /// Always split at the byte midpoint.
    Half,
}

/// The receiver's packet-merge strategy (libRIST `merge=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergeMode {
    /// No merging — deliver each packet as received (the default).
    #[default]
    Off,
    /// Recombine every even/odd consecutive same-source-time pair.
    Pairs,
    /// Recombine only when the stream is detected to be split (auto-enabled).
    Auto,
}

/// The split point for `payload` under `mode`, as `(first_len, last_len)` with
/// `first_len + last_len == payload.len()`, or `None` when the payload is not split
/// (`mode` is [`SplitMode::Off`] or the payload is too small to halve).
///
/// AUTO splits on a 188-byte MPEG-TS boundary at the midpoint when the payload is
/// TS-aligned (a multiple of 188, at least two packets, first byte `0x47`); otherwise
/// it falls back to the byte midpoint, exactly as libRIST does.
#[must_use]
pub fn split_point(mode: SplitMode, payload: &[u8]) -> Option<(usize, usize)> {
    let len = payload.len();
    if len < 2 {
        return None;
    }
    let first = match mode {
        SplitMode::Off => return None,
        SplitMode::Auto
            if len >= 2 * TS_PACKET_LEN
                && len.is_multiple_of(TS_PACKET_LEN)
                && payload[0] == TS_SYNC_BYTE =>
        {
            // Split on a TS boundary at the midpoint; at least one packet on each side.
            let ts_count = len / TS_PACKET_LEN;
            (ts_count / 2).max(1) * TS_PACKET_LEN
        }
        // AUTO fallback (not TS-aligned) and HALF both split at the byte midpoint.
        SplitMode::Auto | SplitMode::Half => len / 2,
    };
    Some((first, len - first))
}

/// Whether two delivered packets form a split pair the receiver must recombine: the
/// first sequence is even, the second is exactly `first_seq + 1`, and both carry the
/// same source time (libRIST's `(seq & 1) == 0` + `seq+1` + equal `source_time`
/// pairing). The combined payload is `first ‖ second`.
#[must_use]
pub fn is_split_pair(first_seq: u32, first_src: u64, second_seq: u32, second_src: u64) -> bool {
    first_seq & 1 == 0 && second_seq == first_seq.wrapping_add(1) && first_src == second_src
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_never_splits() {
        assert_eq!(split_point(SplitMode::Off, &[0u8; 376]), None);
    }

    #[test]
    fn half_splits_at_byte_midpoint() {
        assert_eq!(split_point(SplitMode::Half, &[0u8; 100]), Some((50, 50)));
        assert_eq!(split_point(SplitMode::Half, &[0u8; 101]), Some((50, 51)));
        assert_eq!(split_point(SplitMode::Half, &[0u8; 1]), None); // too small
    }

    #[test]
    fn auto_splits_on_ts_boundary_when_aligned() {
        // 7 TS packets (1316 bytes), 0x47-synced → split at 3 packets (564) / 4 (752).
        let mut p = vec![0u8; 7 * TS_PACKET_LEN];
        p[0] = TS_SYNC_BYTE;
        assert_eq!(split_point(SplitMode::Auto, &p), Some((3 * 188, 4 * 188)));
        // 2 TS packets → 1 / 1 (each side gets a whole packet).
        let mut p2 = vec![0u8; 2 * TS_PACKET_LEN];
        p2[0] = TS_SYNC_BYTE;
        assert_eq!(split_point(SplitMode::Auto, &p2), Some((188, 188)));
    }

    #[test]
    fn auto_falls_back_to_midpoint_when_not_ts() {
        // Not 188-aligned → byte midpoint.
        assert_eq!(split_point(SplitMode::Auto, &[0u8; 300]), Some((150, 150)));
        // 188-aligned but wrong sync byte → byte midpoint, not TS.
        let p = vec![0u8; 2 * TS_PACKET_LEN]; // first byte 0x00, not 0x47
        assert_eq!(split_point(SplitMode::Auto, &p), Some((188, 188))); // midpoint == TS here
        let mut p3 = vec![0u8; 3 * TS_PACKET_LEN];
        p3[0] = 0x00;
        assert_eq!(split_point(SplitMode::Auto, &p3), Some((282, 282))); // 564/2, not a TS split
    }

    #[test]
    fn merge_pairs_even_then_odd_same_source_time() {
        assert!(is_split_pair(10, 5_000, 11, 5_000)); // even, +1, same st
        assert!(!is_split_pair(11, 5_000, 12, 5_000)); // odd first
        assert!(!is_split_pair(10, 5_000, 12, 5_000)); // not consecutive
        assert!(!is_split_pair(10, 5_000, 11, 6_000)); // different source time
        // Wrap: even u32::MAX-1 then its +1.
        assert!(is_split_pair(u32::MAX - 1, 1, u32::MAX, 1));
    }
}
