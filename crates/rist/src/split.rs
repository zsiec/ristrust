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
//! predicate, [`split_point`] / [`is_split_pair`] — plus two thin (crate-private)
//! host-layer adapters the drivers drive: `split_payload` (the send-side split that
//! the `push_app` site applies) and `Merger` (the receive-side state machine that the
//! delivery drain folds split pairs back together with). Everything here is pure and
//! unit-tested in isolation (it reads no clock and touches no socket); the per-driver
//! plumbing — threading [`SplitMode`]/[`MergeMode`] from the config, forcing an even
//! initial sequence so the first half always lands on an even sequence, and the
//! bonded path distribution — lives in the driver modules.

use bytes::{Bytes, BytesMut};

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

/// The send-side split of one application `payload` under `mode`: the even/odd half
/// pair `(first, Some(last))` when `mode` is active and the payload is non-empty,
/// otherwise the payload unchanged with `None`. Both halves are [`Bytes`] slices of
/// the input's backing buffer, so the split is zero-copy.
///
/// The caller pushes `first` then `last` through the flow with the *same* `now`, so
/// the pair shares a source time and lands on consecutive sequences; with an even
/// initial sequence and every payload splitting, `first` always lands on an even
/// sequence — the pairing [`Merger`] keys on.
///
/// Matching libRIST, an active split *always* emits a pair: a payload too small for
/// [`split_point`] to halve (under two bytes) still splits as a zero-byte first half
/// and the whole payload as the last half. Always emitting a pair keeps the wire
/// sequence parity stable; a slip would strand a later pair's halves on an
/// (odd, even) sequence boundary and the receiver would deliver them unmerged.
pub(crate) fn split_payload(mode: SplitMode, payload: Bytes) -> (Bytes, Option<Bytes>) {
    if mode == SplitMode::Off || payload.is_empty() {
        return (payload, None);
    }
    let (first, _) = split_point(mode, &payload).unwrap_or((0, payload.len()));
    (payload.slice(0..first), Some(payload.slice(first..)))
}

/// The payloads one [`Merger::deliver`] call yields to the application, in order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MergeOut {
    /// Deliver nothing yet — an even first half is held awaiting its partner.
    Hold,
    /// Deliver one payload: a passthrough, a completed merge, or a flushed orphan.
    One(Bytes),
    /// Deliver two payloads in order: a flushed orphan first, then this delivery.
    Two(Bytes, Bytes),
}

impl MergeOut {
    /// The application payloads to deliver, in order (zero, one, or two). Lets a
    /// driver drive the send loop without borrowing `&self` across an `await` (some
    /// drivers hold a non-`Sync` field).
    pub(crate) fn payloads(self) -> impl Iterator<Item = Bytes> {
        let (a, b) = match self {
            MergeOut::Hold => (None, None),
            MergeOut::One(p) => (Some(p), None),
            MergeOut::Two(a, b) => (Some(a), Some(b)),
        };
        [a, b].into_iter().flatten()
    }
}

/// The receive-side packet-merge state machine (libRIST `merge=`). It recombines a
/// split pair — an even-sequence first half held until its `seq + 1` partner of
/// identical source time arrives — back into the original application payload, and
/// degrades any mis-pairing to a harmless orphan (the half delivered as received)
/// rather than splicing the wrong halves together.
///
/// The source-time guard is load-bearing: keying the recombination only on
/// even/odd + `seq + 1` (as a first cut did) corrupts the stream, splicing a
/// leftover half of one payload onto the first half of the next. Requiring the
/// shared source time makes a mis-pair fall through to two orphans instead.
///
/// In [`MergeMode::Auto`] the merge stays dormant until the peer is observed to be
/// pair-splitting (the keepalive L bit, on the GRE profiles); [`MergeMode::Pairs`]
/// always merges; [`MergeMode::Off`] passes every delivery straight through.
#[derive(Debug, Default)]
pub(crate) struct Merger {
    mode: MergeMode,
    /// In [`MergeMode::Auto`], whether the peer has advertised pair-splitting.
    auto_enabled: bool,
    /// A held even-sequence first half awaiting its partner: `(seq, source_time, payload)`.
    held: Option<(u32, u64, Bytes)>,
}

impl Merger {
    /// A merger for `mode` (its initial state holds nothing).
    pub(crate) fn new(mode: MergeMode) -> Merger {
        Merger {
            mode,
            ..Merger::default()
        }
    }

    /// Records whether the peer is advertising pair-splitting, enabling
    /// [`MergeMode::Auto`] (a no-op in the other modes). Driven by the keepalive L bit
    /// on the GRE profiles.
    pub(crate) fn set_auto_enabled(&mut self, on: bool) {
        self.auto_enabled = on;
    }

    /// Whether merging is currently active.
    fn active(&self) -> bool {
        match self.mode {
            MergeMode::Off => false,
            MergeMode::Pairs => true,
            MergeMode::Auto => self.auto_enabled,
        }
    }

    /// Processes one in-order delivered packet, yielding the application payload(s)
    /// to hand on. `discontinuity` marks a gap immediately before this delivery (a
    /// lost predecessor); `source_time` is the packet's source clock from
    /// [`rist_core::flow::Event::Deliver`].
    pub(crate) fn deliver(
        &mut self,
        seq: u32,
        source_time: u64,
        payload: Bytes,
        discontinuity: bool,
    ) -> MergeOut {
        if !self.active() {
            return MergeOut::One(payload);
        }
        // Complete a held pair when this delivery is its in-order, same-source-time
        // partner. The seq+1 check already implies no intervening gap, so a genuine
        // discontinuity can never satisfy it; the explicit guard is defensive.
        if let Some((h_seq, h_src, _)) = self.held {
            if !discontinuity && is_split_pair(h_seq, h_src, seq, source_time) {
                let (_, _, first) = self.held.take().expect("held checked above");
                return MergeOut::One(combine(&first, &payload));
            }
            // Not the partner — its partner was lost, or the stream is not actually
            // split. Flush the orphaned first half, then process this delivery fresh.
            let (_, _, orphan) = self.held.take().expect("held checked above");
            return match self.fresh(seq, source_time, payload) {
                MergeOut::Hold => MergeOut::One(orphan),
                MergeOut::One(p) => MergeOut::Two(orphan, p),
                MergeOut::Two(..) => unreachable!("fresh never yields two"),
            };
        }
        self.fresh(seq, source_time, payload)
    }

    /// Processes a delivery with no held first half: hold an even sequence as a
    /// candidate first half (its partner may follow), deliver an odd one straight
    /// through. Holding ignores `discontinuity` — a fresh pair can follow a loss, and
    /// the source-time guard still protects the eventual merge.
    fn fresh(&mut self, seq: u32, source_time: u64, payload: Bytes) -> MergeOut {
        if seq & 1 == 0 {
            self.held = Some((seq, source_time, payload));
            MergeOut::Hold
        } else {
            MergeOut::One(payload)
        }
    }
}

/// Concatenates a split pair's two halves into one payload.
fn combine(first: &[u8], last: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(first.len() + last.len());
    buf.extend_from_slice(first);
    buf.extend_from_slice(last);
    buf.freeze()
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

    fn b(s: &[u8]) -> Bytes {
        Bytes::copy_from_slice(s)
    }

    #[test]
    fn split_payload_off_is_passthrough() {
        let (first, last) = split_payload(SplitMode::Off, b(b"hello"));
        assert_eq!(first, b(b"hello"));
        assert_eq!(last, None);
    }

    #[test]
    fn split_payload_always_pairs_when_active() {
        // A normal payload halves.
        let (first, last) = split_payload(SplitMode::Half, b(b"abcd"));
        assert_eq!((first, last), (b(b"ab"), Some(b(b"cd"))));
        // A one-byte payload (too small for split_point) still pairs as (empty, whole)
        // so the wire sequence parity never slips.
        let (first, last) = split_payload(SplitMode::Half, b(b"x"));
        assert_eq!((first, last), (b(b""), Some(b(b"x"))));
        // An empty payload is the lone passthrough (libRIST never enqueues one).
        let (first, last) = split_payload(SplitMode::Auto, b(b""));
        assert_eq!((first, last), (b(b""), None));
    }

    #[test]
    fn merger_off_passes_through() {
        let mut m = Merger::new(MergeMode::Off);
        assert_eq!(m.deliver(0, 5, b(b"a"), false), MergeOut::One(b(b"a")));
        assert_eq!(m.deliver(1, 5, b(b"b"), false), MergeOut::One(b(b"b")));
    }

    #[test]
    fn merger_combines_a_split_pair() {
        let mut m = Merger::new(MergeMode::Pairs);
        assert_eq!(m.deliver(10, 900, b(b"ab"), false), MergeOut::Hold);
        assert_eq!(
            m.deliver(11, 900, b(b"cd"), false),
            MergeOut::One(b(b"abcd"))
        );
    }

    #[test]
    fn merger_source_time_guard_prevents_corruption() {
        // The pitfall: keying only on even/odd + seq+1 would splice "ab" onto "cd"
        // here even though they are different payloads (distinct source times). The
        // source-time guard flushes the orphan and delivers the second separately.
        let mut m = Merger::new(MergeMode::Pairs);
        assert_eq!(m.deliver(10, 900, b(b"ab"), false), MergeOut::Hold);
        assert_eq!(
            m.deliver(11, 901, b(b"cd"), false),
            MergeOut::Two(b(b"ab"), b(b"cd"))
        );
    }

    #[test]
    fn merger_unsplit_stream_delivers_in_order() {
        // merge=pairs over a never-split stream: every payload has its own source time,
        // so each even sequence is held one step then flushed in order — no corruption,
        // just a one-delivery hold on the even sequences.
        let mut m = Merger::new(MergeMode::Pairs);
        let mut out = Vec::new();
        for (seq, src, payload) in [(0u32, 1u64, "p0"), (1, 2, "p1"), (2, 3, "p2"), (3, 4, "p3")] {
            match m.deliver(seq, src, b(payload.as_bytes()), false) {
                MergeOut::Hold => {}
                MergeOut::One(p) => out.push(p),
                MergeOut::Two(a, c) => {
                    out.push(a);
                    out.push(c);
                }
            }
        }
        assert_eq!(out, vec![b(b"p0"), b(b"p1"), b(b"p2"), b(b"p3")]);
    }

    #[test]
    fn merger_lost_partner_flushes_orphan() {
        // Even first half held, its odd partner lost: the next delivery (seq+2, with a
        // discontinuity) flushes the orphan, and a fresh pair after the loss still
        // merges (holding ignores the discontinuity flag).
        let mut m = Merger::new(MergeMode::Pairs);
        assert_eq!(m.deliver(10, 900, b(b"orphan"), false), MergeOut::Hold);
        assert_eq!(
            m.deliver(12, 901, b(b"ef"), true),
            // seq 12 is even, so it is held; the orphan flushes alone.
            MergeOut::One(b(b"orphan"))
        );
        assert_eq!(
            m.deliver(13, 901, b(b"gh"), false),
            MergeOut::One(b(b"efgh"))
        );
    }

    #[test]
    fn merger_auto_dormant_until_enabled() {
        let mut m = Merger::new(MergeMode::Auto);
        // Dormant: passes through unmerged.
        assert_eq!(m.deliver(0, 5, b(b"ab"), false), MergeOut::One(b(b"ab")));
        // Enabled once the peer advertises pair-splitting.
        m.set_auto_enabled(true);
        assert_eq!(m.deliver(2, 7, b(b"ab"), false), MergeOut::Hold);
        assert_eq!(m.deliver(3, 7, b(b"cd"), false), MergeOut::One(b(b"abcd")));
    }

    #[test]
    fn split_then_merge_round_trips() {
        // Drive split_payload on the send side and Merger on the receive side over a
        // run of payloads, mimicking the flow's even-start consecutive sequencing, and
        // assert the application bytes survive the round trip exactly.
        let payloads: &[&[u8]] = &[b"first-chunk", b"x", &[0x47; 376], b"another payload here"];
        let mut m = Merger::new(MergeMode::Pairs);
        let mut seq = 0u32; // even start
        let mut got = Vec::new();
        for (i, &p) in payloads.iter().enumerate() {
            let src = 1000 + i as u64; // one source time per application payload
            let (first, last) = split_payload(SplitMode::Auto, b(p));
            let last = last.expect("active split always pairs a non-empty payload");
            for half in [first, last] {
                match m.deliver(seq, src, half, false) {
                    MergeOut::Hold => {}
                    MergeOut::One(out) => got.push(out),
                    MergeOut::Two(a, c) => {
                        got.push(a);
                        got.push(c);
                    }
                }
                seq = seq.wrapping_add(1);
            }
        }
        let want: Vec<Bytes> = payloads.iter().map(|p| b(p)).collect();
        assert_eq!(got, want);
    }
}
