//! The FEC receiver: reconstructs lost media from FEC packets, driven entirely by
//! each FEC packet's own base/geometry rather than any assumed matrix alignment, so
//! it recovers correctly even when the first media packet of a stream is lost.

// See the module-level note in `mod.rs`: the casts into the narrow FEC field widths
// and the wrap-aware sequence space are bounded by construction.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::collections::HashMap;

use bytes::Bytes;

use super::{Config, Packet, Recovered, seq_add, seq_diff};

/// The largest value the ST 2022-5 10-bit Offset/NA fields can hold; a count above
/// it is malformed geometry, rejected before any recovery.
const NA10_MAX: i64 = 0x3ff;

/// The recoverable fields of one media packet held in the window.
struct StoredMedia {
    ts: u32,
    pt: u8,
    ssrc: u32,
    payload: Bytes,
}

/// One received FEC packet: the group it protects (`base`, `stride`, `count`) and
/// the recovery fields/payload to XOR.
struct StoredFec {
    base: u32,
    stride: i64,
    count: i64,
    length_rec: u16,
    pt_rec: u8,
    ts_rec: u32,
    payload: Bytes,
    /// Whether the group is fully resolved (recovered, complete, or unrecoverable),
    /// so `recover_all` stops rescanning it.
    done: bool,
}

/// Reconstructs lost media from FEC packets. It is driven by the FEC packets' own
/// `base` and geometry (`offset`/`na`) rather than any assumed matrix alignment, so
/// it recovers correctly even when the first media packet of a stream is lost: a FEC
/// packet defines its group's exact sequence numbers, the decoder checks them
/// against the media it has stored in a sliding window, and rebuilds the single
/// missing member by XOR. Recovered packets re-enter the window, so a 2-D loss
/// recovered along one dimension cascades into the other.
#[derive(Debug)]
pub struct Decoder {
    cfg: Config,
    payload_size: usize,
    /// The sliding window depth (a few matrices, enough for column FEC), in
    /// sequences behind the front.
    window: i64,
    /// Cap on stored FEC packets (a FEC-flood DoS guard).
    max_fecs: usize,
    /// Received and recovered media in the window, keyed by sequence.
    media: HashMap<u32, StoredMedia>,
    /// FEC packets in the window not yet fully resolved.
    fecs: Vec<StoredFec>,
    /// The highest media sequence seen (the window anchor).
    last_seq: u32,
    have_seq: bool,
}

impl core::fmt::Debug for StoredMedia {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredMedia")
            .field("ts", &self.ts)
            .field("pt", &self.pt)
            .field("ssrc", &self.ssrc)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl core::fmt::Debug for StoredFec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredFec")
            .field("base", &self.base)
            .field("stride", &self.stride)
            .field("count", &self.count)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl Decoder {
    /// Build a decoder for the matrix in `cfg`. `payload_size` is the largest
    /// protected payload (FEC payloads are this size). `isn` seeds the window anchor;
    /// it need not be exact — the window self-corrects from the first media packet.
    #[must_use]
    pub fn new(cfg: Config, payload_size: usize, isn: u32) -> Self {
        let window = (cfg.matrix_size() * 3 + cfg.cols + 8) as i64;
        // Bound the stored FEC set to a few matrices' worth of column + row packets,
        // so a flood of forged/duplicate FEC packets whose bases hug the window front
        // (and so never age out via evict) cannot grow memory/CPU without limit.
        let max_fecs = (cfg.cols + cfg.rows) * 4 + 16;
        Self {
            cfg,
            payload_size,
            window,
            max_fecs,
            media: HashMap::with_capacity(cfg.matrix_size() * 2),
            fecs: Vec::new(),
            last_seq: isn,
            have_seq: false,
        }
    }

    /// Store one received media packet and return any packets its arrival allowed
    /// FEC to recover. `ssrc` is stamped onto any recovery from a group this packet
    /// belongs to (a FEC matrix is per-source, so its members share one SSRC). The
    /// returned `Vec` is empty (no allocation) on the common path with no recovery.
    pub fn push_media(
        &mut self,
        s: u32,
        ts: u32,
        pt: u8,
        ssrc: u32,
        payload: Bytes,
    ) -> Vec<Recovered> {
        let mut out = Vec::new();
        self.advance(s);
        if self.media.contains_key(&s) {
            return out; // duplicate (ARQ / 2022-7 already delivered it)
        }
        self.media.insert(
            s,
            StoredMedia {
                ts,
                pt,
                ssrc,
                payload,
            },
        );
        self.recover_all(&mut out);
        self.evict();
        out
    }

    /// Feed one received FEC packet (already parsed from its wire header) and return
    /// any packets it allowed FEC to recover.
    pub fn push_fec(&mut self, fec: &Packet) -> Vec<Recovered> {
        let mut out = Vec::new();
        let base = self.widen(fec.base);
        let stride = i64::from(fec.offset);
        let count = i64::from(fec.na);
        if stride <= 0 || count <= 1 || count > NA10_MAX {
            return out; // malformed geometry; ignore
        }
        // Constrain the recovery group to the configured matrix: a legitimate FEC
        // packet is a column (offset=L, na=D) or a 2-D row (offset=1, na=L). Trusting
        // the packet's own stride/count would let a forged or corrupt header define
        // an arbitrary group spanning sequences the sender has not transmitted,
        // fabricating a media packet out of attacker/corruption-controlled bytes (the
        // bases may still stagger within the matrix, which the staggered-column
        // interop relies on — only stride and count are fixed by L and D).
        if !self.geometry_ok(stride, count) {
            return out;
        }
        // Dedup by (base, stride, count): a bonded sender duplicates every FEC packet
        // to each path and a flood/forgery repeats it; an identical group carries an
        // identical XOR payload, so one copy suffices and the rest would only cost
        // memory and rescans.
        if self
            .fecs
            .iter()
            .any(|f| f.base == base && f.stride == stride && f.count == count)
        {
            return out;
        }
        // Cap the stored FEC set: evict aged groups first, then drop the oldest stored
        // group if still over the bound (it is closest to the eviction floor).
        if self.fecs.len() >= self.max_fecs {
            self.evict();
            if self.fecs.len() >= self.max_fecs {
                self.fecs.remove(0);
            }
        }
        self.fecs.push(StoredFec {
            base,
            stride,
            count,
            length_rec: fec.length_recovery,
            pt_rec: fec.pt_recovery & 0x7f,
            ts_rec: fec.ts_recovery,
            payload: fec.payload.clone(),
            done: false,
        });
        self.recover_all(&mut out);
        self.evict();
        out
    }

    /// Whether a FEC packet's `(stride, count)` matches the configured matrix: a
    /// column is `(L, D)`; a 2-D row is `(1, L)`. The bases may stagger
    /// (non-block-aligned), but stride and count are fixed by L and D.
    fn geometry_ok(&self, stride: i64, count: i64) -> bool {
        if stride == self.cfg.cols as i64 && count == self.cfg.rows as i64 {
            return true; // column FEC
        }
        if !self.cfg.column_only && stride == 1 && count == self.cfg.cols as i64 {
            return true; // 2-D row FEC
        }
        false
    }

    /// Advance the window anchor to the highest sequence seen.
    fn advance(&mut self, s: u32) {
        if !self.have_seq || seq_diff(self.last_seq, s) > 0 {
            self.last_seq = s;
            self.have_seq = true;
        }
    }

    /// Map a truncated FEC base sequence to the full 32-bit space using the latest
    /// media sequence as context (a FEC packet always protects sequences near the
    /// window). ST 2022-1 truncates the base to 24 bits, ST 2022-5 to 16; the window
    /// is always far smaller than either span, so the nearest candidate is
    /// unambiguous.
    fn widen(&self, base: u32) -> u32 {
        let mask = self.cfg.variant.base_mask();
        let span = self.cfg.variant.base_span();
        let cand = (self.last_seq & !mask) | (base & mask);
        let mut best = cand;
        for c in [cand.wrapping_add(span), cand.wrapping_sub(span)] {
            if seq_diff(self.last_seq, c).abs() < seq_diff(self.last_seq, best).abs() {
                best = c;
            }
        }
        best
    }

    /// Repeatedly scan the stored FEC packets, recovering every group that has
    /// exactly one missing member, until a full pass recovers nothing — so a packet
    /// recovered in one dimension cascades into the FEC of the other.
    fn recover_all(&mut self, out: &mut Vec<Recovered>) {
        loop {
            let mut recovered = false;
            for i in 0..self.fecs.len() {
                if self.try_recover(i, out) {
                    recovered = true;
                }
            }
            if !recovered {
                return;
            }
        }
    }

    /// Rebuild the single missing member of `self.fecs[i]`'s group, if exactly one is
    /// missing, and store it back into the window (so the opposite dimension can use
    /// it). Returns true only when it recovers a packet.
    fn try_recover(&mut self, i: usize, out: &mut Vec<Recovered>) -> bool {
        if self.fecs[i].done {
            return false;
        }
        let base = self.fecs[i].base;
        let stride = self.fecs[i].stride;
        let count = self.fecs[i].count;

        // Only recover while the whole group is inside the window. `base` is the
        // oldest member (stride > 0), so once it ages below the floor a member may
        // have been evicted, and treating an evicted (but received) member as missing
        // would "recover" a packet that was never lost. Give the group to ARQ instead.
        if seq_diff(seq_add(self.last_seq, -self.window), base) < 0 {
            self.fecs[i].done = true;
            return false;
        }
        // Refuse to recover a member the sender cannot yet have transmitted. A
        // legitimate FEC group is emitted only after all its members were sent, so
        // every real member is <= last_seq (the highest sequence seen). If the newest
        // member is still ahead of the window front, the "missing" member is a
        // not-yet-sent (future) sequence, not a loss, and fabricating it would preempt
        // the real packet when it arrives. Leave the group active so it can recover
        // once a later media packet advances last_seq past it.
        let newest = seq_add(base, (count - 1) * stride);
        if seq_diff(self.last_seq, newest) > 0 {
            return false;
        }

        let mut missing = 0u32;
        let mut missing_count = 0u32;
        for k in 0..count {
            let s = seq_add(base, k * stride);
            if !self.media.contains_key(&s) {
                missing_count += 1;
                if missing_count > 1 {
                    return false; // more than one missing: not recoverable yet
                }
                missing = s;
            }
        }
        if missing_count == 0 {
            self.fecs[i].done = true;
            return false;
        }

        let mut length = self.fecs[i].length_rec;
        let mut pt = self.fecs[i].pt_rec;
        let mut ts = self.fecs[i].ts_rec;
        let mut ssrc = 0u32; // the group's SSRC, from any present member
        let mut payload = vec![0u8; self.payload_size];
        {
            let fec_payload = &self.fecs[i].payload;
            let n = fec_payload.len().min(self.payload_size);
            payload[..n].copy_from_slice(&fec_payload[..n]);
        }
        for k in 0..count {
            let s = seq_add(base, k * stride);
            if let Some(m) = self.media.get(&s) {
                ssrc = m.ssrc;
                length ^= m.payload.len() as u16;
                pt ^= m.pt & 0x7f;
                ts ^= m.ts;
                for (dst, &src) in payload.iter_mut().zip(m.payload.iter()) {
                    *dst ^= src;
                }
            }
        }
        if usize::from(length) > self.payload_size {
            // Implausible recovered length: this group can never recover, stop
            // rescanning it.
            self.fecs[i].done = true;
            return false;
        }
        let recovered = Bytes::copy_from_slice(&payload[..usize::from(length)]);
        out.push(Recovered {
            seq: missing,
            timestamp: ts,
            payload_type: pt,
            ssrc,
            payload: recovered.clone(),
        });
        self.media.insert(
            missing,
            StoredMedia {
                ts,
                pt,
                ssrc,
                payload: recovered,
            },
        );
        self.fecs[i].done = true;
        true
    }

    /// Drop media and FEC packets older than the window, bounding memory.
    fn evict(&mut self) {
        let lo = seq_add(self.last_seq, -self.window);
        self.media.retain(|&s, _| seq_diff(lo, s) >= 0);
        self.fecs.retain(|f| seq_diff(lo, f.base) >= 0);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Direction, Encoder, Variant};
    use super::*;
    use std::collections::{HashMap, HashSet};

    const TEST_PAYLOAD_SIZE: usize = 200;
    /// A fixed SSRC for media fed in the recovery tests (a FEC matrix is per-source).
    const TEST_SSRC: u32 = 0x0CAF_E17E;

    fn cfg(cols: usize, rows: usize, column_only: bool, variant: Variant) -> Config {
        Config {
            cols,
            rows,
            column_only,
            variant,
        }
    }

    /// A deterministic, seq-dependent payload of varying length so recovery is
    /// verifiable and the length/pt/ts clips are all exercised.
    fn mk_payload(s: u32) -> Vec<u8> {
        let n = 80 + (s % 40) as usize;
        (0..n).map(|i| (s as u8) ^ ((i * 7 + 1) as u8)).collect()
    }
    fn mk_ts(s: u32) -> u32 {
        s.wrapping_mul(160).wrapping_add(7)
    }
    fn mk_pt(s: u32) -> u8 {
        (96 + s % 16) as u8 // dynamic RTP PT, < 128
    }

    /// One wire datagram in transmission order: a media packet or a FEC packet.
    enum Event {
        Media(u32),
        Fec(Packet),
    }

    /// Push `n` media packets starting at `isn` through an [`Encoder`] and return the
    /// interleaved transmission sequence (media + FEC) plus the original payloads.
    fn encode_stream(cfg: Config, isn: u32, n: usize) -> (Vec<Event>, HashMap<u32, Vec<u8>>) {
        let mut enc = Encoder::new(cfg, TEST_PAYLOAD_SIZE, isn);
        let mut events = Vec::new();
        let mut orig = HashMap::new();
        for i in 0..n {
            let s = seq_add(isn, i as i64);
            let p = mk_payload(s);
            orig.insert(s, p.clone());
            events.push(Event::Media(s));
            for fp in enc.push(s, mk_ts(s), mk_pt(s), &p) {
                events.push(Event::Fec(fp));
            }
        }
        (events, orig)
    }

    /// Feed the transmission sequence through a [`Decoder`], dropping the media in
    /// `drop`, and return the set of recovered sequences. Asserts no fabrication
    /// (every recovered payload/header equals the original). The decoder is created
    /// lazily from the first ARRIVING media, like the session, and the FEC base is
    /// truncated to the variant width to exercise widening, like the wire.
    fn replay(
        cfg: Config,
        events: &[Event],
        drop: &HashSet<u32>,
        orig: &HashMap<u32, Vec<u8>>,
    ) -> HashSet<u32> {
        let mut dec: Option<Decoder> = None;
        let mut recovered = HashSet::new();
        let mask = cfg.variant.base_mask();
        for e in events {
            let rs: Vec<Recovered> = match e {
                Event::Fec(fp) => {
                    if let Some(d) = dec.as_mut() {
                        let mut wire = fp.clone();
                        wire.base &= mask; // the wire truncates the base; the decoder widens
                        d.push_fec(&wire)
                    } else {
                        Vec::new()
                    }
                }
                Event::Media(s) => {
                    if drop.contains(s) {
                        Vec::new()
                    } else {
                        let s = *s;
                        let d = dec.get_or_insert_with(|| Decoder::new(cfg, TEST_PAYLOAD_SIZE, s));
                        d.push_media(
                            s,
                            mk_ts(s),
                            mk_pt(s),
                            TEST_SSRC,
                            Bytes::from(orig[&s].clone()),
                        )
                    }
                }
            };
            for r in rs {
                if let Some(want) = orig.get(&r.seq) {
                    assert_eq!(
                        r.payload.as_ref(),
                        want.as_slice(),
                        "recovered seq {} payload mismatch",
                        r.seq
                    );
                    assert_eq!(r.timestamp, mk_ts(r.seq), "recovered seq {} ts", r.seq);
                    assert_eq!(r.payload_type, mk_pt(r.seq), "recovered seq {} pt", r.seq);
                }
                recovered.insert(r.seq);
            }
        }
        recovered
    }

    fn drop_set<I: IntoIterator<Item = u32>>(it: I) -> HashSet<u32> {
        it.into_iter().collect()
    }

    /// Hand-build one column FEC [`Packet`] protecting the D members
    /// `{base, base+L, ..., base+(D-1)L}` from the given payloads (absent payloads
    /// clip as zero-length, with seq-derived pt/ts), as an external sender would.
    fn col_fec(base: u32, l: usize, d: usize, payloads: &HashMap<u32, Vec<u8>>) -> Packet {
        let mut length = 0u16;
        let mut pt = 0u8;
        let mut ts = 0u32;
        let mut clip = vec![0u8; TEST_PAYLOAD_SIZE];
        for j in 0..d {
            let s = seq_add(base, (j * l) as i64);
            let p: &[u8] = payloads.get(&s).map_or(&[], Vec::as_slice);
            length ^= p.len() as u16;
            pt ^= mk_pt(s) & 0x7f;
            ts ^= mk_ts(s);
            for (dst, &src) in clip.iter_mut().zip(p) {
                *dst ^= src;
            }
        }
        Packet {
            direction: Direction::Column,
            base,
            offset: l as u16,
            na: d as u16,
            length_recovery: length,
            pt_recovery: pt,
            ts_recovery: ts,
            payload: Bytes::from(clip),
        }
    }

    /// Build a column FEC [`Packet`] with an arbitrary `(offset, na)` geometry and
    /// payload, as a forged/corrupt packet would.
    fn raw_fec(base: u32, offset: u16, na: u16, payload: &[u8]) -> Packet {
        Packet {
            direction: Direction::Column,
            base,
            offset,
            na,
            length_recovery: 0,
            pt_recovery: 0,
            ts_recovery: 0,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    // ---- recovery KATs (ported from ristgo internal/fec/fec_test.go) ----

    #[test]
    fn column_only_recovers_one_per_column() {
        let c = cfg(4, 4, true, Variant::St20221);
        let isn = 1000;
        let (events, orig) = encode_stream(c, isn, 64); // 4 matrices
        // Drop the diagonal of the first matrix: one per column and one per row.
        let drop =
            drop_set((0..4).map(|k| seq_add(isn, i64::from(k) * c.cols as i64 + i64::from(k))));
        let rec = replay(c, &events, &drop, &orig);
        for s in &drop {
            assert!(rec.contains(s), "column-only FEC failed to recover seq {s}");
        }
    }

    #[test]
    fn two_d_recovers_single_loss() {
        let c = cfg(5, 4, false, Variant::St20221);
        let isn = 5000;
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 3);
        let drop = drop_set([seq_add(isn, 7)]); // middle of the first matrix
        let rec = replay(c, &events, &drop, &orig);
        assert!(
            rec.contains(&seq_add(isn, 7)),
            "2-D FEC failed a single loss"
        );
    }

    #[test]
    fn two_d_recursive_recovery() {
        let c = cfg(4, 4, false, Variant::St20221);
        let isn = 200;
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 2);
        // r0c0, r0c1, r1c0: row 0 and column 0 each have two losses, but column 1 has
        // one (r0c1) and row 1 has one (r1c0). Recovering r0c1 then leaves row 0 with
        // one loss; recovering r1c0 leaves column 0 with one. The cascade gets all three.
        let drop = drop_set([seq_add(isn, 0), seq_add(isn, 1), seq_add(isn, 4)]);
        let rec = replay(c, &events, &drop, &orig);
        for s in &drop {
            assert!(rec.contains(s), "recursive 2-D FEC failed seq {s}");
        }
    }

    #[test]
    fn decoder_robust_to_lost_first_packet() {
        let c = cfg(5, 5, false, Variant::St20221);
        let isn = 9000;
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 3);
        // Drop the matrix origin (the decoder never sees the true ISN) plus one
        // isolated packet in each of the first two matrices; each is its column's only
        // loss, so all are recoverable despite the misaligned anchor.
        let drop = drop_set([
            seq_add(isn, 0),
            seq_add(isn, 12),
            seq_add(isn, c.matrix_size() as i64 + 8),
        ]);
        let rec = replay(c, &events, &drop, &orig);
        for s in &drop {
            assert!(
                rec.contains(s),
                "failed to recover seq {s} after a lost first packet"
            );
        }
    }

    #[test]
    fn unrecoverable_double_column_loss_is_not_fabricated() {
        let c = cfg(4, 4, true, Variant::St20221);
        let isn = 0;
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 2);
        // Two losses in column 0 (rows 0 and 1): column-only FEC cannot recover them.
        let drop = drop_set([seq_add(isn, 0), seq_add(isn, 4)]);
        let rec = replay(c, &events, &drop, &orig);
        assert!(
            !rec.contains(&seq_add(isn, 0)),
            "wrongly recovered a double column loss"
        );
        assert!(
            !rec.contains(&seq_add(isn, 4)),
            "wrongly recovered a double column loss"
        );
    }

    /// A tiny deterministic RNG so the property tests reproduce by seed (the same
    /// SplitMix64 constants as ristgo).
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// Drive seeded random loss through the decoder and assert the two FEC
    /// invariants: nothing fabricated (enforced inside `replay`), and completeness
    /// under recoverable loss (at most one loss per matrix → 2-D FEC recovers all).
    fn random_loss_property(variant: Variant, seeds: u64) {
        for seed in 1..=seeds {
            let mut rng = SplitMix64(seed);
            let c = cfg(
                4 + (rng.next() % 5) as usize,
                4 + (rng.next() % 5) as usize,
                false,
                variant,
            );
            let matrices = 4;
            let isn = rng.next() as u32;
            let (events, orig) = encode_stream(c, isn, c.matrix_size() * matrices);

            // Sparse mode (every 3rd seed): at most one drop per matrix — fully
            // recoverable. Otherwise: arbitrary ~12% loss, where replay still
            // guarantees nothing is fabricated.
            let sparse = seed % 3 == 0;
            let mut drop = HashSet::new();
            if sparse {
                for m in 1..matrices {
                    // skip matrix 0 so the window aligns
                    let pos = (rng.next() as usize) % c.matrix_size();
                    drop.insert(seq_add(isn, (m * c.matrix_size() + pos) as i64));
                }
            } else {
                for i in 0..c.matrix_size() * matrices {
                    if rng.next() % 100 < 12 {
                        drop.insert(seq_add(isn, i as i64));
                    }
                }
            }

            let rec = replay(c, &events, &drop, &orig);
            if sparse {
                for s in &drop {
                    assert!(
                        rec.contains(s),
                        "seed {seed} (L={} D={}): single per-matrix loss seq {s} not recovered",
                        c.cols,
                        c.rows
                    );
                }
            }
        }
    }

    #[test]
    fn decoder_random_loss_property_2022_1() {
        random_loss_property(Variant::St20221, 60);
    }

    #[test]
    fn decoder_random_loss_property_2022_5() {
        random_loss_property(Variant::St20225, 40);
    }

    // ---- ST 2022-5 variant + widening ----

    #[test]
    fn variant_2022_5_column_only() {
        let c = cfg(5, 4, true, Variant::St20225);
        let isn = 1000;
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 3);
        let drop = drop_set((0..c.cols).map(|k| seq_add(isn, (k * c.cols + k) as i64)));
        let rec = replay(c, &events, &drop, &orig);
        for s in &drop {
            assert!(rec.contains(s), "2022-5 column-only failed seq {s}");
        }
    }

    #[test]
    fn variant_2022_5_single_loss_across_the_16_bit_base_wrap() {
        let c = cfg(5, 4, false, Variant::St20225);
        let isn = 60_000; // near the 16-bit base wrap, to exercise widening
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 3);
        let drop = drop_set([seq_add(isn, 7)]);
        let rec = replay(c, &events, &drop, &orig);
        assert!(
            rec.contains(&seq_add(isn, 7)),
            "2022-5 single loss not recovered across the 16-bit base wrap"
        );
    }

    #[test]
    fn variant_2022_5_recursive() {
        let c = cfg(4, 4, false, Variant::St20225);
        let isn = 200;
        let (events, orig) = encode_stream(c, isn, c.matrix_size() * 2);
        let drop = drop_set([seq_add(isn, 0), seq_add(isn, 1), seq_add(isn, 4)]);
        let rec = replay(c, &events, &drop, &orig);
        for s in &drop {
            assert!(rec.contains(s), "2022-5 recursive 2-D failed seq {s}");
        }
    }

    #[test]
    fn decoder_makes_no_block_alignment_assumption() {
        // ST 2022-5 §7.1 / Annex B: recover from column FEC whose bases are staggered
        // (advancing by less than a full block) and overlap, deriving the protected
        // set from each header's base + j*offset alone.
        const L: usize = 5;
        const D: usize = 3;
        let mut orig = HashMap::new();
        for i in 0..40u32 {
            orig.insert(i, mk_payload(i));
        }
        let bases = [0u32, 3, 6, 9, 12];
        let dropped = [5u32, 13, 16, 9, 22]; // one member per staggered column
        let drop = drop_set(dropped);

        let mut dec = Decoder::new(cfg(L, D, false, Variant::St20225), TEST_PAYLOAD_SIZE, 0);
        let mut recovered = HashSet::new();
        // Feed all non-dropped media first, then the FEC (column FEC arrives after its block).
        for i in 0..40u32 {
            if drop.contains(&i) {
                continue;
            }
            for r in dec.push_media(
                i,
                mk_ts(i),
                mk_pt(i),
                TEST_SSRC,
                Bytes::from(orig[&i].clone()),
            ) {
                recovered.insert(r.seq);
            }
        }
        for base in bases {
            for r in dec.push_fec(&col_fec(base, L, D, &orig)) {
                assert_eq!(
                    r.payload.as_ref(),
                    orig[&r.seq].as_slice(),
                    "staggered recovery corrupt"
                );
                recovered.insert(r.seq);
            }
        }
        for m in &drop {
            assert!(
                recovered.contains(m),
                "failed to recover staggered-column loss seq {m}"
            );
        }
    }

    // ---- false-recovery guards (F2/F3/F10/F11) ----

    #[test]
    fn rejects_forged_and_future_geometry() {
        let c = cfg(10, 10, false, Variant::St20221);
        let mut dec = Decoder::new(c, TEST_PAYLOAD_SIZE, 0);
        let mut payloads = HashMap::new();
        for i in 0..200u32 {
            payloads.insert(i, mk_payload(i));
            assert!(
                dec.push_media(
                    i,
                    mk_ts(i),
                    mk_pt(i),
                    TEST_SSRC,
                    Bytes::from(payloads[&i].clone())
                )
                .is_empty(),
                "unexpected recovery feeding complete media at {i}"
            );
        }
        // (a) Off-matrix stride/count: a forged column {base:0, offset:200, na:2} over
        // the complete window makes member 200 (never sent) the lone "missing" one. The
        // geometry constraint rejects stride=200 (config L=10) before any recovery.
        assert!(
            dec.push_fec(&raw_fec(0, 200, 2, b"fabricated-future-packet-bytes"))
                .is_empty(),
            "off-matrix forged FEC fabricated a packet"
        );
        assert_eq!(
            dec.fecs.len(),
            0,
            "off-matrix FEC must be rejected outright, not stored"
        );
        // (b) Matrix-shaped but extending past last_seq: a real column over
        // {110,120,...,200} has all of 110..190 present and only future seq 200
        // "missing". The upper-bound guard refuses rather than fabricating seq 200.
        payloads.insert(200, mk_payload(200)); // mixed into the FEC XOR; never fed to the decoder
        assert!(
            dec.push_fec(&col_fec(110, 10, 10, &payloads)).is_empty(),
            "matrix-shaped future-extending FEC fabricated a packet"
        );
        assert!(
            !dec.media.contains_key(&200),
            "decoder fabricated and stored not-yet-sent seq 200"
        );
    }

    #[test]
    fn upper_bound_guard_delays_rather_than_drops() {
        // A column whose newest member is briefly ahead of the front must recover once
        // a later media packet advances last_seq past it.
        const DROPPED: u32 = 15; // the last member of column 0's matrix
        let c = cfg(5, 4, true, Variant::St20221);
        let mut dec = Decoder::new(c, TEST_PAYLOAD_SIZE, 0);
        let mut payloads = HashMap::new();
        for i in 0..20u32 {
            payloads.insert(i, mk_payload(i));
        }
        for s in 0..15u32 {
            dec.push_media(
                s,
                mk_ts(s),
                mk_pt(s),
                TEST_SSRC,
                Bytes::from(payloads[&s].clone()),
            );
        }
        // Column 0 protects {0,5,10,15}; its FEC arrives while last_seq is 14 (< 15).
        assert!(
            dec.push_fec(&col_fec(0, 5, 4, &payloads)).is_empty(),
            "recovered before last_seq advanced"
        );
        // A later in-order packet (seq 16) advances last_seq past 15; recovery fires.
        let got = dec.push_media(
            16,
            mk_ts(16),
            mk_pt(16),
            TEST_SSRC,
            Bytes::from(payloads[&16].clone()),
        );
        assert_eq!(
            got.len(),
            1,
            "deferred recovery did not fire after last_seq advanced"
        );
        assert_eq!(got[0].seq, DROPPED);
        assert_eq!(
            got[0].payload.as_ref(),
            payloads[&DROPPED].as_slice(),
            "deferred recovery payload mismatch"
        );
    }

    #[test]
    fn fec_flood_is_bounded() {
        let c = cfg(10, 10, false, Variant::St20221);
        let mut dec = Decoder::new(c, TEST_PAYLOAD_SIZE, 0);
        let mut payloads = HashMap::new();
        for i in 0..1000u32 {
            payloads.insert(i, mk_payload(i));
            dec.push_media(
                i,
                mk_ts(i),
                mk_pt(i),
                TEST_SSRC,
                Bytes::from(payloads[&i].clone()),
            );
        }
        // 200 distinct, geometry-valid column bases near the front (well over max_fecs).
        for base in 800..1000u32 {
            dec.push_fec(&col_fec(base, 10, 10, &payloads));
        }
        assert!(
            dec.fecs.len() <= dec.max_fecs,
            "fecs grew to {}, exceeding cap {} (flood guard failed)",
            dec.fecs.len(),
            dec.max_fecs
        );
    }

    #[test]
    fn duplicate_fec_is_deduped() {
        let c = cfg(4, 4, true, Variant::St20221);
        let mut dec = Decoder::new(c, TEST_PAYLOAD_SIZE, 0);
        let mut payloads = HashMap::new();
        for i in 0..16u32 {
            payloads.insert(i, mk_payload(i));
            if i == 5 {
                continue; // drop one member so the group cannot resolve immediately
            }
            dec.push_media(
                i,
                mk_ts(i),
                mk_pt(i),
                TEST_SSRC,
                Bytes::from(payloads[&i].clone()),
            );
        }
        let fec = col_fec(1, 4, 4, &payloads);
        dec.push_fec(&fec); // recovers seq 5; the group becomes done
        for _ in 0..50 {
            dec.push_fec(&fec); // identical duplicates must not pile up
        }
        assert_eq!(
            dec.fecs.len(),
            1,
            "duplicate FEC packets must not accumulate"
        );
    }

    #[test]
    fn implausible_recovered_length_is_marked_done() {
        let c = cfg(4, 4, true, Variant::St20221);
        let mut dec = Decoder::new(c, TEST_PAYLOAD_SIZE, 0);
        let mut payloads = HashMap::new();
        for i in 0..16u32 {
            payloads.insert(i, mk_payload(i));
        }
        payloads.insert(5, vec![0u8; TEST_PAYLOAD_SIZE * 4]); // dropped member, over-large length
        for i in 0..16u32 {
            if i == 5 {
                continue;
            }
            dec.push_media(
                i,
                mk_ts(i),
                mk_pt(i),
                TEST_SSRC,
                Bytes::from(payloads[&i].clone()),
            );
        }
        let rec = dec.push_fec(&col_fec(1, 4, 4, &payloads)); // recovered length 4*size > cap
        assert!(rec.is_empty(), "implausible-length group must not recover");
        assert_eq!(dec.fecs.len(), 1);
        assert!(
            dec.fecs[0].done,
            "implausible-length group not marked done (would rescan each push)"
        );
    }

    #[test]
    fn recovery_carries_the_group_ssrc() {
        const GROUP_SSRC: u32 = 0xDEAD_BEEF;
        let c = cfg(4, 4, true, Variant::St20221);
        let mut dec = Decoder::new(c, TEST_PAYLOAD_SIZE, 0);
        let mut payloads = HashMap::new();
        for i in 0..16u32 {
            payloads.insert(i, mk_payload(i));
            if i == 5 {
                continue;
            }
            dec.push_media(
                i,
                mk_ts(i),
                mk_pt(i),
                GROUP_SSRC,
                Bytes::from(payloads[&i].clone()),
            );
        }
        let rec = dec.push_fec(&col_fec(1, 4, 4, &payloads));
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].seq, 5);
        assert_eq!(
            rec[0].ssrc, GROUP_SSRC,
            "recovery must carry its group's SSRC"
        );
    }

    #[test]
    fn protects_a_payload_larger_than_the_legacy_clip() {
        // An Advanced full datagram reaches ~1512 bytes; recovery must be intact when
        // the payload size admits it, and rejected when a too-small size truncates.
        const BIG: usize = 1512;
        const DROPPED: u32 = 5;
        let c = cfg(4, 4, true, Variant::St20221);
        let big_payload = |s: u32| -> Vec<u8> {
            (0..BIG)
                .map(|k| (s as u8).wrapping_mul(7).wrapping_add((k * 3 + 1) as u8))
                .collect()
        };
        let run = |payload_size: usize| -> (bool, bool) {
            let mut enc = Encoder::new(c, payload_size, 0);
            let mut dec = Decoder::new(c, payload_size, 0);
            let mut orig = HashMap::new();
            let mut events = Vec::new();
            for i in 0..16u32 {
                let p = big_payload(i);
                orig.insert(i, p.clone());
                events.push(Event::Media(i));
                for fp in enc.push(i, mk_ts(i), mk_pt(i), &p) {
                    events.push(Event::Fec(fp));
                }
            }
            let mut got: Option<Bytes> = None;
            for e in &events {
                match e {
                    Event::Fec(fp) => {
                        for r in dec.push_fec(fp) {
                            if r.seq == DROPPED {
                                got = Some(r.payload);
                            }
                        }
                    }
                    Event::Media(s) if *s != DROPPED => {
                        for r in dec.push_media(
                            *s,
                            mk_ts(*s),
                            mk_pt(*s),
                            TEST_SSRC,
                            Bytes::from(orig[s].clone()),
                        ) {
                            if r.seq == DROPPED {
                                got = Some(r.payload);
                            }
                        }
                    }
                    Event::Media(_) => {}
                }
            }
            let intact = got
                .as_ref()
                .is_some_and(|g| g.as_ref() == orig[&DROPPED].as_slice());
            (got.is_some(), intact)
        };
        let (recovered, intact) = run(2048);
        assert!(
            recovered && intact,
            "large payload not recovered intact with a sufficient buffer"
        );
        let (recovered, _) = run(1500);
        assert!(
            !recovered,
            "a 1512-byte payload must not recover with a 1500-byte FEC buffer"
        );
    }
}
