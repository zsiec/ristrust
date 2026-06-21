//! The receiver half of the flow core: the seq-indexed ring, `(seq,
//! source_time)` dedup (the SMPTE 2022-7 multipath merge), successor-driven
//! missing detection, NACK cadence, and time-driven in-order playout.
//!
//! Ported step for step from ristgo `internal/flow/receiver.go`, which itself
//! follows libRIST's `receiver_enqueue` / `receiver_mark_missing` /
//! `rist_receiver_nack_output` / output-thread loop. The arithmetic is matched
//! for interop; deviations from libRIST are noted at the point they occur.

// Justification: the ring is indexed by `seq & mask` and the missing-detection
// walk does wrap-aware modular arithmetic. The casts below convert between the
// 32-bit sequence space, ring indices (`usize`), and signed interpacket spacing;
// their ranges are bounded by the ring size and the half-space by construction.
// `cast_precision_loss` covers the return-bandwidth token bucket's microsecond→f64
// refill arithmetic (a rate, where sub-microsecond precision is irrelevant).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

use std::collections::VecDeque;

use bytes::Bytes;

use super::{
    Event, Flow, NACK_CADENCE, Output, RTT_ECHO_INTERVAL, Role, TimerId, TimingMode, mul_1_1,
};
use crate::clock::{Micros, Ntp64, Timestamp};
use crate::seq::{self, Seq32};
use crate::wire::{Feedback, FragRole, MediaPacket};

/// The occupancy state of one ring slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SlotState {
    /// No packet buffered in this slot.
    #[default]
    Empty,
    /// A packet is buffered in this slot.
    Filled,
}

/// One entry of the receiver ring: the buffered packet plus the timing and path
/// bookkeeping playout and dedup need. Mirrors the libRIST `rist_buffer` fields
/// `receiver_enqueue` and the output thread read (seq, source_time, packet_time,
/// target_output_time).
#[derive(Debug, Clone, Default)]
struct Slot {
    /// The retained reference to the media payload (zero-copy; see the crate
    /// ownership note).
    payload: Bytes,
    /// The sender's NTP-64 media timestamp; together with `seq` it forms the
    /// duplicate-validation key.
    source_time: u64,
    /// The local instant the first accepted copy was fed.
    arrival: Timestamp,
    /// `source_time` mapped into the local clock domain via the offset locked at
    /// the first packet.
    packet_time: Timestamp,
    /// `packet_time + recovery_buffer`: the playout deadline.
    output_time: Timestamp,
    /// A bitset of the paths that delivered a copy of this packet (bit `path &
    /// 63`). Diagnostic: dedup correctness does not depend on it.
    path_seen: u64,
    /// The widened 32-bit sequence number occupying this slot.
    seq: u32,
    /// The Advanced fragment role carried by the packet, surfaced at delivery for
    /// the host reassembler.
    frag: FragRole,
    /// The RIST virtual source port decoded from the packet (Main/Advanced), surfaced at
    /// delivery so the host can report it per block. `0` on the Simple profile.
    virt_src_port: u16,
    /// The RIST virtual destination port decoded from the packet (Main/Advanced). `0` on
    /// the Simple profile (no virtual ports).
    virt_dst_port: u16,
    /// `Empty` or `Filled`.
    state: SlotState,
}

/// One queued retransmission request (libRIST `rist_missing_buffer`): retried on
/// the NACK cadence until recovered or abandoned. The linked list of the C /
/// ristgo originals is a [`VecDeque`] here — same FIFO order, no raw pointers.
#[derive(Debug, Clone)]
struct MissingEntry {
    /// The missing sequence number.
    seq: u32,
    /// The path the gap was detected on. Stored for the per-path NACK-peer
    /// selection bonding adds; the single-path NACK uses `last_path` for now.
    #[allow(dead_code)]
    path: u8,
    /// How many NACKs have been emitted for this entry.
    nack_count: u32,
    /// When the entry was created (clamped into `[now-recoveryBuffer, now]`).
    insertion_time: Timestamp,
    /// The next instant a NACK is due for this entry.
    next_nack: Timestamp,
}

/// The receiver half's mutable state.
// The boolean flags (`started`, `pending_discontinuity`, and the two timer
// shadows) mirror libRIST's / ristgo's per-flow receiver state directly; folding
// them into enums would obscure the port without buying clarity.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct ReceiverState {
    /// The seq-indexed ring (`seq & mask`). Length is a power of two.
    ring: Box<[Slot]>,
    /// `ring.len() - 1`, the index mask.
    mask: u32,

    /// Whether the first packet has locked the clock offset and seeded cursors.
    pub(super) started: bool,
    /// Maps source timestamps into the local clock domain: `packet_time =
    /// to_timestamp(source_time) + offset`. Locked at the first packet (libRIST
    /// `time_offset = now - source_time`).
    offset: Micros,
    /// The media-stream SSRC learned from the first packet, echoed in NACKs.
    ssrc: u32,

    /// The wire framing of the anchored flow ([`MediaPacket::short_seq`]): `true`
    /// for 16-bit Simple/Main framing, `false` for the Advanced 32-bit native
    /// sequence. A started flow whose next fresh packet carries a different value is
    /// following a mid-stream framing change (TR-06-3 §9 Main↔Advanced) and is
    /// re-anchored like a flow-id change.
    short_seq: bool,

    /// libRIST `last_seq_found`: the newest in-order sequence accepted, the
    /// anchor of missing-detection walks.
    last_found: u32,
    /// The newest source timestamp seen (libRIST `max_source_time`).
    max_source_time: u64,
    /// `max_source_time` mapped into the local clock domain.
    last_packet_time: Timestamp,
    /// The newest (circularly greatest) sequence inserted; bounds the playout
    /// scan.
    highest: u32,
    /// The in-order playout cursor: the next sequence to hand to the
    /// application.
    deliver_next: u32,
    /// Set when sequences immediately before the next delivery were abandoned.
    pending_discontinuity: bool,
    /// The path of the most recently accepted media packet; feedback leaves on
    /// it.
    pub(super) last_path: u8,

    /// The FIFO missing queue.
    missing: VecDeque<MissingEntry>,

    /// Requested-timer shadows so steady-state `feed` emits nothing.
    pub(super) playout_armed: bool,
    playout_deadline: Timestamp,
    pub(super) nack_armed: bool,

    /// Recovery-buffer auto-scaling state (libRIST `_librist_receiver_buffer_calc`),
    /// active only when the buffer is windowed (`recovery_buffer_min !=
    /// recovery_buffer_max`) and a sender max has been learned via buffer
    /// negotiation. `sender_max_buffer` is libRIST's `sender_max_buffer_ticks` (the
    /// largest buffer the sender retains for retransmission, so the receiver never
    /// sizes past what can be recovered); `0` means not yet learned, holding the
    /// static midpoint. `loss_snap`/`recovered_snap` hold the cumulative
    /// `lost`/`recovered` counters at the previous recalc, so the loss-growth
    /// modifier sees the per-period delta.
    sender_max_buffer: Micros,
    loss_snap: u64,
    recovered_snap: u64,

    /// The instant the source-clock offset was last (re-)anchored — the first packet,
    /// or a wrap re-anchor. The wrap guard requires `3 * recovery_buffer` of dwell
    /// since this instant, so a single anomalous or out-of-order timestamp cannot
    /// trip a re-anchor (libRIST `time_offset_changed_ts`).
    last_resync: Timestamp,

    /// Return-bandwidth NACK-channel token bucket (libRIST return-bandwidth). When
    /// `nack_seqs_per_sec > 0` the receiver spends one token per NACKed sequence,
    /// refilling at that rate (capped at `nack_token_burst`); a sequence with no
    /// token is left due and re-serviced next pass. `0` means unlimited.
    nack_seqs_per_sec: f64,
    nack_token_burst: f64,
    nack_tokens: f64,
    nack_tokens_time: Timestamp,

    /// Inter-packet arrival spacing (libRIST `min_ips`/`cur_ips`/`max_ips`): the gap
    /// between consecutive received media packets, sampled on every arrival.
    /// `ips_last_arrival` is the previous arrival instant; `ips_min_us` starts at
    /// `i64::MAX` (a sentinel reported as `0` until the first delta).
    ips_last_arrival: Timestamp,
    ips_min_us: i64,
    ips_cur_us: i64,
    ips_max_us: i64,

    /// Running mean of the recovery-buffer level (libRIST `avg_buffer_time`), sampled
    /// once per recalc tick (~100 ms) in [`auto_scale_buffer`](Self::auto_scale_buffer).
    /// The gauge is `buffer_time_sum / buffer_time_samples`; before the first sample the
    /// flow reports the current static buffer instead.
    buffer_time_sum: i64,
    buffer_time_samples: u64,
}

impl ReceiverState {
    /// Allocates a receiver state with a `ring_size`-slot ring (power of two).
    pub(super) fn new(ring_size: usize) -> ReceiverState {
        ReceiverState {
            ring: vec![Slot::default(); ring_size].into_boxed_slice(),
            mask: (ring_size - 1) as u32,
            started: false,
            offset: Micros::ZERO,
            ssrc: 0,
            short_seq: false,
            last_found: 0,
            max_source_time: 0,
            last_packet_time: Timestamp::ZERO,
            highest: 0,
            deliver_next: 0,
            pending_discontinuity: false,
            last_path: 0,
            missing: VecDeque::new(),
            playout_armed: false,
            playout_deadline: Timestamp::ZERO,
            nack_armed: false,
            sender_max_buffer: Micros::ZERO,
            loss_snap: 0,
            recovered_snap: 0,
            last_resync: Timestamp::ZERO,
            nack_seqs_per_sec: 0.0,
            nack_token_burst: 0.0,
            nack_tokens: 0.0,
            nack_tokens_time: Timestamp::ZERO,
            ips_last_arrival: Timestamp::ZERO,
            ips_min_us: i64::MAX,
            ips_cur_us: 0,
            ips_max_us: 0,
            buffer_time_sum: 0,
            buffer_time_samples: 0,
        }
    }

    /// A receiver state with a minimal ring, for a sender-role flow (it never
    /// receives media, so a full ring would only waste memory).
    pub(super) fn empty() -> ReceiverState {
        ReceiverState::new(1)
    }

    /// Arms the return-bandwidth NACK token bucket from a kbps cap: the rate is the
    /// return-channel bytes/sec divided by the bytes a range-NACK spends per
    /// sequence, and the bucket starts full at one per-pass NACK group (libRIST
    /// arms it identically in `flow_new`).
    pub(super) fn set_return_bandwidth(&mut self, return_maxbitrate: u32) {
        self.nack_seqs_per_sec =
            f64::from(return_maxbitrate) * 1000.0 / 8.0 / RIST_NACK_BYTES_PER_SEQ;
        self.nack_token_burst = RIST_NACK_TOKEN_BURST;
        self.nack_tokens = self.nack_token_burst;
    }
}

impl std::fmt::Debug for ReceiverState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverState")
            .field("started", &self.started)
            .field("ring_len", &self.ring.len())
            .field("last_found", &self.last_found)
            .field("deliver_next", &self.deliver_next)
            .field("highest", &self.highest)
            .field("missing", &self.missing.len())
            .finish_non_exhaustive()
    }
}

/// The `path_seen` bit for a path index (aliasing mod 64; path counts in real
/// 2022-7 deployments are single digit).
fn path_bit(path: u8) -> u64 {
    1u64 << (path & 63)
}

/// Recovery-buffer auto-scaling tuning (libRIST `_librist_receiver_buffer_calc`'s
/// "magic numbers", which its own comment notes "still need tuning"): the cap on how
/// much the auto-scaled buffer may shrink per recalc, so a transient RTT dip cannot
/// abruptly collapse the playout deadline and shed packets still in flight.
const BUFFER_DECREASE_STEP: Micros = Micros::from_millis(50);
/// Per-period buffer-growth weight per lost packet (libRIST +5%).
const BUFFER_GROWTH_PER_LOST: f64 = 0.05;
/// Per-period buffer-growth weight per recovered packet (libRIST +2%; ristgo folds
/// libRIST's `recovered_3nack`/`recovered_morenack` classes into one delta at this
/// weight, erring slightly toward a larger buffer — the safe direction).
const BUFFER_GROWTH_PER_RECOVERED: f64 = 0.02;
/// Per-period lost count above which the receiver jumps straight to the sender's max
/// buffer (libRIST `has_high_loss`).
const BUFFER_HIGH_LOSS_THRESHOLD: u64 = 25;

/// Source-clock wrap constants (libRIST `receiver_calculate_packet_time`).
///
/// A source media timestamp that jumps backward by more than half the 32-bit
/// timestamp space is a true wrap of the 32-bit RTP-derived counter, not jitter or
/// reordering. `source_time` crosses the wire as NTP-64; one full wrap of the 32-bit
/// MPEG-TS counter at 90 kHz spans `(2^32 / 90000)` seconds of media time:
///
/// - [`SRC_WRAP_PERIOD_NTP`] is that span in NTP-64 ticks (`(UINT32_MAX << 32) /
///   90000`), libRIST's bump amount; [`SRC_WRAP_HALF_NTP`] is half of it, the
///   backward-delta threshold that identifies a genuine wrap.
/// - [`SRC_WRAP_PERIOD_MICROS`] is the same span in microseconds (`2^32 * 100 / 9`),
///   added to the stored clock offset (which the core keeps in microseconds) so the
///   wrapped source time maps back to ~now and playout continues seamlessly.
///
/// The 90 kHz figure is a constant, not a profile import — the core stays
/// profile-agnostic and never branches on payload type.
const SRC_WRAP_PERIOD_NTP: u64 = (0xFFFF_FFFFu64 << 32) / 90000;
/// Half [`SRC_WRAP_PERIOD_NTP`]: a backward `source_time` delta exceeding this marks
/// a true 32-bit wrap (libRIST's `(max_source_time - source_time) > UINT32_MAX/2`,
/// scaled to the NTP-64 `source_time` domain).
const SRC_WRAP_HALF_NTP: u64 = SRC_WRAP_PERIOD_NTP / 2;
/// One wrap period in microseconds (`2^32 * 100 / 9`): the offset bump applied on a
/// detected wrap.
const SRC_WRAP_PERIOD_MICROS: Micros = Micros::from_micros((1i64 << 32) * 100 / 9);

/// Bytes a libRIST range-NACK spends per requested sequence number
/// (`ristNackBytesPerSeq`): the divisor turning a return-bandwidth kbps cap into a
/// NACK-sequence rate.
const RIST_NACK_BYTES_PER_SEQ: f64 = 4.0;
/// The return-bandwidth token-bucket burst ceiling: one full per-pass NACK group
/// (libRIST `RIST_MAX_NACKS`).
const RIST_NACK_TOKEN_BURST: f64 = 200.0;

impl Flow {
    /// Maps a packet's NTP-64 source timestamp into the local clock domain using
    /// the offset locked at the first packet.
    fn map_source_time(&self, source_time: u64) -> Timestamp {
        Ntp64::from_bits(source_time).to_timestamp() + self.receiver.offset
    }

    /// The local instant playout schedules from for an inbound packet. In
    /// [`TimingMode::Source`] it is the media source timestamp mapped into the local
    /// clock (inter-packet spacing follows the source clock), with the source-clock
    /// wrap re-anchor applied; in [`TimingMode::Arrival`] it is the arrival instant
    /// `now`, so each packet is held a fixed recovery buffer from arrival.
    ///
    /// Source-clock re-anchor (libRIST `receiver_calculate_packet_time` wrap fix-up):
    /// the 32-bit RTP-derived source counter wraps every ~13 h at 90 kHz; after a
    /// wrap the offset locked at the first packet is one wrap period stale, so every
    /// later packet would map into the past and be shed as too-late — a permanent
    /// stall. A TRUE backward wrap is detected — a fresh non-retransmit whose source
    /// time fell back by more than half the 32-bit space — gated by a
    /// `3 * recovery_buffer` dwell so a single anomalous or out-of-order timestamp
    /// cannot trigger it. On a wrap the offset is BUMPED by one wrap period (keeping
    /// playout continuous) rather than snapped to now; ordinary jitter/reordering
    /// moves the source time by milliseconds — far below the ~6.6 h half-span — so it
    /// never triggers.
    fn receiver_packet_time(
        &mut self,
        now: Timestamp,
        source_time: u64,
        retransmit: bool,
    ) -> Timestamp {
        if self.cfg.timing_mode == TimingMode::Arrival {
            return now;
        }
        let mut pt = self.map_source_time(source_time);
        let dwell = Micros::from_micros(self.recovery_buffer.as_micros().saturating_mul(3));
        // The 32-bit source-clock wrap re-anchor is for the RTP-derived SOURCE clock;
        // RTC mode's NTP-64 wall clock does not wrap on that boundary (libRIST gates the
        // re-anchor on `!rtc_timing_mode`).
        if self.cfg.timing_mode == TimingMode::Source
            && !retransmit
            && source_time < self.receiver.max_source_time
            && self.receiver.max_source_time - source_time > SRC_WRAP_HALF_NTP
            && (now - self.receiver.last_resync) >= dwell
        {
            self.receiver.offset = self.receiver.offset + SRC_WRAP_PERIOD_MICROS;
            pt = self.map_source_time(source_time);
            self.receiver.max_source_time = source_time;
            self.receiver.last_packet_time = pt;
            self.receiver.last_resync = now;
            self.stats.clock_resync += 1;
        }
        pt
    }

    /// The receiver-role body of [`Flow::feed`]: first-packet init, packet-time
    /// mapping, too-late shedding, `(seq, source_time)` dedup, insert, missing
    /// detection, then timer scheduling — following `receiver_enqueue`.
    /// The inter-packet arrival spacing gauges `(min, cur, max)` in microseconds;
    /// `min` is reported as `0` until the first inter-arrival delta is sampled.
    pub(crate) fn ips_gauges(&self) -> (i64, i64, i64) {
        let min = if self.receiver.ips_min_us == i64::MAX {
            0
        } else {
            self.receiver.ips_min_us
        };
        (min, self.receiver.ips_cur_us, self.receiver.ips_max_us)
    }

    /// The average recovery-buffer (playout) level in microseconds — the libRIST
    /// `avg_buffer_time` gauge. The running mean of the dynamic buffer sampled per
    /// recalc tick; before the first sample (or on a sender) it reports the current
    /// static buffer so the gauge is never a misleading `0`.
    pub(crate) fn avg_buffer_time_us(&self) -> i64 {
        if self.role != Role::Receiver {
            return 0;
        }
        if self.receiver.buffer_time_samples == 0 {
            return self.recovery_buffer.as_micros();
        }
        self.receiver.buffer_time_sum / self.receiver.buffer_time_samples as i64
    }

    /// Samples the inter-packet arrival gap from the previous arrival, updating the
    /// spacing gauges. Called on every received packet before any dedup/too-late/reset
    /// test (matching libRIST's per-arrival measurement); the first packet
    /// (`started == false`) only seeds the anchor.
    fn sample_arrival_spacing(&mut self, now: Timestamp) {
        if self.receiver.started {
            let delta = (now - self.receiver.ips_last_arrival).as_micros();
            self.receiver.ips_cur_us = delta;
            self.receiver.ips_min_us = self.receiver.ips_min_us.min(delta);
            self.receiver.ips_max_us = self.receiver.ips_max_us.max(delta);
        }
        self.receiver.ips_last_arrival = now;
    }

    // The receiver feed: arrival spacing, packet-time mapping, dedup, insert, missing
    // detection, and timer scheduling in one pass mirroring libRIST's receiver_enqueue;
    // splitting it would scatter the tightly-ordered state updates.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn recv_feed(&mut self, now: Timestamp, path: u8, pkt: MediaPacket) {
        self.sample_arrival_spacing(now);

        // Flow-id change (libRIST "Detected flow id change ... resetting state"): a
        // started flow receiving a fresh packet whose flow id (the SSRC with the
        // retransmit LSB masked) differs from the one it anchored on is seeing a new
        // source flow — a sender restart with a new SSRC, or a different sender taking
        // over the tuple. Discard the buffered state and re-anchor on the new flow
        // rather than merging two distinct flows into one ring (which would corrupt
        // dedup and playout). A retransmit cannot anchor a flow, so it never triggers
        // a reset.
        if self.receiver.started
            && !pkt.retransmit
            && (pkt.ssrc & !0x1) != (self.receiver.ssrc & !0x1)
        {
            self.reset_receiver();
            self.stats.flow_resets += 1;
        }
        // Wire framing change (libRIST TR-06-3 §9 Main↔Advanced interop): a started
        // Advanced flow whose next fresh packet switches sequence framing — Main
        // 16-bit to Advanced 32-bit (the upgrade once a peer advertises I=1), or vice
        // versa. The two framings carry different timestamp encodings, so the
        // source-time→local mapping must be re-derived for the new scale; but the
        // SEQUENCE is continuous across the switch (one sender counter, and a
        // 16-bit-zero RTP start makes the Main-widened sequence equal the Advanced
        // sequence), so this is a LOSSLESS ring-preserving re-anchor: keep the buffered
        // ring, the delivery cursor, and the missing set, and only re-lock the timing
        // baseline. Already-buffered packets keep their stored output_time; a gap open
        // at the switch still heals via ARQ. Re-set max_source_time so the backward-wrap
        // guard does not misfire on the timestamp-scale change. (Simple/Main/matched-
        // Advanced flows never change framing, so this never fires.)
        if self.receiver.started && !pkt.retransmit && pkt.short_seq != self.receiver.short_seq {
            let src = Ntp64::from_bits(pkt.source_time).to_timestamp();
            self.receiver.offset = now - src;
            self.receiver.max_source_time = pkt.source_time;
            self.receiver.last_packet_time = now;
            self.receiver.last_resync = now;
            self.receiver.short_seq = pkt.short_seq;
            self.stats.framing_resets += 1;
        }
        if !self.receiver.started {
            // A flow cannot start on a retransmit.
            if pkt.retransmit {
                return;
            }
            self.start(now, path, pkt);
            return;
        }

        let seqn = pkt.seq;
        let source_time = pkt.source_time;
        let retransmit = pkt.retransmit;

        // Count every retransmit-flagged copy that reaches the started flow, before
        // any too-late / dedup / cursor test sheds it (libRIST), so
        // `retransmitted_received` tallies all received retransmits — including late
        // and duplicate ones — distinct from `recovered` (gaps ARQ actually filled).
        if retransmit {
            self.stats.retransmitted_received += 1;
        }

        let packet_time = self.receiver_packet_time(now, source_time, retransmit);

        // Track the newest source timestamp and its packet time, mirroring
        // calculate_packet_time. The update runs before the out-of-order test
        // (as in libRIST) so the clock-advancing packet never compares to itself.
        if source_time > self.receiver.max_source_time {
            self.receiver.max_source_time = source_time;
            self.receiver.last_packet_time = packet_time;
        }

        // Out-of-order / too-late shedding by SOURCE time: only packets older than
        // the newest packet time and not the immediate successor of last_found
        // qualify. Applies to both source-paced modes (SOURCE and RTC); skipped in
        // ARRIVAL timing, where playout is not source-paced (the seq-based cursor guard
        // below sheds the unrecoverable ones instead).
        let mut out_of_order = false;
        if self.cfg.timing_mode != TimingMode::Arrival
            && packet_time < self.receiver.last_packet_time
            && seqn != self.receiver.last_found.wrapping_add(1)
        {
            if now > packet_time + self.recovery_buffer_110 {
                self.stats.too_late += 1;
                if retransmit {
                    self.stats.too_late_retransmit += 1;
                }
                return;
            }
            if !retransmit {
                out_of_order = true;
            }
        }

        // Playout-cursor guard: a packet circularly behind deliver_next can never
        // be delivered in order again (DEVIATION: libRIST approximates this with
        // its buffer-full check; comparing the cursor sheds it deterministically
        // and keeps the no-late-delivery invariant exact).
        if Seq32::new(seqn).less(Seq32::new(self.receiver.deliver_next)) {
            self.stats.too_late += 1;
            if retransmit {
                self.stats.too_late_retransmit += 1;
            }
            return;
        }

        let idx = (seqn & self.receiver.mask) as usize;
        let (was_filled, is_dup) = {
            let s = &self.receiver.ring[idx];
            let filled = s.state == SlotState::Filled;
            (
                filled,
                filled && s.seq == seqn && s.source_time == source_time,
            )
        };
        if is_dup {
            // An ARQ re-send or another 2022-7 path's copy: record the path and
            // drop. This single test is the entire multipath merge.
            self.receiver.ring[idx].path_seen |= path_bit(path);
            self.stats.duplicates += 1;
            return;
        }
        if was_filled {
            // Same slot, different (seq, source_time): a stale entry from a
            // sequence discontinuity or ring wrap — overwrite.
            self.stats.overwritten += 1;
        }

        let output_time = packet_time + self.recovery_buffer;
        let pkt_bytes = pkt.payload.len() as u64;
        {
            let s = &mut self.receiver.ring[idx];
            s.state = SlotState::Filled;
            s.seq = seqn;
            s.source_time = source_time;
            s.payload = pkt.payload;
            s.frag = pkt.frag;
            s.virt_src_port = pkt.virt_src_port;
            s.virt_dst_port = pkt.virt_dst_port;
            s.arrival = now;
            s.packet_time = packet_time;
            s.output_time = output_time;
            s.path_seen = path_bit(path);
        }
        self.stats.received += 1;
        self.stats.received_bytes += pkt_bytes;
        if out_of_order {
            self.stats.reordered += 1;
        }
        if Seq32::new(self.receiver.highest).less(Seq32::new(seqn)) {
            self.receiver.highest = seqn;
        }
        self.receiver.last_path = path;

        // Missing detection and last_found advance, gated exactly as libRIST:
        // retransmits trigger neither; out-of-order packets trigger neither but
        // still fill their hole.
        if !retransmit {
            if !out_of_order && seqn.wrapping_sub(1) != self.receiver.last_found {
                self.mark_missing(now, path, seqn, packet_time);
            }
            if !out_of_order {
                self.receiver.last_found = seqn;
            }
        }

        self.arm_playout(output_time);
        self.schedule_nack(now);
    }

    /// Discards all buffered receiver state on a flow-id change (libRIST clears
    /// `receiver_queue_has_items`), so the next packet re-anchors a fresh flow via
    /// [`start`](Self::start). It clears the ring (no stale slot from the old flow
    /// can be delivered or deduped against the new one), drops the missing queue,
    /// clears `started`, and disarms the playout/NACK timer flags so `start` re-arms
    /// them at the new flow's deadlines (`start` also re-seeds every cursor, so the
    /// stale cursors need no explicit reset). It preserves what is a property of the
    /// link, not the flow: the ring allocation, the RTT estimator, and the
    /// (auto-scaled) recovery buffer.
    fn reset_receiver(&mut self) {
        let r = &mut self.receiver;
        r.ring.fill(Slot::default());
        r.missing.clear();
        r.started = false;
        r.pending_discontinuity = false;
        r.playout_armed = false;
        r.nack_armed = false;
    }

    /// Records the maximum buffer the peer retains as a sender (libRIST
    /// `sender_max_buffer_ticks`), learned from an inbound buffer-negotiation
    /// message. It enables receiver-side recovery-buffer auto-scaling, which never
    /// sizes the playout buffer past what the sender can retransmit. A value below
    /// `recovery_buffer_min` disables negotiation (the receiver falls back to the
    /// static midpoint). Receiver-role only.
    pub fn set_sender_max_buffer(&mut self, max_buffer: Micros) {
        if self.role != Role::Receiver {
            return;
        }
        if max_buffer.as_micros() < self.cfg.recovery_buffer_min.as_micros() {
            self.receiver.sender_max_buffer = Micros::ZERO;
            return;
        }
        if self.receiver.sender_max_buffer.as_micros() == 0 {
            // Activation: baseline the loss counters so the first recalc's modifier
            // measures loss over the period since auto-scaling turned on, not all
            // loss since the flow started (which would spuriously trip the high-loss
            // jump after a lossy startup/handshake).
            self.receiver.loss_snap = self.stats.lost;
            self.receiver.recovered_snap = self.stats.recovered;
        }
        self.receiver.sender_max_buffer = max_buffer;
    }

    /// The receiver's current recovery (playout) buffer — the static midpoint until
    /// auto-scaling activates, then the dynamically sized value. The host reads it to
    /// advertise the receiver's buffer back to the sender via buffer negotiation. It
    /// is the live value the too-late and NACK-abandon thresholds use.
    #[must_use]
    pub fn current_recovery_buffer(&self) -> Micros {
        self.recovery_buffer
    }

    /// Recomputes the recovery (playout) buffer from the smoothed RTT and recent
    /// loss, porting libRIST's `_librist_receiver_buffer_calc`. It runs only for a
    /// receiver with a windowed buffer (`recovery_buffer_min != recovery_buffer_max`),
    /// a positive `rtt_multiplier`, and a sender max learned via buffer negotiation;
    /// otherwise the static midpoint set in [`Flow::new`] stands. Called on the
    /// receiver's periodic RTT-echo timer (~100 ms), so the loss-growth modifier sees
    /// the loss accrued over that period and the buffer keeps adapting even if echo
    /// responses stop arriving.
    ///
    /// The deadline of an already-buffered packet is fixed at its insertion (each
    /// slot stores its own `output_time`), so changing the buffer here only affects
    /// packets inserted afterward and the live too-late / NACK-abandon thresholds —
    /// never retroactively re-dating a packet, which preserves the in-order /
    /// no-late-delivery invariants. Growth is unbounded within `[min, max]`; shrink is
    /// rate-limited.
    #[allow(clippy::cast_precision_loss)]
    pub(super) fn auto_scale_buffer(&mut self) {
        if self.role != Role::Receiver {
            return;
        }
        // Sample the live recovery-buffer level for the avg_buffer_time gauge on every
        // recalc tick (~100 ms), whether or not the dynamic scaling below proceeds — a
        // static or scaling-disabled buffer still contributes its constant level to the
        // running mean.
        self.receiver.buffer_time_sum += self.recovery_buffer.as_micros();
        self.receiver.buffer_time_samples += 1;

        if self.cfg.rtt_multiplier == 0 {
            return;
        }
        if self.cfg.recovery_buffer_min.as_micros() == self.cfg.recovery_buffer_max.as_micros() {
            return;
        }
        let sender_max = self.receiver.sender_max_buffer.as_micros();
        if sender_max <= 0 {
            // Auto-scaling activates only once the sender advertises the buffer it
            // retains; until then the receiver holds the static midpoint.
            return;
        }

        // desired = smoothedRTT * multiplier + reorder. The smoothed RTT is read
        // unclamped, as libRIST does here (the [rtt_min, rtt_max] clamp paces NACK
        // retries, not buffer sizing).
        let mut desired = self.est.smoothed().as_micros() * i64::from(self.cfg.rtt_multiplier)
            + self.cfg.reorder_buffer.as_micros();

        // Loss-driven growth over the period since the last recalc.
        let lost_delta = self.stats.lost - self.receiver.loss_snap;
        let recovered_delta = self.stats.recovered - self.receiver.recovered_snap;
        let modifier = 1.0
            + lost_delta as f64 * BUFFER_GROWTH_PER_LOST
            + recovered_delta as f64 * BUFFER_GROWTH_PER_RECOVERED;
        desired = (desired as f64 * modifier) as i64;
        if lost_delta > BUFFER_HIGH_LOSS_THRESHOLD {
            // Heavy loss: jump straight to the largest buffer the sender supports.
            desired = sender_max;
        }

        // Rate-limit the decrease so a brief RTT dip cannot collapse the deadline.
        let cur = self.recovery_buffer.as_micros();
        if desired < cur && cur - desired > BUFFER_DECREASE_STEP.as_micros() {
            desired = cur - BUFFER_DECREASE_STEP.as_micros();
        }

        // Clamp to the configured window, then to what the sender retains.
        desired = desired.clamp(
            self.cfg.recovery_buffer_min.as_micros(),
            self.cfg.recovery_buffer_max.as_micros(),
        );
        if desired > sender_max {
            desired = sender_max;
        }

        let desired = Micros::from_micros(desired);
        self.recovery_buffer = desired;
        self.recovery_buffer_110 = mul_1_1(desired);
        self.receiver.loss_snap = self.stats.lost;
        self.receiver.recovered_snap = self.stats.recovered;
    }

    /// First-packet initialization (libRIST `receiver_enqueue` empty-queue
    /// branch): lock the clock offset, seed cursors, insert the packet, and start
    /// the playout and RTT-echo schedules. The first packet never triggers
    /// missing detection.
    fn start(&mut self, now: Timestamp, path: u8, pkt: MediaPacket) {
        let src = Ntp64::from_bits(pkt.source_time).to_timestamp();
        let output_time = now + self.recovery_buffer;
        let pkt_bytes = pkt.payload.len() as u64;
        {
            let r = &mut self.receiver;
            r.offset = now - src;
            r.started = true;
            r.ssrc = pkt.ssrc;
            r.short_seq = pkt.short_seq;
            r.last_found = pkt.seq;
            r.max_source_time = pkt.source_time;
            r.last_packet_time = now; // == src + offset by construction
            r.last_resync = now; // dwell anchor for the source-clock wrap re-anchor
            r.highest = pkt.seq;
            r.deliver_next = pkt.seq;
            r.last_path = path;

            let idx = (pkt.seq & r.mask) as usize;
            let s = &mut r.ring[idx];
            s.state = SlotState::Filled;
            s.seq = pkt.seq;
            s.source_time = pkt.source_time;
            s.payload = pkt.payload;
            s.frag = pkt.frag;
            s.virt_src_port = pkt.virt_src_port;
            s.virt_dst_port = pkt.virt_dst_port;
            s.arrival = now;
            s.packet_time = now;
            s.output_time = output_time;
            s.path_seen = path_bit(path);
        }
        self.stats.received += 1;
        self.stats.received_bytes += pkt_bytes;

        self.arm_playout(output_time);
        // A no-recovery (one-way) transport has no return channel, so the receiver
        // originates no RTT echo requests.
        if !self.cfg.no_recovery {
            self.outputs.push_back(Output::SetTimer {
                id: TimerId::RttEcho,
                deadline: now + RTT_ECHO_INTERVAL,
            });
        }
    }

    /// Queues missing entries for every sequence in `(last_found, current)`,
    /// following `receiver_mark_missing`: the per-entry nack time is interpolated
    /// linearly between the two known packet times (assuming CBR).
    fn mark_missing(&mut self, now: Timestamp, path: u8, current: u32, packet_time_now: Timestamp) {
        // A no-recovery (one-way) transport has no return channel: never queue
        // missing entries, so no NACKs are ever requested. The `last_found` cursor
        // still advances at the call site and the playout timer reclaims the hole
        // at its deadline (recovery by playout-skip, not ARQ).
        if self.cfg.no_recovery {
            return;
        }
        let last_found = self.receiver.last_found;
        let gap = u64::from(current.wrapping_sub(last_found));
        // Wraparound guard pinned to seq::MAX_GAP_16 (32768) for flows widened
        // from 16-bit sequences (libRIST `if (missing_count > 32768) return`).
        if gap > seq::MAX_GAP_16 {
            return;
        }
        // gap == 0 means a re-keyed packet for last_found itself; libRIST's walk
        // would mark ~2^16 bogus entries — return early instead.
        if gap == 0 {
            return;
        }

        // Interpolate per-packet time between the anchors. When the anchor slot
        // is gone libRIST substitutes the wall clock; `now` is the equivalent.
        let idx = (last_found & self.receiver.mask) as usize;
        let mut packet_time_last = now;
        {
            let s = &self.receiver.ring[idx];
            if s.state == SlotState::Filled && s.seq == last_found {
                packet_time_last = s.packet_time;
            }
        }
        let mut delta = packet_time_now - packet_time_last;
        if delta < Micros::ZERO {
            // A non-positive spread degenerates to zero spacing (libRIST's
            // unsigned subtraction would wrap enormous here).
            delta = Micros::ZERO;
        }
        let interpacket = Micros::from_micros(delta.as_micros() / (gap as i64 + 1));

        let ring_len = self.receiver.ring.len() as u64;
        let mut nack_time = packet_time_last;
        let mut count = 1u64;
        let mut m = last_found.wrapping_add(1);
        while m != current {
            // Buffer-bloat guard: stop queuing new gaps once the missing queue
            // reaches `missing_counter_max` (derived from the recovery window and
            // recovery_maxbitrate). Already-queued entries keep being retried; the
            // unmarked tail is re-detected on the next packet (libRIST
            // `if (missing_count > missing_counter_max) break`).
            if self.receiver.missing.len() as u32 > self.missing_counter_max {
                break;
            }
            nack_time = nack_time + interpacket;
            self.add_missing(now, path, m, nack_time);
            count += 1;
            if count == ring_len {
                // Safety bound (libRIST `counter == receiver_queue_max`).
                break;
            }
            m = m.wrapping_add(1);
        }
    }

    /// Appends one missing entry (libRIST `rist_receiver_missing`): the insertion
    /// time is the interpolated nack time clamped into `[now-recoveryBuffer,
    /// now]` — out-of-range becomes `now` — and is retained only for the
    /// abandon-age check. The first NACK is scheduled at
    /// `now + max(clamp(smoothed_rtt, rtt_min, rtt_max)/2, reorder_buffer)`,
    /// matching libRIST's `rist_receiver_missing` (cold start: `clamp/2` = 2.5 ms
    /// < the 15 ms reorder floor, so the first NACK is `now + reorder_buffer`).
    fn add_missing(&mut self, now: Timestamp, path: u8, missing_seq: u32, nack_time: Timestamp) {
        let mut insertion = nack_time;
        if insertion > now || insertion < now - self.recovery_buffer {
            insertion = now;
        }
        let clamped = self.est.clamped(self.cfg.rtt_min, self.cfg.rtt_max);
        let first_delay = Micros::from_micros(clamped.as_micros() / 2).max(self.cfg.reorder_buffer);
        let next_nack = now + first_delay;
        self.receiver.missing.push_back(MissingEntry {
            seq: missing_seq,
            path,
            nack_count: 0,
            insertion_time: insertion,
            next_nack,
        });
        self.stats.missing += 1;
    }

    /// Arms the NACK cadence timer when missing entries are queued and the timer
    /// is idle. The cadence is libRIST's `RIST_MAX_JITTER` = 5 ms receiver-loop
    /// bound.
    pub(crate) fn schedule_nack(&mut self, now: Timestamp) {
        if self.receiver.missing.is_empty() || self.receiver.nack_armed {
            return;
        }
        self.receiver.nack_armed = true;
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Nack,
            deadline: now + NACK_CADENCE,
        });
    }

    /// Walks the missing queue once (libRIST `rist_receiver_nack_output` /
    /// `rist_process_nack`):
    ///
    /// - slot filled with the entry's seq → recovered, remove (count
    ///   `recovered` only when at least one NACK went out);
    /// - slot filled with another seq → stale entry, remove;
    /// - `nack_count >= max_retries` → abandon;
    /// - age > `recovery_buffer*1.1` → abandon;
    /// - `now >= next_nack` → NACK it: `next_nack = now + 1.1*clamp(rtt)`,
    ///   `nack_count++`.
    ///
    /// All sequences NACKed in one pass leave as a single [`Feedback::Nack`].
    pub(crate) fn process_nacks(&mut self, now: Timestamp) {
        if self.receiver.missing.is_empty() {
            return;
        }
        let retry = self.est.retry_interval(self.cfg.rtt_min, self.cfg.rtt_max);
        // Refill the return-bandwidth token bucket from the elapsed time (sans-I/O:
        // the rate is applied against the explicit `now`). The bucket starts full, so
        // the first pass — whatever `now` is — just clamps at the burst cap.
        if self.receiver.nack_seqs_per_sec > 0.0 {
            let elapsed = now - self.receiver.nack_tokens_time;
            if elapsed > Micros::ZERO {
                self.receiver.nack_tokens +=
                    elapsed.as_micros() as f64 / 1_000_000.0 * self.receiver.nack_seqs_per_sec;
                if self.receiver.nack_tokens > self.receiver.nack_token_burst {
                    self.receiver.nack_tokens = self.receiver.nack_token_burst;
                }
            }
            self.receiver.nack_tokens_time = now;
        }
        let mut entries = std::mem::take(&mut self.receiver.missing);
        let mut kept: VecDeque<MissingEntry> = VecDeque::with_capacity(entries.len());
        let mut batch: Vec<u32> = Vec::new();
        while let Some(mut e) = entries.pop_front() {
            let idx = (e.seq & self.receiver.mask) as usize;
            let (filled, slot_seq) = {
                let s = &self.receiver.ring[idx];
                (s.state == SlotState::Filled, s.seq)
            };
            if filled && slot_seq == e.seq {
                if e.nack_count > 0 {
                    self.stats.recovered += 1;
                    if e.nack_count == 1 {
                        self.stats.recovered_one_retry += 1;
                    }
                }
                continue; // recovered: remove
            }
            if filled {
                continue; // slot reused by another sequence: remove
            }
            if e.nack_count >= self.cfg.max_retries {
                self.stats.abandoned += 1;
                continue;
            }
            if (now - e.insertion_time) > self.recovery_buffer_110 {
                self.stats.abandoned += 1;
                continue;
            }
            // A NACK is emitted only when due AND a return-bandwidth token is
            // available (or the bucket is unlimited). With no token the entry is left
            // due — `next_nack` is not advanced — so it is serviced on the next pass
            // rather than dropped (recovery slows, nothing is lost), matching the
            // RIST_MAX_NACKS per-pass cap.
            if now >= e.next_nack
                && (self.receiver.nack_seqs_per_sec <= 0.0 || self.receiver.nack_tokens >= 1.0)
            {
                e.next_nack = now + retry;
                e.nack_count += 1;
                batch.push(e.seq);
                self.stats.nacks_sent += 1;
                if self.receiver.nack_seqs_per_sec > 0.0 {
                    self.receiver.nack_tokens -= 1.0;
                }
            }
            kept.push_back(e);
        }
        self.receiver.missing = kept;
        if !batch.is_empty() {
            let ssrc = self.receiver.ssrc;
            let path = self.receiver.last_path;
            self.outputs.push_back(Output::SendFeedback {
                path,
                fb: Feedback::Nack {
                    ssrc,
                    missing: batch,
                },
            });
        }
    }

    /// Time-driven in-order delivery at `now`: the slot at the cursor is
    /// delivered once `now >= output_time`; a hole is skipped only when the next
    /// buffered packet is itself due, at which point the skipped sequences are
    /// counted lost and the next delivery carries a discontinuity flag.
    pub(crate) fn deliver_due(&mut self, now: Timestamp) {
        if !self.receiver.started {
            return;
        }
        loop {
            let cursor = self.receiver.deliver_next;
            let idx = (cursor & self.receiver.mask) as usize;
            let (filled, slot_seq, output_time) = {
                let s = &self.receiver.ring[idx];
                (s.state == SlotState::Filled, s.seq, s.output_time)
            };
            if filled && slot_seq == cursor {
                if now < output_time {
                    self.arm_playout(output_time);
                    return;
                }
                self.emit_deliver(idx);
                continue;
            }

            // Hole at the cursor: find the next buffered packet.
            let dist = Seq32::new(cursor).distance(Seq32::new(self.receiver.highest));
            if dist <= 0 {
                // Nothing buffered ahead of the cursor.
                self.disarm_playout();
                return;
            }
            let ring_n = self.receiver.ring.len() as i64;
            let limit = dist.min(ring_n);
            let mut found_seq = 0u32;
            let mut found = false;
            let mut k: i64 = 1;
            while k <= limit {
                let n = cursor.wrapping_add(k as u32);
                let i = (n & self.receiver.mask) as usize;
                let s = &self.receiver.ring[i];
                if s.state == SlotState::Filled && s.seq == n {
                    found_seq = n;
                    found = true;
                    break;
                }
                k += 1;
            }
            if !found {
                if dist > ring_n {
                    // The ring lapped the cursor without any packet for a whole
                    // ring span: those sequences are unrecoverable.
                    let target = cursor.wrapping_add(self.receiver.ring.len() as u32);
                    self.skip_to(target);
                    continue;
                }
                self.disarm_playout();
                return;
            }
            let out_time = {
                let i = (found_seq & self.receiver.mask) as usize;
                self.receiver.ring[i].output_time
            };
            if now < out_time {
                // The hole may still be recovered until the next packet is due.
                self.arm_playout(out_time);
                return;
            }
            self.skip_to(found_seq);
        }
    }

    /// Hands the slot's payload to the application and advances the cursor. The
    /// payload reference moves into the event; the slot is cleared.
    fn emit_deliver(&mut self, idx: usize) {
        let (seqn, source_time, payload, frag, virt_src_port, virt_dst_port) = {
            let s = &mut self.receiver.ring[idx];
            s.state = SlotState::Empty;
            (
                s.seq,
                s.source_time,
                std::mem::take(&mut s.payload),
                s.frag,
                s.virt_src_port,
                s.virt_dst_port,
            )
        };
        let discontinuity = self.receiver.pending_discontinuity;
        self.receiver.pending_discontinuity = false;
        self.events.push_back(Event::Deliver {
            seq: seqn,
            source_time,
            payload,
            discontinuity,
            frag,
            virt_src_port,
            virt_dst_port,
        });
        self.stats.delivered += 1;
        self.receiver.deliver_next = self.receiver.deliver_next.wrapping_add(1);
    }

    /// Abandons every sequence in `[deliver_next, target)` as lost, clears stale
    /// slots passed over, and marks the discontinuity for the next delivery.
    fn skip_to(&mut self, target: u32) {
        let from = self.receiver.deliver_next;
        let lost = u64::from(target.wrapping_sub(from));
        let mut n = from;
        while n != target {
            let idx = (n & self.receiver.mask) as usize;
            let s = &mut self.receiver.ring[idx];
            if s.state == SlotState::Filled {
                s.state = SlotState::Empty;
                s.payload = Bytes::new();
            }
            n = n.wrapping_add(1);
        }
        self.receiver.deliver_next = target;
        self.receiver.pending_discontinuity = true;
        self.stats.lost += lost;
        self.stats.discontinuities += 1;
    }

    /// Requests the playout timer for `deadline` unless an earlier or equal
    /// request is already outstanding (so in-order steady state emits nothing).
    fn arm_playout(&mut self, deadline: Timestamp) {
        if self.receiver.playout_armed && deadline >= self.receiver.playout_deadline {
            return;
        }
        self.receiver.playout_armed = true;
        self.receiver.playout_deadline = deadline;
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Playout,
            deadline,
        });
    }

    /// Cancels an outstanding playout timer request.
    fn disarm_playout(&mut self) {
        if !self.receiver.playout_armed {
            return;
        }
        self.receiver.playout_armed = false;
        self.outputs.push_back(Output::ClearTimer {
            id: TimerId::Playout,
        });
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::{Slot, SlotState};
    use crate::clock::{Micros, Timestamp};
    use crate::flow::testutil::{
        TEST_SSRC, delivered_seqs, drain_events, drain_outputs, mk_pkt, src_ntp,
    };
    use crate::flow::{Config, Event, Flow, Output, Role, TimerId, TimingMode};
    use crate::rtt::Estimator;
    use crate::wire::Feedback;

    /// A millisecond duration in the core's `Micros` unit.
    fn ms(n: i64) -> Micros {
        Micros::from_micros(n * 1000)
    }

    /// A receiver flow with a windowed recovery buffer (`min != max`) so dynamic
    /// auto-scaling is eligible. Static midpoint is `(1000-200)/2 + 200 = 600 ms`.
    fn windowed_recv() -> Flow {
        let mut cfg = Config::librist_defaults();
        cfg.recovery_buffer_min = ms(200);
        cfg.recovery_buffer_max = ms(1000);
        cfg.reorder_buffer = ms(15);
        cfg.rtt_multiplier = 7;
        Flow::new(Role::Receiver, cfg)
    }

    /// Runs the auto-scaler to a steady value (the decrease is rate-limited to 50 ms
    /// per recalc, so a fall takes several recalcs; with no fresh loss the modifier
    /// is 1 and the buffer steps monotonically to its clamp).
    fn converge(f: &mut Flow) {
        let mut prev = -1;
        for _ in 0..64 {
            if f.recovery_buffer.as_micros() == prev {
                break;
            }
            prev = f.recovery_buffer.as_micros();
            f.auto_scale_buffer();
        }
    }

    #[test]
    fn auto_scale_buffer_librist_calc() {
        // No sender max learned: holds the static midpoint.
        let mut f = windowed_recv();
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(600).as_micros(),
            "no sender max"
        );

        // Scales to smoothedRTT*multiplier + reorder = 100*7 + 15 = 715 ms, and the
        // 1.1x threshold tracks it.
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(715).as_micros(),
            "rtt*mult+reorder"
        );
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let want110 = (ms(715).as_micros() as f64 * 1.1) as i64;
        assert_eq!(
            f.recovery_buffer_110.as_micros(),
            want110,
            "110 must track dynamic buffer"
        );

        // Clamps up to buffer_min (20*7+15 = 155 ms, below the 200 ms floor).
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(20));
        converge(&mut f);
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(200).as_micros(),
            "clamp to min"
        );

        // Clamps down to the sender max (715 desired, sender retains only 500).
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(500));
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(500).as_micros(),
            "clamp to sender max"
        );

        // A sender max below buffer_min disables scaling.
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(100));
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(600).as_micros(),
            "sender max < min disables"
        );

        // Loss grows the buffer: 5 lost -> modifier 1 + 5*0.05 = 1.25.
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(50)); // base 50*7+15 = 365 ms
        converge(&mut f);
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(365).as_micros(),
            "loss-free base"
        );
        f.stats.lost += 5;
        f.auto_scale_buffer();
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let want = (ms(365).as_micros() as f64 * 1.25) as i64;
        assert_eq!(f.recovery_buffer.as_micros(), want, "loss-grown");

        // Heavy loss (> 25 this period) jumps straight to the sender max.
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(900));
        f.est = Estimator::new(ms(50));
        f.auto_scale_buffer(); // snapshot
        f.stats.lost += 30;
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(900).as_micros(),
            "high-loss jump"
        );

        // Decrease is rate-limited to 50 ms per recalc.
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(100)); // 715 ms
        f.auto_scale_buffer();
        f.est = Estimator::new(ms(20)); // desired falls to 155 -> clamp 200, a 515 ms drop
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(665).as_micros(),
            "decrease capped at 50ms"
        );

        // A non-windowed buffer (min == max) never scales.
        let mut cfg = Config::librist_defaults();
        cfg.recovery_buffer_min = ms(500);
        cfg.recovery_buffer_max = ms(500);
        cfg.rtt_multiplier = 7;
        let mut f = Flow::new(Role::Receiver, cfg);
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(500).as_micros(),
            "non-windowed never scales"
        );
    }

    #[test]
    fn avg_buffer_time_tracks_the_recovery_buffer() {
        // A static (non-windowed) receiver: the gauge reports the constant buffer even
        // before any sample, and stays there as recalc ticks accumulate.
        let mut cfg = Config::librist_defaults();
        cfg.recovery_buffer_min = ms(500);
        cfg.recovery_buffer_max = ms(500);
        let mut f = Flow::new(Role::Receiver, cfg);
        assert_eq!(
            f.avg_buffer_time_us(),
            ms(500).as_micros(),
            "pre-sample static"
        );
        for _ in 0..4 {
            f.auto_scale_buffer(); // samples 500ms each tick, never scales
        }
        assert_eq!(f.avg_buffer_time_us(), ms(500).as_micros(), "static mean");

        // A windowed receiver that scales 600 -> 715ms: the running mean lies between
        // the two sampled levels (600 sampled first, then 715).
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer(); // samples 600 (pre-scale), then grows to 715
        f.auto_scale_buffer(); // samples 715
        let avg = f.avg_buffer_time_us();
        assert_eq!(
            avg,
            i64::midpoint(ms(600).as_micros(), ms(715).as_micros()),
            "windowed mean"
        );

        // A sender flow always reports 0.
        let s = Flow::new(Role::Sender, Config::librist_defaults());
        assert_eq!(s.avg_buffer_time_us(), 0, "sender reports 0");
    }

    #[test]
    fn set_rtt_multiplier_takes_effect_on_next_auto_scale() {
        // Base: mult 7, smoothed 100 ms -> 100*7 + 15 = 715 ms.
        let mut f = windowed_recv();
        f.set_sender_max_buffer(ms(1000));
        f.est = Estimator::new(ms(100));
        f.auto_scale_buffer();
        assert_eq!(f.recovery_buffer.as_micros(), ms(715).as_micros(), "mult 7");

        // A runtime change is read live by the next pass: mult 3 -> 100*3 + 15 = 315 ms
        // (clamped within [200, 1000], so the full value stands). The decrease is
        // rate-limited to 50 ms/recalc, so converge to the new steady value.
        f.set_rtt_multiplier(3);
        converge(&mut f);
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(315).as_micros(),
            "mult 3 after runtime set"
        );

        // 0 disables auto-scaling: the buffer then holds wherever it was.
        f.set_rtt_multiplier(0);
        f.est = Estimator::new(ms(500)); // would be huge if scaling were live
        f.auto_scale_buffer();
        assert_eq!(
            f.recovery_buffer.as_micros(),
            ms(315).as_micros(),
            "mult 0 freezes the buffer"
        );
    }

    fn ts(us: u64) -> Timestamp {
        Timestamp::from_micros(us)
    }

    fn recv() -> Flow {
        Flow::new(Role::Receiver, Config::librist_defaults())
    }

    fn slot_of(f: &Flow, seq: u32) -> &Slot {
        &f.receiver.ring[(seq & f.receiver.mask) as usize]
    }

    fn rtx(seq: u32, src_us: u64, payload: &'static [u8]) -> crate::wire::MediaPacket {
        let mut p = mk_pkt(seq, src_us, payload);
        p.retransmit = true;
        p
    }

    /// A media packet on a specific flow (SSRC), for the flow-id-change tests.
    fn pkt_on(seq: u32, src_us: u64, ssrc: u32) -> crate::wire::MediaPacket {
        let mut p = mk_pkt(seq, src_us, b"x");
        p.ssrc = ssrc;
        p
    }

    #[test]
    fn inter_packet_spacing_tracks_arrival_gaps() {
        const FLOW_A: u32 = 0x1000_0000;
        let mut f = recv();
        // First packet only seeds the anchor (no delta yet).
        f.feed(ts(10_000), 0, pkt_on(100, 0, FLOW_A));
        let s = f.stats();
        assert_eq!((s.ips_min_us, s.ips_cur_us, s.ips_max_us), (0, 0, 0));
        // +5 ms, then +3 ms: cur tracks the last gap, min/max the extremes.
        f.feed(ts(15_000), 0, pkt_on(101, 7_000, FLOW_A));
        f.feed(ts(18_000), 0, pkt_on(102, 11_000, FLOW_A));
        let s = f.stats();
        assert_eq!(s.ips_cur_us, 3_000);
        assert_eq!(s.ips_min_us, 3_000);
        assert_eq!(s.ips_max_us, 5_000);
    }

    #[test]
    fn flow_id_change_resets_and_reanchors() {
        const FLOW_A: u32 = 0x1000_0000;
        const FLOW_B: u32 = 0x2000_0000;
        let mut f = recv();

        // Anchor on flow A and buffer two packets.
        f.feed(ts(10_000), 0, pkt_on(100, 0, FLOW_A));
        f.feed(ts(17_000), 0, pkt_on(101, 7_000, FLOW_A));
        assert_eq!(f.receiver.ssrc, FLOW_A);
        assert_eq!(f.stats().flow_resets, 0);

        // A fresh packet whose SSRC differs only in the retransmit LSB is the SAME
        // flow id (the `& !0x1` mask), so it must NOT reset.
        f.feed(ts(18_000), 0, pkt_on(102, 11_000, FLOW_A | 0x1));
        assert_eq!(
            f.stats().flow_resets,
            0,
            "a same-flow-id packet (LSB only) wrongly reset"
        );

        // A retransmit bearing a different flow id must NOT reset (a retransmit
        // cannot anchor a flow).
        let mut rt = pkt_on(100, 0, FLOW_B);
        rt.retransmit = true;
        f.feed(ts(18_500), 0, rt);
        assert_eq!(f.stats().flow_resets, 0, "a retransmit triggered a reset");

        // A fresh packet on flow B is a genuine flow-id change: reset + re-anchor.
        f.feed(ts(30_000), 0, pkt_on(5000, 23_000, FLOW_B));
        assert_eq!(f.stats().flow_resets, 1, "flow-id change not counted");
        assert_eq!(f.receiver.ssrc, FLOW_B, "did not re-anchor on flow B");
        assert!(f.receiver.started && f.receiver.deliver_next == 5000);
        assert!(
            f.receiver.missing.is_empty(),
            "missing queue not cleared on reset"
        );
        // Flow A's buffered slot was cleared (when it does not alias flow B's slot).
        let ring_idx = |seq: u32| seq & f.receiver.mask;
        if ring_idx(100) != ring_idx(5000) {
            assert_eq!(
                slot_of(&f, 100).state,
                SlotState::Empty,
                "flow A ring slot survived the reset"
            );
        }
    }

    #[test]
    fn framing_change_reanchors_losslessly() {
        // TR-06-3 §9 Main↔Advanced interop: an anchored Main (16-bit) flow that sees
        // the Advanced (32-bit) upgrade on the SAME SSRC and the continuing sequence
        // re-anchors its TIMING baseline while PRESERVING the buffered ring, the
        // delivery cursor, and the missing set. The switch is lossless: every packet
        // buffered before the upgrade is still delivered, in order, none lost. The
        // SSRC stays the same, so the SSRC-change reset alone would miss it.
        const SSRC: u32 = 0x4000_0000;
        let mut f = recv();
        let main_pkt = |seq: u32, src_us: u64| {
            let mut p = pkt_on(seq, src_us, SSRC);
            p.short_seq = true;
            p
        };
        let adv_pkt = |seq: u32, src_us: u64| {
            let mut p = pkt_on(seq, src_us, SSRC);
            p.short_seq = false;
            p
        };

        // Anchor on Main (16-bit) framing and buffer two packets (delivery is
        // time-driven, so they stay in the ring).
        f.feed(ts(10_000), 0, main_pkt(100, 0));
        f.feed(ts(17_000), 0, main_pkt(101, 7_000));
        assert!(f.receiver.short_seq, "did not anchor on Main framing");

        // A retransmit in the other framing must NOT re-anchor (it cannot anchor a flow).
        let mut rt = adv_pkt(100, 0);
        rt.retransmit = true;
        f.feed(ts(18_000), 0, rt);
        assert_eq!(
            f.stats().framing_resets,
            0,
            "a retransmit wrongly re-anchored"
        );

        // The Main→Advanced upgrade on the SAME SSRC and continuing sequence (102).
        f.feed(ts(24_000), 0, adv_pkt(102, 17_000));
        assert_eq!(f.stats().framing_resets, 1, "framing switch not counted");
        assert_eq!(f.stats().flow_resets, 0, "SSRC unchanged across the switch");
        assert!(
            !f.receiver.short_seq,
            "did not re-anchor on Advanced framing"
        );
        // Ring-PRESERVING: the cursor is unmoved and all three packets are buffered
        // (a ring-clearing reset would have re-anchored deliver_next to 102).
        assert!(
            f.receiver.started && f.receiver.deliver_next == 100,
            "re-anchor moved the cursor: deliver_next = {} (ring preserved expected 100)",
            f.receiver.deliver_next
        );
        for seqn in [100u32, 101, 102] {
            assert_eq!(
                slot_of(&f, seqn).state,
                SlotState::Filled,
                "seq {seqn} not buffered after the switch — ring was cleared"
            );
        }

        // Drive playout well past the recovery buffer: all three deliver in order,
        // none lost.
        f.handle_timer(ts(10_000_000), TimerId::Playout);
        let evs = drain_events(&mut f);
        assert_eq!(
            delivered_seqs(&evs),
            vec![100, 101, 102],
            "framing switch was not lossless"
        );
        assert_eq!(f.stats().lost, 0, "framing switch counted lost, want 0");
    }

    #[test]
    fn first_packet_locks_offset_and_schedules() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b"a"));

        assert_eq!(f.receiver.offset.as_micros(), 10_000);
        assert_eq!(f.receiver.last_found, 100);
        assert_eq!(f.receiver.deliver_next, 100);
        let s = slot_of(&f, 100);
        assert_eq!(s.state, SlotState::Filled);
        assert_eq!(s.packet_time, ts(10_000));
        assert_eq!(s.output_time, ts(1_010_000));

        assert_eq!(
            drain_outputs(&mut f),
            vec![
                Output::SetTimer {
                    id: TimerId::Playout,
                    deadline: ts(1_010_000)
                },
                Output::SetTimer {
                    id: TimerId::RttEcho,
                    deadline: ts(110_000)
                },
            ]
        );

        // A later in-order packet maps through the locked offset; steady state.
        f.feed(ts(17_500), 0, mk_pkt(101, 7_000, b"b"));
        let s2 = slot_of(&f, 101);
        assert_eq!(s2.packet_time, ts(17_000));
        assert_eq!(s2.output_time, ts(1_017_000));
        assert!(
            drain_outputs(&mut f).is_empty(),
            "steady state emits nothing"
        );
    }

    #[test]
    fn no_recovery_receiver_never_nacks_but_still_delivers() {
        let mut c = Config::librist_defaults();
        c.no_recovery = true;
        let mut f = Flow::new(Role::Receiver, c);

        // First packet arms playout only — no RTT-echo cadence.
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b"a"));
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SetTimer {
                id: TimerId::Playout,
                deadline: ts(1_010_000),
            }],
            "one-way first packet must arm only the playout timer"
        );

        // A gap (101 never arrives): a normal receiver would queue a missing entry
        // and arm TimerNack. One-way does neither — no recovery output of any kind.
        f.feed(ts(24_000), 0, mk_pkt(102, 14_000, b"c"));
        let outs = drain_outputs(&mut f);
        assert!(
            !outs.iter().any(|o| {
                matches!(o, Output::SetTimer { id, .. }
                    if *id == TimerId::Nack || *id == TimerId::RttEcho)
                    || matches!(o, Output::SendFeedback { .. })
            }),
            "one-way receiver requested recovery on a gap: {outs:?}"
        );
        assert!(
            f.receiver.missing.is_empty(),
            "one-way receiver queued a missing entry"
        );

        // Playout still drives in-order delivery and skips the hole at its deadline.
        f.handle_timer(ts(1_010_000), TimerId::Playout);
        assert_eq!(delivered_seqs(&drain_events(&mut f)), vec![100]);
        drain_outputs(&mut f);
        f.handle_timer(ts(1_024_000), TimerId::Playout);
        let evs = drain_events(&mut f);
        assert_eq!(delivered_seqs(&evs), vec![102]);
        assert!(
            matches!(
                evs[0],
                Event::Deliver {
                    discontinuity: true,
                    ..
                }
            ),
            "delivery after a skipped hole must flag a discontinuity"
        );

        let st = f.stats();
        assert_eq!((st.delivered, st.lost), (2, 1));
    }

    #[test]
    fn first_packet_retransmit_ignored() {
        let mut f = recv();
        f.feed(ts(10_000), 0, rtx(100, 0, b"a"));
        assert!(!f.receiver.started, "flow must not start on a retransmit");
        // No counters moved (the RTT gauge is seeded to rtt_min, so the full snapshot
        // is not all-default — assert the counters that should be untouched).
        let s = f.stats();
        assert_eq!(s.received, 0);
        assert_eq!(s.received_bytes, 0);
        assert_eq!(s.delivered, 0);
        assert_eq!(s.retransmitted_received, 0);
        assert_eq!(s.missing, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)] // a table test: the case array is the bulk
    fn feed_dedup_overwrite_insert() {
        struct Step {
            now: u64,
            path: u8,
            seq: u32,
            src: u64,
            payload: &'static [u8],
            retrans: bool,
        }
        struct Case {
            steps: &'static [Step],
            received: u64,
            duplicates: u64,
            overwritten: u64,
            payload: &'static [u8],
            paths: u64,
        }
        const CASES: &[Case] = &[
            Case {
                // exact duplicate dropped, path recorded
                steps: &[
                    Step {
                        now: 10_000,
                        path: 0,
                        seq: 100,
                        src: 0,
                        payload: b"orig",
                        retrans: false,
                    },
                    Step {
                        now: 10_500,
                        path: 1,
                        seq: 100,
                        src: 0,
                        payload: b"copy",
                        retrans: false,
                    },
                ],
                received: 1,
                duplicates: 1,
                overwritten: 0,
                payload: b"orig",
                paths: 0b11,
            },
            Case {
                // retransmit duplicate dropped
                steps: &[
                    Step {
                        now: 10_000,
                        path: 0,
                        seq: 100,
                        src: 0,
                        payload: b"orig",
                        retrans: false,
                    },
                    Step {
                        now: 12_000,
                        path: 0,
                        seq: 100,
                        src: 0,
                        payload: b"orig",
                        retrans: true,
                    },
                ],
                received: 1,
                duplicates: 1,
                overwritten: 0,
                payload: b"orig",
                paths: 0b1,
            },
            Case {
                // same seq, different source_time overwrites (stale slot)
                steps: &[
                    Step {
                        now: 10_000,
                        path: 0,
                        seq: 100,
                        src: 0,
                        payload: b"old",
                        retrans: false,
                    },
                    Step {
                        now: 20_000,
                        path: 1,
                        seq: 100,
                        src: 9_000,
                        payload: b"new",
                        retrans: false,
                    },
                ],
                received: 2,
                duplicates: 0,
                overwritten: 1,
                payload: b"new",
                paths: 0b10,
            },
            Case {
                // ring-collision seq overwrites (seq + 2^16; gap guard skips marking)
                steps: &[
                    Step {
                        now: 10_000,
                        path: 0,
                        seq: 100,
                        src: 0,
                        payload: b"old",
                        retrans: false,
                    },
                    Step {
                        now: 20_000,
                        path: 0,
                        seq: 100 + (1 << 16),
                        src: 9_000,
                        payload: b"new",
                        retrans: false,
                    },
                ],
                received: 2,
                duplicates: 0,
                overwritten: 1,
                payload: b"new",
                paths: 0b1,
            },
        ];
        for (ci, c) in CASES.iter().enumerate() {
            let mut f = recv();
            let mut last_seq = 0;
            for st in c.steps {
                let mut p = mk_pkt(st.seq, st.src, st.payload);
                p.retransmit = st.retrans;
                f.feed(ts(st.now), st.path, p);
                last_seq = st.seq;
            }
            let stats = f.stats();
            assert_eq!(stats.received, c.received, "case {ci} received");
            assert_eq!(stats.duplicates, c.duplicates, "case {ci} duplicates");
            assert_eq!(stats.overwritten, c.overwritten, "case {ci} overwritten");
            let s = slot_of(&f, last_seq);
            assert_eq!(s.payload.as_ref(), c.payload, "case {ci} payload");
            assert_eq!(s.path_seen, c.paths, "case {ci} path_seen");
        }
    }

    #[test]
    fn missing_detect_interpolation_exact() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(17_000), 0, mk_pkt(101, 7_000, b""));
        drain_outputs(&mut f);

        // Gap 101 -> 105: missing 102..104. packet_time_last = pt(101) = 17000,
        // delta = 45000-17000 = 28000, interpacket = 28000/(4+1) = 5600.
        f.feed(ts(45_000), 3, mk_pkt(105, 35_000, b""));

        let got: Vec<(u32, u8, u64, u64, u32)> = f
            .receiver
            .missing
            .iter()
            .map(|e| {
                (
                    e.seq,
                    e.path,
                    e.insertion_time.as_micros(),
                    e.next_nack.as_micros(),
                    e.nack_count,
                )
            })
            .collect();
        // first_nack = now + max(clamp(rtt)/2, reorder_buffer), anchored to
        // now = 45000 (libRIST rist_receiver_missing). Cold start: clamp/2 =
        // 2.5 ms < the 15 ms reorder floor, so every entry is 45000 + 15000 =
        // 60000 regardless of its interpolated insertion time.
        assert_eq!(
            got,
            vec![
                (102, 3, 22_600, 60_000, 0),
                (103, 3, 28_200, 60_000, 0),
                (104, 3, 33_800, 60_000, 0),
            ]
        );
        assert_eq!(f.stats().missing, 3);
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SetTimer {
                id: TimerId::Nack,
                deadline: ts(50_000)
            }]
        );
        assert_eq!(f.receiver.last_found, 105);
    }

    #[test]
    fn missing_insertion_time_clamped() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        // Source stalled then jumped 2s: interpolated times fall below
        // now-recoveryBuffer, so insertion is clamped to now.
        f.feed(ts(2_010_000), 0, mk_pkt(102, 2_000_000, b""));
        let e = f.receiver.missing.front().expect("missing 101");
        assert_eq!(e.seq, 101);
        assert_eq!(e.insertion_time, ts(2_010_000));
        // first_nack = now + max(clamp(rtt)/2, reorder_buffer) = 2010000 + 15000.
        assert_eq!(e.next_nack, ts(2_025_000));
    }

    #[test]
    fn missing_gap_guards() {
        // (first, next, want_missing). A gap of exactly MaxGap16 is still loss, but
        // the missing-queue is bounded by `missing_counter_max` (3571 with the
        // defaults — see `congestion::derived_bounds_match_librist_defaults`), so the
        // guard stops once the queue exceeds it: 3572 entries, not the full 32767.
        // The unmarked tail is re-detected on the next packet.
        let cases: &[(u32, u32, u64)] = &[
            (100, 100 + 32768, 3572), // gap of exactly MaxGap16: loss, capped
            (100, 100 + 32769, 0),    // strictly greater: wraparound/reorder
        ];
        for &(first, next, want) in cases {
            let mut f = recv();
            f.feed(ts(10_000), 0, mk_pkt(first, 0, b""));
            f.feed(ts(17_000), 0, mk_pkt(next, 7_000, b""));
            assert_eq!(f.stats().missing, want, "gap {first}->{next}");
        }
    }

    #[test]
    fn missing_skipped_for_retransmit_and_out_of_order() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(38_000), 0, mk_pkt(104, 28_000, b"")); // marks 101..103
        assert_eq!(f.stats().missing, 3);

        // A retransmit filling a hole re-runs neither detection nor last_found.
        f.feed(ts(40_000), 0, rtx(102, 14_000, b""));
        assert_eq!(f.stats().missing, 3);
        assert_eq!(f.receiver.last_found, 104);

        // An out-of-order original fills its hole without moving last_found.
        f.feed(ts(41_000), 0, mk_pkt(101, 7_000, b""));
        let st = f.stats();
        assert_eq!(
            (st.missing, st.reordered, f.receiver.last_found),
            (3, 1, 104)
        );
    }

    #[test]
    fn nack_pass_batch_and_retry_timing() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(17_000), 0, mk_pkt(101, 7_000, b""));
        f.feed(ts(45_000), 0, mk_pkt(105, 35_000, b"")); // missing 102..104
        drain_outputs(&mut f);

        // Every entry's first nack is scheduled at now + reorder_buffer =
        // 45000 + 15000 = 60000. The 5 ms cadence timer fires at 50000 and 55000
        // with nothing yet due, re-arming each time.
        f.handle_timer(ts(50_000), TimerId::Nack);
        let outs = drain_outputs(&mut f);
        assert!(
            !outs
                .iter()
                .any(|o| matches!(o, Output::SendFeedback { .. }))
        );
        assert_eq!(
            outs,
            vec![Output::SetTimer {
                id: TimerId::Nack,
                deadline: ts(55_000)
            }]
        );
        f.handle_timer(ts(55_000), TimerId::Nack);
        let outs = drain_outputs(&mut f);
        assert!(
            !outs
                .iter()
                .any(|o| matches!(o, Output::SendFeedback { .. }))
        );

        // 60000: every entry's first nack is due -> one grouped Nack, each
        // re-scheduled at now + 1.1*clamp(rtt) = 60000 + 5500.
        f.handle_timer(ts(60_000), TimerId::Nack);
        let outs = drain_outputs(&mut f);
        let nacks: Vec<&Output> = outs
            .iter()
            .filter(|o| matches!(o, Output::SendFeedback { .. }))
            .collect();
        assert_eq!(nacks.len(), 1);
        let Output::SendFeedback {
            fb: Feedback::Nack { ssrc, missing },
            ..
        } = nacks[0]
        else {
            panic!("want a Nack feedback, got {:?}", nacks[0]);
        };
        assert_eq!(missing, &vec![102, 103, 104]);
        assert_eq!(*ssrc, TEST_SSRC);
        // Re-armed on the 5 ms cadence.
        assert_eq!(
            *outs.last().unwrap(),
            Output::SetTimer {
                id: TimerId::Nack,
                deadline: ts(65_000)
            }
        );
        for e in &f.receiver.missing {
            // next_nack = now + (u64)(rtt*1.1) = 60000 + 5500.
            assert_eq!((e.next_nack, e.nack_count), (ts(65_500), 1));
        }
        assert_eq!(f.stats().nacks_sent, 3);

        // 65000: nothing due (65500 > 65000) -> no feedback, just the re-arm.
        f.handle_timer(ts(65_000), TimerId::Nack);
        let outs = drain_outputs(&mut f);
        assert!(
            !outs
                .iter()
                .any(|o| matches!(o, Output::SendFeedback { .. }))
        );
        assert_eq!(
            outs,
            vec![Output::SetTimer {
                id: TimerId::Nack,
                deadline: ts(70_000)
            }]
        );

        // 70000: due again (65500 <= 70000).
        f.handle_timer(ts(70_000), TimerId::Nack);
        let outs = drain_outputs(&mut f);
        assert_eq!(
            outs.iter()
                .filter(|o| matches!(o, Output::SendFeedback { .. }))
                .count(),
            1
        );
        assert_eq!(f.stats().nacks_sent, 6);
    }

    #[test]
    fn nack_abandon_max_retries() {
        let mut cfg = Config::librist_defaults();
        cfg.max_retries = 2;
        let mut f = Flow::new(Role::Receiver, cfg);
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(24_000), 0, mk_pkt(102, 14_000, b"")); // missing 101
        drain_outputs(&mut f);

        // First nack is due at 24000 + reorder_buffer(15000) = 39000.
        f.process_nacks(ts(40_000)); // nack #1 (due at 39000)
        f.process_nacks(ts(50_000)); // nack #2 (next_nack was 40000+5500)
        assert_eq!(f.stats().nacks_sent, 2);
        // Third pass: nack_count(2) >= max_retries(2) -> abandon.
        f.process_nacks(ts(60_000));
        let st = f.stats();
        assert_eq!(
            (st.abandoned, st.nacks_sent, f.receiver.missing.len()),
            (1, 2, 0)
        );
    }

    #[test]
    fn nack_abandon_age_exact() {
        let mut cfg = Config::librist_defaults();
        cfg.max_retries = 1 << 30; // never trip the retry limit
        let mut f = Flow::new(Role::Receiver, cfg);
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(24_000), 0, mk_pkt(102, 14_000, b"")); // missing 101, insertion 14666
        drain_outputs(&mut f);

        assert_eq!(
            f.receiver.missing.front().unwrap().insertion_time,
            ts(14_666)
        );
        // Abandon strictly after insertion + recoveryBuffer*1.1 (`>` comparison).
        let deadline = ts(14_666 + 1_100_000);
        f.process_nacks(deadline); // age == threshold: not abandoned (sends a nack)
        assert_eq!(f.stats().abandoned, 0);
        f.process_nacks(ts(deadline.as_micros() + 1)); // age > threshold: abandoned
        let st = f.stats();
        assert_eq!((st.abandoned, f.receiver.missing.len()), (1, 0));
    }

    #[test]
    fn nack_recovered_removal() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(24_000), 0, mk_pkt(102, 14_000, b"")); // missing 101
        drain_outputs(&mut f);

        // Recovered before any NACK went out: removed silently.
        f.feed(ts(25_000), 0, mk_pkt(101, 7_000, b""));
        f.process_nacks(ts(26_000));
        let st = f.stats();
        assert_eq!(
            (f.receiver.missing.len(), st.recovered, st.nacks_sent),
            (0, 0, 0)
        );

        // A hole NACKed once, then recovered: counts Recovered.
        f.feed(ts(45_000), 0, mk_pkt(104, 35_000, b"")); // missing 103
        f.process_nacks(ts(60_000)); // nack #1
        f.feed(ts(61_000), 0, rtx(103, 28_000, b""));
        f.process_nacks(ts(62_000));
        let st = f.stats();
        assert_eq!((st.recovered, f.receiver.missing.len()), (1, 0));
    }

    #[test]
    fn too_late_drop_on_feed() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b""));
        f.feed(ts(2_010_000), 0, mk_pkt(200, 2_000_000, b""));
        drain_outputs(&mut f);
        let base = f.stats();

        // packet_time 510000 < last_packet_time, seq != successor, and
        // now > packet_time + 1.1*recoveryBuffer (= 1610000) -> shed.
        f.feed(ts(2_011_000), 0, mk_pkt(150, 500_000, b""));
        let st = f.stats();
        assert_eq!(st.too_late, base.too_late + 1);
        assert_eq!(st.received, base.received);

        // Same shape but within the window: accepted as a reordered packet.
        f.feed(ts(2_011_500), 0, mk_pkt(151, 1_500_000, b""));
        let st = f.stats();
        assert_eq!(st.received, base.received + 1);
        assert_eq!(st.reordered, base.reordered + 1);
    }

    #[test]
    fn delivery_in_order_time_driven() {
        let mut f = recv();
        for i in 0..3u32 {
            f.feed(
                ts(10_000 + 7_000 * u64::from(i)),
                0,
                mk_pkt(100 + i, 7_000 * u64::from(i), b"x"),
            );
        }
        drain_outputs(&mut f);

        // Before the first output_time nothing may be delivered.
        f.tick(ts(1_009_999));
        assert!(drain_events(&mut f).is_empty());

        // At exactly output_time the packet is delivered.
        f.handle_timer(ts(1_010_000), TimerId::Playout);
        let evs = drain_events(&mut f);
        assert_eq!(delivered_seqs(&evs), vec![100]);
        let Event::Deliver { discontinuity, .. } = &evs[0];
        assert!(!discontinuity);
        // The next deadline is re-armed at packet 101's output_time.
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SetTimer {
                id: TimerId::Playout,
                deadline: ts(1_017_000)
            }]
        );

        // A late tick delivers everything due, in order.
        f.tick(ts(1_030_000));
        assert_eq!(delivered_seqs(&drain_events(&mut f)), vec![101, 102]);
        let st = f.stats();
        assert_eq!((st.delivered, st.lost, st.discontinuities), (3, 0, 0));
        // Ring drained: the playout timer is released.
        let outs = drain_outputs(&mut f);
        assert_eq!(
            *outs.last().unwrap(),
            Output::ClearTimer {
                id: TimerId::Playout
            }
        );
    }

    #[test]
    fn delivery_skips_abandoned_with_discontinuity() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b"a"));
        f.feed(ts(24_000), 0, mk_pkt(102, 14_000, b"c")); // 101 never arrives
        drain_outputs(&mut f);

        // 100 due at 1010000; 102 due at 1024000; the hole holds delivery.
        f.handle_timer(ts(1_010_000), TimerId::Playout);
        assert_eq!(delivered_seqs(&drain_events(&mut f)), vec![100]);
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SetTimer {
                id: TimerId::Playout,
                deadline: ts(1_024_000)
            }]
        );

        // Once 102 is due, 101 is abandoned and delivery advances with a flag.
        f.handle_timer(ts(1_024_000), TimerId::Playout);
        let evs = drain_events(&mut f);
        assert_eq!(delivered_seqs(&evs), vec![102]);
        let Event::Deliver { discontinuity, .. } = &evs[0];
        assert!(
            discontinuity,
            "delivery after a skip must flag a discontinuity"
        );
        let st = f.stats();
        assert_eq!((st.lost, st.discontinuities, st.delivered), (1, 1, 2));
    }

    #[test]
    fn late_retransmit_behind_cursor_shed() {
        let mut f = recv();
        f.feed(ts(10_000), 0, mk_pkt(100, 0, b"a"));
        f.tick(ts(1_010_000));
        assert_eq!(f.stats().delivered, 1);
        drain_events(&mut f);
        drain_outputs(&mut f);

        // A copy behind the playout cursor can never be delivered: shed as too
        // late, not re-buffered, not counted a duplicate.
        f.feed(ts(1_011_000), 0, rtx(100, 0, b"a"));
        let st = f.stats();
        assert_eq!((st.too_late, st.received, st.duplicates), (1, 1, 0));
    }

    #[test]
    fn rtt_echo_request_answered_and_response_observed() {
        let mut f = recv();
        f.feed(ts(10_000), 2, mk_pkt(100, 0, b""));
        drain_outputs(&mut f);

        // Inbound request: answered verbatim, zero delay, on the most recent
        // path, echoing the requester's SSRC.
        f.feed_feedback(
            ts(20_000),
            Feedback::RttEchoRequest {
                ssrc: 0xABCD_0001,
                timestamp: 0xDEAD_BEEF,
            },
        );
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SendFeedback {
                path: 2,
                fb: Feedback::RttEchoResponse {
                    ssrc: 0xABCD_0001,
                    timestamp: 0xDEAD_BEEF,
                    processing_delay: 0
                },
            }]
        );

        // Inbound response: sample = (now - sent) - delay folded into the EWMA:
        // 40000 - 40000/8 + 8000 = 43000 -> smoothed 5375. The SSRC is ignored
        // by the RTT calculation.
        f.feed_feedback(
            ts(20_000),
            Feedback::RttEchoResponse {
                ssrc: 0,
                timestamp: src_ntp(10_000),
                processing_delay: 2_000,
            },
        );
        assert_eq!(f.est.smoothed().as_micros(), 5_375);
    }

    #[test]
    fn rtt_echo_timer_cadence() {
        let mut f = recv();
        f.feed(ts(10_000), 1, mk_pkt(100, 0, b""));
        drain_outputs(&mut f);

        f.handle_timer(ts(110_000), TimerId::RttEcho); // RIST_PING_INTERVAL = 100 ms
        assert_eq!(
            drain_outputs(&mut f),
            vec![
                Output::SendFeedback {
                    path: 1,
                    // Originated: SSRC left 0 for the codec to fill.
                    fb: Feedback::RttEchoRequest {
                        ssrc: 0,
                        timestamp: src_ntp(110_000)
                    },
                },
                Output::SetTimer {
                    id: TimerId::RttEcho,
                    deadline: ts(210_000)
                },
            ]
        );
    }

    #[test]
    fn receiver_ignores_sender_only_entry_points() {
        let mut f = recv();
        f.push_app(ts(1_000), bytes::Bytes::from_static(b"payload"));
        assert!(
            drain_outputs(&mut f).is_empty(),
            "receiver PushApp emitted output"
        );
        f.feed_feedback(
            ts(3_000),
            Feedback::Nack {
                ssrc: 1,
                missing: vec![1],
            },
        );
        assert!(drain_outputs(&mut f).is_empty());
        assert_eq!(f.stats().ignored_feedback, 1);
    }

    #[test]
    fn feedback_without_handler_counted() {
        let mut f = recv();
        f.feed_feedback(
            ts(1_000),
            Feedback::SenderReport {
                ntp: 1,
                rtp_time: 2,
            },
        );
        f.feed_feedback(ts(2_000), Feedback::Keepalive);
        f.feed_feedback(
            ts(3_000),
            Feedback::Nack {
                ssrc: 1,
                missing: vec![],
            },
        );
        assert_eq!(f.stats().ignored_feedback, 3);
        assert!(drain_outputs(&mut f).is_empty());
    }

    #[test]
    fn source_clock_wrap_reanchors_offset() {
        // Anchor near the top of the 32-bit source-counter range (47000 s of media),
        // local clock == source so the offset is 0.
        let mut f = recv();
        let t0: u64 = 47_000_000_000;
        f.feed(ts(t0), 0, mk_pkt(100, t0, b"x"));
        drain_outputs(&mut f);

        // A later non-successor packet whose source time fell back to 100 s — a
        // ~46900 s backward jump, well over the ~23864 s half-span — after more than
        // 3 * recovery_buffer (3 s) of dwell. The receiver re-anchors (offset += one
        // wrap period) and accepts it rather than shedding it as too-late.
        f.feed(ts(t0 + 4_000_000), 0, mk_pkt(105, 100_000_000, b"x"));
        assert_eq!(f.stats().clock_resync, 1, "wrap must re-anchor once");
        assert_eq!(f.stats().received, 2, "wrapped packet must be accepted");
        assert_eq!(f.stats().too_late, 0, "wrapped packet must not be shed");
    }

    #[test]
    fn source_clock_wrap_respects_dwell_guard() {
        // The same backward jump within the dwell window (< 3 * recovery_buffer) is
        // NOT treated as a wrap (it could be a single anomalous timestamp); the
        // far-past packet is shed instead.
        let mut f = recv();
        let t0: u64 = 47_000_000_000;
        f.feed(ts(t0), 0, mk_pkt(100, t0, b"x"));
        drain_outputs(&mut f);
        f.feed(ts(t0 + 1_000_000), 0, mk_pkt(105, 100_000_000, b"x"));
        assert_eq!(
            f.stats().clock_resync,
            0,
            "dwell guard must suppress re-anchor"
        );
        assert_eq!(f.stats().too_late, 1, "far-past packet shed without a wrap");
    }

    #[test]
    fn arrival_timing_accepts_stale_source_timestamps() {
        // In ARRIVAL timing the source-time too-late test is skipped: a non-successor
        // packet bearing a very old source timestamp (which SOURCE timing would shed)
        // is accepted, paced from its arrival instant instead.
        let mut cfg = Config::librist_defaults();
        cfg.timing_mode = TimingMode::Arrival;
        let mut f = Flow::new(Role::Receiver, cfg);
        f.feed(ts(10_000_000), 0, mk_pkt(100, 10_000_000, b"x"));
        f.feed(ts(10_005_000), 0, mk_pkt(105, 1_000_000, b"x")); // source 9 s in the past
        assert_eq!(f.stats().received, 2, "arrival timing must accept it");
        assert_eq!(
            f.stats().too_late,
            0,
            "arrival timing must not shed by source time"
        );
    }

    #[test]
    fn rtc_timing_disables_source_clock_wrap_reanchor() {
        // RTC timing carries a 64-bit NTP wall clock that never wraps on the 32-bit RTP
        // boundary, so the source-clock wrap re-anchor is disabled. The same backward
        // source jump that SOURCE timing re-anchors (see source_clock_wrap_reanchors_offset)
        // produces no resync under RTC; the far-past packet is shed as too-late instead
        // (RTC keeps the source-time too-late test, unlike ARRIVAL).
        let mut cfg = Config::librist_defaults();
        cfg.timing_mode = TimingMode::Rtc;
        let mut f = Flow::new(Role::Receiver, cfg);
        let t0: u64 = 47_000_000_000;
        f.feed(ts(t0), 0, mk_pkt(100, t0, b"x"));
        drain_outputs(&mut f);
        f.feed(ts(t0 + 4_000_000), 0, mk_pkt(105, 100_000_000, b"x"));
        assert_eq!(
            f.stats().clock_resync,
            0,
            "RTC must not re-anchor on a backward source jump"
        );
        assert_eq!(
            f.stats().too_late,
            1,
            "the far-past packet is shed (no wrap re-anchor under RTC)"
        );
    }

    #[test]
    fn return_bandwidth_token_bucket_throttles_nacks() {
        // With a return-bandwidth cap, a NACK pass spends one token per sequence; when
        // the bucket runs dry the remaining due entries are LEFT due (not abandoned)
        // and serviced on a later pass once tokens refill.
        let mut cfg = Config::librist_defaults();
        cfg.return_maxbitrate = 100;
        let mut f = Flow::new(Role::Receiver, cfg);
        f.feed(ts(1_000_000), 0, mk_pkt(0, 0, b"x"));
        f.feed(ts(1_005_000), 0, mk_pkt(6, 5_000, b"x")); // gap → missing 1..=5
        let missing = f.receiver.missing.len();
        assert!(
            missing >= 3,
            "expected several missing entries, got {missing}"
        );
        drain_outputs(&mut f);

        // Only two tokens available, and pin tokens_time to the pass instant so the
        // refill adds nothing this pass.
        let pass = ts(1_030_000); // past every entry's first next_nack (~+15 ms)
        f.receiver.nack_tokens = 2.0;
        f.receiver.nack_tokens_time = pass;
        f.process_nacks(pass);
        assert_eq!(f.stats().nacks_sent, 2, "throttled to the available tokens");
        assert_eq!(
            f.receiver.missing.len(),
            missing,
            "throttled entries are kept, not abandoned"
        );

        // Refill and run again: the still-due entries (un-NACKed last pass) now go.
        f.receiver.nack_tokens = 100.0;
        f.receiver.nack_tokens_time = pass;
        f.process_nacks(pass);
        assert_eq!(
            f.stats().nacks_sent as usize,
            missing,
            "the rest are serviced once tokens refill"
        );
    }
}
