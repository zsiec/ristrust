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
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::collections::VecDeque;

use bytes::Bytes;

use super::{Event, Flow, NACK_CADENCE, Output, RTT_ECHO_INTERVAL, TimerId};
use crate::clock::{Micros, Ntp64, Timestamp};
use crate::seq::{self, Seq32};
use crate::wire::{Feedback, MediaPacket};

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
        }
    }

    /// A receiver state with a minimal ring, for a sender-role flow (it never
    /// receives media, so a full ring would only waste memory).
    pub(super) fn empty() -> ReceiverState {
        ReceiverState::new(1)
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

impl Flow {
    /// Maps a packet's NTP-64 source timestamp into the local clock domain using
    /// the offset locked at the first packet.
    fn map_source_time(&self, source_time: u64) -> Timestamp {
        Ntp64::from_bits(source_time).to_timestamp() + self.receiver.offset
    }

    /// The receiver-role body of [`Flow::feed`]: first-packet init, packet-time
    /// mapping, too-late shedding, `(seq, source_time)` dedup, insert, missing
    /// detection, then timer scheduling — following `receiver_enqueue`.
    pub(crate) fn recv_feed(&mut self, now: Timestamp, path: u8, pkt: MediaPacket) {
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
        let packet_time = self.map_source_time(source_time);

        // Track the newest source timestamp and its packet time, mirroring
        // calculate_packet_time. The update runs before the out-of-order test
        // (as in libRIST) so the clock-advancing packet never compares to itself.
        if source_time > self.receiver.max_source_time {
            self.receiver.max_source_time = source_time;
            self.receiver.last_packet_time = packet_time;
        }

        // Out-of-order / too-late shedding: only packets older than the newest
        // packet time and not the immediate successor of last_found qualify.
        let mut out_of_order = false;
        if packet_time < self.receiver.last_packet_time
            && seqn != self.receiver.last_found.wrapping_add(1)
        {
            if now > packet_time + self.recovery_buffer_110 {
                self.stats.too_late += 1;
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
        {
            let s = &mut self.receiver.ring[idx];
            s.state = SlotState::Filled;
            s.seq = seqn;
            s.source_time = source_time;
            s.payload = pkt.payload;
            s.arrival = now;
            s.packet_time = packet_time;
            s.output_time = output_time;
            s.path_seen = path_bit(path);
        }
        self.stats.received += 1;
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

    /// First-packet initialization (libRIST `receiver_enqueue` empty-queue
    /// branch): lock the clock offset, seed cursors, insert the packet, and start
    /// the playout and RTT-echo schedules. The first packet never triggers
    /// missing detection.
    fn start(&mut self, now: Timestamp, path: u8, pkt: MediaPacket) {
        let src = Ntp64::from_bits(pkt.source_time).to_timestamp();
        let output_time = now + self.recovery_buffer;
        {
            let r = &mut self.receiver;
            r.offset = now - src;
            r.started = true;
            r.ssrc = pkt.ssrc;
            r.last_found = pkt.seq;
            r.max_source_time = pkt.source_time;
            r.last_packet_time = now; // == src + offset by construction
            r.highest = pkt.seq;
            r.deliver_next = pkt.seq;
            r.last_path = path;

            let idx = (pkt.seq & r.mask) as usize;
            let s = &mut r.ring[idx];
            s.state = SlotState::Filled;
            s.seq = pkt.seq;
            s.source_time = pkt.source_time;
            s.payload = pkt.payload;
            s.arrival = now;
            s.packet_time = now;
            s.output_time = output_time;
            s.path_seen = path_bit(path);
        }
        self.stats.received += 1;

        self.arm_playout(output_time);
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::RttEcho,
            deadline: now + RTT_ECHO_INTERVAL,
        });
    }

    /// Queues missing entries for every sequence in `(last_found, current)`,
    /// following `receiver_mark_missing`: the per-entry nack time is interpolated
    /// linearly between the two known packet times (assuming CBR).
    fn mark_missing(&mut self, now: Timestamp, path: u8, current: u32, packet_time_now: Timestamp) {
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
            if now >= e.next_nack {
                e.next_nack = now + retry;
                e.nack_count += 1;
                batch.push(e.seq);
                self.stats.nacks_sent += 1;
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
        let (seqn, payload) = {
            let s = &mut self.receiver.ring[idx];
            s.state = SlotState::Empty;
            (s.seq, std::mem::take(&mut s.payload))
        };
        let discontinuity = self.receiver.pending_discontinuity;
        self.receiver.pending_discontinuity = false;
        self.events.push_back(Event::Deliver {
            seq: seqn,
            payload,
            discontinuity,
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
    use crate::clock::Timestamp;
    use crate::flow::testutil::{
        TEST_SSRC, delivered_seqs, drain_events, drain_outputs, mk_pkt, src_ntp,
    };
    use crate::flow::{Config, Event, Flow, Output, Role, TimerId};
    use crate::wire::Feedback;

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
    fn first_packet_retransmit_ignored() {
        let mut f = recv();
        f.feed(ts(10_000), 0, rtx(100, 0, b"a"));
        assert!(!f.receiver.started, "flow must not start on a retransmit");
        assert_eq!(f.stats(), crate::flow::Stats::default());
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
}
