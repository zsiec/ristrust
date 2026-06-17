//! The effect and event types the deterministic core emits, plus its `Stats`.
//!
//! The core never performs I/O. Instead it pushes [`Output`] effects (drained by
//! the host and performed on the wire) and [`Event`]s (drained by the host and
//! surfaced to the application). Timers are *declarative*: the core requests them
//! by [`TimerId`]; the host owns the wheel and calls
//! [`Flow::handle_timer`](crate::flow::Flow::handle_timer) when one fires.

use crate::clock::Timestamp;
use crate::wire::{Feedback, MediaPacket};

/// Identifies one declarative timer the core requests. Re-issuing `SetTimer` for
/// an armed id replaces its deadline. `Ord`/`Hash` so the host (and the test
/// timer wheel) can key a map by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerId {
    /// Wakes the receiver when the earliest buffered packet reaches its playout
    /// deadline so time-driven in-order delivery can proceed.
    Playout,
    /// Paces the receiver's NACK processing pass (libRIST bounds the receiver
    /// loop's jitter at `RIST_MAX_JITTER` = 5 ms).
    Nack,
    /// Paces a flow's RTT echo requests (libRIST `RIST_PING_INTERVAL` = 100 ms).
    /// Both roles originate echo requests; each runs on its own host wheel, so the
    /// single id never collides.
    RttEcho,
}

/// One side effect the core asks the host to perform, drained in FIFO order via
/// [`Flow::poll_output`](crate::flow::Flow::poll_output).
///
/// Exhaustive (not `#[non_exhaustive]`) so hosts `match` over the complete set and
/// adding a variant is a compile error everywhere it must be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Transmit one media packet on the given path. Emitted by the sender half
    /// (first transmissions and retransmissions); the receiver half never emits
    /// it.
    SendMedia {
        /// The network path index the packet must leave on.
        path: u8,
        /// The normalized media packet to encode and send.
        pkt: MediaPacket,
    },
    /// Transmit one control message on the given path. The host's profile strategy
    /// chooses the wire encoding; the core only speaks normalized [`Feedback`].
    SendFeedback {
        /// The network path index the feedback must leave on.
        path: u8,
        /// The normalized feedback to encode and send.
        fb: Feedback,
    },
    /// Arm (or re-arm) `id` to fire once `deadline` passes.
    SetTimer {
        /// The timer being armed.
        id: TimerId,
        /// The absolute instant the timer must fire at.
        deadline: Timestamp,
    },
    /// Cancel `id` if it is armed (a no-op otherwise).
    ClearTimer {
        /// The timer being cancelled.
        id: TimerId,
    },
}

/// One application-visible occurrence produced by the core, drained in FIFO order
/// via [`Flow::poll_event`](crate::flow::Flow::poll_event).
///
/// Exhaustive for the same reason as [`Output`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Hands one in-order media payload to the application. The core retains no
    /// copy; the consumer owns the bytes after delivery.
    Deliver {
        /// The 32-bit (widened) sequence number of the delivered packet.
        seq: u32,
        /// The packet's source timestamp (the sender's NTP-64 media clock, as carried
        /// on the wire). Two packets that the sender emitted from one application
        /// payload — e.g. a split/merge bonding pair — share a source time, so the host
        /// merge layer keys the recombination on it (a mis-paired neighbour with a
        /// different source time stays a harmless orphan rather than corrupting the
        /// stream).
        source_time: u64,
        /// The delivered media payload.
        payload: bytes::Bytes,
        /// Whether one or more sequence numbers immediately before this packet
        /// were abandoned (never recovered before their playout deadline), so the
        /// output stream has a gap here.
        discontinuity: bool,
        /// The Advanced-profile fragment role carried by the delivered packet
        /// ([`crate::wire::FragRole::Standalone`] for unfragmented media and on the
        /// Simple/Main profiles). The host reassembler folds non-standalone roles
        /// into whole application payloads.
        frag: crate::wire::FragRole,
    },
}

/// A snapshot of one flow's counters. Counter semantics mirror libRIST's receiver
/// and sender flow stats where an analog exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    // --- Gauges (filled by [`Flow::stats`](crate::flow::Flow::stats) at snapshot
    // time from live estimator/bitrate state; they stay 0 in the raw incremental
    // struct, unlike the counters below which the flow increments in place). ---
    /// The smoothed round-trip time in microseconds (the RTT EWMA), 0 before the
    /// first sample. Mirrors libRIST's per-flow `rtt` gauge.
    pub smoothed_rtt_us: i64,
    /// The sender's smoothed first-transmission bit rate (bits/sec, 1 s window) —
    /// libRIST's `bandwidth`. 0 on a receiver flow.
    pub data_bitrate_bps: i64,
    /// The sender's smoothed retransmission bit rate (bits/sec, 1 s window) —
    /// libRIST's `retry_bandwidth`. 0 on a receiver flow.
    pub retry_bitrate_bps: i64,

    // --- Receiver half ---
    /// Media packets accepted into the receiver ring (first copies and accepted
    /// retransmissions; duplicates and too-late drops excluded).
    pub received: u64,
    /// Payload bytes accepted into the receiver ring (the byte analog of
    /// [`received`](Self::received)) — libRIST's `received_bytes`.
    pub received_bytes: u64,
    /// Packets dropped by the `(seq, source_time)` duplicate test — ARQ
    /// duplicates and extra SMPTE 2022-7 path copies alike.
    pub duplicates: u64,
    /// Accepted packets that arrived out of order.
    pub reordered: u64,
    /// Ring slots overwritten because they held a stale entry (same slot,
    /// different `(seq, source_time)`).
    pub overwritten: u64,
    /// Packets dropped because they could no longer be delivered (older than the
    /// recovery window, or behind the in-order playout cursor).
    pub too_late: u64,
    /// The retransmitted subset of [`too_late`](Self::too_late): too-late drops
    /// whose packet carried the retransmit flag. The arrival rate of late-but-fresh
    /// first transmissions is then `too_late - too_late_retransmit`, the quantity
    /// TR-06-4 source-adaptation reports as the LQM "Late" field.
    pub too_late_retransmit: u64,
    /// Inbound media packets flagged as retransmissions that reached a started flow,
    /// counted before any too-late / dedup / cursor test sheds them — so this tallies
    /// all retransmits actually received (including late and duplicate ones),
    /// distinct from [`recovered`](Self::recovered) (gaps an ARQ resend actually
    /// filled).
    pub retransmitted_received: u64,
    /// Source-clock re-anchors: a fresh non-retransmit packet whose source time fell
    /// backward by more than half the 32-bit timestamp space — a true wrap of the
    /// 32-bit RTP-derived counter (~13 h at 90 kHz) — bumped the clock offset by one
    /// wrap period so playout stays continuous (libRIST
    /// `receiver_calculate_packet_time`). Source-timing mode only.
    pub clock_resync: u64,
    /// Missing entries created by gap detection (each lost sequence once).
    pub missing: u64,
    /// Individual sequence numbers emitted in NACK feedback (retries included).
    pub nacks_sent: u64,
    /// Missing entries removed because the packet arrived after at least one NACK.
    pub recovered: u64,
    /// Missing entries given up on (after max retries or ageing past the window).
    pub abandoned: u64,
    /// Packets handed to the application via [`Event::Deliver`].
    pub delivered: u64,
    /// Sequence numbers skipped at playout because they never arrived in time.
    pub lost: u64,
    /// Contiguous runs of skipped sequence numbers in the delivered stream.
    pub discontinuities: u64,
    /// Inbound feedback the flow had no handler for in its current role/stage
    /// (counted instead of panicking so additive wire variants can never crash
    /// the core).
    pub ignored_feedback: u64,
    /// Flow-id changes: a fresh (non-retransmit) packet whose flow id (SSRC with
    /// the retransmit LSB masked) differed from the one the flow anchored on, so
    /// the receiver discarded its buffered state and re-anchored on the new flow
    /// rather than merging two distinct flows into one ring (libRIST's "Detected
    /// flow id change ... resetting state").
    pub flow_resets: u64,

    // --- Sender half ---
    /// First-transmission media packets emitted by `push_app`.
    pub sent: u64,
    /// Payload bytes in first-transmission media packets — libRIST's `sent_bytes`.
    pub sent_bytes: u64,
    /// Retransmission media packets emitted in response to NACK feedback.
    pub retransmitted: u64,
    /// Payload bytes in retransmission media packets — libRIST's `retransmitted_bytes`.
    pub retransmitted_bytes: u64,
    /// NACKed sequence numbers no longer in the sender history (aged out or never
    /// sent) and therefore not resendable.
    pub retransmit_skipped: u64,
    /// NACKed sequence numbers withheld by the per-packet retransmit gate because
    /// the previous retransmit was less than one clamped RTT ago.
    pub retransmit_suppressed: u64,
    /// NACKed sequence numbers refused because the packet had already been
    /// retransmitted the maximum number of times.
    pub retransmit_exhausted: u64,
    /// NACKed sequence numbers refused because emitting the retransmit would have
    /// exceeded `recovery_maxbitrate` under the active congestion-control mode
    /// (libRIST `bandwidth_skip`); the entry stays resendable and is re-NACKed.
    pub bandwidth_skipped: u64,
}
