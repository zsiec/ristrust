//! The receiver half of the flow core (scaffolding).
//!
//! Phase 1 (WP1) fills these in: a power-of-two ring indexed by `seq & mask`;
//! de-duplication by `(seq, source_time)` — the one test that implements the
//! SMPTE 2022-7 multipath merge; successor-driven missing-detection pinned to
//! [`seq::MAX_GAP_16`](crate::seq::MAX_GAP_16) for widened flows; NACK cadence;
//! and time-driven in-order playout after the recovery buffer.

use super::{Flow, TimerId};
use crate::clock::Timestamp;
use crate::wire::{Feedback, MediaPacket};

impl Flow {
    /// Accepts one inbound media packet on `path`. Scaffold: drops it.
    pub(crate) fn recv_feed(&mut self, _now: Timestamp, _path: u8, _pkt: MediaPacket) {
        // TODO(WP1): ring insert + (seq, source_time) dedup (the 2022-7 merge) +
        // missing-detection over (last_found, seq) + playout scheduling.
    }

    /// Handles inbound control destined for the receiver half (RTT echo, SR).
    pub(crate) fn recv_handle_feedback(&mut self, _now: Timestamp, _fb: Feedback) {
        // TODO(WP1): RTT echo request/response; SR-based playout offset.
    }

    /// Fires a receiver-side declarative timer (playout, NACK pacing, RTT echo).
    pub(crate) fn recv_handle_timer(&mut self, _now: Timestamp, _id: TimerId) {
        // TODO(WP1): deliver due packets; emit NACKs on the retry cadence.
    }
}
