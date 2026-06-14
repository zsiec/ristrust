//! The sender half of the flow core (scaffolding).
//!
//! Phase 1 (WP1) fills these in: sequence assignment and first-transmission
//! emission (even base SSRC; the codec toggles the LSB on retransmits); a
//! retransmit history ring; NACK servicing through the per-packet RTT gate (the
//! raw last sample clamped, not the EWMA — see [`rtt`](crate::rtt)); retry
//! exhaustion accounting; and RTT echo origination.

use super::{Flow, TimerId};
use crate::clock::Timestamp;
use crate::wire::Feedback;
use bytes::Bytes;

impl Flow {
    /// Submits one application payload for first transmission. Scaffold: drops it.
    pub(crate) fn send_push_app(&mut self, _now: Timestamp, _payload: Bytes) {
        // TODO(WP1): assign next seq, build MediaPacket, emit Output::SendMedia,
        // record in the retransmit history.
    }

    /// Handles inbound control destined for the sender half (NACK, RTT echo req).
    pub(crate) fn send_handle_feedback(&mut self, _now: Timestamp, _fb: Feedback) {
        // TODO(WP1): on Feedback::Nack, retransmit through the per-packet RTT
        // gate; on RttEchoRequest, emit a response.
    }

    /// Fires a sender-side declarative timer (RTT echo cadence).
    pub(crate) fn send_handle_timer(&mut self, _now: Timestamp, _id: TimerId) {
        // TODO(WP1): originate RTT echo requests on the ping interval.
    }
}
