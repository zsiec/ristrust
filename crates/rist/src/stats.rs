//! The public per-session statistics snapshot and its shared cell.
//!
//! [`Stats`] is a curated, public subset of the flow core's counters. The driver
//! task owns the flow, so it publishes a snapshot into a shared [`StatsCell`] after
//! each event; the public [`Sender`](crate::Sender) / [`Receiver`](crate::Receiver)
//! handle reads the latest snapshot through its `stats()` method.

use std::sync::{Arc, Mutex};

/// A snapshot of a [`Sender`](crate::Sender)'s or [`Receiver`](crate::Receiver)'s
/// counters, read via their `stats()` method. Sender-only and receiver-only fields
/// are zero on the other role.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    // --- Receiver ---
    /// Media packets accepted into the recovery buffer (first copies and accepted
    /// retransmissions).
    pub received: u64,
    /// Packets handed to the application via `recv`.
    pub delivered: u64,
    /// Sequence numbers given up on (never recovered before their playout deadline).
    pub lost: u64,
    /// Packets recovered by retransmission after a NACK.
    pub recovered: u64,
    /// Packets reconstructed by SMPTE ST 2022-1 FEC (no NACK round trip), distinct
    /// from [`recovered`](Stats::recovered) (ARQ). Always `0` until FEC lands.
    pub fec_recovered: u64,
    /// Dropped duplicate packets (ARQ re-sends and extra SMPTE 2022-7 path copies).
    pub duplicates: u64,
    /// Accepted packets that arrived out of order.
    pub reordered: u64,
    /// Sequence numbers requested in NACK feedback.
    pub nacks_sent: u64,
    /// Missing packets given up on after exhausting retries or ageing out.
    pub abandoned: u64,
    /// Gaps in the delivered stream (one per contiguous run of unrecovered
    /// sequence numbers) — the receiver's view of unrecoverable loss.
    pub discontinuities: u64,

    // --- Sender ---
    /// First-transmission media packets.
    pub sent: u64,
    /// Retransmitted media packets.
    pub retransmitted: u64,
    /// NACKed sequences no longer in the history (aged out of the buffer).
    pub retransmit_skipped: u64,
    /// NACKed sequences withheld because the previous retransmission was less than
    /// one RTT ago.
    pub retransmit_suppressed: u64,
}

impl From<rist_core::flow::Stats> for Stats {
    /// Maps the flow core's counters to the curated public snapshot.
    fn from(f: rist_core::flow::Stats) -> Stats {
        Stats {
            received: f.received,
            delivered: f.delivered,
            lost: f.lost,
            recovered: f.recovered,
            // SMPTE ST 2022-1 FEC is not implemented yet (PARITY WP18); the core has
            // no FEC-recovered counter to map, so this stays 0 until it lands.
            fec_recovered: 0,
            duplicates: f.duplicates,
            reordered: f.reordered,
            nacks_sent: f.nacks_sent,
            abandoned: f.abandoned,
            discontinuities: f.discontinuities,
            sent: f.sent,
            retransmitted: f.retransmitted,
            retransmit_skipped: f.retransmit_skipped,
            retransmit_suppressed: f.retransmit_suppressed,
        }
    }
}

/// A shared cell holding a session's latest [`Stats`] snapshot: the driver task
/// publishes into it after each event; the public handle reads it. Cloned between a
/// driver and its `Sender`/`Receiver` handle.
#[derive(Debug, Clone, Default)]
pub(crate) struct StatsCell(Arc<Mutex<Stats>>);

impl StatsCell {
    /// Publishes the flow core's current counters as the latest snapshot.
    pub(crate) fn publish(&self, core: rist_core::flow::Stats) {
        *self.0.lock().expect("stats mutex poisoned") = core.into();
    }

    /// Reads the latest published snapshot (all-zero until the first publish).
    pub(crate) fn snapshot(&self) -> Stats {
        *self.0.lock().expect("stats mutex poisoned")
    }
}
