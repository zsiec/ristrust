//! The public per-session statistics snapshot and its shared cell.
//!
//! [`Stats`] is a curated, public subset of the flow core's counters. The driver
//! task owns the flow, so it publishes a snapshot into a shared [`StatsCell`] after
//! each event; the public [`Sender`](crate::Sender) / [`Receiver`](crate::Receiver)
//! handle reads the latest snapshot through its `stats()` method.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    /// Maps the flow core's counters to the curated public snapshot. The host-tracked
    /// `fec_recovered` count is layered on when the snapshot is published (the flow
    /// core has no FEC counter — FEC recovery is a host concern).
    fn from(f: rist_core::flow::Stats) -> Stats {
        Stats {
            received: f.received,
            delivered: f.delivered,
            lost: f.lost,
            recovered: f.recovered,
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

/// The shared state behind a [`StatsCell`]: the latest counter snapshot plus the
/// two lightweight session-status fields the public handles expose
/// (`authenticated` / `ssrc`), kept as atomics so the driver can update them without
/// taking the stats mutex.
#[derive(Debug, Default)]
struct CellInner {
    stats: Mutex<Stats>,
    /// Whether the session is authenticated: `true` immediately for a session with no
    /// EAP-SRP (none required), or once the handshake completes.
    authenticated: AtomicBool,
    /// The media SSRC the receiver learned from the first packet (`0` until learned).
    ssrc: AtomicU32,
}

/// A shared cell holding a session's latest [`Stats`] snapshot plus its
/// authenticated / learned-SSRC status: the driver task publishes into it; the
/// public handle reads it. Cloned between a driver and its `Sender`/`Receiver`
/// handle.
#[derive(Debug, Clone, Default)]
pub(crate) struct StatsCell(Arc<CellInner>);

impl StatsCell {
    /// Publishes the flow core's current counters as the latest snapshot, layering on
    /// the host-tracked SMPTE ST 2022-1 FEC-recovered count (0 when FEC is off).
    pub(crate) fn publish(&self, core: rist_core::flow::Stats, fec_recovered: u64) {
        let mut snapshot: Stats = core.into();
        snapshot.fec_recovered = fec_recovered;
        *self.0.stats.lock().expect("stats mutex poisoned") = snapshot;
    }

    /// Reads the latest published snapshot (all-zero until the first publish).
    pub(crate) fn snapshot(&self) -> Stats {
        *self.0.stats.lock().expect("stats mutex poisoned")
    }

    /// Records whether the session is currently authenticated (driver-side).
    pub(crate) fn set_authenticated(&self, yes: bool) {
        self.0.authenticated.store(yes, Ordering::Relaxed);
    }

    /// Whether the session is authenticated (handle-side read).
    pub(crate) fn authenticated(&self) -> bool {
        self.0.authenticated.load(Ordering::Relaxed)
    }

    /// Records the media SSRC a receiver learned (driver-side).
    pub(crate) fn set_ssrc(&self, ssrc: u32) {
        self.0.ssrc.store(ssrc, Ordering::Relaxed);
    }

    /// The learned media SSRC, or `0` until a packet has been received (handle-side).
    pub(crate) fn ssrc(&self) -> u32 {
        self.0.ssrc.load(Ordering::Relaxed)
    }
}
