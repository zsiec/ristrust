//! The public per-session statistics snapshot and its shared cell.
//!
//! [`Stats`] is a curated, public subset of the flow core's counters. The driver
//! task owns the flow, so it publishes a snapshot into a shared [`StatsCell`] after
//! each event; the public [`Sender`](crate::Sender) / [`Receiver`](crate::Receiver)
//! handle reads the latest snapshot through its `stats()` method.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A snapshot of a [`Sender`](crate::Sender)'s or [`Receiver`](crate::Receiver)'s
/// counters and gauges, read via their `stats()` method. Sender-only and
/// receiver-only fields are zero on the other role.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct Stats {
    // --- Receiver ---
    /// Media packets accepted into the recovery buffer (first copies and accepted
    /// retransmissions).
    pub received: u64,
    /// Payload bytes accepted into the recovery buffer (the byte analog of
    /// [`received`](Stats::received)).
    pub received_bytes: u64,
    /// Packets handed to the application via `recv`.
    pub delivered: u64,
    /// Sequence numbers given up on (never recovered before their playout deadline).
    pub lost: u64,
    /// Packets recovered by retransmission after a NACK.
    pub recovered: u64,
    /// Packets reconstructed by SMPTE ST 2022-1 / 2022-5 FEC (no NACK round trip),
    /// distinct from [`recovered`](Stats::recovered) (ARQ).
    pub fec_recovered: u64,
    /// Dropped duplicate packets (ARQ re-sends and extra SMPTE 2022-7 path copies).
    pub duplicates: u64,
    /// Accepted packets that arrived out of order.
    pub reordered: u64,
    /// Packets dropped because they arrived too late to be delivered (older than the
    /// recovery window, or behind the playout cursor).
    pub too_late: u64,
    /// The retransmitted subset of [`too_late`](Stats::too_late) (a recovery that
    /// arrived after its deadline).
    pub too_late_retransmit: u64,
    /// Inbound packets flagged as retransmissions that reached the flow (before any
    /// dedup/too-late test), distinct from [`recovered`](Stats::recovered).
    pub retransmitted_received: u64,
    /// Source-clock re-anchors after a 32-bit RTP-timestamp wrap (libRIST
    /// `ClockResync`).
    pub clock_resync: u64,
    /// Missing entries created by gap detection (each lost sequence once).
    pub missing: u64,
    /// Sequence numbers requested in NACK feedback.
    pub nacks_sent: u64,
    /// Missing packets given up on after exhausting retries or ageing out.
    pub abandoned: u64,
    /// Ring slots overwritten because they held a stale entry.
    pub overwritten: u64,
    /// Flow-id changes that reset the receiver's buffered state.
    pub flow_resets: u64,
    /// Gaps in the delivered stream (one per contiguous run of unrecovered
    /// sequence numbers) — the receiver's view of unrecoverable loss.
    pub discontinuities: u64,

    // --- Sender ---
    /// First-transmission media packets.
    pub sent: u64,
    /// Payload bytes in first-transmission media packets.
    pub sent_bytes: u64,
    /// Retransmitted media packets.
    pub retransmitted: u64,
    /// Payload bytes in retransmitted media packets.
    pub retransmitted_bytes: u64,
    /// NACKed sequences no longer in the history (aged out of the buffer).
    pub retransmit_skipped: u64,
    /// NACKed sequences withheld because the previous retransmission was less than
    /// one RTT ago.
    pub retransmit_suppressed: u64,
    /// NACKed sequences refused because the packet was already retransmitted the
    /// maximum number of times.
    pub retransmit_exhausted: u64,
    /// NACKed sequences refused because the retransmit would have exceeded
    /// `recovery_maxbitrate` under the active congestion-control mode.
    pub bandwidth_skipped: u64,

    // --- Gauges ---
    /// Smoothed round-trip time (the RTT EWMA); zero before the first sample.
    pub rtt: Duration,
    /// The sender's smoothed first-transmission bit rate, bits/sec (libRIST
    /// `bandwidth`); zero on a receiver.
    pub bandwidth_bps: u64,
    /// The sender's smoothed retransmission bit rate, bits/sec (libRIST
    /// `retry_bandwidth`); zero on a receiver.
    pub retry_bandwidth_bps: u64,
    /// A derived receiver link-quality percentage in `[0, 100]`: the fraction of
    /// expected packets that arrived (including via recovery),
    /// `100 × received / (received + lost)`. `100.0` when no packets are expected
    /// (e.g. on a pure sender).
    pub quality: f64,
}

impl From<rist_core::flow::Stats> for Stats {
    /// Maps the flow core's counters and gauges to the curated public snapshot. The
    /// host-tracked `fec_recovered` count is layered on at publish time (the flow core
    /// has no FEC counter — FEC recovery is a host concern), and `quality` is derived.
    #[allow(clippy::cast_precision_loss)] // counts well within f64's exact range here
    fn from(f: rist_core::flow::Stats) -> Stats {
        let expected = f.received + f.lost;
        let quality = if expected == 0 {
            100.0
        } else {
            100.0 * f.received as f64 / expected as f64
        };
        Stats {
            received: f.received,
            received_bytes: f.received_bytes,
            delivered: f.delivered,
            lost: f.lost,
            recovered: f.recovered,
            fec_recovered: 0,
            duplicates: f.duplicates,
            reordered: f.reordered,
            too_late: f.too_late,
            too_late_retransmit: f.too_late_retransmit,
            retransmitted_received: f.retransmitted_received,
            clock_resync: f.clock_resync,
            missing: f.missing,
            nacks_sent: f.nacks_sent,
            abandoned: f.abandoned,
            overwritten: f.overwritten,
            flow_resets: f.flow_resets,
            discontinuities: f.discontinuities,
            sent: f.sent,
            sent_bytes: f.sent_bytes,
            retransmitted: f.retransmitted,
            retransmitted_bytes: f.retransmitted_bytes,
            retransmit_skipped: f.retransmit_skipped,
            retransmit_suppressed: f.retransmit_suppressed,
            retransmit_exhausted: f.retransmit_exhausted,
            bandwidth_skipped: f.bandwidth_skipped,
            rtt: Duration::from_micros(u64::try_from(f.smoothed_rtt_us).unwrap_or(0)),
            bandwidth_bps: u64::try_from(f.data_bitrate_bps).unwrap_or(0),
            retry_bandwidth_bps: u64::try_from(f.retry_bitrate_bps).unwrap_or(0),
            quality,
        }
    }
}

impl Stats {
    /// Serializes the snapshot to a flat JSON object (libRIST's `stats_json` analog),
    /// every counter and gauge as a field. Hand-rolled to avoid a serialization
    /// dependency; the byte counts and gauges round-trip as integers, `quality` and
    /// `rtt_us` as numbers.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"received\":{},\"received_bytes\":{},\"delivered\":{},\"lost\":{},",
                "\"recovered\":{},\"fec_recovered\":{},\"duplicates\":{},\"reordered\":{},",
                "\"too_late\":{},\"too_late_retransmit\":{},\"retransmitted_received\":{},",
                "\"clock_resync\":{},\"missing\":{},\"nacks_sent\":{},\"abandoned\":{},",
                "\"overwritten\":{},\"flow_resets\":{},\"discontinuities\":{},",
                "\"sent\":{},\"sent_bytes\":{},\"retransmitted\":{},\"retransmitted_bytes\":{},",
                "\"retransmit_skipped\":{},\"retransmit_suppressed\":{},",
                "\"retransmit_exhausted\":{},\"bandwidth_skipped\":{},",
                "\"rtt_us\":{},\"bandwidth_bps\":{},\"retry_bandwidth_bps\":{},\"quality\":{:.3}",
                "}}"
            ),
            self.received,
            self.received_bytes,
            self.delivered,
            self.lost,
            self.recovered,
            self.fec_recovered,
            self.duplicates,
            self.reordered,
            self.too_late,
            self.too_late_retransmit,
            self.retransmitted_received,
            self.clock_resync,
            self.missing,
            self.nacks_sent,
            self.abandoned,
            self.overwritten,
            self.flow_resets,
            self.discontinuities,
            self.sent,
            self.sent_bytes,
            self.retransmitted,
            self.retransmitted_bytes,
            self.retransmit_skipped,
            self.retransmit_suppressed,
            self.retransmit_exhausted,
            self.bandwidth_skipped,
            self.rtt.as_micros(),
            self.bandwidth_bps,
            self.retry_bandwidth_bps,
            self.quality,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_counters_bytes_gauges_and_quality() {
        // core::Stats is #[non_exhaustive]; mutate a default rather than literal-init.
        let mut core = rist_core::flow::Stats::default();
        core.received = 90;
        core.received_bytes = 90 * 1316;
        core.lost = 10;
        core.recovered = 5;
        core.sent = 100;
        core.sent_bytes = 100 * 1316;
        core.retransmitted = 7;
        core.retransmitted_bytes = 7 * 1316;
        core.too_late = 2;
        core.missing = 12;
        core.smoothed_rtt_us = 8_000;
        core.data_bitrate_bps = 12_000_000;
        core.retry_bitrate_bps = 800_000;
        let s: Stats = core.into();
        assert_eq!(s.received_bytes, 90 * 1316);
        assert_eq!(s.sent_bytes, 100 * 1316);
        assert_eq!(s.retransmitted_bytes, 7 * 1316);
        assert_eq!(s.too_late, 2);
        assert_eq!(s.missing, 12);
        assert_eq!(s.rtt, Duration::from_micros(8_000));
        assert_eq!(s.bandwidth_bps, 12_000_000);
        assert_eq!(s.retry_bandwidth_bps, 800_000);
        // quality = 100 * received / (received + lost) = 100 * 90 / 100 = 90.0.
        assert!((s.quality - 90.0).abs() < 1e-9, "quality = {}", s.quality);
    }

    #[test]
    fn quality_is_100_when_no_packets_expected() {
        let s: Stats = rist_core::flow::Stats::default().into();
        assert!((s.quality - 100.0).abs() < 1e-9);
    }

    #[test]
    fn to_json_is_flat_and_contains_every_field() {
        let mut core = rist_core::flow::Stats::default();
        core.received = 3;
        core.sent_bytes = 4096;
        core.smoothed_rtt_us = 5_000;
        let s: Stats = core.into();
        let j = s.to_json();
        assert!(j.starts_with('{') && j.ends_with('}'));
        for key in [
            "\"received\":3",
            "\"sent_bytes\":4096",
            "\"rtt_us\":5000",
            "\"bandwidth_bps\":0",
            "\"quality\":100.000",
        ] {
            assert!(j.contains(key), "JSON missing {key:?}: {j}");
        }
    }
}
