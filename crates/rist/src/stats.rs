//! The public per-session statistics snapshot and its shared cell.
//!
//! [`Stats`] is a curated, public subset of the flow core's counters. The driver
//! task owns the flow, so it publishes a snapshot into a shared [`StatsCell`] after
//! each event; the public [`Sender`](crate::Sender) / [`Receiver`](crate::Receiver)
//! handle reads the latest snapshot through its `stats()` method.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Profile;

/// Per-peer (per-path) statistics for one bonded path, or the single peer of a
/// non-bonded session — the libRIST `rist_stats_*_peer` analog, surfaced in
/// [`Stats::peers`]. A receiver session fills the `received_*` counters; a sender
/// session fills `sent_*` / `retransmitted_*`; `rtt` is per-path.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct PeerStats {
    /// The smoothed per-path round-trip time (the flow RTT on a non-bonded session).
    pub rtt: Duration,
    /// Media packets received from this peer (receiver session).
    pub received: u64,
    /// Payload bytes received from this peer (receiver session).
    pub received_bytes: u64,
    /// First-transmission media packets sent to this peer (sender session).
    pub sent: u64,
    /// First-transmission payload bytes sent to this peer (sender session).
    pub sent_bytes: u64,
    /// Retransmitted media packets sent to this peer (sender session).
    pub retransmitted: u64,
    /// Retransmitted payload bytes sent to this peer (sender session).
    pub retransmitted_bytes: u64,
    /// The path's SMPTE 2022-7 load-share weight (`0` = full duplication, or the
    /// single non-bonded peer).
    pub weight: u32,
    /// The path's NACK-recovery priority (`0` on the single non-bonded peer).
    pub priority: u32,
    /// Whether the path is currently live. Always `true` for the single non-bonded peer.
    pub alive: bool,
}

/// A snapshot of a [`Sender`](crate::Sender)'s or [`Receiver`](crate::Receiver)'s
/// counters and gauges, read via their `stats()` method. Sender-only and
/// receiver-only fields are zero on the other role.
#[derive(Debug, Clone, Default, PartialEq)]
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
    /// The subset of [`recovered`](Stats::recovered) that cleared on the first NACK
    /// (libRIST `recovered_one_retry`) — a high ratio indicates a healthy link.
    pub recovered_one_retry: u64,
    /// [`recovered`](Stats::recovered) bucketed by NACK depth — the number of NACKs the
    /// packet needed before it arrived (2, 3, 4, or more than 4) — mirroring libRIST's
    /// `recovered_{two,three,four,more}_nacks`. The distribution shows whether losses
    /// clear promptly or grind through repeated retries.
    pub recovered_two_nacks: u64,
    /// [`recovered`](Stats::recovered) after three NACKs (libRIST `recovered_three_nacks`).
    pub recovered_three_nacks: u64,
    /// [`recovered`](Stats::recovered) after four NACKs (libRIST `recovered_four_nacks`).
    pub recovered_four_nacks: u64,
    /// [`recovered`](Stats::recovered) after more than four NACKs (libRIST `recovered_more_nacks`).
    pub recovered_more_nacks: u64,
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
    /// Smallest inter-packet arrival gap seen so far (libRIST `min_ips`); zero before
    /// the first inter-arrival sample, and on a sender.
    pub inter_packet_min: Duration,
    /// Most recent inter-packet arrival gap (libRIST `cur_ips`).
    pub inter_packet_cur: Duration,
    /// Largest inter-packet arrival gap seen so far (libRIST `max_ips`).
    pub inter_packet_max: Duration,
    /// The average recovery-buffer (playout) level (libRIST `avg_buffer_time`): the
    /// running mean of the dynamic buffer, equal to the static buffer when not
    /// windowed, and zero on a sender.
    pub avg_buffer_time: Duration,
    /// Per-peer (per-path) statistics (libRIST `rist_stats_*_peer`). A non-bonded
    /// session reports exactly one peer mirroring the flow; a bonded session reports
    /// one per path with its own RTT, counters, weight, and liveness.
    pub peers: Vec<PeerStats>,

    // --- Wire framing (for the Prometheus `*_info` series) ---
    /// The configured RIST wire profile (libRIST stats `profile` field).
    pub profile: Profile,
    /// The on-wire sequence-number width: 16 (Simple/Main framing) or 32 (Advanced
    /// framing). An Advanced flow reads 16 until the source upgrades framing
    /// (TR-06-3 §9); always 16 for Simple/Main (libRIST `seq_bits`).
    pub seq_bits: u8,
    /// Whether Advanced framing is currently active on the wire: `true` only for an
    /// Advanced-profile session whose framing has upgraded to 32-bit, `false` while an
    /// Advanced session is still on the §9 Main-framing fallback window and `false` for
    /// Simple/Main (libRIST `advanced_active`).
    pub advanced_active: bool,
}

impl From<rist_core::flow::Stats> for Stats {
    /// Maps the flow core's counters and gauges to the curated public snapshot. The
    /// host-tracked `fec_recovered` count is layered on at publish time (the flow core
    /// has no FEC counter — FEC recovery is a host concern), and `quality` is derived.
    #[allow(clippy::cast_precision_loss)]
    // counts well within f64's exact range here
    // The `From` trait fixes the by-value signature; core `Stats` is `Copy` and this
    // runs only at snapshot time, so the ~272-byte copy is irrelevant.
    #[allow(clippy::large_types_passed_by_value)]
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
            recovered_one_retry: f.recovered_one_retry,
            recovered_two_nacks: f.recovered_two_nacks,
            recovered_three_nacks: f.recovered_three_nacks,
            recovered_four_nacks: f.recovered_four_nacks,
            recovered_more_nacks: f.recovered_more_nacks,
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
            inter_packet_min: Duration::from_micros(u64::try_from(f.ips_min_us).unwrap_or(0)),
            inter_packet_cur: Duration::from_micros(u64::try_from(f.ips_cur_us).unwrap_or(0)),
            inter_packet_max: Duration::from_micros(u64::try_from(f.ips_max_us).unwrap_or(0)),
            avg_buffer_time: Duration::from_micros(
                u64::try_from(f.avg_buffer_time_us).unwrap_or(0),
            ),
            // Left empty here so the per-input publish stays allocation-free; the
            // single-peer default is materialized lazily at read time (see
            // `StatsCell::snapshot`), and a bonded driver supplies its per-path list.
            peers: Vec::new(),
            // seq_bits follows the flow's anchored framing (32 only once an Advanced
            // source has upgraded). profile and advanced_active are not flow facts
            // (the core is profile-agnostic); they are overlaid from the session in
            // `StatsCell::snapshot` via `set_framing`.
            profile: Profile::Simple,
            seq_bits: if f.anchored && !f.short_seq { 32 } else { 16 },
            advanced_active: false,
        }
    }
}

impl Stats {
    /// Builds the single-peer view of a non-bonded session from the flow aggregate —
    /// the libRIST single-peer case. Materialized at read time so the hot publish path
    /// never allocates a peer vector.
    fn single_peer(&self) -> PeerStats {
        PeerStats {
            rtt: self.rtt,
            received: self.received,
            received_bytes: self.received_bytes,
            sent: self.sent,
            sent_bytes: self.sent_bytes,
            retransmitted: self.retransmitted,
            retransmitted_bytes: self.retransmitted_bytes,
            weight: 0,
            priority: 0,
            alive: true,
        }
    }

    /// Serializes the snapshot to a flat JSON object (libRIST's `stats_json` analog),
    /// every counter and gauge as a field. Hand-rolled to avoid a serialization
    /// dependency; the byte counts and gauges round-trip as integers, `quality` and
    /// `rtt_us` as numbers.
    #[must_use]
    pub fn to_json(&self) -> String {
        let peers_json = self
            .peers
            .iter()
            .map(PeerStats::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{",
                "\"received\":{},\"received_bytes\":{},\"delivered\":{},\"lost\":{},",
                "\"recovered\":{},\"recovered_one_retry\":{},",
                "\"recovered_two_nacks\":{},\"recovered_three_nacks\":{},\"recovered_four_nacks\":{},\"recovered_more_nacks\":{},",
                "\"fec_recovered\":{},\"duplicates\":{},\"reordered\":{},",
                "\"too_late\":{},\"too_late_retransmit\":{},\"retransmitted_received\":{},",
                "\"clock_resync\":{},\"missing\":{},\"nacks_sent\":{},\"abandoned\":{},",
                "\"overwritten\":{},\"flow_resets\":{},\"discontinuities\":{},",
                "\"sent\":{},\"sent_bytes\":{},\"retransmitted\":{},\"retransmitted_bytes\":{},",
                "\"retransmit_skipped\":{},\"retransmit_suppressed\":{},",
                "\"retransmit_exhausted\":{},\"bandwidth_skipped\":{},",
                "\"rtt_us\":{},\"bandwidth_bps\":{},\"retry_bandwidth_bps\":{},\"quality\":{:.3},",
                "\"ips_min_us\":{},\"ips_cur_us\":{},\"ips_max_us\":{},\"avg_buffer_time_us\":{},",
                "\"profile\":{},\"seq_bits\":{},\"advanced_active\":{},",
                "\"peers\":[{}]",
                "}}"
            ),
            self.received,
            self.received_bytes,
            self.delivered,
            self.lost,
            self.recovered,
            self.recovered_one_retry,
            self.recovered_two_nacks,
            self.recovered_three_nacks,
            self.recovered_four_nacks,
            self.recovered_more_nacks,
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
            self.inter_packet_min.as_micros(),
            self.inter_packet_cur.as_micros(),
            self.inter_packet_max.as_micros(),
            self.avg_buffer_time.as_micros(),
            self.profile.as_u8(),
            self.seq_bits,
            self.advanced_active,
            peers_json,
        )
    }
}

impl From<crate::bonding::PathStats> for PeerStats {
    /// Maps one bonded path's [`PathStats`](crate::bonding::PathStats) snapshot to the
    /// public per-peer form.
    fn from(p: crate::bonding::PathStats) -> PeerStats {
        PeerStats {
            rtt: Duration::from_micros(u64::try_from(p.rtt.as_micros()).unwrap_or(0)),
            received: p.recv_pkts,
            received_bytes: p.recv_bytes,
            sent: p.sent_pkts,
            sent_bytes: p.sent_bytes,
            retransmitted: p.retx_pkts,
            retransmitted_bytes: p.retx_bytes,
            weight: p.weight,
            priority: p.priority,
            alive: p.alive,
        }
    }
}

impl PeerStats {
    /// Serializes one peer to a flat JSON object for [`Stats::to_json`]'s `peers` array.
    #[must_use]
    fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"rtt_us\":{},\"received\":{},\"received_bytes\":{},",
                "\"sent\":{},\"sent_bytes\":{},\"retransmitted\":{},\"retransmitted_bytes\":{},",
                "\"weight\":{},\"priority\":{},\"alive\":{}}}"
            ),
            self.rtt.as_micros(),
            self.received,
            self.received_bytes,
            self.sent,
            self.sent_bytes,
            self.retransmitted,
            self.retransmitted_bytes,
            self.weight,
            self.priority,
            self.alive,
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
    /// The wire profile as a libRIST discriminant (0 simple, 1 main, 2 advanced) and
    /// whether Advanced framing is currently active, for the Prometheus `*_info`
    /// series. Published by the driver alongside the counters; the profile is static
    /// but advanced_active tracks the mutable §9 framing state.
    profile: AtomicU8,
    advanced_active: AtomicBool,
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
    // Core `Stats` is `Copy` and `publish` is called ~once per status tick, so taking
    // the ~272-byte snapshot by value (to feed the by-value `From`) is not worth a ref.
    #[allow(clippy::large_types_passed_by_value)]
    pub(crate) fn publish(&self, core: rist_core::flow::Stats, fec_recovered: u64) {
        self.publish_peers(core, fec_recovered, Vec::new());
    }

    /// Like [`publish`](Self::publish), but replaces the single-peer default with an
    /// explicit per-path peer list (a bonded driver passes one entry per path). An
    /// empty `peers` keeps the flow-derived single peer.
    #[allow(clippy::large_types_passed_by_value)]
    pub(crate) fn publish_peers(
        &self,
        core: rist_core::flow::Stats,
        fec_recovered: u64,
        peers: Vec<PeerStats>,
    ) {
        let mut snapshot: Stats = core.into();
        snapshot.fec_recovered = fec_recovered;
        if !peers.is_empty() {
            snapshot.peers = peers;
        }
        *self.0.stats.lock().expect("stats mutex poisoned") = snapshot;
    }

    /// Reads the latest published snapshot (all-zero until the first publish). A
    /// non-bonded session's `peers` is empty in the stored snapshot (kept so the hot
    /// publish never allocates) and is materialized here, on this rare read path, as
    /// the single peer mirroring the flow.
    pub(crate) fn snapshot(&self) -> Stats {
        let mut s = self.0.stats.lock().expect("stats mutex poisoned").clone();
        if s.peers.is_empty() {
            s.peers.push(s.single_peer());
        }
        // Overlay the session-owned framing metadata (seq_bits already came from the
        // flow snapshot via `From`); profile and advanced_active are not flow facts.
        s.profile = Profile::from_u8(self.0.profile.load(Ordering::Relaxed));
        s.advanced_active = self.0.advanced_active.load(Ordering::Relaxed);
        s
    }

    /// Records the wire-framing metadata for the Prometheus `*_info` series
    /// (driver-side): the profile discriminant and whether Advanced framing is
    /// currently active. Called by the driver task when it publishes counters.
    pub(crate) fn set_framing(&self, profile: u8, advanced_active: bool) {
        self.0.profile.store(profile, Ordering::Relaxed);
        self.0
            .advanced_active
            .store(advanced_active, Ordering::Relaxed);
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
        core.recovered_one_retry = 4;
        core.avg_buffer_time_us = 600_000;
        core.sent = 100;
        core.sent_bytes = 100 * 1316;
        core.retransmitted = 7;
        core.retransmitted_bytes = 7 * 1316;
        core.too_late = 2;
        core.missing = 12;
        core.smoothed_rtt_us = 8_000;
        core.data_bitrate_bps = 12_000_000;
        core.retry_bitrate_bps = 800_000;
        core.ips_min_us = 3_000;
        core.ips_cur_us = 4_000;
        core.ips_max_us = 9_000;
        let s: Stats = core.into();
        assert_eq!(s.received_bytes, 90 * 1316);
        assert_eq!(s.sent_bytes, 100 * 1316);
        assert_eq!(s.retransmitted_bytes, 7 * 1316);
        assert_eq!(s.too_late, 2);
        assert_eq!(s.missing, 12);
        assert_eq!(s.rtt, Duration::from_micros(8_000));
        assert_eq!(s.bandwidth_bps, 12_000_000);
        assert_eq!(s.retry_bandwidth_bps, 800_000);
        assert_eq!(s.inter_packet_min, Duration::from_micros(3_000));
        assert_eq!(s.inter_packet_cur, Duration::from_micros(4_000));
        assert_eq!(s.inter_packet_max, Duration::from_micros(9_000));
        assert_eq!(s.recovered_one_retry, 4);
        assert_eq!(s.avg_buffer_time, Duration::from_micros(600_000));
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
        core.recovered_one_retry = 2;
        core.recovered_two_nacks = 6;
        core.recovered_more_nacks = 1;
        core.avg_buffer_time_us = 700_000;
        core.anchored = true; // 32-bit Advanced framing => seq_bits 32
        let mut s: Stats = core.into();
        s.profile = crate::Profile::Advanced;
        s.advanced_active = true;
        let j = s.to_json();
        assert!(j.starts_with('{') && j.ends_with('}'));
        for key in [
            "\"received\":3",
            "\"sent_bytes\":4096",
            "\"rtt_us\":5000",
            "\"bandwidth_bps\":0",
            "\"quality\":100.000",
            "\"ips_max_us\":0",
            "\"recovered_one_retry\":2",
            "\"avg_buffer_time_us\":700000",
            // libRIST-parity stats fields (4d55974, 8cf3c81).
            "\"recovered_two_nacks\":6",
            "\"recovered_more_nacks\":1",
            "\"profile\":2",
            "\"seq_bits\":32",
            "\"advanced_active\":true",
        ] {
            assert!(j.contains(key), "JSON missing {key:?}: {j}");
        }
    }
}
