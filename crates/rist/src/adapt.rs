//! Host-side source adaptation (VSF TR-06-4 Part 1): the receiver's Link Quality
//! Message emitter and the sender's rate-control bridge.
//!
//! The wire codec ([`rist_codec::adapt`]) owns the 44-byte LQM format and the AIMD
//! controller; this module is the thin host glue that turns flow statistics into an
//! LQM each reporting period ([`LqmEmitter`]) and feeds an inbound LQM to the
//! controller, reporting the new encoder-rate target to the application
//! ([`RateControl`]). The profile codecs handle the encapsulation (Simple/Main RR
//! profile extension, Advanced control index `0x0002`); a driver only calls these
//! two helpers.

use std::time::Duration;

use rist_codec::adapt::{Controller, ControllerConfig, Lqm, bandwidth_kbps};
use rist_core::clock::Timestamp;
use rist_core::flow::Stats;

use crate::config::{Config, RateCallback};

/// The RTP header bytes attributed to each received packet for the LQM bandwidth
/// fields (the spec counts payload plus RTP header). 12 = the fixed RTP header.
const RTP_HEADER_BYTES: u64 = 12;

/// Builds Link Quality Messages from flow-statistic deltas on the reporting
/// cadence. The receiver meters each accepted media packet's bytes (via
/// [`LqmEmitter::meter`]) and, once a reporting period elapses, snapshots the flow
/// stats to produce one [`Lqm`].
pub(crate) struct LqmEmitter {
    /// The monotonically increasing LQM sequence number.
    seq: u32,
    /// The reporting cadence.
    period: Duration,
    /// The receiver's recovery (NACK) window, in ms, reported each period.
    nack_window_ms: u32,
    /// The instant the current reporting period began.
    last_emit: Timestamp,
    /// The flow stats snapshot at the start of the current period.
    prev: Stats,
    /// RTP-level bytes (payload + header) of source packets metered this run.
    rx_bytes: u64,
    /// RTP-level bytes of retransmitted packets metered this run.
    rx_retrans_bytes: u64,
    /// `rx_bytes` at the start of the current period.
    prev_rx_bytes: u64,
    /// `rx_retrans_bytes` at the start of the current period.
    prev_rx_retrans_bytes: u64,
}

impl LqmEmitter {
    /// Creates an emitter that reports every `period`, tagging each LQM with the
    /// recovery window `nack_window_ms`. `start` anchors the first reporting
    /// period.
    pub(crate) fn new(period: Duration, nack_window_ms: u32, start: Timestamp) -> LqmEmitter {
        LqmEmitter {
            seq: 0,
            period,
            nack_window_ms,
            last_emit: start,
            prev: Stats::default(),
            rx_bytes: 0,
            rx_retrans_bytes: 0,
            prev_rx_bytes: 0,
            prev_rx_retrans_bytes: 0,
        }
    }

    /// Meters one accepted media packet's RTP-level bytes (payload + header),
    /// separated by whether it was a retransmission, for the LQM bandwidth fields.
    pub(crate) fn meter(&mut self, payload_len: usize, retransmit: bool) {
        let bytes = payload_len as u64 + RTP_HEADER_BYTES;
        if retransmit {
            self.rx_retrans_bytes = self.rx_retrans_bytes.saturating_add(bytes);
        } else {
            self.rx_bytes = self.rx_bytes.saturating_add(bytes);
        }
    }

    /// Whether a reporting period has elapsed at `now`.
    pub(crate) fn due(&self, now: Timestamp) -> bool {
        (now - self.last_emit).as_micros() >= micros(self.period)
    }

    /// Snapshots the flow `stats` and metered bytes into one Link Quality Message
    /// for the period ending at `now`, then opens the next period. The counter
    /// fields are exact deltas; the bandwidth fields are derived from the metered
    /// RTP bytes (the spec notes NPD makes them uncomputable from packet counts).
    pub(crate) fn build(&mut self, now: Timestamp, stats: &Stats) -> Lqm {
        let elapsed_us = (now - self.last_emit).as_micros().max(0);
        let period_ms = u32::try_from(elapsed_us / 1000).unwrap_or(u32::MAX);
        self.seq = self.seq.wrapping_add(1);

        let lqm = Lqm {
            sequence_number: self.seq,
            reporting_period_ms: period_ms,
            nack_window_ms: self.nack_window_ms,
            source_received: delta(stats.received, self.prev.received),
            original_lost: delta(stats.missing, self.prev.missing),
            // ristrust has no dedicated "retransmit received" counter; the
            // recovered count (missing entries filled by a retransmit) is its
            // closest analog and is not consumed by the controller.
            retransmitted_received: delta(stats.recovered, self.prev.recovered),
            recovered: delta(stats.recovered, self.prev.recovered),
            unrecovered: delta(stats.lost, self.prev.lost),
            late: delta(stats.too_late, self.prev.too_late),
            data_bandwidth_kbps: bandwidth_kbps(self.rx_bytes - self.prev_rx_bytes, period_ms),
            retransmission_bandwidth_kbps: bandwidth_kbps(
                self.rx_retrans_bytes - self.prev_rx_retrans_bytes,
                period_ms,
            ),
        };

        self.prev = *stats;
        self.prev_rx_bytes = self.rx_bytes;
        self.prev_rx_retrans_bytes = self.rx_retrans_bytes;
        self.last_emit = now;
        lqm
    }
}

/// The sender's rate-control bridge: feeds each inbound Link Quality Message to the
/// AIMD controller and reports the new encoder-rate target to the application.
pub(crate) struct RateControl {
    controller: Controller,
    callback: RateCallback,
}

impl RateControl {
    /// Builds a rate controller from `cfg` when a rate callback is configured;
    /// `None` (no callback) disables rate control. The controller's ceiling is
    /// `max_bitrate_kbps`, its floor `min_bitrate_kbps`, and its additive step is
    /// 1% of the ceiling.
    pub(crate) fn from_config(cfg: &Config) -> Option<RateControl> {
        let callback = cfg.on_rate_adapt.clone()?;
        let mut cc = ControllerConfig {
            max_kbps: cfg.max_bitrate_kbps,
            initial_kbps: cfg.max_bitrate_kbps,
            increase_kbps: (cfg.max_bitrate_kbps / 100).max(1),
            ..ControllerConfig::default()
        };
        if cfg.min_bitrate_kbps > 0 {
            cc.min_kbps = cfg.min_bitrate_kbps;
        }
        Some(RateControl {
            controller: Controller::new(cc),
            callback,
        })
    }

    /// Folds one inbound 44-byte Link Quality Message into the controller and
    /// invokes the rate callback with the new target. A malformed LQM is ignored.
    pub(crate) fn handle(&mut self, lqm: &[u8; 44]) {
        let Ok(m) = Lqm::parse(lqm) else {
            return;
        };
        let target = self.controller.observe_lqm(&m);
        self.callback.call(target);
    }
}

/// A saturating `u64` delta cast down to the LQM's `u32` field width.
fn delta(now: u64, prev: u64) -> u32 {
    u32::try_from(now.saturating_sub(prev)).unwrap_or(u32::MAX)
}

/// A `Duration` as whole microseconds (saturating into the core's `i64` domain).
fn micros(d: Duration) -> i64 {
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}
