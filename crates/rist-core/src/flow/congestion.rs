//! Congestion control + NACK pacing (ported from libRIST v0.2.18, ristgo
//! `internal/flow/congestion.go`), kept pure: time enters only via explicit `now`
//! arguments, so the whole mechanism lives in the sans-I/O core with no clock read.
//!
//! The sender paces retransmissions against `recovery_maxbitrate` using a pair of
//! 1/8-weight byte-rate EWMAs ([`BitrateEwma`], a slow 1 s window + a fast 100 ms
//! window). [`CongestionMode`] selects which windows the data and retry rates read.
//! Two derived bounds cap the work either half does per pass:
//! [`derive_missing_counter_max`] (the receiver's missing-queue ceiling) and
//! [`derive_max_nacks_per_loop`] (the sender's retransmits-per-service-pass cap);
//! [`derive_ring_size`] sizes the history/recovery ring from the recovery window.

use crate::clock::Timestamp;

use super::{Config, DEFAULT_RING_SIZE};

/// `sizeof(rist_gre_seq) + sizeof(rist_rtp_hdr) + sizeof(u32)` = 12 + 12 + 4, the
/// per-packet overhead libRIST charges (its `rist_gre_seq` omits the 4-byte
/// `checksum_reserved1` of the plain GRE header, so the divisor is 28, not 24).
pub(crate) const RIST_HEADER_OVERHEAD_BYTES: i64 = 28;
/// The fixed MTU libRIST assumes in the `max_nacksperloop` derivation.
const RIST_NACK_MTU_ASSUMED: i64 = 1400;
/// `RIST_MAX_JITTER`, the 5 ms receiver-loop bound in the `max_nacksperloop`
/// derivation.
const RIST_MAX_JITTER_MS: i64 = 5;
/// The slow byte-rate EWMA window (1 s), libRIST's `eight_times_bitrate`.
const BITRATE_SLOW_WINDOW_US: i64 = 1_000_000;
/// The fast byte-rate EWMA window (100 ms), libRIST's `eight_times_bitrate_fast`.
const BITRATE_FAST_WINDOW_US: i64 = 100_000;
/// The assumed average packet size, in bytes, used to size the ring from a
/// recovery window (libRIST's slot accounting).
const RING_PACKET_BYTES: i64 = 1100;
/// The cap on the derived ring (~150 MB at 72 B/slot); beyond this the caller must
/// set `ring_size` explicitly.
pub(crate) const MAX_DERIVED_RING_SIZE: usize = 1 << 21;

/// The sender's `recovery_maxbitrate` pacing mode (libRIST `congestion_control`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CongestionMode {
    /// No bandwidth gate (libRIST `OFF`): retransmits are limited only by the
    /// per-packet RTT/retry gate.
    Off,
    /// Paces retransmits against `recovery_maxbitrate` using the slow (1 s)
    /// data-rate EWMA plus the fast (100 ms) retry-rate EWMA (the default; libRIST
    /// `NORMAL`).
    #[default]
    Normal,
    /// Uses the fast EWMA for both the data and retry rate — reacts quicker and
    /// paces harder, and spaces retransmits at 2×RTT (libRIST `AGGRESSIVE`).
    Aggressive,
}

/// `missing_counter_max = recovery_buffer_ms * max(1, recovery_maxbitrate_kbps /
/// 1000) / 28` (libRIST `init_peer_settings`; 3571 with the defaults). Bounds how
/// many missing entries the receiver queues before it stops marking new gaps — the
/// buffer-bloat / overflow guard.
#[must_use]
pub(crate) fn derive_missing_counter_max(cfg: &Config) -> u32 {
    let recovery_ms = cfg.recovery_buffer().as_micros() / 1000;
    let mbps = (i64::from(cfg.recovery_maxbitrate) / 1000).max(1);
    let v = recovery_ms * mbps / RIST_HEADER_OVERHEAD_BYTES;
    u32::try_from(v.max(0)).unwrap_or(u32::MAX)
}

/// `max_nacksperloop` (libRIST `init_peer_settings`, sender branch; 88 with the
/// defaults). Caps how many retransmissions the sender emits in one service pass;
/// the remainder are dropped this pass and re-NACKed by the receiver.
#[must_use]
pub(crate) fn derive_max_nacks_per_loop(cfg: &Config) -> u32 {
    let kbps = if cfg.recovery_maxbitrate == 0 {
        100_000
    } else {
        i64::from(cfg.recovery_maxbitrate)
    };
    let buf_max_ms = (cfg.recovery_buffer_max.as_micros() / 1000).max(1);
    let mut n = kbps * RIST_MAX_JITTER_MS / (8 * RIST_NACK_MTU_ASSUMED);
    n = n * 1000 / buf_max_ms;
    if n == 0 {
        n = 1;
    }
    u32::try_from((n * 2).max(0)).unwrap_or(u32::MAX)
}

/// The ring capacity (in slots, before the caller's power-of-two rounding) that
/// holds a full recovery window's worth of packets at `recovery_maxbitrate`,
/// floored at [`DEFAULT_RING_SIZE`] and capped at [`MAX_DERIVED_RING_SIZE`]. A pure
/// function of `cfg` (no clock read).
#[must_use]
pub(crate) fn derive_ring_size(cfg: &Config) -> usize {
    let mut window_us = cfg.recovery_buffer_max.as_micros() + 2 * cfg.rtt_min.as_micros();
    let rb = cfg.recovery_buffer().as_micros();
    if rb > window_us {
        window_us = rb;
    }
    let kbps = if cfg.recovery_maxbitrate == 0 {
        100_000
    } else {
        i64::from(cfg.recovery_maxbitrate)
    };
    let packets = (window_us * kbps / (8000 * RING_PACKET_BYTES)).max(0);
    usize::try_from(packets)
        .unwrap_or(MAX_DERIVED_RING_SIZE)
        .clamp(DEFAULT_RING_SIZE, MAX_DERIVED_RING_SIZE)
}

/// A pair of 1/8-weight byte-rate EWMAs (libRIST's `eight_times_bitrate` /
/// `eight_times_bitrate_fast`) over a slow (1 s) and a fast (100 ms) window, kept
/// premultiplied by 8. Fed the on-wire byte count of each emitted packet (and a
/// zero-length refresh so the window-expiry decay fires between packets). Time
/// enters only via the explicit `now` argument.
#[derive(Debug, Clone, Default)]
pub(crate) struct BitrateEwma {
    bytes_slow: i64,
    bytes_fast: i64,
    last_slow: Timestamp,
    last_fast: Timestamp,
    /// Smoothed bits/sec × 8, 1 s window.
    eight_slow: i64,
    /// Smoothed bits/sec × 8, 100 ms window.
    eight_fast: i64,
    seeded: bool,
}

impl BitrateEwma {
    /// Folds `n` on-wire bytes observed at `now` into both windows. `n == 0`
    /// performs only the window-expiry decay (so a stale-but-high estimate decays
    /// between retransmits).
    pub(crate) fn feed(&mut self, now: Timestamp, n: i64) {
        if !self.seeded {
            self.last_slow = now;
            self.last_fast = now;
            self.seeded = true;
        }
        self.bytes_slow += n;
        self.bytes_fast += n;
        let elapsed_slow = (now - self.last_slow).as_micros();
        if elapsed_slow >= BITRATE_SLOW_WINDOW_US {
            let sample = 8 * self.bytes_slow * 1_000_000 / elapsed_slow;
            self.eight_slow += sample - self.eight_slow / 8;
            self.last_slow = now;
            self.bytes_slow = 0;
        }
        let elapsed_fast = (now - self.last_fast).as_micros();
        if elapsed_fast >= BITRATE_FAST_WINDOW_US {
            let sample = 8 * self.bytes_fast * 1_000_000 / elapsed_fast;
            self.eight_fast += sample - self.eight_fast / 8;
            self.last_fast = now;
            self.bytes_fast = 0;
        }
    }

    /// The smoothed slow-window bit rate (`eight_slow / 8`).
    #[must_use]
    pub(crate) fn slow_bps(&self) -> i64 {
        self.eight_slow / 8
    }

    /// The smoothed fast-window bit rate (`eight_fast / 8`).
    #[must_use]
    pub(crate) fn fast_bps(&self) -> i64 {
        self.eight_fast / 8
    }
}

/// Whether emitting another packet would exceed `recovery_maxbitrate` under
/// `mode`: the current bit rate (data-rate + retry-rate) versus
/// `recovery_maxbitrate × 1000` (kbps → bps). [`CongestionMode::Off`] never gates.
#[must_use]
pub(crate) fn over_budget(
    mode: CongestionMode,
    data: &BitrateEwma,
    retry: &BitrateEwma,
    max_kbps: u32,
) -> bool {
    let ceiling = i64::from(max_kbps) * 1000;
    match mode {
        CongestionMode::Off => false,
        CongestionMode::Aggressive => data.fast_bps() + retry.fast_bps() > ceiling,
        CongestionMode::Normal => data.slow_bps() + retry.fast_bps() > ceiling,
    }
}

/// The estimated on-wire UDP-payload size of a media packet — its payload length
/// plus the RIST per-packet overhead — for the bitrate EWMAs. An estimate (exact
/// framing is the codec's), sufficient for the pacing comparison.
#[must_use]
pub(crate) fn wire_bytes(payload_len: usize) -> i64 {
    i64::try_from(payload_len).unwrap_or(i64::MAX) + RIST_HEADER_OVERHEAD_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Micros;

    fn at(ms: i64) -> Timestamp {
        Timestamp::from_micros(u64::try_from(ms * 1000).unwrap_or(0))
    }

    #[test]
    fn derived_bounds_match_librist_defaults() {
        let cfg = Config::librist_defaults();
        // recovery 1000 ms, recovery_maxbitrate 100000 kbps.
        assert_eq!(derive_missing_counter_max(&cfg), 1000 * 100 / 28); // 3571
        assert_eq!(derive_max_nacks_per_loop(&cfg), 88);
        // The default window fits inside the floor ring.
        assert_eq!(derive_ring_size(&cfg), DEFAULT_RING_SIZE);
    }

    #[test]
    fn ring_grows_with_bitrate_and_window() {
        let mut cfg = Config::librist_defaults();
        cfg.recovery_buffer_min = Micros::from_millis(8000);
        cfg.recovery_buffer_max = Micros::from_millis(8000);
        cfg.recovery_maxbitrate = 200_000; // 200 Mbps
        let size = derive_ring_size(&cfg);
        assert!(
            size > DEFAULT_RING_SIZE,
            "a large window/bitrate grows the ring"
        );
        assert!(size <= MAX_DERIVED_RING_SIZE);
    }

    #[test]
    fn over_budget_respects_mode_and_ceiling() {
        // Feed a high steady data rate over a full slow window.
        let mut data = BitrateEwma::default();
        let retry = BitrateEwma::default();
        // 1 MB over 1 s = 8 Mbit/s; feed in fast-window chunks so both EWMAs settle.
        for k in 0..=20 {
            data.feed(at(k * 100), 100_000); // 100 KB per 100 ms = 8 Mbit/s
        }
        // OFF never gates.
        assert!(!over_budget(CongestionMode::Off, &data, &retry, 1));
        // At a 1 kbps ceiling the 8 Mbit/s data rate is over budget.
        assert!(over_budget(CongestionMode::Normal, &data, &retry, 1));
        // At a 100 Mbit/s ceiling it is not.
        assert!(!over_budget(CongestionMode::Normal, &data, &retry, 100_000));
    }

    #[test]
    fn ewma_idle_decays_toward_zero() {
        let mut e = BitrateEwma::default();
        // Busy: 100 KB every 100 ms for ~3 s, so the slow (1 s) window expires
        // several times and the smoothed estimate actually rises above zero.
        for k in 0..30 {
            e.feed(at(k * 100), 100_000);
        }
        let busy = e.slow_bps();
        assert!(
            busy > 0,
            "a steady data rate establishes a non-zero estimate"
        );
        // Long idle with only zero-length refreshes drives the rate back down.
        for k in 0..90 {
            e.feed(at(3_000 + k * 1000), 0);
        }
        assert!(e.slow_bps() < busy, "idle must decay the estimate");
    }
}
