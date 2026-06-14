//! Source-adaptation Link Quality Message + AIMD rate controller (VSF TR-06-4
//! Part 1).
//!
//! Two pure, deterministic pieces with no I/O and no clock:
//!
//! - [`Lqm`] — the 44-byte Link Quality Message of TR-06-4 Part 1 Figure 2:
//!   eleven 32-bit big-endian counters the receiver sends to the sender each
//!   reporting period. [`Lqm::encode`] / [`Lqm::parse`] are byte-exact to the
//!   spec; the profile-specific encapsulation (Simple/Main RR profile extension,
//!   Advanced control index `0x0002`/`0x0003`) lives in the host.
//! - [`Controller`] — an additive-increase / multiplicative-decrease rate
//!   controller. It folds each LQM (or a bare loss fraction) into an encoder
//!   bit-rate target that is **monotone in loss**: more loss never raises the
//!   target. This is the TR-06-4 Part 1 §6.1 rate-adaptation example, not a wire
//!   format — there is no libRIST equivalent, so the bar is spec conformance plus
//!   a closed-loop simulation. Ported from ristgo's `internal/adapt`.

// The AIMD arithmetic reproduces ristgo's integer `int(rate * (1 - cut))`
// truncation exactly; the f64 round-trips are deliberate. Counter-to-f64 widening
// (u32 -> f64) is lossless.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

use thiserror::Error;

/// The exact wire size of a Link Quality Message (Figure 2: eleven 32-bit
/// counters).
pub const LQM_SIZE: usize = 44;

/// An error decoding a Link Quality Message.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdaptError {
    /// The buffer was shorter than [`LQM_SIZE`] bytes.
    #[error("rist: adapt: short link quality message: {0} < {LQM_SIZE} bytes")]
    ShortLqm(usize),
}

/// A VSF TR-06-4 Part 1 Link Quality Message (Figure 2): eleven 32-bit counters
/// the receiver reports to the sender for source adaptation. All fields are raw
/// per-reporting-period values; the controller interprets them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Lqm {
    /// A monotonically increasing per-message sequence number (lets the sender
    /// detect lost or duplicate LQMs; there is no LQM retransmission).
    pub sequence_number: u32,
    /// The reporting period covered by this message, in milliseconds.
    pub reporting_period_ms: u32,
    /// The receiver's current NACK (recovery) window, in milliseconds.
    pub nack_window_ms: u32,
    /// Count of source packets received this period.
    pub source_received: u32,
    /// Count of original packets lost this period (the congestion signal).
    pub original_lost: u32,
    /// Count of retransmitted packets received this period.
    pub retransmitted_received: u32,
    /// Count of packets lost then recovered (by retransmission or FEC).
    pub recovered: u32,
    /// Count of packets never recovered within the NACK window.
    pub unrecovered: u32,
    /// Count of source packets received too late to use (outside the window).
    pub late: u32,
    /// Measured source data bandwidth, in kbit/s (rounded to the nearest 1000
    /// bit/s).
    pub data_bandwidth_kbps: u32,
    /// Measured retransmission bandwidth, in kbit/s (same rounding).
    pub retransmission_bandwidth_kbps: u32,
}

impl Lqm {
    /// Encodes the message into its 44-byte big-endian wire form (Figure 2).
    #[must_use]
    pub fn encode(&self) -> [u8; LQM_SIZE] {
        let mut b = [0u8; LQM_SIZE];
        let fields = [
            self.sequence_number,
            self.reporting_period_ms,
            self.nack_window_ms,
            self.source_received,
            self.original_lost,
            self.retransmitted_received,
            self.recovered,
            self.unrecovered,
            self.late,
            self.data_bandwidth_kbps,
            self.retransmission_bandwidth_kbps,
        ];
        for (i, f) in fields.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&f.to_be_bytes());
        }
        b
    }

    /// Appends the 44-byte wire form to `dst`.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.encode());
    }

    /// Parses a Link Quality Message from the first [`LQM_SIZE`] bytes of `b`
    /// (trailing bytes are ignored, matching the spec's fixed-size field).
    ///
    /// # Errors
    /// Returns [`AdaptError::ShortLqm`] when `b` is shorter than [`LQM_SIZE`].
    pub fn parse(b: &[u8]) -> Result<Lqm, AdaptError> {
        if b.len() < LQM_SIZE {
            return Err(AdaptError::ShortLqm(b.len()));
        }
        let u = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Ok(Lqm {
            sequence_number: u(0),
            reporting_period_ms: u(4),
            nack_window_ms: u(8),
            source_received: u(12),
            original_lost: u(16),
            retransmitted_received: u(20),
            recovered: u(24),
            unrecovered: u(28),
            late: u(32),
            data_bandwidth_kbps: u(36),
            retransmission_bandwidth_kbps: u(40),
        })
    }

    /// The original-loss fraction `original_lost / (source_received +
    /// original_lost)`, the congestion signal. Returns 0 when nothing was
    /// accounted (never NaN).
    #[must_use]
    pub fn loss_fraction(&self) -> f64 {
        let denom = f64::from(self.source_received) + f64::from(self.original_lost);
        if denom == 0.0 {
            0.0
        } else {
            f64::from(self.original_lost) / denom
        }
    }

    /// The residual (unrecovered) loss fraction `unrecovered / (source_received +
    /// original_lost)`: loss the recovery window did not repair. Returns 0 when
    /// nothing was accounted.
    #[must_use]
    pub fn residual_loss_fraction(&self) -> f64 {
        let denom = f64::from(self.source_received) + f64::from(self.original_lost);
        if denom == 0.0 {
            0.0
        } else {
            f64::from(self.unrecovered) / denom
        }
    }
}

/// Converts a per-period byte count into kbit/s, rounded to the nearest 1000
/// bit/s (the spec's bandwidth rounding). Returns 0 for a zero-length period.
/// This is the receiver's `DataBandwidthKbps` / `RetransmissionBandwidthKbps`
/// computation; the RTP header (and any extension) bytes are included by the
/// caller, per the spec.
#[must_use]
pub fn bandwidth_kbps(delta_bytes: u64, period_ms: u32) -> u32 {
    if period_ms == 0 {
        return 0;
    }
    let bits = delta_bytes.saturating_mul(8);
    let p = u64::from(period_ms);
    ((bits + p / 2) / p) as u32
}

/// The largest fraction a single multiplicative decrease may cut the rate by
/// (90%): a floor on how far one bad report can drop the target.
const MAX_CUT: f64 = 0.90;

/// The tunable parameters of the AIMD [`Controller`]. All rates are in kbit/s.
#[derive(Debug, Clone, Copy)]
pub struct ControllerConfig {
    /// The floor the target is never driven below.
    pub min_kbps: u32,
    /// The ceiling the target is never driven above.
    pub max_kbps: u32,
    /// The starting target (clamped to `[min_kbps, max_kbps]`).
    pub initial_kbps: u32,
    /// The loss fraction at or below which the controller probes up.
    pub target_loss: f64,
    /// The additive step added each clean report.
    pub increase_kbps: u32,
    /// The multiplicative-decrease gain: `cut = decrease_gain * severity`.
    pub decrease_gain: f64,
}

impl Default for ControllerConfig {
    /// The defaults: 500 kbit/s floor, 100 Mbit/s ceiling (libRIST's
    /// `recovery_maxbitrate`), starting at the ceiling, a 0.5% loss target, a
    /// 1000 kbit/s additive step, and a decrease gain of 8.
    fn default() -> ControllerConfig {
        let max_kbps = 100_000;
        ControllerConfig {
            min_kbps: 500,
            max_kbps,
            initial_kbps: max_kbps,
            target_loss: 0.005,
            increase_kbps: max_kbps / 100,
            decrease_gain: 8.0,
        }
    }
}

/// An additive-increase / multiplicative-decrease encoder rate controller. Each
/// [`Controller::observe_lqm`] (or [`Controller::observe`]) returns a new target
/// bit rate in kbit/s that is monotone in loss. The controller owns no clock and
/// no I/O; it is a pure function of its configuration and the reports it is fed.
#[derive(Debug, Clone)]
pub struct Controller {
    cfg: ControllerConfig,
    /// The current target bit rate, in kbit/s.
    current: u32,
}

impl Controller {
    /// Builds a controller from `cfg`, normalizing it (a `max_kbps` below
    /// `min_kbps` is raised to `min_kbps`) and seeding the target at the clamped
    /// `initial_kbps`.
    #[must_use]
    pub fn new(mut cfg: ControllerConfig) -> Controller {
        if cfg.max_kbps < cfg.min_kbps {
            cfg.max_kbps = cfg.min_kbps;
        }
        let current = clamp_kbps(cfg.initial_kbps, cfg.min_kbps, cfg.max_kbps);
        Controller { cfg, current }
    }

    /// The current target bit rate, in kbit/s.
    #[must_use]
    pub fn current_kbps(&self) -> u32 {
        self.current
    }

    /// Folds one raw loss fraction into the target and returns the new value:
    /// additive increase at or below `target_loss`, else a multiplicative
    /// decrease scaled by the overage (capped at a 90% cut). Negative inputs are
    /// treated as zero.
    pub fn observe(&mut self, loss_fraction: f64) -> u32 {
        let loss = loss_fraction.max(0.0);
        if loss <= self.cfg.target_loss {
            self.increase();
            return self.current;
        }
        self.decrease(self.cfg.decrease_gain * (loss - self.cfg.target_loss));
        self.current
    }

    /// Folds one Link Quality Message into the target using the TR-06-4 Part 1
    /// §6.1 two-signal rule: probe **up** only when no packets went unrecovered
    /// *and* the original loss is at or below `target_loss`; otherwise back
    /// **off**, scaling the cut by the worse of the residual (unrecovered) loss
    /// or the original loss above target. A report with no accounting (all zero)
    /// holds the current target.
    pub fn observe_lqm(&mut self, m: &Lqm) -> u32 {
        if m.source_received == 0 && m.original_lost == 0 && m.unrecovered == 0 {
            return self.current; // no information this period: hold
        }
        let orig_loss = m.loss_fraction();
        if m.unrecovered == 0 && orig_loss <= self.cfg.target_loss {
            self.increase();
            return self.current;
        }
        let severity = m
            .residual_loss_fraction()
            .max(orig_loss - self.cfg.target_loss);
        self.decrease(self.cfg.decrease_gain * severity);
        self.current
    }

    /// Applies the additive increase, clamped to the configured bounds.
    fn increase(&mut self) {
        self.current = clamp_kbps(
            self.current.saturating_add(self.cfg.increase_kbps),
            self.cfg.min_kbps,
            self.cfg.max_kbps,
        );
    }

    /// Applies a multiplicative decrease by `cut` (clamped to `[0, MAX_CUT]`),
    /// then to the configured bounds. Reproduces ristgo's `int(rate * (1 - cut))`
    /// truncation.
    fn decrease(&mut self, cut: f64) {
        let cut = cut.clamp(0.0, MAX_CUT);
        let scaled = (f64::from(self.current) * (1.0 - cut)) as u32;
        self.current = clamp_kbps(scaled, self.cfg.min_kbps, self.cfg.max_kbps);
    }
}

/// Clamps a kbit/s value to `[lo, hi]` (assumes `lo <= hi`).
fn clamp_kbps(v: u32, lo: u32, hi: u32) -> u32 {
    v.clamp(lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ristgo golden Link Quality Message and its exact 44-byte encoding.
    fn golden() -> (Lqm, [u8; LQM_SIZE]) {
        let m = Lqm {
            sequence_number: 1,
            reporting_period_ms: 1000,
            nack_window_ms: 500,
            source_received: 1000,
            original_lost: 10,
            retransmitted_received: 8,
            recovered: 7,
            unrecovered: 3,
            late: 2,
            data_bandwidth_kbps: 5000,
            retransmission_bandwidth_kbps: 120,
        };
        let hex = "00000001000003e8000001f4000003e80000000a00000008000000070000000300000002000013880000\
0078";
        let mut bytes = [0u8; LQM_SIZE];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        (m, bytes)
    }

    #[test]
    fn lqm_golden_bytes() {
        let (m, want) = golden();
        assert_eq!(
            m.encode(),
            want,
            "LQM encoding diverged from the golden bytes"
        );
    }

    #[test]
    fn lqm_round_trip_ignores_trailing() {
        let (m, _) = golden();
        let mut wire = m.encode().to_vec();
        wire.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // trailing bytes ignored
        assert_eq!(Lqm::parse(&wire).unwrap(), m);
    }

    #[test]
    fn lqm_parse_short_errors() {
        for n in 0..LQM_SIZE {
            assert_eq!(Lqm::parse(&vec![0u8; n]), Err(AdaptError::ShortLqm(n)));
        }
        assert!(Lqm::parse(&[0u8; LQM_SIZE]).is_ok());
    }

    #[test]
    #[allow(clippy::float_cmp)] // the empty-LQM branch returns a literal 0.0, exactly
    fn loss_fractions() {
        let m = Lqm {
            source_received: 990,
            original_lost: 10,
            unrecovered: 2,
            ..Lqm::default()
        };
        assert!((m.loss_fraction() - 0.01).abs() < 1e-12);
        assert!((m.residual_loss_fraction() - 0.002).abs() < 1e-12);
        // Empty LQM: both are 0, never NaN.
        let empty = Lqm::default();
        assert_eq!(empty.loss_fraction(), 0.0);
        assert_eq!(empty.residual_loss_fraction(), 0.0);
    }

    #[test]
    fn bandwidth_rounds_to_nearest_kbps() {
        // 625_000 bytes = 5_000_000 bits over 1000 ms = 5000 kbit/s.
        assert_eq!(bandwidth_kbps(625_000, 1000), 5000);
        // 626 bytes * 8 = 5008 bits over 1 ms → 5008 kbit/s (exact).
        assert_eq!(bandwidth_kbps(626, 1), 5008);
        // Half-up rounding: 1 byte = 8 bits over 16 ms → 0.5 → 1 kbit/s.
        assert_eq!(bandwidth_kbps(1, 16), 1);
        // Zero period guards against divide-by-zero.
        assert_eq!(bandwidth_kbps(1000, 0), 0);
    }

    /// A small config for the controller property tests (matches ristgo's
    /// `simCfg`): a low ceiling so probe-up converges quickly.
    fn sim_cfg() -> ControllerConfig {
        ControllerConfig {
            min_kbps: 500,
            max_kbps: 15_000,
            initial_kbps: 15_000,
            target_loss: 0.005,
            increase_kbps: 1_000,
            decrease_gain: 8.0,
        }
    }

    #[test]
    fn observe_is_monotone_in_loss() {
        // For a fixed start, increasing loss never increases the target.
        let losses = [0.0, 0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0];
        let mut prev = u32::MAX;
        for &loss in &losses {
            let mut c = Controller::new(sim_cfg());
            let target = c.observe(loss);
            assert!(
                target <= prev,
                "loss {loss}: target {target} rose above the lower-loss target {prev}"
            );
            prev = target;
        }
    }

    #[test]
    fn observe_probes_up_when_clean() {
        let mut c = Controller::new(ControllerConfig {
            initial_kbps: 500,
            ..sim_cfg()
        });
        let mut last = c.current_kbps();
        // Repeated clean reports strictly increase until the ceiling.
        for _ in 0..100 {
            let t = c.observe(0.0);
            assert!(t >= last);
            last = t;
        }
        assert_eq!(last, sim_cfg().max_kbps, "should converge to the ceiling");
    }

    #[test]
    fn observe_stays_within_bounds() {
        let mut c = Controller::new(sim_cfg());
        // Hammer with alternating heavy loss and clean: always in [min, max].
        for i in 0..2000 {
            let loss = if i % 2 == 0 { 0.9 } else { 0.0 };
            let t = c.observe(loss);
            assert!((sim_cfg().min_kbps..=sim_cfg().max_kbps).contains(&t));
        }
    }

    #[test]
    fn new_normalizes_inverted_bounds() {
        // max < min degenerates to a fixed rate at the floor.
        let mut c = Controller::new(ControllerConfig {
            min_kbps: 10_000,
            max_kbps: 5_000,
            initial_kbps: 8_000,
            ..ControllerConfig::default()
        });
        assert_eq!(c.observe(0.5), 10_000, "inverted bounds pin to the floor");
        assert_eq!(c.observe(0.0), 10_000);
    }

    #[test]
    fn observe_lqm_two_signal_rule() {
        let base = ControllerConfig {
            initial_kbps: 50_000,
            ..ControllerConfig::default()
        };
        // Thin loss (0.1%) but a packet went unrecovered → back off.
        let mut c = Controller::new(base);
        let m = Lqm {
            source_received: 1000,
            original_lost: 1,
            unrecovered: 1,
            ..Lqm::default()
        };
        assert!(c.observe_lqm(&m) < 50_000, "unrecovered loss must back off");

        // Thin loss (0.1%), nothing unrecovered → probe up.
        let mut c = Controller::new(base);
        let m = Lqm {
            source_received: 1000,
            original_lost: 1,
            unrecovered: 0,
            ..Lqm::default()
        };
        assert!(
            c.observe_lqm(&m) > 50_000,
            "clean-enough link must probe up"
        );

        // No accounting at all → hold.
        let mut c = Controller::new(base);
        assert_eq!(
            c.observe_lqm(&Lqm::default()),
            50_000,
            "a stall report holds"
        );
    }

    #[test]
    fn observe_lqm_tracks_capacity_monotonically() {
        // A simple closed loop: a link of fixed capacity drops everything above it,
        // loss rising with the overshoot. The controller's steady-state rate
        // (averaged over the back half, since AIMD oscillates) must sit within a
        // band of capacity and rise with capacity. The additive step scales with
        // capacity so the oscillation amplitude is comparable across links.
        let mut steady = Vec::new();
        for &cap in &[2_000u32, 5_000, 10_000] {
            let mut c = Controller::new(ControllerConfig {
                min_kbps: 100,
                max_kbps: 20_000,
                initial_kbps: 100,
                target_loss: 0.005,
                increase_kbps: (cap / 40).max(50),
                decrease_gain: 8.0,
            });
            let mut rate = c.current_kbps();
            let (mut sum, mut samples) = (0u64, 0u64);
            for step in 0..6000 {
                // Loss appears in proportion to how far the rate exceeds capacity.
                let loss = if rate > cap {
                    f64::from(rate - cap) / f64::from(rate)
                } else {
                    0.0
                };
                rate = c.observe(loss);
                if step >= 3000 {
                    sum += u64::from(rate);
                    samples += 1;
                }
            }
            let avg = (sum / samples) as u32;
            assert!(
                avg >= cap * 6 / 10 && avg <= cap * 14 / 10,
                "capacity {cap}: steady avg rate {avg} outside the [0.6x, 1.4x] band"
            );
            steady.push(avg);
        }
        assert!(
            steady.windows(2).all(|w| w[1] >= w[0]),
            "steady rate must be monotone non-decreasing in capacity: {steady:?}"
        );
    }
}
