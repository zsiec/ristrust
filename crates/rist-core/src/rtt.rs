//! Round-trip-time estimation, ported from libRIST's `eight_times_rtt` EWMA.
//!
//! libRIST keeps a premultiplied exponentially-weighted moving average
//! (`eight_times_rtt`, weight 1/8) and, separately, the most recent raw sample
//! (`last_rtt`). The receiver paces NACK retries off the smoothed value; the
//! sender's per-packet retransmit gate uses the *raw last* sample (clamped) so it
//! tracks current RTT rather than a lagging average. [`Estimator`] reproduces both
//! and the exact integer arithmetic, so recovery cadence matches libRIST for
//! interop.

// Justification: `retry_interval` reproduces libRIST's `(uint64_t)(rtt * 1.1)`
// float multiply-and-truncate exactly; the f64 round-trip is deliberate.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::clock::Micros;

/// An immutable RTT estimator. Value type: each [`Estimator::observe`] returns an
/// updated estimator rather than mutating in place, keeping it trivially
/// deterministic and `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimator {
    /// The premultiplied EWMA (`eight_times_rtt`), in microseconds.
    eight_times_rtt: i64,
    /// The most recent raw RTT sample, in microseconds (0 until first observe).
    last_sample: i64,
}

impl Estimator {
    /// A cold-start estimator seeded so [`Estimator::smoothed`] immediately reads
    /// `rtt_min`: `eight_times_rtt = rtt_min * 8` (libRIST `init_peer_settings`).
    #[must_use]
    pub fn new(rtt_min: Micros) -> Estimator {
        Estimator {
            eight_times_rtt: rtt_min.as_micros().saturating_mul(8).max(0),
            last_sample: 0,
        }
    }

    /// Folds one RTT sample into the EWMA and records it as the last raw sample.
    /// Negative samples are pinned to zero, matching libRIST. Arithmetic is
    /// truncating integer division: `etr -= etr/8; etr += sample`.
    #[must_use]
    pub fn observe(self, sample: Micros) -> Estimator {
        let s = sample.as_micros().max(0);
        let etr = self.eight_times_rtt - self.eight_times_rtt / 8 + s;
        Estimator {
            eight_times_rtt: etr,
            last_sample: s,
        }
    }

    /// The smoothed EWMA estimate, `eight_times_rtt / 8` (truncating).
    #[must_use]
    pub fn smoothed(self) -> Micros {
        Micros::from_micros(self.eight_times_rtt / 8)
    }

    /// The smoothed estimate clamped to `[rtt_min, rtt_max]` — the receiver's NACK
    /// retry basis.
    #[must_use]
    pub fn clamped(self, rtt_min: Micros, rtt_max: Micros) -> Micros {
        self.smoothed().clamp_range(rtt_min, rtt_max)
    }

    /// The most recent raw RTT sample (zero before the first observe).
    #[must_use]
    pub fn last(self) -> Micros {
        Micros::from_micros(self.last_sample)
    }

    /// The raw last sample clamped to `[rtt_min, rtt_max]` — the sender's
    /// per-packet retransmit gate uses this (deliberately fresh, not smoothed).
    #[must_use]
    pub fn last_clamped(self, rtt_min: Micros, rtt_max: Micros) -> Micros {
        self.last().clamp_range(rtt_min, rtt_max)
    }

    /// The NACK retry spacing: `clamp(rtt, rtt_min, rtt_max) * 1.1`, reproducing
    /// libRIST's `(uint64_t)(rtt * 1.1)` float multiply-and-truncate.
    #[must_use]
    pub fn retry_interval(self, rtt_min: Micros, rtt_max: Micros) -> Micros {
        let base = self.clamped(rtt_min, rtt_max).as_micros();
        Micros::from_micros((base as f64 * 1.1) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT_MIN: Micros = Micros::from_millis(5);
    const RTT_MAX: Micros = Micros::from_millis(500);

    #[test]
    fn cold_start_reads_rtt_min() {
        let e = Estimator::new(RTT_MIN);
        assert_eq!(e.smoothed(), RTT_MIN);
        assert_eq!(e.clamped(RTT_MIN, RTT_MAX), RTT_MIN);
    }

    #[test]
    fn ewma_converges_toward_samples() {
        let mut e = Estimator::new(RTT_MIN);
        let sample = Micros::from_millis(100);
        for _ in 0..50 {
            e = e.observe(sample);
        }
        // After many identical samples the EWMA sits near the sample value.
        let s = e.smoothed().as_micros();
        assert!((95_000..=100_000).contains(&s), "smoothed was {s} us");
        assert_eq!(e.last(), sample);
    }

    #[test]
    fn retry_interval_is_ten_percent_over_clamped() {
        let e = Estimator::new(RTT_MIN); // clamped == 5 ms
        assert_eq!(
            e.retry_interval(RTT_MIN, RTT_MAX),
            Micros::from_micros(5_500)
        );
    }

    #[test]
    fn negative_samples_are_pinned_to_zero() {
        let e = Estimator::new(RTT_MIN).observe(Micros::from_micros(-1_000));
        assert_eq!(e.last(), Micros::ZERO);
    }
}
