//! Time, as the deterministic core understands it.
//!
//! The core never reads a real clock. Instead, every input method takes an
//! explicit `now: Timestamp`, and the host (the only place a real clock lives)
//! supplies it. [`Timestamp`] is an opaque count of microseconds on an arbitrary
//! monotonic epoch — only differences are meaningful — and [`Micros`] is a signed
//! microsecond duration. Mirrors ristgo's `internal/clock` `Timestamp` /
//! `Microseconds` so the port is a close translation and the simulator is a plain
//! `u64` clock.

use std::ops::{Add, Sub};

/// A point in time, as microseconds on an arbitrary monotonic epoch.
///
/// Opaque: only differences (via [`Timestamp::sub`]) carry meaning across the
/// API. The host maps the OS monotonic clock into this domain; tests use a fake
/// clock that is just an increasing `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The zero instant (epoch). Useful as a fake-clock origin in tests.
    pub const ZERO: Timestamp = Timestamp(0);

    /// Builds a timestamp from a raw microsecond count.
    #[must_use]
    pub const fn from_micros(micros: u64) -> Timestamp {
        Timestamp(micros)
    }

    /// Returns the raw microsecond count on the arbitrary epoch.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }
}

impl Add<Micros> for Timestamp {
    type Output = Timestamp;

    /// Advances (or rewinds, for a negative duration) a timestamp, saturating at
    /// the `u64` bounds rather than wrapping.
    fn add(self, rhs: Micros) -> Timestamp {
        let mag = rhs.0.unsigned_abs();
        if rhs.0 >= 0 {
            Timestamp(self.0.saturating_add(mag))
        } else {
            Timestamp(self.0.saturating_sub(mag))
        }
    }
}

// Subtracting a duration is adding its negation; the `+` here is intentional.
#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub<Micros> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Micros) -> Timestamp {
        self + Micros(rhs.0.saturating_neg())
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = Micros;

    /// The signed duration from `rhs` to `self`. Saturates at the `i64` bounds.
    fn sub(self, rhs: Timestamp) -> Micros {
        if self.0 >= rhs.0 {
            Micros(i64::try_from(self.0 - rhs.0).unwrap_or(i64::MAX))
        } else {
            Micros(
                i64::try_from(rhs.0 - self.0)
                    .unwrap_or(i64::MAX)
                    .saturating_neg(),
            )
        }
    }
}

/// A signed duration in microseconds.
///
/// Signed because wrap-aware distances and clock deltas can be negative. Matches
/// ristgo's `clock.Microseconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Micros(i64);

impl Micros {
    /// The zero duration.
    pub const ZERO: Micros = Micros(0);

    /// A duration of `micros` microseconds.
    #[must_use]
    pub const fn from_micros(micros: i64) -> Micros {
        Micros(micros)
    }

    /// A duration of `millis` milliseconds (saturating).
    #[must_use]
    pub const fn from_millis(millis: i64) -> Micros {
        Micros(millis.saturating_mul(1000))
    }

    /// The duration as a raw, signed microsecond count.
    #[must_use]
    pub const fn as_micros(self) -> i64 {
        self.0
    }

    /// The duration in whole milliseconds (truncating toward zero).
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0 / 1000
    }

    /// Clamps the duration to `[min, max]`.
    #[must_use]
    pub fn clamp_range(self, min: Micros, max: Micros) -> Micros {
        Micros(self.0.clamp(min.0, max.0))
    }
}

impl Add for Micros {
    type Output = Micros;

    fn add(self, rhs: Micros) -> Micros {
        Micros(self.0.saturating_add(rhs.0))
    }
}

impl Sub for Micros {
    type Output = Micros;

    fn sub(self, rhs: Micros) -> Micros {
        Micros(self.0.saturating_sub(rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_difference_is_signed() {
        let a = Timestamp::from_micros(1_000);
        let b = Timestamp::from_micros(1_500);
        assert_eq!((b - a), Micros::from_micros(500));
        assert_eq!((a - b), Micros::from_micros(-500));
    }

    #[test]
    fn advancing_and_rewinding_round_trip() {
        let t = Timestamp::from_micros(10_000);
        assert_eq!(t + Micros::from_millis(5), Timestamp::from_micros(15_000));
        assert_eq!(t - Micros::from_millis(5), Timestamp::from_micros(5_000));
        assert_eq!(
            t + Micros::from_micros(-3_000),
            Timestamp::from_micros(7_000)
        );
    }

    #[test]
    fn rewind_saturates_at_zero() {
        let t = Timestamp::from_micros(100);
        assert_eq!(t - Micros::from_micros(1_000), Timestamp::ZERO);
    }

    #[test]
    fn clamp_range_bounds_duration() {
        let lo = Micros::from_millis(5);
        let hi = Micros::from_millis(500);
        assert_eq!(Micros::from_millis(1).clamp_range(lo, hi), lo);
        assert_eq!(Micros::from_millis(900).clamp_range(lo, hi), hi);
        assert_eq!(
            Micros::from_millis(50).clamp_range(lo, hi),
            Micros::from_millis(50)
        );
    }
}
