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

/// Microseconds per second, the conversion base between [`Timestamp`] and the
/// NTP fraction.
const US_PER_SECOND: u64 = 1_000_000;

/// A 64-bit NTP-format timestamp (RFC 5905), as carried in RTCP Sender Reports
/// and RIST RTT-echo messages: the upper 32 bits count seconds since the NTP
/// epoch (1900-01-01) and the lower 32 bits hold the fraction of a second in
/// units of 1/2^32 s (~233 ps).
///
/// This is the on-the-wire form of [`MediaPacket::source_time`] and of the RTT
/// echo timestamps: the deterministic core converts a [`Timestamp`] to NTP-64
/// when stamping a packet and back when mapping a received packet's source time
/// into the local clock domain. Conversions are *relative to the same arbitrary
/// epoch* the [`Timestamp`] is built against — RTT echo echoes the value back
/// verbatim, so the epoch cancels. Conversions round to nearest, so a round trip
/// through the coarser microsecond unit is exact; seconds beyond the 32-bit
/// range wrap, matching NTP era semantics (mirrors ristgo's `clock.NTPTime`).
///
/// [`MediaPacket::source_time`]: crate::wire::MediaPacket::source_time
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ntp64(u64);

impl Ntp64 {
    /// Wraps a raw 64-bit NTP value (e.g. one received on the wire).
    #[must_use]
    pub const fn from_bits(bits: u64) -> Ntp64 {
        Ntp64(bits)
    }

    /// The raw 64-bit NTP value, for encoding onto the wire.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// The integer-seconds field (upper 32 bits).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // deliberate: the upper 32 bits
    pub const fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// The fractional-second field (lower 32 bits), in units of 1/2^32 s.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // deliberate: the lower 32 bits
    pub const fn fraction(self) -> u32 {
        self.0 as u32
    }

    /// The middle 32 bits (low 16 of seconds, high 16 of fraction): the compact
    /// form RTCP LSR/DLSR fields carry, with 1/65536 s resolution.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // deliberate: the middle 32 bits
    pub const fn middle32(self) -> u32 {
        (self.0 >> 16) as u32
    }

    /// Converts a [`Timestamp`] (microseconds since its epoch) into NTP-64,
    /// rounding the fraction to nearest. Seconds beyond 2^32 wrap (NTP era).
    #[must_use]
    pub fn from_timestamp(ts: Timestamp) -> Ntp64 {
        let micros = ts.as_micros();
        let sec = micros / US_PER_SECOND;
        let us = micros % US_PER_SECOND;
        // round((us / 1e6) * 2^32). us < 1e6, so `us << 32` < 2^52: no overflow.
        let frac = ((us << 32) + US_PER_SECOND / 2) / US_PER_SECOND;
        // `sec << 32` discards bits above 2^64 — the NTP era wrap, matching the
        // unsigned `sec<<32` in libRIST / ristgo.
        Ntp64((sec << 32) | frac)
    }

    /// Converts back into a [`Timestamp`] (microseconds since the epoch the value
    /// was built against), rounding to the nearest microsecond.
    #[must_use]
    pub fn to_timestamp(self) -> Timestamp {
        let sec = self.0 >> 32;
        let frac = self.0 & 0xFFFF_FFFF;
        let us = (frac * US_PER_SECOND + (1 << 31)) >> 32;
        Timestamp::from_micros(sec * US_PER_SECOND + us)
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

    // --- NTP-64 conversions (golden vectors ported from ristgo clock/ntp_test) ---

    #[test]
    fn ntp_from_timestamp_golden_vectors() {
        // (micros, want_seconds, want_fraction).
        let cases: &[(u64, u32, u32)] = &[
            (0, 0, 0),                   // zero
            (1_000_000, 1, 0),           // one second
            (1_500_000, 1, 0x8000_0000), // one and a half seconds
            (250_000, 0, 0x4000_0000),   // quarter second
            (1, 0, 4295),                // round(1 * 2^32 / 1e6) = 4295
        ];
        for &(micros, want_sec, want_frac) in cases {
            let n = Ntp64::from_timestamp(Timestamp::from_micros(micros));
            assert_eq!(n.seconds(), want_sec, "seconds for {micros} us");
            assert_eq!(n.fraction(), want_frac, "fraction for {micros} us");
        }
    }

    #[test]
    fn ntp_from_timestamp_max_microsecond_fraction() {
        let n = Ntp64::from_timestamp(Timestamp::from_micros(999_999));
        let want = u32::try_from(((999_999u64 << 32) + US_PER_SECOND / 2) / US_PER_SECOND).unwrap();
        assert_eq!(n.fraction(), want);
        assert_eq!(n.seconds(), 0);
    }

    #[test]
    fn ntp_seconds_beyond_32_bits_wrap() {
        // 2^32 s + 0.5 s: the seconds field wraps to zero (NTP era semantics).
        let ts = Timestamp::from_micros((1u64 << 32) * US_PER_SECOND + 500_000);
        let n = Ntp64::from_timestamp(ts);
        assert_eq!(n.seconds(), 0);
        assert_eq!(n.fraction(), 0x8000_0000);
    }

    #[test]
    fn ntp_timestamp_round_trip_is_exact() {
        // Timestamp -> Ntp64 -> Timestamp is exact at microsecond precision (the
        // NTP fraction is ~4295x finer than 1 us and both directions round).
        let secs = [0u64, 1, 77, 4_000_000_000];
        let micros = [
            0u64, 1, 2, 3, 499, 1000, 499_999, 500_000, 500_001, 999_998, 999_999,
        ];
        for sec in secs {
            for us in micros {
                let want = Timestamp::from_micros(sec * US_PER_SECOND + us);
                let got = Ntp64::from_timestamp(want).to_timestamp();
                assert_eq!(got, want, "round trip {sec}s + {us}us");
            }
        }
    }

    #[test]
    fn ntp_field_accessors() {
        let n = Ntp64::from_bits(0x1234_5678_9ABC_DEF0);
        assert_eq!(n.seconds(), 0x1234_5678);
        assert_eq!(n.fraction(), 0x9ABC_DEF0);
        assert_eq!(n.middle32(), 0x5678_9ABC);
        assert_eq!(n.bits(), 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn ntp_middle32_matches_field_composition() {
        for bits in [0u64, 1, 0xCAFE_BABE_1234_5678, 0xFFFF_FFFF_FFFF_FFFF] {
            let n = Ntp64::from_bits(bits);
            let want = (n.seconds() & 0xFFFF) << 16 | n.fraction() >> 16;
            assert_eq!(n.middle32(), want, "middle32 for {bits:#018x}");
        }
    }
}
