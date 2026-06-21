//! Wrap-aware sequence-number arithmetic for 16- and 32-bit sequence spaces.
//!
//! RTP sequence numbers (Simple/Main) are 16-bit and wrap; the Advanced profile
//! and the flow core work in a widened 32-bit space. Both are *circular*: there
//! is no total order, only "is `a` before `b` within half the space". [`Seq16`]
//! and [`Seq32`] provide the operations the protocol needs — `distance`, `less`,
//! `forward_gap` (loss vs wraparound), and modular `add`/`sub` — with the same
//! semantics as ristgo's `internal/seq`, which is fuzzed and validated against
//! libRIST's behavior.
//!
//! Key invariant: `a.add(a.distance(b)) == b` for all `a`, `b`. At exact
//! antipodes (`distance == 2^(N-1)`), both `a.less(b)` and `b.less(a)` are true —
//! a deliberate consequence of circular ordering, matching libRIST.

// Justification: wrap-aware sequence arithmetic is intentionally modular. The
// casts below are deliberate truncations/reinterpretations into and out of the
// sequence width; their ranges are bounded by the modulus by construction.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    // `add`/`sub` take a signed offset and intentionally read like the wrapping
    // operations they are; they are not the `std::ops` traits (which take `Self`).
    clippy::should_implement_trait
)]

/// The largest forward gap a widened 16-bit (Simple/Main) flow interprets as loss
/// rather than wraparound (32768, the half-16-bit-space antipode). Matches the
/// `short_seq` branch of libRIST's `receiver_mark_missing` cap
/// (`short_seq ? UINT16_SIZE/2 : receiver_queue_max/2`); native 32-bit Advanced
/// flows instead scale the cap to half their recovery ring (see `mark_missing`).
pub const MAX_GAP_16: u64 = 1 << 15;

/// The half-32-bit-space antipode (2^31), the 32-bit analog of [`MAX_GAP_16`] for
/// circular ordering.
///
/// NOTE: this is **not** the Advanced missing-packet cap. Since libRIST's
/// 2026-06-20 fix, `receiver_mark_missing` caps a 32-bit flow's gap at
/// `receiver_queue_max/2` — half the recovery ring, not half the sequence space —
/// so `mark_missing` scales to `ring.len()/2`, not this constant.
pub const MAX_GAP_32: u64 = 1 << 31;

macro_rules! define_seq {
    ($name:ident, $inner:ty, $bits:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name($inner);

        impl $name {
            const MOD_I64: i64 = 1i64 << $bits;
            const MOD_U64: u64 = 1u64 << $bits;
            const HALF_U64: u64 = 1u64 << ($bits - 1);

            /// The exact-antipode threshold, `2^(N-1)`.
            pub const HALF: $inner = 1 << ($bits - 1);

            /// The largest forward gap interpreted as loss rather than wraparound.
            pub const MAX_GAP: u64 = 1u64 << ($bits - 1);

            /// Wraps a raw value into a sequence number.
            #[must_use]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            /// The raw underlying value.
            #[must_use]
            pub const fn value(self) -> $inner {
                self.0
            }

            /// The next sequence number, wrapping past the maximum to zero.
            #[must_use]
            pub const fn inc(self) -> Self {
                Self(self.0.wrapping_add(1))
            }

            /// The previous sequence number, wrapping past zero to the maximum.
            #[must_use]
            pub const fn dec(self) -> Self {
                Self(self.0.wrapping_sub(1))
            }

            /// `self + n` modulo `2^N`, for any signed offset.
            #[must_use]
            pub fn add(self, n: i64) -> Self {
                Self(self.0.wrapping_add(n.rem_euclid(Self::MOD_I64) as $inner))
            }

            /// `self - n` modulo `2^N`, for any signed offset.
            #[must_use]
            pub fn sub(self, n: i64) -> Self {
                self.add(n.saturating_neg())
            }

            /// The unsigned raw gap `(other - self) mod 2^N`.
            #[must_use]
            fn raw_gap(self, other: Self) -> u64 {
                u64::from(other.0.wrapping_sub(self.0))
            }

            /// The signed circular distance from `self` to `other`, in
            /// `[-(2^(N-1) - 1), 2^(N-1)]`. Satisfies `self.add(self.distance(o)) == o`.
            #[must_use]
            pub fn distance(self, other: Self) -> i64 {
                let raw = self.raw_gap(other);
                if raw <= Self::HALF_U64 {
                    raw as i64
                } else {
                    raw as i64 - Self::MOD_U64 as i64
                }
            }

            /// Whether `self` is circularly before `other`. At exact antipodes
            /// both `a.less(b)` and `b.less(a)` hold (circular order has no total
            /// antisymmetry there).
            #[must_use]
            pub fn less(self, other: Self) -> bool {
                self.distance(other) > 0
            }

            /// Wrap-aware ordering: `Equal` when identical, else `Less`/`Greater`
            /// by [`Self::less`]. **Not** a total order (antipodes return `Less`
            /// in both directions), so this type deliberately does not implement
            /// [`Ord`].
            #[must_use]
            pub fn wrapping_cmp(self, other: Self) -> core::cmp::Ordering {
                use core::cmp::Ordering;
                if self.0 == other.0 {
                    Ordering::Equal
                } else if self.less(other) {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }

            /// The raw forward gap to `other` and whether it is a plausible loss
            /// gap (`<= MAX_GAP`) rather than a wraparound from a late/old packet.
            #[must_use]
            pub fn forward_gap(self, other: Self) -> (u64, bool) {
                let raw = self.raw_gap(other);
                (raw, raw <= Self::MAX_GAP)
            }
        }
    };
}

define_seq!(
    Seq16,
    u16,
    16,
    "A wrap-aware 16-bit sequence number (RTP; Simple/Main profiles)."
);
define_seq!(
    Seq32,
    u32,
    32,
    "A wrap-aware 32-bit sequence number (the widened space the flow core uses)."
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::cmp::Ordering;

    #[test]
    fn inc_dec_wrap_at_boundary() {
        assert_eq!(Seq16::new(0xFFFF).inc(), Seq16::new(0));
        assert_eq!(Seq16::new(0).dec(), Seq16::new(0xFFFF));
        assert_eq!(Seq32::new(u32::MAX).inc(), Seq32::new(0));
    }

    #[test]
    fn distance_round_trips_through_add() {
        let cases = [
            (10u16, 20u16),
            (0xFFF0, 0x0005),
            (0x0005, 0xFFF0),
            (100, 100),
        ];
        for (a, b) in cases {
            let (a, b) = (Seq16::new(a), Seq16::new(b));
            assert_eq!(a.add(a.distance(b)), b, "add(distance) must recover b");
        }
    }

    #[test]
    fn less_is_wrap_aware() {
        // Across the wrap, 0xFFF0 precedes 0x0005.
        assert!(Seq16::new(0xFFF0).less(Seq16::new(0x0005)));
        assert!(!Seq16::new(0x0005).less(Seq16::new(0xFFF0)));
        // Equal is not "less".
        assert!(!Seq16::new(42).less(Seq16::new(42)));
    }

    #[test]
    fn antipode_is_less_in_both_directions() {
        let a = Seq16::new(0);
        let b = Seq16::new(0x8000); // exact antipode
        assert!(a.less(b));
        assert!(b.less(a));
        assert_eq!(a.wrapping_cmp(b), Ordering::Less);
        assert_eq!(b.wrapping_cmp(a), Ordering::Less);
    }

    #[test]
    fn forward_gap_distinguishes_loss_from_wraparound() {
        // A small forward jump is loss.
        let (gap, forward) = Seq16::new(100).forward_gap(Seq16::new(105));
        assert_eq!(gap, 5);
        assert!(forward);
        // A jump beyond half the space is a wraparound (old/late packet), not loss.
        let (_, forward) = Seq16::new(100).forward_gap(Seq16::new(40_000));
        assert!(!forward);
    }

    #[test]
    fn max_gap_constants_match_half() {
        assert_eq!(Seq16::MAX_GAP, MAX_GAP_16);
        assert_eq!(Seq32::MAX_GAP, MAX_GAP_32);
    }

    // ---- cppcompat golden vectors (ported verbatim from ristgo internal/seq) ----
    //
    // These tables are language-agnostic data validated against libRIST's
    // behavior in the Go sibling; porting them keeps ristrust's wrap-aware
    // arithmetic bit-identical to ristgo's, which is the precondition for the
    // differential and interop gates in later workpackages.

    const MAX16: u16 = 0xFFFF;
    const MAX32: u32 = 0xFFFF_FFFF;
    const HALF16: u16 = Seq16::HALF;
    const HALF32: u32 = Seq32::HALF;

    /// Interesting 16-bit values for boundary scans.
    const B16: [u16; 9] = [
        0,
        1,
        2,
        100,
        HALF16 - 1,
        HALF16,
        HALF16 + 1,
        MAX16 - 1,
        MAX16,
    ];
    /// Interesting 32-bit values for boundary scans.
    const B32: [u32; 9] = [
        0,
        1,
        2,
        100,
        HALF32 - 1,
        HALF32,
        HALF32 + 1,
        MAX32 - 1,
        MAX32,
    ];

    /// Wrap-aware compare mapped to the -1/0/+1 convention of ristgo's `Compare`.
    fn cmp16(a: u16, b: u16) -> i32 {
        match Seq16::new(a).wrapping_cmp(Seq16::new(b)) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    fn cmp32(a: u32, b: u32) -> i32 {
        match Seq32::new(a).wrapping_cmp(Seq32::new(b)) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    #[test]
    fn inc_golden() {
        let c16: &[(u16, u16)] = &[
            (0, 1),
            (1, 2),
            (100, 101),
            (HALF16 - 1, HALF16),
            (HALF16, HALF16 + 1),
            (MAX16 - 1, MAX16),
            (MAX16, 0),
        ];
        for &(input, want) in c16 {
            assert_eq!(Seq16::new(input).inc(), Seq16::new(want), "inc16({input})");
        }
        let c32: &[(u32, u32)] = &[
            (0, 1),
            (HALF32 - 1, HALF32),
            (HALF32, HALF32 + 1),
            (MAX32 - 1, MAX32),
            (MAX32, 0),
        ];
        for &(input, want) in c32 {
            assert_eq!(Seq32::new(input).inc(), Seq32::new(want), "inc32({input})");
        }
    }

    #[test]
    fn dec_golden() {
        let c16: &[(u16, u16)] = &[
            (1, 0),
            (2, 1),
            (HALF16, HALF16 - 1),
            (MAX16, MAX16 - 1),
            (0, MAX16),
        ];
        for &(input, want) in c16 {
            assert_eq!(Seq16::new(input).dec(), Seq16::new(want), "dec16({input})");
        }
        let c32: &[(u32, u32)] = &[(1, 0), (HALF32, HALF32 - 1), (MAX32, MAX32 - 1), (0, MAX32)];
        for &(input, want) in c32 {
            assert_eq!(Seq32::new(input).dec(), Seq32::new(want), "dec32({input})");
        }
    }

    #[test]
    fn add_golden() {
        let c16: &[(u16, i64, u16)] = &[
            (0, 0, 0),
            (0, 1, 1),
            (0, 100, 100),
            (MAX16 - 1, 1, MAX16),
            (MAX16, 1, 0),
            (MAX16 - 5, 10, 4),
            (0, i64::from(MAX16), MAX16),
            (1, i64::from(MAX16), 0),
            (0, 1 << 16, 0),
            (5, 3 << 16, 5),
            (0, -1, MAX16),
            (10, -10, 0),
            (0, -i64::from(HALF16), HALF16),
            (100, -(1 << 16), 100),
        ];
        for &(a, n, want) in c16 {
            assert_eq!(Seq16::new(a).add(n), Seq16::new(want), "add16({a},{n})");
        }
        let c32: &[(u32, i64, u32)] = &[
            (0, 0, 0),
            (0, 1, 1),
            (MAX32 - 1, 1, MAX32),
            (MAX32, 1, 0),
            (MAX32 - 5, 10, 4),
            (0, i64::from(MAX32), MAX32),
            (1, i64::from(MAX32), 0),
            (0, 1 << 32, 0),
            (5, 3 << 32, 5),
            (0, -1, MAX32),
            (10, -10, 0),
            (0, -i64::from(HALF32), HALF32),
            (100, -(1 << 32), 100),
        ];
        for &(a, n, want) in c32 {
            assert_eq!(Seq32::new(a).add(n), Seq32::new(want), "add32({a},{n})");
        }
    }

    #[test]
    fn sub_golden() {
        let c16: &[(u16, i64, u16)] = &[
            (0, 0, 0),
            (1, 1, 0),
            (100, 50, 50),
            (0, 1, MAX16),
            (5, 10, MAX16 - 4),
            (MAX16, i64::from(MAX16), 0),
            (0, 1 << 16, 0),
            (0, -1, 1),
            (MAX16, -1, 0),
        ];
        for &(a, n, want) in c16 {
            assert_eq!(Seq16::new(a).sub(n), Seq16::new(want), "sub16({a},{n})");
        }
        let c32: &[(u32, i64, u32)] = &[
            (0, 0, 0),
            (1, 1, 0),
            (100, 50, 50),
            (0, 1, MAX32),
            (5, 10, MAX32 - 4),
            (MAX32, i64::from(MAX32), 0),
            (0, 1 << 32, 0),
            (0, -1, 1),
            (MAX32, -1, 0),
        ];
        for &(a, n, want) in c32 {
            assert_eq!(Seq32::new(a).sub(n), Seq32::new(want), "sub32({a},{n})");
        }
    }

    #[test]
    fn distance_golden() {
        let c16: &[(u16, u16, i64)] = &[
            (0, 0, 0),
            (100, 100, 0),
            (MAX16, MAX16, 0),
            (0, 1, 1),
            (0, 100, 100),
            (100, 200, 100),
            (1, 0, -1),
            (200, 100, -100),
            (0, HALF16 - 1, 32767),
            (HALF16 - 1, 0, -32767),
            (0, HALF16, 32768),
            (HALF16, 0, 32768),
            (0, HALF16 + 1, -32767),
            (HALF16 + 1, 0, 32767),
            (MAX16, 0, 1),
            (0, MAX16, -1),
            (MAX16 - 5, 5, 11),
            (5, MAX16 - 5, -11),
            (65530, 10, 16),
            (10, 65530, -16),
            (100, 100u16.wrapping_add(HALF16), 32768),
            (100u16.wrapping_add(HALF16), 100, 32768),
        ];
        for &(a, b, want) in c16 {
            assert_eq!(
                Seq16::new(a).distance(Seq16::new(b)),
                want,
                "dist16({a},{b})"
            );
        }
        let c32: &[(u32, u32, i64)] = &[
            (0, 0, 0),
            (MAX32, MAX32, 0),
            (0, 1, 1),
            (1, 0, -1),
            (200, 100, -100),
            (0, HALF32 - 1, 2_147_483_647),
            (HALF32 - 1, 0, -2_147_483_647),
            (0, HALF32, 2_147_483_648),
            (HALF32, 0, 2_147_483_648),
            (0, HALF32 + 1, -2_147_483_647),
            (HALF32 + 1, 0, 2_147_483_647),
            (MAX32, 0, 1),
            (0, MAX32, -1),
            (MAX32 - 5, 5, 11),
            (5, MAX32 - 5, -11),
            (100, 100u32.wrapping_add(HALF32), 2_147_483_648),
        ];
        for &(a, b, want) in c32 {
            assert_eq!(
                Seq32::new(a).distance(Seq32::new(b)),
                want,
                "dist32({a},{b})"
            );
        }
    }

    #[test]
    fn less_golden() {
        let c16: &[(u16, u16, bool)] = &[
            (0, 0, false),
            (100, 100, false),
            (0, 1, true),
            (1, 0, false),
            (100, 200, true),
            (200, 100, false),
            (MAX16, 0, true),
            (0, MAX16, false),
            (MAX16 - 5, 5, true),
            (5, MAX16 - 5, false),
            (0, HALF16 - 1, true),
            (HALF16 - 1, 0, false),
            (0, HALF16, true),
            (HALF16, 0, true),
            (0, HALF16 + 1, false),
            (HALF16 + 1, 0, true),
        ];
        for &(a, b, want) in c16 {
            assert_eq!(Seq16::new(a).less(Seq16::new(b)), want, "less16({a},{b})");
        }
        let c32: &[(u32, u32, bool)] = &[
            (0, 1, true),
            (1, 0, false),
            (MAX32, 0, true),
            (0, MAX32, false),
            (0, HALF32, true),
            (HALF32, 0, true),
            (0, HALF32 + 1, false),
            (HALF32 + 1, 0, true),
        ];
        for &(a, b, want) in c32 {
            assert_eq!(Seq32::new(a).less(Seq32::new(b)), want, "less32({a},{b})");
        }
    }

    #[test]
    fn compare_golden() {
        let c16: &[(u16, u16, i32)] = &[
            (0, 0, 0),
            (MAX16, MAX16, 0),
            (0, 1, -1),
            (1, 0, 1),
            (MAX16, 0, -1),
            (0, MAX16, 1),
            (0, HALF16 - 1, -1),
            (HALF16 - 1, 0, 1),
            (0, HALF16, -1),
            (HALF16, 0, -1),
            (0, HALF16 + 1, 1),
            (HALF16 + 1, 0, -1),
        ];
        for &(a, b, want) in c16 {
            assert_eq!(cmp16(a, b), want, "cmp16({a},{b})");
        }
        let c32: &[(u32, u32, i32)] = &[
            (0, 0, 0),
            (0, 1, -1),
            (1, 0, 1),
            (MAX32, 0, -1),
            (0, MAX32, 1),
            (0, HALF32, -1),
            (HALF32, 0, -1),
            (0, HALF32 + 1, 1),
            (HALF32 + 1, 0, -1),
        ];
        for &(a, b, want) in c32 {
            assert_eq!(cmp32(a, b), want, "cmp32({a},{b})");
        }
    }

    #[test]
    fn forward_gap_golden() {
        // (last, current, gap, forward).
        let c16: &[(u16, u16, u64, bool)] = &[
            (0, 0, 0, true),
            (0, 1, 1, true),
            (0, 5, 5, true),
            (100, 99, 65535, false),
            (100, 90, 65526, false),
            (MAX16, 0, 1, true),
            (MAX16 - 1, 3, 5, true),
            (0, HALF16, u64::from(HALF16), true),
            (0, HALF16 + 1, u64::from(HALF16) + 1, false),
            (0, MAX16, 65535, false),
            (12345, 12345u16.wrapping_add(HALF16), 32768, true),
        ];
        for &(last, current, gap, forward) in c16 {
            assert_eq!(
                Seq16::new(last).forward_gap(Seq16::new(current)),
                (gap, forward),
                "fwd_gap16({last},{current})"
            );
        }
        let c32: &[(u32, u32, u64, bool)] = &[
            (0, 0, 0, true),
            (0, 1, 1, true),
            (100, 99, 4_294_967_295, false),
            (MAX32, 0, 1, true),
            (MAX32 - 1, 3, 5, true),
            (0, HALF32, u64::from(HALF32), true),
            (0, HALF32 + 1, u64::from(HALF32) + 1, false),
            (0, MAX32, 4_294_967_295, false),
            (12345, 12345u32.wrapping_add(HALF32), 1 << 31, true),
        ];
        for &(last, current, gap, forward) in c32 {
            assert_eq!(
                Seq32::new(last).forward_gap(Seq32::new(current)),
                (gap, forward),
                "fwd_gap32({last},{current})"
            );
        }
    }

    #[test]
    fn max_gap_constants_pinned_to_librist() {
        assert_eq!(MAX_GAP_16, 32768);
        assert_eq!(MAX_GAP_32, 2_147_483_648);
        assert_eq!(u64::from(HALF16), MAX_GAP_16);
        assert_eq!(u64::from(HALF32), MAX_GAP_32);
    }

    #[test]
    fn add_sub_round_trip_table() {
        let offsets: [i64; 12] = [
            0,
            1,
            100,
            -1,
            -100,
            32768,
            -32768,
            65535,
            1 << 16,
            1 << 31,
            1 << 32,
            -(1 << 32),
        ];
        for a in B16 {
            for n in offsets {
                assert_eq!(Seq16::new(a).add(n).sub(n), Seq16::new(a), "rt16({a},{n})");
            }
        }
        for a in B32 {
            for n in offsets {
                assert_eq!(Seq32::new(a).add(n).sub(n), Seq32::new(a), "rt32({a},{n})");
            }
        }
    }

    #[test]
    fn sixteen_bit_wrap_sequence_is_monotonic() {
        let mut last = Seq16::new(65530);
        for _ in 0..20 {
            let cur = last.inc();
            assert!(last.less(cur), "stream not monotonic at {}", last.value());
            assert_eq!(last.distance(cur), 1);
            assert_eq!(last.forward_gap(cur), (1, true));
            last = cur;
        }
        assert_eq!(last.value(), 65550u32.wrapping_sub(65536) as u16);
    }

    #[test]
    fn thirty_two_bit_wrap_sequence_is_monotonic() {
        let mut last = Seq32::new(MAX32 - 5);
        for _ in 0..20 {
            let cur = last.inc();
            assert!(last.less(cur));
            assert_eq!(last.distance(cur), 1);
            last = cur;
        }
        assert_eq!(last.value(), 14);
    }

    /// Per-pair distance/compare/forward_gap consistency check (ristgo's
    /// `checkDistance`/`checkCompare`), including the exact-antipode pin.
    fn check_pair16(a: u16, b: u16) {
        let (sa, sb) = (Seq16::new(a), Seq16::new(b));
        assert_eq!(sa.distance(sa), 0);
        let (dab, dba) = (sa.distance(sb), sb.distance(sa));
        if b.wrapping_sub(a) == HALF16 {
            assert_eq!((dab, dba), (i64::from(HALF16), i64::from(HALF16)));
            assert!(sa.less(sb) && sb.less(sa));
            assert_eq!((cmp16(a, b), cmp16(b, a)), (-1, -1));
        } else {
            assert_eq!(dab, -dba, "distance not antisymmetric ({a},{b})");
            if a != b {
                assert_ne!(sa.less(sb), sb.less(sa), "less not antisymmetric ({a},{b})");
                assert_eq!(cmp16(a, b), -cmp16(b, a));
            }
        }
        assert!(dab <= i64::from(HALF16) && dab > -i64::from(HALF16));
        assert_eq!(sa.add(dab), sb, "add(distance) must recover b ({a},{b})");
        assert_eq!(dab > 0, sa.less(sb));
        let (gap, forward) = sa.forward_gap(sb);
        assert_eq!(gap, u64::from(b.wrapping_sub(a)));
        assert_eq!(forward, dab >= 0);
    }

    fn check_pair32(a: u32, b: u32) {
        let (sa, sb) = (Seq32::new(a), Seq32::new(b));
        let (dab, dba) = (sa.distance(sb), sb.distance(sa));
        if b.wrapping_sub(a) == HALF32 {
            assert_eq!((dab, dba), (i64::from(HALF32), i64::from(HALF32)));
            assert!(sa.less(sb) && sb.less(sa));
        } else {
            assert_eq!(dab, -dba);
            if a != b {
                assert_ne!(sa.less(sb), sb.less(sa));
            }
        }
        assert_eq!(sa.add(dab), sb);
        assert_eq!(dab > 0, sa.less(sb));
        let (gap, forward) = sa.forward_gap(sb);
        assert_eq!(gap, u64::from(b.wrapping_sub(a)));
        assert_eq!(forward, dab >= 0);
    }

    #[test]
    fn distance_less_consistency_16_exhaustive() {
        let offsets: [u16; 8] = [0, 1, 2, HALF16 - 1, HALF16, HALF16 + 1, MAX16 - 1, MAX16];
        for a in 0..=MAX16 {
            for off in offsets {
                check_pair16(a, a.wrapping_add(off));
            }
        }
    }

    #[test]
    fn distance_less_consistency_32_boundary_grid() {
        for a in B32 {
            for off in B32 {
                check_pair32(a, a.wrapping_add(off));
            }
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Distance is antisymmetric (modulo the antipode pin), recovers `b`
        /// through `add`, and agrees in sign with `less` — for every 16-bit pair.
        #[test]
        fn distance16_invariants(a in any::<u16>(), b in any::<u16>()) {
            let (sa, sb) = (Seq16::new(a), Seq16::new(b));
            let dab = sa.distance(sb);
            prop_assert!(dab <= i64::from(Seq16::HALF));
            prop_assert!(dab > -i64::from(Seq16::HALF));
            prop_assert_eq!(sa.add(dab), sb);
            prop_assert_eq!(dab > 0, sa.less(sb));
            if b.wrapping_sub(a) != Seq16::HALF {
                prop_assert_eq!(dab, -sb.distance(sa));
            }
        }

        /// The same invariants for every 32-bit pair.
        #[test]
        fn distance32_invariants(a in any::<u32>(), b in any::<u32>()) {
            let (sa, sb) = (Seq32::new(a), Seq32::new(b));
            let dab = sa.distance(sb);
            prop_assert!(dab <= i64::from(Seq32::HALF));
            prop_assert!(dab > -i64::from(Seq32::HALF));
            prop_assert_eq!(sa.add(dab), sb);
            prop_assert_eq!(dab > 0, sa.less(sb));
            if b.wrapping_sub(a) != Seq32::HALF {
                prop_assert_eq!(dab, -sb.distance(sa));
            }
        }

        /// `add` then `sub` of any signed offset is the identity, both widths.
        #[test]
        fn add_sub_round_trips(base in any::<u32>(), n in any::<i64>()) {
            let a16 = Seq16::new(base as u16);
            prop_assert_eq!(a16.add(n).sub(n), a16);
            let a32 = Seq32::new(base);
            prop_assert_eq!(a32.add(n).sub(n), a32);
        }
    }
}
