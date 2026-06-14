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
/// rather than wraparound. libRIST's `receiver_mark_missing` rejects gaps greater
/// than this unconditionally; the flow core pins its loss threshold here.
pub const MAX_GAP_16: u64 = 1 << 15;

/// The 32-bit analog of [`MAX_GAP_16`] (a generalization; libRIST pins all gaps to
/// [`MAX_GAP_16`] — whether native 32-bit Advanced flows use this is decided
/// against libRIST when the Advanced profile lands).
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
}
