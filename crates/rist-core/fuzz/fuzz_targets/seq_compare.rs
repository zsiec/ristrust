//! Fuzzes the `less` / `wrapping_cmp` invariants for both sequence widths
//! (ristgo internal/seq `FuzzCompare16`/`FuzzCompare32`): the order is
//! irreflexive, its sign agrees with `wrapping_cmp`, and it is antisymmetric and
//! total over each pair — except at the exact antipode, where both directions
//! are deliberately pinned `Less`.
#![no_main]

use core::cmp::Ordering;
use libfuzzer_sys::fuzz_target;
use rist_core::seq::{Seq16, Seq32};

fuzz_target!(|input: (u16, u16, u32, u32)| {
    let (a16, b16, a32, b32) = input;
    check16(a16, b16);
    check32(a32, b32);
});

fn check16(a: u16, b: u16) {
    let (sa, sb) = (Seq16::new(a), Seq16::new(b));
    assert!(!sa.less(sa));
    assert_eq!(sa.wrapping_cmp(sa), Ordering::Equal);
    let (lab, lba) = (sa.less(sb), sb.less(sa));
    if b.wrapping_sub(a) == Seq16::HALF {
        assert!(lab && lba);
        assert_eq!(sa.wrapping_cmp(sb), Ordering::Less);
        assert_eq!(sb.wrapping_cmp(sa), Ordering::Less);
    } else if a == b {
        assert!(!lab && !lba);
    } else {
        assert_ne!(lab, lba);
        assert_eq!(sa.wrapping_cmp(sb), sb.wrapping_cmp(sa).reverse());
    }
}

fn check32(a: u32, b: u32) {
    let (sa, sb) = (Seq32::new(a), Seq32::new(b));
    assert!(!sa.less(sa));
    assert_eq!(sa.wrapping_cmp(sa), Ordering::Equal);
    let (lab, lba) = (sa.less(sb), sb.less(sa));
    if b.wrapping_sub(a) == Seq32::HALF {
        assert!(lab && lba);
        assert_eq!(sa.wrapping_cmp(sb), Ordering::Less);
        assert_eq!(sb.wrapping_cmp(sa), Ordering::Less);
    } else if a == b {
        assert!(!lab && !lba);
    } else {
        assert_ne!(lab, lba);
        assert_eq!(sa.wrapping_cmp(sb), sb.wrapping_cmp(sa).reverse());
    }
}
