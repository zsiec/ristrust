//! Fuzzes the wrap-aware `distance` invariants for both sequence widths
//! (ristgo internal/seq `FuzzDistance16`/`FuzzDistance32`): for any pair,
//! `distance` is bounded by the half-space, recovers `b` through `add`, agrees
//! in sign with `less` and `forward_gap`, and is antisymmetric except at the
//! exact antipode.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rist_core::seq::{Seq16, Seq32};

fuzz_target!(|input: (u16, u16, u32, u32)| {
    let (a16, b16, a32, b32) = input;
    check16(a16, b16);
    check32(a32, b32);
});

fn check16(a: u16, b: u16) {
    let (sa, sb) = (Seq16::new(a), Seq16::new(b));
    assert_eq!(sa.distance(sa), 0);
    let (dab, dba) = (sa.distance(sb), sb.distance(sa));
    if b.wrapping_sub(a) == Seq16::HALF {
        assert_eq!(dab, i64::from(Seq16::HALF));
        assert_eq!(dba, i64::from(Seq16::HALF));
    } else {
        assert_eq!(dab, -dba);
    }
    assert!(dab <= i64::from(Seq16::HALF) && dab >= -i64::from(Seq16::HALF) + 1);
    assert_eq!(sa.add(dab), sb);
    assert_eq!(dab > 0, sa.less(sb));
    let (gap, forward) = sa.forward_gap(sb);
    assert_eq!(gap, u64::from(b.wrapping_sub(a)));
    assert_eq!(forward, dab >= 0);
}

fn check32(a: u32, b: u32) {
    let (sa, sb) = (Seq32::new(a), Seq32::new(b));
    assert_eq!(sa.distance(sa), 0);
    let (dab, dba) = (sa.distance(sb), sb.distance(sa));
    if b.wrapping_sub(a) == Seq32::HALF {
        assert_eq!(dab, i64::from(Seq32::HALF));
        assert_eq!(dba, i64::from(Seq32::HALF));
    } else {
        assert_eq!(dab, -dba);
    }
    assert!(dab <= i64::from(Seq32::HALF) && dab >= -i64::from(Seq32::HALF) + 1);
    assert_eq!(sa.add(dab), sb);
    assert_eq!(dab > 0, sa.less(sb));
    let (gap, forward) = sa.forward_gap(sb);
    assert_eq!(gap, u64::from(b.wrapping_sub(a)));
    assert_eq!(forward, dab >= 0);
}
