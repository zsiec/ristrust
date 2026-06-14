//! Fuzzes the `add`/`sub` round-trip for both sequence widths (ristgo
//! internal/seq `FuzzAddSub`): adding then subtracting any signed offset is the
//! identity, and never panics, for any starting sequence and any `i64` offset.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rist_core::seq::{Seq16, Seq32};

fuzz_target!(|input: (u32, i64)| {
    let (base, n) = input;
    let a16 = Seq16::new(base as u16);
    assert_eq!(a16.add(n).sub(n), a16);
    let a32 = Seq32::new(base);
    assert_eq!(a32.add(n).sub(n), a32);
});
