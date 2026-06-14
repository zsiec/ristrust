//! Fuzzes the Link Quality Message codec (ristgo internal/adapt `FuzzParseLQM`):
//! arbitrary bytes must never panic, every LQM that parses must re-encode to the
//! same first 44 bytes, and the loss fractions must always be in `[0, 1]`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rist_codec::adapt::{self, LQM_SIZE};

fuzz_target!(|data: &[u8]| {
    let Ok(m) = adapt::Lqm::parse(data) else {
        return;
    };
    // Re-encoding reproduces the first 44 bytes exactly (trailing bytes ignored).
    assert_eq!(
        m.encode().as_slice(),
        &data[..LQM_SIZE],
        "decode(encode(x)) != x for the first 44 bytes"
    );
    // The loss fractions are well-defined probabilities, never NaN or out of range.
    let loss = m.loss_fraction();
    let residual = m.residual_loss_fraction();
    assert!((0.0..=1.0).contains(&loss), "loss fraction out of range: {loss}");
    assert!(
        (0.0..=1.0).contains(&residual),
        "residual loss fraction out of range: {residual}"
    );
});
