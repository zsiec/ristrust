//! Fuzzes the FEC header codec (ristgo internal/fec `FuzzParseHeader` /
//! `FuzzParseHeader5`): arbitrary bytes must never panic when decoded as either
//! variant, and a decoded header is a stable fixpoint —
//! `decode(encode(decode(x))) == decode(x)` (the first decode drops the reserved
//! and E/M flag bits, so the canonical re-encoding re-decodes identically).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rist_codec::fec_header::{decode, encode};
use rist_core::fec::Variant;

fuzz_target!(|data: &[u8]| {
    for variant in [Variant::St20221, Variant::St20225] {
        let Ok(p) = decode(data, variant) else {
            continue;
        };
        let reencoded = encode(&p, variant);
        let p2 = decode(&reencoded, variant).expect("a re-encoded FEC header must decode");
        assert_eq!(p, p2, "decode(encode(decode(x))) != decode(x)");
    }
});
