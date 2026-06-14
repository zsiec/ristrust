//! Fuzzes the RTCP compound codec (ristgo internal/rtcp `FuzzParseCompound`):
//! arbitrary bytes must never panic, and every compound that parses must
//! re-encode each typed packet to bytes that re-parse to an identical value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rist_codec::rtcp::{self, Packet};

fuzz_target!(|data: &[u8]| {
    let Ok(pkts) = rtcp::parse_compound(data) else {
        return;
    };
    for pkt in &pkts {
        // Every parsed packet (including Raw) re-encodes and re-parses stably.
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), pkt.marshal_size(), "marshal_size disagrees with encode");
        let (reparsed, n) = rtcp::parse(&bytes).expect("re-encoded packet must parse");
        assert_eq!(n, bytes.len(), "re-parse did not consume the whole packet");
        // A Raw round-trips to Raw with identical bytes; typed packets to the
        // same value.
        match (pkt, &reparsed) {
            (Packet::Raw(a), Packet::Raw(b)) => assert_eq!(a, b),
            _ => assert_eq!(pkt, &reparsed, "decode(encode(x)) != x"),
        }
    }
});
