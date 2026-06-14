//! Fuzzes the RTP codec (ristgo internal/rtp `FuzzPacketUnmarshal`): arbitrary
//! bytes must never panic, and every packet that decodes must re-encode and
//! re-decode to an identical value, byte-stably.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rist_codec::rtp::Packet;

fuzz_target!(|data: &[u8]| {
    let buf = Bytes::copy_from_slice(data);
    if let Ok(pkt) = Packet::decode(&buf) {
        let encoded = pkt.encode().expect("a decoded packet must re-encode");
        let redecoded = Packet::decode(&encoded).expect("re-encoded bytes must decode");
        assert_eq!(redecoded, pkt, "decode(encode(x)) != x");
        let reencoded = redecoded.encode().expect("re-encode must succeed");
        assert_eq!(reencoded, encoded, "re-encode is not byte-stable");
    }
});
