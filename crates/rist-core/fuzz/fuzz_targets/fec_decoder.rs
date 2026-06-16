//! Fuzzes the FEC decoder (ristgo internal/fec `FuzzDecoder`): arbitrary media and
//! FEC field input must never panic, and must never FABRICATE a future packet — a
//! forged FEC header must not coerce the decoder into "recovering" a not-yet-sent
//! sequence from attacker-controlled bytes. Every recovered sequence must be at or
//! behind the highest media sequence seen.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rist_core::fec::{Config, Decoder, Direction, Packet, Recovered, Variant};
use rist_core::seq::Seq32;

fuzz_target!(|input: (u32, u16, u16, u16, u8, u32, Vec<u8>, u32, u32, Vec<u8>)| {
    let (base, offset, na, lrec, ptrec, tsrec, fpay, s, ts, mpay) = input;
    let cfg = Config {
        cols: 4,
        rows: 4,
        column_only: false,
        variant: Variant::St20221,
    };
    let mut d = Decoder::new(cfg, 200, 0);

    // Feed one media packet, then one FEC packet (the ristgo order). After the media
    // push, the highest sequence seen is `s`; no recovery may be ahead of it.
    let mut recovered = d.push_media(s, ts, ts as u8, ts, Bytes::from(mpay));
    recovered.extend(d.push_fec(&Packet {
        direction: Direction::Column,
        base,
        offset,
        na,
        length_recovery: lrec,
        pt_recovery: ptrec,
        ts_recovery: tsrec,
        payload: Bytes::from(fpay),
    }));

    no_future(&recovered, s);
});

/// Assert no recovered sequence is ahead of the highest media sequence seen.
fn no_future(recovered: &[Recovered], last: u32) {
    for r in recovered {
        assert!(
            Seq32::new(last).distance(Seq32::new(r.seq)) <= 0,
            "fabricated future packet: recovered {} ahead of last media {}",
            r.seq,
            last
        );
    }
}
