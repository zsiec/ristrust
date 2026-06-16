//! The Simple-profile (VSF TR-06-1) codec strategy.
//!
//! This is the narrow-waist translation: it converts between the flow core's
//! normalized [`MediaPacket`] / [`Feedback`] values and on-the-wire RTP and
//! compound RTCP bytes. The flow core only ever sees 32-bit sequence numbers and
//! NTP-64 source times; the 16-bit RTP sequence and the 32-bit 90 kHz RTP
//! timestamp are widened back here (and narrowed on encode), and the retransmit
//! SSRC-LSB toggle is folded into [`MediaPacket::retransmit`].
//!
//! Ported from ristgo `internal/session/codec.go` (the Simple path). The Main and
//! Advanced strategies are added in their workpackages.

// This pure, fully-tested translation layer is built ahead of its consumer: the
// session/driver pump (the next host step) calls it on every datagram. Until then
// it is reachable only from its own tests.
#![allow(dead_code)]

use bytes::Bytes;

use rist_codec::rtcp::{self, Packet as RtcpPacket};
use rist_codec::{adv, crypto, gre, lpc, npd, rtp};
use rist_core::clock::{Ntp64, Timestamp};
use rist_core::wire::{Feedback, MediaPacket};

/// A failure translating between the wire and the narrow waist. Shared by the
/// Simple [`codec`](crate::codec) and Main [`codec_main`](crate::codec_main)
/// strategies; the GRE/crypto/NPD variants only arise on the Main path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum CodecError {
    /// An RTP packet failed to decode.
    #[error("rist: {0}")]
    Rtp(#[from] rtp::RtpError),
    /// A compound RTCP datagram failed to parse.
    #[error("rist: {0}")]
    Rtcp(#[from] rtcp::RtcpError),
    /// An RTP packet carried a version other than 2.
    #[error("rist: rtp version {0}, want 2")]
    BadVersion(u8),
    /// A Main-profile GRE header failed to parse or encode.
    #[error("rist: {0}")]
    Gre(#[from] gre::GreError),
    /// A Main-profile PSK crypto operation failed.
    #[error("rist: {0}")]
    Crypto(#[from] crypto::CryptoError),
    /// A Main-profile NPD suppress/expand operation failed.
    #[error("rist: {0}")]
    Npd(#[from] npd::NpdError),
    /// A Main-profile framing invariant was violated (e.g. an encrypted datagram
    /// arrived with no decryptor configured, or the GRE protocol type was wrong).
    #[error("rist: main: {0}")]
    Main(&'static str),
    /// An Advanced-profile header or control message failed to parse or encode.
    #[error("rist: {0}")]
    Adv(#[from] adv::AdvError),
    /// An Advanced-profile LZ4 compression operation failed.
    #[error("rist: {0}")]
    Lpc(#[from] lpc::LpcError),
    /// An Advanced-profile framing invariant was violated.
    #[error("rist: adv: {0}")]
    AdvProfile(&'static str),
}

/// Converts microseconds to 90 kHz RTP ticks. `90000/1e6 = 9/100`; the `9/100`
/// form keeps the product small enough to never overflow `i64` for any realistic
/// session-relative timestamp.
fn rtp_ticks_from_micros(us: i64) -> i64 {
    us * 9 / 100
}

/// The inverse of [`rtp_ticks_from_micros`].
fn micros_from_rtp_ticks(ticks: i64) -> i64 {
    ticks * 100 / 9
}

/// Maps an NTP-64 source time to the 32-bit 90 kHz RTP timestamp (truncating).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub(crate) fn rtp_ts_from_source(src: u64) -> u32 {
    let us = Ntp64::from_bits(src).to_timestamp().as_micros() as i64;
    rtp_ticks_from_micros(us) as u32
}

/// Encodes a normalized [`MediaPacket`] as a Simple-profile RTP packet. The base
/// (even) SSRC gets its LSB set on a retransmission (the only wire difference for
/// a re-send); the sequence is narrowed to 16 bits and the source time to the
/// 32-bit 90 kHz RTP timestamp.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn encode_media(pkt: &MediaPacket) -> Result<Bytes, CodecError> {
    let ssrc = if pkt.retransmit {
        rtp::mark_retransmit(pkt.ssrc)
    } else {
        pkt.ssrc
    };
    let p = rtp::Packet {
        header: rtp::Header {
            version: rtp::VERSION,
            payload_type: rtp::PAYLOAD_TYPE_MPEGTS,
            sequence_number: pkt.seq as u16,
            timestamp: rtp_ts_from_source(pkt.source_time),
            ssrc,
            ..rtp::Header::default()
        },
        payload: pkt.payload.clone(),
        padding_size: 0,
    };
    Ok(p.encode()?)
}

/// Reconstructs the flow core's 32-bit sequence and NTP-64 source time from a
/// Simple-profile RTP packet's 16-bit sequence and 32-bit timestamp. Stateful
/// (one per receiving flow), reference-anchored at the first packet and resolved
/// to the value nearest the previous packet's thereafter. Within the recovery
/// window neither field can roll, so a retransmit and its original always
/// reconstruct to the same `(seq, source_time)` pair — exactly what the core's
/// duplicate test relies on.
///
/// The reconstructed source time is *dedup-stable* (a wire timestamp always maps
/// to the same value within the window), not a faithful copy of the sender's wall
/// clock: the flow's offset-lock absorbs the absolute difference.
#[derive(Debug, Default)]
pub(crate) struct MediaDecoder {
    started: bool,
    ref_seq: u32,
    ref_ticks: i64,
    /// The raw on-the-wire 32-bit RTP timestamp of the last decoded packet, the
    /// value the FEC XOR is keyed on (the separate-port FEC clips this, not the
    /// reconstructed source time).
    last_wire_ts: u32,
}

impl MediaDecoder {
    /// A fresh decoder for one receiving flow.
    pub(crate) fn new() -> MediaDecoder {
        MediaDecoder::default()
    }

    /// The raw RTP timestamp of the last decoded packet (the FEC timestamp clip).
    pub(crate) fn last_wire_ts(&self) -> u32 {
        self.last_wire_ts
    }

    /// Reconstructs the dedup-stable NTP-64 source time of a FEC-recovered packet
    /// from its recovered RTP timestamp, WITHOUT advancing the decoder's reference
    /// (a recovered sequence is at or behind the in-order front). The mapping is
    /// stable in the wire timestamp within the recovery window, so a recovery and a
    /// later ARQ retransmit / 2022-7 duplicate of the same sequence reconstruct to
    /// the identical `(seq, source_time)` and the flow's dedup absorbs the duplicate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub(crate) fn source_time(&self, wire_ts: u32) -> u64 {
        let ticks = widen_ticks(wire_ts, self.ref_ticks);
        let micros = micros_from_rtp_ticks(ticks).max(0) as u64;
        Ntp64::from_timestamp(Timestamp::from_micros(micros)).bits()
    }

    /// Parses one RTP datagram into the normalized [`MediaPacket`] fed to the
    /// flow core. `payload` is sliced zero-copy from `buf` (the core retains it).
    pub(crate) fn decode(&mut self, buf: &Bytes) -> Result<MediaPacket, CodecError> {
        let p = rtp::Packet::decode(buf)?;
        if p.header.version != rtp::VERSION {
            return Err(CodecError::BadVersion(p.header.version));
        }
        self.last_wire_ts = p.header.timestamp;
        let (seq, source_time) = self.widen(p.header.sequence_number, p.header.timestamp);
        Ok(MediaPacket {
            seq,
            source_time,
            ssrc: rtp::normalize_ssrc(p.header.ssrc),
            payload: p.payload,
            retransmit: rtp::is_retransmit(p.header.ssrc),
            path_id: 0,
            // The Simple profile does not fragment; every payload is whole.
            frag: rist_core::wire::FragRole::Standalone,
        })
    }

    /// Widens a 16-bit RTP sequence and 32-bit timestamp to the flow core's 32-bit
    /// sequence and NTP-64 source time, advancing the decoder's reference state.
    /// Anchored at the first call, resolved nearest the previous value thereafter.
    /// Shared by the Simple [`MediaDecoder::decode`] and the Main strategy (which
    /// applies NPD expansion to the payload before calling this).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub(crate) fn widen(&mut self, seq16: u16, ts32: u32) -> (u32, u64) {
        let (seq32, ticks) = if self.started {
            (
                widen_seq(seq16, self.ref_seq),
                widen_ticks(ts32, self.ref_ticks),
            )
        } else {
            self.started = true;
            (u32::from(seq16), i64::from(ts32))
        };
        self.ref_seq = seq32;
        self.ref_ticks = ticks;
        let micros = micros_from_rtp_ticks(ticks).max(0) as u64;
        let src = Ntp64::from_timestamp(Timestamp::from_micros(micros)).bits();
        (seq32, src)
    }
}

/// Reconstructs a 32-bit sequence from a 16-bit wire value, choosing the
/// interpretation nearest `reference` (the previous widened sequence).
fn widen_seq(wire16: u16, reference: u32) -> u32 {
    let cand = (reference & 0xFFFF_0000) | u32::from(wire16);
    let diff = i64::from(cand) - i64::from(reference);
    if diff > (1 << 15) {
        cand.wrapping_sub(1 << 16)
    } else if diff < -(1 << 15) {
        cand.wrapping_add(1 << 16)
    } else {
        cand
    }
}

/// Reconstructs a 64-bit RTP tick count from a 32-bit wire timestamp, choosing
/// the interpretation nearest `reference` (the previous reconstructed value).
/// Shared with the Advanced strategy, whose 2^16 MHz timestamp wraps every ~65 ms.
pub(crate) fn widen_ticks(wire32: u32, reference: i64) -> i64 {
    let cand = (reference & !0xFFFF_FFFF_i64) | i64::from(wire32);
    let diff = cand - reference;
    if diff > (1 << 31) {
        cand - (1 << 32)
    } else if diff < -(1 << 31) {
        cand + (1 << 32)
    } else {
        cand
    }
}

/// Builds one Simple-profile compound RTCP datagram from the flow's drained
/// feedback effects. `lead` is the mandatory first packet (an empty RR on the
/// receiver, an SR on the sender); SDES/CNAME follows; then NACKs and finally
/// echo packets, satisfying the TR-06-1 §5.2.1 ordering. `local_ssrc` stamps the
/// SDES and originated echo requests; `bitmask` selects the NACK encoding.
pub(crate) fn encode_feedback(
    lead: RtcpPacket,
    local_ssrc: u32,
    cname: &str,
    fbs: &[Feedback],
    bitmask: bool,
) -> Result<Vec<u8>, CodecError> {
    let mut pkts = vec![
        lead,
        RtcpPacket::Sdes(rtcp::Sdes {
            ssrc: local_ssrc,
            cname: cname.to_string(),
        }),
    ];
    let mut nacks = Vec::new();
    let mut echoes = Vec::new();
    for fb in fbs {
        match fb {
            Feedback::Nack { ssrc, missing } => {
                if bitmask {
                    // SenderSSRC is zero: TR-06-1 §5.3.2.1 has the RIST sender
                    // ignore it and libRIST transmits zero, so match that.
                    for p in rtcp::encode_bitmask_nack(0, *ssrc, missing) {
                        nacks.push(RtcpPacket::BitmaskNack(p));
                    }
                } else {
                    for p in rtcp::encode_range_nack(local_ssrc, *ssrc, missing) {
                        nacks.push(RtcpPacket::RangeNack(p));
                    }
                }
            }
            Feedback::RttEchoRequest { timestamp, .. } => {
                // An originated request carries SSRC 0 from the flow; stamp the
                // local SSRC so the peer's response filter accepts our echo.
                echoes.push(RtcpPacket::EchoRequest(rtcp::EchoRequest {
                    ssrc: local_ssrc,
                    timestamp: *timestamp,
                    padding: Bytes::new(),
                }));
            }
            Feedback::RttEchoResponse {
                ssrc,
                timestamp,
                processing_delay,
            } => {
                // Echo the requester's SSRC (captured on decode), not our own.
                echoes.push(RtcpPacket::EchoResponse(rtcp::EchoResponse {
                    ssrc: *ssrc,
                    timestamp: *timestamp,
                    processing_delay: *processing_delay,
                    padding: Bytes::new(),
                }));
            }
            // SR (the lead), Keepalive, ExtSeq, and LinkQuality are not flow
            // feedback effects on the Simple wire; the flow never emits them here.
            // FlowAttribute is Advanced-only — the Simple wire has no such message.
            Feedback::SenderReport { .. }
            | Feedback::Keepalive
            | Feedback::ExtSeq { .. }
            | Feedback::LinkQuality { .. }
            | Feedback::FlowAttribute { .. } => {}
        }
    }
    pkts.extend(nacks);
    pkts.extend(echoes);

    let mut dst = Vec::with_capacity(rtcp::compound_marshal_size(&pkts));
    rtcp::build_compound(&mut dst, &pkts)?;
    Ok(dst)
}

/// Parses a compound RTCP datagram into the normalized feedback the flow core
/// consumes. NACK sequences arrive 16-bit on the wire and are widened to 32 bits
/// nearest-at-most `nack_ref` (the sender's current send position) so they match
/// the sender's history keys. SR/RR/SDES are dropped — the core has no use for
/// them this stage.
pub(crate) fn decode_feedback(b: &[u8], nack_ref: u32) -> Result<Vec<Feedback>, CodecError> {
    let pkts = rtcp::parse_compound(b)?;
    let mut out = Vec::new();
    for p in &pkts {
        match p {
            RtcpPacket::RangeNack(pk) => {
                out.push(nack_to_wire(pk.media_ssrc, &pk.missing_seqs(), nack_ref));
            }
            RtcpPacket::BitmaskNack(pk) => {
                out.push(nack_to_wire(pk.media_ssrc, &pk.missing_seqs(), nack_ref));
            }
            RtcpPacket::EchoRequest(pk) => out.push(Feedback::RttEchoRequest {
                ssrc: pk.ssrc,
                timestamp: pk.timestamp,
            }),
            RtcpPacket::EchoResponse(pk) => out.push(Feedback::RttEchoResponse {
                ssrc: pk.ssrc,
                timestamp: pk.timestamp,
                processing_delay: pk.processing_delay,
            }),
            RtcpPacket::LinkQualityReport(pk) => out.push(Feedback::LinkQuality { lqm: pk.lqm }),
            // Reports, SDES, EXTSEQ, foreign (Raw), and any future packet type are
            // not flow input. (rtcp::Packet is #[non_exhaustive], so a wildcard is
            // required; new variants default to "ignored" here by design.)
            _ => {}
        }
    }
    Ok(out)
}

/// Widens a NACK's 16-bit sequence list to the sender's 32-bit space. A NACK only
/// ever requests a sequence at or before the sender's send position, so each is
/// widened to the value at most `nack_ref` — this resolves the full 2^16 history
/// ring, where the symmetric "nearest" rule would mis-map a sequence more than
/// 2^15 behind the cursor.
#[allow(clippy::cast_possible_truncation)]
fn nack_to_wire(ssrc: u32, narrow: &[u32], nack_ref: u32) -> Feedback {
    let missing = narrow
        .iter()
        .map(|&s| widen_seq_at_most(s as u16, nack_ref))
        .collect();
    Feedback::Nack { ssrc, missing }
}

/// Reconstructs the 32-bit sequence with low 16 bits `wire16` that is greatest
/// while still `<= reference`. Used for NACK sequences, never in the future
/// relative to the sender's send position.
pub(crate) fn widen_seq_at_most(wire16: u16, reference: u32) -> u32 {
    let cand = (reference & 0xFFFF_0000) | u32::from(wire16);
    if cand > reference {
        cand.wrapping_sub(1 << 16)
    } else {
        cand
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_codec::rtcp::{EmptyReceiverReport, Packet as RtcpPacket};

    fn media(seq: u32, source_time: u64, ssrc: u32, retransmit: bool) -> MediaPacket {
        MediaPacket {
            seq,
            source_time,
            ssrc,
            payload: Bytes::from_static(&[0x47, 0x01, 0x02, 0x03]),
            retransmit,
            path_id: 0,
            frag: rist_core::wire::FragRole::Standalone,
        }
    }

    #[test]
    fn media_round_trip_preserves_seq_ssrc_payload_and_retransmit() {
        let src = Ntp64::from_timestamp(Timestamp::from_micros(1_000_000)).bits();
        let mut dec = MediaDecoder::new();
        for (seq, retransmit) in [(1000u32, false), (1001, false), (1001, true)] {
            let pkt = media(seq, src, 0x0ACE_0AC0, retransmit);
            let wire = encode_media(&pkt).unwrap();
            let got = dec.decode(&wire).unwrap();
            assert_eq!(got.seq, seq, "seq");
            assert_eq!(got.ssrc, 0x0ACE_0AC0, "normalized ssrc");
            assert_eq!(got.retransmit, retransmit, "retransmit flag");
            assert_eq!(got.payload, pkt.payload, "payload");
        }
    }

    #[test]
    fn retransmit_sets_ssrc_lsb_on_the_wire() {
        let pkt = media(5, 0, 0x0ACE_0AC0, true);
        let wire = encode_media(&pkt).unwrap();
        // Decode raw to inspect the wire SSRC (odd = retransmit-marked).
        let raw = rtp::Packet::decode(&wire).unwrap();
        assert_eq!(raw.header.ssrc, 0x0ACE_0AC1);
        assert!(rtp::is_retransmit(raw.header.ssrc));
    }

    #[test]
    fn seq_widening_across_the_16_bit_wrap() {
        // A contiguous stream crossing 0xFFFF -> 0x0000 must widen monotonically.
        let src = Ntp64::from_timestamp(Timestamp::from_micros(5_000)).bits();
        let mut dec = MediaDecoder::new();
        let mut last = None;
        for i in 0..10u32 {
            let seq16 = 0xFFFBu32.wrapping_add(i); // 0xFFFB..0x0004
            let pkt = media(seq16, src, 0x0ACE_0AC0, false);
            let got = dec.decode(&encode_media(&pkt).unwrap()).unwrap();
            if let Some(prev) = last {
                assert_eq!(got.seq, prev + 1, "widened seq must increment by 1");
            }
            last = Some(got.seq);
        }
    }

    #[test]
    fn ticks_widening_across_the_32_bit_wrap() {
        // The 32-bit RTP timestamp wraps (~13 h at 90 kHz). The codec reconstructs
        // a MONOTONIC 64-bit tick count across the wrap, so the flow's source-time→
        // local-time offset (locked once at the first packet) stays valid for the
        // life of the stream — ristrust handles the source-clock wrap at the codec
        // waist, not via a flow re-anchor. A contiguous stream crossing
        // 0xFFFF_FFFF -> 0x0000_0000 must never step backward.
        let mut reference: i64 = 0xFFFF_FFF0;
        let mut prev = reference;
        let start = reference;
        for i in 0..32u32 {
            let wire = 0xFFFF_FFF0u32.wrapping_add(i); // 0xFFFF_FFF0 .. 0x0000_000F
            let widened = widen_ticks(wire, reference);
            assert!(
                widened >= prev,
                "ticks must be monotonic across the wrap: {prev} -> {widened}"
            );
            prev = widened;
            reference = widened;
        }
        // The reconstruction crossed 2^32 exactly once (no false extra wrap).
        assert_eq!(
            prev - start,
            31,
            "exactly the 31 contiguous steps, wrap absorbed"
        );
        assert!(prev >= (1i64 << 32), "the 64-bit value carried past 2^32");
    }

    #[test]
    fn widen_seq_at_most_resolves_the_full_history_ring() {
        // A NACK for a sequence far behind the cursor must widen below it.
        let cursor = 0x0001_0005u32; // sent up to here
        assert_eq!(widen_seq_at_most(0x0005, cursor), 0x0001_0005);
        assert_eq!(widen_seq_at_most(0x0004, cursor), 0x0001_0004);
        // A wire value that would be "ahead" maps to the previous epoch.
        assert_eq!(widen_seq_at_most(0xFFFF, cursor), 0x0000_FFFF);
    }

    #[test]
    fn feedback_round_trip_nack_range_and_bitmask() {
        let nack = Feedback::Nack {
            ssrc: 0x0ACE_0AC0,
            missing: vec![0x0001_0005, 0x0001_0006, 0x0001_0007, 0x0001_0010],
        };
        let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: 0x0ACE_0AC0 });
        for bitmask in [false, true] {
            let wire = encode_feedback(
                lead.clone(),
                0x0ACE_0AC0,
                "rust",
                std::slice::from_ref(&nack),
                bitmask,
            )
            .unwrap();
            let got = decode_feedback(&wire, 0x0001_0010).unwrap();
            assert_eq!(got.len(), 1, "one NACK back (bitmask={bitmask})");
            let Feedback::Nack { ssrc, missing } = &got[0] else {
                panic!("want a Nack, got {:?}", got[0]);
            };
            assert_eq!(*ssrc, 0x0ACE_0AC0);
            assert_eq!(
                missing,
                &vec![0x0001_0005, 0x0001_0006, 0x0001_0007, 0x0001_0010]
            );
        }
    }

    #[test]
    fn feedback_round_trip_echo_request_and_response() {
        let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: 0x0ACE_0AC0 });
        // An originated request (ssrc 0) gets the local ssrc stamped on the wire.
        let req = Feedback::RttEchoRequest {
            ssrc: 0,
            timestamp: 0xDEAD_BEEF,
        };
        let wire = encode_feedback(lead.clone(), 0x0ACE_0AC0, "r", &[req], false).unwrap();
        let got = decode_feedback(&wire, 0).unwrap();
        assert_eq!(
            got,
            vec![Feedback::RttEchoRequest {
                ssrc: 0x0ACE_0AC0,
                timestamp: 0xDEAD_BEEF
            }]
        );

        // A response echoes the requester's ssrc verbatim.
        let resp = Feedback::RttEchoResponse {
            ssrc: 0x1234_5678,
            timestamp: 0xCAFE,
            processing_delay: 1500,
        };
        let wire =
            encode_feedback(lead, 0x0ACE_0AC0, "r", std::slice::from_ref(&resp), false).unwrap();
        let got = decode_feedback(&wire, 0).unwrap();
        assert_eq!(got, vec![resp]);
    }

    #[test]
    fn decode_feedback_ignores_reports_and_sdes() {
        // A bare empty RR + SDES (no feedback) decodes to nothing.
        let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: 1 });
        let wire = encode_feedback(lead, 1, "x", &[], false).unwrap();
        assert!(decode_feedback(&wire, 0).unwrap().is_empty());
    }
}
