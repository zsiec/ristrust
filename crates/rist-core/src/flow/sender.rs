//! The sender half of the flow core: sequence assignment + first-transmission
//! emission, the retransmit history ring, NACK servicing through the per-packet
//! RTT gate (the raw last sample clamped, *not* the EWMA — see [`rtt`]), retry
//! exhaustion accounting, and RTT echo origination.
//!
//! Ported from ristgo `internal/flow/sender.go`, which follows libRIST's
//! `rist_sender_enqueue` / `rist_retry_enqueue` / `rist_retry_dequeue`. The base
//! SSRC is stamped even; the codec sets the retransmit LSB, never the core.
//!
//! [`rtt`]: crate::rtt

// Justification: the history ring is indexed by `seq & mask`; the cast to a ring
// index (`usize`) is bounded by the ring size by construction.
#![allow(clippy::cast_possible_truncation)]

use super::congestion::{BitrateEwma, CongestionMode, over_budget, wire_bytes};
use super::{Flow, Output, RTT_ECHO_INTERVAL, TimerId};
use crate::clock::{Ntp64, Timestamp};
use crate::wire::{Feedback, FragRole, MediaPacket};
use bytes::Bytes;

/// The occupancy state of one history slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SlotState {
    /// No packet stored in this slot.
    #[default]
    Empty,
    /// A transmitted packet is stored in this slot, available to re-send.
    Filled,
}

/// One entry of the sender history ring: a transmitted packet retained so it can
/// be re-sent on NACK. Mirrors the libRIST `rist_buffer` retransmit fields
/// (seq_rtp, source_time, transmit_count, last_retry_request).
#[derive(Debug, Clone, Default)]
struct SenderSlot {
    /// The retained media payload, re-sent verbatim on retransmit (zero-copy;
    /// the producer must not mutate it after `push_app`).
    payload: Bytes,
    /// The NTP-64 media timestamp stamped at first send and repeated unchanged on
    /// every retransmit, so the receiver maps a recovered packet onto its
    /// original playout slot.
    source_time: u64,
    /// The 32-bit sequence occupying this slot; a NACK whose seq does not match
    /// means the entry aged out (the ring wrapped) and the request is
    /// unserviceable.
    seq: u32,
    /// The number of retransmissions so far (the first transmission is not
    /// counted). Abandoned once it reaches `max_retries`.
    transmit_count: u32,
    /// The instant of the most recent retransmission; the gate suppresses another
    /// within one clamped RTT. Meaningful only when `retried` is true.
    last_retry: Timestamp,
    /// Whether `last_retry` has been set (libRIST's `last_retry_request != 0`
    /// guard): the first retransmit is never gated.
    retried: bool,
    /// The fragment role, repeated unchanged on every retransmit so a recovered
    /// fragment reassembles in its original run.
    frag: FragRole,
    /// `Empty` or `Filled`.
    state: SlotState,
}

/// The sender half's mutable state.
pub(super) struct SenderState {
    /// The retransmit-history ring (`seq & mask`). Length is a power of two.
    ring: Box<[SenderSlot]>,
    /// `ring.len() - 1`, the index mask.
    mask: u32,
    /// Whether the first `push_app` has armed the RTT-echo schedule.
    started: bool,
    /// The base (even) flow SSRC stamped into every outgoing packet; the codec
    /// sets its LSB on retransmissions, never the core.
    ssrc: u32,
    /// The 32-bit sequence assigned to the next `push_app` packet, incrementing
    /// by one per packet.
    next_seq: u32,
    /// The network path first transmissions and retransmissions leave on (always
    /// 0 this stage; multi-path transmission is bonding's job).
    pub(super) tx_path: u8,
    /// The `recovery_maxbitrate` pacing EWMAs (libRIST `cli_bw` / `retry_bw`):
    /// `data_bw` is fed every first transmission, `retry_bw` every retransmission.
    data_bw: BitrateEwma,
    retry_bw: BitrateEwma,
}

impl SenderState {
    /// Allocates a sender state with a `ring_size`-slot history ring.
    pub(super) fn new(ring_size: usize, ssrc: u32, start_seq: u32) -> SenderState {
        SenderState {
            ring: vec![SenderSlot::default(); ring_size].into_boxed_slice(),
            mask: (ring_size - 1) as u32,
            started: false,
            ssrc,
            next_seq: start_seq,
            tx_path: 0,
            data_bw: BitrateEwma::default(),
            retry_bw: BitrateEwma::default(),
        }
    }

    /// A sender state with a minimal ring, for a receiver-role flow (it never
    /// transmits media, so a full ring would only waste memory).
    pub(super) fn empty() -> SenderState {
        SenderState::new(1, 0, 0)
    }
}

impl std::fmt::Debug for SenderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderState")
            .field("started", &self.started)
            .field("ring_len", &self.ring.len())
            .field("ssrc", &self.ssrc)
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

impl Flow {
    /// The sender-role body of [`Flow::push_app`]/[`Flow::push_app_frag`]: assign
    /// the next sequence, store the packet (and its fragment role) in the history
    /// ring, and emit its first transmission (libRIST `rist_sender_enqueue` followed
    /// by the data send).
    pub(crate) fn send_push_app(&mut self, now: Timestamp, payload: Bytes, frag: FragRole) {
        self.send_push_app_block(now, payload, frag, None, None);
    }

    /// As [`Flow::send_push_app`], but with an optional explicit sequence number and/or
    /// source timestamp (libRIST's `RIST_DATA_FLAGS_USE_SEQ` + `ts_ntp`). `seq` of
    /// `None` takes the next auto-incremented sequence; `source_time` of `None` derives
    /// it from `now`. When `seq` is supplied the auto counter is advanced past it so a
    /// later auto-sequenced send cannot collide. A transparent relay uses this to
    /// preserve an upstream flow's `(seq, source_time)` on the re-sent copy.
    pub(crate) fn send_push_app_block(
        &mut self,
        now: Timestamp,
        payload: Bytes,
        frag: FragRole,
        seq: Option<u32>,
        source_time: Option<u64>,
    ) {
        if !self.sender.started {
            self.sender.started = true;
            // Originate RTT echo requests so the retransmit gate has a real RTT.
            // libRIST gates origination on `peer->echo_enabled`, which flips true
            // only after an inbound echo; the deterministic core has no such
            // precondition, so origination is intentionally ungated. End-to-end
            // this matches libRIST, whose receiver originates echoes
            // unconditionally and flips the sender's `echo_enabled` within one
            // cadence. A no-recovery (one-way) transport has no return channel, so
            // there is no RTT to measure and no retransmits to gate: no echo.
            if !self.cfg.no_recovery {
                self.outputs.push_back(Output::SetTimer {
                    id: TimerId::RttEcho,
                    deadline: now + RTT_ECHO_INTERVAL,
                });
            }
        }

        // An explicit (USE_SEQ) sequence is used verbatim, then the auto counter is
        // advanced past it so a subsequent auto-sequenced send cannot collide; an
        // absent override takes and advances the counter as usual.
        let seqn = seq.unwrap_or(self.sender.next_seq);
        self.sender.next_seq = seqn.wrapping_add(1);
        let source_time = source_time.unwrap_or_else(|| Ntp64::from_timestamp(now).bits());
        let payload_len = payload.len();
        let wire_n = wire_bytes(payload_len);

        // A no-recovery (one-way) transport never retransmits, so retaining the
        // packet in the history ring would only waste memory: emit and forget. A
        // later (stray) NACK finds an empty slot and is reported unserviceable.
        if !self.cfg.no_recovery {
            let idx = (seqn & self.sender.mask) as usize;
            // Lazy eviction: a new sequence reusing this slot overwrites the stale
            // entry, exactly as libRIST's ring overwrites aged packets. A later
            // NACK for the overwritten sequence finds a mismatched slot and is
            // reported unserviceable.
            let sl = &mut self.sender.ring[idx];
            sl.state = SlotState::Filled;
            sl.seq = seqn;
            sl.source_time = source_time;
            sl.payload = payload.clone();
            sl.transmit_count = 0;
            sl.retried = false;
            sl.last_retry = Timestamp::ZERO;
            sl.frag = frag;
        }

        let ssrc = self.sender.ssrc;
        let tx_path = self.sender.tx_path;
        self.outputs.push_back(Output::SendMedia {
            path: tx_path,
            pkt: MediaPacket {
                seq: seqn,
                source_time,
                ssrc,
                payload,
                retransmit: false,
                path_id: tx_path,
                frag,
                // The sending codec encodes the configured virtual ports; the waist
                // carries them only on the receive path (per-packet decode).
                virt_src_port: 0,
                virt_dst_port: 0,
            },
        });
        self.sender.data_bw.feed(now, wire_n); // recovery_maxbitrate data-rate EWMA
        self.stats.sent += 1;
        self.stats.sent_bytes += payload_len as u64;
    }

    /// The sender's smoothed first-transmission bit rate (bits/sec, 1 s window) for
    /// the [`Stats`](crate::flow::Stats) `data_bitrate_bps` gauge. 0 on a receiver
    /// flow (the data-rate EWMA is never fed).
    pub(crate) fn data_bitrate_bps(&self) -> i64 {
        self.sender.data_bw.slow_bps()
    }

    /// The sender's smoothed retransmission bit rate (bits/sec, 1 s window) for the
    /// `retry_bitrate_bps` gauge. 0 on a receiver flow.
    pub(crate) fn retry_bitrate_bps(&self) -> i64 {
        self.sender.retry_bw.slow_bps()
    }

    /// Retransmits every requested sequence still resendable, applying the
    /// libRIST sender gates in libRIST's own evaluation order
    /// (`rist_retry_dequeue`): the RTT/bloat suppression gate, then the
    /// `recovery_maxbitrate` bandwidth cap, then the max-retries cap:
    ///
    /// - slot empty or a different seq → aged out (`retransmit_skipped`);
    /// - last retransmit < one clamped RTT ago → suppressed
    ///   (`retransmit_suppressed`);
    /// - emitting would exceed `recovery_maxbitrate` under the active congestion
    ///   mode → withheld WITHOUT advancing retry state (`bandwidth_skipped`), so
    ///   the entry stays resendable and is re-NACKed;
    /// - `transmit_count >= max_retries` → abandoned (`retransmit_exhausted`);
    /// - otherwise → re-send with `retransmit` set.
    ///
    /// The bandwidth cap precedes the max-retries cap so a sequence that is both
    /// over budget and past its retry budget is counted as a bandwidth skip,
    /// matching libRIST (which returns on the rate check before it touches
    /// `transmit_count`). The gate clamps the most recent **raw** RTT sample
    /// (libRIST `peer->last_rtt`), deliberately fresher than the EWMA the receiver
    /// uses for its retry interval (see [`rtt`](crate::rtt)). The requested SSRC is
    /// ignored: the host demuxes feedback to this flow before it arrives.
    pub(crate) fn service_nack(&mut self, now: Timestamp, missing: Vec<u32>) {
        let mut rtt = self.est.last_clamped(self.cfg.rtt_min, self.cfg.rtt_max);
        // Aggressive congestion control spaces retransmits at 2×RTT (libRIST doubles
        // the suppression spacing under AGGRESSIVE); NORMAL keeps the 1×RTT gate.
        if self.cfg.congestion_control == CongestionMode::Aggressive {
            rtt = rtt + rtt;
        }
        let tx_path = self.sender.tx_path;
        let base_ssrc = self.sender.ssrc;
        let mode = self.cfg.congestion_control;
        let max_kbps = self.cfg.recovery_maxbitrate;
        let max_nacks = self.max_nacks_per_loop;
        // Decay the bitrate windows so a stale-but-high estimate falls even when no
        // new bytes have flowed since the last pass (libRIST refreshes with len 0 at
        // the top of rist_retry_dequeue).
        self.sender.data_bw.feed(now, 0);
        self.sender.retry_bw.feed(now, 0);
        let mut emitted = 0u32;
        for m in missing {
            let idx = (m & self.sender.mask) as usize;
            let (filled, slot_seq, retried, last_retry, transmit_count) = {
                let sl = &self.sender.ring[idx];
                (
                    sl.state == SlotState::Filled,
                    sl.seq,
                    sl.retried,
                    sl.last_retry,
                    sl.transmit_count,
                )
            };
            if !filled || slot_seq != m {
                self.stats.retransmit_skipped += 1;
            } else if retried && (now - last_retry) < rtt {
                self.stats.retransmit_suppressed += 1;
            } else if over_budget(mode, &self.sender.data_bw, &self.sender.retry_bw, max_kbps) {
                // Over the recovery_maxbitrate ceiling: refuse WITHOUT advancing the
                // retry state, so the receiver re-NACKs and we accept it once the
                // rate decays (libRIST returns before touching transmit_count). This
                // gate precedes the max-retries cap to match libRIST's order.
                self.stats.bandwidth_skipped += 1;
            } else if transmit_count >= self.cfg.max_retries {
                self.stats.retransmit_exhausted += 1;
            } else {
                let (source_time, payload, frag) = {
                    let sl = &mut self.sender.ring[idx];
                    sl.last_retry = now;
                    sl.retried = true;
                    sl.transmit_count += 1;
                    (sl.source_time, sl.payload.clone(), sl.frag)
                };
                let payload_len = payload.len();
                let retry_n = wire_bytes(payload_len);
                self.outputs.push_back(Output::SendMedia {
                    path: tx_path,
                    pkt: MediaPacket {
                        seq: m,
                        source_time,
                        ssrc: base_ssrc,
                        payload,
                        retransmit: true,
                        path_id: tx_path,
                        frag,
                        virt_src_port: 0,
                        virt_dst_port: 0,
                    },
                });
                self.sender.retry_bw.feed(now, retry_n);
                self.stats.retransmitted += 1;
                self.stats.retransmitted_bytes += payload_len as u64;
                emitted += 1;
                if emitted >= max_nacks {
                    return; // per-pass retransmit budget exhausted; receiver re-NACKs the rest
                }
            }
        }
    }

    /// Services the sender's [`TimerId::RttEcho`]: originate one RTT echo request
    /// on the transmit path and re-arm the cadence. Mirrors the receiver's echo
    /// handling so both peers measure RTT symmetrically.
    pub(crate) fn sender_handle_timer(&mut self, now: Timestamp, id: TimerId) {
        if id == TimerId::RttEcho && self.sender.started {
            let tx_path = self.sender.tx_path;
            self.outputs.push_back(Output::SendFeedback {
                path: tx_path,
                fb: Feedback::RttEchoRequest {
                    // Originated: the codec fills the local SSRC.
                    ssrc: 0,
                    timestamp: Ntp64::from_timestamp(now).bits(),
                },
            });
            self.outputs.push_back(Output::SetTimer {
                id: TimerId::RttEcho,
                deadline: now + RTT_ECHO_INTERVAL,
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::SlotState;
    use crate::clock::Timestamp;
    use crate::flow::testutil::{TEST_SSRC, drain_outputs, src_ntp};
    use crate::flow::{Config, CongestionMode, Flow, Output, Role};
    use crate::wire::FragRole;
    use crate::wire::{Feedback, MediaPacket};
    use bytes::Bytes;

    fn ts(us: u64) -> Timestamp {
        Timestamp::from_micros(us)
    }

    fn sender_config() -> Config {
        let mut c = Config::librist_defaults();
        c.ssrc = TEST_SSRC; // even: LSB reserved for the retransmit marker
        c.start_seq = 100;
        c
    }

    fn sender() -> Flow {
        Flow::new(Role::Sender, sender_config())
    }

    fn media_outputs(outs: &[Output]) -> Vec<&MediaPacket> {
        outs.iter()
            .filter_map(|o| match o {
                Output::SendMedia { pkt, .. } => Some(pkt),
                _ => None,
            })
            .collect()
    }

    fn nack(missing: Vec<u32>) -> Feedback {
        Feedback::Nack {
            ssrc: TEST_SSRC,
            missing,
        }
    }

    fn slot_of(f: &Flow, seq: u32) -> &super::SenderSlot {
        &f.sender.ring[(seq & f.sender.mask) as usize]
    }

    #[test]
    fn push_app_first_packet_arms_echo_and_sends() {
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a"));

        assert_eq!(
            drain_outputs(&mut f),
            vec![
                Output::SetTimer {
                    id: crate::flow::TimerId::RttEcho,
                    deadline: ts(110_000)
                },
                Output::SendMedia {
                    path: 0,
                    pkt: MediaPacket {
                        seq: 100,
                        source_time: src_ntp(10_000),
                        ssrc: TEST_SSRC,
                        payload: Bytes::from_static(b"a"),
                        retransmit: false,
                        path_id: 0,
                        frag: FragRole::Standalone,
                        ..Default::default()
                    },
                },
            ]
        );
        assert_eq!(f.stats().sent, 1);

        let sl = slot_of(&f, 100);
        assert_eq!(sl.state, SlotState::Filled);
        assert_eq!(sl.seq, 100);
        assert_eq!(sl.payload.as_ref(), b"a");

        // Second packet: next sequence, no re-arm, steady state.
        f.push_app(ts(11_000), Bytes::from_static(b"b"));
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SendMedia {
                path: 0,
                pkt: MediaPacket {
                    seq: 101,
                    source_time: src_ntp(11_000),
                    ssrc: TEST_SSRC,
                    payload: Bytes::from_static(b"b"),
                    retransmit: false,
                    path_id: 0,
                    frag: FragRole::Standalone,
                    ..Default::default()
                },
            }]
        );
    }

    #[test]
    fn push_app_block_uses_explicit_seq_and_source_time() {
        let mut f = sender();
        // USE_SEQ + ts_ntp: the explicit seq 5000 and source_time are used verbatim,
        // not the auto sequence (which would have started at 100).
        f.push_app_block(
            ts(10_000),
            Bytes::from_static(b"a"),
            FragRole::Standalone,
            Some(5000),
            Some(src_ntp(7_000)),
        );
        let outs = drain_outputs(&mut f);
        let ms = media_outputs(&outs);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].seq, 5000, "explicit seq used verbatim");
        assert_eq!(
            ms[0].source_time,
            src_ntp(7_000),
            "explicit source_time used"
        );
        // Stored in the history ring at the explicit sequence (so a NACK recovers it).
        assert_eq!(slot_of(&f, 5000).state, SlotState::Filled);

        // The auto counter advanced past the override: a plain push_app now takes 5001,
        // never colliding with the app-supplied sequence.
        f.push_app(ts(11_000), Bytes::from_static(b"b"));
        let outs = drain_outputs(&mut f);
        let ms = media_outputs(&outs);
        assert_eq!(ms[0].seq, 5001, "auto counter advanced past the override");

        // A None override falls back to auto seq + now-derived source_time.
        f.push_app_block(
            ts(12_000),
            Bytes::from_static(b"c"),
            FragRole::Standalone,
            None,
            None,
        );
        let outs = drain_outputs(&mut f);
        let ms = media_outputs(&outs);
        assert_eq!(ms[0].seq, 5002);
        assert_eq!(ms[0].source_time, src_ntp(12_000));
    }

    #[test]
    fn no_recovery_sender_keeps_no_history_and_never_echoes() {
        let mut c = sender_config();
        c.no_recovery = true;
        let mut f = Flow::new(Role::Sender, c);

        f.push_app(ts(10_000), Bytes::from_static(b"a")); // seq 100
        let outs = drain_outputs(&mut f);
        // The first transmission goes out, but with no RTT-echo cadence armed and
        // no feedback emitted (a one-way transport has no return channel).
        let ms = media_outputs(&outs);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].seq, 100);
        assert!(!ms[0].retransmit);
        assert!(
            !outs.iter().any(|o| {
                matches!(o, Output::SetTimer { id, .. } if *id == crate::flow::TimerId::RttEcho)
                    || matches!(o, Output::SendFeedback { .. })
            }),
            "one-way sender armed a recovery timer or emitted feedback: {outs:?}"
        );
        // No history retained: the ring slot stays empty.
        assert_eq!(slot_of(&f, 100).state, SlotState::Empty);

        // A stray NACK for seq 100 finds no history: nothing is retransmitted and
        // it is counted as skipped (aged out), not suppressed or exhausted.
        f.feed_feedback(ts(20_000), nack(vec![100]));
        assert!(media_outputs(&drain_outputs(&mut f)).is_empty());
        let st = f.stats();
        assert_eq!((st.retransmitted, st.retransmit_skipped), (0, 1));
    }

    #[test]
    fn service_nack_retransmits_from_history() {
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a")); // seq 100
        f.push_app(ts(11_000), Bytes::from_static(b"b")); // seq 101
        f.push_app(ts(12_000), Bytes::from_static(b"c")); // seq 102
        drain_outputs(&mut f);

        // NACK for 101: same seq, same source_time, base (even) SSRC, payload "b".
        f.feed_feedback(ts(20_000), nack(vec![101]));
        let outs = drain_outputs(&mut f);
        assert_eq!(
            media_outputs(&outs),
            vec![&MediaPacket {
                seq: 101,
                source_time: src_ntp(11_000),
                ssrc: TEST_SSRC,
                payload: Bytes::from_static(b"b"),
                retransmit: true,
                path_id: 0,
                frag: FragRole::Standalone,
                ..Default::default()
            }]
        );
        let st = f.stats();
        assert_eq!((st.retransmitted, st.sent), (1, 3));
        let sl = slot_of(&f, 101);
        assert_eq!(
            (sl.transmit_count, sl.retried, sl.last_retry),
            (1, true, ts(20_000))
        );
    }

    fn sender_with(mode: CongestionMode, max_kbps: u32) -> Flow {
        let mut c = sender_config();
        c.congestion_control = mode;
        c.recovery_maxbitrate = max_kbps;
        Flow::new(Role::Sender, c)
    }

    #[test]
    fn service_nack_bandwidth_gate_skips_when_over_budget() {
        // Normal mode with a 1 kbps ceiling: a modest data rate puts the slow EWMA
        // far over budget, so the NACK is refused with `bandwidth_skipped` and the
        // slot's retry state is left untouched (the receiver re-NACKs once the rate
        // decays).
        let mut f = sender_with(CongestionMode::Normal, 1);
        let big = Bytes::from(vec![0u8; 1000]);
        f.push_app(ts(10_000), big.clone()); // seq 100, seeds the EWMA
        f.push_app(ts(20_000), big.clone()); // seq 101
        f.push_app(ts(1_020_000), big.clone()); // seq 102: crosses the 1 s slow window
        drain_outputs(&mut f);

        f.feed_feedback(ts(1_030_000), nack(vec![100]));
        let outs = drain_outputs(&mut f);
        assert!(
            media_outputs(&outs).is_empty(),
            "retransmit refused while over budget"
        );
        let st = f.stats();
        assert_eq!((st.retransmitted, st.bandwidth_skipped), (0, 1));
        let sl = slot_of(&f, 100);
        assert_eq!((sl.transmit_count, sl.retried), (0, false));
    }

    #[test]
    fn service_nack_off_mode_ignores_the_budget() {
        // The same over-budget scenario under congestion_control=Off retransmits.
        let mut f = sender_with(CongestionMode::Off, 1);
        let big = Bytes::from(vec![0u8; 1000]);
        f.push_app(ts(10_000), big.clone());
        f.push_app(ts(20_000), big.clone());
        f.push_app(ts(1_020_000), big.clone());
        drain_outputs(&mut f);

        f.feed_feedback(ts(1_030_000), nack(vec![100]));
        let outs = drain_outputs(&mut f);
        assert_eq!(media_outputs(&outs).len(), 1);
        let st = f.stats();
        assert_eq!((st.retransmitted, st.bandwidth_skipped), (1, 0));
    }

    #[test]
    fn service_nack_caps_retransmits_per_pass() {
        // recovery_maxbitrate=1 derives max_nacks_per_loop=2; Off keeps the budget
        // gate out of the way, so a five-seq NACK emits exactly two retransmits in one
        // pass and the receiver re-NACKs the rest.
        let mut f = sender_with(CongestionMode::Off, 1);
        f.push_app(ts(10_000), Bytes::from_static(b"x")); // 100
        f.push_app(ts(11_000), Bytes::from_static(b"x")); // 101
        f.push_app(ts(12_000), Bytes::from_static(b"x")); // 102
        f.push_app(ts(13_000), Bytes::from_static(b"x")); // 103
        f.push_app(ts(14_000), Bytes::from_static(b"x")); // 104
        drain_outputs(&mut f);

        f.feed_feedback(ts(20_000), nack(vec![100, 101, 102, 103, 104]));
        let outs = drain_outputs(&mut f);
        assert_eq!(media_outputs(&outs).len(), 2, "per-pass NACK budget");
        assert_eq!(f.stats().retransmitted, 2);
    }

    #[test]
    fn service_nack_unknown_seq_skipped() {
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a")); // seq 100
        drain_outputs(&mut f);

        f.feed_feedback(ts(20_000), nack(vec![99, 200, 100]));
        let outs = drain_outputs(&mut f);
        let ms = media_outputs(&outs);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].seq, 100);
        let st = f.stats();
        assert_eq!((st.retransmit_skipped, st.retransmitted), (2, 1));
    }

    #[test]
    fn service_nack_gate_suppresses_within_rtt() {
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a")); // seq 100
        drain_outputs(&mut f);
        // Cold-start RTT = rtt_min = 5 ms, so the gate window is 5 ms.

        f.feed_feedback(ts(20_000), nack(vec![100])); // retransmit #1
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 1);

        // Re-NACK 4 ms later: inside the 5 ms window -> suppressed.
        f.feed_feedback(ts(24_000), nack(vec![100]));
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 0);
        assert_eq!(f.stats().retransmit_suppressed, 1);

        // Re-NACK at the window edge (now - last_retry == rtt): allowed (`<`).
        f.feed_feedback(ts(25_000), nack(vec![100]));
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 1);
        let st = f.stats();
        assert_eq!((st.retransmitted, st.retransmit_suppressed), (2, 1));
    }

    #[test]
    fn service_nack_gate_uses_raw_last_rtt() {
        // The gate must clamp the raw last RTT sample, not the EWMA. Warm the
        // estimator with one large sample so the bases diverge, then re-NACK at a
        // delay only the raw basis suppresses.
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a")); // seq 100
        drain_outputs(&mut f);

        let warm: i64 = 200_000; // 200 ms
        f.feed_feedback(
            ts(1_000_000),
            Feedback::RttEchoResponse {
                ssrc: 0,
                timestamp: src_ntp(1_000_000 - warm.unsigned_abs()),
                processing_delay: 0,
            },
        );
        assert_eq!(f.est.last().as_micros(), warm);

        f.feed_feedback(ts(2_000_000), nack(vec![100])); // retransmit #1
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 1);

        // Re-NACK 100 ms later: 100 ms < clamp(raw 200 ms) -> suppressed. Under
        // the smoothed basis (~29 ms) it would NOT be, so this pins the raw gate.
        f.feed_feedback(ts(2_100_000), nack(vec![100]));
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 0);
        assert_eq!(f.stats().retransmit_suppressed, 1);
    }

    #[test]
    fn service_nack_max_retries_exhausted() {
        let mut cfg = sender_config();
        cfg.max_retries = 2;
        let mut f = Flow::new(Role::Sender, cfg);
        f.push_app(ts(10_000), Bytes::from_static(b"a")); // seq 100
        drain_outputs(&mut f);

        // Two retransmits spaced beyond the 5 ms gate.
        f.feed_feedback(ts(20_000), nack(vec![100]));
        f.feed_feedback(ts(30_000), nack(vec![100]));
        drain_outputs(&mut f);
        assert_eq!(f.stats().retransmitted, 2);

        // Third: transmit_count(2) >= max_retries(2) -> exhausted, no send.
        f.feed_feedback(ts(40_000), nack(vec![100]));
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 0);
        let st = f.stats();
        assert_eq!((st.retransmit_exhausted, st.retransmitted), (1, 2));
    }

    #[test]
    fn service_nack_aged_out_after_wrap() {
        let mut cfg = sender_config();
        cfg.ring_size = 16; // tiny ring so a later seq overwrites an old slot
        cfg.start_seq = 0;
        let mut f = Flow::new(Role::Sender, cfg);
        // Send seq 0, then seq 1..=16 — seq 16 maps to ring index 0, overwriting 0.
        f.push_app(ts(10_000), Bytes::from_static(b"old"));
        for i in 1..=16u64 {
            f.push_app(ts(10_000 + i * 1_000), Bytes::from_static(b"x"));
        }
        drain_outputs(&mut f);

        // NACK for the overwritten seq 0: its slot now holds seq 16 -> skipped.
        f.feed_feedback(ts(40_000), nack(vec![0]));
        assert_eq!(media_outputs(&drain_outputs(&mut f)).len(), 0);
        assert_eq!(f.stats().retransmit_skipped, 1);
    }

    #[test]
    fn sender_rtt_echo_originate_answer_observe() {
        use crate::flow::TimerId;
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a"));
        drain_outputs(&mut f);

        // Origination: TimerRttEcho fires -> request on the transmit path, re-arm.
        f.handle_timer(ts(110_000), TimerId::RttEcho);
        assert_eq!(
            drain_outputs(&mut f),
            vec![
                Output::SendFeedback {
                    path: 0,
                    // Originated: SSRC left 0 for the codec to fill.
                    fb: Feedback::RttEchoRequest {
                        ssrc: 0,
                        timestamp: src_ntp(110_000)
                    },
                },
                Output::SetTimer {
                    id: TimerId::RttEcho,
                    deadline: ts(210_000)
                },
            ]
        );

        // Answer an inbound request verbatim, echoing the requester's SSRC.
        f.feed_feedback(
            ts(120_000),
            Feedback::RttEchoRequest {
                ssrc: 0xFEED_0002,
                timestamp: 0xABCD,
            },
        );
        assert_eq!(
            drain_outputs(&mut f),
            vec![Output::SendFeedback {
                path: 0,
                fb: Feedback::RttEchoResponse {
                    ssrc: 0xFEED_0002,
                    timestamp: 0xABCD,
                    processing_delay: 0
                },
            }]
        );

        // Observe a response: sample = 10000 - 2000 = 8000;
        // eight_times_rtt = 40000 - 5000 + 8000 = 43000 -> smoothed 5375.
        f.feed_feedback(
            ts(120_000),
            Feedback::RttEchoResponse {
                ssrc: 0,
                timestamp: src_ntp(110_000),
                processing_delay: 2_000,
            },
        );
        assert_eq!(f.est.smoothed().as_micros(), 5_375);
    }

    #[test]
    fn sender_ignores_receiver_entry_points() {
        use crate::flow::TimerId;
        let mut f = sender();
        f.push_app(ts(10_000), Bytes::from_static(b"a"));
        drain_outputs(&mut f);

        // Media in, Tick, and receiver-only timers do nothing on a sender.
        f.feed(ts(20_000), 0, super::super::testutil::mk_pkt(1, 0, b""));
        f.tick(ts(30_000));
        f.handle_timer(ts(40_000), TimerId::Playout);
        f.handle_timer(ts(50_000), TimerId::Nack);
        assert!(drain_outputs(&mut f).is_empty());
    }
}
