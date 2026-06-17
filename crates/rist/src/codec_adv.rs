//! The Advanced-profile (VSF TR-06-3:2024) codec strategy: the single-UDP-port,
//! RTP-based analog of the Main-profile codec in [`codec_main`](crate::codec_main).
//! It translates between the flow core's normalized [`MediaPacket`] / [`Feedback`]
//! values and Advanced-profile datagrams, framing through
//! [`adv`](rist_codec::adv) (the byte-exact header + control codec),
//! [`crypto`](rist_codec::crypto) (AES-CTR payload encryption), and
//! [`lpc`](rist_codec::lpc) (LZ4 payload compression). Ported from ristgo
//! `internal/session/codec_adv.go`.
//!
//! # Single-port multiplex
//!
//! Advanced profile carries media AND control over one UDP port as plain RTP (V=2,
//! PT=127, 1 MHz clock) followed by the 4-byte profile-defined extension — no GRE
//! framing. Media packets carry `enc_type=DIRECT` (5) on the even (protected) base
//! SSRC; control messages carry `enc_type=CONTROL` (4) on the odd (unprotected) base
//! SSRC. The receive demux is the encapsulation Type field, not a port.
//!
//! # Sequence numbers
//!
//! The Advanced wire sequence is natively 32-bit (low 16 in the RTP header, high 16
//! in the profile extension's seq_ext), so there is NO widening on this path. NACK
//! control messages carry full 32-bit sequences too.
//!
//! # Encryption and compression (order)
//!
//! On send the payload is compressed THEN encrypted; on receive decrypted THEN
//! decompressed. Encryption is AES-CTR over the PAYLOAD ONLY (libRIST's mode-1
//! deviation), IV = the 32-bit sequence (the same `build_iv` as the Main path), the
//! nonce in `psk_nonce`, the sequence echoed in `psk_iv`. Compression is LZ4
//! raw-block, applied only when it shrinks the payload (`lpc_mode = LZ4`).
//!
//! # Timestamp / source-time
//!
//! Although TR-06-3 specifies a 1 MHz clock, libRIST computes the timestamp at an
//! effective 2^16 MHz rate (`micros << 16`), wrapping the 32-bit field every ~65 ms.
//! This codec matches that byte-for-byte. libRIST discards the received timestamp;
//! ristrust instead reconstructs a dedup-stable source time from the wrapping
//! timestamp, sequence-anchored so a retransmit and its original reconstruct to the
//! same `(seq, source_time)` (the flow core's dedup invariant) across the wrap.

// Built ahead of its consumer (the Advanced driver); reachable only from its tests
// until then. The casts narrow the 2^16 MHz timestamp and slice wrap-aware deltas;
// they are deliberate and bounded.
#![allow(dead_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use bytes::Bytes;

use rist_codec::{adv, crypto, lpc};
use rist_core::clock::{Ntp64, Timestamp};
use rist_core::wire::{Feedback, FragRole, MediaPacket};

use crate::codec::{self, CodecError};
use crate::codec_main::Decoded;

/// The shift between microseconds and the Advanced 2^16 MHz timestamp.
const ADV_CLOCK_SHIFT: u32 = 16;

/// Bounds an LZ4 decompression, matching libRIST's `RIST_MAX_PACKET_SIZE`.
const MAX_ADV_DECOMPRESSED: usize = 10_000;

/// The stateful Advanced-profile codec for one direction of a flow. Not safe for
/// concurrent use; the host serializes a single send/receive path onto it.
#[derive(Debug)]
pub(crate) struct AdvCodec {
    /// The PSK encryptor, or `None` when encryption is disabled.
    send_key: Option<crypto::Key>,
    /// The PSK decryptor, or `None` when encryption is disabled.
    recv_key: Option<crypto::Decryptor>,
    /// Whether LZ4 compression is enabled on the media send path.
    compression: bool,
    /// The even base SSRC; media uses the protected (even) form, control the odd.
    ssrc: u32,
    /// The reduced-overhead virtual source port encoded into the Flow ID (or 0).
    src_port: u16,
    /// The reduced-overhead virtual destination port encoded into the Flow ID (or 0).
    dst_port: u16,
    /// The per-datagram control sequence counter (the unprotected flow's sequence).
    ctrl_seq: u32,

    // Source-time reconstruction state (see `adv_source_micros`).
    ts_started: bool,
    ts_base_seq: u32,
    ts_base_ticks: i64,
    ts_ref_seq: u32,
    ts_ref_ticks: i64,

    /// Inbound control messages whose Control Index this codec did not recognize
    /// (TR-06-3 §5.3.10), queued as `(ci, head)` for the host to answer with a
    /// Control Message Unsupported Response. Drained via [`AdvCodec::take_unsupported`].
    pending_unsupported: Vec<(u16, [u8; 6])>,
}

impl AdvCodec {
    /// Constructs an Advanced-profile codec. `send_key`/`recv_key` may be `None` to
    /// disable PSK; `compression` turns on LZ4 on the media send path; `ssrc` is the
    /// even base SSRC; `src_port`/`dst_port` are the Flow ID virtual ports (zero
    /// disables the Flow ID field).
    pub(crate) fn new(
        send_key: Option<crypto::Key>,
        recv_key: Option<crypto::Decryptor>,
        compression: bool,
        ssrc: u32,
        src_port: u16,
        dst_port: u16,
    ) -> AdvCodec {
        AdvCodec {
            send_key,
            recv_key,
            compression,
            ssrc,
            src_port,
            dst_port,
            ctrl_seq: 0,
            ts_started: false,
            ts_base_seq: 0,
            ts_base_ticks: 0,
            ts_ref_seq: 0,
            ts_ref_ticks: 0,
            pending_unsupported: Vec::new(),
        }
    }

    /// Drains the queue of inbound control messages whose Control Index was not
    /// recognized, each as `(incoming_ci, head)` (the first 48 bits of the offending
    /// body, zero-padded). The host answers each with a Control Message Unsupported
    /// Response (TR-06-3 §5.3.10).
    pub(crate) fn take_unsupported(&mut self) -> Vec<(u16, [u8; 6])> {
        std::mem::take(&mut self.pending_unsupported)
    }

    /// Frames a Control Message Unsupported Response echoing `ci` and `head`, stamped
    /// with `ts` (TR-06-3 §5.3.10).
    pub(crate) fn encode_unsupported(
        &mut self,
        ci: u16,
        head: [u8; 6],
        ts: u32,
    ) -> Result<Vec<u8>, CodecError> {
        let mut body = Vec::new();
        adv::build_unsupported(&mut body, self.ctrl_ssrc(), ci, head);
        self.frame_control(&body, ts)
    }

    /// Whether a PSK is configured.
    pub(crate) fn has_psk(&self) -> bool {
        self.send_key.is_some()
    }

    /// Re-keys the data channel to the EAP-SRP session key K after authentication
    /// with no configured secret. K is the raw 32-byte SRP session key (a SHA-256
    /// digest), so it keys through the **raw** derivation (no NUL-truncation) to
    /// match how libRIST installs an EAP-pushed passphrase — see
    /// [`crypto::derive_key_raw`] and the Main codec's `set_session_key`.
    pub(crate) fn set_session_key(&mut self, k: &[u8]) -> Result<(), CodecError> {
        let bits = crypto::AesKeyBits::Aes256;
        self.send_key = Some(crypto::Key::new_raw(k, bits, 0, false)?);
        self.recv_key = Some(crypto::Decryptor::new_raw(k, bits)?);
        Ok(())
    }

    /// Maps an NTP-64 source time to the 32-bit Advanced timestamp (`micros << 16`).
    fn adv_ts_from_source(src: u64) -> u32 {
        let micros = Ntp64::from_bits(src).to_timestamp().as_micros();
        (micros << ADV_CLOCK_SHIFT) as u32
    }

    /// Encodes a normalized [`MediaPacket`] as one Advanced DIRECT datagram: the
    /// payload compressed (when enabled and it shrinks) then encrypted (when a PSK
    /// is configured), framed with the protected (even) SSRC, the split 32-bit
    /// sequence, the timestamp, the R flag, and the optional Flow ID.
    pub(crate) fn encode_media(&mut self, pkt: &MediaPacket) -> Result<Vec<u8>, CodecError> {
        let mut payload: Vec<u8> = pkt.payload.to_vec();
        let mut lpc_mode = adv::LPC_NONE;

        if self.compression && !payload.is_empty() {
            let mut comp = Vec::new();
            lpc::compress(&mut comp, &payload);
            if comp.len() < payload.len() {
                payload = comp;
                lpc_mode = adv::LPC_LZ4;
            }
        }

        let (first_frag, last_frag) = frag_to_flags(pkt.frag);
        let mut params = adv::Params {
            seq: pkt.seq,
            timestamp: Self::adv_ts_from_source(pkt.source_time),
            ssrc: adv::ssrc_protected(self.ssrc),
            enc_type: adv::TYPE_DIRECT,
            psk_mode: adv::PSK_NONE,
            lpc_mode,
            first_frag,
            last_frag,
            retransmit: pkt.retransmit,
            ..adv::Params::default()
        };
        if self.src_port != 0 || self.dst_port != 0 {
            params.flow_id = Some(flow_id_from_ports(self.src_port, self.dst_port));
        }

        if let Some(key) = self.send_key.as_mut() {
            payload = key.encrypt(pkt.seq, &payload)?;
            params.psk_mode = adv::PSK_AES_CTR;
            params.psk_nonce = Some(key.nonce());
            params.psk_iv = Some(pkt.seq.to_be_bytes());
        }

        let mut out = Vec::with_capacity(adv::header_size(&params) + payload.len());
        adv::build(&mut out, &params, &payload)?;
        Ok(out)
    }

    /// Demultiplexes an already-parsed Advanced packet (the host parses the header
    /// to route Type=8 GRE-wrapped packets to the GRE substrate). A DIRECT packet
    /// returns media; a CONTROL packet returns feedback; other types are an error.
    pub(crate) fn decode_parsed(&mut self, p: &adv::Parsed) -> Result<Decoded, CodecError> {
        match p.enc_type {
            adv::TYPE_CONTROL => self.decode_control_msg(&p.payload),
            adv::TYPE_DIRECT => Ok(Decoded::Media(self.decode_media_adv(p)?)),
            _ => Err(CodecError::AdvProfile("unsupported encapsulation type")),
        }
    }

    /// Dispatches one Type=CONTROL payload. A PSK future-nonce announcement
    /// (TR-06-3 §5.3.9) is a decryptor concern — pre-derive the announced key so the
    /// first packet under the new nonce decrypts without a PBKDF2 stall — and yields
    /// no flow input; every other control index maps to normalized feedback.
    fn decode_control_msg(&mut self, payload: &Bytes) -> Result<Decoded, CodecError> {
        let (ci, body) = adv::parse_control(payload)?;
        match ci {
            adv::CI_PSK_NONCE => {
                // Pre-derive the announced future nonce's key (a decryptor concern).
                if let (Ok(pn), Some(key)) = (adv::PskNonce::parse(&body), self.recv_key.as_mut()) {
                    // Honor the announced key size (128/192/256 — TR-06-3 §5.3.9); an
                    // unrecognized value falls back to 128 rather than mis-deriving.
                    let bits = crypto::AesKeyBits::from_bits(pn.key_bits)
                        .unwrap_or(crypto::AesKeyBits::Aes128);
                    key.precompute(pn.nonce, bits);
                }
                Ok(Decoded::Ignored)
            }
            // Recognized control indices that carry normalized feedback.
            adv::CI_NACK_BITMASK
            | adv::CI_NACK_RANGE
            | adv::CI_RTT_ECHO_REQ
            | adv::CI_RTT_ECHO_RESP
            | adv::CI_LQM_GLOBAL
            | adv::CI_LQM_LINK_SPECIFIC
            | adv::CI_FLOW_ATTR => Ok(Decoded::Feedback(self.decode_control(payload)?)),
            // Recognized but yielding no flow input: keepalive and SRP-auth are
            // handled on the substrate; FEC control is consumed before this point;
            // an inbound Unsupported is logged at the host but never answered (a
            // reply would loop). None of these triggers an Unsupported response.
            adv::CI_KEEPALIVE
            | adv::CI_SRP_AUTH
            | adv::CI_UNSUPPORTED
            | adv::CI_FEC_2022_5_ROW
            | adv::CI_FEC_2022_5_COL
            | adv::CI_FEC_2022_1_ROW
            | adv::CI_FEC_2022_1_COL => Ok(Decoded::Ignored),
            // An unrecognized control index (§5.3.10): queue an Unsupported response
            // echoing the CI and the first 48 bits of the body, so the peer learns we
            // did not understand it.
            _ => {
                let mut head = [0u8; 6];
                let n = body.len().min(6);
                head[..n].copy_from_slice(&body[..n]);
                self.pending_unsupported.push((ci, head));
                Ok(Decoded::Ignored)
            }
        }
    }

    /// Parses and demultiplexes one Advanced datagram (a convenience over
    /// [`adv::parse`] + [`AdvCodec::decode_parsed`]).
    pub(crate) fn decode(&mut self, buf: &Bytes) -> Result<Decoded, CodecError> {
        let p = adv::parse(buf)?;
        self.decode_parsed(&p)
    }

    /// Reconstructs a [`MediaPacket`] from a parsed DIRECT packet: decrypt (AES-CTR
    /// mode 1) then decompress (LZ4), then map the native 32-bit sequence and the
    /// wrapping timestamp to the normalized fields. The F/L bits map to the packet's
    /// [`FragRole`](rist_core::wire::FragRole) (the host reassembler folds a run);
    /// libRIST always sends whole packets (F=L=1, `Standalone`), so an interop peer
    /// only ever yields that role.
    fn decode_media_adv(&mut self, p: &adv::Parsed) -> Result<MediaPacket, CodecError> {
        let mut data: Vec<u8> = p.payload.to_vec();

        match p.psk_mode {
            adv::PSK_NONE => {
                if self.recv_key.is_some() {
                    return Err(CodecError::AdvProfile(
                        "cleartext payload but a decryptor is configured",
                    ));
                }
            }
            adv::PSK_AES_CTR => {
                let Some(key) = self.recv_key.as_mut() else {
                    return Err(CodecError::AdvProfile(
                        "encrypted payload but no decryptor configured",
                    ));
                };
                let (Some(nonce_b), Some(iv_b)) = (&p.psk_nonce, &p.psk_iv) else {
                    return Err(CodecError::AdvProfile("AES-CTR payload missing nonce/iv"));
                };
                let mut nonce = [0u8; crypto::NONCE_SIZE];
                nonce.copy_from_slice(nonce_b);
                let iv_seq = u32::from_be_bytes([iv_b[0], iv_b[1], iv_b[2], iv_b[3]]);
                data = key.decrypt(nonce, iv_seq, &data)?;
            }
            _ => return Err(CodecError::AdvProfile("unsupported PSK mode")),
        }

        match p.lpc_mode {
            adv::LPC_NONE => {}
            adv::LPC_LZ4 => {
                if !data.is_empty() {
                    let mut out = Vec::new();
                    lpc::decompress(&mut out, &data, MAX_ADV_DECOMPRESSED)?;
                    data = out;
                }
            }
            _ => return Err(CodecError::AdvProfile("unsupported LPC mode")),
        }

        let micros = self.adv_source_micros(p.seq, p.timestamp);
        let src = Ntp64::from_timestamp(Timestamp::from_micros(micros.max(0) as u64)).bits();
        Ok(MediaPacket {
            seq: p.seq,
            source_time: src,
            ssrc: adv::ssrc_protected(p.ssrc),
            payload: Bytes::from(data),
            retransmit: p.retransmit,
            path_id: 0,
            frag: flags_to_frag(p.first_frag, p.last_frag),
        })
    }

    /// Reconstructs a dedup-stable source time (microseconds) from the native 32-bit
    /// sequence and the 2^16 MHz timestamp. The timestamp wraps every ~65 ms, far
    /// inside the recovery window, so the widening reference is extrapolated from the
    /// sequence by a flow-averaged rate (anchored at the first packet, tracking the
    /// in-order front) rather than from arrival order — keeping a retransmit's
    /// timestamp in the same epoch as its original.
    fn adv_source_micros(&mut self, seq_num: u32, wire_ts: u32) -> i64 {
        if !self.ts_started {
            self.ts_started = true;
            self.ts_base_seq = seq_num;
            self.ts_base_ticks = i64::from(wire_ts);
            self.ts_ref_seq = seq_num;
            self.ts_ref_ticks = i64::from(wire_ts);
            return self.ts_base_ticks >> ADV_CLOCK_SHIFT;
        }
        let mut reference = self.ts_ref_ticks;
        let d = self.ts_ref_seq.wrapping_sub(self.ts_base_seq) as i32;
        if d > 0 {
            let ticks_per_seq = (self.ts_ref_ticks - self.ts_base_ticks) / i64::from(d);
            reference += i64::from(seq_num.wrapping_sub(self.ts_ref_seq) as i32) * ticks_per_seq;
        }
        let ticks = codec::widen_ticks(wire_ts, reference);
        if seq_num.wrapping_sub(self.ts_ref_seq) as i32 > 0 {
            self.ts_ref_seq = seq_num;
            self.ts_ref_ticks = ticks;
        }
        ticks.max(0) >> ADV_CLOCK_SHIFT
    }

    /// Decodes one Type=CONTROL payload into normalized feedback. NACK
    /// bitmask/range become a [`Feedback::Nack`] (native 32-bit sequences); RTT echo
    /// request/response and LQM become the matching variants. Keepalive, flow-attr,
    /// and PSK-future-nonce yield no feedback (liveness and nonce rotation are
    /// host/decryptor concerns). An unknown control index is ignored.
    fn decode_control(&self, payload: &Bytes) -> Result<Vec<Feedback>, CodecError> {
        let (ci, body) = adv::parse_control(payload)?;
        let out = match ci {
            adv::CI_NACK_BITMASK => {
                let n = adv::NackBitmask::parse(&body)?;
                vec![Feedback::Nack {
                    ssrc: n.media_ssrc,
                    missing: n.missing(),
                }]
            }
            adv::CI_NACK_RANGE => {
                let n = adv::NackRange::parse(&body)?;
                vec![Feedback::Nack {
                    ssrc: n.media_ssrc,
                    missing: n.missing(),
                }]
            }
            adv::CI_RTT_ECHO_REQ => {
                let e = adv::RttEcho::parse(&body)?;
                vec![Feedback::RttEchoRequest {
                    ssrc: 0,
                    timestamp: e.timestamp(),
                }]
            }
            adv::CI_RTT_ECHO_RESP => {
                let e = adv::RttEcho::parse(&body)?;
                vec![Feedback::RttEchoResponse {
                    ssrc: 0,
                    timestamp: e.timestamp(),
                    processing_delay: e.processing_delay,
                }]
            }
            adv::CI_LQM_GLOBAL | adv::CI_LQM_LINK_SPECIFIC => {
                if body.len() < 44 {
                    Vec::new()
                } else {
                    let mut lqm = [0u8; 44];
                    lqm.copy_from_slice(&body[..44]);
                    vec![Feedback::LinkQuality { lqm }]
                }
            }
            adv::CI_FLOW_ATTR => vec![Feedback::FlowAttribute {
                json: body.to_vec(),
            }],
            _ => Vec::new(),
        };
        Ok(out)
    }

    /// The unprotected (odd) base SSRC used for control datagrams.
    fn ctrl_ssrc(&self) -> u32 {
        adv::ssrc_unprotected(self.ssrc)
    }

    /// Encodes the drained feedback effects into complete Advanced control datagrams
    /// — one per message (libRIST sends and reads exactly one entry per datagram). A
    /// NACK expands to one datagram per entry; echoes and keepalives map to one each.
    /// `ts` is the timestamp stamped into each control packet (the receiver ignores
    /// it). The control sequence counter advances once per datagram.
    pub(crate) fn encode_feedback(
        &mut self,
        fbs: &[Feedback],
        bitmask: bool,
        ts: u32,
    ) -> Result<Vec<Vec<u8>>, CodecError> {
        let mut out = Vec::new();
        for fb in fbs {
            match fb {
                Feedback::Nack { ssrc, missing } => {
                    if bitmask {
                        for n in adv::encode_bitmask_nack(*ssrc, missing) {
                            let mut body = Vec::new();
                            adv::build_nack_bitmask(&mut body, n);
                            out.push(self.frame_control(&body, ts)?);
                        }
                    } else {
                        for n in adv::encode_range_nack(*ssrc, missing) {
                            let mut body = Vec::new();
                            adv::build_nack_range(&mut body, n);
                            out.push(self.frame_control(&body, ts)?);
                        }
                    }
                }
                Feedback::RttEchoRequest { timestamp, .. } => {
                    let e = adv::RttEcho::from_timestamp(self.ctrl_ssrc(), *timestamp, 0);
                    let mut body = Vec::new();
                    adv::build_rtt_echo_request(&mut body, e);
                    out.push(self.frame_control(&body, ts)?);
                }
                Feedback::RttEchoResponse {
                    timestamp,
                    processing_delay,
                    ..
                } => {
                    let e = adv::RttEcho::from_timestamp(
                        self.ctrl_ssrc(),
                        *timestamp,
                        *processing_delay,
                    );
                    let mut body = Vec::new();
                    adv::build_rtt_echo_response(&mut body, e);
                    out.push(self.frame_control(&body, ts)?);
                }
                Feedback::Keepalive => {
                    let mut body = Vec::new();
                    adv::build_keepalive(
                        &mut body,
                        adv::Keepalive {
                            caps: adv::KEEPALIVE_CAP_I,
                            ..adv::Keepalive::default()
                        },
                    );
                    out.push(self.frame_control(&body, ts)?);
                }
                // Not emitted by the flow on the encode path: SenderReport/ExtSeq/
                // LinkQuality are host/codec concerns, and a flow attribute is sent
                // directly via `encode_flow_attr`, never as a flow-emitted feedback.
                Feedback::SenderReport { .. }
                | Feedback::ExtSeq { .. }
                | Feedback::LinkQuality { .. }
                | Feedback::FlowAttribute { .. } => {}
            }
        }
        Ok(out)
    }

    /// Wraps a control payload (CI + Length sub-header + body) in a Type=CONTROL
    /// packet on the unprotected (odd) SSRC: no encryption, no compression, F=L=E=1.
    fn frame_control(&mut self, payload: &[u8], ts: u32) -> Result<Vec<u8>, CodecError> {
        self.frame_control_frag(payload, true, true, ts)
    }

    /// [`AdvCodec::frame_control`] with explicit fragment roles: a control message
    /// larger than the MTU is sent as a run of Type=Control packets carrying the F/L
    /// bits, which the peer reassembles before decoding. The control sequence counter
    /// advances once per fragment, so consecutive fragments carry consecutive
    /// sequences (the receiver derives a lost fragment from a sequence gap). Only the
    /// in-band FEC carriage fragments control messages (TR-06-3 §5.3.5).
    pub(crate) fn frame_control_frag(
        &mut self,
        payload: &[u8],
        first: bool,
        last: bool,
        ts: u32,
    ) -> Result<Vec<u8>, CodecError> {
        let seq = self.ctrl_seq;
        self.ctrl_seq = self.ctrl_seq.wrapping_add(1);
        let params = adv::Params {
            seq,
            timestamp: ts,
            ssrc: self.ctrl_ssrc(),
            enc_type: adv::TYPE_CONTROL,
            psk_mode: adv::PSK_NONE,
            lpc_mode: adv::LPC_NONE,
            first_frag: first,
            last_frag: last,
            expedite: true,
            ..adv::Params::default()
        };
        let mut out = Vec::new();
        adv::build(&mut out, &params, payload)?;
        Ok(out)
    }

    /// Builds one Advanced keep-alive control datagram (I-bit set) for the host's
    /// liveness ticker.
    pub(crate) fn keepalive_datagram(&mut self, ts: u32) -> Result<Vec<u8>, CodecError> {
        let mut body = Vec::new();
        adv::build_keepalive(
            &mut body,
            adv::Keepalive {
                caps: adv::KEEPALIVE_CAP_I,
                ..adv::Keepalive::default()
            },
        );
        self.frame_control(&body, ts)
    }

    /// Builds one Advanced Type=Control datagram carrying a 44-byte Link Quality
    /// Message at control index `0x0002` (Global), for source adaptation
    /// (TR-06-4 Part 1 §5.4).
    pub(crate) fn lqm_datagram(&mut self, lqm: &[u8; 44], ts: u32) -> Result<Vec<u8>, CodecError> {
        let mut body = Vec::new();
        adv::build_control(&mut body, adv::CI_LQM_GLOBAL, lqm);
        self.frame_control(&body, ts)
    }

    /// Frames one fire-and-forget flow-attribute control datagram (TR-06-3 §5.3.7,
    /// control index `0x8001`) carrying the opaque `json` payload.
    pub(crate) fn flow_attr_datagram(
        &mut self,
        json: &[u8],
        ts: u32,
    ) -> Result<Vec<u8>, CodecError> {
        let mut body = Vec::new();
        adv::build_flow_attr(&mut body, json);
        self.frame_control(&body, ts)
    }
}

/// Builds the Advanced Flow ID from the reduced-overhead virtual ports (matching
/// libRIST: outer = destination port, the 12-bit inner = source port).
fn flow_id_from_ports(src_port: u16, dst_port: u16) -> adv::FlowId {
    adv::FlowId {
        outer: dst_port,
        inner: src_port & 0x0FFF,
        sub: 0,
    }
}

/// Maps a normalized [`FragRole`] to the Advanced header's first/last fragment
/// flags. The flag pair carries the role positionally: a standalone packet sets
/// both, a run is first-only → neither → last-only (TR-06-3 §5).
fn frag_to_flags(frag: FragRole) -> (bool, bool) {
    match frag {
        FragRole::Standalone => (true, true),
        FragRole::First => (true, false),
        FragRole::Middle => (false, false),
        FragRole::Last => (false, true),
    }
}

/// Inverse of [`frag_to_flags`]: recovers the fragment role from the parsed
/// first/last flag pair. Shared with the FEC in-band carriage (the F/L bits of a
/// fragmented FEC control packet).
pub(crate) fn flags_to_frag(first: bool, last: bool) -> FragRole {
    match (first, last) {
        (true, true) => FragRole::Standalone,
        (true, false) => FragRole::First,
        (false, false) => FragRole::Middle,
        (false, true) => FragRole::Last,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rist_codec::crypto::AesKeyBits;

    const SP: u16 = 1971;
    const DP: u16 = 1968;

    fn src_ntp(us: u64) -> u64 {
        Ntp64::from_timestamp(Timestamp::from_micros(us)).bits()
    }

    fn media(
        seq: u32,
        source_time: u64,
        ssrc: u32,
        payload: &[u8],
        retransmit: bool,
    ) -> MediaPacket {
        MediaPacket {
            seq,
            source_time,
            ssrc,
            payload: Bytes::copy_from_slice(payload),
            retransmit,
            path_id: 0,
            frag: rist_core::wire::FragRole::Standalone,
        }
    }

    fn codec_pair(bits: Option<AesKeyBits>, compression: bool, ssrc: u32) -> (AdvCodec, AdvCodec) {
        match bits {
            None => (
                AdvCodec::new(None, None, compression, ssrc, SP, DP),
                AdvCodec::new(None, None, false, ssrc, SP, DP),
            ),
            Some(b) => {
                let sk = crypto::Key::new(b"adv-secret", b, 0, false).unwrap();
                let rd = crypto::Decryptor::new(b"adv-secret", b).unwrap();
                (
                    AdvCodec::new(Some(sk), None, compression, ssrc, SP, DP),
                    AdvCodec::new(None, Some(rd), false, ssrc, SP, DP),
                )
            }
        }
    }

    fn must_media(c: &mut AdvCodec, b: &[u8]) -> MediaPacket {
        match c.decode(&Bytes::copy_from_slice(b)).expect("decode") {
            Decoded::Media(p) => p,
            other => panic!("decoded as {other:?}, want media"),
        }
    }

    #[test]
    fn media_round_trip_all_modes() {
        let cases: &[(&str, Option<AesKeyBits>, bool)] = &[
            ("clear", None, false),
            ("lz4", None, true),
            ("aes128", Some(AesKeyBits::Aes128), false),
            ("aes192", Some(AesKeyBits::Aes192), false),
            ("aes256+lz4", Some(AesKeyBits::Aes256), true),
        ];
        for &(name, bits, comp) in cases {
            const SSRC: u32 = 0x0ACE_0AC0;
            let (mut enc, mut dec) = codec_pair(bits, comp, SSRC);
            // A compressible payload so LZ4 actually fires.
            let payload =
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-advanced-profile-AAAAAAAAAAAAAAAA".to_vec();
            let pkt = media(0x0001_2345, src_ntp(1_000_000), SSRC, &payload, false);
            let dg = enc.encode_media(&pkt).unwrap();
            let got = must_media(&mut dec, &dg);
            assert_eq!(got.seq, pkt.seq, "{name} seq");
            assert_eq!(got.ssrc, SSRC, "{name} ssrc");
            assert!(!got.retransmit, "{name} retransmit");
            assert_eq!(got.payload.as_ref(), payload.as_slice(), "{name} payload");
        }
    }

    #[test]
    fn frag_role_round_trips() {
        // Each fragment role maps to the header F/L bit pair and back. The encode
        // side sets the bits from MediaPacket.frag; the decode side recovers it.
        const SSRC: u32 = 0x0ACE_0AC0;
        for role in [
            FragRole::Standalone,
            FragRole::First,
            FragRole::Middle,
            FragRole::Last,
        ] {
            let (mut enc, mut dec) = codec_pair(None, false, SSRC);
            let pkt = MediaPacket {
                seq: 0x42,
                source_time: src_ntp(2_000_000),
                ssrc: SSRC,
                payload: Bytes::from_static(b"frag-payload"),
                retransmit: false,
                path_id: 0,
                frag: role,
            };
            let dg = enc.encode_media(&pkt).unwrap();
            let got = must_media(&mut dec, &dg);
            assert_eq!(got.frag, role, "{role:?} should survive the round trip");
            assert_eq!(got.payload.as_ref(), b"frag-payload", "{role:?} payload");
        }
    }

    #[test]
    fn frag_flag_mapping_is_total() {
        // The four roles cover the four F/L combinations bijectively.
        assert_eq!(frag_to_flags(FragRole::Standalone), (true, true));
        assert_eq!(frag_to_flags(FragRole::First), (true, false));
        assert_eq!(frag_to_flags(FragRole::Middle), (false, false));
        assert_eq!(frag_to_flags(FragRole::Last), (false, true));
        assert_eq!(flags_to_frag(true, true), FragRole::Standalone);
        assert_eq!(flags_to_frag(true, false), FragRole::First);
        assert_eq!(flags_to_frag(false, false), FragRole::Middle);
        assert_eq!(flags_to_frag(false, true), FragRole::Last);
    }

    #[test]
    fn unknown_control_index_emits_unsupported() {
        let mut c = AdvCodec::new(None, None, false, 0x10, 0, 0);

        // A recognized no-feedback CI (keepalive) queues no Unsupported.
        let mut ka = Vec::new();
        adv::build_control(&mut ka, adv::CI_KEEPALIVE, &[]);
        let _ = c.decode_control_msg(&Bytes::from(ka)).unwrap();
        assert!(
            c.take_unsupported().is_empty(),
            "a recognized CI must not trigger Unsupported"
        );

        // An unrecognized CI queues an Unsupported echoing the CI and the first 48
        // bits of the body.
        let mut unk = Vec::new();
        adv::build_control(
            &mut unk,
            0x7FFF,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x99],
        );
        let _ = c.decode_control_msg(&Bytes::from(unk)).unwrap();
        let pending = c.take_unsupported();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 0x7FFF, "echoed CI");
        assert_eq!(
            pending[0].1,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "first 48 bits"
        );

        // The framed response round-trips to a CI_UNSUPPORTED control echoing both.
        let dg = c
            .encode_unsupported(0x7FFF, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 0)
            .unwrap();
        let parsed = adv::parse(&Bytes::from(dg)).unwrap();
        let (ci, body) = adv::parse_control(&parsed.payload).unwrap();
        assert_eq!(ci, adv::CI_UNSUPPORTED);
        assert_eq!(&body[4..6], &[0x7F, 0xFF], "incoming CI echoed in the body");
        assert_eq!(
            &body[8..14],
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "head echoed"
        );
    }

    #[test]
    fn golden_media_header_shape() {
        // PSK off, no compression, no ports: a bare DIRECT packet.
        let mut c = AdvCodec::new(None, None, false, 0x0ACE_0AC0, 0, 0);
        let dg = c
            .encode_media(&media(
                0x1234_5678,
                src_ntp(0),
                0x0ACE_0AC0,
                &[0xDE, 0xAD],
                false,
            ))
            .unwrap();
        // RTP V=2 PT=127, seq low 0x5678; ext seq_ext 0x1234, flags F|L=0xC0,
        // params Type=DIRECT(5).
        assert_eq!(&dg[..4], &[0x80, 0x7F, 0x56, 0x78]);
        assert_eq!(&dg[8..12], &[0x0A, 0xCE, 0x0A, 0xC0]); // even SSRC
        assert_eq!(&dg[12..16], &[0x12, 0x34, 0xC0, 0x05]); // seq_ext, flags, params
        assert_eq!(&dg[16..], &[0xDE, 0xAD]);
    }

    #[test]
    fn retransmit_dedup_stable() {
        const SSRC: u32 = 0x0042_0042;
        let (mut enc, mut dec) = codec_pair(None, false, SSRC);
        let orig = media(500, src_ntp(5_000_000), SSRC, &[1, 2, 3], false);
        let d0 = must_media(&mut dec, &enc.encode_media(&orig).unwrap());
        for i in 1..=5u32 {
            let p = media(
                500 + i,
                src_ntp(5_000_000 + u64::from(i) * 1000),
                SSRC,
                &[i as u8],
                false,
            );
            must_media(&mut dec, &enc.encode_media(&p).unwrap());
        }
        let mut rt = orig.clone();
        rt.retransmit = true;
        let d_rt = must_media(&mut dec, &enc.encode_media(&rt).unwrap());
        assert_eq!(d_rt.seq, d0.seq);
        assert_eq!(
            d_rt.source_time, d0.source_time,
            "retransmit dedup-stable source time"
        );
        assert!(d_rt.retransmit);
    }

    #[test]
    fn feedback_nack_and_echo_round_trip() {
        const SSRC: u32 = 0x1234_5678;
        let (mut enc, mut dec) = codec_pair(None, false, SSRC);
        let fbs = vec![
            Feedback::Nack {
                ssrc: adv::ssrc_protected(SSRC),
                missing: vec![100, 101, 102, 200],
            },
            Feedback::RttEchoRequest {
                ssrc: 0,
                timestamp: 0xDEAD_BEEF_0000_0001,
            },
        ];
        for bitmask in [false, true] {
            let dgs = enc.encode_feedback(&fbs, bitmask, 0).unwrap();
            let mut nack_missing = Vec::new();
            let mut got_echo = false;
            for dg in &dgs {
                if let Decoded::Feedback(out) = dec.decode(&Bytes::copy_from_slice(dg)).unwrap() {
                    for f in out {
                        match f {
                            Feedback::Nack { missing, .. } => nack_missing.extend(missing),
                            Feedback::RttEchoRequest { timestamp, .. } => {
                                got_echo = timestamp == 0xDEAD_BEEF_0000_0001;
                            }
                            _ => {}
                        }
                    }
                }
            }
            nack_missing.sort_unstable();
            nack_missing.dedup();
            assert_eq!(nack_missing, vec![100, 101, 102, 200], "bitmask={bitmask}");
            assert!(got_echo, "bitmask={bitmask} echo");
        }
    }

    #[test]
    fn control_is_unprotected_ssrc_and_keepalive() {
        let mut c = AdvCodec::new(None, None, false, 0x0ACE_0AC0, 0, 0);
        let ka = c.keepalive_datagram(0).unwrap();
        let p = adv::parse(&Bytes::from(ka)).unwrap();
        assert_eq!(p.enc_type, adv::TYPE_CONTROL);
        assert_eq!(p.ssrc, adv::ssrc_unprotected(0x0ACE_0AC0)); // odd
        assert!(p.expedite);
    }

    #[test]
    fn psk_mismatch_rejected() {
        const SSRC: u32 = 0x5;
        let sk = crypto::Key::new(b"k", AesKeyBits::Aes128, 0, false).unwrap();
        let mut enc = AdvCodec::new(Some(sk), None, false, SSRC, 0, 0);
        let mut plain = AdvCodec::new(None, None, false, SSRC, 0, 0);
        let dg = enc
            .encode_media(&media(1, src_ntp(0), SSRC, &[1], false))
            .unwrap();
        assert!(
            plain.decode(&Bytes::from(dg)).is_err(),
            "encrypted without decryptor"
        );
    }
}
