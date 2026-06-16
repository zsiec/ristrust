//! The Main-profile (VSF TR-06-2) codec strategy: the GRE-tunnelled analog of the
//! Simple-profile codec in [`codec`](crate::codec). It translates between the flow
//! core's normalized [`MediaPacket`] / [`Feedback`] values and Main-profile GRE
//! datagrams, reusing the Simple codec's RTP encode and sequence/timestamp widening
//! ([`codec::encode_media`], [`MediaDecoder::widen`], [`codec::widen_seq_at_most`])
//! and wrapping their bytes in the Main-profile framing. Ported from ristgo
//! `internal/session/codec_main.go`.
//!
//! # Single-port multiplex
//!
//! Main profile carries media AND compound RTCP over one UDP port, both
//! GRE-tunnelled (`RIST_GRE_PROTOCOL_TYPE_REDUCED`). Every outbound datagram is:
//!
//! ```text
//! GRE base header (seq always; +nonce when encrypting)
//!   | reduced-overhead header (virt src/dst port)
//!   | inner RTP packet (media)  OR  compound RTCP (feedback)
//! ```
//!
//! When PSK is enabled the reduced header and the inner RTP/RTCP are encrypted
//! together as one AES-CTR region beginning immediately after the GRE sequence
//! number; the GRE base header, nonce, and sequence stay in cleartext. The IV is
//! the 32-bit GRE sequence ([`crypto::build_iv`]).
//!
//! # GRE sequence number
//!
//! The GRE sequence is the codec's own monotonically increasing per-datagram
//! counter — the AES IV high bytes and the GRE-layer sequence, NOT the media RTP
//! sequence. It increments for every datagram sent, media or RTCP.
//!
//! # Receive demux (the key rule)
//!
//! After GRE parse, decrypting if a key is present, and stripping the 4-byte
//! reduced header, the codec peeks the second byte of the inner packet (the
//! RTP/RTCP payload-type byte). With `pt = byte & 0x7f`, `72 <= pt <= 77` means
//! RTCP (PT 200-205) and routes to compound-RTCP feedback decode; anything else is
//! RTP media. The reduced-header port is not consulted — the PT byte is
//! authoritative, matching libRIST.

// This stateful translation layer is built ahead of its consumer: the Main-profile
// driver (the next host step) calls it on every datagram. Until then it is
// reachable only from its own tests.
#![allow(dead_code)]
// Justification: the codec narrows the 32-bit core sequence to the 16-bit RTP wire
// and slices 16-bit halves off NACK sequences; those casts are deliberate and
// bounded by the field widths.
#![allow(clippy::cast_possible_truncation)]

use bytes::Bytes;

use rist_codec::rtcp::{self, Packet as RtcpPacket};
use rist_codec::{crypto, gre, npd, rtp};
use rist_core::wire::{Feedback, MediaPacket};

use crate::codec::{self, CodecError, MediaDecoder};

/// The inner-packet byte index whose low 7 bits hold the payload type for both RTP
/// (marker+PT) and RTCP (the packet-type octet): the second octet of the inner
/// packet.
const RTCP_PT_BYTE_LOW: usize = 1;

/// The RTCP payload-type window after masking the marker bit: PT 200-205 minus 128.
/// An inner second-byte whose low 7 bits fall in this range is decoded as compound
/// RTCP; anything else is RTP media.
const RTCP_PT_MIN: u8 = 72;
const RTCP_PT_MAX: u8 = 77;

/// The classification of one inbound Main datagram for the GRE control path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlKind {
    /// Not a control datagram (route it to [`MainCodec::decode`]).
    None,
    /// A GRE keepalive; the decoded body is returned alongside when it parsed.
    Keepalive,
}

/// The result of decoding one Main-profile data datagram.
#[derive(Debug)]
pub(crate) enum Decoded {
    /// An RTP media packet, reconstructed into the narrow waist.
    Media(MediaPacket),
    /// A compound-RTCP datagram, decoded into normalized feedback.
    Feedback(Vec<Feedback>),
    /// A VSF buffer-negotiation control message (GRE v2): the peer's advertised
    /// sender-max / receiver-current recovery buffer. A host concern, not flow
    /// input — the driver feeds the sender-max to the flow's auto-scaler.
    BufferNeg(gre::BufferNegotiation),
    /// A well-formed datagram with nothing for the flow core (e.g. a VSF
    /// keepalive subtype).
    Ignored,
}

/// The stateful Main-profile codec for one direction of a flow. It carries the GRE
/// sequence counter, the PSK send [`crypto::Key`] and receive [`crypto::Decryptor`],
/// the media decoder's widening references, and the reduced-header virtual ports. It
/// is NOT safe for concurrent use; the host serializes a single send/receive path
/// onto it.
#[derive(Debug)]
pub(crate) struct MainCodec {
    /// The PSK encryptor, or `None` when encryption is disabled.
    send_key: Option<crypto::Key>,
    /// The PSK decryptor, or `None` when encryption is disabled. It re-derives its
    /// AES key whenever the inbound GRE nonce changes.
    recv_key: Option<crypto::Decryptor>,
    /// Selects the GRE H bit for outbound encrypted datagrams. Meaningful only when
    /// `send_key` is set; the receive path honors the inbound H bit independently.
    key_size_256: bool,
    /// The per-datagram GRE sequence counter (the AES IV high bytes and the
    /// GRE-layer sequence). Increments for every datagram sent.
    gre_seq: u32,
    /// Reconstructs the 32-bit media sequence and NTP-64 source time from a received
    /// RTP packet, exactly as the Simple codec does (16-bit rollover counting).
    dec: MediaDecoder,
    /// The reduced-overhead virtual source port.
    src_port: u16,
    /// The reduced-overhead virtual destination port.
    dst_port: u16,
    /// Selects null-packet deletion on the media encode path.
    npd_enabled: bool,
    /// The even base SSRC of this flow, stamped into outbound compound RTCP.
    ssrc: u32,
    /// The SDES canonical name for outbound compound RTCP.
    cname: String,
}

impl MainCodec {
    /// Constructs a Main-profile codec. `send_key`/`recv_key` may be `None` to
    /// disable PSK; when set they must derive from the same passphrase and key size,
    /// and `key_size_256` must match the send key's size (true for 256-bit).
    /// `npd_enabled` turns on null-packet-deletion suppression on the media encode
    /// path. `ssrc` and `cname` seed the outbound compound RTCP.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the codec config
    pub(crate) fn new(
        send_key: Option<crypto::Key>,
        recv_key: Option<crypto::Decryptor>,
        key_size_256: bool,
        src_port: u16,
        dst_port: u16,
        npd_enabled: bool,
        ssrc: u32,
        cname: String,
    ) -> MainCodec {
        MainCodec {
            send_key,
            recv_key,
            key_size_256,
            gre_seq: 0,
            dec: MediaDecoder::new(),
            src_port,
            dst_port,
            npd_enabled,
            ssrc,
            cname,
        }
    }

    /// Whether a PSK is configured (a send key is present). When a passphrase was
    /// configured (`with_secret`), the data channel keys from it and the EAP-SRP
    /// handshake only gates the channel; with no PSK, the host re-keys to the SRP
    /// session key K after authentication.
    pub(crate) fn has_psk(&self) -> bool {
        self.send_key.is_some()
    }

    /// Re-keys the data channel to a new PSK passphrase, deriving a fresh send
    /// [`crypto::Key`] and receive [`crypto::Decryptor`] over it. After EAP-SRP
    /// authentication libRIST sets the data passphrase to the SRP session key K (or
    /// a pushed passphrase), so the host calls this with K to flow encrypted media.
    pub(crate) fn set_psk(&mut self, passphrase: &[u8]) -> Result<(), CodecError> {
        let bits = crypto::AesKeyBits::Aes256;
        self.send_key = Some(crypto::Key::new(passphrase, bits, 0, false)?);
        self.recv_key = Some(crypto::Decryptor::new(passphrase, bits)?);
        self.key_size_256 = true;
        Ok(())
    }

    /// The raw on-the-wire RTP timestamp of the last decoded media packet — the value
    /// the separate-port FEC XOR is keyed on (delegated to the media decoder).
    pub(crate) fn last_wire_ts(&self) -> u32 {
        self.dec.last_wire_ts()
    }

    /// Reconstructs the dedup-stable source time of a FEC-recovered packet from its
    /// recovered RTP timestamp, without advancing the decoder's reference.
    pub(crate) fn fec_source_time(&self, wire_ts: u32) -> u64 {
        self.dec.source_time(wire_ts)
    }

    /// The payload the FEC must be computed over for this codec (TR-06-2 §8.6.2).
    /// When null-packet deletion is active the sender transmits the suppressed
    /// payload but the receiver reconstructs the expanded form, so FEC must be over
    /// that canonical expanded form: suppress then expand to normalize the nulls. A
    /// no-op when NPD is off, the payload carries no canonicalizable nulls, or the
    /// payload is FEC-ineligible — FEC is then over the payload as-is.
    pub(crate) fn fec_payload(&self, payload: &Bytes) -> Bytes {
        if !self.npd_enabled {
            return payload.clone();
        }
        let mut reduced = Vec::new();
        let Ok((bits, suppressed)) = npd::suppress(&mut reduced, payload) else {
            return payload.clone();
        };
        if suppressed == 0 {
            return payload.clone(); // no canonicalizable nulls
        }
        let mut canon = Vec::new();
        if npd::expand(&mut canon, &reduced, bits).is_err() {
            return payload.clone();
        }
        Bytes::from(canon)
    }

    // ---- encode ----

    /// Encodes a normalized [`MediaPacket`] as one Main-profile data datagram. The
    /// RTP packet is built exactly as the Simple codec's `encode_media` does; when
    /// NPD is enabled and the payload is a whole number of ≤7 TS packets containing
    /// at least one null packet, the nulls are suppressed and a RIST NPD header
    /// extension is prepended. The RTP bytes are then framed in the reduced-overhead
    /// header and GRE, encrypted under the PSK when one is configured.
    pub(crate) fn encode_media(&mut self, pkt: &MediaPacket) -> Result<Vec<u8>, CodecError> {
        let inner = self.build_media_rtp(pkt)?;
        self.frame(&inner)
    }

    /// Builds the inner RTP packet for a media datagram, applying NPD suppression and
    /// the RIST header extension when enabled and applicable. When NPD does not apply
    /// — disabled, ineligible payload, or no null packets present — the RTP packet is
    /// byte-identical to the Simple codec's `encode_media` output.
    fn build_media_rtp(&mut self, pkt: &MediaPacket) -> Result<Vec<u8>, CodecError> {
        if self.npd_enabled {
            let mut reduced = Vec::new();
            // Suppress copies through unchanged (suppressed==0) when there are no
            // nulls, and errors on an ineligible size. Either way, fall back to a
            // plain RTP packet — libRIST attaches the extension only when
            // suppression fired.
            if let Ok((bits, suppressed)) = npd::suppress(&mut reduced, &pkt.payload)
                && suppressed > 0
            {
                let ssrc = if pkt.retransmit {
                    rtp::mark_retransmit(pkt.ssrc)
                } else {
                    pkt.ssrc
                };
                let ext = npd::Ext {
                    npd: true,
                    size204: bits & npd::NPD_SIZE_204 != 0,
                    null_bitmap: bits & npd::NULL_BITMAP_MASK,
                    // libRIST emits seq_ext=0 on the Simple/Main path; the receiver
                    // widens by rollover, not from seq_ext.
                    seq_ext: 0,
                };
                // The RTP layer writes the 4-byte RFC 3550 extension header itself;
                // the extension payload is only the four bytes after it (flags,
                // npd_bits, seq_ext) — Ext's 8-byte encoding minus identifier+length.
                let mut ext_full = Vec::with_capacity(npd::EXT_SIZE);
                ext.append_to(&mut ext_full);
                let p = rtp::Packet {
                    header: rtp::Header {
                        version: rtp::VERSION,
                        payload_type: rtp::PAYLOAD_TYPE_MPEGTS,
                        sequence_number: pkt.seq as u16,
                        timestamp: codec::rtp_ts_from_source(pkt.source_time),
                        ssrc,
                        extension: true,
                        extension_profile: npd::IDENTIFIER,
                        extension_payload: Bytes::copy_from_slice(&ext_full[4..]),
                        ..rtp::Header::default()
                    },
                    payload: Bytes::from(reduced),
                    padding_size: 0,
                };
                return Ok(p.encode()?.to_vec());
            }
        }
        Ok(codec::encode_media(pkt)?.to_vec())
    }

    /// Encodes one Main-profile feedback datagram. It builds the compound RTCP
    /// exactly as the Simple codec's `encode_feedback` does — the lead SR/RR, then
    /// SDES/CNAME, then NACKs, then echoes — but interleaves an EXTSEQ APP packet
    /// before any NACK whose missing sequences have non-zero high 16 bits (TR-06-2
    /// §8.4). The compound is then framed in the reduced header and GRE, encrypted
    /// under the PSK when one is configured. `bitmask` selects the NACK encoding.
    pub(crate) fn encode_feedback(
        &mut self,
        lead: RtcpPacket,
        fbs: &[Feedback],
        bitmask: bool,
    ) -> Result<Vec<u8>, CodecError> {
        let compound = self.build_compound(lead, fbs, bitmask)?;
        self.frame(&compound)
    }

    /// Assembles the compound RTCP bytes for a feedback datagram (lead, SDES, NACKs,
    /// echoes), splitting a NACK whose sequences span more than the low 16 bits by
    /// upper half and preceding each group with its own EXTSEQ packet (TR-06-2 §8.4).
    fn build_compound(
        &self,
        lead: RtcpPacket,
        fbs: &[Feedback],
        bitmask: bool,
    ) -> Result<Vec<u8>, CodecError> {
        let mut pkts = vec![
            lead,
            RtcpPacket::Sdes(rtcp::Sdes {
                ssrc: self.ssrc,
                cname: self.cname.clone(),
            }),
        ];
        let mut nacks = Vec::new();
        let mut echoes = Vec::new();
        for fb in fbs {
            match fb {
                Feedback::Nack { ssrc, missing } => {
                    self.encode_nack(*ssrc, missing, bitmask, &mut nacks);
                }
                Feedback::RttEchoRequest { timestamp, .. } => {
                    // Originated request: stamp the local SSRC so the peer's response
                    // filter accepts our echo.
                    echoes.push(RtcpPacket::EchoRequest(rtcp::EchoRequest {
                        ssrc: self.ssrc,
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
                // FlowAttribute is Advanced-only; the Main wire never emits it.
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

    /// Encodes one NACK into RTCP packets, prepending an EXTSEQ packet before each
    /// group of missing sequences that share an upper 16 bits. When every missing
    /// sequence has a zero upper half, no EXTSEQ is emitted and the output matches
    /// the Simple codec exactly.
    fn encode_nack(
        &self,
        media_ssrc: u32,
        missing: &[u32],
        bitmask: bool,
        out: &mut Vec<RtcpPacket>,
    ) {
        if missing.is_empty() {
            return;
        }
        if !missing.iter().any(|&s| s >> 16 != 0) {
            self.nack_packets(media_ssrc, missing, bitmask, out);
            return;
        }
        // Split into runs of equal upper half, preserving order, each preceded by
        // its EXTSEQ packet.
        let mut i = 0;
        while i < missing.len() {
            let hi = (missing[i] >> 16) as u16;
            let mut j = i;
            while j < missing.len() && (missing[j] >> 16) as u16 == hi {
                j += 1;
            }
            out.push(RtcpPacket::ExtSeq(rtcp::ExtSeq {
                ssrc: self.ssrc,
                seq_high: hi,
            }));
            self.nack_packets(media_ssrc, &missing[i..j], bitmask, out);
            i = j;
        }
    }

    /// Encodes a slice of missing sequences into range or bitmask NACK packets (the
    /// low 16 bits are used; the codec has already grouped by upper half).
    fn nack_packets(
        &self,
        media_ssrc: u32,
        missing: &[u32],
        bitmask: bool,
        out: &mut Vec<RtcpPacket>,
    ) {
        if bitmask {
            // SenderSSRC is zero: libRIST ignores it and transmits zero.
            for p in rtcp::encode_bitmask_nack(0, media_ssrc, missing) {
                out.push(RtcpPacket::BitmaskNack(p));
            }
        } else {
            for p in rtcp::encode_range_nack(self.ssrc, media_ssrc, missing) {
                out.push(RtcpPacket::RangeNack(p));
            }
        }
    }

    /// Frames an inner packet (an RTP packet or compound RTCP) in the reduced-overhead
    /// header and GRE header, encrypting the reduced header together with the inner
    /// packet under the PSK when one is configured. Increments the GRE sequence once.
    fn frame(&mut self, inner: &[u8]) -> Result<Vec<u8>, CodecError> {
        let seq = self.gre_seq;
        self.gre_seq = self.gre_seq.wrapping_add(1);
        let key_size_256 = self.key_size_256;
        let reduced = gre::ReducedHeader {
            src_port: self.src_port,
            dst_port: self.dst_port,
        };
        let mut hdr = gre::Header {
            version: gre::VERSION_MIN, // version 1: REDUCED written directly
            has_seq: true,
            prot_type: gre::PROTO_REDUCED,
            seq,
            ..gre::Header::default()
        };
        let mut out = Vec::new();
        if let Some(key) = self.send_key.as_mut() {
            // The AES-CTR region is the reduced header + inner packet, encrypted as
            // one block under the GRE sequence's IV. The key may rotate on encrypt,
            // so read the nonce afterwards.
            let mut region = Vec::with_capacity(gre::REDUCED_HEADER_SIZE + inner.len());
            reduced.append_to(&mut region);
            region.extend_from_slice(inner);
            let ct = key.encrypt(seq, &region)?;
            hdr.has_key = true;
            hdr.key_size_256 = key_size_256;
            hdr.nonce = key.nonce();
            hdr.append_to(&mut out)?;
            out.extend_from_slice(&ct);
        } else {
            hdr.append_to(&mut out)?;
            reduced.append_to(&mut out);
            out.extend_from_slice(inner);
        }
        Ok(out)
    }

    /// Frames a GRE control body (keepalive) at the given GRE version: version 1
    /// writes the protocol type directly; version ≥ 2 wraps it in the VSF ethertype
    /// plus a 4-byte VSF proto. The body is encrypted under the PSK when one is
    /// configured (matching libRIST, which runs keepalives through the encrypted
    /// path).
    fn frame_control(
        &mut self,
        body: &[u8],
        version: u8,
        proto: u16,
        vsf_subtype: u16,
    ) -> Result<Vec<u8>, CodecError> {
        let seq = self.gre_seq;
        self.gre_seq = self.gre_seq.wrapping_add(1);
        let key_size_256 = self.key_size_256;
        let mut hdr = gre::Header {
            version,
            has_seq: true,
            seq,
            ..gre::Header::default()
        };
        let mut region = Vec::new();
        if version >= gre::VERSION_CUR {
            hdr.prot_type = gre::PROTO_VSF;
            gre::VsfProto {
                ty: gre::VSF_TYPE_RIST,
                subtype: vsf_subtype,
            }
            .append_to(&mut region);
            region.extend_from_slice(body);
        } else {
            hdr.prot_type = proto;
            region.extend_from_slice(body);
        }
        let mut out = Vec::new();
        if let Some(key) = self.send_key.as_mut() {
            let ct = key.encrypt(seq, &region)?;
            hdr.has_key = true;
            hdr.key_size_256 = key_size_256;
            hdr.nonce = key.nonce();
            hdr.append_to(&mut out)?;
            out.extend_from_slice(&ct);
        } else {
            hdr.append_to(&mut out)?;
            out.extend_from_slice(&region);
        }
        Ok(out)
    }

    /// Frames a GRE keepalive carrying this node's MAC and capability bits, at the
    /// negotiated GRE version.
    pub(crate) fn encode_keepalive(
        &mut self,
        ka: &gre::Keepalive,
        version: u8,
    ) -> Result<Vec<u8>, CodecError> {
        let mut body = Vec::new();
        ka.append_to(&mut body);
        self.frame_control(
            &body,
            version,
            gre::PROTO_KEEPALIVE,
            gre::VSF_SUBTYPE_KEEPALIVE,
        )
    }

    /// Frames a VSF buffer-negotiation control message (GRE v2 only — the VSF
    /// wrapper carries the subtype). Each peer uses it to advertise the recovery
    /// buffer it allows as a sender / uses as a receiver (libRIST
    /// `rist_buffer_negotiation`).
    pub(crate) fn encode_buffer_neg(
        &mut self,
        bn: gre::BufferNegotiation,
    ) -> Result<Vec<u8>, CodecError> {
        let mut body = Vec::new();
        bn.append_to(&mut body);
        self.frame_control(
            &body,
            gre::VERSION_CUR,
            gre::PROTO_VSF,
            gre::VSF_SUBTYPE_BUFFER_NEGOTIATION,
        )
    }

    /// Frames an EAP-over-GRE authentication payload: the GRE header (version 1,
    /// sequence present, protocol type EAPOL) followed by the EAP frame, never
    /// encrypted (libRIST excludes EAPOL from PSK). Increments the GRE sequence once.
    pub(crate) fn encode_eapol(&mut self, eap: &[u8]) -> Result<Vec<u8>, CodecError> {
        let seq = self.gre_seq;
        self.gre_seq = self.gre_seq.wrapping_add(1);
        let hdr = gre::Header {
            version: gre::VERSION_MIN,
            has_seq: true,
            prot_type: gre::PROTO_EAPOL,
            seq,
            ..gre::Header::default()
        };
        let mut out = Vec::new();
        hdr.append_to(&mut out)?;
        out.extend_from_slice(eap);
        Ok(out)
    }

    /// Reports whether `b` is an EAP-over-GRE authentication frame and, if so,
    /// returns the EAP payload (the bytes after the GRE header; EAPOL is never
    /// encrypted). The host runs it before [`MainCodec::decode`] so authentication
    /// frames route to the EAP state machine. Never panics on arbitrary input.
    pub(crate) fn peek_eapol<'a>(&self, b: &'a [u8]) -> Option<&'a [u8]> {
        let (hdr, off) = gre::Header::parse(b).ok()?;
        if hdr.prot_type == gre::PROTO_EAPOL {
            Some(&b[off..])
        } else {
            None
        }
    }

    /// Frames one out-of-band datagram (libRIST `RIST_PAYLOAD_TYPE_DATA_OOB`): a GRE
    /// frame carrying `prot_type` (an EtherType; [`gre::PROTO_FULL`] = libRIST's OOB)
    /// with no reduced/RTP header — the raw `payload` follows the GRE header,
    /// encrypted under the PSK when configured (OOB rides the PSK but never ARQ). The
    /// GRE sequence is shared with media (it is the AES IV), so OOB and media advance
    /// one monotonic sequence.
    pub(crate) fn encode_oob(
        &mut self,
        payload: &[u8],
        prot_type: u16,
    ) -> Result<Vec<u8>, CodecError> {
        let seq = self.gre_seq;
        self.gre_seq = self.gre_seq.wrapping_add(1);
        let key_size_256 = self.key_size_256;
        let mut hdr = gre::Header {
            version: gre::VERSION_MIN,
            has_seq: true,
            prot_type,
            seq,
            ..gre::Header::default()
        };
        let mut out = Vec::new();
        if let Some(key) = self.send_key.as_mut() {
            let ct = key.encrypt(seq, payload)?;
            hdr.has_key = true;
            hdr.key_size_256 = key_size_256;
            hdr.nonce = key.nonce();
            hdr.append_to(&mut out)?;
            out.extend_from_slice(&ct);
        } else {
            hdr.append_to(&mut out)?;
            out.extend_from_slice(payload);
        }
        Ok(out)
    }

    /// Reports whether `b` is an out-of-band datagram (a GRE frame whose protocol
    /// type is not one RIST reserves for its own framing) and, if so, returns its
    /// decrypted payload and that protocol type. Unlike EAPOL, OOB participates in
    /// PSK, so it decrypts; the per-packet K bit is honored independently (a
    /// cleartext OOB datagram is returned as cleartext even with a decryptor
    /// configured). `Ok(None)` means `b` is not OOB (route it to the media/control
    /// demux). Never panics on arbitrary input.
    pub(crate) fn peek_oob(&mut self, b: &[u8]) -> Result<Option<(Vec<u8>, u16)>, CodecError> {
        let Ok((hdr, off)) = gre::Header::parse(b) else {
            return Ok(None);
        };
        if gre::is_reserved(hdr.prot_type) {
            return Ok(None);
        }
        let region = &b[off..];
        let payload = if hdr.has_key {
            let Some(key) = self.recv_key.as_mut() else {
                return Err(CodecError::Main(
                    "encrypted OOB but no decryptor configured",
                ));
            };
            key.set_key_bits(crypto::AesKeyBits::from_h_bit(hdr.key_size_256));
            key.decrypt(hdr.nonce, hdr.seq, region)?
        } else {
            region.to_vec()
        };
        Ok(Some((payload, hdr.prot_type)))
    }

    // ---- decode ----

    /// Parses one Main-profile data datagram, demultiplexing on the inner packet's
    /// payload-type byte: RTP media or compound RTCP. `nack_ref` is the host's
    /// current send position; it widens the 16-bit sequences of any NACK not
    /// preceded by an EXTSEQ packet. Arbitrary, truncated, or short-ciphertext input
    /// returns an error and never panics.
    pub(crate) fn decode(&mut self, b: &[u8], nack_ref: u32) -> Result<Decoded, CodecError> {
        let (hdr, off) = gre::Header::parse(b)?;
        let is_vsf = match hdr.prot_type {
            gre::PROTO_REDUCED => false,
            gre::PROTO_VSF => true,
            _ => return Err(CodecError::Main("GRE protocol type is not reduced")),
        };
        let mut region = self.unwrap_region(&hdr, &b[off..])?;

        // Unwrap the version-2 VSF proto (now decrypted). Only REDUCED carries
        // media/RTCP we decode; keepalive/buffer-negotiation subtypes are accepted
        // without action rather than dropped.
        if is_vsf {
            let (vsf, vn) = gre::VsfProto::parse(&region)?;
            if vsf.subtype == gre::VSF_SUBTYPE_BUFFER_NEGOTIATION {
                // The peer's recovery-buffer advertisement (GRE v2); surfaced to the
                // host, which feeds the sender-max to the flow's auto-scaler.
                return Ok(Decoded::BufferNeg(gre::BufferNegotiation::parse(
                    &region[vn..],
                )?));
            }
            if vsf.subtype != gre::VSF_SUBTYPE_REDUCED {
                return Ok(Decoded::Ignored);
            }
            region = region.slice(vn..);
        }

        // Strip the reduced-overhead header; the inner packet follows.
        let (_, n) = gre::ReducedHeader::parse(&region)?;
        region = region.slice(n..);

        // Demux on the inner packet's payload-type byte (the authoritative rule).
        if region.len() <= RTCP_PT_BYTE_LOW {
            return Err(CodecError::Main("inner packet too short to demux"));
        }
        let pt = region[RTCP_PT_BYTE_LOW] & 0x7F;
        if (RTCP_PT_MIN..=RTCP_PT_MAX).contains(&pt) {
            Ok(Decoded::Feedback(
                self.decode_feedback_main(&region, nack_ref)?,
            ))
        } else {
            Ok(Decoded::Media(self.decode_media_main(&region)?))
        }
    }

    /// Returns the region after the GRE header, decrypted when a key is present. A
    /// configured decryptor and a key-bearing header must agree.
    fn unwrap_region(&mut self, hdr: &gre::Header, after_gre: &[u8]) -> Result<Bytes, CodecError> {
        if hdr.has_key {
            let Some(key) = self.recv_key.as_mut() else {
                return Err(CodecError::Main(
                    "encrypted datagram but no decryptor configured",
                ));
            };
            // Honor the GRE H bit: derive at the size the sender signalled.
            key.set_key_bits(crypto::AesKeyBits::from_h_bit(hdr.key_size_256));
            Ok(Bytes::from(key.decrypt(hdr.nonce, hdr.seq, after_gre)?))
        } else if self.recv_key.is_some() {
            Err(CodecError::Main(
                "cleartext datagram but decryptor configured",
            ))
        } else {
            Ok(Bytes::copy_from_slice(after_gre))
        }
    }

    /// Reconstructs a [`MediaPacket`] from an inner RTP packet, NPD-expanding the
    /// payload when the RTP X bit carries the RIST NPD extension at its canonical
    /// shape. The 32-bit media sequence always widens by rollover counting (the
    /// extension's seq_ext is ignored, as libRIST never populates it on this path).
    fn decode_media_main(&mut self, region: &Bytes) -> Result<MediaPacket, CodecError> {
        let p = rtp::Packet::decode(region)?;
        if p.header.version != rtp::VERSION {
            return Err(CodecError::BadVersion(p.header.version));
        }
        let mut payload = p.payload.clone();
        // Honor the RIST NPD extension only at its canonical shape: identifier 0x5249
        // and length 1 (a four-byte payload).
        if p.header.extension
            && p.header.extension_profile == npd::IDENTIFIER
            && p.header.extension_payload.len() == npd::EXT_SIZE - 4
        {
            // Reassemble the 8-byte extension so npd::Ext::parse validates it.
            let mut ext_wire = Vec::with_capacity(npd::EXT_SIZE);
            ext_wire.extend_from_slice(&npd::IDENTIFIER.to_be_bytes());
            ext_wire.extend_from_slice(&npd::LENGTH.to_be_bytes());
            ext_wire.extend_from_slice(&p.header.extension_payload);
            let (ext, _) = npd::Ext::parse(&ext_wire)?;
            if ext.npd {
                let mut expanded = Vec::new();
                npd::expand(
                    &mut expanded,
                    &payload,
                    npd::npd_bits(ext.size204, ext.null_bitmap),
                )?;
                payload = Bytes::from(expanded);
            }
        }
        let (seq, source_time) = self.dec.widen(p.header.sequence_number, p.header.timestamp);
        Ok(MediaPacket {
            seq,
            source_time,
            ssrc: rtp::normalize_ssrc(p.header.ssrc),
            payload,
            retransmit: rtp::is_retransmit(p.header.ssrc),
            path_id: 0,
            // The Main profile does not fragment; every payload is whole.
            frag: rist_core::wire::FragRole::Standalone,
        })
    }

    /// Parses a compound RTCP datagram into normalized feedback, folding each EXTSEQ
    /// packet's high 16 bits into the NACK packets that follow it (TR-06-2 §8.4).
    fn decode_feedback_main(
        &self,
        region: &Bytes,
        nack_ref: u32,
    ) -> Result<Vec<Feedback>, CodecError> {
        let pkts = rtcp::parse_compound(region)?;
        let mut out = Vec::new();
        let mut seq_high = 0u16;
        let mut have_ext = false;
        for p in &pkts {
            match p {
                RtcpPacket::ExtSeq(e) => {
                    seq_high = e.seq_high;
                    have_ext = true;
                }
                RtcpPacket::RangeNack(pk) => {
                    out.push(fold_nack(
                        pk.media_ssrc,
                        &pk.missing_seqs(),
                        seq_high,
                        have_ext,
                        nack_ref,
                    ));
                    have_ext = false; // an EXTSEQ qualifies the NACK(s) that follow it
                }
                RtcpPacket::BitmaskNack(pk) => {
                    out.push(fold_nack(
                        pk.media_ssrc,
                        &pk.missing_seqs(),
                        seq_high,
                        have_ext,
                        nack_ref,
                    ));
                    have_ext = false;
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
                RtcpPacket::LinkQualityReport(pk) => {
                    out.push(Feedback::LinkQuality { lqm: pk.lqm });
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Classifies one inbound Main datagram for the GRE control path. It always
    /// returns the sender's GRE version (for the monotonic version upgrade) and, for
    /// a version-1 keepalive, decodes the keepalive body. A version-2 VSF datagram
    /// returns [`ControlKind::None`] — its subtype lives inside the (possibly
    /// encrypted) region, which [`MainCodec::decode`] owns. Never panics.
    pub(crate) fn peek_control(&mut self, b: &[u8]) -> (ControlKind, Option<gre::Keepalive>, u8) {
        let Ok((hdr, off)) = gre::Header::parse(b) else {
            return (ControlKind::None, None, 0);
        };
        let version = hdr.version;
        if hdr.prot_type != gre::PROTO_KEEPALIVE {
            return (ControlKind::None, None, version);
        }
        let region = if hdr.has_key {
            let Some(key) = self.recv_key.as_mut() else {
                return (ControlKind::None, None, version);
            };
            key.set_key_bits(crypto::AesKeyBits::from_h_bit(hdr.key_size_256));
            match key.decrypt(hdr.nonce, hdr.seq, &b[off..]) {
                Ok(pt) => Bytes::from(pt),
                // It IS a keepalive, just undecodable — still a liveness signal.
                Err(_) => return (ControlKind::Keepalive, None, version),
            }
        } else {
            Bytes::copy_from_slice(&b[off..])
        };
        match gre::Keepalive::parse(&region) {
            Ok(ka) => (ControlKind::Keepalive, Some(ka), version),
            Err(_) => (ControlKind::Keepalive, None, version),
        }
    }
}

/// Widens a NACK's 16-bit sequence list to 32 bits. When an EXTSEQ preceded this
/// NACK its `seq_high` is prepended to every entry (the authoritative TR-06-2 §8.4
/// widening); otherwise the entries widen to at-most `nack_ref`, the host's send
/// position, matching the Simple codec's NACK widening.
fn fold_nack(ssrc: u32, narrow: &[u32], seq_high: u16, have_ext: bool, nack_ref: u32) -> Feedback {
    let missing = if have_ext {
        narrow
            .iter()
            .map(|&s| (u32::from(seq_high) << 16) | (s & 0xFFFF))
            .collect()
    } else {
        narrow
            .iter()
            .map(|&s| codec::widen_seq_at_most(s as u16, nack_ref))
            .collect()
    };
    Feedback::Nack { ssrc, missing }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // synthetic TS PIDs fit u16/u8 by construction
mod tests {
    use super::*;
    use rist_codec::crypto::AesKeyBits;
    use rist_codec::rtcp::EmptyReceiverReport;
    use rist_core::clock::{Ntp64, Timestamp};

    const SP: u16 = gre::DEFAULT_VIRT_SRC_PORT;
    const DP: u16 = gre::DEFAULT_VIRT_DST_PORT;

    /// The NTP-64 source time for a microsecond instant.
    fn src_ntp(us: u64) -> u64 {
        Ntp64::from_timestamp(Timestamp::from_micros(us)).bits()
    }

    /// A non-null 188/204-byte MPEG-TS packet with PID `pid`.
    fn ts_packet(size: usize, pid: u16, fill: u8) -> Vec<u8> {
        let mut p = vec![fill; size];
        p[0] = 0x47;
        p[1] = ((pid >> 8) & 0x1F) as u8;
        p[2] = pid as u8;
        p[3] = 0x10;
        p
    }

    /// A 188/204-byte MPEG-TS null packet (PID 0x1FFF) as npd::expand reconstructs it.
    fn ts_null(size: usize) -> Vec<u8> {
        let mut p = vec![0xFF; size];
        p[0] = 0x47;
        p[1] = 0x1F;
        p[2] = 0xFF;
        p[3] = 1 << 4;
        p
    }

    /// A send/receive codec pair for a round-trip test. `bits` is `None` for
    /// cleartext; `npd_enabled` applies to the send side only.
    fn codec_pair(
        bits: Option<AesKeyBits>,
        npd_enabled: bool,
        ssrc: u32,
    ) -> (MainCodec, MainCodec) {
        match bits {
            None => (
                MainCodec::new(None, None, false, SP, DP, npd_enabled, ssrc, "cam".into()),
                MainCodec::new(None, None, false, SP, DP, false, ssrc, "cam".into()),
            ),
            Some(b) => {
                let sk = crypto::Key::new(b"s3cr3t", b, 0, false).unwrap();
                let rd = crypto::Decryptor::new(b"s3cr3t", b).unwrap();
                let k256 = b == AesKeyBits::Aes256;
                (
                    MainCodec::new(
                        Some(sk),
                        None,
                        k256,
                        SP,
                        DP,
                        npd_enabled,
                        ssrc,
                        "cam".into(),
                    ),
                    MainCodec::new(None, Some(rd), k256, SP, DP, false, ssrc, "cam".into()),
                )
            }
        }
    }

    fn must_media(c: &mut MainCodec, b: &[u8]) -> MediaPacket {
        match c.decode(b, 0).expect("decode") {
            Decoded::Media(p) => p,
            other => panic!("decoded as {other:?}, want media"),
        }
    }

    #[test]
    fn golden_main_media_datagram() {
        let mut c = MainCodec::new(None, None, false, SP, DP, false, 0x0ACE_0AC0, "cam".into());
        let pkt = MediaPacket {
            seq: 0x1234,
            source_time: src_ntp(0),
            ssrc: 0x0ACE_0AC0,
            payload: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
            retransmit: false,
            path_id: 0,
            frag: rist_core::wire::FragRole::Standalone,
        };
        let got = c.encode_media(&pkt).unwrap();
        let want: &[u8] = &[
            0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00, // GRE
            0x07, 0xB3, 0x07, 0xB0, // reduced 1971/1968
            0x80, 0x21, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, // RTP hdr
            0x0A, 0xCE, 0x0A, 0xC0, // SSRC
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn main_media_round_trip() {
        let cases: &[(&str, Option<AesKeyBits>, bool)] = &[
            ("clear", None, false),
            ("clear+npd", None, true),
            ("aes128", Some(AesKeyBits::Aes128), false),
            ("aes128+npd", Some(AesKeyBits::Aes128), true),
            ("aes256", Some(AesKeyBits::Aes256), false),
            ("aes256+npd", Some(AesKeyBits::Aes256), true),
        ];
        for &(name, bits, npd_on) in cases {
            const SSRC: u32 = 0x0BAD_F00E;
            let (mut enc, mut dec) = codec_pair(bits, npd_on, SSRC);
            let mut payload = ts_packet(188, 0x100, 0xAA);
            payload.extend_from_slice(&ts_null(188));
            let pkt = MediaPacket {
                seq: 0x2345,
                source_time: src_ntp(1_000_000),
                ssrc: SSRC,
                payload: Bytes::from(payload.clone()),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            };
            let dg = enc.encode_media(&pkt).unwrap();
            let got = must_media(&mut dec, &dg);
            assert_eq!(got.seq, pkt.seq, "{name} seq");
            assert_eq!(got.ssrc, SSRC, "{name} ssrc");
            assert!(!got.retransmit, "{name} retransmit");
            assert_eq!(got.payload.as_ref(), payload.as_slice(), "{name} payload");
        }
    }

    #[test]
    fn main_media_seq_wrap_rollover() {
        const SSRC: u32 = 0x00CA_FE00;
        let (mut enc, mut dec) = codec_pair(None, true, SSRC); // NPD on
        let lows: [u16; 6] = [0xFFFD, 0xFFFE, 0xFFFF, 0x0000, 0x0001, 0x0002];
        let mut prev = 0u32;
        for (i, &low) in lows.iter().enumerate() {
            let mut payload = ts_packet(188, 0x101, 0xBB);
            payload.extend_from_slice(&ts_null(188));
            let pkt = MediaPacket {
                seq: 0x0003_0000 | u32::from(low), // bogus high bits; must be ignored
                source_time: src_ntp(2_000_000 + i as u64 * 1000),
                ssrc: SSRC,
                payload: Bytes::from(payload.clone()),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            };
            let dg = enc.encode_media(&pkt).unwrap();
            let got = must_media(&mut dec, &dg);
            assert_eq!(got.payload.as_ref(), payload.as_slice(), "payload[{i}]");
            if i == 0 {
                assert_eq!(got.seq, u32::from(low), "first seq anchored at low 16 bits");
            } else {
                assert_eq!(got.seq, prev + 1, "monotonic rollover at [{i}]");
            }
            prev = got.seq;
        }
        assert_eq!(prev >> 16, 1, "high bits after the wrap (final {prev:#x})");
    }

    #[test]
    fn main_retransmit_dedup() {
        const SSRC: u32 = 0x0042_0042;
        let (mut enc, mut dec) = codec_pair(None, false, SSRC);
        let orig = MediaPacket {
            seq: 500,
            source_time: src_ntp(5_000_000),
            ssrc: SSRC,
            payload: Bytes::from_static(&[1, 2, 3]),
            retransmit: false,
            path_id: 0,
            frag: rist_core::wire::FragRole::Standalone,
        };
        let dg0 = enc.encode_media(&orig).unwrap();
        let d0 = must_media(&mut dec, &dg0);
        for i in 1..=5u32 {
            let p = MediaPacket {
                seq: 500 + i,
                source_time: src_ntp(5_000_000 + u64::from(i) * 1000),
                ssrc: SSRC,
                payload: Bytes::copy_from_slice(&[i as u8]),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            };
            must_media(&mut dec, &enc.encode_media(&p).unwrap());
        }
        let mut rt = orig.clone();
        rt.retransmit = true;
        let d_rt = must_media(&mut dec, &enc.encode_media(&rt).unwrap());
        assert_eq!(d_rt.seq, d0.seq, "retransmit seq == original");
        assert_eq!(
            d_rt.source_time, d0.source_time,
            "retransmit src == original"
        );
        assert!(d_rt.retransmit, "retransmit flag");
    }

    #[test]
    fn main_feedback_round_trip() {
        let cases: &[(&str, Option<AesKeyBits>, bool)] = &[
            ("clear-range", None, false),
            ("clear-bitmask", None, true),
            ("aes128-range", Some(AesKeyBits::Aes128), false),
            ("aes256-bitmask", Some(AesKeyBits::Aes256), true),
        ];
        for &(name, bits, bitmask) in cases {
            const SSRC: u32 = 0x1234_5678;
            let (mut enc, mut dec) = codec_pair(bits, false, SSRC);
            let fbs = vec![
                Feedback::Nack {
                    ssrc: SSRC,
                    missing: vec![100, 101, 200],
                },
                Feedback::RttEchoRequest {
                    ssrc: 0,
                    timestamp: 0xDEAD_BEEF_0000_0001,
                },
                Feedback::RttEchoResponse {
                    ssrc: SSRC,
                    timestamp: 0xCAFE_0000_0000_0002,
                    processing_delay: 250,
                },
            ];
            let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: SSRC });
            let dg = enc.encode_feedback(lead, &fbs, bitmask).unwrap();
            let out = match dec.decode(&dg, 300).expect("decode") {
                Decoded::Feedback(f) => f,
                other => panic!("{name}: decoded as {other:?}, want feedback"),
            };
            let mut nack = None;
            let mut got_req = false;
            let mut got_resp = false;
            for fb in &out {
                match fb {
                    Feedback::Nack { missing, .. } => nack = Some(missing.clone()),
                    Feedback::RttEchoRequest { timestamp, .. } => {
                        got_req = *timestamp == 0xDEAD_BEEF_0000_0001;
                    }
                    Feedback::RttEchoResponse {
                        timestamp,
                        processing_delay,
                        ..
                    } => got_resp = *timestamp == 0xCAFE_0000_0000_0002 && *processing_delay == 250,
                    _ => {}
                }
            }
            assert_eq!(nack, Some(vec![100, 101, 200]), "{name} nack");
            assert!(got_req, "{name} echo request");
            assert!(got_resp, "{name} echo response");
        }
    }

    #[test]
    fn main_nack_extseq() {
        const SSRC: u32 = 0xDEAD_BEEE;
        let (mut enc, mut dec) = codec_pair(None, false, SSRC);
        let want = vec![
            0x0002_FFFE,
            0x0002_FFFF,
            0x0003_0000,
            0x0003_0001,
            0x0003_0010,
        ];
        let fbs = vec![Feedback::Nack {
            ssrc: SSRC,
            missing: want.clone(),
        }];
        let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: SSRC });
        let dg = enc.encode_feedback(lead, &fbs, false).unwrap();
        let out = match dec.decode(&dg, 0).expect("decode") {
            Decoded::Feedback(f) => f,
            other => panic!("decoded as {other:?}, want feedback"),
        };
        let mut got = Vec::new();
        for fb in &out {
            if let Feedback::Nack { missing, .. } = fb {
                got.extend_from_slice(missing);
            }
        }
        assert_eq!(got, want);
    }

    #[test]
    fn main_pt_demux() {
        const SSRC: u32 = 0x0001_0002;
        let (mut enc, mut dec) = codec_pair(None, false, SSRC);
        let media = enc
            .encode_media(&MediaPacket {
                seq: 7,
                source_time: src_ntp(0),
                ssrc: SSRC,
                payload: Bytes::from_static(&[9]),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            })
            .unwrap();
        assert!(matches!(dec.decode(&media, 0).unwrap(), Decoded::Media(_)));

        let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: SSRC });
        let fb = enc
            .encode_feedback(
                lead,
                &[Feedback::RttEchoRequest {
                    ssrc: 0,
                    timestamp: 1,
                }],
                false,
            )
            .unwrap();
        assert!(matches!(dec.decode(&fb, 0).unwrap(), Decoded::Feedback(_)));
    }

    #[test]
    fn main_encrypted_needs_decryptor() {
        const SSRC: u32 = 0x5;
        let sk = crypto::Key::new(b"k", AesKeyBits::Aes128, 0, false).unwrap();
        let mut enc = MainCodec::new(Some(sk), None, false, SP, DP, false, SSRC, "c".into());
        let mut plain_dec = MainCodec::new(None, None, false, SP, DP, false, SSRC, "c".into());
        let dg = enc
            .encode_media(&MediaPacket {
                seq: 1,
                source_time: src_ntp(0),
                ssrc: SSRC,
                payload: Bytes::from_static(&[1]),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            })
            .unwrap();
        assert!(
            plain_dec.decode(&dg, 0).is_err(),
            "encrypted without decryptor"
        );

        let mut plain_enc = MainCodec::new(None, None, false, SP, DP, false, SSRC, "c".into());
        let rd = crypto::Decryptor::new(b"k", AesKeyBits::Aes128).unwrap();
        let mut cipher_dec = MainCodec::new(None, Some(rd), false, SP, DP, false, SSRC, "c".into());
        let dg2 = plain_enc
            .encode_media(&MediaPacket {
                seq: 1,
                source_time: src_ntp(0),
                ssrc: SSRC,
                payload: Bytes::from_static(&[1]),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            })
            .unwrap();
        assert!(
            cipher_dec.decode(&dg2, 0).is_err(),
            "cleartext with decryptor"
        );
    }

    #[test]
    fn main_gre_seq_increments() {
        let mut c = MainCodec::new(None, None, false, SP, DP, false, 1, "c".into());
        let seq_of = |b: &[u8]| gre::Header::parse(b).unwrap().0.seq;
        let m0 = c
            .encode_media(&MediaPacket {
                seq: 1,
                source_time: src_ntp(0),
                ssrc: 1,
                payload: Bytes::from_static(&[1]),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            })
            .unwrap();
        let lead = RtcpPacket::EmptyReceiverReport(EmptyReceiverReport { ssrc: 1 });
        let f1 = c.encode_feedback(lead, &[], false).unwrap();
        let m2 = c
            .encode_media(&MediaPacket {
                seq: 2,
                source_time: src_ntp(0),
                ssrc: 1,
                payload: Bytes::from_static(&[2]),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            })
            .unwrap();
        assert_eq!((seq_of(&m0), seq_of(&f1), seq_of(&m2)), (0, 1, 2));
    }

    #[test]
    fn main_npd_fallback() {
        const SSRC: u32 = 0x9;
        let (mut enc, mut dec) = codec_pair(None, true, SSRC);
        // Not a multiple of 188/204: NPD does not apply.
        let odd = vec![0x55u8; 100];
        let dg = enc
            .encode_media(&MediaPacket {
                seq: 1,
                source_time: src_ntp(0),
                ssrc: SSRC,
                payload: Bytes::from(odd.clone()),
                retransmit: false,
                path_id: 0,
                frag: rist_core::wire::FragRole::Standalone,
            })
            .unwrap();
        let got = must_media(&mut dec, &dg);
        assert_eq!(got.payload.as_ref(), odd.as_slice());
    }

    #[test]
    fn main_decode_short_inputs() {
        let mut c = MainCodec::new(None, None, false, SP, DP, false, 1, "c".into());
        let cases: &[&[u8]] = &[
            &[],
            &[0x10],
            &[0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00],
            &[0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00],
            &[0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00, 0x07, 0xB3],
            &[
                0x10, 0x08, 0x88, 0xB6, 0x00, 0x00, 0x00, 0x00, 0x07, 0xB3, 0x07, 0xB0,
            ],
            &[
                0x10, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0xB3, 0x07, 0xB0, 0x80, 0x21,
            ],
        ];
        for (i, b) in cases.iter().enumerate() {
            assert!(c.decode(b, 0).is_err(), "case {i} must error");
        }
    }

    #[test]
    fn decode_main_vsf_wrapper() {
        const SSRC: u32 = 0x0BAD_F00E;
        let (mut enc, mut dec) = codec_pair(None, false, SSRC);
        // Encode a v1 reduced media datagram, then rewrap as v2 VSF REDUCED.
        let pkt = MediaPacket {
            seq: 0x2345,
            source_time: src_ntp(1_000_000),
            ssrc: SSRC,
            payload: Bytes::from(ts_packet(188, 0x100, 0xAA)),
            retransmit: false,
            path_id: 0,
            frag: rist_core::wire::FragRole::Standalone,
        };
        let dg = enc.encode_media(&pkt).unwrap();
        let (mut hdr, off) = gre::Header::parse(&dg).unwrap();
        hdr.prot_type = gre::PROTO_VSF;
        hdr.version = 2;
        let mut wrapped = Vec::new();
        hdr.append_to(&mut wrapped).unwrap();
        gre::VsfProto {
            ty: gre::VSF_TYPE_RIST,
            subtype: gre::VSF_SUBTYPE_REDUCED,
        }
        .append_to(&mut wrapped);
        wrapped.extend_from_slice(&dg[off..]);
        let got = must_media(&mut dec, &wrapped);
        assert_eq!(got.seq, pkt.seq, "VSF-reduced media seq");

        // A keepalive VSF subtype must be accepted (Ignored), not an error.
        let mut ka = Vec::new();
        gre::Header {
            version: 2,
            has_seq: true,
            prot_type: gre::PROTO_VSF,
            ..gre::Header::default()
        }
        .append_to(&mut ka)
        .unwrap();
        gre::VsfProto {
            ty: gre::VSF_TYPE_RIST,
            subtype: gre::VSF_SUBTYPE_KEEPALIVE,
        }
        .append_to(&mut ka);
        ka.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        assert!(matches!(dec.decode(&ka, 0).unwrap(), Decoded::Ignored));
    }

    #[test]
    fn gre_keepalive_round_trip() {
        for bits in [None, Some(AesKeyBits::Aes128)] {
            let (mut enc, mut dec) = codec_pair(bits, false, 0x0BAD_F00E);
            let ka = gre::Keepalive {
                mac: [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02],
                caps: gre::Capabilities::standard(),
                ..gre::Keepalive::default()
            };
            let dg = enc.encode_keepalive(&ka, gre::VERSION_MIN).unwrap();
            let (kind, got, ver) = dec.peek_control(&dg);
            assert_eq!(kind, ControlKind::Keepalive, "{bits:?} v1 kind");
            assert_eq!(ver, gre::VERSION_MIN, "{bits:?} v1 version");
            let got = got.expect("keepalive body");
            assert_eq!(got.mac, ka.mac);
            assert_eq!(got.caps, ka.caps);

            // A v2 keepalive reports version 2 (its VSF body is decoded by decode()).
            let dg2 = enc.encode_keepalive(&ka, gre::VERSION_CUR).unwrap();
            let (_, _, ver2) = dec.peek_control(&dg2);
            assert_eq!(ver2, gre::VERSION_CUR, "{bits:?} v2 version");

            // Media must not be misdetected as a keepalive.
            let md = enc
                .encode_media(&MediaPacket {
                    seq: 1,
                    source_time: src_ntp(0),
                    ssrc: 0x0BAD_F00E,
                    payload: Bytes::from(ts_packet(188, 0x100, 0xAA)),
                    retransmit: false,
                    path_id: 0,
                    frag: rist_core::wire::FragRole::Standalone,
                })
                .unwrap();
            let (kind, _, _) = dec.peek_control(&md);
            assert_eq!(kind, ControlKind::None, "{bits:?} media not keepalive");
        }
    }

    #[test]
    fn buffer_neg_round_trip() {
        // Cleartext and PSK: a buffer-negotiation message frames as a GRE-v2 VSF
        // control datagram and decodes back to its advertised sender max.
        for bits in [None, Some(AesKeyBits::Aes128)] {
            let (mut enc, mut dec) = codec_pair(bits, false, 0x0BAD_F010);
            let bn = gre::BufferNegotiation {
                sender_max_ms: 1050,
                receiver_cur_ms: 0,
                proto_type: 0,
            };
            let dg = enc.encode_buffer_neg(bn).unwrap();
            let Decoded::BufferNeg(got) = dec.decode(&dg, 0).unwrap() else {
                panic!("{bits:?}: expected a BufferNeg decode");
            };
            assert_eq!(got, bn, "{bits:?} buffer-negotiation round-trip");
        }
    }
}
