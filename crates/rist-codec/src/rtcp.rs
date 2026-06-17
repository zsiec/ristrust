//! The RIST compound RTCP codec: the minimal RTCP subset of VSF TR-06-1 §5.2
//! (Sender Report, Receiver Report, empty RR, SDES/CNAME, RTT Echo), the two NACK
//! retransmission-request encodings of §5.3.2 (RFC 4585 Generic NACK bitmask and
//! the RIST APP range NACK), and the EXTSEQ APP packet of TR-06-2 §8.4 that
//! widens NACK sequence numbers to 32 bits.
//!
//! libRIST is the interop ground truth; where the spec is ambiguous the byte
//! layout here matches libRIST's behavior.
//!
//! # Decoding policy
//!
//! [`parse`] / [`parse_compound`] never panic on arbitrary input. Framing
//! violations (truncation, an RTCP version other than 2, a length field that
//! overruns the datagram) are hard errors. A packet that frames correctly but is
//! not a RIST shape (unknown payload type, foreign APP name, an SR with reception
//! blocks, …) is returned as [`Packet::Raw`] rather than an error, mirroring
//! RFC 3550's "ignore what you do not understand" rule so one foreign packet
//! cannot poison a whole compound. Decoded packets do not alias the input.
//!
//! # Encoding policy
//!
//! Encoders are canonical: they always produce the exact byte layout RIST
//! mandates. `decode(encode(x)) == x` for every value an encoder can produce, and
//! re-encoding a decoded packet is byte-stable.
//!
//! Portions of the bitmask-NACK FCI packing are adapted from
//! [pion/rtcp](https://github.com/pion/rtcp) (MIT; see `NOTICE.md`).

// Justification: the codec reads/writes fixed-width big-endian fields; the casts
// between byte slices, the 5-bit count subfield, and word counts are deliberate
// and bounded by the field widths.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    // The per-type `append_to(&self, …)` encoders keep a uniform `&self`
    // signature across every packet type for readability; a couple of the
    // Copy variants (EmptyReceiverReport, ExtSeq) would technically be cheaper
    // by value, but the uniformity is worth more than the register.
    clippy::trivially_copy_pass_by_ref
)]

use bytes::Bytes;

/// Errors returned by the RTCP codec. `Display` strings are prefixed `"rist: "`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RtcpError {
    /// A buffer is too short for the RTCP header or the size its length field
    /// declares.
    #[error("rist: rtcp packet truncated: {got} bytes, need {need}")]
    ShortPacket {
        /// Bytes available.
        got: usize,
        /// Bytes required.
        need: usize,
    },
    /// A packet's version field is not 2.
    #[error("rist: rtcp version is not 2: got {0}")]
    BadVersion(u8),
    /// [`parse_compound`] was handed an empty datagram.
    #[error("rist: empty rtcp compound")]
    EmptyCompound,
    /// [`build_compound`] was handed packets that violate the RIST ordering
    /// rules (TR-06-1 §5.2.1, TR-06-2 §8.4).
    #[error("rist: rtcp compound order violation: {0}")]
    CompoundOrder(&'static str),
}

/// RTCP Sender Report (PTYPE_SR = 200).
pub const PT_SENDER_REPORT: u8 = 200;
/// RTCP Receiver Report (PTYPE_RR = 201).
pub const PT_RECEIVER_REPORT: u8 = 201;
/// RTCP Source Description (PTYPE_SDES = 202).
pub const PT_SDES: u8 = 202;
/// RTCP Application-Defined, carrying the RIST range NACK, RTT echo, and EXTSEQ
/// packets (PTYPE_NACK_CUSTOM = 204).
pub const PT_APP: u8 = 204;
/// RTCP Transport-Layer Feedback, carrying the RFC 4585 Generic NACK bitmask
/// (PTYPE_NACK_BITMASK = 205).
pub const PT_TRANSPORT_FEEDBACK: u8 = 205;

/// APP "RIST" subtype: range-based retransmission request (NACK_FMT_RANGE = 0).
pub const APP_SUBTYPE_RANGE_NACK: u8 = 0;
/// APP "RIST" subtype: EXTSEQ sequence-number extension (TR-06-2 §8.4).
pub const APP_SUBTYPE_EXT_SEQ: u8 = 1;
/// APP "RIST" subtype: RTT Echo Request (ECHO_REQUEST = 2).
pub const APP_SUBTYPE_ECHO_REQUEST: u8 = 2;
/// APP "RIST" subtype: RTT Echo Response (ECHO_RESPONSE = 3).
pub const APP_SUBTYPE_ECHO_RESPONSE: u8 = 3;

/// RFC 4585 feedback message type for the Generic NACK (NACK_FMT_BITMASK = 1).
pub const FMT_GENERIC_NACK: u8 = 1;

/// The 32-bit ASCII name "RIST" carried by every RIST APP packet.
pub const NAME_RIST: u32 = 0x5249_5354;

/// The record budget a single seam-encoded NACK packet applies (TR-06-1
/// §5.3.2.2 mandates at most 16 range requests per packet; the bitmask path
/// follows the same bound). Decoders accept arbitrarily long packets.
pub const MAX_NACK_RECORDS_PER_PACKET: usize = 16;

/// The number of sequence numbers a single decoded NACK may expand to. The wire
/// sequence is 16-bit, so there are only 2^16 distinct values; this caps an
/// amplification DoS where a crafted range NACK would otherwise materialize ~24M
/// entries per datagram. It never truncates a conforming request.
const MAX_NACK_EXPAND: usize = 1 << 16;

const HEADER_SIZE: usize = 4;
/// The fixed prefix of every RIST APP packet: header, media SSRC, "RIST" name.
const APP_FIXED_SIZE: usize = 12;
const VERSION_FLAG: u8 = 0x80;

const SENDER_REPORT_SIZE: usize = 28;
const EMPTY_RR_SIZE: usize = 8;
const RECEIVER_REPORT_SIZE: usize = 32;
const ECHO_FIXED_SIZE: usize = 24;
const EXT_SEQ_SIZE: usize = 16;
const SDES_FIXED_SIZE: usize = 10;
const SDES_ITEM_CNAME: u8 = 1;
const MAX_CNAME_LEN: usize = 255;

/// The byte size of the Link Quality Message that rides on an RR as a
/// profile-specific extension (TR-06-4 Part 1 Figure 2).
pub const LQM_EXTENSION_SIZE: usize = 44;
const LQM_REPORT_SIZE: usize = EMPTY_RR_SIZE + LQM_EXTENSION_SIZE;

/// The RIST RTCP Sender Report (TR-06-1 §5.2.2): PT=200, RC=0, no reception
/// blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderReport {
    /// The originator of the report (libRIST sends the flow ID).
    pub ssrc: u32,
    /// The sender wallclock at report time, NTP-64.
    pub ntp: u64,
    /// The RTP timestamp corresponding to the same instant as `ntp`.
    pub rtp_time: u32,
    /// Total RTP data packets sent since transmission started.
    pub packet_count: u32,
    /// Total RTP payload octets sent since transmission started.
    pub octet_count: u32,
}

/// The empty RR of TR-06-1 §5.2.3: PT=201, RC=0 — just header and SSRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmptyReceiverReport {
    /// The originator of the report.
    pub ssrc: u32,
}

/// The full RR of TR-06-1 §5.2.4: PT=201, RC=1, one reception report block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceiverReport {
    /// The originator of this report (the RIST receiver).
    pub sender_ssrc: u32,
    /// The SSRC of the received stream the block describes.
    pub media_ssrc: u32,
    /// The 8-bit fixed-point fraction lost since the previous report.
    pub fraction_lost: u8,
    /// The 24-bit cumulative packets lost (only the low 24 bits are used).
    pub cumulative_lost: u32,
    /// The extended highest sequence number received.
    pub highest_seq: u32,
    /// The interarrival jitter estimate, in RTP timestamp units.
    pub jitter: u32,
    /// The middle 32 bits of the NTP timestamp of the last SR received.
    pub lsr: u32,
    /// The delay since that SR was received, in 1/65536-second units.
    pub dlsr: u32,
}

/// An empty RR carrying a 44-byte Link Quality Message as a profile-specific
/// extension (TR-06-4 Part 1 §5.2). The LQM bytes are opaque here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkQualityReport {
    /// The originator (the RIST receiver).
    pub ssrc: u32,
    /// The 44-byte Link Quality Message (`adapt` encodes/decodes it).
    pub lqm: [u8; LQM_EXTENSION_SIZE],
}

impl Default for LinkQualityReport {
    fn default() -> Self {
        LinkQualityReport {
            ssrc: 0,
            lqm: [0; LQM_EXTENSION_SIZE],
        }
    }
}

/// The RIST SDES packet of TR-06-1 §5.2.5: PT=202, SC=1, one CNAME item.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sdes {
    /// The originator (the RIST sender or receiver).
    pub ssrc: u32,
    /// The canonical name (truncated to 255 bytes on encode). Held as raw bytes, not a
    /// `String`, so an arbitrary (non-UTF-8) peer CNAME round-trips byte-stably and the
    /// NAT-rebind identity comparison is byte-exact rather than lossy.
    pub cname: Bytes,
}

/// One Packet Range Request of TR-06-1 §5.3.2.2: packets `start` through
/// `start + extra` inclusive (mod 2^16) are requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NackRange {
    /// The first missing sequence number.
    pub start: u16,
    /// Additional contiguous missing packets after `start` (0 = only `start`).
    pub extra: u16,
}

/// The RIST range-based retransmission request (APP PT=204, subtype 0, "RIST").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RangeNack {
    /// The SSRC of the media stream the request relates to (either LSB variant).
    pub media_ssrc: u32,
    /// The range records.
    pub ranges: Vec<NackRange>,
}

/// One Generic NACK FCI of RFC 4585 §6.2.1: a packet ID plus a 16-bit bitmask
/// covering the 16 packets after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NackPair {
    /// The sequence number of a lost packet.
    pub pid: u16,
    /// The bitmask of following lost packets: bit `i` set means `pid + i + 1`
    /// (mod 2^16) is also lost.
    pub blp: u16,
}

/// The bitmask-based retransmission request of TR-06-1 §5.3.2.1: the RFC 4585
/// Generic NACK, PT=205, FMT=1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitmaskNack {
    /// The originator of this packet (libRIST transmits 0).
    pub sender_ssrc: u32,
    /// The SSRC of the media stream the request relates to.
    pub media_ssrc: u32,
    /// The Generic NACK FCIs.
    pub fcis: Vec<NackPair>,
}

/// The RIST RTT Echo Request of TR-06-1 §5.2.6 (APP PT=204, subtype 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EchoRequest {
    /// The SSRC the measurement relates to.
    pub ssrc: u32,
    /// An arbitrary 64-bit value echoed back verbatim (NTP-64 suggested).
    pub timestamp: u64,
    /// Optional padding so RTT can be measured with media-sized packets;
    /// zero-filled to a multiple of 4 on encode.
    pub padding: Bytes,
}

/// The RIST RTT Echo Response of TR-06-1 §5.2.6 (APP PT=204, subtype 3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EchoResponse {
    /// The SSRC the measurement relates to.
    pub ssrc: u32,
    /// The requester's timestamp, copied verbatim.
    pub timestamp: u64,
    /// Microseconds between receiving the request and sending this response.
    pub processing_delay: u32,
    /// Echoes the request's padding (zero-filled to a multiple of 4 on encode).
    pub padding: Bytes,
}

/// The RIST EXTSEQ packet of TR-06-2 §8.4 (APP PT=204, subtype 1): the upper 16
/// bits of the 32-bit extended sequence for the NACK packet(s) that follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtSeq {
    /// The SSRC the following request relates to.
    pub ssrc: u32,
    /// The most significant 16 bits prepended to the following NACK starts.
    pub seq_high: u16,
}

/// One RTCP packet of a RIST compound datagram. A real sum type (vs ristgo's
/// sealed interface): adding a variant is a compile error at every `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Packet {
    /// A Sender Report.
    SenderReport(SenderReport),
    /// A full Receiver Report.
    ReceiverReport(ReceiverReport),
    /// An empty Receiver Report.
    EmptyReceiverReport(EmptyReceiverReport),
    /// An empty RR carrying a Link Quality Message extension.
    LinkQualityReport(LinkQualityReport),
    /// A Source Description (CNAME).
    Sdes(Sdes),
    /// A range-based NACK.
    RangeNack(RangeNack),
    /// A bitmask (Generic) NACK.
    BitmaskNack(BitmaskNack),
    /// An RTT echo request.
    EchoRequest(EchoRequest),
    /// An RTT echo response.
    EchoResponse(EchoResponse),
    /// An EXTSEQ sequence-extension packet.
    ExtSeq(ExtSeq),
    /// A well-framed packet that is not a RIST shape: preserved verbatim (header
    /// included) so a compound parses losslessly and foreign packets are skipped
    /// per RFC 3550.
    Raw(Bytes),
}

/// Rounds `n` up to the next multiple of 4.
fn pad_to_4(n: usize) -> usize {
    (n + 3) & !3
}

/// The canonical SDES whole-packet size for an `n`-byte CNAME: 10 fixed bytes +
/// name + 1–4 zero terminator bytes, rounded to a multiple of 4.
fn sdes_size(n: usize) -> usize {
    (SDES_FIXED_SIZE + n + 1 + 3) & !3
}

impl Packet {
    /// The encoded size in bytes (always a multiple of 4).
    #[must_use]
    pub fn marshal_size(&self) -> usize {
        match self {
            Packet::SenderReport(_) => SENDER_REPORT_SIZE,
            Packet::ReceiverReport(_) => RECEIVER_REPORT_SIZE,
            Packet::EmptyReceiverReport(_) => EMPTY_RR_SIZE,
            Packet::LinkQualityReport(_) => LQM_REPORT_SIZE,
            Packet::Sdes(p) => sdes_size(p.cname.len().min(MAX_CNAME_LEN)),
            Packet::RangeNack(p) => APP_FIXED_SIZE + 4 * p.ranges.len(),
            Packet::BitmaskNack(p) => APP_FIXED_SIZE + 4 * p.fcis.len(),
            Packet::EchoRequest(p) => ECHO_FIXED_SIZE + pad_to_4(p.padding.len()),
            Packet::EchoResponse(p) => ECHO_FIXED_SIZE + pad_to_4(p.padding.len()),
            Packet::ExtSeq(_) => EXT_SEQ_SIZE,
            Packet::Raw(b) => b.len(),
        }
    }

    /// Appends the canonical encoding to `dst`.
    pub fn append_to(&self, dst: &mut Vec<u8>) {
        match self {
            Packet::SenderReport(p) => p.append_to(dst),
            Packet::ReceiverReport(p) => p.append_to(dst),
            Packet::EmptyReceiverReport(p) => p.append_to(dst),
            Packet::LinkQualityReport(p) => p.append_to(dst),
            Packet::Sdes(p) => p.append_to(dst),
            Packet::RangeNack(p) => p.append_to(dst),
            Packet::BitmaskNack(p) => p.append_to(dst),
            Packet::EchoRequest(p) => p.append_to(dst),
            Packet::EchoResponse(p) => p.append_to(dst),
            Packet::ExtSeq(p) => p.append_to(dst),
            Packet::Raw(b) => dst.extend_from_slice(b),
        }
    }

    /// Encodes the packet into a freshly allocated buffer.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut dst = Vec::with_capacity(self.marshal_size());
        self.append_to(&mut dst);
        dst
    }
}

/// Appends the 4-byte fixed header. `count` is the 5-bit RC/SC/FMT/subtype
/// field; `words` is the length field (`size/4 - 1`).
fn append_header(dst: &mut Vec<u8>, count: u8, pt: u8, words: u16) {
    dst.push(VERSION_FLAG | count);
    dst.push(pt);
    dst.extend_from_slice(&words.to_be_bytes());
}

impl SenderReport {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(dst, 0, PT_SENDER_REPORT, 6);
        dst.extend_from_slice(&self.ssrc.to_be_bytes());
        dst.extend_from_slice(&self.ntp.to_be_bytes());
        dst.extend_from_slice(&self.rtp_time.to_be_bytes());
        dst.extend_from_slice(&self.packet_count.to_be_bytes());
        dst.extend_from_slice(&self.octet_count.to_be_bytes());
    }
}

impl EmptyReceiverReport {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(dst, 0, PT_RECEIVER_REPORT, 1);
        dst.extend_from_slice(&self.ssrc.to_be_bytes());
    }
}

impl ReceiverReport {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(dst, 1, PT_RECEIVER_REPORT, 7);
        dst.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        dst.extend_from_slice(&self.media_ssrc.to_be_bytes());
        let fl_cl = (u32::from(self.fraction_lost) << 24) | (self.cumulative_lost & 0x00FF_FFFF);
        dst.extend_from_slice(&fl_cl.to_be_bytes());
        dst.extend_from_slice(&self.highest_seq.to_be_bytes());
        dst.extend_from_slice(&self.jitter.to_be_bytes());
        dst.extend_from_slice(&self.lsr.to_be_bytes());
        dst.extend_from_slice(&self.dlsr.to_be_bytes());
    }
}

impl LinkQualityReport {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(dst, 0, PT_RECEIVER_REPORT, (LQM_REPORT_SIZE / 4 - 1) as u16);
        dst.extend_from_slice(&self.ssrc.to_be_bytes());
        dst.extend_from_slice(&self.lqm);
    }
}

impl Sdes {
    fn append_to(&self, dst: &mut Vec<u8>) {
        let name = &self.cname[..self.cname.len().min(MAX_CNAME_LEN)];
        let size = sdes_size(name.len());
        append_header(dst, 1, PT_SDES, (size / 4 - 1) as u16);
        dst.extend_from_slice(&self.ssrc.to_be_bytes());
        dst.push(SDES_ITEM_CNAME);
        dst.push(name.len() as u8);
        dst.extend_from_slice(name);
        // Zero terminator + padding to the canonical size.
        dst.resize(dst.len() + (size - SDES_FIXED_SIZE - name.len()), 0);
    }
}

impl RangeNack {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(
            dst,
            APP_SUBTYPE_RANGE_NACK,
            PT_APP,
            (2 + self.ranges.len()) as u16,
        );
        dst.extend_from_slice(&self.media_ssrc.to_be_bytes());
        dst.extend_from_slice(&NAME_RIST.to_be_bytes());
        for r in &self.ranges {
            dst.extend_from_slice(&r.start.to_be_bytes());
            dst.extend_from_slice(&r.extra.to_be_bytes());
        }
    }

    /// Expands the range records into the full requested sequence list, in
    /// record order, wrapping at the 16-bit boundary. Values are 16-bit numbers
    /// in `u32` slots, widened to 32 bits by the session.
    #[must_use]
    pub fn missing_seqs(&self) -> Vec<u32> {
        let mut dst = Vec::new();
        for r in &self.ranges {
            let mut s = r.start;
            for _ in 0..=u32::from(r.extra) {
                if dst.len() >= MAX_NACK_EXPAND {
                    return dst;
                }
                dst.push(u32::from(s));
                s = s.wrapping_add(1);
            }
        }
        dst
    }
}

impl NackPair {
    /// Appends the up-to-17 sequence numbers this pair requests (PID first, then
    /// each set BLP bit) to `dst`.
    fn append_seqs(self, dst: &mut Vec<u32>, cap: usize) {
        if dst.len() >= cap {
            return;
        }
        dst.push(u32::from(self.pid));
        for i in 0..16u16 {
            if dst.len() >= cap {
                return; // cap reached mid-FCI: never overshoot the expansion bound
            }
            if self.blp & (1 << i) != 0 {
                dst.push(u32::from(self.pid.wrapping_add(i + 1)));
            }
        }
    }
}

impl BitmaskNack {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(
            dst,
            FMT_GENERIC_NACK,
            PT_TRANSPORT_FEEDBACK,
            (2 + self.fcis.len()) as u16,
        );
        dst.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        dst.extend_from_slice(&self.media_ssrc.to_be_bytes());
        for f in &self.fcis {
            dst.extend_from_slice(&f.pid.to_be_bytes());
            dst.extend_from_slice(&f.blp.to_be_bytes());
        }
    }

    /// Expands the FCIs into the full requested sequence list, in FCI order.
    #[must_use]
    pub fn missing_seqs(&self) -> Vec<u32> {
        let mut dst = Vec::new();
        for f in &self.fcis {
            if dst.len() >= MAX_NACK_EXPAND {
                break;
            }
            f.append_seqs(&mut dst, MAX_NACK_EXPAND);
        }
        dst
    }
}

fn append_echo(dst: &mut Vec<u8>, subtype: u8, ssrc: u32, ts: u64, delay: u32, padding: &[u8]) {
    let pad = pad_to_4(padding.len());
    append_header(dst, subtype, PT_APP, (5 + pad / 4) as u16);
    dst.extend_from_slice(&ssrc.to_be_bytes());
    dst.extend_from_slice(&NAME_RIST.to_be_bytes());
    dst.extend_from_slice(&ts.to_be_bytes());
    dst.extend_from_slice(&delay.to_be_bytes());
    dst.extend_from_slice(padding);
    dst.resize(dst.len() + (pad - padding.len()), 0);
}

impl EchoRequest {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_echo(
            dst,
            APP_SUBTYPE_ECHO_REQUEST,
            self.ssrc,
            self.timestamp,
            0,
            &self.padding,
        );
    }
}

impl EchoResponse {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_echo(
            dst,
            APP_SUBTYPE_ECHO_RESPONSE,
            self.ssrc,
            self.timestamp,
            self.processing_delay,
            &self.padding,
        );
    }
}

impl ExtSeq {
    fn append_to(&self, dst: &mut Vec<u8>) {
        append_header(dst, APP_SUBTYPE_EXT_SEQ, PT_APP, 3);
        dst.extend_from_slice(&self.ssrc.to_be_bytes());
        dst.extend_from_slice(&NAME_RIST.to_be_bytes());
        dst.extend_from_slice(&self.seq_high.to_be_bytes());
        dst.extend_from_slice(&[0u8, 0]); // reserved
    }
}

/// The decoded fixed RTCP header.
struct RtcpHeader {
    count: u8,
    pt: u8,
    size: usize,
}

fn parse_header(b: &[u8]) -> Result<RtcpHeader, RtcpError> {
    if b.len() < HEADER_SIZE {
        return Err(RtcpError::ShortPacket {
            got: b.len(),
            need: HEADER_SIZE,
        });
    }
    if b[0] >> 6 != 2 {
        return Err(RtcpError::BadVersion(b[0] >> 6));
    }
    let size = (usize::from(u16::from_be_bytes([b[2], b[3]])) + 1) * 4;
    if size > b.len() {
        return Err(RtcpError::ShortPacket {
            got: b.len(),
            need: size,
        });
    }
    Ok(RtcpHeader {
        count: b[0] & 0x1F,
        pt: b[1],
        size,
    })
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

/// Decodes the first RTCP packet in `b`, returning the packet and the number of
/// bytes it consumed. Framing violations are errors; well-framed non-RIST shapes
/// come back as [`Packet::Raw`]. The returned packet does not alias `b`.
pub fn parse(b: &[u8]) -> Result<(Packet, usize), RtcpError> {
    let h = parse_header(b)?;
    let body = &b[..h.size];
    // P bit (0x20) must be clear for a typed RIST shape (TR-06-1 §5.2: P=0).
    if b[0] & 0x20 == 0
        && let Some(pkt) = decode_typed(&h, body)
    {
        return Ok((pkt, h.size));
    }
    Ok((Packet::Raw(Bytes::copy_from_slice(body)), h.size))
}

fn decode_typed(h: &RtcpHeader, body: &[u8]) -> Option<Packet> {
    match h.pt {
        PT_SENDER_REPORT => decode_sender_report(h, body),
        PT_RECEIVER_REPORT => decode_receiver_report(h, body),
        PT_SDES => decode_sdes(h, body),
        PT_APP => decode_app(h, body),
        PT_TRANSPORT_FEEDBACK => decode_bitmask_nack(h, body),
        _ => None,
    }
}

fn decode_app(h: &RtcpHeader, body: &[u8]) -> Option<Packet> {
    if body.len() < APP_FIXED_SIZE || be32(body, 8) != NAME_RIST {
        return None;
    }
    match h.count {
        APP_SUBTYPE_RANGE_NACK => Some(decode_range_nack(body)),
        APP_SUBTYPE_EXT_SEQ => decode_ext_seq(body),
        APP_SUBTYPE_ECHO_REQUEST | APP_SUBTYPE_ECHO_RESPONSE => decode_echo(h.count, body),
        _ => None,
    }
}

fn decode_sender_report(h: &RtcpHeader, body: &[u8]) -> Option<Packet> {
    if h.count != 0 || h.size != SENDER_REPORT_SIZE {
        return None;
    }
    Some(Packet::SenderReport(SenderReport {
        ssrc: be32(body, 4),
        ntp: be64(body, 8),
        rtp_time: be32(body, 16),
        packet_count: be32(body, 20),
        octet_count: be32(body, 24),
    }))
}

fn decode_receiver_report(h: &RtcpHeader, body: &[u8]) -> Option<Packet> {
    match (h.count, h.size) {
        (0, EMPTY_RR_SIZE) => Some(Packet::EmptyReceiverReport(EmptyReceiverReport {
            ssrc: be32(body, 4),
        })),
        (1, RECEIVER_REPORT_SIZE) => Some(Packet::ReceiverReport(ReceiverReport {
            sender_ssrc: be32(body, 4),
            media_ssrc: be32(body, 8),
            fraction_lost: body[12],
            cumulative_lost: be32(body, 12) & 0x00FF_FFFF,
            highest_seq: be32(body, 16),
            jitter: be32(body, 20),
            lsr: be32(body, 24),
            dlsr: be32(body, 28),
        })),
        (0, LQM_REPORT_SIZE) => {
            let mut lqm = [0u8; LQM_EXTENSION_SIZE];
            lqm.copy_from_slice(&body[8..LQM_REPORT_SIZE]);
            Some(Packet::LinkQualityReport(LinkQualityReport {
                ssrc: be32(body, 4),
                lqm,
            }))
        }
        _ => None,
    }
}

fn decode_sdes(h: &RtcpHeader, body: &[u8]) -> Option<Packet> {
    if h.count != 1 || h.size < SDES_FIXED_SIZE + 1 || body[8] != SDES_ITEM_CNAME {
        return None;
    }
    let n = usize::from(body[9]);
    if SDES_FIXED_SIZE + n + 1 > h.size {
        return None;
    }
    if body[SDES_FIXED_SIZE + n..].iter().any(|&x| x != 0) {
        return None;
    }
    let cname = Bytes::copy_from_slice(&body[SDES_FIXED_SIZE..SDES_FIXED_SIZE + n]);
    Some(Packet::Sdes(Sdes {
        ssrc: be32(body, 4),
        cname,
    }))
}

fn decode_range_nack(body: &[u8]) -> Packet {
    let n = (body.len() - APP_FIXED_SIZE) / 4;
    let ranges = (0..n)
        .map(|i| NackRange {
            start: be16(body, APP_FIXED_SIZE + 4 * i),
            extra: be16(body, APP_FIXED_SIZE + 4 * i + 2),
        })
        .collect();
    Packet::RangeNack(RangeNack {
        media_ssrc: be32(body, 4),
        ranges,
    })
}

fn decode_bitmask_nack(h: &RtcpHeader, body: &[u8]) -> Option<Packet> {
    if h.count != FMT_GENERIC_NACK || h.size < APP_FIXED_SIZE {
        return None;
    }
    let n = (h.size - APP_FIXED_SIZE) / 4;
    let fcis = (0..n)
        .map(|i| NackPair {
            pid: be16(body, APP_FIXED_SIZE + 4 * i),
            blp: be16(body, APP_FIXED_SIZE + 4 * i + 2),
        })
        .collect();
    Some(Packet::BitmaskNack(BitmaskNack {
        sender_ssrc: be32(body, 4),
        media_ssrc: be32(body, 8),
        fcis,
    }))
}

fn decode_echo(subtype: u8, body: &[u8]) -> Option<Packet> {
    if body.len() < ECHO_FIXED_SIZE {
        return None;
    }
    let ssrc = be32(body, 4);
    let timestamp = be64(body, 12);
    let padding = Bytes::copy_from_slice(&body[ECHO_FIXED_SIZE..]);
    if subtype == APP_SUBTYPE_ECHO_REQUEST {
        Some(Packet::EchoRequest(EchoRequest {
            ssrc,
            timestamp,
            padding,
        }))
    } else {
        Some(Packet::EchoResponse(EchoResponse {
            ssrc,
            timestamp,
            processing_delay: be32(body, 20),
            padding,
        }))
    }
}

fn decode_ext_seq(body: &[u8]) -> Option<Packet> {
    if body.len() != EXT_SEQ_SIZE {
        return None;
    }
    Some(Packet::ExtSeq(ExtSeq {
        ssrc: be32(body, 4),
        seq_high: be16(body, 12),
    }))
}

/// Decodes a UDP datagram holding one or more concatenated RTCP packets
/// (TR-06-1 §5.2.1) in wire order. Framing violations anywhere fail the whole
/// compound; non-RIST shapes come back as [`Packet::Raw`].
pub fn parse_compound(b: &[u8]) -> Result<Vec<Packet>, RtcpError> {
    if b.is_empty() {
        return Err(RtcpError::EmptyCompound);
    }
    let mut pkts = Vec::new();
    let mut off = 0;
    while off < b.len() {
        let (pkt, n) = parse(&b[off..])?;
        pkts.push(pkt);
        off += n;
    }
    Ok(pkts)
}

/// The total encoded size of `pkts` concatenated into one compound.
#[must_use]
pub fn compound_marshal_size(pkts: &[Packet]) -> usize {
    pkts.iter().map(Packet::marshal_size).sum()
}

/// Appends the RIST compound encoding of `pkts` to `dst`, enforcing the ordering
/// rules of TR-06-1 §5.2.1 and TR-06-2 §8.4: a report packet first, the SDES
/// second, then any EXTSEQ/NACK feedback (each EXTSEQ immediately followed by the
/// NACK it qualifies), and echo packets last. On a violation, `dst` is left
/// unchanged.
pub fn build_compound(dst: &mut Vec<u8>, pkts: &[Packet]) -> Result<(), RtcpError> {
    check_compound_order(pkts)?;
    for p in pkts {
        p.append_to(dst);
    }
    Ok(())
}

fn check_compound_order(pkts: &[Packet]) -> Result<(), RtcpError> {
    if pkts.len() < 2 {
        return Err(RtcpError::CompoundOrder(
            "a compound needs a report packet and an SDES packet",
        ));
    }
    match pkts[0] {
        Packet::SenderReport(_)
        | Packet::ReceiverReport(_)
        | Packet::EmptyReceiverReport(_)
        | Packet::LinkQualityReport(_) => {}
        _ => {
            return Err(RtcpError::CompoundOrder(
                "first packet must be an SR or (empty) RR",
            ));
        }
    }
    if !matches!(pkts[1], Packet::Sdes(_)) {
        return Err(RtcpError::CompoundOrder(
            "second packet must be the SDES/CNAME",
        ));
    }

    // After the report+SDES prefix: feedback (class 0) then echo (class 1).
    let mut class = 0u8;
    for i in 2..pkts.len() {
        let c = match pkts[i] {
            Packet::ExtSeq(_) => {
                let followed_by_nack = pkts
                    .get(i + 1)
                    .is_some_and(|p| matches!(p, Packet::RangeNack(_) | Packet::BitmaskNack(_)));
                if !followed_by_nack {
                    return Err(RtcpError::CompoundOrder(
                        "ExtSeq must be followed by a NACK packet",
                    ));
                }
                0
            }
            Packet::RangeNack(_) | Packet::BitmaskNack(_) | Packet::Raw(_) => 0,
            Packet::EchoRequest(_) | Packet::EchoResponse(_) => 1,
            _ => {
                return Err(RtcpError::CompoundOrder(
                    "only feedback and echo packets may follow the report and SDES",
                ));
            }
        };
        if c < class {
            return Err(RtcpError::CompoundOrder(
                "feedback packets must precede the echo packets",
            ));
        }
        class = c;
    }
    Ok(())
}

/// Packs `missing` — 16-bit sequence numbers in ascending circular order — into
/// the minimal list of range records, split into packets of at most
/// [`MAX_NACK_RECORDS_PER_PACKET`] records. A run of consecutive (mod 2^16)
/// numbers becomes a single `{start, extra}` record, across the 65535→0 wrap.
/// Only the low 16 bits of each value are used. `sender_ssrc` is accepted for
/// symmetry with [`encode_bitmask_nack`] but unused (the range wire carries only
/// the media SSRC).
#[must_use]
pub fn encode_range_nack(_sender_ssrc: u32, media_ssrc: u32, missing: &[u32]) -> Vec<RangeNack> {
    if missing.is_empty() {
        return Vec::new();
    }
    let mut pkts: Vec<RangeNack> = Vec::new();
    let mut ranges: Vec<NackRange> = Vec::new();
    let mut cur = NackRange {
        start: missing[0] as u16,
        extra: 0,
    };
    let mut last = missing[0] as u16;
    let flush = |ranges: &mut Vec<NackRange>, cur: NackRange, pkts: &mut Vec<RangeNack>| {
        ranges.push(cur);
        if ranges.len() == MAX_NACK_RECORDS_PER_PACKET {
            pkts.push(RangeNack {
                media_ssrc,
                ranges: std::mem::take(ranges),
            });
        }
    };
    for &m in &missing[1..] {
        let s = m as u16;
        if s == last.wrapping_add(1) && cur.extra < 0xFFFF {
            cur.extra += 1;
        } else {
            flush(&mut ranges, cur, &mut pkts);
            cur = NackRange { start: s, extra: 0 };
        }
        last = s;
    }
    flush(&mut ranges, cur, &mut pkts);
    if !ranges.is_empty() {
        pkts.push(RangeNack { media_ssrc, ranges });
    }
    pkts
}

/// Packs `missing` — 16-bit sequence numbers in ascending circular order — into
/// the minimal list of Generic NACK FCIs, split into packets of at most
/// [`MAX_NACK_RECORDS_PER_PACKET`] FCIs. Each FCI covers its PID plus the 16
/// following sequence numbers, wrapping at 65535→0. Only the low 16 bits of each
/// value are used.
#[must_use]
pub fn encode_bitmask_nack(sender_ssrc: u32, media_ssrc: u32, missing: &[u32]) -> Vec<BitmaskNack> {
    if missing.is_empty() {
        return Vec::new();
    }
    let mut pkts: Vec<BitmaskNack> = Vec::new();
    for pair in nack_pairs_from_seqs(missing) {
        if pkts
            .last()
            .is_none_or(|p| p.fcis.len() == MAX_NACK_RECORDS_PER_PACKET)
        {
            pkts.push(BitmaskNack {
                sender_ssrc,
                media_ssrc,
                fcis: Vec::new(),
            });
        }
        pkts.last_mut().unwrap().fcis.push(pair);
    }
    pkts
}

/// Packs sequence numbers in ascending circular order into minimal NackPairs.
/// Adapted from pion/rtcp (MIT): the `u16` subtraction makes the 17-packet
/// window test wrap-correct at the 65535→0 boundary.
fn nack_pairs_from_seqs(missing: &[u32]) -> Vec<NackPair> {
    let mut pairs = Vec::new();
    let mut cur = NackPair {
        pid: missing[0] as u16,
        blp: 0,
    };
    for &m in &missing[1..] {
        let s = m as u16;
        let d = s.wrapping_sub(cur.pid);
        if (1..=16).contains(&d) {
            cur.blp |= 1 << (d - 1);
        } else {
            pairs.push(cur);
            cur = NackPair { pid: s, blp: 0 };
        }
    }
    pairs.push(cur);
    pairs
}

/// Returns the full sequence list requested by a NACK packet of either encoding,
/// or `None` when `pkt` is not a NACK. Values are 16-bit numbers in `u32` slots.
#[must_use]
pub fn decode_nack(pkt: &Packet) -> Option<Vec<u32>> {
    match pkt {
        Packet::RangeNack(p) => Some(p.missing_seqs()),
        Packet::BitmaskNack(p) => Some(p.missing_seqs()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Golden {
        name: &'static str,
        pkt: Packet,
        want: &'static [u8],
    }

    #[allow(clippy::too_many_lines)] // a golden table: the vector literal is the bulk
    fn goldens() -> Vec<Golden> {
        vec![
            Golden {
                name: "SenderReport",
                pkt: Packet::SenderReport(SenderReport {
                    ssrc: 0x1234_5678,
                    ntp: 0x83AA_7E80_4000_0000,
                    rtp_time: 0x0001_5180,
                    packet_count: 256,
                    octet_count: 8192,
                }),
                want: &[
                    0x80, 0xC8, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78, 0x83, 0xAA, 0x7E, 0x80, 0x40,
                    0x00, 0x00, 0x00, 0x00, 0x01, 0x51, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x20, 0x00,
                ],
            },
            Golden {
                name: "EmptyReceiverReport",
                pkt: Packet::EmptyReceiverReport(EmptyReceiverReport { ssrc: 0xDEAD_BEEF }),
                want: &[0x80, 0xC9, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF],
            },
            Golden {
                name: "ReceiverReport",
                pkt: Packet::ReceiverReport(ReceiverReport {
                    sender_ssrc: 0x0000_0001,
                    media_ssrc: 0xCAFE_BABE,
                    fraction_lost: 0x10,
                    cumulative_lost: 0x00_01_02,
                    highest_seq: 0x0001_0003,
                    jitter: 32,
                    lsr: 0x7E80_4000,
                    dlsr: 0x0001_0000,
                }),
                want: &[
                    0x81, 0xC9, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0xCA, 0xFE, 0xBA, 0xBE, 0x10,
                    0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x7E, 0x80,
                    0x40, 0x00, 0x00, 0x01, 0x00, 0x00,
                ],
            },
            Golden {
                name: "SDES",
                pkt: Packet::Sdes(Sdes {
                    ssrc: 0x1122_3344,
                    cname: "ristgo".into(),
                }),
                want: &[
                    0x81, 0xCA, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44, 0x01, 0x06, b'r', b'i', b's',
                    b't', b'g', b'o', 0x00, 0x00, 0x00, 0x00,
                ],
            },
            Golden {
                name: "SDES one-byte terminator",
                pkt: Packet::Sdes(Sdes {
                    ssrc: 0x1122_3344,
                    cname: "abcde".into(),
                }),
                want: &[
                    0x81, 0xCA, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x01, 0x05, b'a', b'b', b'c',
                    b'd', b'e', 0x00,
                ],
            },
            Golden {
                name: "RangeNACK",
                pkt: Packet::RangeNack(RangeNack {
                    media_ssrc: 0x0000_CAFE,
                    ranges: vec![
                        NackRange {
                            start: 100,
                            extra: 0,
                        },
                        NackRange {
                            start: 200,
                            extra: 4,
                        },
                    ],
                }),
                want: &[
                    0x80, 0xCC, 0x00, 0x04, 0x00, 0x00, 0xCA, 0xFE, 0x52, 0x49, 0x53, 0x54, 0x00,
                    0x64, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x04,
                ],
            },
            Golden {
                name: "BitmaskNACK",
                pkt: Packet::BitmaskNack(BitmaskNack {
                    sender_ssrc: 0,
                    media_ssrc: 0x0000_CAFE,
                    fcis: vec![NackPair {
                        pid: 1000,
                        blp: 0x0005,
                    }],
                }),
                want: &[
                    0x81, 0xCD, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCA, 0xFE, 0x03,
                    0xE8, 0x00, 0x05,
                ],
            },
            Golden {
                name: "EchoRequest",
                pkt: Packet::EchoRequest(EchoRequest {
                    ssrc: 0x0000_BEEF,
                    timestamp: 0xE3D1_5C00_8000_0000,
                    padding: Bytes::new(),
                }),
                want: &[
                    0x82, 0xCC, 0x00, 0x05, 0x00, 0x00, 0xBE, 0xEF, 0x52, 0x49, 0x53, 0x54, 0xE3,
                    0xD1, 0x5C, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            },
            Golden {
                name: "EchoRequest with padding",
                pkt: Packet::EchoRequest(EchoRequest {
                    ssrc: 0x0000_BEEF,
                    timestamp: 0xE3D1_5C00_8000_0000,
                    padding: Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]),
                }),
                want: &[
                    0x82, 0xCC, 0x00, 0x06, 0x00, 0x00, 0xBE, 0xEF, 0x52, 0x49, 0x53, 0x54, 0xE3,
                    0xD1, 0x5C, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB,
                    0xCC, 0xDD,
                ],
            },
            Golden {
                name: "EchoResponse",
                pkt: Packet::EchoResponse(EchoResponse {
                    ssrc: 0x0000_BEEF,
                    timestamp: 0xE3D1_5C00_8000_0000,
                    processing_delay: 1500,
                    padding: Bytes::new(),
                }),
                want: &[
                    0x83, 0xCC, 0x00, 0x05, 0x00, 0x00, 0xBE, 0xEF, 0x52, 0x49, 0x53, 0x54, 0xE3,
                    0xD1, 0x5C, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC,
                ],
            },
            Golden {
                name: "ExtSeq",
                pkt: Packet::ExtSeq(ExtSeq {
                    ssrc: 0xCAFE_BABE,
                    seq_high: 0x0102,
                }),
                want: &[
                    0x81, 0xCC, 0x00, 0x03, 0xCA, 0xFE, 0xBA, 0xBE, 0x52, 0x49, 0x53, 0x54, 0x01,
                    0x02, 0x00, 0x00,
                ],
            },
        ]
    }

    #[test]
    fn golden_encode() {
        for g in goldens() {
            assert_eq!(g.pkt.encode(), g.want, "{} encode", g.name);
            assert_eq!(g.pkt.marshal_size(), g.want.len(), "{} size", g.name);
        }
    }

    #[test]
    fn golden_decode() {
        for g in goldens() {
            let (got, n) = parse(g.want).unwrap();
            assert_eq!(n, g.want.len(), "{} consumed", g.name);
            assert_eq!(got, g.pkt, "{} decode", g.name);
        }
    }

    #[test]
    fn golden_append_preserves_prefix() {
        for g in goldens() {
            let mut buf = vec![0x01u8, 0x02, 0x03];
            g.pkt.append_to(&mut buf);
            assert_eq!(&buf[..3], &[0x01, 0x02, 0x03]);
            assert_eq!(&buf[3..], g.want, "{} append", g.name);
        }
    }

    #[test]
    fn golden_compound() {
        // libRIST receiver NACK compound: empty RR, SDES, NACK.
        let pkts = vec![
            Packet::EmptyReceiverReport(EmptyReceiverReport { ssrc: 0x0F0F_0F02 }),
            Packet::Sdes(Sdes {
                ssrc: 0x0F0F_0F02,
                cname: "go".into(),
            }),
            Packet::RangeNack(RangeNack {
                media_ssrc: 0x0F0F_0F02,
                ranges: vec![NackRange { start: 7, extra: 2 }],
            }),
        ];
        let want: &[u8] = &[
            0x80, 0xC9, 0x00, 0x01, 0x0F, 0x0F, 0x0F, 0x02, // empty RR
            0x81, 0xCA, 0x00, 0x03, 0x0F, 0x0F, 0x0F, 0x02, 0x01, 0x02, b'g', b'o', 0x00, 0x00,
            0x00, 0x00, // SDES "go"
            0x80, 0xCC, 0x00, 0x03, 0x0F, 0x0F, 0x0F, 0x02, 0x52, 0x49, 0x53, 0x54, 0x00, 0x07,
            0x00, 0x02, // range NACK 7..9
        ];

        let mut got = Vec::new();
        build_compound(&mut got, &pkts).unwrap();
        assert_eq!(got, want);
        assert_eq!(compound_marshal_size(&pkts), want.len());
        assert_eq!(parse_compound(want).unwrap(), pkts);
    }

    #[test]
    fn nack_round_trip_through_encoders() {
        // Consecutive run + isolated + wrap.
        let missing: Vec<u32> = vec![100, 101, 102, 200, 0xFFFF, 0, 1];
        let range = encode_range_nack(0, 0xCAFE, &missing);
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].missing_seqs(), missing);
        let bitmask = encode_bitmask_nack(0, 0xCAFE, &missing);
        let expanded: Vec<u32> = bitmask.iter().flat_map(BitmaskNack::missing_seqs).collect();
        assert_eq!(expanded, missing);
        // The run 100..102 collapses to one record (start 100, extra 2).
        assert_eq!(
            range[0].ranges[0],
            NackRange {
                start: 100,
                extra: 2
            }
        );
        // Wrap 0xFFFF -> 0 -> 1 is one record.
        assert!(
            range[0]
                .ranges
                .iter()
                .any(|r| r.start == 0xFFFF && r.extra == 2)
        );
    }

    #[test]
    fn nack_encoders_split_at_record_budget() {
        // 17 isolated sequences -> two range packets (16 + 1).
        let missing: Vec<u32> = (0..17u32).map(|i| (i as u16 as u32) * 2).collect();
        let pkts = encode_range_nack(0, 1, &missing);
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].ranges.len(), MAX_NACK_RECORDS_PER_PACKET);
        assert_eq!(pkts[1].ranges.len(), 1);
    }

    #[test]
    fn parse_rejects_framing_violations() {
        assert!(matches!(parse(&[0x80]), Err(RtcpError::ShortPacket { .. })));
        assert!(matches!(
            parse(&[0x40, 0xC8, 0, 6]),
            Err(RtcpError::BadVersion(1))
        ));
        assert!(matches!(
            parse(&[0x80, 0xC8, 0xFF, 0xFF, 0, 0, 0, 0]),
            Err(RtcpError::ShortPacket { .. })
        ));
        assert!(matches!(parse_compound(&[]), Err(RtcpError::EmptyCompound)));
    }

    #[test]
    fn unknown_shapes_become_raw() {
        // PT 200 with a non-RIST length/count -> Raw, not an error.
        let foreign: &[u8] = &[0x81, 0xC8, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        let (pkt, n) = parse(foreign).unwrap();
        assert_eq!(n, foreign.len());
        assert!(matches!(pkt, Packet::Raw(_)));
        assert_eq!(pkt.encode(), foreign);
    }

    #[test]
    fn sdes_cname_round_trips_non_utf8_byte_stably() {
        // A non-UTF-8 CNAME must survive decode→re-encode byte-for-byte (the reason the
        // field is `Bytes`, not a lossily-decoded `String`).
        let raw: &[u8] = &[0x52, 0xFF, 0x00, 0xC3, 0x28, 0x49]; // invalid UTF-8 bytes
        let wire = Packet::Sdes(Sdes {
            ssrc: 0x1234_5678,
            cname: Bytes::copy_from_slice(raw),
        })
        .encode();
        let (pkt, n) = parse(&wire).unwrap();
        assert_eq!(n, wire.len());
        match pkt {
            Packet::Sdes(s) => {
                assert_eq!(s.cname.as_ref(), raw, "CNAME bytes preserved");
                assert_eq!(Packet::Sdes(s).encode(), wire, "re-encode byte-stable");
            }
            other => panic!("expected Sdes, got {other:?}"),
        }
    }

    #[test]
    fn build_compound_enforces_order() {
        let sdes = Packet::Sdes(Sdes {
            ssrc: 1,
            cname: "x".into(),
        });
        let rr = Packet::EmptyReceiverReport(EmptyReceiverReport { ssrc: 1 });
        let echo = Packet::EchoRequest(EchoRequest {
            ssrc: 1,
            timestamp: 0,
            padding: Bytes::new(),
        });
        let nack = Packet::RangeNack(RangeNack {
            media_ssrc: 1,
            ranges: vec![],
        });
        let ext = Packet::ExtSeq(ExtSeq {
            ssrc: 1,
            seq_high: 0,
        });

        let mut buf = Vec::new();
        assert!(build_compound(&mut buf, &[sdes.clone(), rr.clone()]).is_err());
        assert!(
            build_compound(
                &mut buf,
                &[rr.clone(), sdes.clone(), echo.clone(), nack.clone()]
            )
            .is_err()
        );
        assert!(
            build_compound(
                &mut buf,
                &[rr.clone(), sdes.clone(), ext.clone(), echo.clone()]
            )
            .is_err()
        );
        assert!(build_compound(&mut buf, &[rr, sdes, ext, nack, echo]).is_ok());
    }
}
