//! The narrow waist: normalized types that decouple the profile codecs from the
//! deterministic [`flow`](crate::flow) core.
//!
//! Every RIST profile speaks a different wire dialect — Simple is bare RTP/RTCP
//! on an even/odd port pair, Main tunnels the same traffic over GRE with optional
//! PSK encryption, and Advanced replaces RTCP with its own control messages. The
//! codec crate (`rist-codec`) owns those dialects: it decodes inbound datagrams
//! into the types here and encodes them back out. The core consumes and produces
//! *only* these normalized types — it never parses a byte of wire format, never
//! sees a 16-bit sequence number, and never learns which profile is in use. That
//! is what makes one ARQ + reorder + dedup + SMPTE 2022-7 merge implementation
//! serve all three profiles.
//!
//! # Extension policy
//!
//! New profile behavior is a new field on [`MediaPacket`] or a new [`Feedback`]
//! variant — *never* a profile branch inside `flow`. The waist enums are
//! deliberately **not** `#[non_exhaustive]`: keeping them exhaustive means adding
//! a variant is a compile error at every `match` that must handle it, across the
//! codec and host crates. That compile-time exhaustiveness is the whole point of
//! using a sum type here (in the Go sibling it was a hand-maintained convention
//! that occasionally let a new variant fall through to "unknown").

use bytes::Bytes;

/// The normalized form of one media datagram, regardless of which profile carried
/// it or which path delivered it.
///
/// Codecs produce it on receive and consume it on send; `flow` stores it in the
/// seq-indexed ring and deduplicates it by the `(seq, source_time)` pair — the
/// single test that implements the SMPTE 2022-7 multipath merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaPacket {
    /// The media sequence number, **always 32-bit at this layer**. Simple and
    /// Main codecs widen the 16-bit RTP sequence number by rollover counting (the
    /// upper 16 bits are the wrap count); Advanced carries a native 32-bit
    /// extended sequence. The core only ever does 32-bit wrap-aware arithmetic.
    pub seq: u32,

    /// The sender's media timestamp in NTP-64-compatible units (upper 32 bits
    /// whole seconds, lower 32 bits fractional). Used both for playout scheduling
    /// and as the second half of the `(seq, source_time)` duplicate test.
    pub source_time: u64,

    /// The RTP synchronization source, with the retransmit toggle already
    /// cleared. RIST senders use an even base SSRC and set the low bit on
    /// retransmissions; the receiving codec un-toggles it before the packet
    /// crosses this waist, so every copy of a stream carries the same SSRC here.
    pub ssrc: u32,

    /// The media payload (typically MPEG-TS cells). Reference-counted and
    /// zero-copy: ownership crosses the waist with the packet (no copy). The Go
    /// sibling documents this handoff in a comment; here the compiler enforces it.
    pub payload: Bytes,

    /// Whether this copy is an ARQ retransmission, set by the codec from the
    /// SSRC-LSB toggle. `flow` uses it to skip missing-detection for recovered
    /// packets and to keep retry statistics honest.
    pub retransmit: bool,

    /// Which network path delivered (or should carry) this packet. Single-path
    /// flows use `0`. For SMPTE 2022-7 bonding the session assigns a stable index
    /// per registered peer, and `flow` records per-path arrival without ever
    /// knowing what a path is.
    pub path_id: u8,
}

/// The normalized form of everything that is not media: RTCP control traffic in
/// Simple/Main, and Advanced profile control messages.
///
/// `flow` emits `Feedback` values describing intent ("retransmit these
/// sequences") and the host's profile strategy runs the matching encoder; inbound
/// control traffic is decoded into `Feedback` before `flow` sees it. The host
/// chooses the concrete wire encoding (RFC 4585 bitmask NACK vs RIST APP range
/// NACK vs an Advanced control message) — `flow` never knows which was used.
///
/// Intentionally exhaustive (not `#[non_exhaustive]`): see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feedback {
    /// Asks the sender to retransmit missing media packets. Emitted by the
    /// receiving side; `missing` is in the 32-bit widened sequence space and the
    /// codec narrows it for the 16-bit Simple/Main wire encodings.
    Nack {
        /// The media stream the missing sequences belong to.
        ssrc: u32,
        /// The sequence numbers to retransmit, 32-bit widened.
        missing: Vec<u32>,
    },

    /// Asks the peer to echo a timestamp so the requester can measure RTT. On the
    /// Simple/Main wire this is an RTCP APP packet (PT 204, name "RIST",
    /// subtype 2).
    RttEchoRequest {
        /// The requester's clock sample, echoed back verbatim.
        timestamp: u64,
    },

    /// Answers an [`Feedback::RttEchoRequest`] (RTCP APP PT 204, subtype 3). The
    /// requester computes RTT as `(now − timestamp) − processing_delay`.
    RttEchoResponse {
        /// The requester's original timestamp, echoed verbatim.
        timestamp: u64,
        /// Microseconds the responder spent between receiving the request and
        /// sending this response, subtracted to isolate network round-trip time.
        processing_delay: u32,
    },

    /// The timing essentials of an RTCP Sender Report (PT 200): the mapping
    /// between the sender's wallclock and the RTP media timeline, used by the
    /// receiver to convert RTP timestamps to wallclock for playout.
    SenderReport {
        /// The sender's wallclock at report time, NTP-64.
        ntp: u64,
        /// The RTP timestamp corresponding to the same instant as `ntp`.
        rtp_time: u32,
    },

    /// Marks a peer as alive without carrying media. In Main these are GRE frames
    /// (VSF EtherType 0xCCE0, subtype 0x8000) carrying a MAC, capability bits, and
    /// optional JSON; those fields are added as Main profile lands.
    Keepalive,

    /// Announces the upper 16 bits of the 32-bit extended sequence space that
    /// subsequent 16-bit NACK entries belong to (Main profile EXTSEQ RTCP APP,
    /// PT 204 subtype 1; VSF TR-06-2 §8.4). Widening is a codec concern: `flow`
    /// itself never emits or consumes this — it lives here so the profile
    /// strategies can exchange it without a profile branch.
    ExtSeq {
        /// The most significant 16 bits prepended to the following NACK entries.
        seq_high: u16,
    },

    /// A VSF TR-06-4 Part 1 Link Quality Message from the receiver to the sender
    /// for source adaptation. The 44 bytes are the opaque on-the-wire LQM
    /// (Figure 2), decoded by `rist-codec::adapt`; carrying them raw keeps this
    /// crate free of a TR-06-4 dependency. It is a host concern, not `flow` input:
    /// the host intercepts it to drive the rate controller.
    LinkQuality {
        /// The 44-byte Link Quality Message.
        lqm: [u8; 44],
    },
}
