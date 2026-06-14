//! RTCP control codec (Simple/Main profiles).
//!
//! Scaffolding (Phase 2 / WP2). Compound RTCP: SR(200)/RR(201)/SDES-CNAME(202),
//! RFC 4585 Generic NACK (PT205/FMT1, bitmask — ported from pion/rtcp, see
//! `NOTICE.md`), RIST APP "RIST" range NACK (PT204), RTT-echo (PT204 subtype
//! 2/3), and EXTSEQ (PT204 subtype 1). Decodes into / encodes from
//! [`rist_core::wire::Feedback`]. Golden-byte tables ported from ristgo.
