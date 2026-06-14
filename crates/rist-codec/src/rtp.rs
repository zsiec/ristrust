//! RTP media codec (Simple/Main profiles).
//!
//! Scaffolding (Phase 2 / WP2). Encodes/decodes the RFC 3550 RTP header and the
//! RIST reduced-overhead virt-port prefix, widening the 16-bit sequence number to
//! the core's 32-bit space (rollover counting) and translating the retransmit
//! SSRC-LSB toggle. Ported (trimmed) from pion/rtp — see `NOTICE.md`. Decode is
//! zero-copy into the caller buffer; arbitrary bytes must never panic (fuzzed).
