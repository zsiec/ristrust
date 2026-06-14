//! Null-packet deletion (Main profile).
//!
//! Scaffolding (Phase 3 / WP3). The 0x5249 ("RI") RTP header extension: a 7-bit
//! NPD bitmap + 16-bit seq-ext that lets the sender suppress null MPEG-TS packets
//! and the receiver reconstruct them. Ported from libRIST's mpegts handling.
