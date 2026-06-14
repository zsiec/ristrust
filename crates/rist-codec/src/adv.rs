//! Advanced profile codec (VSF TR-06-3).
//!
//! Scaffolding (Phase 4 / WP4). RTP PT=127 + the always-present 4-byte profile
//! extension `{seq_ext, flags(F/L/E/R/I/P/H), params(PSK|LPC|Type)}`; Type=4
//! control messages (NACK, RTT echo, keepalive, flow-attr, psk-nonce). Note the
//! libRIST hybrid: `-p 2` runs a Main GRE/RTCP-SDES handshake substrate under the
//! PT=127 framing, and the adv RTP timestamp is effectively 2^16 MHz (see
//! `ORCHESTRATION.md` WP4 binding).
