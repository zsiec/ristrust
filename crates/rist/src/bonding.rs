//! SMPTE 2022-7 bonding host layer (scaffolding).
//!
//! Phase 5 (WP5): register N peers onto one flow (identical seq/ts TX), track
//! per-path liveness and the differential-delay budget, and select the NACK peer
//! (libRIST `rist_nack_peer_preferred`: highest priority, then lowest raw RTT).
//! The packet-level merge itself already lives in [`rist_core::flow`].
