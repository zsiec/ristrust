//! SRP-6a / SHA-256 primitives (Main profile authentication).
//!
//! Scaffolding (Phase 3 / WP3). RFC 5054 PAD-compliant SRP over the 2048-bit
//! group: verifier generation, client/server key agreement, and M1/M2 proofs.
//! KAT vectors are ported from ristgo (captured from libRIST). libRIST pads only
//! `k` and `u`; `K = H(S)` and the proof component hashes use minimal length.
