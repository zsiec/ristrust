//! GRE-over-UDP tunnel codec (Main profile).
//!
//! Scaffolding (Phase 3 / WP3). VSF TR-06-2 GRE framing: C/K/S flags, 3-bit
//! version, H AES-keylen bit, optional 32-bit nonce + 32-bit seq; the VSF
//! EtherType 0xCCE0 type/subtype (keepalive 0x8000); reduced-overhead inner
//! header. Version 1 uses `prot_type` directly; the 0xCCE0 VSF wrapper is v≥2.
