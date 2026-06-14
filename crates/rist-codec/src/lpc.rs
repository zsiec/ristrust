//! LZ4 block compression (Advanced profile LPC).
//!
//! Scaffolding (Phase 4 / WP4). A pure-Rust LZ4 *block*-format codec (LPC=1),
//! compress-then-encrypt on send and decrypt-then-decompress on receive. The
//! decompressor must decode libRIST's vendored-LZ4 blocks; the compressor need
//! only emit valid blocks. Ported from the LZ4 spec/algorithm — see `NOTICE.md`.
