//! `rist://` URL parsing (scaffolding).
//!
//! Phase 2 (WP2): parse the full libRIST `rist://` parameter set into an address
//! plus a [`Config`](crate::config::Config), so the same URL string works against
//! ffmpeg/libRIST (`buffer`, `buffer-min/max`, `rtt-min/max`, `rtt-multiplier`,
//! `reorder-buffer`, `bandwidth`, `secret`, `aes-type`, `cname`, `profile`, …).
//! Until then the constructors accept a bare `IP:port`.
