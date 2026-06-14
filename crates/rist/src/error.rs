//! Error types for the host crate. User-facing `Display` strings are prefixed
//! `"rist: "` to match the Go sibling's convention.

/// A configuration validation failure, returned by
/// [`Config::validate`](crate::config::Config::validate) and wrapped by
/// [`Error::Config`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The recovery buffer is outside the accepted `[50 ms, 30 s]` range.
    #[error("rist: recovery buffer {ms} ms outside the 50 ms..=30 s range")]
    BufferOutOfRange {
        /// The offending value, in milliseconds.
        ms: u128,
    },
    /// `buffer_max` is below `buffer_min`.
    #[error("rist: buffer_max is below buffer_min")]
    BufferRangeInverted,
    /// The reorder buffer is larger than the minimum recovery buffer.
    #[error("rist: reorder_buffer exceeds buffer_min")]
    ReorderTooLarge,
    /// `rtt_min` is outside the accepted `[1 ms, 1 s]` range.
    #[error("rist: rtt_min outside the 1 ms..=1 s range")]
    RttOutOfRange,
    /// `rtt_max` is below `rtt_min` or above the 1 s ceiling.
    #[error("rist: rtt_max below rtt_min or above 1 s")]
    RttRangeInverted,
    /// The RTT multiplier is outside the accepted `[1, 100]` range.
    #[error("rist: rtt_multiplier {value} outside the 1..=100 range")]
    RttMultiplierOutOfRange {
        /// The offending multiplier.
        value: u32,
    },
    /// A retry count exceeds the 100 ceiling.
    #[error("rist: retry count exceeds 100")]
    RetriesOutOfRange,
    /// `min_retries` is greater than `max_retries`.
    #[error("rist: min_retries exceeds max_retries")]
    RetriesInverted,
    /// The keepalive interval is zero.
    #[error("rist: keepalive_interval must be positive")]
    KeepaliveZero,
    /// The session timeout is below the keepalive interval.
    #[error("rist: session_timeout is below keepalive_interval")]
    SessionTimeoutBelowKeepalive,
    /// The maximum bitrate is zero.
    #[error("rist: max_bitrate_kbps must be positive")]
    MaxBitrateZero,
}

/// The top-level error type for the host crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration validation failed.
    #[error("rist: invalid configuration: {0}")]
    Config(#[from] ConfigError),
    /// An underlying I/O operation failed (socket bind, send, receive).
    #[error("rist: io error: {0}")]
    Io(#[from] std::io::Error),
    /// The address could not be parsed as `IP:port`. (`rist://` URL parsing lands
    /// in WP2.)
    #[error("rist: invalid address: {0}")]
    InvalidAddr(String),
    /// A feature that is scaffolded but not yet implemented was invoked.
    #[error("rist: not yet implemented: {0}")]
    Unimplemented(&'static str),
}
