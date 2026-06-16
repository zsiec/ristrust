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
    /// A feature was configured on a profile that does not support it (e.g. a PSK
    /// secret on the Simple profile, or LZ4 compression outside Advanced). The
    /// configuration is rejected rather than silently ignoring the feature.
    #[error("rist: {feature} is not supported on the {profile} profile")]
    ProfileFeatureUnsupported {
        /// The unsupported feature.
        feature: &'static str,
        /// The profile that does not support it.
        profile: &'static str,
    },
    /// The configured multicast `interface` (libRIST `miface`) does not resolve to
    /// a network interface on this host.
    #[error("rist: multicast interface {name:?} not found")]
    MulticastInterfaceNotFound {
        /// The interface name that failed to resolve.
        name: String,
    },
    /// `multicast_source` (the SSM source filter) is not a valid IP literal.
    #[error("rist: multicast_source {value:?} is not a valid IP address")]
    MulticastSourceInvalid {
        /// The offending value.
        value: String,
    },
    /// One-way mode was combined with EAP-SRP authentication, which needs a return
    /// channel for the handshake.
    #[error("rist: one-way mode is incompatible with EAP-SRP authentication")]
    OneWayWithAuth,
    /// The forward-error-correction matrix or carriage is invalid: the L×D matrix is
    /// outside the TR-06 bounds for the chosen variant, or in-band carriage was
    /// requested on a non-Advanced profile.
    #[error("rist: invalid FEC configuration: {reason}")]
    FecInvalid {
        /// A short description of the violation.
        reason: &'static str,
    },
    /// The DTLS configuration is invalid: DTLS was combined with a feature it
    /// excludes (the GRE PSK `secret` or EAP-SRP), or no DTLS authentication method
    /// (PSK or certificate) was provided.
    #[cfg(feature = "dtls")]
    #[error("rist: invalid DTLS configuration: {reason}")]
    DtlsInvalid {
        /// A short description of the violation.
        reason: &'static str,
    },
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
    /// The address could not be parsed as `IP:port`.
    #[error("rist: invalid address: {0}")]
    InvalidAddr(String),
    /// A `rist://` URL was malformed: an unsupported scheme, a missing port, or a
    /// query parameter that is not a valid integer or is out of range.
    #[error("rist: invalid url: {0}")]
    Url(String),
    /// The session has closed: its driver task exited (the local handle was
    /// dropped/closed or an unrecoverable socket error occurred), so no further
    /// data can be sent or received. A close caused by peer silence or a failed
    /// handshake is reported more specifically as [`Error::SessionTimeout`] or
    /// [`Error::Auth`].
    #[error("rist: session closed")]
    Closed,
    /// The session was torn down because no traffic (media, control, or keepalive)
    /// arrived from the peer within `session_timeout`. Surfaced by `send`/`recv`
    /// once the session ends.
    #[error("rist: session timed out")]
    SessionTimeout,
    /// The Main/Advanced EAP-SRP handshake failed — the configured credentials did
    /// not authenticate against the peer (or the peer's proof was refused) — and the
    /// session was torn down. Surfaced by `send`/`recv` once the session ends.
    #[error("rist: authentication failed")]
    Auth,
    /// [`Sender::write_flow_attribute`](crate::Sender::write_flow_attribute) was
    /// called on a non-Advanced sender. Flow attributes (TR-06-3 §5.3.7) are an
    /// Advanced-profile control message.
    #[error("rist: flow attributes require the Advanced profile")]
    FlowAttrUnsupported,
    /// An out-of-band operation was used on a profile without the OOB side channel.
    /// OOB passthrough exists only on the Main and Advanced profiles.
    #[error("rist: out-of-band data requires the Main or Advanced profile")]
    OobUnsupported,
    /// `write_oob_typed` was given a GRE protocol type RIST reserves for its own
    /// framing (reduced/keepalive/EAPOL/VSF); such a datagram would be misrouted by
    /// the peer's demux. Use [`OOB_PROTOCOL_IP`](crate::OOB_PROTOCOL_IP) or another
    /// non-reserved EtherType.
    #[error("rist: OOB protocol type 0x{0:04X} is reserved for RIST framing")]
    OobProtocol(u16),
    /// A [`Sender::send`](crate::Sender::send) payload exceeded the maximum a single
    /// write may carry. With Advanced-profile fragmentation enabled the limit is
    /// `fragment_size` × [`MAX_FRAGMENTS_PER_WRITE`](crate::MAX_FRAGMENTS_PER_WRITE);
    /// chunk the media before submitting it.
    #[error("rist: payload {len} bytes exceeds the maximum {max}; chunk media before send")]
    PayloadTooLarge {
        /// The submitted payload length, in bytes.
        len: usize,
        /// The maximum a single write may carry, in bytes.
        max: usize,
    },
    /// A feature that is scaffolded but not yet implemented was invoked.
    #[error("rist: not yet implemented: {0}")]
    Unimplemented(&'static str),
}
