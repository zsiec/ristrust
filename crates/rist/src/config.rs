//! Public configuration: all libRIST defaults, a fluent builder, and validation.
//!
//! Durations are `std::time::Duration` at the public surface; the session layer
//! converts them to the core's microsecond domain. Defaults match libRIST exactly
//! so a ristrust peer interoperates with libRIST.

use std::sync::Arc;
use std::time::Duration;

use rist_codec::crypto::AesKeyBits;
use rist_core::flow::CongestionMode;

use crate::error::ConfigError;

/// A source-adaptation rate callback (TR-06-4 Part 1): invoked with the new
/// encoder bit-rate target, in kbit/s, each time an inbound Link Quality Message
/// moves it. The application should retune its encoder toward that target. The
/// callback runs on the session task, so it must not block.
#[derive(Clone)]
pub struct RateCallback(Arc<dyn Fn(u32) + Send + Sync>);

impl RateCallback {
    /// Wraps `f` as a rate callback.
    pub fn new(f: impl Fn(u32) + Send + Sync + 'static) -> RateCallback {
        RateCallback(Arc::new(f))
    }

    /// Invokes the callback with a new target rate in kbit/s.
    pub(crate) fn call(&self, target_kbps: u32) {
        (self.0)(target_kbps);
    }
}

impl std::fmt::Debug for RateCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RateCallback(..)")
    }
}

/// The RIST profile (wire dialect) a session speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// VSF TR-06-1: bare RTP/RTCP on an even/odd UDP port pair.
    Simple,
    /// VSF TR-06-2: GRE-over-UDP tunnel, PSK encryption, EAP-SRP auth.
    Main,
    /// VSF TR-06-3: compact header, AEAD, LZ4 compression, control messages.
    Advanced,
}

/// Which wire encoding the receiver uses for negative acknowledgements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NackType {
    /// RTCP APP "RIST" `{start, extra}` ranges (libRIST default).
    Range,
    /// RFC 4585 Generic NACK (PT 205, FMT 1) `{PID, BLP}` bitmask.
    Bitmask,
}

/// Session configuration. Construct via [`Config::default`] (the libRIST defaults)
/// and refine with the `with_*` builder methods; call [`Config::validate`] before
/// use (the constructors do this for you).
#[derive(Debug, Clone)]
#[non_exhaustive]
// The bool fields are independent on/off feature flags (compression, NPD, source
// adaptation, multicast loopback), not a state space to model as an enum.
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// The profile (wire dialect).
    pub profile: Profile,
    /// Minimum recovery buffer (`recovery_length_min`).
    pub buffer_min: Duration,
    /// Maximum recovery buffer (`recovery_length_max`).
    pub buffer_max: Duration,
    /// Reorder tolerance before a gap is treated as loss.
    pub reorder_buffer: Duration,
    /// Lower RTT clamp.
    pub rtt_min: Duration,
    /// Upper RTT clamp.
    pub rtt_max: Duration,
    /// RTT multiplier for the recovery window.
    pub rtt_multiplier: u32,
    /// Minimum retransmission requests before giving up.
    pub min_retries: u32,
    /// Maximum retransmission requests before giving up.
    pub max_retries: u32,
    /// Peer liveness timeout.
    pub session_timeout: Duration,
    /// Keepalive cadence.
    pub keepalive_interval: Duration,
    /// Recovery bitrate ceiling, in kbps. Doubles as `recovery_maxbitrate`: the
    /// rate the sender paces retransmissions against under
    /// [`CongestionMode::Normal`] / [`CongestionMode::Aggressive`].
    pub max_bitrate_kbps: u32,
    /// How the sender paces retransmissions against `max_bitrate_kbps`. Default
    /// [`CongestionMode::Normal`] (the libRIST default).
    pub congestion_control: CongestionMode,
    /// Virtual source port advertised on the wire.
    pub virt_src_port: u16,
    /// Virtual destination port advertised on the wire.
    pub virt_dst_port: u16,
    /// NACK wire encoding.
    pub nack_type: NackType,
    /// Canonical name (RTCP SDES CNAME), if set.
    pub cname: Option<String>,
    /// PSK passphrase (Main/Advanced); `None` means no encryption.
    pub secret: Option<String>,
    /// AES key size when `secret` is set; defaults to 256-bit if unset.
    pub aes_key_bits: Option<AesKeyBits>,
    /// Packets to encrypt under one PSK nonce before rotating to a fresh nonce and
    /// re-derived key (Main/Advanced). `0` (the default) rotates only at the
    /// per-nonce reuse-limit ceiling, matching libRIST.
    pub key_rotation: u32,
    /// EAP-SRP username (Main profile); enables authentication when set with
    /// `srp_password`. A sender authenticates as this user; a listener verifies it.
    pub srp_username: Option<String>,
    /// EAP-SRP password paired with `srp_username`.
    pub srp_password: Option<String>,
    /// Enable LZ4 payload compression on the send path (Advanced profile).
    pub compression: bool,
    /// Enable Main-profile null-packet deletion on the send path (TR-06-2 §8.6).
    /// A sender suppresses null MPEG-TS packets and signals their positions in the
    /// RIST NPD RTP extension, saving the bandwidth of transmitting stuffing; the
    /// receiver reconstructs them. Main profile only. Default: off.
    pub null_packet_deletion: bool,
    /// Run as a one-way / no-return-channel transport: the sender keeps no
    /// retransmit history and emits no control traffic; the receiver requests no
    /// retransmission and sends nothing back (reclaiming unrecoverable loss by
    /// playout-skip). Set it on **both** ends. Incompatible with EAP-SRP (the
    /// handshake needs a return channel). Default: off.
    pub one_way: bool,
    /// The uniform SMPTE 2022-7 bonding load-share weight applied to every path of
    /// a `dial_bonded` sender. `0` (the default, `WEIGHT_DUPLICATE`) duplicates the
    /// stream onto every path for full redundancy; `> 0` load-shares it across the
    /// paths in proportion to the weight. Per-path weights use `dial_bonded_weighted`
    /// instead. Ignored by non-bonded senders and by all receivers.
    pub weight: u32,
    /// Make a receiver emit periodic Link Quality Messages for source adaptation
    /// (TR-06-4 Part 1). Carried as an RR profile-specific extension (Simple/Main)
    /// or an Advanced control message (index `0x0002`). Default: off.
    pub source_adaptation: bool,
    /// The encoder rate floor, in kbit/s, for source-adaptation control (the
    /// controller's `min_kbps`). `max_bitrate_kbps` is the ceiling.
    pub min_bitrate_kbps: u32,
    /// The source-adaptation rate callback. When set on a sender, each inbound
    /// Link Quality Message drives the AIMD controller and this is invoked with the
    /// new encoder bit-rate target. `None` (default) disables rate control.
    pub on_rate_adapt: Option<RateCallback>,
    /// Network interface name for multicast (libRIST `miface`): a sender's egress
    /// interface and a receiver's group-membership interface. `None` (the default)
    /// lets the OS choose. Consulted only when the bind (receiver) or destination
    /// (sender) address is a multicast group; a unicast address ignores it.
    pub interface: Option<String>,
    /// IP multicast hop limit (TTL) stamped on a sender's outbound multicast
    /// datagrams. `0` (the default) uses the OS default of 1, restricting traffic
    /// to the local link; routed multicast needs a higher value sized to the
    /// network diameter. Consulted only when the destination is a multicast group.
    pub multicast_ttl: u8,
    /// Source-specific multicast (SSM, RFC 4607) source filter for a receiver bound
    /// to a multicast group: only datagrams from this exact source IP are accepted.
    /// `None` (the default) is any-source multicast. IPv4 only. It is an error to
    /// set this when the bind address is not a multicast group.
    pub multicast_source: Option<String>,
    /// Whether a sender transmitting to a multicast group also receives its own
    /// datagrams on the same host (`IP_MULTICAST_LOOP`). Default `false`.
    pub multicast_loopback: bool,
}

impl Default for Config {
    /// The libRIST default parameters.
    fn default() -> Config {
        Config {
            profile: Profile::Simple,
            buffer_min: Duration::from_millis(1000),
            buffer_max: Duration::from_millis(1000),
            reorder_buffer: Duration::from_millis(15),
            rtt_min: Duration::from_millis(5),
            rtt_max: Duration::from_millis(500),
            rtt_multiplier: 7,
            min_retries: 6,
            max_retries: 20,
            session_timeout: Duration::from_millis(2000),
            keepalive_interval: Duration::from_millis(1000),
            max_bitrate_kbps: 100_000,
            congestion_control: CongestionMode::Normal,
            virt_src_port: 1971,
            virt_dst_port: 1968,
            nack_type: NackType::Range,
            cname: None,
            secret: None,
            aes_key_bits: None,
            key_rotation: 0,
            srp_username: None,
            srp_password: None,
            compression: false,
            null_packet_deletion: false,
            one_way: false,
            weight: 0,
            source_adaptation: false,
            min_bitrate_kbps: 500,
            on_rate_adapt: None,
            interface: None,
            multicast_ttl: 0,
            multicast_source: None,
            multicast_loopback: false,
        }
    }
}

impl Config {
    /// Sets the profile.
    #[must_use]
    pub fn with_profile(mut self, profile: Profile) -> Config {
        self.profile = profile;
        self
    }

    /// Sets both the minimum and maximum recovery buffer to `buffer`.
    #[must_use]
    pub fn with_buffer(mut self, buffer: Duration) -> Config {
        self.buffer_min = buffer;
        self.buffer_max = buffer;
        self
    }

    /// Sets the recovery buffer range.
    #[must_use]
    pub fn with_buffer_range(mut self, min: Duration, max: Duration) -> Config {
        self.buffer_min = min;
        self.buffer_max = max;
        self
    }

    /// Sets the RTT clamps.
    #[must_use]
    pub fn with_rtt(mut self, min: Duration, max: Duration) -> Config {
        self.rtt_min = min;
        self.rtt_max = max;
        self
    }

    /// Sets the retry bounds.
    #[must_use]
    pub fn with_retries(mut self, min: u32, max: u32) -> Config {
        self.min_retries = min;
        self.max_retries = max;
        self
    }

    /// Sets the NACK wire encoding.
    #[must_use]
    pub fn with_nack_type(mut self, nack_type: NackType) -> Config {
        self.nack_type = nack_type;
        self
    }

    /// Sets the keepalive cadence.
    #[must_use]
    pub fn with_keepalive(mut self, interval: Duration) -> Config {
        self.keepalive_interval = interval;
        self
    }

    /// Sets the peer liveness timeout: a session whose peer sends nothing (media,
    /// control, or keepalive) for this long is torn down. Must be at least
    /// `keepalive_interval` (enforced by [`Config::validate`]).
    #[must_use]
    pub fn with_session_timeout(mut self, timeout: Duration) -> Config {
        self.session_timeout = timeout;
        self
    }

    /// Sets the PSK passphrase (enables encryption on Main/Advanced).
    #[must_use]
    pub fn with_secret(mut self, secret: impl Into<String>) -> Config {
        self.secret = Some(secret.into());
        self
    }

    /// Sets the AES key size used with [`Config::with_secret`].
    #[must_use]
    pub fn with_aes_key_bits(mut self, bits: AesKeyBits) -> Config {
        self.aes_key_bits = Some(bits);
        self
    }

    /// Sets the PSK key-rotation interval in packets (Main/Advanced); `0` (the
    /// default) rotates only at the per-nonce reuse-limit ceiling.
    #[must_use]
    pub fn with_key_rotation(mut self, packets: u32) -> Config {
        self.key_rotation = packets;
        self
    }

    /// Sets the EAP-SRP credentials (Main profile). A sender authenticates as this
    /// user; a listener verifies a connecting peer against it.
    #[must_use]
    pub fn with_srp_credentials(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Config {
        self.srp_username = Some(username.into());
        self.srp_password = Some(password.into());
        self
    }

    /// Enables LZ4 payload compression on the send path (Advanced profile).
    #[must_use]
    pub fn with_compression(mut self, on: bool) -> Config {
        self.compression = on;
        self
    }

    /// Enables Main-profile null-packet deletion on the send path (TR-06-2 §8.6):
    /// the sender suppresses null MPEG-TS packets and signals their positions in
    /// the RIST NPD RTP extension, saving stuffing bandwidth. Main profile only.
    #[must_use]
    pub fn with_null_packet_deletion(mut self, on: bool) -> Config {
        self.null_packet_deletion = on;
        self
    }

    /// Runs the session as a one-way / no-return-channel transport (no ARQ, no
    /// control egress). Set it on both the sender and the receiver. Incompatible
    /// with EAP-SRP authentication.
    #[must_use]
    pub fn with_one_way(mut self, on: bool) -> Config {
        self.one_way = on;
        self
    }

    /// Sets the uniform 2022-7 bonding load-share weight for a `dial_bonded` sender
    /// (`0` = full duplication; `> 0` = load-share). For per-path weights use
    /// `dial_bonded_weighted`.
    #[must_use]
    pub fn with_weight(mut self, weight: u32) -> Config {
        self.weight = weight;
        self
    }

    /// Makes a receiver emit periodic Link Quality Messages for source adaptation
    /// (TR-06-4 Part 1).
    #[must_use]
    pub fn with_source_adaptation(mut self, on: bool) -> Config {
        self.source_adaptation = on;
        self
    }

    /// Sets the encoder rate floor, in kbit/s, for source-adaptation control.
    #[must_use]
    pub fn with_min_bitrate(mut self, kbps: u32) -> Config {
        self.min_bitrate_kbps = kbps;
        self
    }

    /// Selects how the sender paces retransmissions against `max_bitrate_kbps`
    /// (default [`CongestionMode::Normal`]).
    #[must_use]
    pub fn with_congestion_control(mut self, mode: CongestionMode) -> Config {
        self.congestion_control = mode;
        self
    }

    /// Sets the multicast interface name (libRIST `miface`) used for group
    /// membership (receiver) and egress (sender).
    #[must_use]
    pub fn with_multicast_interface(mut self, name: impl Into<String>) -> Config {
        self.interface = Some(name.into());
        self
    }

    /// Sets the outbound multicast hop limit (TTL); `0` keeps the OS default of 1.
    #[must_use]
    pub fn with_multicast_ttl(mut self, ttl: u8) -> Config {
        self.multicast_ttl = ttl;
        self
    }

    /// Sets the source-specific-multicast (SSM) source IP filter for a receiver
    /// bound to a multicast group (IPv4 only).
    #[must_use]
    pub fn with_multicast_source(mut self, source: impl Into<String>) -> Config {
        self.multicast_source = Some(source.into());
        self
    }

    /// Sets whether a multicast sender also receives its own datagrams on this
    /// host (`IP_MULTICAST_LOOP`).
    #[must_use]
    pub fn with_multicast_loopback(mut self, on: bool) -> Config {
        self.multicast_loopback = on;
        self
    }

    /// Sets the source-adaptation rate callback on a sender: each inbound Link
    /// Quality Message drives the AIMD controller and calls `f` with the new
    /// encoder bit-rate target (kbit/s).
    #[must_use]
    pub fn with_rate_callback(mut self, f: impl Fn(u32) + Send + Sync + 'static) -> Config {
        self.on_rate_adapt = Some(RateCallback::new(f));
        self
    }

    /// Sets the canonical name (RTCP SDES CNAME).
    #[must_use]
    pub fn with_cname(mut self, cname: impl Into<String>) -> Config {
        self.cname = Some(cname.into());
        self
    }

    /// Validates the configuration against libRIST's accepted ranges.
    ///
    /// # Errors
    /// Returns the [`ConfigError`] describing the first violation found (buffer,
    /// RTT, retry, keepalive, or bitrate bounds).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let min_ms = self.buffer_min.as_millis();
        if !(50..=30_000).contains(&min_ms) {
            return Err(ConfigError::BufferOutOfRange { ms: min_ms });
        }
        if self.buffer_max < self.buffer_min {
            return Err(ConfigError::BufferRangeInverted);
        }
        if self.reorder_buffer > self.buffer_min {
            return Err(ConfigError::ReorderTooLarge);
        }
        if !(1..=1000).contains(&self.rtt_min.as_millis()) {
            return Err(ConfigError::RttOutOfRange);
        }
        if self.rtt_max < self.rtt_min || self.rtt_max.as_millis() > 1000 {
            return Err(ConfigError::RttRangeInverted);
        }
        if !(1..=100).contains(&self.rtt_multiplier) {
            return Err(ConfigError::RttMultiplierOutOfRange {
                value: self.rtt_multiplier,
            });
        }
        if self.min_retries > 100 || self.max_retries > 100 {
            return Err(ConfigError::RetriesOutOfRange);
        }
        if self.min_retries > self.max_retries {
            return Err(ConfigError::RetriesInverted);
        }
        if self.keepalive_interval.is_zero() {
            return Err(ConfigError::KeepaliveZero);
        }
        if self.session_timeout < self.keepalive_interval {
            return Err(ConfigError::SessionTimeoutBelowKeepalive);
        }
        if self.max_bitrate_kbps == 0 {
            return Err(ConfigError::MaxBitrateZero);
        }
        // One-way mode has no return channel, so the EAP-SRP handshake cannot run.
        if self.one_way && (self.srp_username.is_some() || self.srp_password.is_some()) {
            return Err(ConfigError::OneWayWithAuth);
        }
        // Fail closed: reject features a profile would silently ignore.
        let unsupported =
            |feature, profile| ConfigError::ProfileFeatureUnsupported { feature, profile };
        match self.profile {
            Profile::Simple => {
                if self.secret.is_some() {
                    return Err(unsupported("PSK encryption (secret)", "Simple"));
                }
                if self.srp_username.is_some() || self.srp_password.is_some() {
                    return Err(unsupported("EAP-SRP authentication", "Simple"));
                }
                if self.compression {
                    return Err(unsupported("LZ4 compression", "Simple"));
                }
                if self.null_packet_deletion {
                    return Err(unsupported("null-packet deletion", "Simple"));
                }
            }
            Profile::Main => {
                if self.compression {
                    // LZ4 compression is an Advanced-profile feature only.
                    return Err(unsupported("LZ4 compression", "Main"));
                }
            }
            Profile::Advanced => {
                if self.null_packet_deletion {
                    // NPD is a Main-profile (MPEG-TS-over-GRE) feature; the Advanced
                    // profile carries an opaque media payload.
                    return Err(unsupported("null-packet deletion", "Advanced"));
                }
            }
        }
        // Multicast field-level checks (address-dependent checks — e.g. an SSM
        // source on a unicast bind — happen at socket construction, where the
        // bind/destination address is known).
        if let Some(name) = &self.interface
            && crate::multicast::resolve_interface(name).is_err()
        {
            return Err(ConfigError::MulticastInterfaceNotFound { name: name.clone() });
        }
        if let Some(src) = &self.multicast_source
            && src.parse::<std::net::IpAddr>().is_err()
        {
            return Err(ConfigError::MulticastSourceInvalid { value: src.clone() });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_librist() {
        let c = Config::default();
        assert_eq!(c.profile, Profile::Simple);
        assert_eq!(c.buffer_min, Duration::from_millis(1000));
        assert_eq!(c.rtt_min, Duration::from_millis(5));
        assert_eq!(c.rtt_max, Duration::from_millis(500));
        assert_eq!(c.rtt_multiplier, 7);
        assert_eq!(c.min_retries, 6);
        assert_eq!(c.max_retries, 20);
        assert_eq!(c.keepalive_interval, Duration::from_millis(1000));
        assert_eq!(c.session_timeout, Duration::from_millis(2000));
        assert_eq!(c.max_bitrate_kbps, 100_000);
        assert_eq!(c.congestion_control, CongestionMode::Normal);
        assert_eq!(c.virt_src_port, 1971);
        assert_eq!(c.virt_dst_port, 1968);
        assert_eq!(c.nack_type, NackType::Range);
        c.validate().expect("defaults must validate");
    }

    #[test]
    fn with_congestion_control_overrides_the_default() {
        let c = Config::default().with_congestion_control(CongestionMode::Aggressive);
        assert_eq!(c.congestion_control, CongestionMode::Aggressive);
    }

    #[test]
    fn validate_rejects_bad_multicast_config() {
        // A non-IP SSM source is rejected.
        assert!(matches!(
            Config::default()
                .with_multicast_source("not-an-ip")
                .validate(),
            Err(ConfigError::MulticastSourceInvalid { .. })
        ));
        // An unknown interface name is rejected.
        assert!(matches!(
            Config::default()
                .with_multicast_interface("nonexistent-iface-zzz")
                .validate(),
            Err(ConfigError::MulticastInterfaceNotFound { .. })
        ));
        // A valid IP source on its own (the bind-address check happens at
        // construction) passes field-level validation.
        Config::default()
            .with_multicast_source("232.1.2.3")
            .validate()
            .expect("a valid source IP passes field validation");
    }

    #[test]
    fn validate_rejects_inverted_buffer_range() {
        let c = Config::default()
            .with_buffer_range(Duration::from_millis(1000), Duration::from_millis(500));
        assert_eq!(c.validate(), Err(ConfigError::BufferRangeInverted));
    }

    #[test]
    fn validate_fails_closed_on_unsupported_profile_features() {
        // Encryption/auth/compression on Simple, and compression on Main, are
        // rejected rather than silently ignored.
        assert!(matches!(
            Config::default().with_secret("x").validate(),
            Err(ConfigError::ProfileFeatureUnsupported { .. })
        ));
        assert!(matches!(
            Config::default().with_srp_credentials("u", "p").validate(),
            Err(ConfigError::ProfileFeatureUnsupported { .. })
        ));
        assert!(matches!(
            Config::default()
                .with_profile(Profile::Main)
                .with_compression(true)
                .validate(),
            Err(ConfigError::ProfileFeatureUnsupported { .. })
        ));
        // The supported combinations still validate.
        assert!(
            Config::default()
                .with_profile(Profile::Advanced)
                .with_compression(true)
                .validate()
                .is_ok()
        );
        assert!(
            Config::default()
                .with_profile(Profile::Main)
                .with_secret("x")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_gates_null_packet_deletion_to_main() {
        // NPD is a Main-profile feature; rejected (not silently ignored) elsewhere.
        assert!(matches!(
            Config::default().with_null_packet_deletion(true).validate(),
            Err(ConfigError::ProfileFeatureUnsupported { .. })
        ));
        assert!(matches!(
            Config::default()
                .with_profile(Profile::Advanced)
                .with_null_packet_deletion(true)
                .validate(),
            Err(ConfigError::ProfileFeatureUnsupported { .. })
        ));
        assert!(
            Config::default()
                .with_profile(Profile::Main)
                .with_null_packet_deletion(true)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_one_way_with_auth() {
        // One-way has no return channel, so EAP-SRP cannot run.
        assert_eq!(
            Config::default()
                .with_profile(Profile::Main)
                .with_one_way(true)
                .with_srp_credentials("u", "p")
                .validate(),
            Err(ConfigError::OneWayWithAuth)
        );
        // One-way alone (no auth) is fine.
        assert!(
            Config::default()
                .with_profile(Profile::Main)
                .with_one_way(true)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_inverted_retries() {
        let c = Config::default().with_retries(20, 6);
        assert_eq!(c.validate(), Err(ConfigError::RetriesInverted));
    }

    #[test]
    fn builder_sets_fields() {
        let c = Config::default()
            .with_profile(Profile::Main)
            .with_secret("hunter2")
            .with_aes_key_bits(AesKeyBits::Aes128)
            .with_key_rotation(2048)
            .with_session_timeout(Duration::from_millis(3000))
            .with_nack_type(NackType::Bitmask);
        assert_eq!(c.profile, Profile::Main);
        assert_eq!(c.secret.as_deref(), Some("hunter2"));
        assert_eq!(c.aes_key_bits, Some(AesKeyBits::Aes128));
        assert_eq!(c.key_rotation, 2048);
        assert_eq!(c.session_timeout, Duration::from_millis(3000));
        assert_eq!(c.nack_type, NackType::Bitmask);
    }
}
