#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod url;

mod adapt;
mod bonding;
mod codec;
mod codec_adv;
mod codec_main;
mod driver;
mod driver_adv;
mod driver_bonded;
mod driver_bonded_simple;
mod driver_main;
#[cfg(feature = "dtls")]
mod dtls_transport;
mod fec;
mod multi;
mod multicast;
mod peer;
mod reassembler;
mod receiver;
mod reflector;
mod sender;
mod session;
mod socket;
pub mod split;
mod stats;

pub use config::{Config, FlowAttrCallback, NackType, Profile, RateCallback};
pub use error::{ConfigError, Error};
pub use fec::{FecCarriage, FecConfig, FecVariant};
pub use multi::{
    MAX_FLOWS, MultiReceiver, listen_multi, listen_multi_bonded, listen_multi_bonded_with,
    listen_multi_with,
};
pub use receiver::{
    Receiver, dial_receiver, dial_receiver_with, listen, listen_bonded, listen_bonded_priority,
    listen_bonded_priority_with, listen_bonded_with, listen_with,
};
pub use reflector::{Reflector, reflect, reflect_with};
pub use runtime::{AsyncUdpSocket, Runtime, TokioRuntime};
pub use sender::{
    MAX_FRAGMENTS_PER_WRITE, Sender, dial, dial_bonded, dial_bonded_weighted,
    dial_bonded_weighted_with, dial_bonded_with, dial_with, listen_sender, listen_sender_with,
};
pub use split::{MergeMode, SplitMode};
pub use stats::Stats;
pub use url::parse_url;

/// The AES key size for PSK encryption, re-exported for use with
/// [`Config::with_aes_key_bits`].
pub use rist_codec::crypto::AesKeyBits;

/// The sender's retransmission-pacing mode, re-exported for use with
/// [`Config::with_congestion_control`].
pub use rist_core::flow::CongestionMode;

/// The receiver's playout-scheduling clock, re-exported for use with
/// [`Config::with_timing_mode`].
pub use rist_core::flow::TimingMode;

/// The DTLS connection configuration (PSK or ECDHE-ECDSA), re-exported for use with
/// [`Config::with_dtls`]. [`DtlsIdentity`] is the certificate + key an ECDHE server
/// presents (generate a self-signed one with [`DtlsIdentity::generate`]). (Feature
/// `dtls`.)
#[cfg(feature = "dtls")]
pub use rist_codec::dtls::{Config as DtlsConfig, cert::Identity as DtlsIdentity};

/// The crate version (`CARGO_PKG_VERSION`), e.g. for an SDES tool tag or logging.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The default out-of-band GRE protocol type: EtherType `0x0800` (IPv4), the value
/// libRIST stamps on every out-of-band datagram. [`Sender::write_oob`] uses it; it
/// is the only OOB protocol type that interoperates with libRIST (a libRIST peer
/// delivers a `0x0800` GRE frame as out-of-band data but drops other types). Other
/// values tunnel an arbitrary protocol between two ristrust peers, dispatched on
/// via the protocol type [`Receiver::read_oob`] returns.
pub const OOB_PROTOCOL_IP: u16 = rist_codec::gre::PROTO_FULL;

/// The largest media payload a single [`Sender::send`] can carry that still leaves
/// room for the heaviest per-profile framing within a standard 1500-byte MTU. A
/// payload at this limit fits the lightest profiles but, with the heaviest framing
/// (Advanced + AES, or Main + DTLS), is IP-fragmented on a strict-MTU path. For a
/// size safe on *every* profile, keep each write at or below [`SAFE_MEDIA_PAYLOAD`].
pub const MAX_MEDIA_PAYLOAD: usize = 1460;

/// The largest media payload that fits without IP fragmentation on *any* profile,
/// including Main+DTLS, on a standard 1500-byte MTU path. It is the 7-cell MPEG-TS
/// payload (`7 × 188`); chunking writes to this size never fragments regardless of
/// profile or encryption.
pub const SAFE_MEDIA_PAYLOAD: usize = 1316;
