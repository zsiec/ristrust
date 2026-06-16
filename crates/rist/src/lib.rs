#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
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
mod driver_main;
mod multicast;
mod peer;
mod receiver;
mod sender;
mod session;
mod socket;

pub use config::{Config, NackType, Profile, RateCallback};
pub use error::{ConfigError, Error};
pub use receiver::{Receiver, listen, listen_bonded, listen_bonded_with, listen_with};
pub use runtime::{AsyncUdpSocket, Runtime, TokioRuntime};
pub use sender::{Sender, dial, dial_bonded, dial_bonded_with, dial_with};
pub use url::parse_url;

/// The AES key size for PSK encryption, re-exported for use with
/// [`Config::with_aes_key_bits`].
pub use rist_codec::crypto::AesKeyBits;

/// The sender's retransmission-pacing mode, re-exported for use with
/// [`Config::with_congestion_control`].
pub use rist_core::flow::CongestionMode;

/// The crate version (`CARGO_PKG_VERSION`), e.g. for an SDES tool tag or logging.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
