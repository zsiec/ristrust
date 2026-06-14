#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod runtime;
pub mod url;

mod bonding;
mod driver;
mod peer;
mod receiver;
mod sender;
mod session;
mod socket;

pub use config::{Config, NackType, Profile};
pub use error::{ConfigError, Error};
pub use receiver::{Receiver, listen};
pub use runtime::{AsyncUdpSocket, Runtime, TokioRuntime};
pub use sender::{Sender, dial};
pub use url::parse_url;

/// The AES key size for PSK encryption, re-exported for use with
/// [`Config::with_aes_key_bits`].
pub use rist_codec::crypto::AesKeyBits;
