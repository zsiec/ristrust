//! The public media sender and the [`dial`] constructor.
//!
//! Scaffolding: [`dial`] validates the config and binds the local UDP socket
//! (connection setup is real); the media path ([`Sender::send`]) is wired in
//! Phase 2 (WP2), when the session event loop drives the flow core.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::config::Config;
use crate::error::Error;
use crate::runtime::{AsyncUdpSocket, Runtime, TokioRuntime};

/// An io-native RIST media sender. Created with [`dial`].
#[derive(Debug)]
pub struct Sender {
    cfg: Config,
    socket: Arc<dyn AsyncUdpSocket>,
    remote: SocketAddr,
}

impl Sender {
    /// The configuration this sender was created with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The bound local address.
    ///
    /// # Errors
    /// Returns the underlying socket error if the address cannot be read.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The remote receiver's address.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Submits one media payload for reliable transmission.
    ///
    /// # Errors
    /// Currently always returns [`Error::Unimplemented`] — the media path lands in
    /// Phase 2 (WP2).
    pub async fn send(&self, _payload: &[u8]) -> Result<(), Error> {
        Err(Error::Unimplemented(
            "Sender::send (media path lands in WP2)",
        ))
    }

    /// Closes the sender, releasing its socket and tasks.
    ///
    /// # Errors
    /// Never, in the current scaffold.
    pub async fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

/// Connects a RIST sender to `addr` (an `IP:port`).
///
/// Validates `cfg` and binds the local UDP socket. `rist://` URL parsing and the
/// media path land in Phase 2 (WP2).
///
/// # Errors
/// Returns [`Error::Config`] if the configuration is invalid, [`Error::InvalidAddr`]
/// if `addr` is not an `IP:port`, or [`Error::Io`] if the socket cannot be bound.
pub async fn dial(addr: &str, cfg: Config) -> Result<Sender, Error> {
    cfg.validate()?;
    let remote: SocketAddr = addr
        .parse()
        .map_err(|_| Error::InvalidAddr(addr.to_owned()))?;
    let unspecified = if remote.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let socket = TokioRuntime.bind(SocketAddr::new(unspecified, 0))?;
    tracing::debug!(%remote, "rist: sender socket bound (scaffold: media path is WP2)");
    Ok(Sender {
        cfg,
        socket,
        remote,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dial_binds_and_records_remote() {
        let sender = dial("127.0.0.1:5000", Config::default())
            .await
            .expect("dial loopback");
        assert_eq!(sender.remote_addr().port(), 5000);
        assert_ne!(sender.local_addr().expect("local").port(), 0);
        assert_eq!(sender.config().rtt_multiplier, 7);
    }

    #[tokio::test]
    async fn dial_rejects_invalid_address() {
        let err = dial("not-an-address", Config::default()).await.unwrap_err();
        assert!(matches!(err, Error::InvalidAddr(_)));
    }

    #[tokio::test]
    async fn send_is_unimplemented_for_now() {
        let sender = dial("127.0.0.1:5001", Config::default()).await.unwrap();
        assert!(matches!(
            sender.send(b"hello").await,
            Err(Error::Unimplemented(_))
        ));
    }
}
