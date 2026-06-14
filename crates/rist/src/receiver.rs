//! The public media receiver and the [`listen`] constructor.
//!
//! Scaffolding: [`listen`] validates the config and binds the local UDP socket;
//! the in-order, ARQ-recovered read path ([`Receiver::recv`]) is wired in Phase 2
//! (WP2).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;

use crate::config::Config;
use crate::error::Error;
use crate::runtime::{AsyncUdpSocket, Runtime, TokioRuntime};

/// An io-native RIST media receiver. Created with [`listen`].
#[derive(Debug)]
pub struct Receiver {
    cfg: Config,
    socket: Arc<dyn AsyncUdpSocket>,
}

impl Receiver {
    /// The configuration this receiver was created with.
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

    /// Reads the next in-order, ARQ-recovered media payload.
    ///
    /// # Errors
    /// Currently always returns [`Error::Unimplemented`] — the read path lands in
    /// Phase 2 (WP2).
    pub async fn recv(&self) -> Result<Bytes, Error> {
        Err(Error::Unimplemented(
            "Receiver::recv (read path lands in WP2)",
        ))
    }

    /// Closes the receiver, releasing its socket and tasks.
    ///
    /// # Errors
    /// Never, in the current scaffold.
    pub async fn close(self) -> Result<(), Error> {
        Ok(())
    }
}

/// Binds a RIST receiver to `addr` (an `IP:port`).
///
/// Validates `cfg` and binds the local UDP socket. `rist://` URL parsing and the
/// read path land in Phase 2 (WP2).
///
/// # Errors
/// Returns [`Error::Config`] if the configuration is invalid, [`Error::InvalidAddr`]
/// if `addr` is not an `IP:port`, or [`Error::Io`] if the socket cannot be bound.
pub async fn listen(addr: &str, cfg: Config) -> Result<Receiver, Error> {
    cfg.validate()?;
    let local: SocketAddr = addr
        .parse()
        .map_err(|_| Error::InvalidAddr(addr.to_owned()))?;
    let socket = TokioRuntime.bind(local)?;
    tracing::debug!(%local, "rist: receiver socket bound (scaffold: read path is WP2)");
    Ok(Receiver { cfg, socket })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listen_binds_the_requested_port() {
        let receiver = listen("127.0.0.1:0", Config::default())
            .await
            .expect("listen loopback");
        assert_ne!(receiver.local_addr().expect("local").port(), 0);
    }

    #[tokio::test]
    async fn recv_is_unimplemented_for_now() {
        let receiver = listen("127.0.0.1:0", Config::default()).await.unwrap();
        assert!(matches!(
            receiver.recv().await,
            Err(Error::Unimplemented(_))
        ));
    }
}
