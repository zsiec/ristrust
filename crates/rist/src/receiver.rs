//! The public media receiver and the [`listen`] constructor.

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::Error;
use crate::runtime::TokioRuntime;
use crate::socket::SimpleSocket;

/// An io-native RIST media receiver. Created with [`listen`]; yields in-order,
/// ARQ-recovered media payloads from a background session task.
#[derive(Debug)]
pub struct Receiver {
    cfg: Config,
    socket: SimpleSocket,
    data_out: mpsc::Receiver<Bytes>,
    task: tokio::task::JoinHandle<()>,
}

impl Receiver {
    /// The configuration this receiver was created with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The bound local media address.
    ///
    /// # Errors
    /// Returns the underlying socket error if the address cannot be read.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.media_local()
    }

    /// Reads the next in-order, ARQ-recovered media payload.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] when the session has shut down (peer timeout or
    /// the driver exiting) and no further data will arrive.
    pub async fn recv(&mut self) -> Result<Bytes, Error> {
        self.data_out.recv().await.ok_or(Error::Closed)
    }

    /// Closes the receiver, stopping its background task and releasing its sockets.
    ///
    /// # Errors
    /// Never; the result is for API symmetry and forward compatibility.
    pub async fn close(self) -> Result<(), Error> {
        self.task.abort();
        Ok(())
    }
}

/// Binds a RIST receiver to `addr`. `addr` may be a bare `IP:port` (an even media
/// port; RTCP binds the adjacent odd port) or a `rist://` URL whose query
/// parameters refine `cfg`.
///
/// # Errors
/// Returns [`Error::Url`] for a malformed URL, [`Error::Config`] for an invalid
/// configuration, [`Error::InvalidAddr`] if `addr` is not an `IP:port`, or
/// [`Error::Io`] if the port is not a positive even number or the sockets cannot
/// be bound.
pub async fn listen(addr: &str, cfg: Config) -> Result<Receiver, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    let local: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    let spawned = crate::session::build_receiver(&TokioRuntime, &cfg, local)?;
    tracing::debug!(%local, "rist: receiver listening");
    Ok(Receiver {
        cfg,
        socket: spawned.socket,
        data_out: spawned.data_out,
        task: spawned.task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listen_binds_an_even_port_pair() {
        let receiver = listen("127.0.0.1:5002", Config::default())
            .await
            .expect("listen loopback");
        assert_eq!(receiver.local_addr().expect("local").port(), 5002);
        receiver.close().await.unwrap();
    }

    #[tokio::test]
    async fn listen_rejects_odd_port() {
        let err = listen("127.0.0.1:5003", Config::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
