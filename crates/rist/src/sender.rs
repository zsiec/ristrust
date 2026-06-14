//! The public media sender and the [`dial`] constructor.

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::Error;
use crate::runtime::TokioRuntime;
use crate::socket::SimpleSocket;

/// An io-native RIST media sender. Created with [`dial`]; reliably transmits
/// application payloads as Simple-profile RTP, recovering loss via ARQ driven by
/// a background session task.
#[derive(Debug)]
pub struct Sender {
    cfg: Config,
    socket: SimpleSocket,
    remote: SocketAddr,
    app_in: mpsc::Sender<Bytes>,
    task: tokio::task::JoinHandle<()>,
}

impl Sender {
    /// The configuration this sender was created with.
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

    /// The remote receiver's media address.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Submits one media payload for reliable transmission. Applies back-pressure
    /// when the session's send queue is full.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] if the session has shut down.
    pub async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        self.app_in
            .send(Bytes::copy_from_slice(payload))
            .await
            .map_err(|_| Error::Closed)
    }

    /// Closes the sender, stopping its background task and releasing its sockets.
    ///
    /// # Errors
    /// Never; the result is for API symmetry and forward compatibility.
    pub async fn close(self) -> Result<(), Error> {
        drop(self.app_in); // signal the driver to drain and exit
        self.task.abort();
        Ok(())
    }
}

/// Connects a RIST sender to `addr`. `addr` may be a bare `IP:port` (the
/// receiver's even media port) or a `rist://` URL whose query parameters refine
/// `cfg`.
///
/// # Errors
/// Returns [`Error::Url`] for a malformed URL, [`Error::Config`] for an invalid
/// configuration, [`Error::InvalidAddr`] if `addr` is not an `IP:port` or its
/// media port is not even, or [`Error::Io`] if the sockets cannot be bound.
pub async fn dial(addr: &str, cfg: Config) -> Result<Sender, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    let remote: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    if !remote.port().is_multiple_of(2) {
        return Err(Error::InvalidAddr(format!(
            "media port {} must be even",
            remote.port()
        )));
    }
    let spawned = crate::session::build_sender(&TokioRuntime, &cfg, remote)?;
    tracing::debug!(%remote, "rist: sender dialed");
    Ok(Sender {
        cfg,
        socket: spawned.socket,
        remote,
        app_in: spawned.app_in,
        task: spawned.task,
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
        sender.close().await.unwrap();
    }

    #[tokio::test]
    async fn dial_rejects_invalid_address() {
        let err = dial("not-an-address", Config::default()).await.unwrap_err();
        assert!(matches!(err, Error::InvalidAddr(_)));
    }

    #[tokio::test]
    async fn dial_rejects_odd_media_port() {
        let err = dial("127.0.0.1:5001", Config::default()).await.unwrap_err();
        assert!(matches!(err, Error::InvalidAddr(_)));
    }

    #[tokio::test]
    async fn dial_accepts_rist_url_with_params() {
        let sender = dial("rist://127.0.0.1:5000?buffer=500", Config::default())
            .await
            .expect("dial rist url");
        assert_eq!(sender.config().buffer_min.as_millis(), 500);
        sender.close().await.unwrap();
    }
}
