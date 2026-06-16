//! The public media receiver and the [`listen`] constructor.

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::Error;
use crate::runtime::{Runtime, TokioRuntime};

/// An io-native RIST media receiver. Created with [`listen`]; yields in-order,
/// ARQ-recovered media payloads from a background session task.
#[derive(Debug)]
pub struct Receiver {
    cfg: Config,
    local: SocketAddr,
    data_out: mpsc::Receiver<Bytes>,
    oob_out: Option<mpsc::Receiver<(u16, Bytes)>>,
    close: crate::driver::CloseFlag,
    stats: crate::stats::StatsCell,
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
    /// Never; the result is for API symmetry (the address is resolved at listen).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    /// A snapshot of this receiver's counters (the receiver-half fields are
    /// populated; sender-half fields are zero). Updated continuously by the session
    /// task.
    #[must_use]
    pub fn stats(&self) -> crate::Stats {
        self.stats.snapshot()
    }

    /// Reads the next out-of-band datagram's payload (the protocol type is
    /// discarded; use [`Receiver::read_oob_typed`] to keep it).
    ///
    /// # Errors
    /// As [`Receiver::read_oob_typed`].
    pub async fn read_oob(&mut self) -> Result<Bytes, Error> {
        self.read_oob_typed().await.map(|(_, payload)| payload)
    }

    /// Reads the next out-of-band datagram as `(GRE protocol type, payload)`. OOB
    /// bypasses the flow core (no reordering or ARQ); it is delivered in arrival
    /// order, decrypted under the PSK when one is configured.
    ///
    /// # Errors
    /// Returns [`Error::OobUnsupported`] on a Simple-profile receiver, or
    /// [`Error::Closed`] when the session has shut down.
    pub async fn read_oob_typed(&mut self) -> Result<(u16, Bytes), Error> {
        let Some(rx) = self.oob_out.as_mut() else {
            return Err(Error::OobUnsupported);
        };
        rx.recv().await.ok_or(Error::Closed)
    }

    /// Reads the next in-order, ARQ-recovered media payload.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] when the session has shut down and no further data
    /// will arrive — or the more specific [`Error::SessionTimeout`] / [`Error::Auth`]
    /// when peer silence or a failed handshake was the cause.
    pub async fn recv(&mut self) -> Result<Bytes, Error> {
        self.data_out.recv().await.ok_or_else(|| self.close.error())
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
    listen_with(addr, cfg, &TokioRuntime).await
}

/// Like [`listen`], but binds the transport sockets through `rt`. Lets a custom
/// [`Runtime`] provide the UDP sockets the session drives.
///
/// # Errors
/// As [`listen`].
pub async fn listen_with(addr: &str, cfg: Config, rt: &dyn Runtime) -> Result<Receiver, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    let local: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    let spawned = crate::session::build_receiver(rt, &cfg, local)?;
    tracing::debug!(%local, "rist: receiver listening");
    Ok(Receiver {
        cfg,
        local: spawned.local,
        data_out: spawned.data_out,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Dials a reversed-role **caller-receiver**: a media receiver that calls out to a
/// [`listen_sender`](crate::listen_sender) listening at `addr` (a bare `IP:port` or `rist://` URL),
/// announces itself so the sender learns where to send, then receives media. Main
/// profile only; PSK supported, EAP-SRP refused.
///
/// # Errors
/// Returns [`Error::Url`]/[`Error::InvalidAddr`] for a bad address, [`Error::Config`]
/// for an invalid configuration, or [`Error::Io`] (wrapping the non-Main / EAP-SRP
/// rejection) if the profile is unsupported or the socket cannot be bound.
pub async fn dial_receiver(addr: &str, cfg: Config) -> Result<Receiver, Error> {
    dial_receiver_with(addr, cfg, &TokioRuntime).await
}

/// Like [`dial_receiver`], but binds the transport socket through `rt`.
///
/// # Errors
/// As [`dial_receiver`].
pub async fn dial_receiver_with(
    addr: &str,
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Receiver, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    let remote: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    let spawned = crate::session::build_caller_receiver(rt, &cfg, remote)?;
    tracing::debug!(%remote, "rist: caller-receiver dialed");
    Ok(Receiver {
        cfg,
        local: spawned.local,
        data_out: spawned.data_out,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Binds a SMPTE 2022-7 bonded receiver to every address in `addrs`, merging the
/// media that arrives on each into one in-order, ARQ-recovered stream (the
/// `(seq, source_time)` dedup is the merge). Each address is one Main-profile GRE
/// path; `local_addr` reports the first. Bonding requires the Main profile.
///
/// # Errors
/// Returns [`Error::InvalidAddr`] if `addrs` is empty or an entry is not a valid
/// `IP:port`, [`Error::Config`] for an invalid configuration, or [`Error::Io`]
/// (which wraps the non-Main rejection) if a port is invalid or the sockets cannot
/// be bound.
pub async fn listen_bonded(addrs: &[&str], cfg: Config) -> Result<Receiver, Error> {
    listen_bonded_with(addrs, cfg, &TokioRuntime).await
}

/// Like [`listen_bonded`], but binds every path's transport socket through `rt`.
///
/// # Errors
/// As [`listen_bonded`].
pub async fn listen_bonded_with(
    addrs: &[&str],
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Receiver, Error> {
    if addrs.is_empty() {
        return Err(Error::InvalidAddr(
            "bonded receiver needs at least one address".into(),
        ));
    }
    cfg.validate()?;
    let locals = crate::sender::resolve_bonded_addrs(addrs)?;
    let spawned = crate::session::build_bonded_receiver(rt, &cfg, &locals)?;
    tracing::debug!(paths = locals.len(), "rist: bonded receiver listening");
    Ok(Receiver {
        cfg,
        local: spawned.local,
        data_out: spawned.data_out,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
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
