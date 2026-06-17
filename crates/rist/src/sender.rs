//! The public media sender and the [`dial`] constructor.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::Error;
use crate::reassembler::MAX_REASSEMBLY_FRAGMENTS;
use crate::runtime::{Runtime, TokioRuntime};

/// The most fragments a single [`Sender::send`] may split into when Advanced-profile
/// fragmentation is enabled, so a payload up to `fragment_size` ×
/// `MAX_FRAGMENTS_PER_WRITE` bytes is accepted and a larger one is rejected. It
/// equals the peer reassembler's per-run cap, so a well-behaved sender can never
/// split a write into more fragments than the receiver will reassemble.
pub const MAX_FRAGMENTS_PER_WRITE: usize = MAX_REASSEMBLY_FRAGMENTS;

/// An io-native RIST media sender. Created with [`dial`]; reliably transmits
/// application payloads (Simple-profile RTP or Main-profile GRE), recovering loss
/// via ARQ driven by a background session task.
#[derive(Debug)]
pub struct Sender {
    cfg: Config,
    local: SocketAddr,
    remote: SocketAddr,
    app_in: mpsc::Sender<Bytes>,
    weight_cmd: Option<mpsc::Sender<(u8, u32)>>,
    flow_attr_cmd: Option<mpsc::Sender<Vec<u8>>>,
    oob_in: Option<mpsc::Sender<(u16, Vec<u8>)>>,
    oob_out: Option<mpsc::Receiver<(u16, Bytes)>>,
    close: crate::driver::CloseFlag,
    stats: crate::stats::StatsCell,
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
    /// Never; the result is for API symmetry (the address is resolved at dial).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    /// The remote receiver's media address.
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// The bound local media (even) port (ristgo `LocalPort`). Convenience over
    /// [`local_addr`](Self::local_addr) when only the port is needed.
    #[must_use]
    pub fn local_port(&self) -> u16 {
        self.local.port()
    }

    /// A snapshot of this sender's counters (the sender-half fields are populated;
    /// receiver-half fields are zero). Updated continuously by the session task.
    #[must_use]
    pub fn stats(&self) -> crate::Stats {
        self.stats.snapshot()
    }

    /// Changes the SMPTE 2022-7 load-share weight of bonded path `path` at runtime
    /// (`0` returns it to full duplication; `> 0` puts it in the weighted rotation).
    /// Takes effect from the next rotation round.
    ///
    /// # Errors
    /// Returns [`Error::Unimplemented`] on a non-bonded sender (only a `dial_bonded`
    /// / `dial_bonded_weighted` sender has per-path weights), or [`Error::Closed`] if
    /// the session has shut down.
    pub async fn set_weight(&self, path: usize, weight: u32) -> Result<(), Error> {
        let Some(cmd) = &self.weight_cmd else {
            return Err(Error::Unimplemented("set_weight requires a bonded sender"));
        };
        let index = u8::try_from(path).map_err(|_| Error::InvalidAddr(format!("path {path}")))?;
        cmd.send((index, weight)).await.map_err(|_| Error::Closed)
    }

    /// Sends one Advanced-profile flow attribute (TR-06-3 §5.3.7): an opaque,
    /// fire-and-forget control message (UTF-8 JSON by convention) the peer surfaces
    /// through its `Config::with_flow_attr_callback`. Held until the peer is known
    /// and (under EAP-SRP) authenticated, like media.
    ///
    /// # Errors
    /// Returns [`Error::FlowAttrUnsupported`] on a non-Advanced sender, or
    /// [`Error::Closed`] if the session has shut down.
    pub async fn write_flow_attribute(&self, json: &[u8]) -> Result<(), Error> {
        let Some(cmd) = &self.flow_attr_cmd else {
            return Err(Error::FlowAttrUnsupported);
        };
        cmd.send(json.to_vec())
            .await
            .map_err(|_| self.close.error())
    }

    /// Sends one out-of-band datagram alongside the media stream as an IPv4 GRE
    /// frame ([`OOB_PROTOCOL_IP`](crate::OOB_PROTOCOL_IP)) — the libRIST-interoperable
    /// out-of-band form. PSK-encrypted when a secret is configured; never ARQ-retried.
    ///
    /// # Errors
    /// As [`Sender::write_oob_typed`].
    pub async fn write_oob(&self, payload: &[u8]) -> Result<(), Error> {
        self.write_oob_typed(crate::OOB_PROTOCOL_IP, payload).await
    }

    /// Sends one out-of-band datagram under the GRE protocol type `proto` (an
    /// EtherType). Any non-reserved value tunnels an arbitrary protocol to a peer
    /// that dispatches on the type [`Receiver::read_oob`](crate::Receiver::read_oob)
    /// returns. Fire-and-forget; held until the peer is known/authenticated.
    ///
    /// # Errors
    /// Returns [`Error::OobUnsupported`] on a Simple-profile sender, [`Error::OobProtocol`]
    /// if `proto` is one RIST reserves for its own framing, or [`Error::Closed`] if the
    /// session has shut down.
    pub async fn write_oob_typed(&self, proto: u16, payload: &[u8]) -> Result<(), Error> {
        if rist_codec::gre::is_reserved(proto) {
            return Err(Error::OobProtocol(proto));
        }
        let Some(cmd) = &self.oob_in else {
            return Err(Error::OobUnsupported);
        };
        cmd.send((proto, payload.to_vec()))
            .await
            .map_err(|_| self.close.error())
    }

    /// Reads the next reverse out-of-band datagram's payload sent by the receiver
    /// (the protocol type is discarded; use [`Sender::read_oob_typed`] to keep it).
    ///
    /// # Errors
    /// As [`Sender::read_oob_typed`].
    pub async fn read_oob(&mut self) -> Result<Bytes, Error> {
        self.read_oob_typed().await.map(|(_, payload)| payload)
    }

    /// Reads the next reverse out-of-band datagram from the receiver as `(GRE
    /// protocol type, payload)`. OOB bypasses the flow core (no reordering or ARQ);
    /// it is delivered in arrival order, decrypted under the PSK when one is
    /// configured. The mirror of [`Receiver::write_oob`](crate::Receiver::write_oob).
    ///
    /// # Errors
    /// Returns [`Error::OobUnsupported`] on a Simple-profile or bonded sender, or
    /// [`Error::Closed`] when the session has shut down.
    pub async fn read_oob_typed(&mut self) -> Result<(u16, Bytes), Error> {
        let Some(rx) = self.oob_out.as_mut() else {
            return Err(Error::OobUnsupported);
        };
        rx.recv().await.ok_or(Error::Closed)
    }

    /// Submits one media payload for reliable transmission. Applies back-pressure
    /// when the session's send queue is full.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] if the session has shut down — or the more specific
    /// [`Error::SessionTimeout`] / [`Error::Auth`] when that was the cause. Returns
    /// [`Error::PayloadTooLarge`] when Advanced-profile fragmentation is enabled and
    /// the payload exceeds `fragment_size` × [`MAX_FRAGMENTS_PER_WRITE`].
    pub async fn send(&self, payload: &[u8]) -> Result<(), Error> {
        if self.cfg.fragment_size > 0 {
            let max = self.cfg.fragment_size * MAX_FRAGMENTS_PER_WRITE;
            if payload.len() > max {
                return Err(Error::PayloadTooLarge {
                    len: payload.len(),
                    max,
                });
            }
        }
        self.app_in
            .send(Bytes::copy_from_slice(payload))
            .await
            .map_err(|_| self.close.error())
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
    dial_with(addr, cfg, &TokioRuntime).await
}

/// Like [`dial`], but binds the transport sockets through `rt`. Lets a custom
/// [`Runtime`] (e.g. a loss-injecting one in tests, or an alternative async
/// runtime) provide the UDP sockets the session drives.
///
/// # Errors
/// As [`dial`].
pub async fn dial_with(addr: &str, cfg: Config, rt: &dyn Runtime) -> Result<Sender, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    let remote: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    // The Simple profile binds an even/odd pair, so its media port must be even;
    // the Main profile multiplexes onto a single port and accepts any.
    if cfg.profile == crate::config::Profile::Simple && !remote.port().is_multiple_of(2) {
        return Err(Error::InvalidAddr(format!(
            "media port {} must be even",
            remote.port()
        )));
    }
    let spawned = crate::session::build_sender(rt, &cfg, remote)?;
    tracing::debug!(target: crate::logging::SESSION, %remote, "rist: sender dialed");
    Ok(Sender {
        cfg,
        local: spawned.local,
        remote,
        app_in: spawned.app_in,
        weight_cmd: spawned.weight_cmd,
        flow_attr_cmd: spawned.flow_attr_cmd,
        oob_in: spawned.oob_in,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Connects a SMPTE 2022-7 bonded sender to every address in `addrs`, transmitting
/// the identical media (same sequence and source time) on all of them for full
/// redundancy. Each address is one Main-profile GRE path; a receiver merges the
/// copies. Bonding requires the Main profile (`cfg.profile == Profile::Main`).
///
/// # Errors
/// Returns [`Error::InvalidAddr`] if `addrs` is empty or an entry is not a valid
/// `IP:port` (a `rist://` URL's address part is accepted), [`Error::Config`] for an
/// invalid configuration, or [`Error::Io`] (which wraps the non-Main rejection) if
/// the sockets cannot be bound.
pub async fn dial_bonded(addrs: &[&str], cfg: Config) -> Result<Sender, Error> {
    dial_bonded_with(addrs, cfg, &TokioRuntime).await
}

/// Like [`dial_bonded`], but binds every path's transport socket through `rt`.
///
/// # Errors
/// As [`dial_bonded`].
pub async fn dial_bonded_with(
    addrs: &[&str],
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Sender, Error> {
    if addrs.is_empty() {
        return Err(Error::InvalidAddr(
            "bonded sender needs at least one address".into(),
        ));
    }
    cfg.validate()?;
    let remotes = resolve_bonded_addrs(addrs)?;
    // Uniform weight on every path (`cfg.weight`; 0 = full duplication).
    let peers: Vec<(SocketAddr, u32)> = remotes.iter().map(|&a| (a, cfg.weight)).collect();
    let spawned = crate::session::build_bonded_sender(rt, &cfg, &peers)?;
    tracing::debug!(target: crate::logging::BONDING, paths = peers.len(), "rist: bonded sender dialed");
    Ok(Sender {
        cfg,
        local: spawned.local,
        remote: peers[0].0,
        app_in: spawned.app_in,
        weight_cmd: spawned.weight_cmd,
        flow_attr_cmd: spawned.flow_attr_cmd,
        oob_in: spawned.oob_in,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Connects a SMPTE 2022-7 bonded sender with a per-path load-share `weight` on
/// each address: `0` duplicates the stream onto that path (full redundancy), `> 0`
/// puts it in the weighted load-share rotation (datagrams split across the weighted
/// paths in proportion to their weights). Duplicate and weighted paths compose.
/// Bonding requires the Main profile. The path index for [`Sender::set_weight`] is
/// the position in `peers`.
///
/// # Errors
/// As [`dial_bonded`].
pub async fn dial_bonded_weighted(peers: &[(&str, u32)], cfg: Config) -> Result<Sender, Error> {
    dial_bonded_weighted_with(peers, cfg, &TokioRuntime).await
}

/// Like [`dial_bonded_weighted`], but binds every path's transport socket through `rt`.
///
/// # Errors
/// As [`dial_bonded`].
pub async fn dial_bonded_weighted_with(
    peers: &[(&str, u32)],
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Sender, Error> {
    if peers.is_empty() {
        return Err(Error::InvalidAddr(
            "bonded sender needs at least one address".into(),
        ));
    }
    cfg.validate()?;
    let addrs: Vec<&str> = peers.iter().map(|&(a, _)| a).collect();
    let remotes = resolve_bonded_addrs(&addrs)?;
    let resolved: Vec<(SocketAddr, u32)> = remotes
        .iter()
        .zip(peers)
        .map(|(&addr, &(_, weight))| (addr, weight))
        .collect();
    let spawned = crate::session::build_bonded_sender(rt, &cfg, &resolved)?;
    tracing::debug!(
        target: crate::logging::BONDING,
        paths = resolved.len(),
        "rist: weighted bonded sender dialed"
    );
    Ok(Sender {
        cfg,
        local: spawned.local,
        remote: resolved[0].0,
        app_in: spawned.app_in,
        weight_cmd: spawned.weight_cmd,
        flow_attr_cmd: spawned.flow_attr_cmd,
        oob_in: spawned.oob_in,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Binds a reversed-role **listener-sender**: a media sender that listens on `addr`
/// (a bare `IP:port` or a `rist://` URL) and waits for a [`dial_receiver`](crate::dial_receiver) caller to
/// announce itself, then sends media to it. Media submitted via [`Sender::send`] is
/// held until the caller connects. Main profile only; PSK and EAP-SRP supported (the
/// listener-sender is the authenticatee).
///
/// # Errors
/// Returns [`Error::Url`]/[`Error::InvalidAddr`] for a bad address, [`Error::Config`]
/// for an invalid configuration, or [`Error::Io`] (wrapping the non-Main / EAP-SRP
/// rejection) if the profile is unsupported or the socket cannot be bound.
pub async fn listen_sender(addr: &str, cfg: Config) -> Result<Sender, Error> {
    listen_sender_with(addr, cfg, &TokioRuntime).await
}

/// Like [`listen_sender`], but binds the transport socket through `rt`.
///
/// # Errors
/// As [`listen_sender`].
pub async fn listen_sender_with(
    addr: &str,
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Sender, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    let local: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    let spawned = crate::session::build_listener_sender(rt, &cfg, local)?;
    tracing::debug!(target: crate::logging::SESSION, %local, "rist: listener-sender bound");
    Ok(Sender {
        cfg,
        local: spawned.local,
        // The peer is learned from the caller's announcement; unknown until then.
        remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        app_in: spawned.app_in,
        weight_cmd: spawned.weight_cmd,
        flow_attr_cmd: spawned.flow_attr_cmd,
        oob_in: spawned.oob_in,
        oob_out: spawned.oob_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Resolves each bonded address (a bare `IP:port` or a `rist://` URL whose address
/// part is taken; per-path query refinement is not applied — the shared `cfg`
/// governs every path) into a [`SocketAddr`].
pub(crate) fn resolve_bonded_addrs(addrs: &[&str]) -> Result<Vec<SocketAddr>, Error> {
    addrs
        .iter()
        .map(|a| {
            let addr = if a.contains("://") {
                crate::url::parse_url(a, Config::default())?.0
            } else {
                (*a).to_string()
            };
            addr.parse().map_err(|_| Error::InvalidAddr(addr))
        })
        .collect()
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
