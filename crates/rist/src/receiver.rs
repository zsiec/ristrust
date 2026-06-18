//! The public media receiver and the [`listen`] constructor.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::config::{Config, NackType};
use crate::driver::RxControl;
use crate::error::{ConfigError, Error};
use crate::runtime::{Runtime, TokioRuntime};

/// One recovered media packet with its per-packet metadata, delivered by
/// [`Receiver::recv_block`] when [`Config::with_block_delivery`](crate::Config::with_block_delivery)
/// is enabled (libRIST's `rist_receiver_data_block`). Raw per-packet granularity: it
/// bypasses the split-merge recombination that `recv` applies.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DataBlock {
    /// The recovered media payload.
    pub payload: Bytes,
    /// The 32-bit (widened) sequence number of the packet.
    pub seq: u32,
    /// The sender's NTP-64 source timestamp (libRIST `ts_ntp`).
    pub source_time: u64,
    /// The RIST virtual source port decoded from the packet's reduced-overhead header.
    pub virt_src_port: u16,
    /// The RIST virtual destination port decoded from the packet's reduced-overhead
    /// header — the virtual-stream demux key.
    pub virt_dst_port: u16,
}

/// An io-native RIST media receiver. Created with [`listen`]; yields in-order,
/// ARQ-recovered media payloads from a background session task.
#[derive(Debug)]
pub struct Receiver {
    cfg: Config,
    local: SocketAddr,
    data_out: mpsc::Receiver<Bytes>,
    /// Per-packet block delivery channel ([`Config::with_block_delivery`]); `Some` makes
    /// [`recv_block`](Self::recv_block) the delivery path and `recv` unavailable.
    block_out: Option<mpsc::Receiver<crate::driver::MediaBlock>>,
    oob_out: Option<mpsc::Receiver<(u16, Bytes)>>,
    oob_in: Option<mpsc::Sender<(u16, Vec<u8>)>>,
    rx_ctrl: Option<mpsc::Sender<RxControl>>,
    peer_cmd: Option<mpsc::Sender<crate::driver_bonded::PeerCmd>>,
    close: crate::driver::CloseFlag,
    stats: crate::stats::StatsCell,
    task: tokio::task::JoinHandle<()>,
}

impl Receiver {
    /// Assembles a `Receiver` from its parts — used by [`listen`] and by the
    /// [`MultiReceiver`](crate::multi) to surface a demultiplexed per-flow receiver.
    #[allow(clippy::too_many_arguments)] // a constructor over the handle's parts
    pub(crate) fn from_parts(
        cfg: Config,
        local: SocketAddr,
        data_out: mpsc::Receiver<Bytes>,
        oob_out: Option<mpsc::Receiver<(u16, Bytes)>>,
        close: crate::driver::CloseFlag,
        stats: crate::stats::StatsCell,
        task: tokio::task::JoinHandle<()>,
    ) -> Receiver {
        Receiver {
            cfg,
            local,
            data_out,
            oob_out,
            // A demultiplexed per-flow receiver has no reverse-OOB send channel.
            oob_in: None,
            // …nor a runtime-control channel (its driver was injected): the runtime
            // setters return `Unimplemented` on it.
            rx_ctrl: None,
            peer_cmd: None,
            block_out: None,
            close,
            stats,
            task,
        }
    }

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

    /// The bound local media (even) port (ristgo `LocalPort`). Convenience over
    /// [`local_addr`](Self::local_addr) when only the port is needed — useful when
    /// the receiver was bound to port `0` and the OS chose the port.
    #[must_use]
    pub fn local_port(&self) -> u16 {
        self.local.port()
    }

    /// A snapshot of this receiver's counters (the receiver-half fields are
    /// populated; sender-half fields are zero). Updated continuously by the session
    /// task.
    #[must_use]
    pub fn stats(&self) -> crate::Stats {
        self.stats.snapshot()
    }

    /// Whether the session is authenticated: `true` once the Main/Advanced EAP-SRP
    /// handshake has completed, or immediately for a session with no authentication
    /// configured (no credentials, or the Simple profile). Updated by the session task.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.stats.authenticated()
    }

    /// The media SSRC learned from the first received packet, or `0` until one has
    /// arrived (ristgo `Receiver.SSRC`). For a bonded receiver it is the single merged
    /// stream's SSRC.
    #[must_use]
    pub fn ssrc(&self) -> u32 {
        self.stats.ssrc()
    }

    /// Switches the NACK feedback format at runtime (libRIST `rist_receiver_nack_type_set`):
    /// [`NackType::Range`] (the libRIST default) or [`NackType::Bitmask`]. Takes effect
    /// from the next NACK the receiver emits; the choice is local — a libRIST or ristrust
    /// sender decodes either format regardless.
    ///
    /// # Errors
    /// Returns [`Error::Unimplemented`] on a demultiplexed per-flow receiver from a
    /// [`MultiReceiver`](crate::MultiReceiver) (which has no control channel), or
    /// [`Error::Closed`] if the session has shut down.
    pub async fn set_nack_type(&self, nack_type: NackType) -> Result<(), Error> {
        let Some(cmd) = &self.rx_ctrl else {
            return Err(Error::Unimplemented(
                "set_nack_type requires a single-flow receiver",
            ));
        };
        let bitmask = matches!(nack_type, NackType::Bitmask);
        cmd.send(RxControl::NackBitmask(bitmask))
            .await
            .map_err(|_| self.close.error())
    }

    /// Sets the recovery-buffer RTT multiplier at runtime (libRIST
    /// `rist_recovery_rtt_multiplier_set`): the factor by which the auto-scaling
    /// recovery buffer grows relative to the smoothed RTT. Effective only when the
    /// buffer is windowed (`buffer_min != buffer_max`) and the sender has advertised its
    /// retained buffer; it then takes effect on the next recalculation cycle (~1 s).
    /// `multiplier` must be in `1..=100` (the same range [`Config`] validates).
    ///
    /// # Errors
    /// Returns [`Error::Config`] if `multiplier` is out of range, [`Error::Unimplemented`]
    /// on a demultiplexed per-flow receiver, or [`Error::Closed`] if the session has
    /// shut down.
    pub async fn set_rtt_multiplier(&self, multiplier: u32) -> Result<(), Error> {
        if !(1..=100).contains(&multiplier) {
            return Err(Error::Config(ConfigError::RttMultiplierOutOfRange {
                value: multiplier,
            }));
        }
        let Some(cmd) = &self.rx_ctrl else {
            return Err(Error::Unimplemented(
                "set_rtt_multiplier requires a single-flow receiver",
            ));
        };
        cmd.send(RxControl::RttMultiplier(multiplier))
            .await
            .map_err(|_| self.close.error())
    }

    /// Adds a bonded input path at runtime (libRIST `rist_peer_create`): the receiver
    /// binds `local` (a bare `IP:port`) as a new path at `index`, recovering and merging
    /// its media into the same flow. The caller owns the index space (the construction
    /// paths are `0..N`, so a fresh path uses an unused index `>= N`); a duplicate index
    /// is ignored. Available only on a bonded receiver built with the default runtime
    /// ([`listen_bonded`] / [`listen_bonded_priority`]) — a custom-runtime receiver
    /// cannot bind a socket at runtime. The added path binds unicast (no multicast group).
    ///
    /// # Errors
    /// Returns [`Error::Unimplemented`] on a non-bonded, Simple-bonded, or custom-runtime
    /// receiver, [`Error::InvalidAddr`] if `local`/`index` is invalid, or [`Error::Closed`]
    /// if the session has shut down.
    pub async fn add_path(&self, index: usize, local: &str, weight: u32) -> Result<(), Error> {
        let Some(cmd) = &self.peer_cmd else {
            return Err(Error::Unimplemented(
                "add_path requires a default-runtime Main/Advanced bonded receiver",
            ));
        };
        let index = u8::try_from(index).map_err(|_| Error::InvalidAddr(format!("path {index}")))?;
        let local: SocketAddr = local
            .parse()
            .map_err(|_| Error::InvalidAddr(local.to_string()))?;
        cmd.send(crate::driver_bonded::PeerCmd::Add {
            index,
            addr: local,
            weight,
            priority: 0,
        })
        .await
        .map_err(|_| self.close.error())
    }

    /// Removes a bonded input path at runtime (libRIST `rist_peer_destroy`): the receiver
    /// stops reading `index`'s socket and drops it from the merge and per-peer stats. An
    /// unknown index is a no-op. Same availability as [`add_path`](Self::add_path).
    ///
    /// # Errors
    /// Returns [`Error::Unimplemented`] on a non-bonded, Simple-bonded, or custom-runtime
    /// receiver, [`Error::InvalidAddr`] if `index` is out of range, or [`Error::Closed`]
    /// if the session has shut down.
    pub async fn remove_path(&self, index: usize) -> Result<(), Error> {
        let Some(cmd) = &self.peer_cmd else {
            return Err(Error::Unimplemented(
                "remove_path requires a default-runtime Main/Advanced bonded receiver",
            ));
        };
        let index = u8::try_from(index).map_err(|_| Error::InvalidAddr(format!("path {index}")))?;
        cmd.send(crate::driver_bonded::PeerCmd::Remove { index })
            .await
            .map_err(|_| self.close.error())
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

    /// Sends one reverse out-of-band datagram back to the sender as an IPv4 GRE frame
    /// ([`OOB_PROTOCOL_IP`](crate::OOB_PROTOCOL_IP)) — the mirror of
    /// [`Sender::write_oob`](crate::Sender::write_oob). PSK-encrypted when a secret is
    /// configured; never ARQ-retried; dropped until the sender's address is known.
    ///
    /// # Errors
    /// As [`Receiver::write_oob_typed`].
    pub async fn write_oob(&self, payload: &[u8]) -> Result<(), Error> {
        self.write_oob_typed(crate::OOB_PROTOCOL_IP, payload).await
    }

    /// Sends one reverse out-of-band datagram to the sender under the GRE protocol
    /// type `proto` (an EtherType). Fire-and-forget; the receive-side counterpart of
    /// [`Sender::write_oob_typed`](crate::Sender::write_oob_typed).
    ///
    /// # Errors
    /// Returns [`Error::OobUnsupported`] on a Simple-profile or bonded receiver,
    /// [`Error::OobProtocol`] if `proto` is one RIST reserves for its own framing, or
    /// [`Error::Closed`] if the session has shut down.
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

    /// Reads the next in-order, ARQ-recovered media payload.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] when the session has shut down and no further data
    /// will arrive — or the more specific [`Error::SessionTimeout`] / [`Error::Auth`]
    /// when peer silence or a failed handshake was the cause. Returns
    /// [`Error::Unimplemented`] on a block-delivery receiver
    /// ([`Config::with_block_delivery`](crate::Config::with_block_delivery)) — use
    /// [`recv_block`](Self::recv_block) there.
    pub async fn recv(&mut self) -> Result<Bytes, Error> {
        if self.block_out.is_some() {
            return Err(Error::Unimplemented(
                "recv is unavailable on a block-delivery receiver; use recv_block",
            ));
        }
        self.data_out.recv().await.ok_or_else(|| self.close.error())
    }

    /// Reads the next recovered packet as a [`DataBlock`] with its per-packet metadata —
    /// sequence, source timestamp, and decoded virtual ports (libRIST
    /// `rist_receiver_data_block`). Delivery is at raw per-packet granularity (no
    /// split-merge recombination). Requires
    /// [`Config::with_block_delivery`](crate::Config::with_block_delivery).
    ///
    /// # Errors
    /// Returns [`Error::Unimplemented`] unless the receiver was built with block delivery,
    /// or [`Error::Closed`] (or [`Error::SessionTimeout`] / [`Error::Auth`]) once the
    /// session has shut down.
    pub async fn recv_block(&mut self) -> Result<DataBlock, Error> {
        let Some(rx) = self.block_out.as_mut() else {
            return Err(Error::Unimplemented(
                "recv_block requires Config::with_block_delivery on a Main receiver",
            ));
        };
        let b = rx.recv().await.ok_or_else(|| self.close.error())?;
        Ok(DataBlock {
            payload: b.payload,
            seq: b.seq,
            source_time: b.source_time,
            virt_src_port: b.virt_src_port,
            virt_dst_port: b.virt_dst_port,
        })
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
    tracing::debug!(target: crate::logging::SESSION, %local, "rist: receiver listening");
    Ok(Receiver {
        cfg,
        local: spawned.local,
        data_out: spawned.data_out,
        oob_out: spawned.oob_out,
        oob_in: spawned.oob_in,
        rx_ctrl: spawned.rx_ctrl,
        peer_cmd: spawned.peer_cmd,
        block_out: spawned.block_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    })
}

/// Dials a reversed-role **caller-receiver**: a media receiver that calls out to a
/// [`listen_sender`](crate::listen_sender) listening at `addr` (a bare `IP:port` or `rist://` URL),
/// announces itself so the sender learns where to send, then receives media. Main and
/// Advanced profiles; PSK and EAP-SRP supported (the caller-receiver is the authenticator).
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
    tracing::debug!(target: crate::logging::SESSION, %remote, "rist: caller-receiver dialed");
    Ok(Receiver {
        cfg,
        local: spawned.local,
        data_out: spawned.data_out,
        oob_out: spawned.oob_out,
        oob_in: spawned.oob_in,
        rx_ctrl: spawned.rx_ctrl,
        peer_cmd: spawned.peer_cmd,
        block_out: spawned.block_out,
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
    // The default runtime is owned (an `Arc<TokioRuntime>`), so the bonded receiver can
    // bind a new path's socket at runtime — `Receiver::add_path` is available. The
    // borrowed-`&dyn Runtime` form (`listen_bonded_with`) cannot, so it has no runtime add.
    if addrs.is_empty() {
        return Err(Error::InvalidAddr(
            "bonded receiver needs at least one address".into(),
        ));
    }
    cfg.validate()?;
    let locals = crate::sender::resolve_bonded_addrs(addrs)?;
    let rt: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let spawned = crate::session::build_bonded_receiver(
        rt.as_ref(),
        &cfg,
        &locals,
        &[],
        Some(Arc::clone(&rt)),
    )?;
    tracing::debug!(target: crate::logging::BONDING, paths = locals.len(), "rist: bonded receiver listening");
    Ok(bonded_receiver(cfg, spawned))
}

/// Like [`listen_bonded`], but binds every path's transport socket through `rt`. A
/// custom runtime cannot be owned by the driver, so runtime [`Receiver::add_path`] is
/// not available on a receiver built this way.
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
    let spawned = crate::session::build_bonded_receiver(rt, &cfg, &locals, &[], None)?;
    tracing::debug!(target: crate::logging::BONDING, paths = locals.len(), "rist: bonded receiver listening");
    Ok(bonded_receiver(cfg, spawned))
}

/// Assembles a bonded `Receiver` from its spawned parts (shared by the bonded-listen
/// constructors).
fn bonded_receiver(cfg: Config, spawned: crate::session::ReceiverSpawned) -> Receiver {
    Receiver {
        cfg,
        local: spawned.local,
        data_out: spawned.data_out,
        oob_out: spawned.oob_out,
        oob_in: spawned.oob_in,
        rx_ctrl: spawned.rx_ctrl,
        peer_cmd: spawned.peer_cmd,
        block_out: spawned.block_out,
        close: spawned.close,
        stats: spawned.stats,
        task: spawned.task,
    }
}

/// Listens as a SMPTE 2022-7 bonded receiver with a per-path NACK-recovery
/// `priority` on each address (libRIST `recovery-priority`): when the receiver must
/// send a NACK it routes it to the highest-priority live, addressable path (ties
/// broken by the lowest raw RTT). Use it to steer retransmission requests toward the
/// link whose sender holds the recovery buffer on an asymmetric multipath. `0` (what
/// [`listen_bonded`] uses) leaves selection to the RTT tie-break. Bonding requires the
/// Main profile; the path index is the position in `peers`.
///
/// # Errors
/// As [`listen_bonded`].
pub async fn listen_bonded_priority(peers: &[(&str, u32)], cfg: Config) -> Result<Receiver, Error> {
    if peers.is_empty() {
        return Err(Error::InvalidAddr(
            "bonded receiver needs at least one address".into(),
        ));
    }
    cfg.validate()?;
    let addrs: Vec<&str> = peers.iter().map(|&(a, _)| a).collect();
    let priorities: Vec<u32> = peers.iter().map(|&(_, p)| p).collect();
    let locals = crate::sender::resolve_bonded_addrs(&addrs)?;
    // Owned default runtime → runtime add available (see `listen_bonded`).
    let rt: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let spawned = crate::session::build_bonded_receiver(
        rt.as_ref(),
        &cfg,
        &locals,
        &priorities,
        Some(Arc::clone(&rt)),
    )?;
    tracing::debug!(target: crate::logging::BONDING, paths = locals.len(), "rist: bonded receiver listening (per-path priority)");
    Ok(bonded_receiver(cfg, spawned))
}

/// Like [`listen_bonded_priority`], but binds every path's transport socket through
/// `rt`. Runtime [`Receiver::add_path`] is not available on a receiver built this way
/// (the borrowed runtime cannot be owned by the driver).
///
/// # Errors
/// As [`listen_bonded`].
pub async fn listen_bonded_priority_with(
    peers: &[(&str, u32)],
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Receiver, Error> {
    if peers.is_empty() {
        return Err(Error::InvalidAddr(
            "bonded receiver needs at least one address".into(),
        ));
    }
    cfg.validate()?;
    let addrs: Vec<&str> = peers.iter().map(|&(a, _)| a).collect();
    let priorities: Vec<u32> = peers.iter().map(|&(_, p)| p).collect();
    let locals = crate::sender::resolve_bonded_addrs(&addrs)?;
    let spawned = crate::session::build_bonded_receiver(rt, &cfg, &locals, &priorities, None)?;
    tracing::debug!(target: crate::logging::BONDING, paths = locals.len(), "rist: bonded receiver listening (per-path priority)");
    Ok(bonded_receiver(cfg, spawned))
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
