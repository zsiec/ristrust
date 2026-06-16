//! Receiver-side stream multiplexing: one bound socket demultiplexed into N
//! independent media flows (libRIST's per-flow receiver model). Ported from ristgo
//! `internal/session/multi.go`.
//!
//! A [`MultiReceiver`] owns the socket read, decides which flow each datagram belongs
//! to, and feeds the matching per-flow **injected** [`Driver`](crate::driver::Driver)
//! — the injected-feed seam from WP19a. Each flow owns its own recovery, timers, and
//! feedback (written back out the shared socket to its own learned peer); new flows
//! surface via [`MultiReceiver::accept`]. The Simple profile keys by the cleartext RTP
//! SSRC; the single-socket profiles (Main/Advanced) key by source address (added in a
//! later sub-phase).

use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::mpsc;

use rist_codec::rtp;

use crate::config::{Config, Profile};
use crate::driver::SimpleInbound;
use crate::error::{ConfigError, Error};
use crate::receiver::Receiver;
use crate::runtime::{Runtime, TokioRuntime};
use crate::socket::SimpleSocket;

/// Caps the number of concurrent demultiplexed flows (libRIST `RIST_MAX_FLOWS`), so a
/// burst of datagrams with spurious SSRCs cannot open unbounded sessions.
pub const MAX_FLOWS: usize = 256;

/// The largest datagram the demultiplexer will read.
const RECV_BUF: usize = 65_536;

/// Demultiplexes the media flows arriving on one bound socket into independent
/// receiver sessions, surfaced via [`MultiReceiver::accept`]. The receiver-side of
/// RIST stream multiplexing: one listen port, many senders, one [`Receiver`] each.
#[derive(Debug)]
pub struct MultiReceiver {
    accept_rx: mpsc::Receiver<Receiver>,
    demux: tokio::task::JoinHandle<()>,
    local: SocketAddr,
}

impl MultiReceiver {
    /// Returns the next newly-seen flow as its own [`Receiver`], blocking until one
    /// appears.
    ///
    /// # Errors
    /// Returns [`Error::Closed`] once the multi-receiver is closed (its demultiplexer
    /// stopped — e.g. a socket error or [`MultiReceiver::close`]).
    pub async fn accept(&mut self) -> Result<Receiver, Error> {
        self.accept_rx.recv().await.ok_or(Error::Closed)
    }

    /// The bound local media address (the listen port every sender targets).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Stops demultiplexing and tears down every flow (each flow's inbound feed dies,
    /// so its session ends and its [`Receiver`] sees [`Error::Closed`]).
    ///
    /// # Errors
    /// Never; the result is for API symmetry.
    pub async fn close(self) -> Result<(), Error> {
        self.demux.abort();
        Ok(())
    }
}

impl Drop for MultiReceiver {
    fn drop(&mut self) {
        // Dropping the multi-receiver stops the demultiplexer, which closes every
        // flow's inbound channel and so ends every per-flow session.
        self.demux.abort();
    }
}

/// Binds a multiplexing RIST receiver to `addr` (a bare `IP:port` or `rist://` URL):
/// one Simple-profile listen port demultiplexed by RTP SSRC into a [`Receiver`] per
/// distinct media stream, surfaced via [`MultiReceiver::accept`].
///
/// # Errors
/// Returns [`Error::Url`]/[`Error::InvalidAddr`] for a bad address, [`Error::Config`]
/// for an invalid configuration (including FEC, which conflicts with SSRC demux),
/// [`Error::Unimplemented`] for a non-Simple profile, or [`Error::Io`] if the port is
/// not a positive even number or the sockets cannot be bound.
pub async fn listen_multi(addr: &str, cfg: Config) -> Result<MultiReceiver, Error> {
    listen_multi_with(addr, cfg, &TokioRuntime).await
}

/// Like [`listen_multi`], but binds the shared transport through `rt`.
///
/// # Errors
/// As [`listen_multi`].
pub async fn listen_multi_with(
    addr: &str,
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<MultiReceiver, Error> {
    let (addr, cfg) = if addr.contains("://") {
        crate::url::parse_url(addr, cfg)?
    } else {
        (addr.to_string(), cfg)
    };
    cfg.validate()?;
    // Multi-flow demuxes the Simple profile by the cleartext RTP SSRC. The
    // single-socket profiles (keyed by source address) land in a later sub-phase.
    if cfg.profile != Profile::Simple {
        return Err(Error::Unimplemented(
            "multi-flow receive currently supports the Simple profile",
        ));
    }
    // Separate-port FEC and SSRC demux conflict: FEC is one auxiliary stream on fixed
    // ports, not per-flow, so it cannot be routed to a specific flow.
    if cfg.fec.is_some() {
        return Err(Error::Config(ConfigError::FecInvalid {
            reason: "FEC is not supported with multi-flow receive",
        }));
    }
    let local: SocketAddr = addr.parse().map_err(|_| Error::InvalidAddr(addr.clone()))?;
    let membership = crate::multicast::receiver_membership(&cfg, local)?;
    let socket = SimpleSocket::listen(rt, local, membership.as_ref())?;
    let bound = socket.media_local()?;
    let (accept_tx, accept_rx) = mpsc::channel(MAX_FLOWS);
    let demux = tokio::spawn(demux_simple(socket, cfg, bound, accept_tx));
    tracing::debug!(%bound, "rist: multi-receiver listening");
    Ok(MultiReceiver {
        accept_rx,
        demux,
        local: bound,
    })
}

/// The demultiplexer task: reads the shared media (even) and RTCP (odd) sockets,
/// keys each datagram by RTP SSRC, and feeds the matching per-flow injected session,
/// creating it on first sight.
async fn demux_simple(
    socket: SimpleSocket,
    cfg: Config,
    local: SocketAddr,
    accept_tx: mpsc::Sender<Receiver>,
) {
    let mut flows: HashMap<u32, mpsc::Sender<SimpleInbound>> = HashMap::new();
    let mut media_buf = vec![0u8; RECV_BUF];
    let mut rtcp_buf = vec![0u8; RECV_BUF];
    loop {
        tokio::select! {
            r = socket.recv_media(&mut media_buf) => match r {
                Ok((n, src)) => {
                    if let Some(ssrc) = peek_media_ssrc(&media_buf[..n]) {
                        let inb = SimpleInbound::Media { data: Bytes::copy_from_slice(&media_buf[..n]), src };
                        route(&mut flows, &socket, &cfg, local, &accept_tx, ssrc, inb).await;
                    }
                }
                Err(_) => break,
            },
            r = socket.recv_rtcp(&mut rtcp_buf) => match r {
                Ok((n, src)) => {
                    if let Some(ssrc) = peek_rtcp_ssrc(&rtcp_buf[..n]) {
                        let inb = SimpleInbound::Rtcp { data: Bytes::copy_from_slice(&rtcp_buf[..n]), src };
                        route(&mut flows, &socket, &cfg, local, &accept_tx, ssrc, inb).await;
                    }
                }
                Err(_) => break,
            },
        }
    }
}

/// Routes one datagram to its flow by SSRC, creating the flow (and surfacing it via
/// `accept`) on first sight. A flow whose session has ended is pruned (its inbound
/// channel is closed); at [`MAX_FLOWS`] a new SSRC is dropped.
async fn route(
    flows: &mut HashMap<u32, mpsc::Sender<SimpleInbound>>,
    socket: &SimpleSocket,
    cfg: &Config,
    local: SocketAddr,
    accept_tx: &mpsc::Sender<Receiver>,
    ssrc: u32,
    inb: SimpleInbound,
) {
    if let Some(tx) = flows.get(&ssrc) {
        if tx.send(inb).await.is_err() {
            flows.remove(&ssrc); // the flow's session ended
        }
        return;
    }
    // Reclaim slots held by ended flows before enforcing the cap.
    flows.retain(|_, tx| !tx.is_closed());
    if flows.len() >= MAX_FLOWS {
        return; // at capacity: drop this datagram, keep demultiplexing
    }
    let (in_tx, receiver) = crate::session::build_injected_simple(socket.clone(), cfg, ssrc, local);
    let _ = in_tx.send(inb).await; // feed the datagram that opened the flow
    flows.insert(ssrc, in_tx);
    // Surface the new flow. A full accept buffer (the caller never drains Accept) only
    // means the flow is not surfaced; it still recovers and delivers.
    let _ = accept_tx.send(receiver).await;
}

/// The normalized SSRC of an RTP media datagram (bytes 8..11), the Simple demux key.
fn peek_media_ssrc(b: &[u8]) -> Option<u32> {
    if b.len() < 12 {
        return None;
    }
    Some(rtp::normalize_ssrc(u32::from_be_bytes([
        b[8], b[9], b[10], b[11],
    ])))
}

/// The normalized SSRC of a compound RTCP datagram's lead report (SR/RR/SDES carry
/// the SSRC at bytes 4..7), used to route feedback to its flow.
fn peek_rtcp_ssrc(b: &[u8]) -> Option<u32> {
    if b.len() < 8 {
        return None;
    }
    Some(rtp::normalize_ssrc(u32::from_be_bytes([
        b[4], b[5], b[6], b[7],
    ])))
}
