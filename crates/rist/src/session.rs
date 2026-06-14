//! Per-flow session assembly: it converts the public [`Config`] into the flow
//! core's parameters, builds the transport + peer + flow, and spawns the
//! [`Driver`](crate::driver::Driver) pump. The driver owns the loop; this module
//! is the glue that wires it up for the Simple profile.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use rist_core::clock::Micros;
use rist_core::flow::{Config as FlowConfig, Flow, Role};

use crate::config::{Config, NackType};
use crate::driver::{Driver, ReceiverSpawned, SenderSpawned};
use crate::peer::Peer;
use crate::runtime::Runtime;
use crate::socket::SimpleSocket;

/// The default base flow SSRC a sender stamps when the public config does not
/// specify one. Even (the LSB is the retransmit marker); the receiver learns it
/// from the first packet, so any even value interoperates. ASCII "RIST".
const DEFAULT_FLOW_SSRC: u32 = 0x5249_5354;

/// The CNAME used in SDES when the config does not set one.
const DEFAULT_CNAME: &str = "ristrust";

/// Converts a public `Duration` to the core's microsecond domain (saturating).
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn dur_to_micros(d: Duration) -> Micros {
    Micros::from_micros(d.as_micros().min(i64::MAX as u128) as i64)
}

/// Derives the flow core's `Config` from the public `Config`.
fn flow_config(cfg: &Config, ssrc: u32, start_seq: u32) -> FlowConfig {
    FlowConfig {
        recovery_buffer_min: dur_to_micros(cfg.buffer_min),
        recovery_buffer_max: dur_to_micros(cfg.buffer_max),
        reorder_buffer: dur_to_micros(cfg.reorder_buffer),
        rtt_min: dur_to_micros(cfg.rtt_min),
        rtt_max: dur_to_micros(cfg.rtt_max),
        min_retries: cfg.min_retries,
        max_retries: cfg.max_retries,
        ring_size: 0, // 0 selects the default 2^16 ring
        ssrc,
        start_seq,
    }
}

/// Builds and spawns a Simple-profile sender driver transmitting media to
/// `remote` (the receiver's even media port) and RTCP to `remote.port() + 1`.
///
/// # Errors
/// Returns an I/O error if the ephemeral transport sockets cannot be bound.
pub(crate) fn build_sender(
    rt: &dyn Runtime,
    cfg: &Config,
    remote: SocketAddr,
) -> io::Result<SenderSpawned> {
    let socket = SimpleSocket::dial_ephemeral(rt, remote.is_ipv6())?;
    let ssrc = DEFAULT_FLOW_SSRC;
    let flow = Flow::new(Role::Sender, flow_config(cfg, ssrc, 0));
    let mut rtcp = remote;
    rtcp.set_port(remote.port().wrapping_add(1));
    let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, rtcp);
    Ok(Driver::spawn_sender(
        flow,
        socket,
        peer,
        ssrc,
        cname_of(cfg),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        0,
    ))
}

/// Builds and spawns a Simple-profile receiver driver bound to `local` (the
/// even media port; RTCP binds the adjacent odd port). The sender's return
/// addresses are learned from inbound traffic.
///
/// # Errors
/// Returns an I/O error if `local` is not a positive even port or the transport
/// sockets cannot be bound.
pub(crate) fn build_receiver(
    rt: &dyn Runtime,
    cfg: &Config,
    local: SocketAddr,
) -> io::Result<ReceiverSpawned> {
    let socket = SimpleSocket::listen(rt, local)?;
    // The receiver's media SSRC is learned from the first packet; the flow config
    // SSRC is unused on the receive half. DEFAULT_FLOW_SSRC is the reporter SSRC
    // for its RTCP until the media SSRC is learned.
    let flow = Flow::new(Role::Receiver, flow_config(cfg, 0, 0));
    let peer = Peer::new(dur_to_micros(cfg.session_timeout));
    Ok(Driver::spawn_receiver(
        flow,
        socket,
        peer,
        DEFAULT_FLOW_SSRC,
        cname_of(cfg),
        bitmask_of(cfg),
        cfg.keepalive_interval,
    ))
}

fn cname_of(cfg: &Config) -> String {
    cfg.cname
        .clone()
        .unwrap_or_else(|| DEFAULT_CNAME.to_string())
}

fn bitmask_of(cfg: &Config) -> bool {
    matches!(cfg.nack_type, NackType::Bitmask)
}
