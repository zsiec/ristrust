//! Per-flow session assembly: it converts the public [`Config`] into the flow
//! core's parameters, builds the transport + peer + flow, and spawns the driver
//! pump. The driver owns the loop; this module is the glue that wires it up,
//! branching between the Simple-profile even/odd transport and the Main-profile
//! single-port GRE transport.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use rist_codec::crypto::{self, AesKeyBits};
use rist_codec::eap::{self, Authenticatee, Authenticator, static_verifier};
use rist_codec::srp;
use rist_core::clock::{Micros, Timestamp};
use rist_core::flow::{Config as FlowConfig, Flow, Role};

use crate::adapt::{LqmEmitter, RateControl};
use crate::bonding::{self, Group};
use crate::codec_adv::AdvCodec;
use crate::codec_main::MainCodec;
use crate::config::{Config, NackType, Profile};
use crate::driver::{Driver, SimpleInbound};
use crate::driver_adv::AdvDriver;
use crate::driver_bonded::{BondedDriver, PathParts};
use crate::driver_main::{EapRole, MainDriver, MainInbound};
use crate::fec::FecState;
use crate::peer::Peer;
use crate::runtime::Runtime;
use crate::socket::{MainSocket, SimpleSocket};

/// The default base flow SSRC a sender stamps when the public config does not
/// specify one. Even (the LSB is the retransmit marker); the receiver learns it
/// from the first packet, so any even value interoperates. ASCII "RIST".
const DEFAULT_FLOW_SSRC: u32 = 0x5249_5354;

/// The CNAME used in SDES when the config does not set one.
const DEFAULT_CNAME: &str = "ristrust";

/// The application-facing handles of a spawned sender, profile-agnostic.
pub(crate) struct SenderSpawned {
    /// The bound local address (for `local_addr`).
    pub(crate) local: SocketAddr,
    /// Sends application payloads into the driver.
    pub(crate) app_in: mpsc::Sender<Bytes>,
    /// Runtime `(path, weight)` commands for a bonded sender (`Sender::set_weight`);
    /// `None` for non-bonded senders.
    pub(crate) weight_cmd: Option<mpsc::Sender<(u8, u32)>>,
    /// Application flow attributes to transmit (`Sender::write_flow_attribute`);
    /// `Some` only on an Advanced sender.
    pub(crate) flow_attr_cmd: Option<mpsc::Sender<Vec<u8>>>,
    /// Out-of-band datagrams to transmit (`Sender::write_oob`); `Some` on a
    /// Main/Advanced sender. Each is `(GRE protocol type, payload)`.
    pub(crate) oob_in: Option<mpsc::Sender<(u16, Vec<u8>)>>,
    /// Reverse out-of-band datagrams received from the peer (`Sender::read_oob`);
    /// `Some` on a Main/Advanced sender. Each is `(GRE protocol type, payload)`.
    pub(crate) oob_out: Option<mpsc::Receiver<(u16, Bytes)>>,
    /// Why the driver exited, read once the channel closes.
    pub(crate) close: crate::driver::CloseFlag,
    /// The live stats snapshot, read by the handle's `stats()`.
    pub(crate) stats: crate::stats::StatsCell,
    /// The driver task handle (aborted on close).
    pub(crate) task: tokio::task::JoinHandle<()>,
}

/// The application-facing handles of a spawned receiver, profile-agnostic.
pub(crate) struct ReceiverSpawned {
    /// The bound local address (for `local_addr`).
    pub(crate) local: SocketAddr,
    /// Receives delivered payloads from the driver.
    pub(crate) data_out: mpsc::Receiver<Bytes>,
    /// Received out-of-band datagrams (`Receiver::read_oob`); `Some` on a
    /// Main/Advanced receiver. Each is `(GRE protocol type, payload)`.
    pub(crate) oob_out: Option<mpsc::Receiver<(u16, Bytes)>>,
    /// Reverse out-of-band datagrams to transmit back to the sender
    /// (`Receiver::write_oob`); `Some` on a Main/Advanced receiver. Each is
    /// `(GRE protocol type, payload)`.
    pub(crate) oob_in: Option<mpsc::Sender<(u16, Vec<u8>)>>,
    /// Why the driver exited, read once the channel closes.
    pub(crate) close: crate::driver::CloseFlag,
    /// The live stats snapshot, read by the handle's `stats()`.
    pub(crate) stats: crate::stats::StatsCell,
    /// The driver task handle (aborted on close).
    pub(crate) task: tokio::task::JoinHandle<()>,
}

/// Converts a public `Duration` to the core's microsecond domain (saturating).
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn dur_to_micros(d: Duration) -> Micros {
    Micros::from_micros(d.as_micros().min(i64::MAX as u128) as i64)
}

/// The effective `[rtt_min, rtt_max]` clamp handed to the flow core, applying
/// libRIST's "rtt_min is too small for the buffer" floor from `store_peer_settings`:
/// the effective `rtt_min` is raised to `buffer_min / max_retries` whenever the
/// configured value is below it. With the defaults (buffer_min 1000 ms, max_retries
/// 20) that floor is 50 ms, not the configured 5 ms. The floor keeps the NACK retry
/// cadence (1.1× the clamped RTT) and the `max_retries` abandon budget commensurate
/// with the playout buffer; without it, a low-RTT link re-NACKs an order of magnitude
/// too often and exhausts `max_retries` in a fraction of the buffer, giving up on
/// recoverable loss far sooner than a libRIST receiver. `rtt_max` is raised to the
/// floored `rtt_min` if a degenerate config left it lower (matching libRIST). The
/// configured `cfg.rtt_min` is left untouched (it stays the reported value); only the
/// value handed to the core is floored — exactly as libRIST computes the effective
/// `recovery_rtt_min` once rather than mutating the user's setting. (The hard 3 ms
/// RIST floor is applied separately inside the core's RTT estimator.)
fn effective_rtt_bounds(cfg: &Config) -> (Micros, Micros) {
    let mut rtt_min = dur_to_micros(cfg.rtt_min).as_micros();
    if cfg.max_retries > 0 {
        let floor = dur_to_micros(cfg.buffer_min).as_micros() / i64::from(cfg.max_retries);
        if floor > rtt_min {
            rtt_min = floor;
        }
    }
    let rtt_max = dur_to_micros(cfg.rtt_max).as_micros().max(rtt_min);
    (Micros::from_micros(rtt_min), Micros::from_micros(rtt_max))
}

/// Derives the flow core's `Config` from the public `Config`.
fn flow_config(cfg: &Config, ssrc: u32, start_seq: u32) -> FlowConfig {
    let (rtt_min, rtt_max) = effective_rtt_bounds(cfg);
    FlowConfig {
        recovery_buffer_min: dur_to_micros(cfg.buffer_min),
        recovery_buffer_max: dur_to_micros(cfg.buffer_max),
        reorder_buffer: dur_to_micros(cfg.reorder_buffer),
        rtt_min,
        rtt_max,
        rtt_multiplier: cfg.rtt_multiplier,
        min_retries: cfg.min_retries,
        max_retries: cfg.max_retries,
        ring_size: 0, // 0 selects the default 2^16 ring
        recovery_maxbitrate: cfg.max_bitrate_kbps,
        congestion_control: cfg.congestion_control,
        ssrc,
        start_seq,
        no_recovery: cfg.one_way,
        timing_mode: cfg.timing_mode,
        return_maxbitrate: cfg.return_bandwidth,
    }
}

/// Builds the per-flow FEC engine when forward error correction is configured,
/// sized for the profile's carriage (full datagram for Advanced in-band, RTP payload
/// for Simple/Main separate-port).
fn build_fec(cfg: &Config) -> Option<FecState> {
    cfg.fec.as_ref().map(|f| FecState::new(f, cfg.profile))
}

fn cname_of(cfg: &Config) -> String {
    cfg.cname
        .clone()
        .unwrap_or_else(|| DEFAULT_CNAME.to_string())
}

fn bitmask_of(cfg: &Config) -> bool {
    matches!(cfg.nack_type, NackType::Bitmask)
}

/// Builds the receiver's Link Quality Message emitter when source adaptation is
/// enabled (TR-06-4 Part 1): one report per keepalive period, tagging each with the
/// recovery (NACK) window. `None` when adaptation is off.
fn build_lqm_emitter(cfg: &Config) -> Option<LqmEmitter> {
    // A one-way receiver sends nothing back, so it emits no Link Quality Messages
    // even when source adaptation is requested.
    if !cfg.source_adaptation || cfg.one_way {
        return None;
    }
    let nack_window_ms = u32::try_from(cfg.buffer_min.as_millis()).unwrap_or(u32::MAX);
    Some(LqmEmitter::new(
        cfg.keepalive_interval,
        nack_window_ms,
        Timestamp::ZERO,
    ))
}

/// A stable locally-administered 48-bit MAC for GRE keepalives, derived from the
/// flow SSRC. The keepalive MAC is informational (a node identifier), not a demux
/// key, so any stable value interoperates.
fn flow_mac(ssrc: u32) -> [u8; 6] {
    let s = ssrc.to_be_bytes();
    [0x02, 0x00, s[0], s[1], s[2], s[3]]
}

/// A random even 32-bit SSRC for a sender's media stream. Even keeps the LSB clear
/// (it is the retransmit marker, so even = original media). An unpredictable SSRC
/// (vs. a fixed constant) resists off-path packet injection. Falls back to the
/// default if the OS CSPRNG is unavailable.
fn random_even_ssrc() -> u32 {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_err() {
        return DEFAULT_FLOW_SSRC;
    }
    u32::from_be_bytes(b) & !1
}

/// A random 16-bit initial RTP sequence number. The wire sequence is 16-bit on the
/// Simple/Main profiles (widened to 32-bit in the core); a random start (vs. 0)
/// resists off-path injection. Falls back to 0 if the CSPRNG is unavailable.
fn random_start_seq() -> u32 {
    let mut b = [0u8; 2];
    if getrandom::fill(&mut b).is_err() {
        return 0;
    }
    u32::from(u16::from_be_bytes(b))
}

/// Builds the EAP-SRP role for a Main-profile flow when credentials are
/// configured: a sender authenticates (authenticatee), a listener verifies
/// (authenticator). The authenticator derives the verifier from a fresh per-session
/// salt (which it advertises in the CHALLENGE), so it only needs the same
/// `(username, password)` the sender uses.
fn build_eap_role(cfg: &Config, sender: bool) -> io::Result<Option<EapRole>> {
    let (Some(user), Some(pass)) = (&cfg.srp_username, &cfg.srp_password) else {
        return Ok(None);
    };
    let invalid = |e: eap::EapError| io::Error::new(io::ErrorKind::InvalidInput, e.to_string());
    // With a configured PSK secret the data channel keys from it and SRP only gates
    // (the role must not push "use K" and override the secret); with no secret the
    // channel re-keys to the SRP session key K. NOTE: the pure-SRP (no-secret) path
    // is a ristrust↔ristrust mode — a libRIST *listener* rejects it ("configured
    // without keysize"), because its keysize gate checks the parent peer's key,
    // which only an explicit `-s` passphrase configures (not the SRP-derived key).
    // For libRIST interop, configure a secret too (the combined PSK+SRP mode).
    let use_key = cfg.secret.is_none();
    if sender {
        let mut a = Authenticatee::new(user, pass).map_err(invalid)?;
        a.set_use_key_passphrase(use_key);
        Ok(Some(EapRole::Authenticatee(Box::new(a))))
    } else {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt)
            .map_err(|_| io::Error::other("rist: srp: CSPRNG unavailable"))?;
        let verifier =
            srp::make_verifier(&srp::default_group(), user, pass, &salt).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "rist: srp: invalid credentials",
                )
            })?;
        let lookup = static_verifier(user, verifier, salt.to_vec());
        let mut a = Authenticator::new(lookup);
        a.set_use_key_passphrase(use_key);
        Ok(Some(EapRole::Authenticator(Box::new(a))))
    }
}

/// Derives the PSK send key + receive decryptor pair (both directions encrypt under
/// the same passphrase, so each side holds both), with the 256-bit flag; or
/// `(None, None, false)` when no secret is configured.
type PskKeys = (Option<crypto::Key>, Option<crypto::Decryptor>, bool);
fn build_psk_keys(cfg: &Config) -> io::Result<PskKeys> {
    let Some(secret) = &cfg.secret else {
        return Ok((None, None, false));
    };
    let bits = cfg.aes_key_bits.unwrap_or(AesKeyBits::Aes256);
    let to_io = |e: crypto::CryptoError| io::Error::new(io::ErrorKind::InvalidInput, e.to_string());
    let send = crypto::Key::new(secret.as_bytes(), bits, cfg.key_rotation, false).map_err(to_io)?;
    let recv = crypto::Decryptor::new(secret.as_bytes(), bits).map_err(to_io)?;
    Ok((Some(send), Some(recv), bits == AesKeyBits::Aes256))
}

/// Builds the Main-profile codec for one direction.
fn build_main_codec(cfg: &Config, ssrc: u32) -> io::Result<MainCodec> {
    let (send_key, recv_key, key_size_256) = build_psk_keys(cfg)?;
    Ok(MainCodec::new(
        send_key,
        recv_key,
        key_size_256,
        cfg.virt_src_port,
        cfg.virt_dst_port,
        // NPD on the send path (Main only; validated in Config::validate). TODO
        // (TR-06-2 §8.6.2): when FEC lands, compute FEC over the NPD-canonicalized
        // payload (route through suppress→expand before the FEC parity).
        cfg.null_packet_deletion,
        ssrc,
        cname_of(cfg),
    ))
}

/// Builds the Advanced-profile media/control codec for one direction.
fn build_adv_codec(cfg: &Config, ssrc: u32) -> io::Result<AdvCodec> {
    let (send_key, recv_key, _) = build_psk_keys(cfg)?;
    Ok(AdvCodec::new(
        send_key,
        recv_key,
        cfg.compression,
        ssrc,
        cfg.virt_src_port,
        cfg.virt_dst_port,
    ))
}

/// The Main-profile sender transport: a DTLS client (the sender dials the receiver,
/// which is the DTLS server) when DTLS is configured, otherwise a plain ephemeral GRE
/// socket. Both present the same [`MainSocket`] interface, so the driver is unaware.
#[cfg_attr(not(feature = "dtls"), allow(unused_variables))]
fn main_sender_socket(
    rt: &dyn Runtime,
    cfg: &Config,
    remote: SocketAddr,
    egress: Option<&crate::multicast::Egress>,
) -> io::Result<MainSocket> {
    #[cfg(feature = "dtls")]
    if let Some(dtls) = &cfg.dtls {
        return crate::dtls_transport::dtls_client(remote, dtls.clone());
    }
    MainSocket::dial_ephemeral(rt, remote.is_ipv6(), egress)
}

/// The Main-profile receiver transport: a DTLS server (it learns its peer from the
/// first datagram) when DTLS is configured, otherwise a plain GRE listen socket.
#[cfg_attr(not(feature = "dtls"), allow(unused_variables))]
fn main_receiver_socket(
    rt: &dyn Runtime,
    cfg: &Config,
    local: SocketAddr,
    membership: Option<&crate::multicast::Membership>,
) -> io::Result<MainSocket> {
    #[cfg(feature = "dtls")]
    if let Some(dtls) = &cfg.dtls {
        return crate::dtls_transport::dtls_server(local, dtls.clone());
    }
    MainSocket::listen(rt, local, membership)
}

/// Builds and spawns a sender driver transmitting media to `remote`. For the
/// Simple profile this is the receiver's even media port (RTCP at `+1`); for the
/// Main profile it is the single GRE port.
///
/// # Errors
/// Returns an I/O error if the transport sockets cannot be bound, or an invalid
/// secret prevents PSK key derivation (Main).
// A flat per-profile constructor wiring the session config into a driver; the three
// profile branches push it just over the line cap.
#[allow(clippy::too_many_lines)]
pub(crate) fn build_sender(
    rt: &dyn Runtime,
    cfg: &Config,
    remote: SocketAddr,
) -> io::Result<SenderSpawned> {
    let ssrc = random_even_ssrc();
    let start_seq = random_start_seq();
    let flow = Flow::new(Role::Sender, flow_config(cfg, ssrc, start_seq));
    // Multicast egress options when `remote` is a group; `None` for unicast.
    let egress = crate::multicast::sender_egress(cfg, remote)?;

    if cfg.profile == Profile::Main {
        let socket = main_sender_socket(rt, cfg, remote, egress.as_ref())?;
        let local = socket.local()?;
        let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, remote);
        let codec = build_main_codec(cfg, ssrc)?;
        let eap = build_eap_role(cfg, true)?;
        let (oob_tx, oob_rx) = mpsc::channel(16);
        let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
        let (app_in, close, stats, task) = MainDriver::spawn_sender(
            flow,
            socket,
            peer,
            codec,
            ssrc,
            flow_mac(ssrc),
            bitmask_of(cfg),
            cfg.keepalive_interval,
            start_seq,
            eap,
            RateControl::from_config(cfg),
            oob_rx,
            rev_oob_tx,
            build_fec(cfg),
        );
        return Ok(SenderSpawned {
            local,
            app_in,
            weight_cmd: None,
            flow_attr_cmd: None,
            oob_in: Some(oob_tx),
            oob_out: Some(rev_oob_rx),
            close,
            stats,
            task,
        });
    }

    if cfg.profile == Profile::Advanced {
        let socket = MainSocket::dial_ephemeral(rt, remote.is_ipv6(), egress.as_ref())?;
        let local = socket.local()?;
        let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, remote);
        let main = build_main_codec(cfg, ssrc)?;
        let adv = build_adv_codec(cfg, ssrc)?;
        let eap = build_eap_role(cfg, true)?;
        // The fire-and-forget flow-attribute and OOB send channels (rare, small).
        let (attr_tx, attr_rx) = mpsc::channel(16);
        let (oob_tx, oob_rx) = mpsc::channel(16);
        let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
        let (app_in, close, stats, task) = AdvDriver::spawn_sender(
            flow,
            socket,
            peer,
            main,
            adv,
            ssrc,
            bitmask_of(cfg),
            cfg.keepalive_interval,
            start_seq,
            eap,
            RateControl::from_config(cfg),
            cfg.on_flow_attr.clone(),
            attr_rx,
            oob_rx,
            rev_oob_tx,
            cfg.fragment_size,
            build_fec(cfg),
        );
        return Ok(SenderSpawned {
            local,
            app_in,
            weight_cmd: None,
            flow_attr_cmd: Some(attr_tx),
            oob_in: Some(oob_tx),
            oob_out: Some(rev_oob_rx),
            close,
            stats,
            task,
        });
    }

    let socket = SimpleSocket::dial_ephemeral(rt, remote.is_ipv6(), egress.as_ref())?;
    let local = socket.media_local()?;
    let mut rtcp = remote;
    rtcp.set_port(remote.port().wrapping_add(1));
    let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, rtcp);
    let (app_in, close, stats, task) = Driver::spawn_sender(
        flow,
        socket,
        peer,
        ssrc,
        cname_of(cfg),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        start_seq,
        RateControl::from_config(cfg),
        build_fec(cfg),
    );
    Ok(SenderSpawned {
        local,
        app_in,
        weight_cmd: None,
        flow_attr_cmd: None,
        oob_in: None,
        oob_out: None,
        close,
        stats,
        task,
    })
}

/// Builds and spawns a receiver driver bound to `local`. For the Simple profile
/// `local` is the even media port (RTCP binds the adjacent odd port); for the Main
/// profile it is the single GRE port. The sender's return address is learned from
/// inbound traffic.
///
/// # Errors
/// Returns an I/O error if `local` is not a valid port for the profile, the
/// transport sockets cannot be bound, or an invalid secret prevents PSK key
/// derivation (Main).
// A per-profile dispatch builder (Main / Advanced / Simple), each branch wiring the
// full session config; splitting it would only scatter that wiring.
#[allow(clippy::too_many_lines)]
pub(crate) fn build_receiver(
    rt: &dyn Runtime,
    cfg: &Config,
    local: SocketAddr,
) -> io::Result<ReceiverSpawned> {
    // The receiver's media SSRC is learned from the first packet; the flow config
    // SSRC is unused on the receive half. DEFAULT_FLOW_SSRC is the reporter SSRC
    // for its RTCP until the media SSRC is learned.
    let flow = Flow::new(Role::Receiver, flow_config(cfg, 0, 0));
    let peer = Peer::new(dur_to_micros(cfg.session_timeout));
    // Multicast group membership when `local` is a group; `None` for unicast.
    let membership = crate::multicast::receiver_membership(cfg, local)?;

    if cfg.profile == Profile::Main {
        let mut socket = main_receiver_socket(rt, cfg, local, membership.as_ref())?;
        let bound = socket.local()?;
        // Separate-port FEC carriage: bind the column (GRE port + 2) and, for 2-D FEC,
        // the row (+ 4) FEC sockets the receiver reads (ST 2022-1 RTP, not GRE-framed).
        // DTLS and FEC are mutually exclusive (validated), so this is skipped for DTLS.
        if let Some(f) = &cfg.fec
            && f.resolved_separate_ports(cfg.profile)
        {
            socket.bind_fec(rt, bound, membership.as_ref(), !f.column_only)?;
        }
        let codec = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let eap = build_eap_role(cfg, false)?;
        let (oob_tx, oob_rx) = mpsc::channel(16);
        let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
        let (data_out, close, stats, task) = MainDriver::spawn_receiver(
            flow,
            socket,
            peer,
            codec,
            DEFAULT_FLOW_SSRC,
            flow_mac(DEFAULT_FLOW_SSRC),
            bitmask_of(cfg),
            cfg.keepalive_interval,
            eap,
            build_lqm_emitter(cfg),
            oob_tx,
            rev_oob_rx,
            false, // a listening receiver is not a caller; no caller-rebind
            build_fec(cfg),
        );
        return Ok(ReceiverSpawned {
            local: bound,
            data_out,
            oob_out: Some(oob_rx),
            oob_in: Some(rev_oob_tx),
            close,
            stats,
            task,
        });
    }

    if cfg.profile == Profile::Advanced {
        let socket = MainSocket::listen(rt, local, membership.as_ref())?;
        let bound = socket.local()?;
        let main = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let adv = build_adv_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let eap = build_eap_role(cfg, false)?;
        let (oob_tx, oob_rx) = mpsc::channel(16);
        let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
        let (data_out, close, stats, task) = AdvDriver::spawn_receiver(
            flow,
            socket,
            peer,
            main,
            adv,
            DEFAULT_FLOW_SSRC,
            bitmask_of(cfg),
            cfg.keepalive_interval,
            eap,
            build_lqm_emitter(cfg),
            cfg.on_flow_attr.clone(),
            oob_tx,
            rev_oob_rx,
            build_fec(cfg),
        );
        return Ok(ReceiverSpawned {
            local: bound,
            data_out,
            oob_out: Some(oob_rx),
            oob_in: Some(rev_oob_tx),
            close,
            stats,
            task,
        });
    }

    let mut socket = SimpleSocket::listen(rt, local, membership.as_ref())?;
    let bound = socket.media_local()?;
    // Separate-port FEC carriage: bind the column (media + 2) and, for 2-D FEC, the
    // row (media + 4) FEC sockets the receiver reads (TR-06-2 §8.4 / SMPTE 2022-1).
    if let Some(f) = &cfg.fec
        && f.resolved_separate_ports(cfg.profile)
    {
        socket.bind_fec(rt, bound, membership.as_ref(), !f.column_only)?;
    }
    let (data_out, close, stats, task) = Driver::spawn_receiver(
        flow,
        socket,
        peer,
        DEFAULT_FLOW_SSRC,
        cname_of(cfg),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        build_lqm_emitter(cfg),
        build_fec(cfg),
    );
    Ok(ReceiverSpawned {
        local: bound,
        data_out,
        oob_out: None,
        oob_in: None,
        close,
        stats,
        task,
    })
}

/// Builds one **injected** Simple-profile receiver flow for a [`MultiReceiver`]:
/// a per-flow [`Driver`] driven by an external demultiplexer rather than its own
/// socket reader. `socket` is the shared bound socket (cloned per flow for sends);
/// `ssrc` is the flow's demux SSRC (tagged into its reports); `local` is the shared
/// bound media address (reported as the per-flow receiver's `local_addr`). Returns
/// the inbound sender the demuxer feeds and the application-facing [`Receiver`].
pub(crate) fn build_injected_simple(
    socket: crate::socket::SimpleSocket,
    cfg: &Config,
    ssrc: u32,
    local: SocketAddr,
) -> (mpsc::Sender<SimpleInbound>, crate::receiver::Receiver) {
    let flow = Flow::new(Role::Receiver, flow_config(cfg, ssrc, 0));
    let peer = Peer::new(dur_to_micros(cfg.session_timeout));
    let (in_tx, data_out, close, stats, task) = Driver::spawn_injected_receiver(
        flow,
        socket,
        peer,
        ssrc,
        cname_of(cfg),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        build_lqm_emitter(cfg),
    );
    let receiver = crate::receiver::Receiver::from_parts(
        cfg.clone(),
        local,
        data_out,
        None,
        close,
        stats,
        task,
    );
    (in_tx, receiver)
}

/// Builds one **injected** Main-profile receiver flow for a [`MultiReceiver`], keyed
/// by source address: a per-source [`MainDriver`] with its own GRE substrate, PSK
/// keys, and EAP-SRP role (so each source decrypts and authenticates independently,
/// fail-closed). `local` is the shared bound address (the per-flow `local_addr`).
///
/// # Errors
/// Returns an I/O error if an invalid secret prevents PSK key derivation.
pub(crate) fn build_injected_main(
    socket: MainSocket,
    cfg: &Config,
    local: SocketAddr,
) -> io::Result<(mpsc::Sender<MainInbound>, crate::receiver::Receiver)> {
    // Source-keyed flows keep the template reporter SSRC (the SSRC is inside the
    // encrypted payload); each flow feeds back to its distinct source, the identity
    // the sender disambiguates on.
    let ssrc = DEFAULT_FLOW_SSRC;
    let flow = Flow::new(Role::Receiver, flow_config(cfg, ssrc, 0));
    let peer = Peer::new(dur_to_micros(cfg.session_timeout));
    let codec = build_main_codec(cfg, ssrc)?;
    let eap = build_eap_role(cfg, false)?;
    let (oob_tx, oob_rx) = mpsc::channel(16);
    let (in_tx, data_out, close, stats, task) = MainDriver::spawn_injected_receiver(
        flow,
        socket,
        peer,
        codec,
        ssrc,
        flow_mac(ssrc),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        eap,
        build_lqm_emitter(cfg),
        oob_tx,
    );
    let receiver = crate::receiver::Receiver::from_parts(
        cfg.clone(),
        local,
        data_out,
        Some(oob_rx),
        close,
        stats,
        task,
    );
    Ok((in_tx, receiver))
}

/// Builds one **injected** Advanced-profile receiver flow for a [`MultiReceiver`],
/// keyed by source address: a per-source [`AdvDriver`] with its own GRE substrate,
/// PSK, EAP-SRP, and fragment reassembly. `local` is the shared bound address.
///
/// # Errors
/// Returns an I/O error if an invalid secret prevents PSK key derivation.
pub(crate) fn build_injected_adv(
    socket: MainSocket,
    cfg: &Config,
    local: SocketAddr,
) -> io::Result<(
    mpsc::Sender<crate::driver_adv::AdvInbound>,
    crate::receiver::Receiver,
)> {
    let ssrc = DEFAULT_FLOW_SSRC;
    let flow = Flow::new(Role::Receiver, flow_config(cfg, ssrc, 0));
    let peer = Peer::new(dur_to_micros(cfg.session_timeout));
    let main = build_main_codec(cfg, ssrc)?;
    let adv = build_adv_codec(cfg, ssrc)?;
    let eap = build_eap_role(cfg, false)?;
    let (oob_tx, oob_rx) = mpsc::channel(16);
    let (in_tx, data_out, close, stats, task) = AdvDriver::spawn_injected_receiver(
        flow,
        socket,
        peer,
        main,
        adv,
        ssrc,
        bitmask_of(cfg),
        cfg.keepalive_interval,
        eap,
        build_lqm_emitter(cfg),
        cfg.on_flow_attr.clone(),
        oob_tx,
    );
    let receiver = crate::receiver::Receiver::from_parts(
        cfg.clone(),
        local,
        data_out,
        Some(oob_rx),
        close,
        stats,
        task,
    );
    Ok((in_tx, receiver))
}

/// Builds one **injected** SMPTE 2022-7 bonded receiver flow for a multi-flow
/// [`MultiReceiver`](crate::MultiReceiver), keyed by source address: a per-source
/// bonded session spanning every demultiplexer path. The demultiplexer owns and
/// reads the `N` path sockets; this flow gets a clone of each (for its outbound
/// handshakes, keepalives, and feedback) and a pre-routed [`Inbound`] feed. `local`
/// is the shared bound address (the per-flow `local_addr`). Multi-flow demux rejects
/// FEC, so no FEC engine is wired.
///
/// # Errors
/// Returns an I/O error if the profile is not Main, `sockets` is empty, or an invalid
/// secret prevents PSK key derivation.
pub(crate) fn build_injected_bonded(
    sockets: &[MainSocket],
    cfg: &Config,
    local: SocketAddr,
) -> io::Result<(
    mpsc::Sender<crate::driver_bonded::Inbound>,
    crate::receiver::Receiver,
)> {
    require_main(cfg)?;
    if sockets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: bonded multi-flow needs at least one path socket",
        ));
    }
    let flow = Flow::new(Role::Receiver, flow_config(cfg, DEFAULT_FLOW_SSRC, 0));
    let mut group = bonding_group(cfg);
    let mut paths = Vec::with_capacity(sockets.len());
    for (i, socket) in sockets.iter().enumerate() {
        let peer = Peer::new(dur_to_micros(cfg.session_timeout));
        let codec = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let eap = build_eap_role(cfg, false)?;
        group.add_path(
            u8::try_from(i).unwrap_or(u8::MAX),
            bonding::WEIGHT_DUPLICATE,
            0,
        );
        paths.push(PathParts {
            socket: socket.clone(),
            peer,
            codec,
            eap,
        });
    }
    let (in_tx, data_out, close, stats, task) = BondedDriver::spawn_injected_receiver(
        flow,
        group,
        paths,
        DEFAULT_FLOW_SSRC,
        flow_mac(DEFAULT_FLOW_SSRC),
        bitmask_of(cfg),
        cfg.keepalive_interval,
    );
    let receiver = crate::receiver::Receiver::from_parts(
        cfg.clone(),
        local,
        data_out,
        None,
        close,
        stats,
        task,
    );
    Ok((in_tx, receiver))
}

/// Rejects a reversed-role session on a profile/feature it does not support.
/// Reversed-role transport rides the Main-profile GRE substrate; EAP-SRP is
/// supported (the single bidirectional GRE socket carries the handshake once the
/// peer is learned — the media sender is the authenticatee whichever side dials),
/// but DTLS is not.
fn require_reversible(cfg: &Config) -> io::Result<()> {
    if cfg.profile == Profile::Simple {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: reversed-role transport requires the Main or Advanced profile",
        ));
    }
    // Reversed-role peer-learning (a sender that waits, or a receiver that dials an
    // announcer) is not modelled by the DTLS client/server handshake here.
    #[cfg(feature = "dtls")]
    if cfg.dtls.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: reversed-role transport does not support DTLS",
        ));
    }
    Ok(())
}

/// Builds a reversed-role **listener-sender**: a media *sender* that binds the
/// well-known port and waits, learning the receiver's address from its inbound
/// announcement (the caller-receiver), then sending media to it. Media is held
/// until that address is known. Main profile only; PSK and EAP-SRP supported (the
/// sender is the authenticatee and opens its EAPOL-START once it learns the caller).
///
/// # Errors
/// As [`build_listener_sender`]'s profile/feature checks, or an I/O bind error.
pub(crate) fn build_listener_sender(
    rt: &dyn Runtime,
    cfg: &Config,
    local: SocketAddr,
) -> io::Result<SenderSpawned> {
    require_reversible(cfg)?;
    let ssrc = random_even_ssrc();
    let start_seq = random_start_seq();
    let flow = Flow::new(Role::Sender, flow_config(cfg, ssrc, start_seq));
    let membership = crate::multicast::receiver_membership(cfg, local)?;
    let socket = MainSocket::listen(rt, local, membership.as_ref())?;
    let bound = socket.local()?;
    // Empty peer: the caller-receiver's announcement teaches us where to send.
    let peer = Peer::new(dur_to_micros(cfg.session_timeout));

    // Advanced reversed-role listener-sender: same single-GRE-port listen + learn-the-
    // caller setup, driven by the Advanced codec (the AdvDriver holds media until the
    // peer is known, like the Main path). Caller-side socket rebind is Main-only.
    if cfg.profile == Profile::Advanced {
        let main = build_main_codec(cfg, ssrc)?;
        let adv = build_adv_codec(cfg, ssrc)?;
        let eap = build_eap_role(cfg, true)?; // the media sender is the authenticatee
        let (attr_tx, attr_rx) = mpsc::channel(16);
        let (oob_tx, oob_rx) = mpsc::channel(16);
        let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
        let (app_in, close, stats, task) = AdvDriver::spawn_sender(
            flow,
            socket,
            peer,
            main,
            adv,
            ssrc,
            bitmask_of(cfg),
            cfg.keepalive_interval,
            start_seq,
            eap,
            RateControl::from_config(cfg),
            cfg.on_flow_attr.clone(),
            attr_rx,
            oob_rx,
            rev_oob_tx,
            cfg.fragment_size,
            None, // FEC + reversed-role deferred
        );
        return Ok(SenderSpawned {
            local: bound,
            app_in,
            weight_cmd: None,
            flow_attr_cmd: Some(attr_tx),
            oob_in: Some(oob_tx),
            oob_out: Some(rev_oob_rx),
            close,
            stats,
            task,
        });
    }

    let codec = build_main_codec(cfg, ssrc)?;
    let eap = build_eap_role(cfg, true)?; // the media sender is the authenticatee
    let (oob_tx, oob_rx) = mpsc::channel(16);
    let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
    let (app_in, close, stats, task) = MainDriver::spawn_sender(
        flow,
        socket,
        peer,
        codec,
        ssrc,
        flow_mac(ssrc),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        start_seq,
        eap,
        RateControl::from_config(cfg),
        oob_rx,
        rev_oob_tx,
        None, // FEC + reversed-role deferred
    );
    Ok(SenderSpawned {
        local: bound,
        app_in,
        weight_cmd: None,
        flow_attr_cmd: None,
        oob_in: Some(oob_tx),
        oob_out: Some(rev_oob_rx),
        close,
        stats,
        task,
    })
}

/// Builds a reversed-role **caller-receiver**: a media *receiver* that dials the
/// listening sender's well-known address, announcing itself (an immediate
/// greeting + keepalives) so the sender learns where to send, then receiving media.
/// Main profile only; PSK and EAP-SRP supported (the receiver is the authenticator,
/// verifying the listener-sender once that side opens the handshake).
///
/// # Errors
/// As [`build_caller_receiver`]'s profile/feature checks, or an I/O bind error.
pub(crate) fn build_caller_receiver(
    rt: &dyn Runtime,
    cfg: &Config,
    remote: SocketAddr,
) -> io::Result<ReceiverSpawned> {
    require_reversible(cfg)?;
    let flow = Flow::new(Role::Receiver, flow_config(cfg, 0, 0));
    let egress = crate::multicast::sender_egress(cfg, remote)?;
    let socket = MainSocket::dial_ephemeral(rt, remote.is_ipv6(), egress.as_ref())?;
    let local = socket.local()?;
    // The sender's address is known up front (we dialled it), so we announce to it.
    let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, remote);

    // Advanced reversed-role caller-receiver: same dial-and-announce setup driven by
    // the Advanced codec. Caller-side socket rebind is a Main-only feature, so an
    // Advanced caller-receiver does not rebind (it relies on the announce/keepalive).
    if cfg.profile == Profile::Advanced {
        let main = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let adv = build_adv_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let eap = build_eap_role(cfg, false)?; // the media receiver is the authenticator
        let (oob_tx, oob_rx) = mpsc::channel(16);
        let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
        let (data_out, close, stats, task) = AdvDriver::spawn_receiver(
            flow,
            socket,
            peer,
            main,
            adv,
            DEFAULT_FLOW_SSRC,
            bitmask_of(cfg),
            cfg.keepalive_interval,
            eap,
            build_lqm_emitter(cfg),
            cfg.on_flow_attr.clone(),
            oob_tx,
            rev_oob_rx,
            None, // FEC + reversed-role deferred
        );
        return Ok(ReceiverSpawned {
            local,
            data_out,
            oob_out: Some(oob_rx),
            oob_in: Some(rev_oob_tx),
            close,
            stats,
            task,
        });
    }

    let codec = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
    let eap = build_eap_role(cfg, false)?; // the media receiver is the authenticator
    // A non-SRP caller-receiver may rebind its own socket to recover a NAT /
    // dynamic-IP source-port change; an SRP session recovers via the listener-side
    // re-association path instead (libRIST's `callerRebind = no EAP`).
    let caller_rebind = eap.is_none();
    let (oob_tx, oob_rx) = mpsc::channel(16);
    let (rev_oob_tx, rev_oob_rx) = mpsc::channel(16);
    let (data_out, close, stats, task) = MainDriver::spawn_receiver(
        flow,
        socket,
        peer,
        codec,
        DEFAULT_FLOW_SSRC,
        flow_mac(DEFAULT_FLOW_SSRC),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        eap,
        build_lqm_emitter(cfg),
        oob_tx,
        rev_oob_rx,
        caller_rebind,
        None, // FEC + reversed-role deferred
    );
    Ok(ReceiverSpawned {
        local,
        data_out,
        oob_out: Some(oob_rx),
        oob_in: Some(rev_oob_tx),
        close,
        stats,
        task,
    })
}

/// An empty bonding group sized by the config's session timeout and RTT clamps,
/// ready for `add_path`.
fn bonding_group(cfg: &Config) -> Group {
    // The 2022-7 duplicate-path grace is the recovery (playout) buffer, matching
    // libRIST's hard_dead = dead_since + recovery_buffer_ticks: a duplicate path's
    // redundancy lingers a playout window past the bare session timeout.
    let (rtt_min, rtt_max) = effective_rtt_bounds(cfg);
    Group::new(
        dur_to_micros(cfg.session_timeout),
        flow_config(cfg, 0, 0).recovery_buffer(),
        rtt_min,
        rtt_max,
    )
}

/// The error returned when a bonded session is requested for a non-Main profile.
/// SMPTE 2022-7 bonding rides the Main-profile GRE transport (matching libRIST and
/// ristgo); the Simple and Advanced profiles are single-path here.
fn require_main(cfg: &Config) -> io::Result<()> {
    if cfg.profile != Profile::Main {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: SMPTE 2022-7 bonding requires the Main profile",
        ));
    }
    // Bonding spreads one flow across several paths/peers, which the single-peer DTLS
    // handshake does not model (ristgo rejects bonded DTLS likewise).
    #[cfg(feature = "dtls")]
    if cfg.dtls.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: DTLS is not supported with SMPTE 2022-7 bonding",
        ));
    }
    Ok(())
}

/// Builds and spawns a bonded Main-profile sender that fans identical media across
/// every remote in `remotes` (full SMPTE 2022-7 redundancy, weight 0). All paths
/// share **one** source socket — so a multiplexing receiver sees the sender's paths
/// as one source (the flow identity) and merges them, while each path keeps its own
/// peer, codec (independent GRE sequence + PSK), and EAP role over that socket; the
/// shared flow assigns one sequence space across them.
///
/// # Errors
/// Returns an I/O error if the profile is not Main, `remotes` is empty, a transport
/// socket cannot be bound, or an invalid secret prevents PSK key derivation.
pub(crate) fn build_bonded_sender(
    rt: &dyn Runtime,
    cfg: &Config,
    peers: &[(SocketAddr, u32)],
) -> io::Result<SenderSpawned> {
    require_main(cfg)?;
    let &(first_remote, _) = peers.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: bonded sender needs at least one remote",
        )
    })?;
    let ssrc = random_even_ssrc();
    let start_seq = random_start_seq();
    let flow = Flow::new(Role::Sender, flow_config(cfg, ssrc, start_seq));
    let mut group = bonding_group(cfg);
    // One shared source socket for every path (the family/egress of the first remote):
    // the sender's datagrams then carry one source address, which a multiplexing
    // receiver keys on to group the paths into a single bonded flow.
    let egress = crate::multicast::sender_egress(cfg, first_remote)?;
    let socket = MainSocket::dial_ephemeral(rt, first_remote.is_ipv6(), egress.as_ref())?;
    let local = socket.local()?;
    let mut paths = Vec::with_capacity(peers.len());
    for (i, &(remote, weight)) in peers.iter().enumerate() {
        let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, remote);
        let codec = build_main_codec(cfg, ssrc)?;
        let eap = build_eap_role(cfg, true)?;
        // `weight` 0 = full 2022-7 duplication; > 0 = weighted load-share.
        group.add_path(u8::try_from(i).unwrap_or(u8::MAX), weight, 0);
        paths.push(PathParts {
            socket: socket.clone(),
            peer,
            codec,
            eap,
        });
    }
    // The runtime `set_weight` command channel (rare control traffic, small depth).
    let (weight_tx, weight_rx) = mpsc::channel(16);
    let (app_in, close, stats, task) = BondedDriver::spawn_sender(
        flow,
        group,
        paths,
        ssrc,
        flow_mac(ssrc),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        start_seq,
        weight_rx,
        RateControl::from_config(cfg),
        build_fec(cfg),
    );
    Ok(SenderSpawned {
        local,
        app_in,
        weight_cmd: Some(weight_tx),
        flow_attr_cmd: None,
        oob_in: None,
        oob_out: None,
        close,
        stats,
        task,
    })
}

/// Builds and spawns a bonded Main-profile receiver that merges media arriving on
/// each local address in `locals` into one flow (the `(seq, source_time)` dedup is
/// the merge). Each local is an independent GRE path; the first bound address is
/// reported as `local_addr`.
///
/// # Errors
/// Returns an I/O error if the profile is not Main, `locals` is empty, a port is
/// invalid, a transport socket cannot be bound, or an invalid secret prevents PSK
/// key derivation.
pub(crate) fn build_bonded_receiver(
    rt: &dyn Runtime,
    cfg: &Config,
    locals: &[SocketAddr],
) -> io::Result<ReceiverSpawned> {
    require_main(cfg)?;
    let flow = Flow::new(Role::Receiver, flow_config(cfg, 0, 0));
    let mut group = bonding_group(cfg);
    let mut paths = Vec::with_capacity(locals.len());
    let mut bound = None;
    for (i, &local) in locals.iter().enumerate() {
        let membership = crate::multicast::receiver_membership(cfg, local)?;
        let mut socket = MainSocket::listen(rt, local, membership.as_ref())?;
        let path_local = socket.local()?;
        if bound.is_none() {
            bound = Some(path_local);
        }
        // Separate-port FEC over bonding: each path binds its own column/row FEC
        // sockets, all feeding the one shared decoder.
        if let Some(f) = &cfg.fec
            && f.resolved_separate_ports(cfg.profile)
        {
            socket.bind_fec(rt, path_local, membership.as_ref(), !f.column_only)?;
        }
        let peer = Peer::new(dur_to_micros(cfg.session_timeout));
        let codec = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let eap = build_eap_role(cfg, false)?;
        group.add_path(
            u8::try_from(i).unwrap_or(u8::MAX),
            bonding::WEIGHT_DUPLICATE,
            0,
        );
        paths.push(PathParts {
            socket,
            peer,
            codec,
            eap,
        });
    }
    let bound = bound.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: bonded receiver needs at least one local address",
        )
    })?;
    let (data_out, close, stats, task) = BondedDriver::spawn_receiver(
        flow,
        group,
        paths,
        DEFAULT_FLOW_SSRC,
        flow_mac(DEFAULT_FLOW_SSRC),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        build_lqm_emitter(cfg),
        build_fec(cfg),
    );
    Ok(ReceiverSpawned {
        local: bound,
        data_out,
        oob_out: None,
        oob_in: None,
        close,
        stats,
        task,
    })
}
