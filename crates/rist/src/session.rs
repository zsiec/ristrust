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
use crate::driver::Driver;
use crate::driver_adv::AdvDriver;
use crate::driver_bonded::{BondedDriver, PathParts};
use crate::driver_main::{EapRole, MainDriver};
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
        recovery_maxbitrate: cfg.max_bitrate_kbps,
        congestion_control: cfg.congestion_control,
        ssrc,
        start_seq,
        no_recovery: cfg.one_way,
    }
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

/// Builds and spawns a sender driver transmitting media to `remote`. For the
/// Simple profile this is the receiver's even media port (RTCP at `+1`); for the
/// Main profile it is the single GRE port.
///
/// # Errors
/// Returns an I/O error if the transport sockets cannot be bound, or an invalid
/// secret prevents PSK key derivation (Main).
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
        let socket = MainSocket::dial_ephemeral(rt, remote.is_ipv6(), egress.as_ref())?;
        let local = socket.local()?;
        let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, remote);
        let codec = build_main_codec(cfg, ssrc)?;
        let eap = build_eap_role(cfg, true)?;
        let (oob_tx, oob_rx) = mpsc::channel(16);
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
        );
        return Ok(SenderSpawned {
            local,
            app_in,
            weight_cmd: None,
            flow_attr_cmd: None,
            oob_in: Some(oob_tx),
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
        );
        return Ok(SenderSpawned {
            local,
            app_in,
            weight_cmd: None,
            flow_attr_cmd: Some(attr_tx),
            oob_in: Some(oob_tx),
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
    );
    Ok(SenderSpawned {
        local,
        app_in,
        weight_cmd: None,
        flow_attr_cmd: None,
        oob_in: None,
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
        let socket = MainSocket::listen(rt, local, membership.as_ref())?;
        let bound = socket.local()?;
        let codec = build_main_codec(cfg, DEFAULT_FLOW_SSRC)?;
        let eap = build_eap_role(cfg, false)?;
        let (oob_tx, oob_rx) = mpsc::channel(16);
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
        );
        return Ok(ReceiverSpawned {
            local: bound,
            data_out,
            oob_out: Some(oob_rx),
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
        );
        return Ok(ReceiverSpawned {
            local: bound,
            data_out,
            oob_out: Some(oob_rx),
            close,
            stats,
            task,
        });
    }

    let socket = SimpleSocket::listen(rt, local, membership.as_ref())?;
    let bound = socket.media_local()?;
    let (data_out, close, stats, task) = Driver::spawn_receiver(
        flow,
        socket,
        peer,
        DEFAULT_FLOW_SSRC,
        cname_of(cfg),
        bitmask_of(cfg),
        cfg.keepalive_interval,
        build_lqm_emitter(cfg),
    );
    Ok(ReceiverSpawned {
        local: bound,
        data_out,
        oob_out: None,
        close,
        stats,
        task,
    })
}

/// An empty bonding group sized by the config's session timeout and RTT clamps,
/// ready for `add_path`.
fn bonding_group(cfg: &Config) -> Group {
    Group::new(
        dur_to_micros(cfg.session_timeout),
        dur_to_micros(cfg.rtt_min),
        dur_to_micros(cfg.rtt_max),
    )
}

/// The error returned when a bonded session is requested for a non-Main profile.
/// SMPTE 2022-7 bonding rides the Main-profile GRE transport (matching libRIST and
/// ristgo); the Simple and Advanced profiles are single-path here.
fn require_main(cfg: &Config) -> io::Result<()> {
    if cfg.profile == Profile::Main {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: SMPTE 2022-7 bonding requires the Main profile",
        ))
    }
}

/// Builds and spawns a bonded Main-profile sender that fans identical media across
/// every remote in `remotes` (full SMPTE 2022-7 redundancy, weight 0). Each remote
/// is an independent GRE path with its own ephemeral local socket, peer, codec, and
/// EAP role; the shared flow assigns one sequence space across them.
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
    let ssrc = random_even_ssrc();
    let start_seq = random_start_seq();
    let flow = Flow::new(Role::Sender, flow_config(cfg, ssrc, start_seq));
    let mut group = bonding_group(cfg);
    let mut paths = Vec::with_capacity(peers.len());
    let mut local = None;
    for (i, &(remote, weight)) in peers.iter().enumerate() {
        let egress = crate::multicast::sender_egress(cfg, remote)?;
        let socket = MainSocket::dial_ephemeral(rt, remote.is_ipv6(), egress.as_ref())?;
        if local.is_none() {
            local = Some(socket.local()?);
        }
        let peer = Peer::with_addrs(dur_to_micros(cfg.session_timeout), remote, remote);
        let codec = build_main_codec(cfg, ssrc)?;
        let eap = build_eap_role(cfg, true)?;
        // `weight` 0 = full 2022-7 duplication; > 0 = weighted load-share.
        group.add_path(u8::try_from(i).unwrap_or(u8::MAX), weight, 0);
        paths.push(PathParts {
            socket,
            peer,
            codec,
            eap,
        });
    }
    let local = local.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "rist: bonded sender needs at least one remote",
        )
    })?;
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
    );
    Ok(SenderSpawned {
        local,
        app_in,
        weight_cmd: Some(weight_tx),
        flow_attr_cmd: None,
        oob_in: None,
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
        let socket = MainSocket::listen(rt, local, membership.as_ref())?;
        if bound.is_none() {
            bound = Some(socket.local()?);
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
    );
    Ok(ReceiverSpawned {
        local: bound,
        data_out,
        oob_out: None,
        close,
        stats,
        task,
    })
}
