//! The async driver for SMPTE 2022-7 bonded Main-profile flows: `N` independent
//! GRE-over-UDP paths feeding one shared [`Flow`] and one bonding [`Group`].
//!
//! This is the multipath generalization of [`MainDriver`](crate::driver_main): the
//! merge is unchanged (every copy of a sequence — fresh, ARQ resend, or another
//! path's duplicate — lands in the one ring and dedups by `(seq, source_time)`),
//! so each path is just its own GRE tunnel with its own [`Peer`], [`MainCodec`]
//! (independent GRE sequence + PSK), and optional EAP role. One reader task per
//! path funnels inbound datagrams into a single channel the pump selects on, so the
//! whole flow still runs in one task with no locking.
//!
//! The [`Group`] supplies the two host policies the core leaves out: the sender
//! fans each media packet out to every live duplicate-weight path
//! ([`Group::duplicate_targets`]), and the receiver routes each NACK to the
//! selected path ([`Group::select_nack_path`]). No protocol logic lives here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use rist_codec::rtcp::{
    EmptyReceiverReport, LinkQualityReport, Packet as RtcpPacket, SenderReport,
};
use rist_codec::{eap, fec_header, gre, rtp};
use rist_core::clock::{Micros, Ntp64, Timestamp};
use rist_core::fec::{Direction, Recovered};
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::{Feedback, FragRole, MediaPacket};

use crate::adapt::{LqmEmitter, RateControl};
use crate::bonding::Group;
use crate::codec::{self};
use crate::codec_adv::AdvCodec;
use crate::codec_main::{ControlKind, Decoded, MainCodec};
use crate::config::ConnectInfo;
use crate::driver::{COMMAND_CAPACITY, CloseFlag, DATA_CAPACITY, RxControl, recv_opt};
use crate::driver_adv::{AdvOpts, adv_ctrl_ts, advanced_framing_active, is_adv_framed};
use crate::driver_main::EapRole;
use crate::fec::{FEC_COLUMN_PORT_OFFSET, FEC_PT, FEC_ROW_PORT_OFFSET, FecState};
use crate::peer::Peer;
use crate::socket::MainSocket;
use crate::split::{self, MergeMode, Merger, SplitMode};
use crate::stats::PeerStats;
use crate::stats::StatsCell;

/// The largest datagram a path reader will receive.
const RECV_BUF: usize = 65_536;

/// The EAP identifier ristrust stamps on its unsolicited passphrase push (matching
/// [`MainDriver`](crate::driver_main)'s convention).
const PASSPHRASE_PUSH_ID: u8 = 0x40;

/// The depth of the shared inbound channel the per-path readers feed.
pub(crate) const INBOUND_CAPACITY: usize = 256;

/// Whether an inbound datagram arrived on a path's GRE (media/control) socket or one
/// of its separate-port FEC sockets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InboundKind {
    /// The GRE socket: media, control, keepalive, or EAPOL.
    Main,
    /// A separate-port FEC socket (column or row): an RTP-wrapped FEC packet.
    Fec,
}

/// One inbound datagram, tagged with the path it arrived on and its socket kind.
/// `pub(crate)` so the multi-flow bonded demultiplexer can route these by source
/// into per-source bonded sessions, but its fields stay private to this module
/// (the demultiplexer only reads [`Inbound::src`] and forwards the value opaquely).
pub(crate) struct Inbound {
    /// The path index (0-based, matching the [`Group`] registration).
    index: u8,
    /// Which of the path's sockets it arrived on.
    kind: InboundKind,
    /// The datagram's source address (the bonded demux key — one source per sender).
    pub(crate) src: SocketAddr,
    /// The datagram bytes.
    data: Bytes,
}

/// A runtime bonded-path command from `Sender::add_path` / `Sender::remove_path`
/// (libRIST `rist_peer_create` / `rist_peer_destroy`), applied to a live bonded
/// sender's path set on its loop. Sender-side only: a bonded sender shares one source
/// socket across paths, so adding a destination needs no new socket or reader.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PeerCmd {
    /// Add a destination path at `index` (`weight` `0` = full 2022-7 duplication),
    /// transmitting to `addr`. A duplicate index is ignored.
    Add {
        index: u8,
        addr: SocketAddr,
        weight: u32,
        priority: u32,
    },
    /// Remove the path with `index` from the fan-out, NACK selection, and stats.
    Remove { index: u8 },
}

/// Builds the per-path transport + codec state for a runtime-added bonded sender path
/// targeting `addr`. The session captures the shared source socket and the cfg-derived
/// codec / EAP-role builders; the driver invokes it on a [`PeerCmd::Add`].
pub(crate) type PathFactory = Box<dyn FnMut(SocketAddr) -> std::io::Result<PathParts> + Send>;

/// The transport + per-path protocol state of one bonded path. The flow, group,
/// and sender bookkeeping are shared on the [`BondedDriver`]; everything that is
/// per-tunnel lives here.
pub(crate) struct PathParts {
    /// This path's GRE socket.
    pub(crate) socket: MainSocket,
    /// This path's remote endpoint (configured on a sender, learned on a receiver).
    pub(crate) peer: Peer,
    /// This path's stateful Main codec (independent GRE sequence + PSK).
    pub(crate) codec: MainCodec,
    /// This path's EAP-SRP role, when authentication is configured.
    pub(crate) eap: Option<EapRole>,
}

/// The per-path runtime state: [`PathParts`] plus the mutable handshake flags.
struct PathLink {
    index: u8,
    socket: MainSocket,
    peer: Peer,
    codec: MainCodec,
    eap: Option<EapRole>,
    /// Whether this path's initial RTCP-SDES handshake has been sent.
    greeted: bool,
    /// Whether this path's data channel is unblocked (true immediately without
    /// EAP, else once its EAP-SRP handshake succeeds).
    authed: bool,
    /// This receiver path's owned reader task, kept so a runtime `remove_path` can abort
    /// it. `None` on a sender (one shared reader) or an injected/multi-flow path.
    reader: Option<tokio::task::JoinHandle<()>>,
}

/// The bonded Main-profile session driver, run as one detached task per flow.
// Justification: the bool fields are independent per-flow flags, not a state enum.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct BondedDriver {
    /// Whether this is the media-originating (sender) half.
    sender: bool,
    flow: Flow,
    /// The bonding policy: liveness, fan-out targets, and NACK-peer selection.
    group: Group,
    /// The bonded paths, indexed by their [`Group`] path index (`paths[i].index ==
    /// i`).
    paths: Vec<PathLink>,
    /// The session clock epoch: `now()` is microseconds since this instant.
    epoch: Instant,
    /// Declarative timers the flow has requested, by id.
    timers: HashMap<TimerId, Timestamp>,
    keepalive: Duration,
    /// The 48-bit MAC advertised in outbound GRE keepalives (informational).
    mac: [u8; 6],
    bitmask: bool,
    /// Records why the task exited, read by the handle once its channel closes.
    close: CloseFlag,
    /// The latest stats snapshot published to the handle's `stats()`.
    stats: StatsCell,
    /// Pre-routed inbound feed for a multi-flow demultiplexed receiver: when `Some`,
    /// the [`MultiReceiver`](crate::MultiReceiver) demultiplexer owns the path readers
    /// and routes this flow's datagrams in, so [`run`](Self::run) spawns none itself.
    /// `None` for a self-driven session (it spawns its own per-path readers).
    injected: Option<mpsc::Receiver<Inbound>>,

    // --- sender half ---
    app_in: Option<mpsc::Receiver<Bytes>>,
    /// Runtime `(path_index, weight)` commands from `Sender::set_weight` (sender
    /// only). `None` on a receiver.
    weight_cmd: Option<mpsc::Receiver<(u8, u32)>>,
    /// Runtime null-packet-deletion toggle from `Sender::set_null_packet_deletion`;
    /// `Some` only on a Main-profile bonded sender (NPD is Main-only). Applied to every
    /// path's codec so the 2022-7 copies stay identical.
    npd_cmd: Option<mpsc::Receiver<bool>>,
    /// Runtime bonded-path add/remove commands from `Sender::add_path`/`remove_path`
    /// (libRIST `rist_peer_create`/`_destroy`); `Some` only on a bonded sender.
    peer_cmd: Option<mpsc::Receiver<PeerCmd>>,
    /// Builds a runtime-added path's transport+codec state, invoked on a
    /// [`PeerCmd::Add`]: a sender path (shared socket + remote) or a receiver path (a
    /// freshly-bound listen socket). `None` when runtime add is unavailable.
    path_factory: Option<PathFactory>,
    /// A retained inbound-channel sender for a runtime-add-capable receiver, so a
    /// [`PeerCmd::Add`] can spawn a reader feeding the same channel. `None` on a sender
    /// or a non-add-capable / injected receiver.
    inbound_tx: Option<mpsc::Sender<Inbound>>,
    /// The host connection accept/reject + disconnect gate (libRIST `rist_auth_handler_set`),
    /// fired once when the bonded session first authenticates. A no-op without callbacks.
    auth: crate::driver_main::AuthGate,
    /// Whether the connect callback has already fired (the session's first path to
    /// authenticate); the bonded session connects once even though paths auth per-path.
    ever_connected: bool,
    /// The highest first-transmission sequence sent (shared across paths — the RTP
    /// sequence space is one stream), the NACK-widening reference.
    highest_sent: u32,
    /// The local flow SSRC (stamped into the SR/echo).
    ssrc: u32,

    // --- receiver half ---
    data_out: Option<mpsc::Sender<Bytes>>,
    /// Runtime receiver-control commands from the [`Receiver`](crate::Receiver) handle
    /// (`set_nack_type` / `set_rtt_multiplier`); `Some` only on a self-driven receiver.
    rx_ctrl: Option<mpsc::Receiver<RxControl>>,
    /// The media SSRC learned from the first inbound packet (one stream, any path).
    learned_ssrc: Option<u32>,

    /// TR-06-3 §9 sender Main fallback (config, off by default): start media in Main
    /// framing and upgrade to Advanced (Type=5) framing once a peer advertises
    /// Advanced capability. See [`crate::config::Config::adv_sender_start_main`].
    adv_sender_start_main: bool,
    /// Whether a peer has advertised Advanced capability via a keep-alive I bit; gates
    /// the §9 framing upgrade when `adv_sender_start_main` is set. A bonded sender
    /// upgrades the whole flow once any path's peer advertises it.
    remote_supports_advanced: bool,

    // --- forward error correction (TR-06-2 §8.4, separate-port over bonding) ---
    /// One shared FEC engine across all paths: the sender clips each first-tx payload
    /// once and fans the FEC across the paths; every path's media and FEC feed the one
    /// decoder, which dedups the 2022-7 duplication and recovers loss that struck every
    /// path at once. `None` when FEC is off.
    fec: Option<FecState>,
    /// The weighted path the most recent media datagram was routed to, reused for that
    /// datagram's FEC fan (so FEC follows media without spending a second rotation
    /// credit). `None` for full-redundancy (every path is a duplicate target).
    last_weighted: Option<u8>,
    /// The source-adaptation Link Quality Message emitter (TR-06-4 Part 1); `Some` on
    /// a bonded receiver with source adaptation enabled. The Global LQM is fanned out
    /// every live path with one shared sequence number (§5.5).
    lqm: Option<LqmEmitter>,
    /// The shared Advanced-profile media codec, `Some` on an Advanced bonded flow. The
    /// per-path [`MainCodec`] still carries the GRE substrate (EAP / RTCP handshake);
    /// Advanced media, keepalive, and NACK feedback are adv-framed through this one
    /// shared codec (encode once, fan to every path; the 2022-7 merge dedups on
    /// receive). `None` for a Main-profile bonded flow.
    adv: Option<AdvCodec>,
    /// The source-adaptation rate controller; `Some` on a bonded sender with a rate
    /// callback configured. It folds each inbound LQM into a target bitrate and invokes
    /// the application's `on_rate_adapt` callback.
    rate: Option<RateControl>,
    /// The sender's packet-split bonding mode (libRIST `split=`); [`SplitMode::Off`]
    /// on a receiver. Each split half fans out across the paths like any media packet.
    split_mode: SplitMode,
    /// The packet-merge state machine (libRIST `merge=`) folding split pairs after the
    /// shared flow's 2022-7 merge; [`MergeMode::Off`] on a sender. In `merge=auto` mode
    /// it is enabled by any path's inbound keepalive L bit.
    merger: Merger,
}

impl BondedDriver {
    /// Builds and spawns a bonded sender driver fanning media out across `paths`,
    /// returning the application payload channel and the driver task handle. The
    /// `group` must already have one path registered per entry in `paths` (same
    /// index order).
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_sender(
        flow: Flow,
        group: Group,
        paths: Vec<PathParts>,
        ssrc: u32,
        mac: [u8; 6],
        bitmask: bool,
        keepalive: Duration,
        start_seq: u32,
        weight_rx: mpsc::Receiver<(u8, u32)>,
        rate: Option<RateControl>,
        adv: Option<AdvCodec>,
        fec: Option<FecState>,
        split_mode: SplitMode,
        npd_cmd: Option<mpsc::Receiver<bool>>,
        peer_cmd: mpsc::Receiver<PeerCmd>,
        path_factory: PathFactory,
        opts: AdvOpts,
    ) -> (
        mpsc::Sender<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = BondedDriver {
            sender: true,
            flow,
            group,
            paths: link_paths(paths),
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            mac,
            bitmask,
            close: close.clone(),
            stats: stats.clone(),
            injected: None,
            app_in: Some(rx),
            weight_cmd: Some(weight_rx),
            npd_cmd,
            peer_cmd: Some(peer_cmd),
            path_factory: Some(path_factory),
            inbound_tx: None, // sender shares one socket; runtime add needs no reader
            auth: crate::driver_main::AuthGate::new(None, None), // a sender does not gate connects
            ever_connected: false,
            highest_sent: start_seq,
            ssrc,
            data_out: None,
            rx_ctrl: None, // a sender takes no receiver-control commands
            learned_ssrc: None,
            adv_sender_start_main: opts.adv_sender_start_main,
            remote_supports_advanced: false,
            fec,
            last_weighted: None,
            lqm: None, // a sender does not emit LQM
            adv,
            rate,
            split_mode,
            merger: Merger::new(MergeMode::Off),
        };
        (tx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns a bonded receiver driver merging media from `paths` (each
    /// a distinct local port), returning the delivered-data channel and the driver
    /// task handle.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_receiver(
        flow: Flow,
        group: Group,
        paths: Vec<PathParts>,
        ssrc: u32,
        mac: [u8; 6],
        bitmask: bool,
        keepalive: Duration,
        lqm: Option<LqmEmitter>,
        adv: Option<AdvCodec>,
        fec: Option<FecState>,
        merge_mode: MergeMode,
        rx_ctrl: mpsc::Receiver<RxControl>,
        peer_cmd: Option<mpsc::Receiver<PeerCmd>>,
        path_factory: Option<PathFactory>,
        auth: crate::driver_main::AuthGate,
        opts: AdvOpts,
    ) -> (
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = BondedDriver {
            sender: false,
            flow,
            group,
            paths: link_paths(paths),
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            mac,
            bitmask,
            close: close.clone(),
            stats: stats.clone(),
            injected: None,
            app_in: None,
            weight_cmd: None,
            npd_cmd: None, // a receiver does not delete null packets
            peer_cmd,
            path_factory,
            inbound_tx: None, // run() retains the inbound sender when add-capable
            auth,
            ever_connected: false,
            highest_sent: 0,
            ssrc,
            data_out: Some(tx),
            rx_ctrl: Some(rx_ctrl),
            learned_ssrc: None,
            adv_sender_start_main: opts.adv_sender_start_main,
            remote_supports_advanced: false,
            fec,
            last_weighted: None,
            lqm,
            adv,
            rate: None, // a receiver does not consume LQM
            split_mode: SplitMode::Off,
            merger: Merger::new(merge_mode),
        };
        (rx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns an **injected** bonded receiver driver for a multi-flow
    /// [`MultiReceiver`](crate::MultiReceiver): like [`spawn_receiver`](Self::spawn_receiver)
    /// but it spawns no path readers of its own. The demultiplexer owns the `N`
    /// path sockets, reads them, and routes this source's datagrams (tagged with
    /// their path index) into the returned [`Inbound`] channel; the driver still
    /// sends its handshakes, keepalives, and feedback out through the [`PathParts`]
    /// socket clones. Multi-flow demux rejects FEC, so there is no FEC engine.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_injected_receiver(
        flow: Flow,
        group: Group,
        paths: Vec<PathParts>,
        ssrc: u32,
        mac: [u8; 6],
        bitmask: bool,
        keepalive: Duration,
        adv: Option<AdvCodec>,
        merge_mode: MergeMode,
        opts: AdvOpts,
    ) -> (
        mpsc::Sender<Inbound>,
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (data_tx, data_rx) = mpsc::channel(DATA_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = BondedDriver {
            sender: false,
            flow,
            group,
            paths: link_paths(paths),
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            mac,
            bitmask,
            close: close.clone(),
            stats: stats.clone(),
            injected: Some(in_rx),
            app_in: None,
            weight_cmd: None,
            npd_cmd: None,
            peer_cmd: None,
            path_factory: None,
            inbound_tx: None,
            auth: crate::driver_main::AuthGate::new(None, None),
            ever_connected: false,
            highest_sent: 0,
            ssrc,
            data_out: Some(data_tx),
            // A demuxed per-flow bonded receiver has no settable handle.
            rx_ctrl: None,
            learned_ssrc: None,
            adv_sender_start_main: opts.adv_sender_start_main,
            remote_supports_advanced: false,
            fec: None,
            last_weighted: None,
            lqm: None, // multi-flow bonded LQM emission is deferred
            adv,
            rate: None,
            split_mode: SplitMode::Off,
            merger: Merger::new(merge_mode),
        };
        (in_tx, data_rx, close, stats, tokio::spawn(driver.run()))
    }

    /// The current session-relative instant.
    #[allow(clippy::cast_possible_truncation)] // session durations fit u64 micros
    fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.epoch.elapsed().as_micros() as u64)
    }

    /// The tokio deadline for a session-relative timestamp.
    fn deadline(&self, ts: Timestamp) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.epoch + Duration::from_micros(ts.as_micros()))
    }

    /// The driver loop. One reader task per path funnels inbound datagrams into a
    /// single channel; the pump selects over that channel, the application input,
    /// the timer wheel, and the keepalive tick.
    // A flat reader-setup + `select!` pump: one arm per input source (inbound, media,
    // the runtime command channels, timer, keepalive). Splitting it would scatter the loop.
    #[allow(clippy::too_many_lines)]
    async fn run(mut self) {
        let mut readers = Vec::new();
        let mut in_rx = if let Some(rx) = self.injected.take() {
            // Multi-flow demux: the demultiplexer owns the path readers and routes
            // this source's datagrams (tagged by path index) into `rx`; spawn none.
            rx
        } else {
            let (in_tx, in_rx) = mpsc::channel::<Inbound>(INBOUND_CAPACITY);
            if self.sender {
                // The sender shares one source socket across all paths: a single reader
                // funnels its inbound (the path is resolved by source in `on_recv`).
                readers.push(spawn_reader(0, self.paths[0].socket.clone(), in_tx.clone()));
                drop(in_tx); // the sender holds no inbound sender; the reader keeps it open
            } else {
                // The receiver binds one socket per path: one reader each, owned by the
                // path so a runtime `remove_path` can abort it.
                for i in 0..self.paths.len() {
                    let h = spawn_reader(
                        self.paths[i].index,
                        self.paths[i].socket.clone(),
                        in_tx.clone(),
                    );
                    self.paths[i].reader = Some(h);
                }
                if self.path_factory.is_some() {
                    // An add-capable receiver retains the inbound sender so a runtime
                    // `add_path` can spawn a reader feeding the same channel. The channel
                    // then no longer closes on reader exhaustion; shutdown rides the
                    // session-timeout (`all_expired`) path instead.
                    self.inbound_tx = Some(in_tx);
                } else {
                    drop(in_tx); // readers keep the channel open; closes on exhaustion
                }
            }
            in_rx
        };

        // A sender knows every path's peer up front: greet each (the RTCP SDES that
        // ungates libRIST's media, plus the GRE MAC beacon) and open each path's
        // EAP-SRP handshake before media flows.
        if self.sender {
            let now = self.now();
            for i in 0..self.paths.len() {
                self.greet(i, now).await;
                self.send_eap_start(i).await;
            }
        }

        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        // Initial status (no-EAP paths are authenticated immediately).
        self.stats.set_authenticated(self.all_authed());

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            // Media is gated until every path's data channel is open; recompute each
            // iteration since EAP can flip a path to authenticated mid-loop.
            let authed = self.all_authed();
            tokio::select! {
                msg = in_rx.recv() => match msg {
                    Some(inb) => {
                        self.on_recv(inb).await;
                        // The host connect callback rejected the session's first
                        // authenticated peer: tear the bonded session down.
                        if self.auth.rejected() {
                            self.close.set_auth();
                            break;
                        }
                    }
                    None => break, // every path reader has exited
                },
                // Hold outbound media until every path's data channel is open (a
                // no-op when authentication is disabled — `authed` is then true).
                payload = recv_app_gated(&mut self.app_in, authed) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.push_split(now, p);
                        self.drain(now).await;
                    }
                    None => break, // sender's app channel closed: shut down
                },
                // Runtime load-share re-balancing from `Sender::set_weight`.
                cmd = recv_weight(&mut self.weight_cmd) => match cmd {
                    Some((index, weight)) => self.group.set_weight(index, weight),
                    // The command channel closed: stop watching it (the dropped
                    // Sender handle also closes the app channel, which breaks above).
                    None => self.weight_cmd = None,
                },
                // Runtime NPD toggle (`Sender::set_null_packet_deletion`): apply to
                // every path codec so the 2022-7 duplicates stay byte-identical.
                on = recv_opt(&mut self.npd_cmd) => match on {
                    Some(on) => for link in &mut self.paths { link.codec.set_npd(on); },
                    None => self.npd_cmd = None,
                },
                // Runtime bonded-path add/remove (`Sender::add_path`/`remove_path`).
                pc = recv_opt(&mut self.peer_cmd) => match pc {
                    Some(c) => self.apply_peer_cmd(c),
                    None => self.peer_cmd = None,
                },
                // Runtime receiver setters (`set_nack_type` / `set_rtt_multiplier`).
                ctrl = recv_opt(&mut self.rx_ctrl) => match ctrl {
                    Some(c) => c.apply(&mut self.bitmask, &mut self.flow),
                    None => self.rx_ctrl = None,
                },
                () = sleep_until_opt(timer_at) => {
                    let now = self.now();
                    self.fire_timers(now);
                    self.drain(now).await;
                },
                _ = keepalive.tick() => {
                    let now = self.now();
                    if self.all_expired(now) {
                        self.close.set_session_timeout();
                        break;
                    }
                    let _ = self.group.tick(now); // advance liveness (deaths logged below)
                    for i in 0..self.paths.len() {
                        if self.paths[i].peer.media().is_some() {
                            self.send_handshake(i, now).await;
                            self.send_keepalive(i, now).await;
                        }
                    }
                    // Source adaptation: fan a Global LQM out every live path when a
                    // reporting period has elapsed (receiver only).
                    self.maybe_emit_lqm(now).await;
                    // Publish session status for the handle's authenticated()/ssrc().
                    self.stats.set_authenticated(self.all_authed());
                    if let Some(s) = self.learned_ssrc {
                        self.stats.set_ssrc(s);
                    }
                },
            }
        }

        for r in readers {
            r.abort();
        }
        // Abort each receiver path's owned reader (runtime-added or initial).
        for p in &mut self.paths {
            if let Some(r) = p.reader.take() {
                r.abort();
            }
        }
        // Notify the host that a connected bonded session ended (libRIST disconn_cb).
        self.auth.disconnected();
    }

    /// Decodes one adv-framed (Advanced media / keepalive / NACK) datagram through the
    /// shared adv codec, feeding media and feedback into the flow. Returns `true` when
    /// the datagram was adv-framed (and thus consumed here), `false` when it is not
    /// Advanced or not adv-framed (a raw GRE substrate datagram for the caller to
    /// handle). The 2022-7 merge dedups copies arriving on other paths.
    fn handle_adv_inbound(&mut self, now: Timestamp, path_id: u8, data: &Bytes) -> bool {
        if self.adv.is_none() || !is_adv_framed(data) {
            return false;
        }
        match self.adv.as_mut().unwrap().decode(data) {
            Ok(Decoded::Media(pkt)) => {
                if self.learned_ssrc.is_none() {
                    self.learned_ssrc = Some(pkt.ssrc);
                }
                if let Some(e) = self.lqm.as_mut() {
                    e.meter(pkt.payload.len(), pkt.retransmit);
                }
                self.group.count_recv(path_id, pkt.payload.len());
                self.flow.feed(now, path_id, pkt);
            }
            Ok(Decoded::Feedback(fbs)) => {
                for fb in fbs {
                    if let Feedback::LinkQuality { lqm } = fb {
                        if let Some(r) = &mut self.rate {
                            r.handle(&lqm);
                        }
                    } else {
                        self.observe_path_rtt(path_id, now, &fb);
                        self.flow.feed_feedback(now, fb);
                    }
                }
            }
            Ok(_) => {} // adv keepalive / control: liveness only (recorded by the caller)
            Err(e) => {
                let psk = self.adv.as_ref().unwrap().has_psk();
                crate::driver::decode_warn(psk, "bonded adv", &e);
            }
        }
        // TR-06-3 §9: a native Advanced keep-alive's I bit advertises the peer's
        // Advanced capability, upgrading the bonded sender's media framing to Advanced.
        if let Some(true) = self.adv.as_mut().and_then(AdvCodec::take_peer_adv_cap) {
            self.remote_supports_advanced = true;
        }
        true
    }

    /// Handles one inbound datagram: learns its path's peer and liveness, then routes
    /// it as EAP, keepalive, media, or feedback. The receiver tags each datagram with
    /// the path (its bound socket); the sender shares one source socket across all
    /// paths, so it resolves the path from the source address (each path's peer is a
    /// distinct remote).
    // A flat inbound dispatcher (path resolution + EAP/keepalive/media/feedback/FEC
    // demux); splitting it would only scatter the one linear decision tree.
    #[allow(clippy::too_many_lines)]
    async fn on_recv(&mut self, inb: Inbound) {
        let now = self.now();
        let i = if self.sender {
            match self
                .paths
                .iter()
                .position(|p| p.peer.media() == Some(inb.src))
            {
                Some(i) => i,
                None => return, // a datagram from an unknown source: drop
            }
        } else {
            inb.index as usize
        };
        if i >= self.paths.len() {
            return;
        }
        // The `u8` path index (paths are registered with `u8` indices, so `i` — bounded
        // by `paths.len()` above — always fits); used for the group/flow path arguments.
        let path_id = u8::try_from(i).unwrap_or(u8::MAX);
        // A separate-port FEC datagram bypasses the GRE demux and feeds the shared FEC
        // decoder directly (liveness rides on the GRE socket's media/control).
        if inb.kind == InboundKind::Fec {
            self.on_bond_fec(now, &inb.data).await;
            return;
        }
        self.paths[i].peer.learn_media(inb.src);
        self.paths[i].peer.observe(now);
        self.group.observe(path_id, now);

        // On first learning this path's peer (the receiver's case), greet it so
        // libRIST ungates its media toward us promptly.
        if !self.paths[i].greeted && self.paths[i].peer.media().is_some() {
            self.greet(i, now).await;
        }

        // EAP-SRP frames (GRE EAPOL, never encrypted) drive the handshake, not the
        // flow. Copy the payload out so the codec borrow ends before driving it.
        if let Some(payload) = self.paths[i]
            .codec
            .peek_eapol(&inb.data)
            .map(<[u8]>::to_vec)
        {
            self.handle_eap(i, &payload).await;
            self.drain(now).await;
            return;
        }

        // Drop non-EAPOL flow input on a path that has not completed its EAP-SRP
        // handshake (per-path authentication gate). A no-op without auth.
        if !self.paths[i].authed {
            self.drain(now).await;
            return;
        }

        // Advanced media / keepalive / NACK feedback are adv-framed through the shared
        // adv codec; the GRE substrate (EAP above, RTCP handshake below) stays raw GRE
        // on the per-path main codec.
        if self.handle_adv_inbound(now, path_id, &inb.data) {
            self.drain(now).await;
            return;
        }

        // A GRE keepalive is a liveness signal only — nothing for the flow, except its
        // L bit drives merge=auto (the peer advertises pair-split on this path).
        let (kind, ka, _ver) = self.paths[i].codec.peek_control(&inb.data);
        if kind == ControlKind::Keepalive {
            if let Some(ka) = &ka {
                self.merger.set_auto_enabled(ka.caps.l);
                // TR-06-3 §9: the GRE keep-alive's extended I bit advertises Advanced
                // capability, upgrading the bonded sender's media framing to Advanced.
                if ka.has_adv_ext && ka.adv_ext.i {
                    self.remote_supports_advanced = true;
                }
            }
        } else {
            match self.paths[i].codec.decode(&inb.data, self.highest_sent) {
                Ok(Decoded::Media(pkt)) => {
                    if self.learned_ssrc.is_none() {
                        self.learned_ssrc = Some(pkt.ssrc);
                    }
                    // FEC over the inner RTP payload: feed it (keyed on the raw wire
                    // timestamp) to the shared decoder, which dedups copies from the
                    // other paths by sequence, before the flow takes the payload.
                    let fec_input = self.fec.is_some().then(|| {
                        (
                            pkt.seq,
                            self.paths[i].codec.last_wire_ts(),
                            pkt.ssrc,
                            pkt.payload.clone(),
                        )
                    });
                    // Meter the merged stream's RTP bytes for the LQM bandwidth fields
                    // before the packet is consumed.
                    if let Some(e) = self.lqm.as_mut() {
                        e.meter(pkt.payload.len(), pkt.retransmit);
                    }
                    // Feed on this path's index: the one ring dedups copies from the
                    // other paths by `(seq, source_time)`.
                    self.group.count_recv(path_id, pkt.payload.len());
                    self.flow.feed(now, path_id, pkt);
                    if let Some((seq, wts, ssrc, payload)) = fec_input {
                        let recovered = self
                            .fec
                            .as_mut()
                            .unwrap()
                            .recv_media(seq, wts, FEC_PT, ssrc, payload);
                        self.feed_fec_recovered(now, recovered);
                    }
                }
                Ok(Decoded::Feedback(fbs)) => {
                    for fb in fbs {
                        // A Link Quality Message is a host-level source-adaptation
                        // signal: drive the rate controller, never the flow core.
                        if let Feedback::LinkQuality { lqm } = fb {
                            if let Some(r) = &mut self.rate {
                                r.handle(&lqm);
                            }
                        } else {
                            self.observe_path_rtt(path_id, now, &fb);
                            self.flow.feed_feedback(now, fb);
                        }
                    }
                }
                // A peer's buffer-negotiation feeds the shared flow's auto-scaler (a
                // non-zero sender-max). ristgo does not originate buffer negotiation
                // from a bonded sender — the per-path max is ill-defined across paths
                // — but a bonded receiver still consumes an inbound advert.
                Ok(Decoded::BufferNeg(bn)) => {
                    if let Some(max) = bn.sender_max() {
                        self.flow.set_sender_max_buffer(max);
                    }
                }
                Ok(Decoded::Ignored) => {}
                Err(e) => {
                    crate::driver::decode_warn(self.paths[i].codec.has_psk(), "bonded main", &e);
                }
            }
        }
        self.drain(now).await;
    }

    /// Drains every pending flow effect once: media fans out to all live
    /// duplicate-weight paths, feedback routes to the selected NACK path, timers
    /// update the wheel, delivered payloads are queued for the application.
    async fn drain(&mut self, now: Timestamp) {
        let mut fbs = Vec::new();
        while let Some(out) = self.flow.poll_output() {
            match out {
                Output::SendMedia { pkt, .. } => {
                    if !pkt.retransmit && seq_after(pkt.seq, self.highest_sent) {
                        self.highest_sent = pkt.seq;
                    }
                    // The 2022-7 fan: the identical (seq, source_time) packet on every
                    // live duplicate-weight path, plus one elected weighted load-share
                    // path (disjoint, so no path is sent it twice).
                    let targets = self.group.duplicate_targets(now);
                    let weighted = self.group.select_weighted(now);
                    self.last_weighted = weighted;
                    // Advanced encodes the media ONCE via the shared adv codec and fans
                    // the identical bytes; Main encodes per-path (each path's GRE
                    // sequence differs). TR-06-3 §9 (opt-in): until a peer advertises
                    // Advanced (I=1), force the per-path Main path so a Main-only bonded
                    // receiver can decode it — the same path the pure-Main fan uses.
                    // Skipped when FEC is configured (an Advanced-only feature a Main-only
                    // peer cannot consume).
                    let use_main_fallback = self.adv_sender_start_main
                        && !self.remote_supports_advanced
                        && self.fec.is_none();
                    let adv_bytes = if use_main_fallback {
                        None
                    } else {
                        self.adv.as_mut().map(|a| a.encode_media(&pkt))
                    };
                    match adv_bytes {
                        Some(Ok(bytes)) => {
                            let bytes = Bytes::from(bytes);
                            for idx in targets {
                                self.send_bytes_on(idx as usize, &bytes).await;
                            }
                            if let Some(idx) = weighted {
                                self.send_bytes_on(idx as usize, &bytes).await;
                            }
                        }
                        Some(Err(e)) => {
                            tracing::debug!(target: crate::logging::SOCKET, seq = pkt.seq, "rist: bonded adv encode media failed: {e}");
                        }
                        None => {
                            for idx in targets {
                                self.send_media_on(idx as usize, &pkt).await;
                            }
                            if let Some(idx) = weighted {
                                self.send_media_on(idx as usize, &pkt).await;
                            }
                            // FEC follows the same fan as media (Main separate-port FEC;
                            // in-band FEC over bonded Advanced is deferred).
                            if self.fec.is_some() && !pkt.retransmit {
                                self.send_bond_fec(now, &pkt).await;
                            }
                        }
                    }
                }
                Output::SendFeedback { fb, .. } => fbs.push(fb),
                Output::SetTimer { id, deadline } => {
                    self.timers.insert(id, deadline);
                }
                Output::ClearTimer { id } => {
                    self.timers.remove(&id);
                }
            }
        }
        if !fbs.is_empty() {
            self.send_feedback(&fbs, now).await;
        }
        // Clone the data channel so the merge loop does not borrow `&self` across the
        // `await` (the per-path EAP roles make `BondedDriver` non-`Sync`).
        let out = self.data_out.clone();
        while let Some(Event::Deliver {
            seq,
            source_time,
            payload,
            discontinuity,
            ..
        }) = self.flow.poll_event()
        {
            for p in self
                .merger
                .deliver(seq, source_time, payload, discontinuity)
                .payloads()
            {
                if let Some(o) = &out
                    && o.send(p).await.is_err()
                {
                    return; // the application Receiver was dropped
                }
            }
        }
        let peers = self
            .group
            .peer_snapshots(now)
            .into_iter()
            .map(PeerStats::from)
            .collect();
        let core = self.flow.stats();
        let (profile, adv_active) = self.framing_meta(&core);
        self.stats.set_framing(profile, adv_active);
        self.stats.publish_peers(core, self.fec_recovered(), peers);
    }

    /// The profile discriminant (1 main, 2 advanced) and whether Advanced framing is
    /// active, for the Prometheus `*_info` series. Bonded carries Main (`adv = None`)
    /// or Advanced (`adv = Some`) framing.
    fn framing_meta(&self, core: &rist_core::flow::Stats) -> (u8, bool) {
        if self.adv.is_some() {
            let active = advanced_framing_active(
                self.sender,
                self.adv_sender_start_main,
                self.remote_supports_advanced,
                core,
            );
            (2, active)
        } else {
            (1, false)
        }
    }

    /// Applies one runtime bonded-path command (libRIST `rist_peer_create`/`_destroy`)
    /// to the live sender path set. `Add` builds the new path (shared source socket, a
    /// fresh codec + EAP role) via the path factory and registers it with the group so
    /// the next media fan-out reaches it; `Remove` drops it from the paths and the group
    /// (the shared socket stays alive for the others). Duplicate adds and unknown removes
    /// are ignored; the new path greets and (if EAP) authenticates on the next keepalive.
    fn apply_peer_cmd(&mut self, cmd: PeerCmd) {
        match cmd {
            PeerCmd::Add {
                index,
                addr,
                weight,
                priority,
            } => {
                if self.paths.iter().any(|p| p.index == index) {
                    return; // duplicate index: ignore (matches Group::add_path)
                }
                let Some(factory) = self.path_factory.as_mut() else {
                    return;
                };
                match factory(addr) {
                    Ok(parts) => {
                        let mut link = link_path_at(index, parts);
                        // A receiver path owns its socket, so spawn a reader feeding the
                        // shared inbound channel (the sender's shared reader already covers
                        // its added remotes).
                        if let Some(tx) = &self.inbound_tx {
                            link.reader =
                                Some(spawn_reader(index, link.socket.clone(), tx.clone()));
                        }
                        self.paths.push(link);
                        self.group.add_path(index, weight, priority);
                        tracing::debug!(target: crate::logging::BONDING, %addr, index, "rist: bonded path added at runtime");
                    }
                    Err(e) => {
                        tracing::warn!(target: crate::logging::BONDING, %addr, "rist: bonded add_path failed: {e}");
                    }
                }
            }
            PeerCmd::Remove { index } => {
                if let Some(pos) = self.paths.iter().position(|p| p.index == index) {
                    if let Some(r) = self.paths[pos].reader.take() {
                        r.abort(); // stop the removed receiver path's reader
                    }
                    self.paths.remove(pos);
                }
                self.group.remove_path(index);
                tracing::debug!(target: crate::logging::BONDING, index, "rist: bonded path removed at runtime");
            }
        }
    }

    /// Folds a per-path RTT sample into the bonding group when `fb` is an RTT-echo
    /// response (the same `now - echoed - processing_delay` measure the flow core uses
    /// for its aggregate estimator), so the per-peer stats and NACK-peer tie-break see
    /// a real per-path RTT. A no-op for any other feedback.
    fn observe_path_rtt(&mut self, path_id: u8, now: Timestamp, fb: &Feedback) {
        if let Feedback::RttEchoResponse {
            timestamp,
            processing_delay,
            ..
        } = fb
        {
            let sent = Ntp64::from_bits(*timestamp).to_timestamp();
            let sample = (now - sent) - Micros::from_micros(i64::from(*processing_delay));
            self.group.observe_rtt(path_id, sample);
        }
    }

    /// Splits one outbound application payload across a consecutive even/odd sequence
    /// pair (libRIST `split=`) when split mode is active, else pushes it whole. Each
    /// half then fans out across the bonded paths like any media packet (full
    /// redundancy or weighted load-share, per the bonding policy).
    fn push_split(&mut self, now: Timestamp, payload: Bytes) {
        let (first, last) = split::split_payload(self.split_mode, payload);
        self.flow.push_app(now, first);
        if let Some(last) = last {
            self.flow.push_app(now, last);
        }
    }

    /// The cumulative FEC-recovered count (0 when FEC is off), for `Stats` and LQM.
    fn fec_recovered(&self) -> u64 {
        self.fec.as_ref().map_or(0, FecState::recovered)
    }

    /// Clips one first-transmission media packet's (NPD-canonicalized) inner RTP
    /// payload into the shared FEC matrix and fans any completed FEC packets — RTP-
    /// wrapped (PT 127) on the column (path media + 2) / row (+ 4) ports — across the
    /// same paths the media went to (every live duplicate path plus the elected
    /// weighted path). The receiver's one decoder dedups the cross-path duplication.
    async fn send_bond_fec(&mut self, now: Timestamp, pkt: &MediaPacket) {
        // The FEC payload canonicalization (NPD §8.6.2) is config-driven, identical on
        // every path; use path 0's codec.
        let fpay = self.paths[0].codec.fec_payload(&pkt.payload);
        let ts = codec::rtp_ts_from_source(pkt.source_time);
        let variant = self
            .fec
            .as_ref()
            .expect("fec present (checked by caller)")
            .variant();
        let fps = self
            .fec
            .as_mut()
            .expect("fec present (checked by caller)")
            .clip(pkt.seq, ts, FEC_PT, &fpay);
        if fps.is_empty() {
            return;
        }
        // The fan set: every live duplicate target plus the weighted path this media
        // datagram was routed to (reused, not re-elected, to avoid spending a credit).
        let mut targets = self.group.duplicate_targets(now);
        if let Some(w) = self.last_weighted
            && !targets.contains(&w)
        {
            targets.push(w);
        }
        let ssrc = self.ssrc;
        for fp in &fps {
            let (rtp_seq, port_off) = match fp.direction {
                Direction::Column => (
                    self.fec.as_mut().unwrap().next_col_seq(),
                    FEC_COLUMN_PORT_OFFSET,
                ),
                Direction::Row => (
                    self.fec.as_mut().unwrap().next_row_seq(),
                    FEC_ROW_PORT_OFFSET,
                ),
            };
            let rtp_pkt = rtp::Packet {
                header: rtp::Header {
                    version: rtp::VERSION,
                    payload_type: FEC_PT,
                    sequence_number: rtp_seq,
                    ssrc,
                    ..rtp::Header::default()
                },
                payload: fec_header::encode(fp, variant),
                padding_size: 0,
            };
            let Ok(bytes) = rtp_pkt.encode() else {
                continue;
            };
            for &idx in &targets {
                let i = idx as usize;
                if i >= self.paths.len() || !self.paths[i].authed {
                    continue;
                }
                let Some(media_dst) = self.paths[i].peer.media() else {
                    continue;
                };
                let mut dst = media_dst;
                dst.set_port(media_dst.port().wrapping_add(port_off));
                let sock = self.paths[i].socket.clone();
                if let Err(e) = sock.send(&bytes, dst).await {
                    tracing::debug!(target: crate::logging::SOCKET, path = i, "rist: bonded send fec failed: {e}");
                }
            }
        }
    }

    /// Handles one inbound separate-port FEC datagram (from any path): strips the RTP
    /// wrapper to the FEC body, feeds it to the shared decoder, and re-injects any
    /// recovered packet into the flow.
    async fn on_bond_fec(&mut self, now: Timestamp, data: &[u8]) {
        let Ok(p) = rtp::Packet::decode(&Bytes::copy_from_slice(data)) else {
            return;
        };
        if self.fec.is_some() {
            let recovered = self.fec.as_mut().unwrap().recv_fec(&p.payload);
            self.feed_fec_recovered(now, recovered);
        }
        self.drain(now).await;
    }

    /// Re-injects FEC-recovered packets into the flow as media, reconstructing each
    /// source time (non-advancing) from the recovered RTP timestamp. The mapping is
    /// timestamp-based and path-independent within the window, so path 0's codec
    /// suffices regardless of which path the FEC arrived on.
    fn feed_fec_recovered(&mut self, now: Timestamp, recovered: Vec<Recovered>) {
        for r in recovered {
            let source_time = self.paths[0].codec.fec_source_time(r.timestamp);
            self.flow.feed(
                now,
                0,
                MediaPacket {
                    seq: r.seq,
                    source_time,
                    ssrc: r.ssrc,
                    payload: r.payload,
                    retransmit: false,
                    path_id: 0,
                    frag: FragRole::Standalone,
                    short_seq: true, // FEC: reconstructed from 16-bit RTP fields
                    // FEC-recovered packets carry no virtual ports (not in the matrix).
                    ..Default::default()
                },
            );
        }
    }

    /// Encodes and transmits one media packet on path `i`, if it is addressed and
    /// authenticated.
    /// Sends pre-encoded media `bytes` on path `i` (the Advanced encode-once-fan path;
    /// the bytes are the shared adv codec's output). A no-op until the path is
    /// authenticated and its peer is known.
    async fn send_bytes_on(&mut self, i: usize, bytes: &Bytes) {
        if !self.paths[i].authed {
            return;
        }
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        let sock = self.paths[i].socket.clone();
        if let Err(e) = sock.send(bytes, dst).await {
            tracing::debug!(target: crate::logging::SOCKET, path = i, "rist: bonded send media bytes failed: {e}");
        }
    }

    async fn send_media_on(&mut self, i: usize, pkt: &rist_core::wire::MediaPacket) {
        if !self.paths[i].authed {
            return;
        }
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        match self.paths[i].codec.encode_media(pkt) {
            Ok(bytes) => {
                // Per-path sent stat (libRIST per-peer): count the media handed to this
                // path's socket, split first-tx vs retransmit. (The shared-adv-codec fan
                // and FEC fan are not metered per path.)
                self.group.count_sent(
                    u8::try_from(i).unwrap_or(u8::MAX),
                    pkt.payload.len(),
                    pkt.retransmit,
                );
                let sock = self.paths[i].socket.clone();
                if let Err(e) = sock.send(&bytes, dst).await {
                    tracing::debug!(
                        target: crate::logging::SOCKET,
                        seq = pkt.seq,
                        path = i,
                        "rist: bonded send media failed: {e}"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    target: crate::logging::SOCKET,
                    seq = pkt.seq,
                    path = i,
                    "rist: bonded encode media failed: {e}"
                );
            }
        }
    }

    /// Builds one compound RTCP datagram from the drained feedback and transmits it
    /// on the selected NACK path (highest priority, then lowest raw RTT, among live
    /// addressable paths).
    async fn send_feedback(&mut self, fbs: &[Feedback], now: Timestamp) {
        let known: Vec<bool> = self
            .paths
            .iter()
            .map(|p| p.peer.media().is_some())
            .collect();
        let Some(idx) = self
            .group
            .select_nack_path(now, |i| known.get(i as usize).copied().unwrap_or(false))
        else {
            return; // no addressable path
        };
        let i = idx as usize;
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        // Advanced feedback (NACKs) is adv-framed through the shared adv codec (one or
        // more datagrams); Main feedback is a single GRE-framed RTCP compound.
        let adv_dgs = self
            .adv
            .as_mut()
            .map(|a| a.encode_feedback(fbs, self.bitmask, adv_ctrl_ts(now)));
        if let Some(result) = adv_dgs {
            match result {
                Ok(dgs) => {
                    let sock = self.paths[i].socket.clone();
                    for dg in dgs {
                        if let Err(e) = sock.send(&dg, dst).await {
                            tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded adv send feedback failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded adv encode feedback failed: {e}");
                }
            }
            return;
        }
        let lead = self.feedback_lead(now);
        match self.paths[i].codec.encode_feedback(lead, fbs, self.bitmask) {
            Ok(bytes) => {
                let sock = self.paths[i].socket.clone();
                if let Err(e) = sock.send(&bytes, dst).await {
                    tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded send feedback failed: {e}");
                }
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded encode feedback failed: {e}");
            }
        }
    }

    /// Sends path `i`'s initial handshake (RTCP SR/RR + SDES, plus the GRE MAC
    /// beacon) and marks it greeted.
    async fn greet(&mut self, i: usize, now: Timestamp) {
        self.send_handshake(i, now).await;
        self.send_keepalive(i, now).await;
        self.paths[i].greeted = true;
    }

    /// Sends one GRE-framed RTCP compound (the SR/RR lead + SDES, no feedback) on
    /// path `i` — the handshake libRIST gates inbound media on.
    async fn send_handshake(&mut self, i: usize, now: Timestamp) {
        if self.flow.config().no_recovery {
            return; // one-way: no control egress
        }
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        let lead = self.feedback_lead(now);
        if let Ok(bytes) = self.paths[i].codec.encode_feedback(lead, &[], self.bitmask) {
            let sock = self.paths[i].socket.clone();
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Sends a keepalive on path `i`: an adv-framed keepalive on an Advanced flow (the
    /// shared adv codec), or a GRE keepalive (MAC + standard capabilities) on Main.
    async fn send_keepalive(&mut self, i: usize, now: Timestamp) {
        if self.flow.config().no_recovery {
            return; // one-way: no control egress
        }
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        let bytes = if let Some(adv) = self.adv.as_mut() {
            adv.keepalive_datagram(adv_ctrl_ts(now))
        } else {
            // Advertise the pair-split capability (the L bit) when split mode is active
            // so a peer running `merge=auto` enables merging (Main bonded substrate).
            let mut caps = gre::Capabilities::standard();
            caps.l = self.split_mode != SplitMode::Off;
            let ka = gre::Keepalive {
                mac: self.mac,
                caps,
                ..gre::Keepalive::default()
            };
            self.paths[i].codec.encode_keepalive(&ka, gre::VERSION_MIN)
        };
        if let Ok(bytes) = bytes {
            let sock = self.paths[i].socket.clone();
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Emits one Link Quality Message (TR-06-4 Part 1) when a reporting period has
    /// elapsed, fanning the Global LQM out every live path with one shared sequence
    /// number (§5.5 — the message is built once). A no-op when source adaptation is
    /// off (sender, one-way, or not configured).
    async fn maybe_emit_lqm(&mut self, now: Timestamp) {
        if self.lqm.as_ref().is_none_or(|e| !e.due(now)) {
            return;
        }
        let ssrc = self.local_ssrc();
        let stats = self.flow.stats();
        let fec = self.fec_recovered();
        let lqm = self
            .lqm
            .as_mut()
            .expect("emitter present (checked above)")
            .build(now, &stats, fec);
        let lqr = LinkQualityReport {
            ssrc,
            lqm: lqm.encode(),
        };
        for i in 0..self.paths.len() {
            let Some(dst) = self.paths[i].peer.media() else {
                continue; // this path's return address is not learned yet
            };
            match self.paths[i].codec.encode_feedback(
                RtcpPacket::LinkQualityReport(lqr),
                &[],
                self.bitmask,
            ) {
                Ok(bytes) => {
                    let sock = self.paths[i].socket.clone();
                    if let Err(e) = sock.send(&bytes, dst).await {
                        tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded lqm send failed: {e}");
                    }
                }
                Err(e) => {
                    tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded lqm encode failed: {e}");
                }
            }
        }
    }

    /// Opens path `i`'s EAP-SRP handshake by sending EAPOL-START (authenticatee
    /// only).
    async fn send_eap_start(&mut self, i: usize) {
        let start = match self.paths[i].eap.as_mut() {
            Some(EapRole::Authenticatee(a)) => {
                let mut w = Vec::new();
                a.start().append_to(&mut w);
                w
            }
            _ => return,
        };
        self.send_eapol(i, &start).await;
    }

    /// Drives path `i`'s EAP role with one received payload, transmitting any reply
    /// and updating the path's authenticated gate; on the transition to
    /// authenticated with no PSK it re-keys that path to the SRP session key.
    async fn handle_eap(&mut self, i: usize, payload: &[u8]) {
        let was_authed = self.paths[i].authed;
        if self.paths[i].eap.is_none() {
            return;
        }
        let reply = self.paths[i].eap.as_mut().and_then(|r| r.recv(payload));
        self.paths[i].authed = self.paths[i]
            .eap
            .as_ref()
            .is_some_and(EapRole::authenticated);
        if let Some(wire) = reply {
            self.send_eapol(i, &wire).await;
        }
        if self.paths[i].authed && !was_authed {
            // The bonded session connects once: the host connect gate fires on the first
            // path to authenticate (all paths share the session's credentials). On reject
            // re-gate this path (its media is dropped) and let the loop tear the session
            // down on `auth.rejected()`.
            if !self.ever_connected {
                self.ever_connected = true;
                if !self.bonded_admit(i) {
                    self.paths[i].authed = false;
                    return;
                }
            }
            if !self.paths[i].codec.has_psk() {
                self.on_authenticated(i).await;
            }
        }
    }

    /// Offers path `i`'s just-authenticated peer to the host connect gate (libRIST
    /// `rist_auth_handler_set`): builds the [`ConnectInfo`] (the path's remote + SRP
    /// username) and returns whether it is admitted. Admits when the remote is unknown.
    fn bonded_admit(&mut self, i: usize) -> bool {
        let Some(remote) = self.paths[i].peer.media() else {
            return true;
        };
        let info = ConnectInfo {
            remote,
            username: self.paths[i]
                .eap
                .as_ref()
                .and_then(EapRole::peer_username)
                .map(str::to_owned),
        };
        self.auth.admit(info)
    }

    /// On path `i` reaching authentication with no configured PSK, re-keys its data
    /// channel to the SRP session key K and pushes "use K" to its peer.
    async fn on_authenticated(&mut self, i: usize) {
        // use_key_as_passphrase keys only the receiver→sender feedback direction with K
        // (media stays cleartext, matching libRIST): the authenticator (receiver) keys its
        // SEND, the authenticatee (sender) keys its RECV. Keying both would encrypt the
        // media and break interop with a libRIST/ristgo peer (which keeps it cleartext).
        let (key, is_authenticator) = match self.paths[i].eap.as_ref() {
            Some(EapRole::Authenticator(a)) => (a.session_key(), true),
            Some(EapRole::Authenticatee(a)) => (a.session_key(), false),
            None => return,
        };
        let Some(key) = key else {
            return;
        };
        let rekey = if is_authenticator {
            self.paths[i].codec.set_send_session_key(&key)
        } else {
            self.paths[i].codec.set_recv_session_key(&key)
        };
        if let Err(e) = rekey {
            tracing::debug!(target: crate::logging::CRYPTO, path = i, "rist: bonded post-auth re-key failed: {e}");
            return;
        }
        let mut wire = Vec::new();
        eap::passphrase_push(PASSPHRASE_PUSH_ID).append_to(&mut wire);
        self.send_eapol(i, &wire).await;
    }

    /// Frames an EAP payload in a GRE EAPOL datagram and sends it on path `i`.
    async fn send_eapol(&mut self, i: usize, eap: &[u8]) {
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        if let Ok(bytes) = self.paths[i].codec.encode_eapol(eap) {
            let sock = self.paths[i].socket.clone();
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// The mandatory first compound packet: an SR on the sender, an empty RR on the
    /// receiver. Shared across paths (one flow, one report).
    #[allow(clippy::cast_possible_truncation)] // RTP timestamp wraps by design
    fn feedback_lead(&self, now: Timestamp) -> RtcpPacket {
        if self.sender {
            RtcpPacket::SenderReport(SenderReport {
                ssrc: self.ssrc,
                ntp: crate::driver::wall_clock_ntp(),
                rtp_time: (now.as_micros() * 9 / 100) as u32,
                packet_count: 0,
                octet_count: 0,
            })
        } else {
            RtcpPacket::EmptyReceiverReport(EmptyReceiverReport {
                ssrc: self.local_ssrc(),
            })
        }
    }

    /// The SSRC stamped into outbound RTCP: the configured flow SSRC on a sender,
    /// the learned media SSRC (or the reporter SSRC until learned) on a receiver.
    fn local_ssrc(&self) -> u32 {
        if self.sender {
            self.ssrc
        } else {
            self.learned_ssrc.unwrap_or(self.ssrc)
        }
    }

    /// Whether every path's data channel is open (media may flow).
    fn all_authed(&self) -> bool {
        self.paths.iter().all(|p| p.authed)
    }

    /// Whether every path's peer has been seen and then gone silent past the
    /// timeout — the condition to tear the bonded session down.
    fn all_expired(&self, now: Timestamp) -> bool {
        self.paths.iter().all(|p| p.peer.expired(now))
    }

    /// The earliest pending timer deadline, if any.
    fn earliest_timer(&self) -> Option<Timestamp> {
        self.timers.values().copied().min()
    }

    /// Fires every due declarative timer in deadline order.
    fn fire_timers(&mut self, now: Timestamp) {
        while let Some((&id, &deadline)) = self.timers.iter().min_by_key(|&(_, d)| *d) {
            if deadline > now {
                break;
            }
            self.timers.remove(&id);
            self.flow.handle_timer(now, id);
        }
    }
}

/// Wraps each [`PathParts`] in its runtime [`PathLink`], stamping the path index
/// and the initial handshake flags (`authed` is true immediately without EAP).
fn link_paths(parts: Vec<PathParts>) -> Vec<PathLink> {
    parts
        .into_iter()
        .enumerate()
        .map(|(i, p)| link_path_at(u8::try_from(i).unwrap_or(u8::MAX), p))
        .collect()
}

/// Builds one [`PathLink`] at an explicit `index` (a runtime [`PeerCmd::Add`], where
/// the caller owns the index space), seeding the handshake flags fresh.
fn link_path_at(index: u8, p: PathParts) -> PathLink {
    PathLink {
        index,
        socket: p.socket,
        peer: p.peer,
        codec: p.codec,
        authed: p.eap.is_none(),
        eap: p.eap,
        greeted: false,
        reader: None,
    }
}

/// Spawns a per-path reader task funnelling inbound datagrams (tagged with the path
/// index) into the shared channel until the socket errors or the channel closes.
/// `pub(crate)` so the multi-flow demultiplexer can drive the `N` bonded path sockets
/// with the same reader, then route each datagram by [`Inbound::src`].
pub(crate) fn spawn_reader(
    index: u8,
    socket: MainSocket,
    tx: mpsc::Sender<Inbound>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        let mut col_buf = vec![0u8; RECV_BUF];
        let mut row_buf = vec![0u8; RECV_BUF];
        // The loop exits when the GRE socket errors (fatal for this path) or the driver
        // drops the channel. The separate-port FEC sockets pend forever when unbound (a
        // sender, or a receiver without FEC), so those arms are then no-ops.
        loop {
            tokio::select! {
                r = socket.recv(&mut buf) => match r {
                    Ok((n, src)) => {
                        let inb = Inbound { index, kind: InboundKind::Main, src, data: Bytes::copy_from_slice(&buf[..n]) };
                        if tx.send(inb).await.is_err() {
                            break; // the driver has shut down
                        }
                    }
                    Err(_) => break,
                },
                r = socket.recv_fec_col(&mut col_buf) => if let Ok((n, src)) = r {
                    let inb = Inbound { index, kind: InboundKind::Fec, src, data: Bytes::copy_from_slice(&col_buf[..n]) };
                    if tx.send(inb).await.is_err() {
                        break;
                    }
                },
                r = socket.recv_fec_row(&mut row_buf) => if let Ok((n, src)) = r {
                    let inb = Inbound { index, kind: InboundKind::Fec, src, data: Bytes::copy_from_slice(&row_buf[..n]) };
                    if tx.send(inb).await.is_err() {
                        break;
                    }
                },
            }
        }
    })
}

/// Awaits the next application payload when every path's data channel is open;
/// never resolves while gated or when there is no application input channel.
async fn recv_app_gated(app_in: &mut Option<mpsc::Receiver<Bytes>>, authed: bool) -> Option<Bytes> {
    if !authed {
        return std::future::pending().await;
    }
    match app_in {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Awaits the next runtime weight command; never resolves when there is no command
/// channel (a receiver-role driver, which takes no weight commands).
async fn recv_weight(ch: &mut Option<mpsc::Receiver<(u8, u32)>>) -> Option<(u8, u32)> {
    match ch {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Sleeps until `at`, or never resolves when there is no pending timer.
async fn sleep_until_opt(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Whether sequence `a` is circularly after `b` (wrap-aware).
fn seq_after(a: u32, b: u32) -> bool {
    Seq32::new(b).less(Seq32::new(a))
}
