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

use rist_codec::eap;
use rist_codec::gre;
use rist_codec::rtcp::{EmptyReceiverReport, Packet as RtcpPacket, SenderReport};
use rist_core::clock::Timestamp;
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::Feedback;

use crate::bonding::Group;
use crate::codec_main::{ControlKind, Decoded, MainCodec};
use crate::driver::{COMMAND_CAPACITY, CloseFlag, DATA_CAPACITY};
use crate::driver_main::EapRole;
use crate::peer::Peer;
use crate::socket::MainSocket;
use crate::stats::StatsCell;

/// The largest datagram a path reader will receive.
const RECV_BUF: usize = 65_536;

/// The EAP identifier ristrust stamps on its unsolicited passphrase push (matching
/// [`MainDriver`](crate::driver_main)'s convention).
const PASSPHRASE_PUSH_ID: u8 = 0x40;

/// The depth of the shared inbound channel the per-path readers feed.
const INBOUND_CAPACITY: usize = 256;

/// One inbound datagram, tagged with the path it arrived on.
struct Inbound {
    /// The path index (0-based, matching the [`Group`] registration).
    index: u8,
    /// The datagram's source address.
    src: SocketAddr,
    /// The datagram bytes.
    data: Bytes,
}

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
}

/// The bonded Main-profile session driver, run as one detached task per flow.
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

    // --- sender half ---
    app_in: Option<mpsc::Receiver<Bytes>>,
    /// The highest first-transmission sequence sent (shared across paths — the RTP
    /// sequence space is one stream), the NACK-widening reference.
    highest_sent: u32,
    /// The local flow SSRC (stamped into the SR/echo).
    ssrc: u32,

    // --- receiver half ---
    data_out: Option<mpsc::Sender<Bytes>>,
    /// The media SSRC learned from the first inbound packet (one stream, any path).
    learned_ssrc: Option<u32>,
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
            app_in: Some(rx),
            highest_sent: start_seq,
            ssrc,
            data_out: None,
            learned_ssrc: None,
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
            app_in: None,
            highest_sent: 0,
            ssrc,
            data_out: Some(tx),
            learned_ssrc: None,
        };
        (rx, close, stats, tokio::spawn(driver.run()))
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
    async fn run(mut self) {
        let (in_tx, mut in_rx) = mpsc::channel::<Inbound>(INBOUND_CAPACITY);
        let mut readers = Vec::with_capacity(self.paths.len());
        for p in &self.paths {
            readers.push(spawn_reader(p.index, p.socket.clone(), in_tx.clone()));
        }
        drop(in_tx); // the driver holds no sender; readers keep the channel open

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

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            // Media is gated until every path's data channel is open; recompute each
            // iteration since EAP can flip a path to authenticated mid-loop.
            let authed = self.all_authed();
            tokio::select! {
                msg = in_rx.recv() => match msg {
                    Some(inb) => self.on_recv(inb).await,
                    None => break, // every path reader has exited
                },
                // Hold outbound media until every path's data channel is open (a
                // no-op when authentication is disabled — `authed` is then true).
                payload = recv_app_gated(&mut self.app_in, authed) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.flow.push_app(now, p);
                        self.drain(now).await;
                    }
                    None => break, // sender's app channel closed: shut down
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
                },
            }
        }

        for r in readers {
            r.abort();
        }
    }

    /// Handles one inbound datagram from path `inb.index`: learns the path's peer
    /// and liveness, then routes it as EAP, keepalive, media, or feedback.
    async fn on_recv(&mut self, inb: Inbound) {
        let now = self.now();
        let i = inb.index as usize;
        if i >= self.paths.len() {
            return;
        }
        self.paths[i].peer.learn_media(inb.src);
        self.paths[i].peer.observe(now);
        self.group.observe(inb.index, now);

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

        // A GRE keepalive is a liveness signal only — nothing for the flow.
        let (kind, _ka, _ver) = self.paths[i].codec.peek_control(&inb.data);
        if kind != ControlKind::Keepalive {
            match self.paths[i].codec.decode(&inb.data, self.highest_sent) {
                Ok(Decoded::Media(pkt)) => {
                    if self.learned_ssrc.is_none() {
                        self.learned_ssrc = Some(pkt.ssrc);
                    }
                    // Feed on this path's index: the one ring dedups copies from the
                    // other paths by `(seq, source_time)`.
                    self.flow.feed(now, inb.index, pkt);
                }
                Ok(Decoded::Feedback(fbs)) => {
                    for fb in fbs {
                        self.flow.feed_feedback(now, fb);
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
                    // Full 2022-7 redundancy: the identical (seq, source_time) packet
                    // on every live duplicate-weight path, each in its own GRE frame.
                    for idx in self.group.duplicate_targets(now) {
                        self.send_media_on(idx as usize, &pkt).await;
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
        while let Some(Event::Deliver { payload, .. }) = self.flow.poll_event() {
            if let Some(out) = &self.data_out
                && out.send(payload).await.is_err()
            {
                return; // the application Receiver was dropped
            }
        }
        self.stats.publish(self.flow.stats());
    }

    /// Encodes and transmits one media packet on path `i`, if it is addressed and
    /// authenticated.
    async fn send_media_on(&mut self, i: usize, pkt: &rist_core::wire::MediaPacket) {
        if !self.paths[i].authed {
            return;
        }
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        match self.paths[i].codec.encode_media(pkt) {
            Ok(bytes) => {
                let sock = self.paths[i].socket.clone();
                if let Err(e) = sock.send(&bytes, dst).await {
                    tracing::debug!(
                        seq = pkt.seq,
                        path = i,
                        "rist: bonded send media failed: {e}"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
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
        let lead = self.feedback_lead(now);
        match self.paths[i].codec.encode_feedback(lead, fbs, self.bitmask) {
            Ok(bytes) => {
                let sock = self.paths[i].socket.clone();
                if let Err(e) = sock.send(&bytes, dst).await {
                    tracing::debug!(path = i, "rist: bonded send feedback failed: {e}");
                }
            }
            Err(e) => tracing::debug!(path = i, "rist: bonded encode feedback failed: {e}"),
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
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        let lead = self.feedback_lead(now);
        if let Ok(bytes) = self.paths[i].codec.encode_feedback(lead, &[], self.bitmask) {
            let sock = self.paths[i].socket.clone();
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Sends a GRE keepalive (MAC + standard capabilities) on path `i`.
    async fn send_keepalive(&mut self, i: usize, _now: Timestamp) {
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        let ka = gre::Keepalive {
            mac: self.mac,
            caps: gre::Capabilities::standard(),
            ..gre::Keepalive::default()
        };
        if let Ok(bytes) = self.paths[i].codec.encode_keepalive(&ka, gre::VERSION_MIN) {
            let sock = self.paths[i].socket.clone();
            let _ = sock.send(&bytes, dst).await;
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
        if self.paths[i].authed && !was_authed && !self.paths[i].codec.has_psk() {
            self.on_authenticated(i).await;
        }
    }

    /// On path `i` reaching authentication with no configured PSK, re-keys its data
    /// channel to the SRP session key K and pushes "use K" to its peer.
    async fn on_authenticated(&mut self, i: usize) {
        let Some(key) = self.paths[i].eap.as_ref().and_then(EapRole::session_key) else {
            return;
        };
        if let Err(e) = self.paths[i].codec.set_psk(&key) {
            tracing::debug!(path = i, "rist: bonded post-auth re-key failed: {e}");
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
        .map(|(i, p)| PathLink {
            index: u8::try_from(i).unwrap_or(u8::MAX),
            socket: p.socket,
            peer: p.peer,
            codec: p.codec,
            authed: p.eap.is_none(),
            eap: p.eap,
            greeted: false,
        })
        .collect()
}

/// Spawns a per-path reader task funnelling inbound datagrams (tagged with the path
/// index) into the shared channel until the socket errors or the channel closes.
fn spawn_reader(
    index: u8,
    socket: MainSocket,
    tx: mpsc::Sender<Inbound>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        // The loop exits when the socket errors (the `while let` guard) or the
        // driver drops the channel (the inner `break`).
        while let Ok((n, src)) = socket.recv(&mut buf).await {
            let inb = Inbound {
                index,
                src,
                data: Bytes::copy_from_slice(&buf[..n]),
            };
            if tx.send(inb).await.is_err() {
                break; // the driver has shut down
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
