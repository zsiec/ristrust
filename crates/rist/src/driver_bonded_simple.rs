//! The async driver for SMPTE 2022-7 bonded **Simple-profile** flows: `N` even/odd
//! (media + RTCP) socket pairs feeding one shared [`Flow`] and one bonding [`Group`].
//!
//! It is the Simple-profile analog of [`BondedDriver`](crate::driver_bonded::BondedDriver):
//! the single-socket bonded driver cannot host the Simple profile's even/odd pair, so
//! Simple bonds through this driver. The merge is unchanged (every copy of a sequence
//! — fresh, ARQ resend, or another path's duplicate — lands in the one ring and dedups
//! by `(seq, source_time)`); each path is its own RTP/RTCP transport. Media is encoded
//! once (the Simple codec is stateless) and fanned to every live duplicate-weight path;
//! NACK feedback goes to one elected path. The Simple profile has no authentication and
//! no GRE substrate, so there is no per-path codec/EAP state — only the transport and
//! the learned peer. FEC over bonded Simple is deferred.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use rist_codec::rtcp::{
    EmptyReceiverReport, LinkQualityReport, Packet as RtcpPacket, SenderReport,
};
use rist_core::clock::Timestamp;
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::wire::Feedback;

use crate::adapt::{LqmEmitter, RateControl};
use crate::bonding::Group;
use crate::codec::{self, MediaDecoder};
use crate::driver::{
    COMMAND_CAPACITY, CloseFlag, DATA_CAPACITY, recv_app_gated, seq_after, sleep_until_opt,
    wall_clock_ntp,
};
use crate::peer::Peer;
use crate::socket::SimpleSocket;
use crate::stats::StatsCell;

/// The largest datagram a path reader will receive.
const RECV_BUF: usize = 65_536;

/// The depth of the shared inbound channel the per-path readers feed.
const INBOUND_CAPACITY: usize = 256;

/// Whether an inbound datagram arrived on a path's media (even) or RTCP (odd) socket.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SimpleKind {
    Media,
    Rtcp,
}

/// One inbound datagram, tagged with the path it arrived on and its socket kind.
/// `pub(crate)` so the multi-flow bonded-Simple demultiplexer can read each path,
/// key by RTP SSRC, and route the datagram (with its path index) into the per-source
/// injected session.
pub(crate) struct SimpleBondInbound {
    /// The path index (receiver: the per-path socket; sender: unused, resolved by src).
    pub(crate) index: u8,
    pub(crate) kind: SimpleKind,
    pub(crate) src: SocketAddr,
    pub(crate) data: Bytes,
}

/// The transport + learned peer of one bonded Simple path. There is no per-path codec
/// or auth state (the Simple profile has neither).
pub(crate) struct SimplePathParts {
    /// This path's even/odd socket pair. On a sender every path shares one socket; on a
    /// receiver each path binds its own.
    pub(crate) socket: SimpleSocket,
    /// This path's remote (configured on a sender, learned on a receiver).
    pub(crate) peer: Peer,
}

/// The per-path runtime state.
struct SimplePathLink {
    index: u8,
    socket: SimpleSocket,
    peer: Peer,
}

/// The bonded Simple-profile session driver, run as one detached task per flow.
pub(crate) struct BondedSimpleDriver {
    sender: bool,
    flow: Flow,
    group: Group,
    paths: Vec<SimplePathLink>,
    epoch: Instant,
    timers: HashMap<TimerId, Timestamp>,
    keepalive: Duration,
    close: CloseFlag,
    stats: StatsCell,

    // --- sender half ---
    app_in: Option<mpsc::Receiver<Bytes>>,
    weight_cmd: Option<mpsc::Receiver<(u8, u32)>>,
    highest_sent: u32,
    ssrc: u32,
    cname: String,
    bitmask: bool,

    // --- receiver half ---
    data_out: Option<mpsc::Sender<Bytes>>,
    mdec: MediaDecoder,
    learned_ssrc: Option<u32>,
    lqm: Option<LqmEmitter>,
    rate: Option<RateControl>,

    /// Pre-routed inbound feed for a multi-flow demultiplexed receiver: when `Some`,
    /// the [`MultiReceiver`](crate::MultiReceiver) demultiplexer owns the path readers
    /// and routes this flow's datagrams in, so [`run`](Self::run) spawns none itself.
    injected: Option<mpsc::Receiver<SimpleBondInbound>>,
}

impl BondedSimpleDriver {
    /// Builds and spawns a bonded Simple sender: one shared even/odd socket fanning the
    /// identical RTP media to every path's media address (full 2022-7 redundancy or
    /// weighted load-share), receiving each path's NACK feedback on the shared RTCP
    /// socket (resolved to a path by source).
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_sender(
        flow: Flow,
        group: Group,
        paths: Vec<SimplePathParts>,
        ssrc: u32,
        cname: String,
        bitmask: bool,
        keepalive: Duration,
        weight_rx: mpsc::Receiver<(u8, u32)>,
        rate: Option<RateControl>,
    ) -> (
        mpsc::Sender<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = BondedSimpleDriver {
            sender: true,
            flow,
            group,
            paths: link_paths(paths),
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            close: close.clone(),
            stats: stats.clone(),
            app_in: Some(rx),
            weight_cmd: Some(weight_rx),
            highest_sent: 0,
            ssrc,
            cname,
            bitmask,
            data_out: None,
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            lqm: None,
            rate,
            injected: None,
        };
        (tx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns a bonded Simple receiver: one even/odd socket per path, merging
    /// the media that arrives on each into one flow.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_receiver(
        flow: Flow,
        group: Group,
        paths: Vec<SimplePathParts>,
        ssrc: u32,
        cname: String,
        bitmask: bool,
        keepalive: Duration,
        lqm: Option<LqmEmitter>,
    ) -> (
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = BondedSimpleDriver {
            sender: false,
            flow,
            group,
            paths: link_paths(paths),
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            close: close.clone(),
            stats: stats.clone(),
            app_in: None,
            weight_cmd: None,
            highest_sent: 0,
            ssrc,
            cname,
            bitmask,
            data_out: Some(tx),
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            lqm,
            rate: None,
            injected: None,
        };
        (rx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns an **injected** bonded Simple receiver for a multi-flow
    /// [`MultiReceiver`](crate::MultiReceiver): like [`spawn_receiver`](Self::spawn_receiver)
    /// but it spawns no path readers — the demultiplexer owns the `N` even/odd sockets,
    /// reads them, keys each datagram by RTP SSRC, and routes this source's datagrams
    /// (tagged with their path index) into the returned [`SimpleBondInbound`] channel.
    /// The driver still sends its keepalives and feedback out through the path sockets.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_injected_receiver(
        flow: Flow,
        group: Group,
        paths: Vec<SimplePathParts>,
        ssrc: u32,
        cname: String,
        bitmask: bool,
        keepalive: Duration,
        lqm: Option<LqmEmitter>,
    ) -> (
        mpsc::Sender<SimpleBondInbound>,
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (data_tx, data_rx) = mpsc::channel(DATA_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = BondedSimpleDriver {
            sender: false,
            flow,
            group,
            paths: link_paths(paths),
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            close: close.clone(),
            stats: stats.clone(),
            app_in: None,
            weight_cmd: None,
            highest_sent: 0,
            ssrc,
            cname,
            bitmask,
            data_out: Some(data_tx),
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            lqm,
            rate: None,
            injected: Some(in_rx),
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

    fn earliest_timer(&self) -> Option<Timestamp> {
        self.timers.values().copied().min()
    }

    fn fire_timers(&mut self, now: Timestamp) {
        while let Some((&id, &deadline)) = self.timers.iter().min_by_key(|&(_, d)| *d) {
            if deadline > now {
                break;
            }
            self.timers.remove(&id);
            self.flow.handle_timer(now, id);
        }
    }

    async fn run(mut self) {
        let mut readers = Vec::new();
        // Multi-flow demux: the demultiplexer owns the path readers and routes this
        // source's datagrams into `in_rx`; spawn none. Otherwise own the readers.
        let mut in_rx = if let Some(rx) = self.injected.take() {
            rx
        } else {
            let (in_tx, in_rx) = mpsc::channel::<SimpleBondInbound>(INBOUND_CAPACITY);
            if self.sender {
                // The sender shares one even/odd socket across all paths: one reader
                // funnels its inbound (the path is resolved by source in `on_recv`).
                readers.push(spawn_reader(0, self.paths[0].socket.clone(), in_tx.clone()));
            } else {
                for p in &self.paths {
                    readers.push(spawn_reader(p.index, p.socket.clone(), in_tx.clone()));
                }
            }
            drop(in_tx);
            in_rx
        };
        if self.sender {
            let now = self.now();
            for i in 0..self.paths.len() {
                self.send_keepalive(i, now).await;
            }
        }

        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;
        self.stats.set_authenticated(true); // the Simple profile has no authentication

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            let any_peer = self.paths.iter().any(|p| p.peer.media().is_some());
            tokio::select! {
                msg = in_rx.recv() => match msg {
                    Some(inb) => self.on_recv(inb).await,
                    None => break,
                },
                payload = recv_app_gated(&mut self.app_in, any_peer) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.flow.push_app(now, p);
                        self.drain(now).await;
                    }
                    None => break,
                },
                cmd = recv_weight(&mut self.weight_cmd) => match cmd {
                    Some((index, weight)) => self.group.set_weight(index, weight),
                    None => self.weight_cmd = None,
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
                    let _ = self.group.tick(now);
                    for i in 0..self.paths.len() {
                        if self.paths[i].peer.rtcp().is_some() {
                            self.send_keepalive(i, now).await;
                        }
                    }
                    self.maybe_emit_lqm(now).await;
                    self.stats.set_authenticated(true);
                    if let Some(s) = self.learned_ssrc {
                        self.stats.set_ssrc(s);
                    }
                },
            }
        }

        for r in readers {
            r.abort();
        }
    }

    /// Whether every path has been seen and then fallen silent past the session timeout.
    fn all_expired(&self, now: Timestamp) -> bool {
        self.paths.iter().all(|p| p.peer.expired(now))
    }

    /// Resolves a sender-side inbound datagram to its path by source address.
    fn sender_path_of(&self, src: SocketAddr) -> Option<usize> {
        self.paths
            .iter()
            .position(|p| p.peer.media() == Some(src) || p.peer.rtcp() == Some(src))
    }

    async fn on_recv(&mut self, inb: SimpleBondInbound) {
        let now = self.now();
        let i = if self.sender {
            match self.sender_path_of(inb.src) {
                Some(i) => i,
                None => return,
            }
        } else {
            inb.index as usize
        };
        if i >= self.paths.len() {
            return;
        }
        let path_id = u8::try_from(i).unwrap_or(u8::MAX);
        match inb.kind {
            SimpleKind::Media => {
                self.paths[i].peer.learn_media(inb.src);
                self.paths[i].peer.observe(now);
                self.group.observe(path_id, now);
                let buf = inb.data;
                if let Ok(pkt) = self.mdec.decode(&buf) {
                    if self.learned_ssrc.is_none() {
                        self.learned_ssrc = Some(pkt.ssrc);
                    }
                    if let Some(e) = self.lqm.as_mut() {
                        e.meter(pkt.payload.len(), pkt.retransmit);
                    }
                    self.flow.feed(now, path_id, pkt);
                }
            }
            SimpleKind::Rtcp => {
                self.paths[i].peer.learn_rtcp(inb.src);
                // Reversed-role learning over bonded Simple is not modelled; a bonded
                // receiver derives nothing from RTCP.
                self.paths[i].peer.observe(now);
                self.group.observe(path_id, now);
                if let Ok(fbs) = codec::decode_feedback(&inb.data, self.highest_sent) {
                    for fb in fbs {
                        if let Feedback::LinkQuality { lqm } = fb {
                            if let Some(r) = &mut self.rate {
                                r.handle(&lqm);
                            }
                        } else {
                            self.flow.feed_feedback(now, fb);
                        }
                    }
                }
            }
        }
        self.drain(now).await;
    }

    async fn drain(&mut self, now: Timestamp) {
        let mut fbs = Vec::new();
        while let Some(out) = self.flow.poll_output() {
            match out {
                Output::SendMedia { pkt, .. } => {
                    if !pkt.retransmit && seq_after(pkt.seq, self.highest_sent) {
                        self.highest_sent = pkt.seq;
                    }
                    // The Simple codec is stateless: encode once, fan the identical RTP
                    // bytes to every duplicate-weight path plus the elected weighted path.
                    let targets = self.group.duplicate_targets(now);
                    let weighted = self.group.select_weighted(now);
                    match codec::encode_media(&pkt) {
                        Ok(bytes) => {
                            for idx in targets {
                                self.send_media_on(idx as usize, &bytes).await;
                            }
                            if let Some(idx) = weighted {
                                self.send_media_on(idx as usize, &bytes).await;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(target: crate::logging::SOCKET, seq = pkt.seq, "rist: bonded-simple encode media failed: {e}");
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
        while let Some(Event::Deliver { payload, .. }) = self.flow.poll_event() {
            if let Some(out) = &self.data_out
                && out.send(payload).await.is_err()
            {
                return;
            }
        }
        self.stats.publish(self.flow.stats(), 0);
    }

    /// Sends one pre-encoded RTP media datagram to path `i`'s media address.
    async fn send_media_on(&self, i: usize, bytes: &Bytes) {
        let Some(dst) = self.paths[i].peer.media() else {
            return;
        };
        if let Err(e) = self.paths[i].socket.send_media(bytes, dst).await {
            tracing::debug!(target: crate::logging::SOCKET, path = i, "rist: bonded-simple send media failed: {e}");
        }
    }

    /// Sends one compound RTCP datagram (the drained feedback) to the elected NACK
    /// path's RTCP address.
    async fn send_feedback(&mut self, fbs: &[Feedback], now: Timestamp) {
        let known: Vec<bool> = self.paths.iter().map(|p| p.peer.rtcp().is_some()).collect();
        let Some(idx) = self
            .group
            .select_nack_path(now, |i| known.get(i as usize).copied().unwrap_or(false))
        else {
            return;
        };
        let i = idx as usize;
        let Some(dst) = self.paths[i].peer.rtcp() else {
            return;
        };
        let lead = self.feedback_lead(now);
        match codec::encode_feedback(lead, self.local_ssrc(), &self.cname, fbs, self.bitmask) {
            Ok(bytes) => {
                if let Err(e) = self.paths[i].socket.send_rtcp(&bytes, dst).await {
                    tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded-simple send rtcp failed: {e}");
                }
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::RTCP, path = i, "rist: bonded-simple encode feedback failed: {e}");
            }
        }
    }

    /// Sends a keepalive (bare lead + SDES compound) on path `i`'s RTCP socket.
    async fn send_keepalive(&self, i: usize, now: Timestamp) {
        if self.flow.config().no_recovery {
            return;
        }
        let Some(dst) = self.paths[i].peer.rtcp() else {
            return;
        };
        let lead = self.feedback_lead(now);
        if let Ok(bytes) =
            codec::encode_feedback(lead, self.local_ssrc(), &self.cname, &[], self.bitmask)
        {
            let _ = self.paths[i].socket.send_rtcp(&bytes, dst).await;
        }
    }

    /// Fans one Link Quality Message (TR-06-4) out every live path when a reporting
    /// period has elapsed (receiver only).
    async fn maybe_emit_lqm(&mut self, now: Timestamp) {
        if self.lqm.as_ref().is_none_or(|e| !e.due(now)) {
            return;
        }
        let ssrc = self.local_ssrc();
        let stats = self.flow.stats();
        let lqm = self
            .lqm
            .as_mut()
            .expect("emitter present (checked above)")
            .build(now, &stats, 0);
        let lqr = RtcpPacket::LinkQualityReport(LinkQualityReport {
            ssrc,
            lqm: lqm.encode(),
        });
        for i in 0..self.paths.len() {
            let Some(dst) = self.paths[i].peer.rtcp() else {
                continue;
            };
            if let Ok(bytes) =
                codec::encode_feedback(lqr.clone(), ssrc, &self.cname, &[], self.bitmask)
            {
                let _ = self.paths[i].socket.send_rtcp(&bytes, dst).await;
            }
        }
    }

    /// The mandatory first compound packet: an SR on the sender, an empty RR on the
    /// receiver.
    #[allow(clippy::cast_possible_truncation)] // RTP timestamp wraps by design
    fn feedback_lead(&self, now: Timestamp) -> RtcpPacket {
        if self.sender {
            RtcpPacket::SenderReport(SenderReport {
                ssrc: self.ssrc,
                ntp: wall_clock_ntp(),
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

    fn local_ssrc(&self) -> u32 {
        if self.sender {
            self.ssrc
        } else {
            self.learned_ssrc.unwrap_or(self.ssrc)
        }
    }
}

/// Wraps the [`SimplePathParts`] into the driver's per-path runtime state.
fn link_paths(parts: Vec<SimplePathParts>) -> Vec<SimplePathLink> {
    parts
        .into_iter()
        .enumerate()
        .map(|(i, p)| SimplePathLink {
            index: u8::try_from(i).unwrap_or(u8::MAX),
            socket: p.socket,
            peer: p.peer,
        })
        .collect()
}

/// Receives the next runtime weight command, or pends when there is no channel.
async fn recv_weight(cmd: &mut Option<mpsc::Receiver<(u8, u32)>>) -> Option<(u8, u32)> {
    match cmd {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Spawns one path reader: it reads the path's media (even) and RTCP (odd) sockets and
/// funnels each datagram, tagged with the path index and kind, into the channel. Used
/// by the driver in self-driven mode and by the multi-flow demultiplexer.
pub(crate) fn spawn_reader(
    index: u8,
    socket: SimpleSocket,
    tx: mpsc::Sender<SimpleBondInbound>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut media_buf = vec![0u8; RECV_BUF];
        let mut rtcp_buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                r = socket.recv_media(&mut media_buf) => match r {
                    Ok((n, src)) => {
                        let inb = SimpleBondInbound { index, kind: SimpleKind::Media, src, data: Bytes::copy_from_slice(&media_buf[..n]) };
                        if tx.send(inb).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
                r = socket.recv_rtcp(&mut rtcp_buf) => match r {
                    Ok((n, src)) => {
                        let inb = SimpleBondInbound { index, kind: SimpleKind::Rtcp, src, data: Bytes::copy_from_slice(&rtcp_buf[..n]) };
                        if tx.send(inb).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
            }
        }
    })
}
