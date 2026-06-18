//! The async driver: the `select!` pump that turns the sans-I/O flow core into
//! real UDP I/O for the Simple profile.
//!
//! One [`Driver`] owns the flow state machine, the even/odd UDP transport, the
//! peer's addressing/liveness, and a declarative-timer wheel. Each loop iteration
//! it waits on the first of: an inbound media datagram, an inbound RTCP datagram,
//! an application payload (sender), the next timer deadline, or the keepalive
//! tick — captures `now`, feeds the flow, then drains its effects (encode + send,
//! arm/clear timers, deliver events to the app). It is a thin, dumb pump: no
//! protocol logic lives here. Mirrors ristgo `internal/session` and srtrust's
//! driver pattern.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use rist_codec::rtcp::{self, EmptyReceiverReport, Packet as RtcpPacket, SenderReport};
use rist_codec::{fec_header, rtp};
use rist_core::clock::{Ntp64, Timestamp};
use rist_core::fec::{Direction, Recovered};
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::{Feedback, FragRole, MediaPacket};

use crate::adapt::{LqmEmitter, RateControl};
use crate::codec::{self, MediaDecoder};
use crate::error::Error;
use crate::fec::{FEC_COLUMN_PORT_OFFSET, FEC_PT, FEC_ROW_PORT_OFFSET, FecState};
use crate::peer::Peer;
use crate::socket::SimpleSocket;
use crate::split::{self, MergeMode, MergeOut, Merger, SplitMode};
use crate::stats::StatsCell;

/// The largest datagram the driver will receive.
const RECV_BUF: usize = 65_536;

/// Capacity of the application → driver payload channel (sender side).
pub(crate) const COMMAND_CAPACITY: usize = 256;

/// Capacity of the driver → application delivered-data channel (receiver side).
pub(crate) const DATA_CAPACITY: usize = 1024;

/// Capacity of the inbound channel feeding a driver's pump (the reader, or in
/// multi-flow a demultiplexer, fills it; the pump drains it). One per flow.
pub(crate) const INBOUND_CAPACITY: usize = 256;

/// One inbound Simple-profile datagram, tagged with the socket it arrived on. The
/// pump reads these from a channel rather than owning the socket directly, so a
/// single-flow driver feeds the channel from its own reader task while a multi-flow
/// [`MultiReceiver`](crate::multi) feeds many drivers' channels from one shared read
/// (the injected-feed seam — ported from ristgo's per-flow injected sessions).
pub(crate) enum SimpleInbound {
    /// An RTP media datagram (even port) and its source address.
    Media { data: Bytes, src: SocketAddr },
    /// A compound RTCP datagram (odd port) and its source address.
    Rtcp { data: Bytes, src: SocketAddr },
    /// A separate-port FEC datagram (column or row; decoded identically).
    Fec { data: Bytes },
}

/// A runtime control command a [`Receiver`](crate::Receiver) handle sends into its
/// driver's `select!` loop — the host side of libRIST's receiver runtime setters
/// (`rist_receiver_nack_type_set`, `rist_recovery_rtt_multiplier_set`). Rare control
/// traffic on a small-depth channel, applied to live driver/flow state by
/// [`RxControl::apply`]. The matching sender setter (NPD) rides its own `bool` channel.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RxControl {
    /// Select the NACK feedback format: `true` = bitmask, `false` = range.
    NackBitmask(bool),
    /// Set the recovery-buffer RTT multiplier pushed into the flow core.
    RttMultiplier(u32),
}

impl RxControl {
    /// Applies this command to the driver's NACK-format flag and flow core. Shared
    /// by every receiver driver so the runtime-setter semantics live in one place.
    pub(crate) fn apply(self, bitmask: &mut bool, flow: &mut Flow) {
        match self {
            RxControl::NackBitmask(b) => *bitmask = b,
            RxControl::RttMultiplier(m) => flow.set_rtt_multiplier(m),
        }
    }
}

/// One application payload submitted with optional per-block metadata — the host
/// carrier for [`Sender::send_block`](crate::Sender::send_block) (libRIST's
/// `RIST_DATA_FLAGS_USE_SEQ` + `ts_ntp`). `seq`/`source_time` of `None` take the flow's
/// auto-incremented sequence and `now`-derived timestamp; `Some` values are used
/// verbatim so a transparent relay can preserve an upstream flow's `(seq, source_time)`.
#[derive(Debug, Clone)]
pub(crate) struct AppBlock {
    /// The media payload.
    pub(crate) payload: Bytes,
    /// An explicit sequence number (USE_SEQ), or `None` for the auto sequence.
    pub(crate) seq: Option<u32>,
    /// An explicit NTP-64 source timestamp (`ts_ntp`), or `None` to derive from `now`.
    pub(crate) source_time: Option<u64>,
}

/// Why a session's driver task exited, shared with the public [`Sender`](crate::Sender)
/// / [`Receiver`](crate::Receiver) handle so a closed channel can surface a specific
/// [`Error`] (peer timeout, auth failure) instead of a bare [`Error::Closed`]. A
/// driver records it just before it breaks its loop; the handle reads it once its
/// channel closes. The default (`0`) is a clean close — the application dropped or
/// closed the handle, or an unremarkable socket error ended the task.
#[derive(Debug, Clone, Default)]
pub(crate) struct CloseFlag(std::sync::Arc<std::sync::atomic::AtomicU8>);

impl CloseFlag {
    const SESSION_TIMEOUT: u8 = 1;
    const AUTH: u8 = 2;

    /// Records that the peer's liveness timeout (`session_timeout`) elapsed.
    pub(crate) fn set_session_timeout(&self) {
        self.0
            .store(Self::SESSION_TIMEOUT, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records that the EAP-SRP handshake failed (bad credentials / refused proof).
    pub(crate) fn set_auth(&self) {
        self.0
            .store(Self::AUTH, std::sync::atomic::Ordering::Relaxed);
    }

    /// The error a closed handle should return given the recorded reason.
    pub(crate) fn error(&self) -> Error {
        match self.0.load(std::sync::atomic::Ordering::Relaxed) {
            Self::SESSION_TIMEOUT => Error::SessionTimeout,
            Self::AUTH => Error::Auth,
            _ => Error::Closed,
        }
    }
}

/// Logs an inbound media/control decode failure. With a PSK configured this almost
/// always means an encryption mismatch — a wrong secret or key size: the GRE/adv
/// PSK is AES-CTR with no authentication tag, so a mis-keyed datagram decrypts to
/// garbage and fails framing here, which to the application otherwise looks like
/// total packet loss with no error reported. Warn (under the `rist::crypto` target)
/// in that case so the misconfiguration is visible; in the clear it is more likely
/// line noise or a stray datagram, so stay at debug.
pub(crate) fn decode_warn(has_psk: bool, what: &str, e: &dyn std::fmt::Display) {
    if has_psk {
        tracing::warn!(target: crate::logging::CRYPTO, "rist: {what} decode failed (likely PSK/key mismatch): {e}");
    } else {
        tracing::debug!(target: crate::logging::CRYPTO, "rist: {what} decode failed: {e}");
    }
}

/// The Simple-profile session driver, run as one detached task per flow.
pub(crate) struct Driver {
    /// Whether this is the media-originating (sender) half.
    sender: bool,
    flow: Flow,
    socket: SimpleSocket,
    peer: Peer,
    /// The session clock epoch: `now()` is microseconds since this instant.
    epoch: Instant,
    /// Declarative timers the flow has requested, by id.
    timers: HashMap<TimerId, Timestamp>,
    keepalive: Duration,
    /// Records why the task exited, read by the handle once its channel closes.
    close: CloseFlag,
    /// The latest stats snapshot published to the handle's `stats()`.
    stats: StatsCell,

    // --- sender half ---
    /// Application payloads to transmit (`None` on a receiver).
    app_in: Option<mpsc::Receiver<Bytes>>,
    /// The highest first-transmission sequence sent, the NACK-widening reference.
    highest_sent: u32,
    /// The local flow SSRC (stamped into media and the SR/echo).
    ssrc: u32,
    cname: String,
    bitmask: bool,
    /// The sender's packet-split bonding mode (libRIST `split=`); [`SplitMode::Off`]
    /// on a receiver.
    split_mode: SplitMode,

    // --- receiver half ---
    /// Delivered in-order payloads handed to the application (`None` on a sender).
    data_out: Option<mpsc::Sender<Bytes>>,
    mdec: MediaDecoder,
    /// The media SSRC learned from the first inbound packet (the receiver's
    /// reporter SSRC until then).
    learned_ssrc: Option<u32>,
    /// The packet-merge state machine (libRIST `merge=`) folding split pairs back
    /// together at delivery; [`MergeMode::Off`] on a sender.
    merger: Merger,
    /// Runtime receiver-control commands from the [`Receiver`](crate::Receiver) handle
    /// (`set_nack_type` / `set_rtt_multiplier`); `None` on a sender or an injected
    /// (multi-flow) receiver, which take no such commands.
    rx_ctrl: Option<mpsc::Receiver<RxControl>>,

    // --- source adaptation (TR-06-4 Part 1) ---
    /// The receiver's Link Quality Message emitter, when source adaptation is on.
    lqm: Option<LqmEmitter>,
    /// The sender's rate controller, when a rate callback is configured.
    rate: Option<RateControl>,

    // --- forward error correction (TR-06-2 §8.4, separate-port carriage) ---
    /// The FEC engine when FEC is configured: the sender clips each first-tx RTP
    /// payload and sends the FEC packets as RTP on the column/row ports; the receiver
    /// reads those ports, feeds media + FEC into the decoder, and re-injects
    /// recoveries.
    fec: Option<FecState>,

    // --- inbound feed ---
    /// The channel the pump drains inbound datagrams from. In single-flow mode `reader`
    /// fills it from the owned socket; in multi-flow mode a demultiplexer fills it.
    inbound: Option<mpsc::Receiver<SimpleInbound>>,
    /// The owned socket-reader task (single-flow); `None` when a demultiplexer feeds
    /// `inbound` (multi-flow injected mode). Aborted when the pump exits.
    reader: Option<tokio::task::JoinHandle<()>>,
}

impl Driver {
    /// Builds and spawns a sender driver transmitting to the peer's media/RTCP
    /// (the receiver's even/odd addresses), returning the application payload
    /// channel and the driver task handle.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_sender(
        flow: Flow,
        socket: SimpleSocket,
        peer: Peer,
        ssrc: u32,
        cname: String,
        bitmask: bool,
        keepalive: Duration,
        start_seq: u32,
        rate: Option<RateControl>,
        fec: Option<FecState>,
        split_mode: SplitMode,
    ) -> (
        mpsc::Sender<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let reader = spawn_reader(socket.clone(), in_tx);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = Driver {
            sender: true,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            close: close.clone(),
            stats: stats.clone(),
            app_in: Some(rx),
            highest_sent: start_seq,
            ssrc,
            cname,
            bitmask,
            split_mode,
            data_out: None,
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            merger: Merger::new(MergeMode::Off),
            rx_ctrl: None, // a sender takes no receiver-control commands
            lqm: None,
            rate,
            fec,
            inbound: Some(in_rx),
            reader: Some(reader),
        };
        (tx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns a receiver driver that learns the sender's return
    /// addresses from inbound traffic, returning the delivered-data channel and the
    /// driver task handle.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_receiver(
        flow: Flow,
        socket: SimpleSocket,
        peer: Peer,
        ssrc: u32,
        cname: String,
        bitmask: bool,
        keepalive: Duration,
        lqm: Option<LqmEmitter>,
        fec: Option<FecState>,
        merge_mode: MergeMode,
        rx_ctrl: mpsc::Receiver<RxControl>,
    ) -> (
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let reader = spawn_reader(socket.clone(), in_tx);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = Driver {
            sender: false,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            close: close.clone(),
            stats: stats.clone(),
            app_in: None,
            highest_sent: 0,
            ssrc,
            cname,
            bitmask,
            split_mode: SplitMode::Off,
            data_out: Some(tx),
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            merger: Merger::new(merge_mode),
            rx_ctrl: Some(rx_ctrl),
            lqm,
            rate: None,
            fec,
            inbound: Some(in_rx),
            reader: Some(reader),
        };
        (rx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns an **injected** Simple receiver driver: it owns no socket
    /// reader — a [`MultiReceiver`](crate::multi) demultiplexer feeds its inbound
    /// channel (the returned [`SimpleInbound`] sender) from one shared socket read,
    /// while this driver decodes, recovers, and writes its feedback back out the
    /// shared socket to its own learned peer. `ssrc` is the flow's demux SSRC (tagged
    /// into its reports). Returns the inbound sender plus the usual receiver handles.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_injected_receiver(
        flow: Flow,
        socket: SimpleSocket,
        peer: Peer,
        ssrc: u32,
        cname: String,
        bitmask: bool,
        keepalive: Duration,
        lqm: Option<LqmEmitter>,
        merge_mode: MergeMode,
    ) -> (
        mpsc::Sender<SimpleInbound>,
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = Driver {
            sender: false,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            close: close.clone(),
            stats: stats.clone(),
            app_in: None,
            highest_sent: 0,
            ssrc,
            cname,
            bitmask,
            split_mode: SplitMode::Off,
            data_out: Some(tx),
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            merger: Merger::new(merge_mode),
            // A demuxed per-flow receiver surfaced via `from_parts` has no control
            // channel, so runtime setters return `Unimplemented` on it.
            rx_ctrl: None,
            lqm,
            rate: None,
            fec: None, // multi-flow rejects separate-port FEC (see listen_multi)
            inbound: Some(in_rx),
            reader: None, // the demultiplexer feeds `inbound`
        };
        (in_tx, rx, close, stats, tokio::spawn(driver.run()))
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

    /// The driver loop. Runs until the application channel closes, the peer
    /// expires, or a socket error occurs.
    async fn run(mut self) {
        // Inbound datagrams arrive over a channel (the injected-feed seam): in
        // single-flow mode `reader` fills it from the owned socket; in multi-flow mode
        // a demultiplexer does. Either way the pump is identical.
        let mut inbound = self.inbound.take().expect("inbound channel set at spawn");

        // A sender knows the peer's RTCP address up front; an immediate keepalive
        // lets the receiver learn the sender's return address (and so send NACKs)
        // without waiting a full keepalive interval.
        if self.sender {
            let now = self.now();
            self.send_keepalive(now).await;
        }

        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        // The Simple profile has no authentication: it is always "authenticated".
        self.stats.set_authenticated(true);

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            tokio::select! {
                msg = inbound.recv() => match msg {
                    Some(inb) => self.on_inbound(inb).await,
                    None => break, // the reader exited (socket error) or the demuxer closed
                },
                // Hold media until the peer's media address is known: a normal sender
                // knows it at construction (always ready); a reversed-role listener-sender
                // holds until it learns the caller from the caller's RTCP announcement.
                payload = recv_app_gated(&mut self.app_in, self.peer.media().is_some()) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.push_split(now, p);
                        self.drain(now).await;
                    }
                    None => break, // sender's app channel closed: shut down.
                },
                // Runtime receiver setters (`set_nack_type` / `set_rtt_multiplier`).
                cmd = recv_opt(&mut self.rx_ctrl) => match cmd {
                    Some(c) => c.apply(&mut self.bitmask, &mut self.flow),
                    None => self.rx_ctrl = None, // handle dropped: stop watching
                },
                () = sleep_until_opt(timer_at) => {
                    let now = self.now();
                    self.fire_timers(now);
                    self.drain(now).await;
                },
                _ = keepalive.tick() => {
                    let now = self.now();
                    if self.peer.expired(now) {
                        self.close.set_session_timeout();
                        break;
                    }
                    // Fill idle gaps only, so the flow's own RTT-echo cadence on
                    // the wire is not doubled.
                    if self.peer.rtcp().is_some() {
                        self.send_keepalive(now).await;
                        // Source adaptation: emit a Link Quality Message when a
                        // reporting period has elapsed (receiver only).
                        self.maybe_emit_lqm(now).await;
                    }
                    // Publish session status: the Simple profile has no authentication,
                    // so the session is always "authenticated"; surface the learned SSRC.
                    self.stats.set_authenticated(true);
                    if let Some(s) = self.learned_ssrc {
                        self.stats.set_ssrc(s);
                    }
                },
            }
        }

        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }

    /// Dispatches one inbound datagram by the socket it arrived on.
    async fn on_inbound(&mut self, inb: SimpleInbound) {
        match inb {
            SimpleInbound::Media { data, src } => self.on_media(src, &data).await,
            SimpleInbound::Rtcp { data, src } => self.on_rtcp(src, &data).await,
            SimpleInbound::Fec { data } => self.on_fec_rtp(&data).await,
        }
    }

    /// Handles one inbound media datagram (receiver path).
    async fn on_media(&mut self, src: SocketAddr, data: &[u8]) {
        let now = self.now();
        self.peer.learn_media(src);
        self.peer.observe(now);
        let buf = Bytes::copy_from_slice(data);
        if let Ok(pkt) = self.mdec.decode(&buf) {
            if self.learned_ssrc.is_none() {
                self.learned_ssrc = Some(pkt.ssrc);
            }
            if let Some(e) = &mut self.lqm {
                e.meter(pkt.payload.len(), pkt.retransmit);
            }
            // FEC over the inner RTP payload (separate-port carriage): feed it keyed
            // on the raw wire timestamp (the value the sender clipped) before the
            // flow takes ownership of the payload, then re-inject any recovery.
            let fec_input = self.fec.is_some().then(|| {
                (
                    pkt.seq,
                    self.mdec.last_wire_ts(),
                    pkt.ssrc,
                    pkt.payload.clone(),
                )
            });
            self.flow.feed(now, 0, pkt);
            if let Some((seq, wts, ssrc, payload)) = fec_input {
                let recovered = self
                    .fec
                    .as_mut()
                    .unwrap()
                    .recv_media(seq, wts, FEC_PT, ssrc, payload);
                self.feed_fec_recovered(now, recovered);
            }
        }
        self.drain(now).await;
    }

    /// Handles one inbound separate-port FEC datagram: strips the RTP wrapper to the
    /// FEC body, feeds it to the FEC decoder, and re-injects any recovered packet into
    /// the flow (the FEC and flow layers both dedup it).
    async fn on_fec_rtp(&mut self, data: &[u8]) {
        let now = self.now();
        let buf = Bytes::copy_from_slice(data);
        let Ok(p) = rtp::Packet::decode(&buf) else {
            return;
        };
        if self.fec.is_some() {
            let recovered = self.fec.as_mut().unwrap().recv_fec(&p.payload);
            self.feed_fec_recovered(now, recovered);
        }
        self.drain(now).await;
    }

    /// Re-injects FEC-recovered packets into the flow as media. The source time is
    /// reconstructed (non-advancing) from the recovered RTP timestamp so a recovery
    /// and a later ARQ retransmit of the same sequence dedup to one delivery.
    fn feed_fec_recovered(&mut self, now: Timestamp, recovered: Vec<Recovered>) {
        for r in recovered {
            let source_time = self.mdec.source_time(r.timestamp);
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
                },
            );
        }
    }

    /// Handles one inbound RTCP datagram (feedback path).
    async fn on_rtcp(&mut self, src: SocketAddr, data: &[u8]) {
        let now = self.now();
        self.peer.learn_rtcp(src);
        // Reversed-role listener-sender: a caller-receiver announces via RTCP only, so
        // derive its media address from the RTCP source (the even media port is the odd
        // RTCP port minus one, since the caller binds a consecutive pair) and learn it.
        // Gated to the sender role: a normal sender's media address is already locked
        // from the dial (so this is a no-op), and a receiver must not derive a peer media
        // address from RTCP (the peer's ports need not be consecutive).
        if self.sender
            && let Some(media_port) = src.port().checked_sub(1)
        {
            self.peer.learn_media(SocketAddr::new(src.ip(), media_port));
        }
        self.peer.observe(now);
        if let Ok(fbs) = codec::decode_feedback(data, self.highest_sent) {
            for fb in fbs {
                // A Link Quality Message is a host-level source-adaptation signal:
                // drive the rate controller, never the flow core.
                if let Feedback::LinkQuality { lqm } = fb {
                    if let Some(r) = &mut self.rate {
                        r.handle(&lqm);
                    }
                } else {
                    self.flow.feed_feedback(now, fb);
                }
            }
        }
        self.drain(now).await;
    }

    /// Drains every pending flow effect once: media sends immediately, feedback
    /// is batched into one compound, timers update the wheel, delivered payloads
    /// are queued for the application.
    async fn drain(&mut self, now: Timestamp) {
        let mut fbs = Vec::new();
        while let Some(out) = self.flow.poll_output() {
            match out {
                Output::SendMedia { pkt, .. } => {
                    if !pkt.retransmit && seq_after(pkt.seq, self.highest_sent) {
                        self.highest_sent = pkt.seq;
                    }
                    self.send_media(&pkt).await;
                    // FEC over the inner RTP payload (first transmissions only, in
                    // sequence order): send any completed FEC packets on the
                    // column/row ports.
                    if self.fec.is_some() && !pkt.retransmit {
                        self.send_fec_simple(&pkt).await;
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
        while let Some(Event::Deliver {
            seq,
            source_time,
            payload,
            discontinuity,
            ..
        }) = self.flow.poll_event()
        {
            match self
                .merger
                .deliver(seq, source_time, payload, discontinuity)
            {
                MergeOut::Hold => {}
                MergeOut::One(p) => {
                    if !self.deliver_out(p).await {
                        return; // the application Receiver was dropped.
                    }
                }
                MergeOut::Two(a, b) => {
                    if !self.deliver_out(a).await || !self.deliver_out(b).await {
                        return;
                    }
                }
            }
        }
        self.stats.publish(self.flow.stats(), self.fec_recovered());
    }

    /// Hands one application payload to the data channel, returning `false` if the
    /// application `Receiver` has been dropped (the caller stops the loop).
    async fn deliver_out(&self, payload: Bytes) -> bool {
        match &self.data_out {
            Some(out) => out.send(payload).await.is_ok(),
            None => true,
        }
    }

    /// Splits one outbound application payload across a consecutive even/odd sequence
    /// pair (libRIST `split=`) when split mode is active, else pushes it whole. Both
    /// halves carry the same `now`, so they share a source time — the pairing the peer
    /// merges on.
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

    /// Encodes and transmits one media datagram to the peer's media address.
    async fn send_media(&self, pkt: &MediaPacket) {
        let Some(dst) = self.peer.media() else { return };
        match codec::encode_media(pkt) {
            Ok(bytes) => {
                if let Err(e) = self.socket.send_media(&bytes, dst).await {
                    tracing::debug!(target: crate::logging::SOCKET, seq = pkt.seq, "rist: send media failed: {e}");
                }
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::SOCKET, seq = pkt.seq, "rist: encode media failed: {e}");
            }
        }
    }

    /// Clips one first-transmission media packet's RTP payload into the FEC matrix and
    /// sends any completed FEC packets as standard ST 2022-1 / ST 2022-5 RTP packets
    /// (PT 127) on the dedicated column (media port + 2) / row (+ 4) ports — the
    /// carriage a conforming ST 2022-1 receiver interoperates with.
    async fn send_fec_simple(&mut self, pkt: &MediaPacket) {
        let Some(media_dst) = self.peer.media() else {
            return;
        };
        if self.fec.is_none() {
            return;
        }
        let variant = self.fec.as_ref().unwrap().variant();
        let ts = codec::rtp_ts_from_source(pkt.source_time);
        let fps = self
            .fec
            .as_mut()
            .unwrap()
            .clip(pkt.seq, ts, FEC_PT, &pkt.payload);
        if fps.is_empty() {
            return;
        }
        let ssrc = self.ssrc;
        let sock = self.socket.clone();
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
            let mut dst = media_dst;
            dst.set_port(media_dst.port().wrapping_add(port_off));
            if let Err(e) = sock.send_media(&bytes, dst).await {
                tracing::debug!(target: crate::logging::SOCKET, "rist: send separate-port fec failed: {e}");
            }
        }
    }

    /// Builds one compound RTCP datagram from the drained feedback and transmits
    /// it to the peer's RTCP address.
    async fn send_feedback(&self, fbs: &[Feedback], now: Timestamp) {
        let Some(dst) = self.peer.rtcp() else {
            return; // return path not learned yet
        };
        let lead = self.feedback_lead(now);
        match codec::encode_feedback(lead, self.local_ssrc(), &self.cname, fbs, self.bitmask) {
            Ok(bytes) => {
                if let Err(e) = self.socket.send_rtcp(&bytes, dst).await {
                    tracing::debug!(target: crate::logging::RTCP, "rist: send rtcp failed: {e}");
                }
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::RTCP, "rist: encode feedback failed: {e}");
            }
        }
    }

    /// Emits one Link Quality Message (TR-06-4 Part 1) when a reporting period has
    /// elapsed: snapshots the flow stats into an LQM and sends it to the peer's RTCP
    /// address as an empty-RR profile-specific extension. A no-op when source
    /// adaptation is off or no reporting period has passed.
    async fn maybe_emit_lqm(&mut self, now: Timestamp) {
        if self.lqm.as_ref().is_none_or(|e| !e.due(now)) {
            return;
        }
        let Some(dst) = self.peer.rtcp() else {
            return;
        };
        let ssrc = self.local_ssrc();
        let stats = self.flow.stats();
        let fec = self.fec_recovered();
        let lqm = self
            .lqm
            .as_mut()
            .expect("emitter present (checked above)")
            .build(now, &stats, fec);
        let lqr = RtcpPacket::LinkQualityReport(rtcp::LinkQualityReport {
            ssrc,
            lqm: lqm.encode(),
        });
        if let Ok(bytes) = codec::encode_feedback(lqr, ssrc, &self.cname, &[], self.bitmask) {
            let _ = self.socket.send_rtcp(&bytes, dst).await;
        }
    }

    /// Sends a bare lead + SDES compound to keep NAT state alive and advertise the
    /// return address; the receiver learns the sender's RTCP source from it.
    async fn send_keepalive(&self, now: Timestamp) {
        // A one-way transport emits no control traffic (so its peer never sees it
        // and the sender never learns a return address to time out against).
        if self.flow.config().no_recovery {
            return;
        }
        let Some(dst) = self.peer.rtcp() else { return };
        let lead = self.feedback_lead(now);
        if let Ok(bytes) =
            codec::encode_feedback(lead, self.local_ssrc(), &self.cname, &[], self.bitmask)
        {
            let _ = self.socket.send_rtcp(&bytes, dst).await;
        }
    }

    /// The mandatory first compound packet: an SR on the sender, an empty RR on
    /// the receiver.
    #[allow(clippy::cast_possible_truncation)] // RTP timestamp wraps by design
    fn feedback_lead(&self, now: Timestamp) -> RtcpPacket {
        if self.sender {
            RtcpPacket::SenderReport(SenderReport {
                ssrc: self.ssrc,
                // Absolute wall-clock NTP (RFC 3550 §6.4.1) paired with the RTP
                // timestamp at the same instant, so a receiver can map RTP time to
                // wall-clock. RTT echoes use their own session-relative timestamps,
                // which cancel the epoch independently.
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

    /// The SSRC stamped into outbound RTCP: the configured flow SSRC on a sender,
    /// the learned media SSRC (or the configured reporter SSRC until learned) on
    /// a receiver.
    fn local_ssrc(&self) -> u32 {
        if self.sender {
            self.ssrc
        } else {
            self.learned_ssrc.unwrap_or(self.ssrc)
        }
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

/// Spawns the single-flow socket reader: it reads the media (even), RTCP (odd), and
/// separate-port FEC (column / row) sockets and funnels each datagram into the pump's
/// inbound channel. The loop exits when the media or RTCP socket errors (fatal for the
/// flow) or the pump drops the channel; the FEC sockets pend forever when unbound, so
/// those arms are then no-ops.
fn spawn_reader(
    socket: SimpleSocket,
    tx: mpsc::Sender<SimpleInbound>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut media_buf = vec![0u8; RECV_BUF];
        let mut rtcp_buf = vec![0u8; RECV_BUF];
        let mut col_buf = vec![0u8; RECV_BUF];
        let mut row_buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                r = socket.recv_media(&mut media_buf) => match r {
                    Ok((n, src)) => {
                        let inb = SimpleInbound::Media { data: Bytes::copy_from_slice(&media_buf[..n]), src };
                        if tx.send(inb).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
                r = socket.recv_rtcp(&mut rtcp_buf) => match r {
                    Ok((n, src)) => {
                        let inb = SimpleInbound::Rtcp { data: Bytes::copy_from_slice(&rtcp_buf[..n]), src };
                        if tx.send(inb).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
                r = socket.recv_fec_col(&mut col_buf) => if let Ok((n, _)) = r {
                    let inb = SimpleInbound::Fec { data: Bytes::copy_from_slice(&col_buf[..n]) };
                    if tx.send(inb).await.is_err() { break; }
                },
                r = socket.recv_fec_row(&mut row_buf) => if let Ok((n, _)) = r {
                    let inb = SimpleInbound::Fec { data: Bytes::copy_from_slice(&row_buf[..n]) };
                    if tx.send(inb).await.is_err() { break; }
                },
            }
        }
    })
}

/// Awaits the next application payload, or never resolves when there is no
/// application input channel (the receiver half).
/// Receives the next application payload, gated on `ready`: while `ready` is false the
/// future never resolves, so a reversed-role listener-sender holds its application
/// media until it has learned the caller's address. A normal sender knows its peer at
/// construction, so `ready` is always true and this is a plain receive.
pub(crate) async fn recv_app_gated(
    app_in: &mut Option<mpsc::Receiver<Bytes>>,
    ready: bool,
) -> Option<Bytes> {
    if !ready {
        return std::future::pending().await;
    }
    match app_in {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Awaits the next message on an optional control channel, or never resolves when
/// there is none (the role takes no such command). Generic over the command type so
/// every driver shares it for the runtime-setter channels ([`RxControl`], the NPD
/// `bool`). Mirrors the per-driver `recv_weight` helper, generalized.
pub(crate) async fn recv_opt<T>(ch: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    match ch {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Sleeps until `at`, or never resolves when there is no pending timer.
pub(crate) async fn sleep_until_opt(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Whether sequence `a` is circularly after `b` (wrap-aware).
pub(crate) fn seq_after(a: u32, b: u32) -> bool {
    Seq32::new(b).less(Seq32::new(a))
}

/// The current absolute wall-clock time as NTP-64 (seconds since 1900-01-01, RFC
/// 3550) for the RTCP Sender Report's NTP field, so a receiver can map RTP
/// timestamps to wall-clock time (RTC/arrival playout, synchronized multi-stream,
/// logging). The sans-I/O core never reads a wall clock — this is a host-only read,
/// stamped when the SR is built. Seconds beyond 2^32 wrap (the NTP era, ~2036),
/// matching libRIST and every other RTCP sender.
pub(crate) fn wall_clock_ntp() -> u64 {
    /// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
    const UNIX_TO_NTP_SECS: u128 = 2_208_988_800;
    let since_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let micros_since_ntp_epoch = since_unix.as_micros() + UNIX_TO_NTP_SECS * 1_000_000;
    let micros = u64::try_from(micros_since_ntp_epoch).unwrap_or(u64::MAX);
    Ntp64::from_timestamp(Timestamp::from_micros(micros)).bits()
}
