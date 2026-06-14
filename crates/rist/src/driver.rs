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
use rist_core::clock::{Ntp64, Timestamp};
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::{Feedback, MediaPacket};

use crate::adapt::{LqmEmitter, RateControl};
use crate::codec::{self, MediaDecoder};
use crate::peer::Peer;
use crate::socket::SimpleSocket;

/// The largest datagram the driver will receive.
const RECV_BUF: usize = 65_536;

/// Capacity of the application → driver payload channel (sender side).
pub(crate) const COMMAND_CAPACITY: usize = 256;

/// Capacity of the driver → application delivered-data channel (receiver side).
pub(crate) const DATA_CAPACITY: usize = 1024;

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

    // --- sender half ---
    /// Application payloads to transmit (`None` on a receiver).
    app_in: Option<mpsc::Receiver<Bytes>>,
    /// The highest first-transmission sequence sent, the NACK-widening reference.
    highest_sent: u32,
    /// The local flow SSRC (stamped into media and the SR/echo).
    ssrc: u32,
    cname: String,
    bitmask: bool,

    // --- receiver half ---
    /// Delivered in-order payloads handed to the application (`None` on a sender).
    data_out: Option<mpsc::Sender<Bytes>>,
    mdec: MediaDecoder,
    /// The media SSRC learned from the first inbound packet (the receiver's
    /// reporter SSRC until then).
    learned_ssrc: Option<u32>,

    // --- source adaptation (TR-06-4 Part 1) ---
    /// The receiver's Link Quality Message emitter, when source adaptation is on.
    lqm: Option<LqmEmitter>,
    /// The sender's rate controller, when a rate callback is configured.
    rate: Option<RateControl>,
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
    ) -> (mpsc::Sender<Bytes>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let driver = Driver {
            sender: true,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            app_in: Some(rx),
            highest_sent: start_seq,
            ssrc,
            cname,
            bitmask,
            data_out: None,
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            lqm: None,
            rate,
        };
        (tx, tokio::spawn(driver.run()))
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
    ) -> (mpsc::Receiver<Bytes>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let driver = Driver {
            sender: false,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            app_in: None,
            highest_sent: 0,
            ssrc,
            cname,
            bitmask,
            data_out: Some(tx),
            mdec: MediaDecoder::new(),
            learned_ssrc: None,
            lqm,
            rate: None,
        };
        (rx, tokio::spawn(driver.run()))
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
        let sock = self.socket.clone();
        let mut media_buf = vec![0u8; RECV_BUF];
        let mut rtcp_buf = vec![0u8; RECV_BUF];

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

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            tokio::select! {
                r = sock.recv_media(&mut media_buf) => match r {
                    Ok((n, src)) => self.on_media(src, &media_buf[..n]).await,
                    Err(_) => break,
                },
                r = sock.recv_rtcp(&mut rtcp_buf) => match r {
                    Ok((n, src)) => self.on_rtcp(src, &rtcp_buf[..n]).await,
                    Err(_) => break,
                },
                payload = recv_app(&mut self.app_in) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.flow.push_app(now, p);
                        self.drain(now).await;
                    }
                    None => break, // sender's app channel closed: shut down.
                },
                () = sleep_until_opt(timer_at) => {
                    let now = self.now();
                    self.fire_timers(now);
                    self.drain(now).await;
                },
                _ = keepalive.tick() => {
                    let now = self.now();
                    if self.peer.expired(now) {
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
                },
            }
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
            self.flow.feed(now, 0, pkt);
        }
        self.drain(now).await;
    }

    /// Handles one inbound RTCP datagram (feedback path).
    async fn on_rtcp(&mut self, src: SocketAddr, data: &[u8]) {
        let now = self.now();
        self.peer.learn_rtcp(src);
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
                return; // the application Receiver was dropped.
            }
        }
    }

    /// Encodes and transmits one media datagram to the peer's media address.
    async fn send_media(&self, pkt: &MediaPacket) {
        let Some(dst) = self.peer.media() else { return };
        match codec::encode_media(pkt) {
            Ok(bytes) => {
                if let Err(e) = self.socket.send_media(&bytes, dst).await {
                    tracing::debug!(seq = pkt.seq, "rist: send media failed: {e}");
                }
            }
            Err(e) => tracing::debug!(seq = pkt.seq, "rist: encode media failed: {e}"),
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
                    tracing::debug!("rist: send rtcp failed: {e}");
                }
            }
            Err(e) => tracing::debug!("rist: encode feedback failed: {e}"),
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
        let lqm = self
            .lqm
            .as_mut()
            .expect("emitter present (checked above)")
            .build(now, &stats);
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

/// Awaits the next application payload, or never resolves when there is no
/// application input channel (the receiver half).
async fn recv_app(app_in: &mut Option<mpsc::Receiver<Bytes>>) -> Option<Bytes> {
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
