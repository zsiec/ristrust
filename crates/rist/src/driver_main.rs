//! The async driver for the Main profile (VSF TR-06-2): the `select!` pump that
//! turns the sans-I/O flow core into GRE-over-UDP I/O on a single port.
//!
//! It mirrors the Simple-profile [`Driver`](crate::driver::Driver) — same timer
//! wheel, same flow-drive-and-drain loop, same thin-dumb-pump discipline — but
//! multiplexes media and compound RTCP through one [`MainSocket`] using the
//! stateful [`MainCodec`], which carries the GRE framing, the per-datagram GRE
//! sequence, and the optional PSK encryption. Liveness rides on GRE keepalives
//! instead of bare RTCP. No protocol logic lives here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use rist_codec::eap::{self, Authenticatee, Authenticator};
use rist_codec::gre;
use rist_codec::rtcp::{
    EmptyReceiverReport, LinkQualityReport, Packet as RtcpPacket, SenderReport,
};
use rist_core::clock::Timestamp;
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::Feedback;

use crate::adapt::{LqmEmitter, RateControl};
use crate::codec_main::{ControlKind, Decoded, MainCodec};
use crate::driver::{COMMAND_CAPACITY, CloseFlag, DATA_CAPACITY};
use crate::peer::Peer;
use crate::socket::MainSocket;

/// The largest datagram the driver will receive.
const RECV_BUF: usize = 65_536;

/// The EAP-SRP authentication role of a Main-profile flow, when authentication is
/// configured: the sender authenticates (authenticatee), the listener verifies
/// (authenticator). Both drive the same EAPOL message exchange.
pub(crate) enum EapRole {
    /// The side being authenticated (a sender). Opens with EAPOL-START.
    Authenticatee(Box<Authenticatee>),
    /// The side verifying a peer (a listener). Responds to EAPOL-START.
    Authenticator(Box<Authenticator>),
}

impl EapRole {
    /// Feeds one received EAP payload to the role and returns the reply frame's wire
    /// bytes, if any. The error (if any) is logged; a failure still emits its frame.
    pub(crate) fn recv(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let reply = match self {
            EapRole::Authenticatee(a) => a.recv(payload),
            EapRole::Authenticator(a) => a.recv(payload),
        };
        if let Some(e) = &reply.error {
            tracing::debug!("rist: eap: {e}");
        }
        reply.frame.map(|f| {
            let mut w = Vec::new();
            f.append_to(&mut w);
            w
        })
    }

    /// Whether authentication has succeeded.
    pub(crate) fn authenticated(&self) -> bool {
        match self {
            EapRole::Authenticatee(a) => a.authenticated(),
            EapRole::Authenticator(a) => a.authenticated(),
        }
    }

    /// Whether the handshake reached a terminal failure (the credentials were
    /// rejected): the role is done but not authenticated.
    pub(crate) fn failed(&self) -> bool {
        match self {
            EapRole::Authenticatee(a) => a.done() && !a.authenticated(),
            EapRole::Authenticator(a) => a.done() && !a.authenticated(),
        }
    }

    /// The 32-byte SRP session key K derived during a successful handshake.
    pub(crate) fn session_key(&self) -> Option<[u8; 32]> {
        match self {
            EapRole::Authenticatee(a) => a.session_key(),
            EapRole::Authenticator(a) => a.session_key(),
        }
    }
}

/// The EAP identifier ristrust stamps on its unsolicited passphrase push (bit 6
/// set, matching libRIST's passphrase-request identifier convention).
const PASSPHRASE_PUSH_ID: u8 = 0x40;

/// The Main-profile session driver, run as one detached task per flow.
// Justification: `sender`/`greeted`/`authed`/`bitmask` are independent per-flow
// flags, not a state enum; collapsing them would obscure the pump's control flow.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct MainDriver {
    /// Whether this is the media-originating (sender) half.
    sender: bool,
    flow: Flow,
    socket: MainSocket,
    peer: Peer,
    /// The session clock epoch: `now()` is microseconds since this instant.
    epoch: Instant,
    /// Declarative timers the flow has requested, by id.
    timers: HashMap<TimerId, Timestamp>,
    keepalive: Duration,
    /// The stateful Main-profile codec (GRE framing, GRE sequence, PSK).
    codec: MainCodec,
    /// The 48-bit MAC advertised in outbound GRE keepalives (informational).
    mac: [u8; 6],
    bitmask: bool,
    /// Records why the task exited, read by the handle once its channel closes.
    close: CloseFlag,

    // --- sender half ---
    app_in: Option<mpsc::Receiver<Bytes>>,
    /// The highest first-transmission sequence sent, the NACK-widening reference.
    highest_sent: u32,
    /// The local flow SSRC (stamped into the SR/echo).
    ssrc: u32,

    // --- receiver half ---
    data_out: Option<mpsc::Sender<Bytes>>,
    /// The media SSRC learned from the first inbound packet.
    learned_ssrc: Option<u32>,
    /// Whether the initial GRE+RTCP handshake has been sent. libRIST gates media
    /// on authenticating the peer via its RTCP SDES, so the handshake must go out
    /// before media — at startup (sender) or on first learning the peer (receiver).
    greeted: bool,

    // --- EAP-SRP authentication (Main profile) ---
    /// The EAP role, when authentication is configured; `None` disables auth.
    eap: Option<EapRole>,
    /// Whether the data channel is unblocked: `true` immediately when no auth is
    /// configured, else only once the EAP-SRP handshake succeeds. A sender holds
    /// outbound media until this is set.
    authed: bool,

    // --- source adaptation (TR-06-4 Part 1) ---
    /// The receiver's Link Quality Message emitter, when source adaptation is on.
    lqm: Option<LqmEmitter>,
    /// The sender's rate controller, when a rate callback is configured.
    rate: Option<RateControl>,
}

impl MainDriver {
    /// Builds and spawns a Main-profile sender driver, returning the application
    /// payload channel and the driver task handle.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_sender(
        flow: Flow,
        socket: MainSocket,
        peer: Peer,
        codec: MainCodec,
        ssrc: u32,
        mac: [u8; 6],
        bitmask: bool,
        keepalive: Duration,
        start_seq: u32,
        eap: Option<EapRole>,
        rate: Option<RateControl>,
    ) -> (mpsc::Sender<Bytes>, CloseFlag, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let driver = MainDriver {
            sender: true,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            codec,
            mac,
            bitmask,
            close: close.clone(),
            app_in: Some(rx),
            highest_sent: start_seq,
            ssrc,
            data_out: None,
            learned_ssrc: None,
            greeted: false,
            eap,
            authed,
            lqm: None,
            rate,
        };
        (tx, close, tokio::spawn(driver.run()))
    }

    /// Builds and spawns a Main-profile receiver driver that learns the sender's
    /// return address from inbound traffic, returning the delivered-data channel and
    /// the driver task handle.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_receiver(
        flow: Flow,
        socket: MainSocket,
        peer: Peer,
        codec: MainCodec,
        ssrc: u32,
        mac: [u8; 6],
        bitmask: bool,
        keepalive: Duration,
        eap: Option<EapRole>,
        lqm: Option<LqmEmitter>,
    ) -> (
        mpsc::Receiver<Bytes>,
        CloseFlag,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let driver = MainDriver {
            sender: false,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            codec,
            mac,
            bitmask,
            close: close.clone(),
            app_in: None,
            highest_sent: 0,
            ssrc,
            data_out: Some(tx),
            learned_ssrc: None,
            greeted: false,
            eap,
            authed,
            lqm,
            rate: None,
        };
        (rx, close, tokio::spawn(driver.run()))
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

    /// The driver loop. Runs until the application channel closes, the peer expires,
    /// or a socket error occurs.
    async fn run(mut self) {
        let sock = self.socket.clone();
        let mut buf = vec![0u8; RECV_BUF];

        // A sender knows the peer's address up front; greet it immediately (the
        // RTCP SDES that ungates libRIST's media, plus the GRE MAC beacon) so the
        // peer authenticates us before our media arrives. When authenticating, also
        // open the EAP-SRP handshake with EAPOL-START.
        if self.sender {
            let now = self.now();
            self.greet(now).await;
            self.send_eap_start().await;
        }

        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            tokio::select! {
                r = sock.recv(&mut buf) => match r {
                    Ok((n, src)) => self.on_recv(src, &buf[..n]).await,
                    Err(_) => break,
                },
                // Hold outbound media until the EAP-SRP handshake authenticates the
                // data channel (a no-op when authentication is disabled).
                payload = recv_app_gated(&mut self.app_in, self.authed) => match payload {
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
                    if self.eap.as_ref().is_some_and(EapRole::failed) {
                        self.close.set_auth();
                        break;
                    }
                    if self.peer.expired(now) {
                        self.close.set_session_timeout();
                        break;
                    }
                    if self.peer.media().is_some() {
                        // The periodic RTCP handshake keeps the session alive and
                        // re-authenticated; the GRE MAC beacon mirrors libRIST's
                        // separate keepalive timer.
                        self.send_handshake(now).await;
                        self.send_keepalive(now).await;
                        // Source adaptation: emit a Link Quality Message when a
                        // reporting period has elapsed (receiver only).
                        self.maybe_emit_lqm(now).await;
                    }
                },
            }
        }
    }

    /// Handles one inbound datagram: learns the peer address and liveness, then
    /// routes it as a keepalive (control), media, or feedback.
    async fn on_recv(&mut self, src: SocketAddr, data: &[u8]) {
        let now = self.now();
        self.peer.learn_media(src);
        self.peer.observe(now);

        // On first learning the peer (the receiver's case), greet it so libRIST
        // ungates its media toward us promptly.
        if !self.greeted && self.peer.media().is_some() {
            self.greet(now).await;
        }

        // EAP-SRP authentication frames (GRE EAPOL, never encrypted) drive the
        // handshake, not the flow. Copy the payload out so the codec borrow ends
        // before driving the role.
        if let Some(eap_payload) = self.codec.peek_eapol(data).map(<[u8]>::to_vec) {
            self.handle_eap(&eap_payload).await;
            self.drain(now).await;
            return;
        }

        // Drop all non-EAPOL flow input from a peer that has not completed the
        // EAP-SRP handshake: an unauthenticated peer's media/feedback must never
        // reach the flow core. A no-op when authentication is disabled (`authed` is
        // then true from the start).
        if !self.authed {
            self.drain(now).await;
            return;
        }

        // A GRE keepalive is a liveness signal only — nothing for the flow.
        let (kind, _ka, _ver) = self.codec.peek_control(data);
        if kind != ControlKind::Keepalive {
            match self.codec.decode(data, self.highest_sent) {
                Ok(Decoded::Media(pkt)) => {
                    if self.learned_ssrc.is_none() {
                        self.learned_ssrc = Some(pkt.ssrc);
                    }
                    if let Some(e) = &mut self.lqm {
                        e.meter(pkt.payload.len(), pkt.retransmit);
                    }
                    self.flow.feed(now, 0, pkt);
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
                            self.flow.feed_feedback(now, fb);
                        }
                    }
                }
                Ok(Decoded::Ignored) => {}
                Err(e) => crate::driver::decode_warn(self.codec.has_psk(), "main", &e),
            }
        }
        self.drain(now).await;
    }

    /// Drains every pending flow effect once: media datagrams send immediately,
    /// feedback is batched into one compound, timers update the wheel, delivered
    /// payloads are queued for the application.
    async fn drain(&mut self, now: Timestamp) {
        let sock = self.socket.clone();
        let mut fbs = Vec::new();
        while let Some(out) = self.flow.poll_output() {
            match out {
                Output::SendMedia { pkt, .. } => {
                    if !pkt.retransmit && seq_after(pkt.seq, self.highest_sent) {
                        self.highest_sent = pkt.seq;
                    }
                    let Some(dst) = self.peer.media() else {
                        continue;
                    };
                    match self.codec.encode_media(&pkt) {
                        Ok(bytes) => {
                            if let Err(e) = sock.send(&bytes, dst).await {
                                tracing::debug!(seq = pkt.seq, "rist: send media failed: {e}");
                            }
                        }
                        Err(e) => tracing::debug!(seq = pkt.seq, "rist: encode media failed: {e}"),
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
                return; // the application Receiver was dropped.
            }
        }
    }

    /// Builds one compound RTCP datagram from the drained feedback and transmits it
    /// (GRE-framed, encrypted under the PSK when configured) to the peer.
    async fn send_feedback(&mut self, fbs: &[rist_core::wire::Feedback], now: Timestamp) {
        let Some(dst) = self.peer.media() else {
            return; // peer address not learned yet
        };
        let lead = self.feedback_lead(now);
        let sock = self.socket.clone();
        match self.codec.encode_feedback(lead, fbs, self.bitmask) {
            Ok(bytes) => {
                if let Err(e) = sock.send(&bytes, dst).await {
                    tracing::debug!("rist: send feedback failed: {e}");
                }
            }
            Err(e) => tracing::debug!("rist: encode feedback failed: {e}"),
        }
    }

    /// Sends the initial handshake — the GRE-framed RTCP (SR/RR + SDES) compound
    /// that authenticates this peer to libRIST and ungates its media, plus the GRE
    /// MAC beacon — and marks the session greeted.
    async fn greet(&mut self, now: Timestamp) {
        self.send_handshake(now).await;
        self.send_keepalive(now).await;
        self.greeted = true;
    }

    /// Sends one GRE-framed RTCP compound (the SR/RR lead + SDES, no feedback) to
    /// the peer. libRIST gates inbound media on authenticating us via this SDES, so
    /// it must precede our media; it also keeps the control plane alive while idle.
    async fn send_handshake(&mut self, now: Timestamp) {
        let Some(dst) = self.peer.media() else { return };
        let lead = self.feedback_lead(now);
        let sock = self.socket.clone();
        if let Ok(bytes) = self.codec.encode_feedback(lead, &[], self.bitmask) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Sends a GRE keepalive carrying this node's MAC and standard capabilities, to
    /// keep the session alive and advertise the return address.
    async fn send_keepalive(&mut self, _now: Timestamp) {
        let Some(dst) = self.peer.media() else { return };
        let ka = gre::Keepalive {
            mac: self.mac,
            caps: gre::Capabilities::standard(),
            ..gre::Keepalive::default()
        };
        let sock = self.socket.clone();
        if let Ok(bytes) = self.codec.encode_keepalive(&ka, gre::VERSION_MIN) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Emits one Link Quality Message (TR-06-4 Part 1) when a reporting period has
    /// elapsed: snapshots the flow stats into an LQM, frames it as the GRE-tunnelled
    /// RR profile-specific extension, and sends it to the peer. A no-op when source
    /// adaptation is off or no reporting period has passed.
    async fn maybe_emit_lqm(&mut self, now: Timestamp) {
        if self.lqm.as_ref().is_none_or(|e| !e.due(now)) {
            return;
        }
        let Some(dst) = self.peer.media() else {
            return;
        };
        let ssrc = self.local_ssrc();
        let stats = self.flow.stats();
        let lqm = self
            .lqm
            .as_mut()
            .expect("emitter present (checked above)")
            .build(now, &stats);
        let lqr = LinkQualityReport {
            ssrc,
            lqm: lqm.encode(),
        };
        let sock = self.socket.clone();
        match self
            .codec
            .encode_feedback(RtcpPacket::LinkQualityReport(lqr), &[], self.bitmask)
        {
            Ok(bytes) => {
                let _ = sock.send(&bytes, dst).await;
            }
            Err(e) => tracing::debug!("rist: main lqm encode failed: {e}"),
        }
    }

    /// Opens the EAP-SRP handshake by sending EAPOL-START (authenticatee only).
    async fn send_eap_start(&mut self) {
        let start = match self.eap.as_mut() {
            Some(EapRole::Authenticatee(a)) => {
                let mut w = Vec::new();
                a.start().append_to(&mut w);
                w
            }
            _ => return,
        };
        self.send_eapol(&start).await;
    }

    /// Drives the EAP role with one received EAP payload, transmitting any reply
    /// frame and updating the authenticated gate. On the transition to
    /// authenticated it re-keys the data channel to the SRP session key and pushes
    /// it to the peer.
    async fn handle_eap(&mut self, payload: &[u8]) {
        let was_authed = self.authed;
        let Some(role) = self.eap.as_mut() else {
            return;
        };
        let reply = role.recv(payload);
        self.authed = self.eap.as_ref().is_some_and(EapRole::authenticated);
        if let Some(wire) = reply {
            self.send_eapol(&wire).await;
        }
        // On the transition to authenticated, key the data channel. A configured
        // PSK secret keys it already (SRP only gates); with no PSK, re-key to the
        // SRP session key K and push it to the peer.
        if self.authed && !was_authed && !self.codec.has_psk() {
            self.on_authenticated().await;
        }
    }

    /// On reaching authentication with no configured PSK, re-keys the data channel
    /// to the SRP session key K (libRIST's post-SRP data passphrase) and pushes
    /// "use K" to the peer so it sets its receive passphrase to K.
    async fn on_authenticated(&mut self) {
        let Some(key) = self.eap.as_ref().and_then(EapRole::session_key) else {
            return;
        };
        if let Err(e) = self.codec.set_psk(&key) {
            tracing::debug!("rist: main: post-auth re-key failed: {e}");
            return;
        }
        let mut wire = Vec::new();
        eap::passphrase_push(PASSPHRASE_PUSH_ID).append_to(&mut wire);
        self.send_eapol(&wire).await;
    }

    /// Frames an EAP payload in a GRE EAPOL datagram and sends it to the peer.
    async fn send_eapol(&mut self, eap: &[u8]) {
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        if let Ok(bytes) = self.codec.encode_eapol(eap) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// The mandatory first compound packet: an SR on the sender, an empty RR on the
    /// receiver.
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
    /// the learned media SSRC (or the configured reporter SSRC until learned) on a
    /// receiver.
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

/// Awaits the next application payload when the data channel is authenticated;
/// never resolves while `authed` is false (holding outbound media until the
/// EAP-SRP handshake completes) or when there is no application input channel.
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
