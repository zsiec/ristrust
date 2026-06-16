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
use rist_codec::rtcp::{
    EmptyReceiverReport, LinkQualityReport, Packet as RtcpPacket, SenderReport,
};
use rist_codec::{fec_header, gre, rtp};
use rist_core::clock::{Micros, Timestamp};
use rist_core::fec::{Direction, Recovered};
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::{Feedback, FragRole, MediaPacket};

use crate::adapt::{LqmEmitter, RateControl};
use crate::codec::{self};
use crate::codec_main::{ControlKind, Decoded, MainCodec};
use crate::driver::{COMMAND_CAPACITY, CloseFlag, DATA_CAPACITY, INBOUND_CAPACITY};
use crate::fec::{FEC_COLUMN_PORT_OFFSET, FEC_PT, FEC_ROW_PORT_OFFSET, FecState};
use crate::peer::Peer;
use crate::socket::MainSocket;
use crate::stats::StatsCell;

/// The largest datagram the driver will receive.
const RECV_BUF: usize = 65_536;

/// One inbound Main-profile datagram, tagged with the socket it arrived on. The pump
/// drains these from a channel (the injected-feed seam): a single-flow driver fills it
/// from its own reader task; a multi-flow [`MultiReceiver`](crate::multi) fills many
/// drivers' channels from one shared read, keyed by source address.
pub(crate) enum MainInbound {
    /// A GRE datagram (media / control / keepalive / EAPOL / OOB) and its source.
    Main { data: Bytes, src: SocketAddr },
    /// A separate-port FEC datagram (column or row; decoded identically).
    Fec { data: Bytes },
}

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
            tracing::debug!(target: crate::logging::CRYPTO, "rist: eap: {e}");
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

    /// Restarts the role's state machine for a forced re-authentication (a NAT
    /// source-port rebind), discarding the prior session so a fresh handshake must
    /// complete before the migrated peer is trusted again.
    pub(crate) fn restart(&mut self) {
        match self {
            EapRole::Authenticatee(a) => a.restart(),
            EapRole::Authenticator(a) => a.restart(),
        }
    }

    /// Re-opens the handshake after a peer migration, returning the opening frame's
    /// wire bytes: an authenticatee re-emits EAPOL-START, an authenticator re-issues
    /// the identity request. Call [`restart`](Self::restart) first.
    pub(crate) fn reopen(&mut self) -> Vec<u8> {
        let frame = match self {
            EapRole::Authenticatee(a) => a.start(),
            EapRole::Authenticator(a) => a.start(),
        };
        let mut w = Vec::new();
        frame.append_to(&mut w);
        w
    }
}

/// The EAP identifier ristrust stamps on its unsolicited passphrase push (bit 6
/// set, matching libRIST's passphrase-request identifier convention).
const PASSPHRASE_PUSH_ID: u8 = 0x40;

/// The Main-profile session driver, run as one detached task per flow.
// Justification: `sender`/`greeted`/`authed`/`bitmask`/`ever_authed`/`reauthing`
// are independent per-flow flags, not a state enum; collapsing them would obscure
// the pump's control flow.
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
    /// The latest stats snapshot published to the handle's `stats()`.
    stats: StatsCell,

    // --- sender half ---
    app_in: Option<mpsc::Receiver<Bytes>>,
    /// The highest first-transmission sequence sent, the NACK-widening reference.
    highest_sent: u32,
    /// The local flow SSRC (stamped into the SR/echo).
    ssrc: u32,
    /// Application out-of-band datagrams to transmit (`Sender::write_oob`); `Some`
    /// on a sender. Each is `(GRE protocol type, payload)`.
    oob_in: Option<mpsc::Receiver<(u16, Vec<u8>)>>,

    // --- receiver half ---
    data_out: Option<mpsc::Sender<Bytes>>,
    /// Received out-of-band datagrams handed to `Receiver::read_oob`; `Some` on a
    /// receiver. Each is `(GRE protocol type, payload)`.
    oob_out: Option<mpsc::Sender<(u16, Bytes)>>,
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
    /// The peer's RTCP SDES CNAME, recorded only from ENCRYPTED RTCP under an
    /// authenticated SRP session — the identity a migrated tuple must re-present to
    /// trigger a NAT source-port rebind re-association. `None` until learned.
    peer_cname: Option<String>,
    /// Whether the EAP-SRP handshake has succeeded at least once. Distinguishes an
    /// initial auth failure (tear the session down) from a re-auth failure (hold
    /// media), and gates CNAME-based re-association on a proven identity.
    ever_authed: bool,
    /// Whether a NAT-rebind / in-band EAP re-authentication is in flight: media is
    /// held (`authed` false) on the as-yet-unproven tuple and the ordinary
    /// session-timeout teardown is suppressed until [`reauth_deadline`](Self::reauth_deadline).
    reauthing: bool,
    /// When an unfinished re-auth tears the session down (a stalled or forged
    /// handshake must not pin the session open). Meaningful only while `reauthing`.
    reauth_deadline: Timestamp,
    /// Whether the authenticatee's opening EAPOL-START has been sent. A dialing
    /// sender knows its peer at startup and starts immediately; a listener-sender
    /// has no peer yet and starts only once it learns the caller (this latch fires
    /// the START exactly once). A forced re-auth re-opens via [`start_reauth`](Self::start_reauth),
    /// not this latch.
    eap_start_sent: bool,

    // --- source adaptation (TR-06-4 Part 1) ---
    /// The receiver's Link Quality Message emitter, when source adaptation is on.
    lqm: Option<LqmEmitter>,
    /// The sender's rate controller, when a rate callback is configured.
    rate: Option<RateControl>,

    // --- forward error correction (TR-06-2 §8.4, separate-port carriage) ---
    /// The FEC engine when FEC is configured: the sender clips each first-tx RTP
    /// payload (NPD-canonicalized, §8.6.2) and sends FEC as RTP on the column/row
    /// ports; the receiver reads those ports and re-injects recoveries into the flow.
    fec: Option<FecState>,

    // --- inbound feed ---
    /// The channel the pump drains inbound datagrams from. In single-flow mode `reader`
    /// fills it from the owned socket; in multi-flow mode a demultiplexer fills it.
    inbound: Option<mpsc::Receiver<MainInbound>>,
    /// The owned socket-reader task (single-flow); `None` when a demultiplexer feeds
    /// `inbound`. Aborted when the pump exits.
    reader: Option<tokio::task::JoinHandle<()>>,
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
        oob_in: mpsc::Receiver<(u16, Vec<u8>)>,
        fec: Option<FecState>,
    ) -> (
        mpsc::Sender<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let reader = spawn_reader(socket.clone(), in_tx);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let stats = StatsCell::default();
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
            stats: stats.clone(),
            app_in: Some(rx),
            highest_sent: start_seq,
            ssrc,
            oob_in: Some(oob_in),
            data_out: None,
            oob_out: None,
            learned_ssrc: None,
            greeted: false,
            eap,
            authed,
            peer_cname: None,
            ever_authed: false,
            reauthing: false,
            reauth_deadline: Timestamp::ZERO,
            eap_start_sent: false,
            lqm: None,
            rate,
            fec,
            inbound: Some(in_rx),
            reader: Some(reader),
        };
        (tx, close, stats, tokio::spawn(driver.run()))
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
        oob_out: mpsc::Sender<(u16, Bytes)>,
        fec: Option<FecState>,
    ) -> (
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let reader = spawn_reader(socket.clone(), in_tx);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let stats = StatsCell::default();
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
            stats: stats.clone(),
            app_in: None,
            highest_sent: 0,
            ssrc,
            oob_in: None,
            data_out: Some(tx),
            oob_out: Some(oob_out),
            learned_ssrc: None,
            greeted: false,
            eap,
            authed,
            peer_cname: None,
            ever_authed: false,
            reauthing: false,
            reauth_deadline: Timestamp::ZERO,
            eap_start_sent: false,
            lqm,
            rate: None,
            fec,
            inbound: Some(in_rx),
            reader: Some(reader),
        };
        (rx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns an **injected** Main-profile receiver driver for a
    /// [`MultiReceiver`](crate::multi): it owns no socket reader — the demultiplexer
    /// (keyed by source address) feeds its inbound channel (the returned [`MainInbound`]
    /// sender) — while this driver runs its own GRE substrate, per-flow PSK/EAP, and
    /// recovery, writing feedback back out the shared socket to its learned peer.
    /// Returns the inbound sender plus the receiver handles (delivered data + OOB).
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_injected_receiver(
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
        oob_out: mpsc::Sender<(u16, Bytes)>,
    ) -> (
        mpsc::Sender<MainInbound>,
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(INBOUND_CAPACITY);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let stats = StatsCell::default();
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
            stats: stats.clone(),
            app_in: None,
            highest_sent: 0,
            ssrc,
            oob_in: None,
            data_out: Some(tx),
            oob_out: Some(oob_out),
            learned_ssrc: None,
            greeted: false,
            eap,
            authed,
            peer_cname: None,
            ever_authed: false,
            reauthing: false,
            reauth_deadline: Timestamp::ZERO,
            eap_start_sent: false,
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

    /// The driver loop. Runs until the application channel closes, the peer expires,
    /// or a socket error occurs.
    async fn run(mut self) {
        // Inbound datagrams arrive over a channel (the injected-feed seam): in
        // single-flow mode `reader` fills it from the owned socket; in multi-flow mode
        // a demultiplexer keyed by source address fills it.
        let mut inbound = self.inbound.take().expect("inbound channel set at spawn");

        // Greet a peer whose address is known up front: a dialing sender (the RTCP
        // SDES that ungates media + the GRE MAC beacon) and, for reversed-role, a
        // caller-receiver announcing itself to a listening sender so the latter
        // learns where to send. A listening sender has no peer yet and greets later,
        // on first learning the caller. When authenticating, also open EAPOL-START.
        if self.sender || self.peer.media().is_some() {
            let now = self.now();
            self.greet(now).await;
        }
        // Open the EAP-SRP handshake (authenticatee only). A dialing sender knows its
        // peer up front and starts now; a listener-sender has no peer yet and starts
        // later, once `on_recv` learns the caller.
        self.maybe_start_eap().await;

        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            tokio::select! {
                msg = inbound.recv() => match msg {
                    Some(inb) => self.on_inbound(inb).await,
                    None => break, // the reader exited (socket error) or the demuxer closed
                },
                // Hold outbound media until the data channel is unblocked: the
                // EAP-SRP handshake has authenticated (a no-op when auth is disabled)
                // AND the peer's address is known. The latter is always true for a
                // dialing sender; for a reversed-role listener-sender it holds media
                // until a caller-receiver announces itself.
                payload = recv_app_gated(&mut self.app_in, self.authed && self.peer.media().is_some()) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.flow.push_app(now, p);
                        self.drain(now).await;
                    }
                    None => break, // sender's app channel closed: shut down.
                },
                // Application out-of-band datagrams (fire-and-forget, gated on auth
                // like media): GRE-frame and send directly, outside the flow core.
                oob = recv_oob_gated(&mut self.oob_in, self.authed) => match oob {
                    Some((proto, payload)) => self.send_oob(&payload, proto).await,
                    None => self.oob_in = None, // write side closed: stop watching
                },
                () = sleep_until_opt(timer_at) => {
                    let now = self.now();
                    self.fire_timers(now);
                    self.drain(now).await;
                },
                _ = keepalive.tick() => {
                    let now = self.now();
                    // An initial auth failure (the handshake never succeeded) tears the
                    // session down. A failure AFTER a prior success is a re-auth failure,
                    // handled in `handle_eap` (media held, re-auth window armed) — not here.
                    if !self.ever_authed && self.eap.as_ref().is_some_and(EapRole::failed) {
                        self.close.set_auth();
                        break;
                    }
                    // Liveness / teardown. While a NAT-rebind / in-band re-auth holds media
                    // on an as-yet-unproven tuple, the ordinary expiry teardown is SUPPRESSED
                    // so a genuine re-auth gets its full round-trip (the rebind only fires once
                    // the old tuple is already dormant, so expiry would otherwise fire on the
                    // very next tick). The window is bounded by `reauth_deadline`: a stalled or
                    // forged re-auth that cannot complete must not pin the session open, so when
                    // it lapses the session IS torn down (a fresh reconnect re-establishes it).
                    if self.reauthing {
                        if now > self.reauth_deadline {
                            self.reauthing = false;
                            self.close.set_session_timeout();
                            break;
                        }
                    } else if self.peer.expired(now) {
                        self.close.set_session_timeout();
                        break;
                    }
                    // Periodic keepalive — suppressed during a re-auth: the peer tuple is
                    // unproven then, so a full RTCP/GRE beacon must not be reflected to it
                    // (a forged trigger carrying a victim source could otherwise turn this
                    // into a reflection); only the EAPOL handshake is sent to it.
                    if self.peer.media().is_some() && !self.reauthing {
                        // The periodic RTCP handshake keeps the session alive and
                        // re-authenticated; the GRE MAC beacon mirrors libRIST's
                        // separate keepalive timer.
                        self.send_handshake(now).await;
                        self.send_keepalive(now).await;
                        // Advertise this sender's max recovery buffer so the receiver
                        // can auto-scale (GRE-v2 buffer negotiation; sender-only).
                        self.send_buffer_neg(now).await;
                        // Source adaptation: emit a Link Quality Message when a
                        // reporting period has elapsed (receiver only).
                        self.maybe_emit_lqm(now).await;
                    }
                },
            }
        }

        if let Some(reader) = self.reader.take() {
            reader.abort();
        }
    }

    /// Dispatches one inbound datagram by the socket it arrived on.
    async fn on_inbound(&mut self, inb: MainInbound) {
        match inb {
            MainInbound::Main { data, src } => self.on_recv(src, &data).await,
            MainInbound::Fec { data } => self.on_fec_rtp(&data).await,
        }
    }

    /// Handles one inbound datagram: learns the peer address and liveness, then
    /// routes it as a keepalive (control), media, or feedback.
    async fn on_recv(&mut self, src: SocketAddr, data: &[u8]) {
        let now = self.now();

        // NAT source-port rebind recovery: on an authenticated SRP session a datagram
        // from a source other than the established peer is consumed here (re-associated
        // under a forced EAP-SRP re-auth, or ignored) instead of through first-source
        // learning. A no-op for a non-SRP, still-forming, or established-peer datagram.
        if self.maybe_reassociate(now, src, data).await {
            return;
        }

        // One GRE socket carries both directions, so the peer's media and RTCP
        // addresses are the one learned address.
        self.peer.learn_media(src);
        self.peer.learn_rtcp(src);
        self.peer.observe(now);

        // On first learning the peer (the receiver's case), greet it so libRIST
        // ungates its media toward us promptly.
        if !self.greeted && self.peer.media().is_some() {
            self.greet(now).await;
        }
        // A listener-sender authenticatee opens its EAP-SRP handshake only once it has
        // learned the calling peer (a no-op after the first START, or for a non-sender
        // / non-authenticatee / already-started flow).
        self.maybe_start_eap().await;

        // EAP-SRP authentication frames (GRE EAPOL, never encrypted) drive the
        // handshake, not the flow. Copy the payload out so the codec borrow ends
        // before driving the role.
        if let Some(eap_payload) = self.codec.peek_eapol(data).map(<[u8]>::to_vec) {
            self.handle_eap(now, &eap_payload).await;
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

        // Out-of-band datagrams (a GRE frame with a non-reserved protocol type)
        // bypass the flow core entirely, delivered to `Receiver::read_oob`.
        match self.codec.peek_oob(data) {
            Ok(Some((payload, proto))) => {
                if let Some(out) = &self.oob_out {
                    let _ = out.send((proto, Bytes::from(payload))).await;
                }
                self.drain(now).await;
                return;
            }
            Ok(None) => {} // not OOB: fall through to the media/control demux
            Err(e) => {
                tracing::debug!(target: crate::logging::SESSION, "rist: main oob decode failed: {e}");
                self.drain(now).await;
                return;
            }
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
                    // FEC over the inner RTP payload (NPD-expanded, matching the
                    // sender's §8.6.2 canonicalization): feed it keyed on the raw wire
                    // timestamp before the flow takes the payload, then re-inject any
                    // recovery.
                    let fec_input = self.fec.is_some().then(|| {
                        (
                            pkt.seq,
                            self.codec.last_wire_ts(),
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
                Ok(Decoded::BufferNeg(bn)) => self.on_buffer_neg(bn),
                Ok(Decoded::Ignored) => {}
                Err(e) => crate::driver::decode_warn(self.codec.has_psk(), "main", &e),
            }
        }

        // Record the peer's CNAME for NAT-rebind re-association, but only under a
        // proven SRP identity. The codec surfaces it solely from ENCRYPTED RTCP SDES
        // (so a keyless forger or a cleartext sender cannot supply one); this gate
        // additionally requires an established per-peer SRP identity so a shared-PSK
        // or plaintext CNAME is never trusted as identity.
        if self.srp_authed() {
            let cname = self.codec.peer_cname().map(str::to_owned);
            if let Some(c) = cname
                && self.peer_cname.as_deref() != Some(c.as_str())
            {
                self.peer_cname = Some(c);
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
                                tracing::debug!(target: crate::logging::SOCKET, seq = pkt.seq, "rist: send media failed: {e}");
                            }
                            // FEC over the (NPD-canonicalized) inner RTP payload, first
                            // transmissions only, in sequence order.
                            if self.fec.is_some() && !pkt.retransmit {
                                self.send_fec_main(&pkt).await;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(target: crate::logging::SOCKET, seq = pkt.seq, "rist: encode media failed: {e}");
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
                return; // the application Receiver was dropped.
            }
        }
        self.stats.publish(self.flow.stats(), self.fec_recovered());
    }

    /// The cumulative FEC-recovered count (0 when FEC is off), for `Stats` and LQM.
    fn fec_recovered(&self) -> u64 {
        self.fec.as_ref().map_or(0, FecState::recovered)
    }

    /// Handles one inbound separate-port FEC datagram: strips the RTP wrapper to the
    /// FEC body, feeds it to the FEC decoder, and re-injects any recovered packet.
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

    /// Re-injects FEC-recovered packets into the flow as media, reconstructing each
    /// source time (non-advancing) from the recovered RTP timestamp.
    fn feed_fec_recovered(&mut self, now: Timestamp, recovered: Vec<Recovered>) {
        for r in recovered {
            let source_time = self.codec.fec_source_time(r.timestamp);
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

    /// Clips one first-transmission media packet's (NPD-canonicalized) inner RTP
    /// payload into the FEC matrix and sends any completed FEC packets as standard
    /// ST 2022-1 / ST 2022-5 RTP (PT 127) on the dedicated column (GRE port + 2) / row
    /// (+ 4) ports — the interoperable separate-port carriage (not GRE-framed).
    async fn send_fec_main(&mut self, pkt: &MediaPacket) {
        let Some(media_dst) = self.peer.media() else {
            return;
        };
        if self.fec.is_none() {
            return;
        }
        let variant = self.fec.as_ref().unwrap().variant();
        let fpay = self.codec.fec_payload(&pkt.payload);
        let ts = codec::rtp_ts_from_source(pkt.source_time);
        let fps = self.fec.as_mut().unwrap().clip(pkt.seq, ts, FEC_PT, &fpay);
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
            if let Err(e) = sock.send(&bytes, dst).await {
                tracing::debug!(target: crate::logging::SOCKET, "rist: send main separate-port fec failed: {e}");
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
                    tracing::debug!(target: crate::logging::RTCP, "rist: send feedback failed: {e}");
                }
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::RTCP, "rist: encode feedback failed: {e}");
            }
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
        if self.flow.config().no_recovery {
            return; // one-way: no control egress
        }
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
        if self.flow.config().no_recovery {
            return; // one-way: no control egress
        }
        let Some(dst) = self.peer.media() else { return };
        // Advertise the FEC capability (the P flag) in the keepalive when FEC is
        // configured (TR-06-2 §8; ristgo `localCaps().P`).
        let mut caps = gre::Capabilities::standard();
        caps.p = self.fec.is_some();
        let ka = gre::Keepalive {
            mac: self.mac,
            caps,
            ..gre::Keepalive::default()
        };
        let sock = self.socket.clone();
        // Advertise GRE v2 (the VSF-wrapped control plane), so the peer learns this
        // node speaks v2 and runs buffer negotiation. Media stays v1-framed.
        if let Ok(bytes) = self.codec.encode_keepalive(&ka, gre::VERSION_CUR) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Advertises this sender's maximum recovery buffer (`recovery_buffer_max +
    /// 2·rtt_min`, libRIST `sender_recover_min_time`) as a GRE-v2 buffer-negotiation
    /// message, so the receiver auto-scales its playout buffer without sizing past
    /// what the sender retains for retransmission. Sender-role, two-way only.
    async fn send_buffer_neg(&mut self, _now: Timestamp) {
        if !self.sender || self.flow.config().no_recovery {
            return;
        }
        let Some(dst) = self.peer.media() else { return };
        let max_ms = {
            let cfg = self.flow.config();
            let micros = cfg.recovery_buffer_max.as_micros() + 2 * cfg.rtt_min.as_micros();
            u16::try_from(micros / 1000).unwrap_or(u16::MAX)
        };
        let bn = gre::BufferNegotiation {
            sender_max_ms: max_ms,
            ..gre::BufferNegotiation::default()
        };
        if let Ok(bytes) = self.codec.encode_buffer_neg(bn) {
            let sock = self.socket.clone();
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Feeds an inbound buffer-negotiation message to the flow: a non-zero sender-max
    /// enables (and bounds) the receiver's recovery-buffer auto-scaling. A no-op on a
    /// sender-role flow (the core guards by role).
    fn on_buffer_neg(&mut self, bn: gre::BufferNegotiation) {
        if bn.sender_max_ms != 0 {
            self.flow
                .set_sender_max_buffer(rist_core::clock::Micros::from_millis(i64::from(
                    bn.sender_max_ms,
                )));
        }
    }

    /// GRE-frames and sends one out-of-band datagram to the peer (PSK-encrypted when
    /// configured). A no-op until the peer's media address is known.
    async fn send_oob(&mut self, payload: &[u8], proto: u16) {
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        match self.codec.encode_oob(payload, proto) {
            Ok(bytes) => {
                let _ = sock.send(&bytes, dst).await;
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::SESSION, "rist: main oob encode failed: {e}");
            }
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
        let sock = self.socket.clone();
        match self
            .codec
            .encode_feedback(RtcpPacket::LinkQualityReport(lqr), &[], self.bitmask)
        {
            Ok(bytes) => {
                let _ = sock.send(&bytes, dst).await;
            }
            Err(e) => {
                tracing::debug!(target: crate::logging::RTCP, "rist: main lqm encode failed: {e}");
            }
        }
    }

    /// Opens the EAP-SRP handshake by sending EAPOL-START once the peer is known
    /// (authenticatee only): a no-op until the calling peer is learned, after the
    /// START has already been sent, or for a non-authenticatee flow.
    async fn maybe_start_eap(&mut self) {
        if self.eap_start_sent || self.peer.media().is_none() {
            return;
        }
        let start = match self.eap.as_mut() {
            Some(EapRole::Authenticatee(a)) => {
                let mut w = Vec::new();
                a.start().append_to(&mut w);
                w
            }
            _ => return,
        };
        self.send_eapol(&start).await;
        self.eap_start_sent = true;
    }

    /// Drives the EAP role with one received EAP payload, transmitting any reply
    /// frame and updating the authenticated gate. On the transition to authenticated
    /// it re-keys the data channel to the SRP session key and pushes it to the peer;
    /// on a regression out of (or failure after) a prior success it holds media and
    /// arms the bounded re-auth window — a forged or replayed EAPOL frame can then
    /// force at most a bounded media gap, never deliver under an unproven tuple.
    async fn handle_eap(&mut self, now: Timestamp, payload: &[u8]) {
        let was_authed = self.authed;
        let Some(role) = self.eap.as_mut() else {
            return;
        };
        let reply = role.recv(payload);
        self.authed = self.eap.as_ref().is_some_and(EapRole::authenticated);
        if let Some(wire) = reply {
            self.send_eapol(&wire).await;
        }
        if self.authed {
            // SUCCESS — the initial handshake, or a NAT-rebind / in-band re-auth just
            // completed and re-proved the migrated tuple.
            self.ever_authed = true;
            self.reauthing = false; // any re-auth is now proven and complete
            // On the transition to authenticated, key the data channel. A configured
            // PSK secret keys it already (SRP only gates); with no PSK, re-key to the
            // SRP session key K and push it to the peer.
            if !was_authed && !self.codec.has_psk() {
                self.on_authenticated().await;
            }
        } else if self.eap.as_ref().is_some_and(EapRole::failed) {
            // A terminal failure. An initial failure (never authenticated) tears the
            // session down — the keepalive tick observes `failed()` and closes with
            // an auth error. A failure AFTER a prior success is a re-auth failure
            // (e.g. a forged/replayed re-auth that could not complete): HOLD media and
            // keep the re-auth window armed so the tick abandons it at the deadline.
            if self.ever_authed {
                self.hold_for_reauth(now);
            }
        } else if was_authed && self.ever_authed {
            // Mid-handshake after a prior success: an inbound EAPOL frame regressed the
            // role OUT of SUCCESS — the genuine peer re-proving after its own
            // rebind/restart (it honors a peer-driven identity request / START), or a
            // forged frame spoofed from the peer's tuple (EAPOL is never encrypted).
            // Either way the tuple is no longer proven: drop `authed` and hold media
            // until the fresh handshake re-proves identity.
            self.hold_for_reauth(now);
        }
    }

    /// Holds media (drops `authed`) and arms the bounded re-auth window if it is not
    /// already armed: the keepalive tick tears the session down at the deadline if the
    /// handshake does not complete, so a stalled or forged re-auth cannot wedge it.
    fn hold_for_reauth(&mut self, now: Timestamp) {
        self.authed = false;
        if !self.reauthing {
            self.reauthing = true;
            self.reauth_deadline = now + self.reauth_timeout();
        }
    }

    /// The window a NAT-rebind / in-band re-auth is given to complete before the
    /// session is torn down: the larger of the recovery buffer (held media that
    /// outlives it is lost anyway) and 4 keepalive intervals (a floor comfortably
    /// above a handshake round-trip and the keepalive-granularity poll that enforces
    /// it). Mirrors libRIST issue #188's bounded re-auth.
    fn reauth_timeout(&self) -> Micros {
        let four_ka =
            Micros::from_micros(i64::try_from(4 * self.keepalive.as_micros()).unwrap_or(i64::MAX));
        self.flow.config().recovery_buffer_max.max(four_ka)
    }

    /// Whether this side's tuple is locked to an authenticated per-peer SRP identity:
    /// an EAP role is configured and has authenticated at least once. Keys off
    /// `ever_authed`, not the live `authed`, so a foreign source stays gated during an
    /// in-flight re-auth (when `authed` is briefly false). A shared PSK (no EAP role)
    /// or plaintext session never qualifies.
    fn srp_authed(&self) -> bool {
        self.eap.is_some() && self.ever_authed
    }

    /// Whether `src` is the established peer's tuple. One Main GRE socket carries both
    /// directions, so the peer's media and RTCP addresses are the one learned address.
    fn same_source(&self, src: SocketAddr) -> bool {
        self.peer.media() == Some(src) || self.peer.rtcp() == Some(src)
    }

    /// Whether `data` is a valid NAT-rebind re-association trigger: an ENCRYPTED RTCP
    /// feedback that decrypts under the per-peer session key AND carries the
    /// established peer's CNAME (libRIST's identity key). The decrypt-under-key is the
    /// unforgeable proof a keyless forger cannot produce; requiring it to be ENCRYPTED
    /// means a cleartext sender or cleartext-RTCP forger cannot supply a matching CNAME
    /// either. EAPOL (forgeable, never encrypted) and media (no SDES) are NOT triggers.
    /// It does not advance the media decoder, so probing a then-dropped datagram cannot
    /// corrupt media decode. (A replay carries the genuine CNAME, so this alone does not
    /// prove liveness — the forced re-auth that follows does; this gate only blocks the
    /// trivially-forged triggers.)
    fn reassoc_trigger(&mut self, data: &[u8]) -> bool {
        if self.peer_cname.is_none() {
            return false;
        }
        let got = self.codec.feedback_cname(data);
        got.is_some() && got.as_deref() == self.peer_cname.as_deref()
    }

    /// Re-opens the EAP-SRP handshake to the (migrated) peer: the authenticatee
    /// re-emits EAPOL-START, the authenticator re-issues the identity request. Call
    /// [`EapRole::restart`] first so the opening frame starts a fresh handshake.
    async fn start_reauth(&mut self) {
        let Some(role) = self.eap.as_mut() else {
            return;
        };
        let frame = role.reopen();
        self.send_eapol(&frame).await;
    }

    /// Recovers a NAT source-port rebind on an authenticated single-flow EAP-SRP
    /// session (mirrors libRIST issue #188, SRP only). Returns `true` when it has
    /// consumed the datagram — by starting a re-association OR by ignoring a datagram
    /// from a source other than the established peer — so the caller skips
    /// first-source-wins learning; `false` lets the normal path run (non-SRP,
    /// still-forming, or the established peer).
    ///
    /// A tuple change is honored only when an authenticated per-peer SRP session is in
    /// force, the established tuple is DORMANT (silent > 2× the keepalive interval),
    /// and the datagram is a valid trigger (see [`reassoc_trigger`](Self::reassoc_trigger)).
    /// Even then the new tuple is NOT trusted: the address migrates and a fresh
    /// EAP-SRP re-auth is forced with media held (`authed` dropped), bounded by
    /// [`reauth_deadline`](Self::reauth_deadline) — so a replay or forger that cannot
    /// finish the handshake never receives media and cannot pin the session open.
    /// Under plaintext or a shared PSK (no per-peer SRP) the CNAME and source are
    /// forgeable, so a rebind is left to the caller-side socket-rebind path.
    ///
    /// Scope: single-flow Main only. A demultiplexing [`MultiReceiver`](crate::multi)
    /// keys flows by source address, so a rebinding peer surfaces there as a NEW flow
    /// (a fresh handshake) and the old flow ages out on timeout.
    async fn maybe_reassociate(&mut self, now: Timestamp, src: SocketAddr, data: &[u8]) -> bool {
        if !self.srp_authed() || self.peer.rtcp().is_none() || self.same_source(src) {
            return false;
        }
        // 2× the keepalive interval == the default session timeout: the established
        // tuple must already be dormant before a foreign source can claim it.
        let dormant =
            Micros::from_micros(i64::try_from(2 * self.keepalive.as_micros()).unwrap_or(i64::MAX));
        if self.reauthing || !self.peer.silent_for(now, dormant) || !self.reassoc_trigger(data) {
            return true; // re-auth in flight, peer still live, or not a valid trigger: ignore
        }
        self.peer.rebind(src);
        self.reauthing = true;
        self.reauth_deadline = now + self.reauth_timeout();
        self.authed = false; // hold media until the migrated tuple re-proves identity
        if let Some(role) = self.eap.as_mut() {
            role.restart();
        }
        self.start_reauth().await;
        tracing::info!(
            target: crate::logging::SESSION,
            %src,
            "rist: main nat-rebind: peer moved; forcing EAP-SRP re-auth"
        );
        true
    }

    /// On reaching authentication with no configured PSK, re-keys the data channel
    /// to the SRP session key K (libRIST's post-SRP data passphrase) and pushes
    /// "use K" to the peer so it sets its receive passphrase to K.
    async fn on_authenticated(&mut self) {
        let Some(key) = self.eap.as_ref().and_then(EapRole::session_key) else {
            return;
        };
        if let Err(e) = self.codec.set_psk(&key) {
            tracing::debug!(target: crate::logging::CRYPTO, "rist: main: post-auth re-key failed: {e}");
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

/// Spawns the single-flow socket reader: it reads the one GRE socket and the
/// separate-port FEC (column / row) sockets and funnels each datagram into the pump's
/// inbound channel. The loop exits when the GRE socket errors (fatal for the flow) or
/// the pump drops the channel; the FEC sockets pend forever when unbound.
fn spawn_reader(socket: MainSocket, tx: mpsc::Sender<MainInbound>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        let mut col_buf = vec![0u8; RECV_BUF];
        let mut row_buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                r = socket.recv(&mut buf) => match r {
                    Ok((n, src)) => {
                        let inb = MainInbound::Main { data: Bytes::copy_from_slice(&buf[..n]), src };
                        if tx.send(inb).await.is_err() { break; }
                    }
                    Err(_) => break,
                },
                r = socket.recv_fec_col(&mut col_buf) => if let Ok((n, _)) = r {
                    let inb = MainInbound::Fec { data: Bytes::copy_from_slice(&col_buf[..n]) };
                    if tx.send(inb).await.is_err() { break; }
                },
                r = socket.recv_fec_row(&mut row_buf) => if let Ok((n, _)) = r {
                    let inb = MainInbound::Fec { data: Bytes::copy_from_slice(&row_buf[..n]) };
                    if tx.send(inb).await.is_err() { break; }
                },
            }
        }
    })
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

/// Awaits the next application out-of-band datagram to transmit; never resolves
/// while unauthenticated (held like media) or when there is no OOB write channel.
async fn recv_oob_gated(
    oob_in: &mut Option<mpsc::Receiver<(u16, Vec<u8>)>>,
    authed: bool,
) -> Option<(u16, Vec<u8>)> {
    if !authed {
        return std::future::pending().await;
    }
    match oob_in {
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
