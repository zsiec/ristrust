//! The async driver for the Advanced profile (VSF TR-06-3): the `select!` pump for
//! the GRE-substrate hybrid.
//!
//! libRIST `-p 2` mixes two framings on one UDP port: raw Main-profile GRE packets
//! (the RTCP-SDES handshake + keepalives that authenticate and keep the control
//! plane alive) and Advanced-framed packets (RTP PT=127: Type=5 media, Type=4
//! control, Type=8 GRE-wrapped). This driver therefore owns BOTH a [`MainCodec`]
//! (the GRE substrate) and an [`AdvCodec`] (media + control), and demultiplexes
//! inbound datagrams by their first byte: V=2/PT in {127, ≥96} is Advanced framing,
//! anything else is raw GRE. It mirrors the Main driver's timer wheel, peer
//! learning, EAP-SRP handshake, and thin-dumb-pump discipline.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use rist_codec::adv;
use rist_codec::rtcp::{EmptyReceiverReport, Packet as RtcpPacket, SenderReport};
use rist_core::clock::Timestamp;
use rist_core::flow::{Event, Flow, Output, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::{Feedback, FragRole};

use crate::adapt::{LqmEmitter, RateControl};
use crate::codec_adv::AdvCodec;
use crate::codec_main::{ControlKind, Decoded, MainCodec};
use crate::config::FlowAttrCallback;
use crate::driver::{COMMAND_CAPACITY, CloseFlag, DATA_CAPACITY};
use crate::driver_main::EapRole;
use crate::peer::Peer;
use crate::reassembler::FragReassembler;
use crate::socket::MainSocket;
use crate::stats::StatsCell;

/// The largest datagram the driver will receive.
const RECV_BUF: usize = 65_536;

/// The EAP identifier ristrust stamps on its unsolicited passphrase push.
const PASSPHRASE_PUSH_ID: u8 = 0x40;

/// Whether `data` is Advanced framing (RTP V=2, PT 127 or a dynamic type ≥ 96)
/// rather than a raw Main-profile GRE packet.
fn is_adv_framed(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] & 0xC0 == 0x80 && {
        let pt = data[1] & 0x7F;
        pt == adv::PAYLOAD_TYPE || pt >= 96
    }
}

/// The Advanced control/media RTP timestamp for a session instant (the effective
/// 2^16 MHz rate: `micros << 16`).
#[allow(clippy::cast_possible_truncation)]
fn adv_ctrl_ts(now: Timestamp) -> u32 {
    (now.as_micros() << 16) as u32
}

/// The Advanced-profile session driver, run as one detached task per flow.
// Justification: the bool fields are independent per-flow flags, not a state enum.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct AdvDriver {
    sender: bool,
    flow: Flow,
    socket: MainSocket,
    peer: Peer,
    epoch: Instant,
    timers: HashMap<TimerId, Timestamp>,
    keepalive: Duration,
    /// The raw Main-profile GRE substrate codec (handshake + keepalive + EAPOL).
    main: MainCodec,
    /// The Advanced media + control codec (Type=5 / Type=4).
    adv: AdvCodec,
    bitmask: bool,
    /// Records why the task exited, read by the handle once its channel closes.
    close: CloseFlag,
    /// The latest stats snapshot published to the handle's `stats()`.
    stats: StatsCell,

    // --- sender half ---
    app_in: Option<mpsc::Receiver<Bytes>>,
    highest_sent: u32,
    ssrc: u32,
    /// When > 0, split an application payload larger than this many bytes across
    /// consecutive fragment sequences (TR-06-3 §5); 0 disables fragmentation.
    frag_size: usize,

    // --- receiver half ---
    data_out: Option<mpsc::Sender<Bytes>>,
    learned_ssrc: Option<u32>,
    greeted: bool,
    /// Reassembles a delivered fragment run into a complete payload before it is
    /// handed to the application (a no-op for unfragmented `Standalone` media).
    reasm: FragReassembler,

    // --- EAP-SRP authentication ---
    eap: Option<EapRole>,
    authed: bool,

    // --- source adaptation (TR-06-4 Part 1) ---
    /// The receiver's Link Quality Message emitter, when source adaptation is on.
    lqm: Option<LqmEmitter>,
    /// The sender's rate controller, when a rate callback is configured.
    rate: Option<RateControl>,

    // --- flow attributes (TR-06-3 §5.3.7) ---
    /// Invoked with each inbound flow-attribute payload, when a callback is set.
    on_flow_attr: Option<FlowAttrCallback>,
    /// Application-submitted flow attributes to transmit (sender only; `None` on a
    /// receiver), from `Sender::write_flow_attribute`.
    flow_attr_cmd: Option<mpsc::Receiver<Vec<u8>>>,

    // --- out-of-band passthrough (carried on the GRE substrate) ---
    /// Application OOB datagrams to transmit (`Some` on a sender). `(prot_type, payload)`.
    oob_in: Option<mpsc::Receiver<(u16, Vec<u8>)>>,
    /// Received OOB datagrams handed to `Receiver::read_oob` (`Some` on a receiver).
    oob_out: Option<mpsc::Sender<(u16, Bytes)>>,
}

impl AdvDriver {
    /// Builds and spawns an Advanced-profile sender driver.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_sender(
        flow: Flow,
        socket: MainSocket,
        peer: Peer,
        main: MainCodec,
        adv: AdvCodec,
        ssrc: u32,
        bitmask: bool,
        keepalive: Duration,
        start_seq: u32,
        eap: Option<EapRole>,
        rate: Option<RateControl>,
        on_flow_attr: Option<FlowAttrCallback>,
        flow_attr_rx: mpsc::Receiver<Vec<u8>>,
        oob_in: mpsc::Receiver<(u16, Vec<u8>)>,
        frag_size: usize,
    ) -> (
        mpsc::Sender<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(COMMAND_CAPACITY);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = AdvDriver {
            sender: true,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            main,
            adv,
            bitmask,
            close: close.clone(),
            stats: stats.clone(),
            app_in: Some(rx),
            highest_sent: start_seq,
            ssrc,
            frag_size,
            data_out: None,
            learned_ssrc: None,
            greeted: false,
            reasm: FragReassembler::default(),
            eap,
            authed,
            lqm: None,
            rate,
            on_flow_attr,
            flow_attr_cmd: Some(flow_attr_rx),
            oob_in: Some(oob_in),
            oob_out: None,
        };
        (tx, close, stats, tokio::spawn(driver.run()))
    }

    /// Builds and spawns an Advanced-profile receiver driver.
    #[allow(clippy::too_many_arguments)] // a constructor wiring the session config
    pub(crate) fn spawn_receiver(
        flow: Flow,
        socket: MainSocket,
        peer: Peer,
        main: MainCodec,
        adv: AdvCodec,
        ssrc: u32,
        bitmask: bool,
        keepalive: Duration,
        eap: Option<EapRole>,
        lqm: Option<LqmEmitter>,
        on_flow_attr: Option<FlowAttrCallback>,
        oob_out: mpsc::Sender<(u16, Bytes)>,
    ) -> (
        mpsc::Receiver<Bytes>,
        CloseFlag,
        StatsCell,
        tokio::task::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(DATA_CAPACITY);
        let authed = eap.is_none();
        let close = CloseFlag::default();
        let stats = StatsCell::default();
        let driver = AdvDriver {
            sender: false,
            flow,
            socket,
            peer,
            epoch: Instant::now(),
            timers: HashMap::new(),
            keepalive,
            main,
            adv,
            bitmask,
            close: close.clone(),
            stats: stats.clone(),
            app_in: None,
            highest_sent: 0,
            ssrc,
            frag_size: 0,
            data_out: Some(tx),
            learned_ssrc: None,
            greeted: false,
            reasm: FragReassembler::default(),
            eap,
            authed,
            lqm,
            rate: None,
            on_flow_attr,
            flow_attr_cmd: None,
            oob_in: None,
            oob_out: Some(oob_out),
        };
        (rx, close, stats, tokio::spawn(driver.run()))
    }

    #[allow(clippy::cast_possible_truncation)] // session durations fit u64 micros
    fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.epoch.elapsed().as_micros() as u64)
    }

    fn deadline(&self, ts: Timestamp) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.epoch + Duration::from_micros(ts.as_micros()))
    }

    async fn run(mut self) {
        let sock = self.socket.clone();
        let mut buf = vec![0u8; RECV_BUF];

        if self.sender {
            let now = self.now();
            self.greet(now).await;
            self.send_eap_start().await;
        }

        let mut keepalive = tokio::time::interval(self.keepalive);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;

        loop {
            let timer_at = self.earliest_timer().map(|ts| self.deadline(ts));
            tokio::select! {
                r = sock.recv(&mut buf) => match r {
                    Ok((n, src)) => self.on_recv(src, &buf[..n]).await,
                    Err(_) => break,
                },
                payload = recv_app_gated(&mut self.app_in, self.authed) => match payload {
                    Some(p) => {
                        let now = self.now();
                        self.push_app(now, &p);
                        self.drain(now).await;
                    }
                    None => break,
                },
                // Application-submitted flow attributes (fire-and-forget, gated on
                // auth like media): frame one Type=Control CI=0x8001 datagram and
                // send it directly, outside the flow core.
                attr = recv_flow_attr(&mut self.flow_attr_cmd, self.authed) => match attr {
                    Some(json) => {
                        let now = self.now();
                        self.send_flow_attr(&json, now).await;
                    }
                    None => self.flow_attr_cmd = None,
                },
                // Application out-of-band datagrams (fire-and-forget, auth-gated):
                // GRE-frame on the substrate codec and send directly.
                oob = recv_oob(&mut self.oob_in, self.authed) => match oob {
                    Some((proto, payload)) => self.send_oob(&payload, proto).await,
                    None => self.oob_in = None,
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

    async fn on_recv(&mut self, src: SocketAddr, data: &[u8]) {
        let now = self.now();
        self.peer.learn_media(src);
        self.peer.observe(now);
        if !self.greeted && self.peer.media().is_some() {
            self.greet(now).await;
        }

        if is_adv_framed(data) {
            // Advanced-framed media/control reaches the flow only after the EAP-SRP
            // handshake authenticates the peer; drop it otherwise. A no-op when
            // authentication is disabled (`authed` is then true from the start).
            if self.authed {
                self.on_adv(now, data);
            }
        } else if let Some(eap_payload) = self.main.peek_eapol(data).map(<[u8]>::to_vec) {
            // Raw Main-profile GRE substrate: EAPOL auth drives the handshake.
            self.handle_eap(&eap_payload).await;
        } else {
            // Out-of-band passthrough (non-reserved GRE protocol type) bypasses the
            // flow core, auth-gated like media. The SR/RR/SDES handshake must still
            // be processed before auth completes, so OOB is peeked only when authed.
            let oob = if self.authed {
                self.main.peek_oob(data)
            } else {
                Ok(None)
            };
            match oob {
                Ok(Some((payload, proto))) => {
                    if let Some(out) = &self.oob_out {
                        let _ = out.send((proto, Bytes::from(payload))).await;
                    }
                }
                Err(e) => tracing::debug!("rist: adv oob decode failed: {e}"),
                Ok(None) => {
                    // Keepalive is liveness only; SR/RR/SDES carry no flow input.
                    let (kind, _ka, _ver) = self.main.peek_control(data);
                    if kind != ControlKind::Keepalive {
                        let _ = self.main.decode(data, self.highest_sent);
                    }
                }
            }
        }
        self.drain(now).await;
    }

    /// Routes one Advanced-framed datagram: Type=8 unwraps an inner GRE substrate
    /// packet; Type=5/4 decode to media/feedback.
    fn on_adv(&mut self, now: Timestamp, data: &[u8]) {
        let buf = Bytes::copy_from_slice(data);
        let Ok(parsed) = adv::parse(&buf) else { return };
        if parsed.enc_type == adv::TYPE_GRE_MAIN {
            // The inner payload is a Main-profile GRE packet (handshake/keepalive).
            let inner = parsed.payload.clone();
            let (kind, _ka, _ver) = self.main.peek_control(&inner);
            if kind != ControlKind::Keepalive {
                let _ = self.main.decode(&inner, self.highest_sent);
            }
            return;
        }
        match self.adv.decode_parsed(&parsed) {
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
                    match fb {
                        // A Link Quality Message is a host-level source-adaptation
                        // signal: drive the rate controller, never the flow core.
                        Feedback::LinkQuality { lqm } => {
                            if let Some(r) = &mut self.rate {
                                r.handle(&lqm);
                            }
                        }
                        // A flow attribute is a host-level side channel: invoke the
                        // application callback, never the flow core.
                        Feedback::FlowAttribute { json } => {
                            if let Some(cb) = &self.on_flow_attr {
                                cb.call(json);
                            }
                        }
                        // Drop inbound Advanced RTT-echo *requests* so the flow
                        // never answers them — see `drops_adv_echo_request` for the
                        // libRIST interop rationale.
                        fb if drops_adv_echo_request(&fb) => {}
                        fb => self.flow.feed_feedback(now, fb),
                    }
                }
            }
            Ok(Decoded::Ignored) => {}
            Err(e) => crate::driver::decode_warn(self.adv.has_psk(), "advanced", &e),
        }
    }

    /// Feeds one application payload to the flow core, splitting it across
    /// consecutive sequences when fragmentation is enabled (`frag_size > 0`) and the
    /// payload exceeds the fragment size. Each fragment is an independently
    /// recoverable sequence tagged with its F/L role; the peer's reassembler folds
    /// them back together. Without fragmentation, or for a payload that already fits,
    /// it is a single unfragmented [`FragRole::Standalone`] push.
    fn push_app(&mut self, now: Timestamp, p: &Bytes) {
        if self.frag_size == 0 || p.len() <= self.frag_size {
            self.flow.push_app(now, p.clone());
            return;
        }
        let mut off = 0;
        while off < p.len() {
            let end = (off + self.frag_size).min(p.len());
            let role = if off == 0 {
                FragRole::First
            } else if end == p.len() {
                FragRole::Last
            } else {
                FragRole::Middle
            };
            self.flow.push_app_frag(now, p.slice(off..end), role);
            off = end;
        }
    }

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
                    match self.adv.encode_media(&pkt) {
                        Ok(bytes) => {
                            if let Err(e) = sock.send(&bytes, dst).await {
                                tracing::debug!(seq = pkt.seq, "rist: adv send media failed: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::debug!(seq = pkt.seq, "rist: adv encode media failed: {e}");
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
        while let Some(Event::Deliver {
            payload,
            discontinuity,
            frag,
            ..
        }) = self.flow.poll_event()
        {
            // Reassemble a fragment run before delivery; an unfragmented payload
            // (`Standalone`) passes straight through, an incomplete or broken run
            // yields nothing (the application sees the same gap as any lost media).
            let Some(out_payload) = self.reasm.push(frag, payload, discontinuity) else {
                continue;
            };
            if let Some(out) = &self.data_out
                && out.send(out_payload).await.is_err()
            {
                return;
            }
        }
        self.stats.publish(self.flow.stats());
    }

    /// Sends each drained feedback effect as an Advanced Type=4 control datagram.
    async fn send_feedback(&mut self, fbs: &[Feedback], now: Timestamp) {
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        match self
            .adv
            .encode_feedback(fbs, self.bitmask, adv_ctrl_ts(now))
        {
            Ok(dgs) => {
                for dg in dgs {
                    if let Err(e) = sock.send(&dg, dst).await {
                        tracing::debug!("rist: adv send feedback failed: {e}");
                    }
                }
            }
            Err(e) => tracing::debug!("rist: adv encode feedback failed: {e}"),
        }
    }

    /// Emits one Link Quality Message (TR-06-4 Part 1) when a reporting period has
    /// elapsed: snapshots the flow stats into an LQM and sends it as a native
    /// Advanced Type=Control message (control index `0x0002`). A no-op when source
    /// adaptation is off or no reporting period has passed.
    async fn maybe_emit_lqm(&mut self, now: Timestamp) {
        if self.lqm.as_ref().is_none_or(|e| !e.due(now)) {
            return;
        }
        let Some(dst) = self.peer.media() else {
            return;
        };
        let stats = self.flow.stats();
        let lqm = self
            .lqm
            .as_mut()
            .expect("emitter present (checked above)")
            .build(now, &stats);
        let sock = self.socket.clone();
        match self.adv.lqm_datagram(&lqm.encode(), adv_ctrl_ts(now)) {
            Ok(bytes) => {
                let _ = sock.send(&bytes, dst).await;
            }
            Err(e) => tracing::debug!("rist: adv lqm encode failed: {e}"),
        }
    }

    /// Sends the raw Main GRE RTCP (SR/RR + SDES) handshake — the substrate that
    /// authenticates this peer to libRIST and ungates its media.
    async fn send_handshake(&mut self, now: Timestamp) {
        if self.flow.config().no_recovery {
            return; // one-way: no control egress
        }
        let Some(dst) = self.peer.media() else { return };
        let lead = self.feedback_lead(now);
        let sock = self.socket.clone();
        if let Ok(bytes) = self.main.encode_feedback(lead, &[], self.bitmask) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// Sends the Advanced keep-alive (Type=4, I-bit), the capability/liveness beacon.
    async fn send_keepalive(&mut self, now: Timestamp) {
        if self.flow.config().no_recovery {
            return; // one-way: no control egress
        }
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        if let Ok(bytes) = self.adv.keepalive_datagram(adv_ctrl_ts(now)) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

    /// GRE-frames and sends one out-of-band datagram on the substrate codec
    /// (PSK-encrypted when configured). A no-op until the peer's address is known.
    async fn send_oob(&mut self, payload: &[u8], proto: u16) {
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        match self.main.encode_oob(payload, proto) {
            Ok(bytes) => {
                let _ = sock.send(&bytes, dst).await;
            }
            Err(e) => tracing::debug!("rist: adv oob encode failed: {e}"),
        }
    }

    /// Frames and sends one fire-and-forget flow-attribute control datagram
    /// (TR-06-3 §5.3.7) to the peer. A no-op until the peer's media address is known.
    async fn send_flow_attr(&mut self, json: &[u8], now: Timestamp) {
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        match self.adv.flow_attr_datagram(json, adv_ctrl_ts(now)) {
            Ok(bytes) => {
                let _ = sock.send(&bytes, dst).await;
            }
            Err(e) => tracing::debug!("rist: adv flow-attr encode failed: {e}"),
        }
    }

    /// Sends the GRE RTCP handshake + the Advanced keepalive, marking greeted.
    async fn greet(&mut self, now: Timestamp) {
        self.send_handshake(now).await;
        self.send_keepalive(now).await;
        self.greeted = true;
    }

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
        if self.authed && !was_authed && !self.main.has_psk() {
            self.on_authenticated().await;
        }
    }

    /// On reaching authentication with no configured PSK, re-keys both the GRE
    /// substrate and the Advanced data channel to the SRP session key K and pushes
    /// "use K" to the peer.
    async fn on_authenticated(&mut self) {
        let Some(key) = self.eap.as_ref().and_then(EapRole::session_key) else {
            return;
        };
        let _ = self.main.set_psk(&key);
        let _ = self.adv.set_psk(&key);
        let mut wire = Vec::new();
        rist_codec::eap::passphrase_push(PASSPHRASE_PUSH_ID).append_to(&mut wire);
        self.send_eapol(&wire).await;
    }

    /// Frames an EAP payload in a GRE EAPOL datagram (the substrate carries auth).
    async fn send_eapol(&mut self, eap: &[u8]) {
        let Some(dst) = self.peer.media() else { return };
        let sock = self.socket.clone();
        if let Ok(bytes) = self.main.encode_eapol(eap) {
            let _ = sock.send(&bytes, dst).await;
        }
    }

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
                ssrc: self.learned_ssrc.unwrap_or(self.ssrc),
            })
        }
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
}

/// Awaits the next application payload when authenticated; never resolves while
/// gated or when there is no application input channel.
async fn recv_app_gated(app_in: &mut Option<mpsc::Receiver<Bytes>>, authed: bool) -> Option<Bytes> {
    if !authed {
        return std::future::pending().await;
    }
    match app_in {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Awaits the next application flow attribute to transmit; never resolves while
/// unauthenticated (held like media) or when there is no flow-attribute channel.
async fn recv_flow_attr(ch: &mut Option<mpsc::Receiver<Vec<u8>>>, authed: bool) -> Option<Vec<u8>> {
    if !authed {
        return std::future::pending().await;
    }
    match ch {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Awaits the next application out-of-band datagram to transmit; never resolves
/// while unauthenticated (held like media) or when there is no OOB write channel.
async fn recv_oob(
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

async fn sleep_until_opt(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

fn seq_after(a: u32, b: u32) -> bool {
    Seq32::new(b).less(Seq32::new(a))
}

/// Whether an inbound Advanced-path feedback item is an RTT-echo *request* that
/// must be dropped before it reaches the flow core, so the flow never answers it.
///
/// Echoing the request verbatim is spec-correct, but libRIST's Advanced-profile
/// RTT-echo *response* handler mis-scales the NTP-64 round-trip — it shifts the
/// fractional diff by 16 instead of 32, inflating the measured RTT by 2^16. A
/// response from us therefore poisons libRIST's peer `last_rtt` to hundreds of
/// seconds, which jams its own retransmit re-queue gate (it refuses a re-NACK
/// while `delta < rtt`): a single dropped retransmit is never re-sent and one
/// packet is permanently lost under loss (observed as unrecovered loss from ~25%).
/// Not answering keeps libRIST's `last_rtt` at its sane default and recovery
/// works; ristrust still *originates* its own RTT-echo requests (scaled correctly
/// by both ends), so its own RTT estimation is unaffected. Advanced-only — the
/// Main/Simple RTT echo uses libRIST's correct response path and must keep
/// answering for those estimators to converge (TR-06-3 §5.3, RTT echo).
fn drops_adv_echo_request(fb: &Feedback) -> bool {
    matches!(fb, Feedback::RttEchoRequest { .. })
}

#[cfg(test)]
mod tests {
    use super::drops_adv_echo_request;
    use rist_core::wire::Feedback;

    #[test]
    fn drops_only_advanced_echo_requests() {
        // The request is dropped so the flow never emits a (libRIST-poisoning) echo.
        assert!(drops_adv_echo_request(&Feedback::RttEchoRequest {
            ssrc: 0,
            timestamp: 1,
        }));
        // Everything else still reaches the flow core: echo *responses* (our own
        // RTT estimation), NACKs (retransmit requests), and SR timing.
        assert!(!drops_adv_echo_request(&Feedback::RttEchoResponse {
            ssrc: 7,
            timestamp: 2,
            processing_delay: 3,
        }));
        assert!(!drops_adv_echo_request(&Feedback::Nack {
            ssrc: 7,
            missing: vec![1, 2, 3],
        }));
        assert!(!drops_adv_echo_request(&Feedback::LinkQuality {
            lqm: [0u8; 44]
        }));
    }
}
