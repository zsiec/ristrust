//! The deterministic N-path network simulator (scaffolding).
//!
//! A seeded fake-clock simulator that drives two real [`Flow`]s through impaired
//! links. It is the testing centerpiece: every flow/bonding test runs here and
//! asserts the four invariants (no duplicate delivered, in-order output, nothing
//! past deadline, completeness under recoverable loss), reproducible by seed.
//!
//! This is the Rust port of ristgo's `internal/simtest` (itself a generalization
//! of srtrust's two-link `Pair`). It is already N-path so SMPTE 2022-7 bonding
//! drops in. The structure is complete; the four-invariant sweeps and the latency
//! invariant land in Phase 1 (WP1) once the flow core delivers packets.

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use rist_core::clock::{Micros, Timestamp};
use rist_core::flow::{Config, Event, Flow, Output, Role, TimerId};
use rist_core::seq::Seq32;
use rist_core::wire::{Feedback, MediaPacket};

/// A seeded SplitMix64 PRNG — the same algorithm and constants as srtrust/ristgo,
/// so a seed reproduces an identical impairment sequence.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform `f64` in `[0, 1)` from the top 53 bits.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A uniform integer in `[0, n)`. Panics if `n == 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "Rng::below requires n > 0");
        self.next_u64() % n
    }
}

/// Per-link impairment parameters.
#[derive(Clone, Copy)]
pub struct LinkConfig {
    pub delay: Micros,
    pub jitter: Micros,
    pub loss: f64,
    pub dup_prob: f64,
}

impl LinkConfig {
    /// A 10 ms link with no loss, jitter, or duplication.
    pub fn perfect() -> LinkConfig {
        LinkConfig {
            delay: Micros::from_millis(10),
            jitter: Micros::ZERO,
            loss: 0.0,
            dup_prob: 0.0,
        }
    }
}

struct Pending<T> {
    at: Timestamp,
    insert: u64,
    payload: T,
}

/// One directional link carrying datagrams of type `T` with delay, jitter, loss,
/// and duplication, all decided deterministically from the seed. Fate is decided
/// in a fixed order (loss, then duplication, then jitter) so a seed reproduces.
pub struct Link<T> {
    cfg: LinkConfig,
    rng: Rng,
    pending: Vec<Pending<T>>,
    next_insert: u64,
    dropped: u64,
}

impl<T: Clone> Link<T> {
    pub fn new(cfg: LinkConfig, seed: u64) -> Link<T> {
        Link {
            cfg,
            rng: Rng::new(seed),
            pending: Vec::new(),
            next_insert: 0,
            dropped: 0,
        }
    }

    /// Offers a datagram at instant `now`. It may be dropped, delayed, and/or
    /// duplicated according to the link config and seed.
    pub fn send(&mut self, now: Timestamp, payload: T) {
        if self.cfg.loss > 0.0 && self.rng.unit() < self.cfg.loss {
            self.dropped += 1;
            return;
        }
        let dup = self.cfg.dup_prob > 0.0 && self.rng.unit() < self.cfg.dup_prob;
        self.enqueue(now, payload.clone());
        if dup {
            self.enqueue(now, payload);
        }
    }

    fn enqueue(&mut self, now: Timestamp, payload: T) {
        let extra = if self.cfg.jitter.as_micros() > 0 {
            self.rng.below(self.cfg.jitter.as_micros() as u64) as i64
        } else {
            0
        };
        let at = now + self.cfg.delay + Micros::from_micros(extra);
        self.pending.push(Pending {
            at,
            insert: self.next_insert,
            payload,
        });
        self.next_insert += 1;
    }

    /// The earliest pending delivery instant, if any.
    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.pending.iter().map(|p| p.at).min()
    }

    /// Removes and returns every datagram due at or before `now`, in delivery
    /// order (ascending `at`, insertion-order tiebreak).
    pub fn drain_due(&mut self, now: Timestamp) -> Vec<T> {
        let mut due: Vec<Pending<T>> = Vec::new();
        let mut keep: Vec<Pending<T>> = Vec::new();
        for p in self.pending.drain(..) {
            if p.at <= now {
                due.push(p);
            } else {
                keep.push(p);
            }
        }
        self.pending = keep;
        due.sort_by_key(|p| (p.at, p.insert));
        due.into_iter().map(|p| p.payload).collect()
    }

    /// The count of datagrams dropped by loss so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// The host side of declarative timers, keyed by [`TimerId`] (one wheel per flow).
#[derive(Default)]
pub struct TimerWheel {
    deadlines: BTreeMap<TimerId, Timestamp>,
}

impl TimerWheel {
    pub fn new() -> TimerWheel {
        TimerWheel::default()
    }

    pub fn set(&mut self, id: TimerId, at: Timestamp) {
        self.deadlines.insert(id, at);
    }

    pub fn clear(&mut self, id: TimerId) {
        self.deadlines.remove(&id);
    }

    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.deadlines.values().copied().min()
    }

    /// Removes and returns every timer due at or before `now`, in `TimerId` order.
    pub fn pop_due(&mut self, now: Timestamp) -> Vec<TimerId> {
        let mut due: Vec<TimerId> = self
            .deadlines
            .iter()
            .filter(|&(_, &at)| at <= now)
            .map(|(&id, _)| id)
            .collect();
        due.sort();
        for id in &due {
            self.deadlines.remove(id);
        }
        due
    }
}

/// A datagram on the wire: either a media packet or a control message.
#[derive(Clone)]
pub enum Datagram {
    Media(MediaPacket),
    Feedback(Feedback),
}

/// Options for [`Fabric::check_invariants`].
#[derive(Default)]
pub struct InvariantOpts {
    /// Assert the delivered run has no internal gaps (completeness under
    /// recoverable loss).
    pub require_contiguous: bool,
    /// When set, assert no packet's end-to-end latency exceeds this bound. The
    /// latency invariant lands in WP1 with deterministic seq assignment.
    pub max_latency: Option<Micros>,
}

/// The N-path fake-clock network simulator: a sender [`Flow`] and a receiver
/// [`Flow`] joined by `n` forward and `n` back links, each with its own seeded
/// impairment and its own host timer wheel.
pub struct Fabric {
    now: Timestamp,
    sender: Flow,
    receiver: Flow,
    fwd: Vec<Link<Datagram>>,
    back: Vec<Link<Datagram>>,
    sender_timers: TimerWheel,
    receiver_timers: TimerWheel,
    source: VecDeque<(Timestamp, Bytes)>,
    delivered: Vec<Bytes>,
    delivered_seqs: Vec<u32>,
}

impl Fabric {
    /// Builds an `num_paths`-path fabric. Forward links carry the sender's media,
    /// back links carry the receiver's feedback; each path's two links are seeded
    /// independently from `seed`.
    pub fn new(num_paths: usize, fwd: LinkConfig, back: LinkConfig, seed: u64) -> Fabric {
        let sender = Flow::new(Role::Sender, Config::librist_defaults());
        let receiver = Flow::new(Role::Receiver, Config::librist_defaults());
        let mut fwd_links = Vec::with_capacity(num_paths);
        let mut back_links = Vec::with_capacity(num_paths);
        for i in 0..num_paths {
            let i = i as u64;
            fwd_links.push(Link::new(
                fwd,
                seed ^ (0xF0F0_0000 ^ i.wrapping_mul(0x1111)),
            ));
            back_links.push(Link::new(
                back,
                seed ^ (0x0F0F_0000 ^ i.wrapping_mul(0x2222)),
            ));
        }
        Fabric {
            now: Timestamp::ZERO,
            sender,
            receiver,
            fwd: fwd_links,
            back: back_links,
            sender_timers: TimerWheel::new(),
            receiver_timers: TimerWheel::new(),
            source: VecDeque::new(),
            delivered: Vec::new(),
            delivered_seqs: Vec::new(),
        }
    }

    /// Schedules one application payload to be pushed into the sender at `at`.
    /// Calls must use non-decreasing `at`.
    pub fn enqueue_source(&mut self, at: Timestamp, payload: Bytes) {
        self.source.push_back((at, payload));
    }

    /// The current fake-clock instant.
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// The payloads delivered out of the receiver so far, in delivery order.
    pub fn delivered(&self) -> &[Bytes] {
        &self.delivered
    }

    /// The sequence numbers delivered so far, in delivery order.
    pub fn delivered_seqs(&self) -> &[u32] {
        &self.delivered_seqs
    }

    /// Advances the fake clock to the next pending event and processes everything
    /// due: pushes due source payloads, delivers due datagrams into the flows,
    /// fires due timers, and drains the resulting effects back onto the links and
    /// wheels. Returns `false` when the network is quiescent (nothing left to do).
    pub fn step(&mut self) -> bool {
        let mut next: Option<Timestamp> = None;
        let mut consider = |t: Option<Timestamp>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n: Timestamp| n.min(t)));
            }
        };
        if let Some((at, _)) = self.source.front() {
            consider(Some(*at));
        }
        for l in &self.fwd {
            consider(l.next_deadline());
        }
        for l in &self.back {
            consider(l.next_deadline());
        }
        consider(self.sender_timers.next_deadline());
        consider(self.receiver_timers.next_deadline());

        let Some(t) = next else {
            return false;
        };
        self.now = t;
        let now = self.now;

        // 1. Push due source payloads into the sender.
        while let Some((at, _)) = self.source.front() {
            if *at <= now {
                let (_, payload) = self.source.pop_front().expect("front exists");
                self.sender.push_app(now, payload);
            } else {
                break;
            }
        }

        // 2. Deliver due forward datagrams into the receiver.
        let mut inbound: Vec<(u8, Datagram)> = Vec::new();
        for (path, link) in self.fwd.iter_mut().enumerate() {
            for d in link.drain_due(now) {
                inbound.push((path as u8, d));
            }
        }
        for (path, d) in inbound {
            feed_datagram(&mut self.receiver, now, path, d);
        }

        // 3. Deliver due back datagrams into the sender.
        let mut inbound: Vec<(u8, Datagram)> = Vec::new();
        for (path, link) in self.back.iter_mut().enumerate() {
            for d in link.drain_due(now) {
                inbound.push((path as u8, d));
            }
        }
        for (path, d) in inbound {
            feed_datagram(&mut self.sender, now, path, d);
        }

        // 4. Fire due timers.
        for id in self.sender_timers.pop_due(now) {
            self.sender.handle_timer(now, id);
        }
        for id in self.receiver_timers.pop_due(now) {
            self.receiver.handle_timer(now, id);
        }

        // 5. Drain effects. The sender's outputs leave on forward links; the
        //    receiver's on back links. Only the receiver produces Deliver events.
        drain_flow(
            &mut self.sender,
            &mut self.fwd,
            &mut self.sender_timers,
            now,
            &mut self.delivered,
            &mut self.delivered_seqs,
        );
        drain_flow(
            &mut self.receiver,
            &mut self.back,
            &mut self.receiver_timers,
            now,
            &mut self.delivered,
            &mut self.delivered_seqs,
        );
        true
    }

    /// Steps until `pred` holds or `max_steps` is reached or the network goes
    /// quiescent. Returns whether `pred` held at the end.
    pub fn run_until(&mut self, mut pred: impl FnMut(&Fabric) -> bool, max_steps: usize) -> bool {
        for _ in 0..max_steps {
            if pred(self) {
                return true;
            }
            if !self.step() {
                return pred(self);
            }
        }
        pred(self)
    }

    /// Validates the delivered stream against the flow invariants, returning a
    /// list of human-readable violations (empty when all hold).
    pub fn check_invariants(&self, opts: &InvariantOpts) -> Vec<String> {
        let mut violations = Vec::new();
        let seqs = &self.delivered_seqs;
        for i in 1..seqs.len() {
            let (prev, cur) = (seqs[i - 1], seqs[i]);
            // (1) No duplicate delivered.
            if prev == cur {
                violations.push(format!("duplicate delivery of seq {cur} at index {i}"));
            // (2) In order under wrap-aware compare.
            } else if !Seq32::new(prev).less(Seq32::new(cur)) {
                violations.push(format!(
                    "out-of-order delivery: seq {cur} after {prev} at index {i}"
                ));
            }
            // (4) Completeness under recoverable loss (no internal gaps).
            if opts.require_contiguous && cur != prev.wrapping_add(1) {
                violations.push(format!(
                    "internal gap: seq jumps {prev} -> {cur} at index {i}"
                ));
            }
        }
        // (3) The end-to-end latency bound is asserted in WP1, once the sender
        // assigns sequence numbers deterministically and per-seq send/deliver
        // instants can be correlated. Acknowledged here so the option is honored.
        let _ = opts.max_latency;
        violations
    }
}

fn feed_datagram(flow: &mut Flow, now: Timestamp, path: u8, d: Datagram) {
    match d {
        Datagram::Media(pkt) => flow.feed(now, path, pkt),
        Datagram::Feedback(fb) => flow.feed_feedback(now, fb),
    }
}

fn drain_flow(
    flow: &mut Flow,
    out_links: &mut [Link<Datagram>],
    timers: &mut TimerWheel,
    now: Timestamp,
    delivered: &mut Vec<Bytes>,
    delivered_seqs: &mut Vec<u32>,
) {
    while let Some(out) = flow.poll_output() {
        match out {
            Output::SendMedia { path, pkt } => {
                out_links[path as usize].send(now, Datagram::Media(pkt));
            }
            Output::SendFeedback { path, fb } => {
                out_links[path as usize].send(now, Datagram::Feedback(fb));
            }
            Output::SetTimer { id, deadline } => timers.set(id, deadline),
            Output::ClearTimer { id } => timers.clear(id),
        }
    }
    while let Some(ev) = flow.poll_event() {
        match ev {
            Event::Deliver { seq, payload, .. } => {
                delivered_seqs.push(seq);
                delivered.push(payload);
            }
        }
    }
}
