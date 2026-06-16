//! The deterministic N-path network simulator.
//!
//! A seeded fake-clock simulator that drives a real sender [`Flow`] and receiver
//! [`Flow`] through impaired links. It is the testing centerpiece: every
//! flow/bonding test runs here and asserts the four invariants (no duplicate
//! delivered, in-order output, nothing past deadline, completeness under
//! recoverable loss), reproducible by seed.
//!
//! This is the Rust port of ristgo's `internal/simtest` (itself a generalization
//! of srtrust's two-link `Pair`). It is already N-path so SMPTE 2022-7 bonding
//! drops in: forward links carry the sender's media, back links carry the
//! receiver's feedback, one [`Link`] per path.

use std::collections::{BTreeMap, HashMap, VecDeque};

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

    /// A link with the given base delay and otherwise no impairment.
    pub fn with_delay(delay: Micros) -> LinkConfig {
        LinkConfig {
            delay,
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

/// A deterministic per-datagram drop predicate (`true` drops), consulted before
/// the probabilistic loss roll so a test can target a specific packet ("the
/// first transmission of seq N") without hunting for a seed. A filter drop
/// consumes no RNG draw.
type DropFilter<T> = Box<dyn FnMut(&T) -> bool>;

/// One directional link carrying datagrams of type `T` with delay, jitter, loss,
/// and duplication, all decided deterministically from the seed. Fate is decided
/// in a fixed order — drop filter, then loss, then duplication, then jitter — so
/// a seed reproduces a pattern stable as unrelated knobs change.
pub struct Link<T> {
    cfg: LinkConfig,
    rng: Rng,
    pending: Vec<Pending<T>>,
    next_insert: u64,
    dropped: u64,
    drop_filter: Option<DropFilter<T>>,
}

impl<T: Clone> Link<T> {
    pub fn new(cfg: LinkConfig, seed: u64) -> Link<T> {
        Link {
            cfg,
            rng: Rng::new(seed),
            pending: Vec::new(),
            next_insert: 0,
            dropped: 0,
            drop_filter: None,
        }
    }

    /// Installs a deterministic drop predicate, consulted before the loss roll.
    pub fn set_drop_filter(&mut self, filter: DropFilter<T>) {
        self.drop_filter = Some(filter);
    }

    /// Offers a datagram at instant `now`. It may be dropped (by the filter or the
    /// loss roll), delayed, and/or duplicated according to the config and seed.
    pub fn send(&mut self, now: Timestamp, payload: T) {
        if let Some(filter) = &mut self.drop_filter
            && filter(&payload)
        {
            self.dropped += 1;
            return;
        }
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

    /// The count of datagrams dropped by the filter or loss so far.
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
    /// recoverable loss). Leave false where abandoned holes are expected.
    pub require_contiguous: bool,
    /// Bounds the allowed spread (max − min) in per-packet delivery latency.
    /// Under the deterministic core latency is constant (a packet is delivered at
    /// `source_time + offset + recovery_buffer` regardless of retransmits), so
    /// `0` is the strict value.
    pub latency_tolerance: Micros,
    /// When set, assert no delivered packet's latency (deliver instant minus
    /// first-transmission instant) exceeds this — the literal "nothing past
    /// deadline" check.
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
    /// Per-seq first-transmission and delivery instants, for the latency
    /// invariant.
    send_time: HashMap<u32, Timestamp>,
    deliver_instant: HashMap<u32, Timestamp>,
    discontinuities: usize,
    /// When set, every media datagram the (single-path) sender emits is
    /// duplicated across every forward path (the SMPTE 2022-7 full-redundancy
    /// sender); the receiver's dedup merges the copies.
    dup_tx: bool,
}

impl Fabric {
    /// Builds a fabric from explicit sender/receiver flows and pre-seeded link
    /// vectors (one [`Link`] per path; `fwd` and `back` must be the same length).
    /// The caller installs drop filters before the run. This is the primitive the
    /// flow and bonding sims build on.
    pub fn from_links(
        sender: Flow,
        receiver: Flow,
        fwd: Vec<Link<Datagram>>,
        back: Vec<Link<Datagram>>,
    ) -> Fabric {
        assert_eq!(
            fwd.len(),
            back.len(),
            "fabric requires len(fwd) == len(back)"
        );
        Fabric {
            now: Timestamp::ZERO,
            sender,
            receiver,
            fwd,
            back,
            sender_timers: TimerWheel::new(),
            receiver_timers: TimerWheel::new(),
            source: VecDeque::new(),
            delivered: Vec::new(),
            delivered_seqs: Vec::new(),
            send_time: HashMap::new(),
            deliver_instant: HashMap::new(),
            discontinuities: 0,
            dup_tx: false,
        }
    }

    /// Builds an `num_paths`-path fabric with default-config flows and uniformly
    /// impaired links, each seeded independently from `seed`. A convenience over
    /// [`Fabric::from_links`] for tests that need no per-link drop filter.
    pub fn new(num_paths: usize, fwd: LinkConfig, back: LinkConfig, seed: u64) -> Fabric {
        let sender = Flow::new(Role::Sender, Config::librist_defaults());
        let receiver = Flow::new(Role::Receiver, Config::librist_defaults());
        let mut fwd_links = Vec::with_capacity(num_paths);
        let mut back_links = Vec::with_capacity(num_paths);
        for i in 0..num_paths as u64 {
            fwd_links.push(Link::new(
                fwd,
                seed ^ (0xF0F0_0000 ^ i.wrapping_mul(0x1111)),
            ));
            back_links.push(Link::new(
                back,
                seed ^ (0x0F0F_0000 ^ i.wrapping_mul(0x2222)),
            ));
        }
        Fabric::from_links(sender, receiver, fwd_links, back_links)
    }

    /// Schedules one application payload to be pushed into the sender at `at`.
    /// Calls must use non-decreasing `at`.
    pub fn enqueue_source(&mut self, at: Timestamp, payload: Bytes) {
        self.source.push_back((at, payload));
    }

    /// Schedules `n` payloads at a constant `interval` starting at `start`:
    /// `payload_fn(i)` supplies the i-th payload (a constant-bitrate source).
    pub fn enqueue_cbr(
        &mut self,
        start: Timestamp,
        interval: Micros,
        n: usize,
        mut payload_fn: impl FnMut(usize) -> Bytes,
    ) {
        let mut at = start;
        for i in 0..n {
            self.enqueue_source(at, payload_fn(i));
            at = at + interval;
        }
    }

    /// Enables bonded duplicate transmission: every media datagram the sender
    /// emits is sent on all forward paths (the SMPTE 2022-7 full-redundancy
    /// sender); the receiver's `(seq, source_time)` dedup merges the copies.
    pub fn set_duplicate_tx(&mut self, on: bool) {
        self.dup_tx = on;
    }

    /// Replaces path `i`'s forward and back links with freshly seeded links —
    /// modeling a path going down (`loss: 1.0`), recovering, or changing
    /// characteristics mid-run. In-flight datagrams on the old links are dropped.
    pub fn degrade_path(&mut self, i: usize, fwd: LinkConfig, back: LinkConfig, seed: u64) {
        assert!(i < self.fwd.len(), "degrade_path index out of range");
        self.fwd[i] = Link::new(fwd, seed);
        self.back[i] = Link::new(back, seed ^ 0x5555_5555_5555_5555);
    }

    /// The current fake-clock instant.
    pub fn now(&self) -> Timestamp {
        self.now
    }

    /// A snapshot of the receiver flow's counters.
    pub fn receiver_stats(&self) -> rist_core::flow::Stats {
        self.receiver.stats()
    }

    /// A snapshot of the sender flow's counters.
    pub fn sender_stats(&self) -> rist_core::flow::Stats {
        self.sender.stats()
    }

    /// The payloads delivered out of the receiver so far, in delivery order.
    pub fn delivered(&self) -> &[Bytes] {
        &self.delivered
    }

    /// The sequence numbers delivered so far, in delivery order.
    pub fn delivered_seqs(&self) -> &[u32] {
        &self.delivered_seqs
    }

    /// The number of delivered packets that carried a discontinuity flag.
    pub fn discontinuities(&self) -> usize {
        self.discontinuities
    }

    /// Advances the fake clock to the next pending event and processes everything
    /// due: pushes due source payloads, delivers due datagrams into the flows,
    /// fires due timers, and drains the resulting effects back onto the links and
    /// wheels. Returns `false` when the network is quiescent.
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
        self.drain_sender(now);
        self.drain_receiver(now);
        true
    }

    /// Steps until `pred` holds, `max_steps` is reached, or the network goes
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

    /// Drains the sender's effects: media (and its first-transmission instant) and
    /// feedback onto the forward links, timer requests onto the sender's wheel.
    fn drain_sender(&mut self, now: Timestamp) {
        while let Some(out) = self.sender.poll_output() {
            match out {
                Output::SendMedia { path, pkt } => {
                    if !pkt.retransmit {
                        self.send_time.entry(pkt.seq).or_insert(now);
                    }
                    if self.dup_tx {
                        for l in &mut self.fwd {
                            l.send(now, Datagram::Media(pkt.clone()));
                        }
                    } else if let Some(l) = self.fwd.get_mut(path as usize) {
                        l.send(now, Datagram::Media(pkt));
                    }
                }
                Output::SendFeedback { path, fb } => {
                    if let Some(l) = self.fwd.get_mut(path as usize) {
                        l.send(now, Datagram::Feedback(fb));
                    }
                }
                Output::SetTimer { id, deadline } => self.sender_timers.set(id, deadline),
                Output::ClearTimer { id } => self.sender_timers.clear(id),
            }
        }
    }

    /// Drains the receiver's effects: feedback onto the back links, timer requests
    /// onto the receiver's wheel, and records delivered packets and their instants.
    fn drain_receiver(&mut self, now: Timestamp) {
        while let Some(out) = self.receiver.poll_output() {
            match out {
                Output::SendFeedback { path, fb } => {
                    if let Some(l) = self.back.get_mut(path as usize) {
                        l.send(now, Datagram::Feedback(fb));
                    }
                }
                // A receiver never originates media; ignore defensively.
                Output::SendMedia { .. } => {}
                Output::SetTimer { id, deadline } => self.receiver_timers.set(id, deadline),
                Output::ClearTimer { id } => self.receiver_timers.clear(id),
            }
        }
        while let Some(Event::Deliver {
            seq,
            payload,
            discontinuity,
            ..
        }) = self.receiver.poll_event()
        {
            self.delivered_seqs.push(seq);
            self.delivered.push(payload);
            self.deliver_instant.insert(seq, now);
            if discontinuity {
                self.discontinuities += 1;
            }
        }
    }

    /// Validates the delivered stream against the four flow invariants, returning
    /// a list of human-readable violations (empty when all hold):
    ///
    /// 1. No duplicate delivered — each seq at most once.
    /// 2. In order — strictly increasing under wrap-aware compare.
    /// 3. Nothing past deadline — uniform delivery latency within
    ///    `latency_tolerance`, and (when set) no greater than `max_latency`.
    /// 4. Completeness under recoverable loss — no internal gaps (when
    ///    `require_contiguous`).
    pub fn check_invariants(&self, opts: &InvariantOpts) -> Vec<String> {
        let mut violations = Vec::new();
        let seqs = &self.delivered_seqs;

        // (1) + (2): strictly increasing under wrap-aware compare.
        for i in 1..seqs.len() {
            let (prev, cur) = (seqs[i - 1], seqs[i]);
            if prev == cur {
                violations.push(format!("duplicate delivery of seq {cur} at index {i}"));
            } else if !Seq32::new(prev).less(Seq32::new(cur)) {
                violations.push(format!(
                    "out-of-order delivery: seq {cur} after {prev} at index {i}"
                ));
            }
            // (4) completeness: no internal gaps.
            if opts.require_contiguous && cur != prev.wrapping_add(1) {
                violations.push(format!(
                    "internal gap: seq jumps {prev} -> {cur} at index {i}"
                ));
            }
        }

        // (3) nothing past deadline: uniform delivery latency, and within the
        // absolute playout deadline when MaxLatency is set.
        let mut min_lat: Option<Micros> = None;
        let mut max_lat: Option<Micros> = None;
        for &s in seqs {
            match (self.send_time.get(&s), self.deliver_instant.get(&s)) {
                (Some(&st), Some(&dt)) => {
                    let lat = dt - st;
                    if let Some(bound) = opts.max_latency
                        && lat > bound
                    {
                        violations.push(format!(
                            "seq {s} delivered late: latency {} us > max {}",
                            lat.as_micros(),
                            bound.as_micros()
                        ));
                    }
                    min_lat = Some(min_lat.map_or(lat, |m| m.min(lat)));
                    max_lat = Some(max_lat.map_or(lat, |m| m.max(lat)));
                }
                _ => violations.push(format!("missing send/deliver timestamp for seq {s}")),
            }
        }
        if let (Some(mn), Some(mx)) = (min_lat, max_lat)
            && (mx - mn) > opts.latency_tolerance
        {
            violations.push(format!(
                "delivery latency varied by {} us (min {}, max {}) > tolerance {}",
                (mx - mn).as_micros(),
                mn.as_micros(),
                mx.as_micros(),
                opts.latency_tolerance.as_micros()
            ));
        }

        violations
    }
}

fn feed_datagram(flow: &mut Flow, now: Timestamp, path: u8, d: Datagram) {
    match d {
        Datagram::Media(pkt) => flow.feed(now, path, pkt),
        Datagram::Feedback(fb) => flow.feed_feedback(now, fb),
    }
}
