//! The deterministic, sans-I/O flow core: ARQ + reorder + dedup + RTT/NACK
//! cadence + SMPTE 2022-7 multipath merge, for every profile, with no profile
//! knowledge.
//!
//! # The seam
//!
//! Time enters only through the `now: Timestamp` argument of each input method.
//! Side effects never happen inline — they are queued and drained:
//!
//! - **Inputs** (`&mut self`): [`Flow::feed`], [`Flow::feed_feedback`],
//!   [`Flow::push_app`], [`Flow::handle_timer`], [`Flow::tick`].
//! - **Outputs**: [`Flow::poll_output`] yields [`Output`] effects (perform on the
//!   wire); [`Flow::poll_event`] yields [`Event`]s (surface to the application).
//!
//! Declarative timers: the core *requests* timers by [`TimerId`]; the host owns
//! the wheel.
//!
//! # Status
//!
//! Scaffolding. The seam, [`Config`], and [`Stats`] are in place; the ARQ ring,
//! dedup, missing-detection, playout, and NACK servicing land in Phase 1 (WP1),
//! built against the N-path simulator and the four invariants (see `PLAN.md`).

mod effects;
mod receiver;
mod sender;

pub use effects::{Event, Output, Stats, TimerId};

use std::collections::VecDeque;

use bytes::Bytes;

use crate::clock::{Micros, Timestamp};
use crate::wire::{Feedback, MediaPacket};

/// The default receiver ring capacity, in slots (power of two). libRIST uses a
/// 2^16-slot ring indexed by `seq & mask`.
pub const DEFAULT_RING_SIZE: usize = 1 << 16;

/// Which half of a RIST flow this instance is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Media-originating: accepts [`Flow::push_app`], services NACK requests,
    /// keeps a retransmit history.
    Sender,
    /// Media-consuming: accepts [`Flow::feed`], detects and NACKs missing
    /// packets, and delivers in order after the recovery buffer.
    Receiver,
}

/// Recovery, reorder, RTT, and retry parameters of one flow. The host derives
/// these from its public `Config`; defaults match libRIST (see
/// [`Config::librist_defaults`]).
#[derive(Debug, Clone)]
pub struct Config {
    /// `recovery_length_min`.
    pub recovery_buffer_min: Micros,
    /// `recovery_length_max` (≥ `recovery_buffer_min`).
    pub recovery_buffer_max: Micros,
    /// `recovery_reorder_buffer`.
    pub reorder_buffer: Micros,
    /// Lower clamp applied to measured RTT.
    pub rtt_min: Micros,
    /// Upper clamp applied to measured RTT.
    pub rtt_max: Micros,
    /// Minimum number of retransmission requests before giving up.
    pub min_retries: u32,
    /// Maximum number of retransmission requests before giving up.
    pub max_retries: u32,
    /// Ring capacity in slots; `0` selects [`DEFAULT_RING_SIZE`], other values
    /// round up to the next power of two.
    pub ring_size: usize,
    /// The base flow SSRC. Must be even; the low bit is reserved for the
    /// retransmit marker.
    pub ssrc: u32,
    /// The first sequence number assigned to `push_app` packets.
    pub start_seq: u32,
}

impl Config {
    /// The libRIST default parameters (see the table in `CLAUDE.md`/`PLAN.md`).
    #[must_use]
    pub fn librist_defaults() -> Config {
        Config {
            recovery_buffer_min: Micros::from_millis(1000),
            recovery_buffer_max: Micros::from_millis(1000),
            reorder_buffer: Micros::from_millis(15),
            rtt_min: Micros::from_millis(5),
            rtt_max: Micros::from_millis(500),
            min_retries: 6,
            max_retries: 20,
            ring_size: DEFAULT_RING_SIZE,
            ssrc: 0,
            start_seq: 0,
        }
    }

    /// The derived recovery buffer time, `(max − min)/2 + min` (→ 1000 ms with the
    /// libRIST defaults). Differential-delay tolerance for 2022-7 is this same
    /// playout budget, not a separate window.
    #[must_use]
    pub fn recovery_buffer(&self) -> Micros {
        let span = self.recovery_buffer_max - self.recovery_buffer_min;
        Micros::from_micros(span.as_micros() / 2) + self.recovery_buffer_min
    }

    /// The effective ring capacity (power of two).
    #[must_use]
    fn effective_ring_size(&self) -> usize {
        if self.ring_size == 0 {
            DEFAULT_RING_SIZE
        } else {
            self.ring_size.next_power_of_two()
        }
    }
}

/// One half of a RIST flow: a pure, deterministic state machine.
///
/// Construct with [`Flow::new`], drive with the input methods, and drain effects
/// with [`Flow::poll_output`] / [`Flow::poll_event`]. The same type serves both
/// roles; [`Flow::role`] selects the behavior.
#[derive(Debug)]
pub struct Flow {
    role: Role,
    cfg: Config,
    #[allow(dead_code)] // consumed once the WP1 ring/history machinery lands
    ring_size: usize,
    outputs: VecDeque<Output>,
    events: VecDeque<Event>,
    stats: Stats,
}

impl Flow {
    /// Constructs a flow for `role` with `cfg`. Pre-sizes internal queues; the
    /// receiver ring (WP1) will be fully pre-allocated so steady-state in-order
    /// receive allocates nothing.
    #[must_use]
    pub fn new(role: Role, cfg: Config) -> Flow {
        let ring_size = cfg.effective_ring_size();
        Flow {
            role,
            cfg,
            ring_size,
            outputs: VecDeque::new(),
            events: VecDeque::new(),
            stats: Stats::default(),
        }
    }

    /// This flow's role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// This flow's configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// A snapshot of this flow's counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Feeds one inbound media packet that arrived on `path` at `now`. Only the
    /// receiver half acts on it; the sender half ignores media.
    pub fn feed(&mut self, now: Timestamp, path: u8, pkt: MediaPacket) {
        match self.role {
            Role::Receiver => self.recv_feed(now, path, pkt),
            Role::Sender => {}
        }
    }

    /// Feeds one inbound control message decoded into normalized [`Feedback`].
    pub fn feed_feedback(&mut self, now: Timestamp, fb: Feedback) {
        match self.role {
            Role::Sender => self.send_handle_feedback(now, fb),
            Role::Receiver => self.recv_handle_feedback(now, fb),
        }
    }

    /// Submits one application payload for transmission. Only the sender half acts
    /// on it.
    pub fn push_app(&mut self, now: Timestamp, payload: Bytes) {
        match self.role {
            Role::Sender => self.send_push_app(now, payload),
            Role::Receiver => {}
        }
    }

    /// Fires a previously requested declarative timer.
    pub fn handle_timer(&mut self, now: Timestamp, id: TimerId) {
        match self.role {
            Role::Receiver => self.recv_handle_timer(now, id),
            Role::Sender => self.send_handle_timer(now, id),
        }
    }

    /// Advances time without any external input — lets the core shed too-late
    /// packets and re-arm cadence timers. A no-op until the WP1 machinery lands.
    pub fn tick(&mut self, _now: Timestamp) {
        // TODO(WP1): age the ring / re-evaluate playout and NACK cadence.
    }

    /// Drains the next queued effect, or `None` when the effect queue is empty.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// Drains the next queued application event, or `None` when none remain.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
}
