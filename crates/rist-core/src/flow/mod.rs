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
//! # The one ring (the 2022-7 merge)
//!
//! Every inbound media packet — first transmission, ARQ retransmit, or a
//! duplicate copy from another 2022-7 path — lands in **one** power-of-two ring
//! indexed by `seq & mask` and validated by `(seq, source_time)`, exactly as
//! libRIST does in `receiver_enqueue`. A filled slot with the same `(seq,
//! source_time)` is a duplicate and is dropped; that single test is the entire
//! multipath merge. A filled slot with a different `(seq, source_time)` is stale
//! and is overwritten. The receiver half owns that machinery; the sender half
//! owns the retransmit history and the per-packet RTT gate.

mod congestion;
mod effects;
mod receiver;
mod sender;

pub use congestion::CongestionMode;
pub use effects::{Event, Output, Stats, TimerId};

use std::collections::VecDeque;

use bytes::Bytes;

use crate::clock::{Micros, Ntp64, Timestamp};
use crate::rtt::Estimator;
use crate::wire::{Feedback, FragRole, MediaPacket};

use receiver::ReceiverState;
use sender::SenderState;

/// The default receiver ring capacity, in slots. libRIST uses a 2^16-slot ring
/// indexed by `seq & mask` (`receiver_queue_max`).
pub const DEFAULT_RING_SIZE: usize = 1 << 16;

/// The receiver NACK cadence: libRIST's `RIST_MAX_JITTER` = 5 ms receiver-loop
/// bound, the longest the NACK pass may lag.
const NACK_CADENCE: Micros = Micros::from_millis(5);

/// The RTT-echo origination interval: libRIST's `RIST_PING_INTERVAL` = 100 ms.
/// Both roles originate echoes to measure their own RTT.
const RTT_ECHO_INTERVAL: Micros = Micros::from_millis(100);

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
    /// Ring capacity in slots; `0` derives it from the recovery window and
    /// `recovery_maxbitrate` (floored at [`DEFAULT_RING_SIZE`]), other values round
    /// up to the next power of two.
    pub ring_size: usize,
    /// `recovery_maxbitrate` in kbps (libRIST default 100000): the ceiling the
    /// sender paces retransmissions against under [`CongestionMode::Normal`] /
    /// [`CongestionMode::Aggressive`], and the basis for the derived ring size,
    /// missing-queue, and per-pass NACK bounds.
    pub recovery_maxbitrate: u32,
    /// The sender's congestion-control / NACK-pacing mode.
    pub congestion_control: CongestionMode,
    /// The base flow SSRC. Must be even; the low bit is reserved for the
    /// retransmit marker.
    pub ssrc: u32,
    /// The first sequence number assigned to `push_app` packets.
    pub start_seq: u32,
    /// Disables ARQ recovery for a one-way / no-return-channel transport: the
    /// sender retains no retransmit history and originates no RTT echo; the
    /// receiver queues no missing entries (so requests no NACKs) and originates no
    /// RTT echo, reclaiming an unrecoverable hole by playout-skip rather than ARQ.
    pub no_recovery: bool,
}

impl Config {
    /// The libRIST default parameters — the authoritative values a ristrust peer
    /// must match to interoperate with libRIST.
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
            recovery_maxbitrate: 100_000,
            congestion_control: CongestionMode::Normal,
            ssrc: 0,
            start_seq: 0,
            no_recovery: false,
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

    /// The effective ring capacity (power of two). `ring_size == 0` derives it from
    /// the recovery window and `recovery_maxbitrate` (then rounds up to a power of
    /// two); an explicit value is rounded up directly.
    #[must_use]
    fn effective_ring_size(&self) -> usize {
        if self.ring_size == 0 {
            congestion::derive_ring_size(self).next_power_of_two()
        } else {
            self.ring_size.next_power_of_two()
        }
    }
}

/// One half of a RIST flow: a pure, deterministic state machine.
///
/// Construct with [`Flow::new`], drive with the input methods, and drain effects
/// with [`Flow::poll_output`] / [`Flow::poll_event`]. The same type serves both
/// roles; [`Flow::role`] selects the behavior. Not safe for concurrent use; the
/// host serializes all calls.
// Fields are module-private to `flow`; the `receiver` / `sender` submodules and
// the white-box test modules are descendants and so may access them, while
// nothing outside the flow core can (the host drives it only through methods).
#[derive(Debug)]
pub struct Flow {
    role: Role,
    cfg: Config,

    /// The derived playout budget (`Config::recovery_buffer`).
    recovery_buffer: Micros,
    /// `recovery_buffer * 1.1`, computed with the same double multiply-and-
    /// truncate libRIST uses for its too-late and NACK-abandon thresholds.
    recovery_buffer_110: Micros,

    /// The libRIST `eight_times_rtt` estimator. One per flow this stage;
    /// per-path attribution lands with bonding.
    est: Estimator,

    /// Bounds how many missing entries the receiver queues before it stops marking
    /// new gaps (the buffer-bloat guard), derived from the recovery window and
    /// `recovery_maxbitrate`.
    missing_counter_max: u32,
    /// Caps the retransmissions the sender emits per service pass (the rest are
    /// re-NACKed), derived likewise.
    max_nacks_per_loop: u32,

    outputs: VecDeque<Output>,
    events: VecDeque<Event>,
    stats: Stats,

    receiver: ReceiverState,
    sender: SenderState,
}

impl Flow {
    /// Constructs a flow for `role` with `cfg`. `ring_size` is normalized
    /// (`0` → [`DEFAULT_RING_SIZE`], else rounded up to a power of two); range
    /// validation is the caller's job. The ring of the matching half is fully
    /// pre-allocated so steady-state in-order receive allocates nothing.
    #[must_use]
    pub fn new(role: Role, cfg: Config) -> Flow {
        let size = cfg.effective_ring_size();
        let recovery_buffer = cfg.recovery_buffer();
        let recovery_buffer_110 = mul_1_1(recovery_buffer);
        let est = Estimator::new(cfg.rtt_min);
        let (receiver, sender) = match role {
            Role::Receiver => (ReceiverState::new(size), SenderState::empty()),
            Role::Sender => (
                ReceiverState::empty(),
                SenderState::new(size, cfg.ssrc, cfg.start_seq),
            ),
        };
        let missing_counter_max = congestion::derive_missing_counter_max(&cfg);
        let max_nacks_per_loop = congestion::derive_max_nacks_per_loop(&cfg);
        Flow {
            role,
            cfg,
            recovery_buffer,
            recovery_buffer_110,
            est,
            missing_counter_max,
            max_nacks_per_loop,
            outputs: VecDeque::new(),
            events: VecDeque::new(),
            stats: Stats::default(),
            receiver,
            sender,
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
    ///
    /// Retains `pkt.payload` by reference (zero-copy) until the packet is
    /// delivered, overwritten, or abandoned; producers must not mutate it after.
    pub fn feed(&mut self, now: Timestamp, path: u8, pkt: MediaPacket) {
        if self.role == Role::Receiver {
            self.recv_feed(now, path, pkt);
        }
    }

    /// Feeds one inbound control message decoded into normalized [`Feedback`].
    ///
    /// Both roles answer an [`Feedback::RttEchoRequest`] immediately (zero
    /// processing delay, since the core responds within the same step) and fold
    /// an [`Feedback::RttEchoResponse`] into the RTT estimator. A
    /// [`Feedback::Nack`] is serviced from the retransmit history on a sender and
    /// ignored on a receiver; every variant without a handler is counted in
    /// [`Stats::ignored_feedback`] rather than crashing — additive wire variants
    /// must never break the core. The match is exhaustive so a *new* variant is a
    /// compile error here, forcing a deliberate handle-or-ignore decision.
    pub fn feed_feedback(&mut self, now: Timestamp, fb: Feedback) {
        match fb {
            Feedback::RttEchoRequest { ssrc, timestamp } => {
                // Echo the requester's SSRC (and timestamp) back: a libRIST
                // requester drops any response whose SSRC differs from its own.
                let path = self.feedback_path();
                self.outputs.push_back(Output::SendFeedback {
                    path,
                    fb: Feedback::RttEchoResponse {
                        ssrc,
                        timestamp,
                        processing_delay: 0,
                    },
                });
            }
            Feedback::RttEchoResponse {
                timestamp,
                processing_delay,
                ..
            } => {
                // sample = (now - echoed timestamp) - processing delay. A negative
                // sample is pinned to zero by the estimator (libRIST
                // calculate_rtt_delay).
                let sent = Ntp64::from_bits(timestamp).to_timestamp();
                let sample = (now - sent) - Micros::from_micros(i64::from(processing_delay));
                self.est = self.est.observe(sample);
            }
            Feedback::Nack { missing, .. } => {
                if self.role == Role::Sender {
                    self.service_nack(now, missing);
                } else {
                    // A receiver does not originate retransmissions.
                    self.stats.ignored_feedback += 1;
                }
            }
            // SenderReport (WP4 offset refinement), Keepalive (host liveness),
            // ExtSeq / LinkQuality / FlowAttribute (codec / host concerns): no core
            // handler. The host intercepts LinkQuality and FlowAttribute before the
            // core; reaching here means they were not, so count and ignore them.
            Feedback::SenderReport { .. }
            | Feedback::Keepalive
            | Feedback::ExtSeq { .. }
            | Feedback::LinkQuality { .. }
            | Feedback::FlowAttribute { .. } => {
                self.stats.ignored_feedback += 1;
            }
        }
    }

    /// The path control messages leave on: the sender's fixed transmit path, or
    /// the receiver's most-recent media path (feedback follows the media back).
    fn feedback_path(&self) -> u8 {
        match self.role {
            Role::Sender => self.sender.tx_path,
            Role::Receiver => self.receiver.last_path,
        }
    }

    /// Submits one complete application payload for transmission. Only the sender
    /// half acts on it; it retains `payload` by reference so it can be re-sent on
    /// NACK. Equivalent to [`Flow::push_app_frag`] with [`FragRole::Standalone`].
    pub fn push_app(&mut self, now: Timestamp, payload: Bytes) {
        self.push_app_frag(now, payload, FragRole::Standalone);
    }

    /// Submits one fragment of an application payload the host has split across
    /// consecutive sequences (Advanced fragmentation). `frag` is the fragment's role
    /// ([`FragRole::First`] / [`FragRole::Middle`] / [`FragRole::Last`]), which the
    /// core carries opaquely onto the [`MediaPacket`] and back out at delivery for
    /// the host reassembler; it ascribes no meaning to it. Each fragment is an
    /// independent sequence, so per-fragment ARQ falls out of the normal ring.
    pub fn push_app_frag(&mut self, now: Timestamp, payload: Bytes, frag: FragRole) {
        if self.role == Role::Sender {
            self.send_push_app(now, payload, frag);
        }
    }

    /// Fires a previously requested declarative timer; `now` is the instant it
    /// fired. Stale or no-longer-relevant IDs are ignored.
    pub fn handle_timer(&mut self, now: Timestamp, id: TimerId) {
        match self.role {
            Role::Sender => self.sender_handle_timer(now, id),
            Role::Receiver => match id {
                TimerId::Playout => {
                    self.receiver.playout_armed = false;
                    self.deliver_due(now);
                }
                TimerId::Nack => {
                    self.receiver.nack_armed = false;
                    self.process_nacks(now);
                    self.schedule_nack(now);
                }
                TimerId::RttEcho => {
                    if self.receiver.started {
                        let path = self.receiver.last_path;
                        self.outputs.push_back(Output::SendFeedback {
                            path,
                            fb: Feedback::RttEchoRequest {
                                // Originated: the codec fills the local SSRC.
                                ssrc: 0,
                                timestamp: Ntp64::from_timestamp(now).bits(),
                            },
                        });
                        self.outputs.push_back(Output::SetTimer {
                            id: TimerId::RttEcho,
                            deadline: now + RTT_ECHO_INTERVAL,
                        });
                    }
                }
            },
        }
    }

    /// Advances time without external input: lets the receiver perform due
    /// in-order delivery and a NACK pass. A host honoring `SetTimer` effects need
    /// not call this, but it is always safe to. A no-op on a sender.
    pub fn tick(&mut self, now: Timestamp) {
        if self.role == Role::Receiver {
            self.deliver_due(now);
            self.process_nacks(now);
        }
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

/// `d * 1.1` via the same `f64` multiply-and-truncate libRIST uses for its
/// recovery-buffer-derived thresholds.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn mul_1_1(d: Micros) -> Micros {
    Micros::from_micros((d.as_micros() as f64 * 1.1) as i64)
}

/// White-box test helpers shared by the receiver and sender test modules. These
/// build packets and drain effect/event queues; they never touch ring internals
/// (those assertions live in the per-half test modules, next to the state).
#[cfg(test)]
pub(crate) mod testutil {
    use super::{Event, Flow, FragRole, MediaPacket, Output};
    use crate::clock::{Ntp64, Timestamp};
    use bytes::Bytes;

    /// The SSRC every test packet carries (even base; LSB reserved for retransmit).
    pub(crate) const TEST_SSRC: u32 = 0x1234_5678;

    /// The NTP-64 source-time wire value for `us` microseconds.
    pub(crate) fn src_ntp(us: u64) -> u64 {
        Ntp64::from_timestamp(Timestamp::from_micros(us)).bits()
    }

    /// A first-transmission media packet at source instant `src_us`.
    pub(crate) fn mk_pkt(seq: u32, src_us: u64, payload: &'static [u8]) -> MediaPacket {
        MediaPacket {
            seq,
            source_time: src_ntp(src_us),
            ssrc: TEST_SSRC,
            payload: Bytes::from_static(payload),
            retransmit: false,
            path_id: 0,
            frag: FragRole::Standalone,
        }
    }

    /// Empties the output queue into a vector.
    pub(crate) fn drain_outputs(f: &mut Flow) -> Vec<Output> {
        let mut out = Vec::new();
        while let Some(o) = f.poll_output() {
            out.push(o);
        }
        out
    }

    /// Empties the event queue into a vector.
    pub(crate) fn drain_events(f: &mut Flow) -> Vec<Event> {
        let mut evs = Vec::new();
        while let Some(e) = f.poll_event() {
            evs.push(e);
        }
        evs
    }

    /// The delivered sequence numbers of a slice of events.
    pub(crate) fn delivered_seqs(evs: &[Event]) -> Vec<u32> {
        evs.iter().map(|Event::Deliver { seq, .. }| *seq).collect()
    }
}
