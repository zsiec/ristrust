//! The four-invariant sim suite: drives a real sender flow and receiver flow
//! through the N-path `Fabric`, asserting the plan's four invariants — no
//! duplicate delivered, in order, nothing past deadline, completeness under
//! recoverable loss — over a seed sweep. Every failure is reproducible from the
//! reported seed. Ported from ristgo `internal/flow/sim_test.go`.

// The simulator is internal test scaffolding (not public API) and exposes a
// fuller surface than any single test uses; it also does deliberate numeric casts
// for the fake clock / PRNG.
#![allow(
    missing_docs,
    missing_debug_implementations,
    unreachable_pub,
    dead_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

mod sim;

use bytes::Bytes;
use rist_core::clock::{Micros, Timestamp};
use rist_core::flow::{Config, Flow, Role};
use sim::{Datagram, Fabric, InvariantOpts, Link, LinkConfig, Rng};

/// Even base SSRC (LSB reserved for the retransmit marker).
const SENDER_SSRC: u32 = 0x0ACE_0AC0;
const SWEEP_SEEDS: u64 = 1024; // >= 1000 seeds per the WP1 gate
const SWEEP_PACKETS: usize = 64;

fn ms(n: i64) -> Micros {
    Micros::from_millis(n)
}

/// Encodes a 0-based source index as an 8-byte payload so delivered payloads can
/// be checked for integrity, not just ordering.
fn seq_payload(i: usize) -> Bytes {
    Bytes::copy_from_slice(&(i as u64).to_be_bytes())
}

/// The `n` sequence numbers a sender starting at `start_seq` emits (wrapping).
fn expected_seqs(start_seq: u32, n: usize) -> Vec<u32> {
    (0..n).map(|i| start_seq.wrapping_add(i as u32)).collect()
}

/// A forward-link drop filter that drops media with probability `loss_p` from its
/// own seeded stream but never drops the anchor (first) or top-anchor (last)
/// sequence, and never drops control. With both endpoints guaranteed, every
/// interior loss has a delivered successor to trigger its NACK, so all
/// recoverable loss is in fact recovered — letting the sweep assert exact
/// completeness rather than a bounded gap.
fn protect_endpoints(
    seed: u64,
    start_seq: u32,
    last_seq: u32,
    loss_p: f64,
) -> Box<dyn FnMut(&Datagram) -> bool> {
    let mut rng = Rng::new(seed ^ 0x9E37_79B9_7F4A_7C15);
    Box::new(move |d: &Datagram| match d {
        Datagram::Media(pkt) => {
            if pkt.seq == start_seq || pkt.seq == last_seq {
                return false;
            }
            rng.unit() < loss_p
        }
        Datagram::Feedback(_) => false,
    })
}

fn new_pair(start_seq: u32) -> (Flow, Flow) {
    let mut scfg = Config::librist_defaults();
    scfg.ssrc = SENDER_SSRC;
    scfg.start_seq = start_seq;
    (
        Flow::new(Role::Sender, scfg),
        Flow::new(Role::Receiver, Config::librist_defaults()),
    )
}

/// Drives one seeded scenario in which all loss is recoverable and asserts the
/// four invariants plus exact completeness. `fwd_cfg` supplies forward
/// impairments (jitter/dup); loss is applied via the endpoint-protecting filter
/// so completeness is exact. The back channel is lossless so NACKs always reach
/// the sender.
fn run_recoverable(
    seed: u64,
    start_seq: u32,
    n: usize,
    fwd_cfg: LinkConfig,
    loss_p: f64,
    source_start: Micros,
    source_gap: Micros,
) {
    let (sender, receiver) = new_pair(start_seq);
    let last_seq = start_seq.wrapping_add((n - 1) as u32);

    let mut fwd = Link::new(fwd_cfg, seed);
    fwd.set_drop_filter(protect_endpoints(seed, start_seq, last_seq, loss_p));
    let back = Link::new(LinkConfig::with_delay(ms(10)), seed ^ 0x1234);

    let mut fab = Fabric::from_links(sender, receiver, vec![fwd], vec![back]);

    // The first packet is sent `source_start` before the rest so it anchors the
    // flow even when jitter would let a later packet arrive first.
    fab.enqueue_source(Timestamp::ZERO, seq_payload(0));
    for i in 1..n {
        let off = source_start.as_micros() + source_gap.as_micros() * (i as i64 - 1);
        fab.enqueue_source(Timestamp::from_micros(off as u64), seq_payload(i));
    }

    let done = fab.run_until(|f| f.delivered_seqs().len() >= n, 200_000);
    assert!(
        done,
        "seed {seed}: only {}/{n} delivered before the step budget (recovered={}, lost={})",
        fab.delivered_seqs().len(),
        fab.receiver_stats().recovered,
        fab.receiver_stats().lost
    );

    // A correct packet's latency is offset + recoveryBuffer, where offset is the
    // first packet's forward delay (<= delay + jitter); max_latency pins the
    // absolute playout deadline on top of the uniformity check.
    let max_lat = Config::librist_defaults().recovery_buffer() + fwd_cfg.delay + fwd_cfg.jitter;
    let opts = InvariantOpts {
        require_contiguous: true,
        latency_tolerance: Micros::ZERO,
        max_latency: Some(max_lat),
    };
    let violations = fab.check_invariants(&opts);
    assert!(
        violations.is_empty(),
        "seed {seed}: invariant violations: {violations:?}"
    );

    assert_eq!(
        fab.delivered_seqs(),
        expected_seqs(start_seq, n).as_slice(),
        "seed {seed}: delivered sequence mismatch"
    );
    // Payload integrity: the k-th delivered payload encodes source index k.
    for (k, p) in fab.delivered().iter().enumerate() {
        assert_eq!(p.len(), 8, "seed {seed}: payload {k} wrong length");
        assert_eq!(
            u64::from_be_bytes(p[..8].try_into().unwrap()),
            k as u64,
            "seed {seed}: payload {k} mismatch"
        );
    }
    let rst = fab.receiver_stats();
    assert_eq!(
        (rst.lost, rst.discontinuities, rst.delivered),
        (0, 0, n as u64),
        "seed {seed}: receiver lost/disc/delivered mismatch"
    );
}

/// The headline gate: 1024 seeds of independent forward loss (plus duplication)
/// with a lossless back channel, each asserting all four invariants and exact
/// completeness. No jitter, so arrival order equals send order; reordering is
/// covered by the jitter sweep.
#[test]
fn four_invariants_recoverable_loss_sweep() {
    let fwd = LinkConfig {
        delay: ms(10),
        jitter: Micros::ZERO,
        loss: 0.0,
        dup_prob: 0.05,
    };
    for seed in 0..SWEEP_SEEDS {
        run_recoverable(seed, 0, SWEEP_PACKETS, fwd, 0.15, ms(1), ms(1));
    }
}

/// Adds forward jitter (reordering) and duplication to the loss, over 256 seeds.
/// The first packet is sent 10 ms ahead of the rest — wider than the jitter — so
/// it still anchors the flow; interior packets reorder freely and must still be
/// delivered in order, deduplicated, complete, and at constant latency.
#[test]
fn four_invariants_jitter_sweep() {
    let fwd = LinkConfig {
        delay: ms(10),
        jitter: ms(3),
        loss: 0.0,
        dup_prob: 0.05,
    };
    for seed in 0..256 {
        run_recoverable(seed, 0, SWEEP_PACKETS, fwd, 0.10, ms(10), ms(1));
    }
}

/// Runs a flow whose sequence space crosses the 32-bit boundary (0xFFFFFFFF -> 0)
/// under loss, exercising the wrap-aware comparisons in dedup, missing-detection,
/// and playout. 128 seeds, exact completeness.
#[test]
fn four_invariants_across_seq_wrap() {
    const N: usize = 64;
    let start_seq = u32::MAX - 30; // 31 sequences before the wrap, 33 after
    let fwd = LinkConfig {
        delay: ms(10),
        jitter: ms(2),
        loss: 0.0,
        dup_prob: 0.05,
    };
    for seed in 0..128 {
        run_recoverable(seed, start_seq, N, fwd, 0.15, ms(10), ms(1));
    }
}

/// The no-impairment baseline: every packet delivered once, in order, with no
/// retransmissions at all.
#[test]
fn perfect_link_exact_delivery() {
    const N: usize = 32;
    let (sender, receiver) = new_pair(1000);
    let fwd = Link::new(LinkConfig::perfect(), 1);
    let back = Link::new(LinkConfig::perfect(), 2);
    let mut fab = Fabric::from_links(sender, receiver, vec![fwd], vec![back]);
    fab.enqueue_cbr(Timestamp::ZERO, ms(1), N, seq_payload);

    assert!(fab.run_until(|f| f.delivered_seqs().len() >= N, 100_000));
    let opts = InvariantOpts {
        require_contiguous: true,
        max_latency: Some(Config::librist_defaults().recovery_buffer() + ms(10)),
        ..InvariantOpts::default()
    };
    assert!(fab.check_invariants(&opts).is_empty());
    assert_eq!(fab.delivered_seqs(), expected_seqs(1000, N).as_slice());
    assert_eq!(
        fab.sender_stats().retransmitted,
        0,
        "perfect link must not retransmit"
    );
    let rst = fab.receiver_stats();
    assert_eq!(
        (rst.recovered, rst.nacks_sent),
        (0, 0),
        "perfect link must not NACK"
    );
}

/// Drops exactly the first transmission of one interior packet and asserts it is
/// recovered by a single retransmit — the canonical ARQ round trip, exactly.
#[test]
fn single_loss_recovered_with_one_retransmit() {
    const N: usize = 16;
    const TARGET: u32 = 7;
    let (sender, receiver) = new_pair(0);

    // 1 ms links: the retransmit round trip (~2 ms) is well under the cold-start
    // NACK retry interval (1.1 x rtt_min = 5.5 ms), so the hole is recovered
    // before the receiver would re-NACK — exactly one retransmit.
    let fast = LinkConfig::with_delay(ms(1));
    let mut fwd = Link::new(fast, 1);
    let mut armed = true;
    fwd.set_drop_filter(Box::new(move |d: &Datagram| {
        if let Datagram::Media(pkt) = d
            && armed
            && !pkt.retransmit
            && pkt.seq == TARGET
        {
            armed = false; // drop only the first transmission of the target
            return true;
        }
        false
    }));
    let back = Link::new(fast, 2);
    let mut fab = Fabric::from_links(sender, receiver, vec![fwd], vec![back]);
    fab.enqueue_cbr(Timestamp::ZERO, ms(1), N, seq_payload);

    assert!(fab.run_until(|f| f.delivered_seqs().len() >= N, 100_000));
    let opts = InvariantOpts {
        require_contiguous: true,
        max_latency: Some(Config::librist_defaults().recovery_buffer() + ms(1)),
        ..InvariantOpts::default()
    };
    assert!(fab.check_invariants(&opts).is_empty());
    assert_eq!(fab.delivered_seqs(), expected_seqs(0, N).as_slice());
    assert_eq!(
        fab.sender_stats().retransmitted,
        1,
        "want exactly one retransmit"
    );
    assert_eq!(fab.receiver_stats().recovered, 1);
}

/// Documents the structural limit of pure ARQ: a lost final packet has no
/// successor to trigger its NACK, so it is never recovered. The delivered run is
/// one short, the gap is bounded (exactly the tail), and the always-on invariants
/// (no duplicate, in order, constant latency) still hold.
#[test]
fn tail_loss_is_bounded_not_complete() {
    const N: usize = 16;
    let (sender, receiver) = new_pair(0);
    let mut fwd = Link::new(LinkConfig::perfect(), 1);
    fwd.set_drop_filter(Box::new(|d: &Datagram| {
        // Drop every transmission of the last sequence: unrecoverable.
        matches!(d, Datagram::Media(pkt) if pkt.seq == (N as u32 - 1))
    }));
    let back = Link::new(LinkConfig::perfect(), 2);
    let mut fab = Fabric::from_links(sender, receiver, vec![fwd], vec![back]);
    fab.enqueue_cbr(Timestamp::ZERO, ms(1), N, seq_payload);

    // Run past the last deliverable packet's playout (no completeness predicate to
    // wait on, since the tail never arrives).
    fab.run_until(|f| f.now() >= Timestamp::from_micros(2_000_000), 100_000);

    // Structural invariants still hold on the delivered prefix; just not
    // contiguity-to-N.
    let opts = InvariantOpts {
        require_contiguous: true,
        max_latency: Some(Config::librist_defaults().recovery_buffer() + ms(10)),
        ..InvariantOpts::default()
    };
    assert!(
        fab.check_invariants(&opts).is_empty(),
        "delivered prefix must be clean"
    );
    assert_eq!(
        fab.delivered_seqs(),
        expected_seqs(0, N - 1).as_slice(),
        "want exactly [0..{}] (tail {} unrecoverable)",
        N - 2,
        N - 1
    );
}

/// Pushes forward loss past what the back channel can repair within the budget
/// (the back channel also drops NACKs): the core must not crash, must deliver no
/// duplicate, nothing out of order, and nothing late; any gap it gives up on is a
/// bounded, accounted discontinuity. The sweep also proves ARQ is doing work (a
/// build with retransmission disabled would fail the recovery floor).
#[test]
fn heavy_loss_graceful_degradation() {
    const N: usize = 80;
    let max_lat = Config::librist_defaults().recovery_buffer() + ms(10); // delay, no jitter
    let (mut total_retransmitted, mut total_recovered, mut total_disc) = (0u64, 0u64, 0u64);
    for seed in 0..64u64 {
        let (sender, receiver) = new_pair(0);
        let fwd = Link::new(
            LinkConfig {
                delay: ms(10),
                jitter: Micros::ZERO,
                loss: 0.6,
                dup_prob: 0.0,
            },
            seed,
        );
        let back = Link::new(
            LinkConfig {
                delay: ms(10),
                jitter: Micros::ZERO,
                loss: 0.3,
                dup_prob: 0.0,
            },
            seed ^ 0x55,
        );
        let mut fab = Fabric::from_links(sender, receiver, vec![fwd], vec![back]);
        fab.enqueue_cbr(Timestamp::ZERO, ms(1), N, seq_payload);

        fab.run_until(|f| f.now() >= Timestamp::from_micros(3_000_000), 500_000);

        // Completeness is NOT required, but the other three are absolute.
        let opts = InvariantOpts {
            require_contiguous: false,
            latency_tolerance: Micros::ZERO,
            max_latency: Some(max_lat),
        };
        let violations = fab.check_invariants(&opts);
        assert!(
            violations.is_empty(),
            "seed {seed}: invariant violations: {violations:?}"
        );

        let rst = fab.receiver_stats();
        assert!(
            rst.delivered <= N as u64,
            "seed {seed}: delivered {} > {N}",
            rst.delivered
        );
        // The Fabric's own discontinuity tally must agree with the receiver's.
        assert_eq!(
            fab.discontinuities() as u64,
            rst.discontinuities,
            "seed {seed}: fabric vs receiver discontinuity disagreement"
        );
        total_retransmitted += fab.sender_stats().retransmitted;
        total_recovered += rst.recovered;
        total_disc += rst.discontinuities;
    }
    assert!(
        total_retransmitted > 0 && total_recovered > 0,
        "no ARQ activity across the sweep (retransmitted={total_retransmitted} recovered={total_recovered}): \
         the test would pass even with recovery disabled"
    );
    assert!(
        total_disc > 0,
        "heavy-loss sweep never exercised an abandoned-gap discontinuity"
    );
}
