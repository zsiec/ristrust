//! The SMPTE 2022-7 bonding sim suite: drives a full-redundancy sender flow and a
//! merging receiver flow through the N-path `Fabric`, asserting the plan's four
//! invariants across paths plus the two properties unique to bonding — single-path
//! loss is covered by the redundant copy with *no retransmit*, and killing a path
//! mid-stream is seamless. Ported from ristgo `internal/flow/bonding_sim_test.go`.
//!
//! The merge itself is not bonding code: every copy of a sequence — fresh, ARQ
//! resend, or a second path's duplicate — lands in the one ring and dedups by
//! `(seq, source_time)`. These tests prove that one ring under N impaired paths.

// The simulator is internal test scaffolding (not public API) and exposes a fuller
// surface than any single test uses; it also does deliberate numeric casts for the
// fake clock / PRNG.
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

fn ms(n: i64) -> Micros {
    Micros::from_millis(n)
}

/// Encodes a 0-based source index as an 8-byte payload for integrity checks.
fn seq_payload(i: usize) -> Bytes {
    Bytes::copy_from_slice(&(i as u64).to_be_bytes())
}

/// The `n` sequence numbers a sender starting at `start_seq` emits (wrapping).
fn expected_seqs(start_seq: u32, n: usize) -> Vec<u32> {
    (0..n).map(|i| start_seq.wrapping_add(i as u32)).collect()
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

/// A forward-link drop filter that drops media with probability `loss_p` from its
/// own seeded stream but never drops the anchor (first) or top-anchor (last)
/// sequence, and never drops control. Guaranteeing both endpoints means every
/// interior loss has a delivered successor to trigger its NACK, so the sweep can
/// assert exact completeness.
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

/// Schedules `n` payloads into the sender: the first 10 ms ahead so it anchors the
/// flow even when jitter would let a later packet arrive first, the rest 1 ms apart.
fn enqueue_anchored(fab: &mut Fabric, n: usize, source_start: Micros) {
    fab.enqueue_source(Timestamp::ZERO, seq_payload(0));
    for i in 1..n {
        let off = source_start.as_micros() + (i as i64 - 1) * 1000;
        fab.enqueue_source(Timestamp::from_micros(off as u64), seq_payload(i));
    }
}

/// Drives one seeded full-redundancy scenario over `num_paths` independently
/// impaired forward paths (each `fwd_cfg` plus endpoint-protected `loss_p`), with
/// lossless back channels, and asserts the four invariants, exact completeness,
/// `lost == 0`, and that the redundant copies actually merged (`duplicates > 0`).
fn run_bonded_recoverable(
    seed: u64,
    num_paths: usize,
    n: usize,
    start_seq: u32,
    fwd_cfg: LinkConfig,
    loss_p: f64,
) {
    let (sender, receiver) = new_pair(start_seq);
    let last_seq = start_seq.wrapping_add((n - 1) as u32);

    let mut fwd = Vec::with_capacity(num_paths);
    let mut back = Vec::with_capacity(num_paths);
    for path in 0..num_paths as u64 {
        let mut link = Link::new(fwd_cfg, seed ^ path.wrapping_mul(0x1111_2222_3333_4444));
        link.set_drop_filter(protect_endpoints(
            seed ^ path.wrapping_mul(0xA5A5),
            start_seq,
            last_seq,
            loss_p,
        ));
        fwd.push(link);
        back.push(Link::new(
            LinkConfig::with_delay(ms(10)),
            seed ^ 0x1234 ^ path.wrapping_mul(0x9999),
        ));
    }

    let mut fab = Fabric::from_links(sender, receiver, fwd, back);
    fab.set_duplicate_tx(true); // every media packet on every path: full 2022-7
    enqueue_anchored(&mut fab, n, ms(10));

    let done = fab.run_until(|f| f.delivered_seqs().len() >= n, 400_000);
    assert!(
        done,
        "seed {seed} ({num_paths} paths): only {}/{n} delivered (recovered={}, lost={})",
        fab.delivered_seqs().len(),
        fab.receiver_stats().recovered,
        fab.receiver_stats().lost
    );

    let max_lat = Config::librist_defaults().recovery_buffer() + fwd_cfg.delay + fwd_cfg.jitter;
    let opts = InvariantOpts {
        require_contiguous: true,
        latency_tolerance: Micros::ZERO,
        max_latency: Some(max_lat),
    };
    let violations = fab.check_invariants(&opts);
    assert!(
        violations.is_empty(),
        "seed {seed} ({num_paths} paths): invariant violations: {violations:?}"
    );

    assert_eq!(
        fab.delivered_seqs(),
        expected_seqs(start_seq, n).as_slice(),
        "seed {seed} ({num_paths} paths): delivered sequence mismatch"
    );
    let rst = fab.receiver_stats();
    assert_eq!(
        (rst.lost, rst.discontinuities, rst.delivered),
        (0, 0, n as u64),
        "seed {seed} ({num_paths} paths): lost/disc/delivered mismatch"
    );
    // The redundant path's copies must have reached the ring and been merged —
    // otherwise this would silently degenerate to a single-path test.
    assert!(
        rst.duplicates > 0,
        "seed {seed} ({num_paths} paths): no duplicates merged — redundancy never exercised"
    );
}

/// Two paths, 30% independent per-path loss, full duplication. ~9% of packets are
/// lost on *both* paths and recovered by ARQ; the rest are covered by the redundant
/// copy. Every sequence is delivered exactly once, in order, complete, at constant
/// latency, across 256 seeds.
#[test]
fn bonding_2path_2022_7_sweep() {
    let fwd = LinkConfig {
        delay: ms(10),
        jitter: Micros::ZERO,
        loss: 0.0,
        dup_prob: 0.0,
    };
    for seed in 0..256 {
        run_bonded_recoverable(seed, 2, 48, 0, fwd, 0.30);
    }
}

/// Three paths, 50% per-path loss plus 3 ms jitter (reordering). Only ~12.5% of
/// packets are lost on all three; redundancy and ARQ together still deliver every
/// sequence in order and complete, proving the merge scales and tolerates reorder.
/// 128 seeds.
#[test]
fn bonding_3path_2022_7_sweep() {
    let fwd = LinkConfig {
        delay: ms(10),
        jitter: ms(3),
        loss: 0.0,
        dup_prob: 0.0,
    };
    for seed in 0..128 {
        run_bonded_recoverable(seed, 3, 48, 0, fwd, 0.50);
    }
}

/// Three paths crossing the 32-bit sequence wrap under heavy per-path loss: the
/// wrap-aware dedup, missing-detection, and playout must hold under multipath. 64
/// seeds.
#[test]
fn bonding_across_seq_wrap() {
    let start_seq = u32::MAX - 20; // 21 sequences before the wrap, 27 after
    let fwd = LinkConfig {
        delay: ms(10),
        jitter: ms(2),
        loss: 0.0,
        dup_prob: 0.0,
    };
    for seed in 0..64 {
        run_bonded_recoverable(seed, 3, 48, start_seq, fwd, 0.40);
    }
}

/// The defining 2022-7 property: a packet lost on one path but delivered on the
/// other is recovered by the *redundant copy*, with zero retransmission and zero
/// ARQ recovery. Drops only the first transmission of one interior sequence on
/// path 0; path 1 carries it. The receiver never sees a gap, so it never NACKs.
#[test]
fn bonding_single_path_loss_zero_retransmit() {
    const N: usize = 24;
    const TARGET: u32 = 11;
    let (sender, receiver) = new_pair(0);

    // Equal-delay paths so the redundant copy arrives in order and no gap is ever
    // detected. Only path 0 drops the target's first transmission.
    let cfg = LinkConfig::with_delay(ms(10));
    let mut fwd0 = Link::new(cfg, 1);
    fwd0.set_drop_filter(Box::new(
        |d: &Datagram| matches!(d, Datagram::Media(pkt) if !pkt.retransmit && pkt.seq == TARGET),
    ));
    let fwd1 = Link::new(cfg, 2); // lossless: always carries the target
    let back0 = Link::new(cfg, 3);
    let back1 = Link::new(cfg, 4);

    let mut fab = Fabric::from_links(sender, receiver, vec![fwd0, fwd1], vec![back0, back1]);
    fab.set_duplicate_tx(true);
    enqueue_anchored(&mut fab, N, ms(10));

    assert!(fab.run_until(|f| f.delivered_seqs().len() >= N, 200_000));
    let opts = InvariantOpts {
        require_contiguous: true,
        latency_tolerance: Micros::ZERO,
        max_latency: Some(Config::librist_defaults().recovery_buffer() + ms(10)),
    };
    assert!(fab.check_invariants(&opts).is_empty());
    assert_eq!(fab.delivered_seqs(), expected_seqs(0, N).as_slice());

    // Redundancy covered the loss: no NACK, no retransmit, no ARQ recovery.
    assert_eq!(
        fab.sender_stats().retransmitted,
        0,
        "redundant copy should cover the loss with no retransmit"
    );
    let rst = fab.receiver_stats();
    assert_eq!(
        (rst.recovered, rst.nacks_sent, rst.lost),
        (0, 0, 0),
        "single-path loss must be covered by the duplicate, not ARQ"
    );
    assert!(rst.duplicates > 0, "the redundant copies must have merged");
    // The dropped target itself was delivered (via path 1).
    assert!(fab.delivered_seqs().contains(&TARGET));
}

/// Killing a path mid-stream is seamless: two redundant paths deliver, then path 1
/// goes fully dark; path 0 carries the rest (its own losses recovered by ARQ on the
/// lossless back channel). The output stays complete, in order, deduplicated, and
/// at constant latency across the transition.
#[test]
fn bonding_path_death_seamless() {
    const N: usize = 60;
    let (sender, receiver) = new_pair(0);

    // Both paths carry interior loss (recovered by redundancy or ARQ); endpoints
    // protected so completeness is exact.
    let cfg = LinkConfig {
        delay: ms(10),
        jitter: Micros::ZERO,
        loss: 0.0,
        dup_prob: 0.0,
    };
    let mut fwd0 = Link::new(cfg, 7);
    fwd0.set_drop_filter(protect_endpoints(7, 0, N as u32 - 1, 0.20));
    let mut fwd1 = Link::new(cfg, 8);
    fwd1.set_drop_filter(protect_endpoints(8, 0, N as u32 - 1, 0.20));
    let back0 = Link::new(LinkConfig::with_delay(ms(10)), 9);
    let back1 = Link::new(LinkConfig::with_delay(ms(10)), 10);

    let mut fab = Fabric::from_links(sender, receiver, vec![fwd0, fwd1], vec![back0, back1]);
    fab.set_duplicate_tx(true);
    enqueue_anchored(&mut fab, N, ms(10));

    // Run until roughly half delivered, then kill path 1 (loss 1.0 both ways).
    fab.run_until(|f| f.delivered_seqs().len() >= N / 2, 200_000);
    fab.degrade_path(
        1,
        LinkConfig {
            delay: ms(10),
            jitter: Micros::ZERO,
            loss: 1.0,
            dup_prob: 0.0,
        },
        LinkConfig {
            delay: ms(10),
            jitter: Micros::ZERO,
            loss: 1.0,
            dup_prob: 0.0,
        },
        99,
    );

    assert!(
        fab.run_until(|f| f.delivered_seqs().len() >= N, 400_000),
        "stream stalled after path death: {}/{N} delivered",
        fab.delivered_seqs().len()
    );

    let opts = InvariantOpts {
        require_contiguous: true,
        latency_tolerance: Micros::ZERO,
        max_latency: Some(Config::librist_defaults().recovery_buffer() + ms(10)),
    };
    let violations = fab.check_invariants(&opts);
    assert!(
        violations.is_empty(),
        "path-death invariant violations: {violations:?}"
    );
    assert_eq!(fab.delivered_seqs(), expected_seqs(0, N).as_slice());
    let rst = fab.receiver_stats();
    assert_eq!(
        (rst.lost, rst.discontinuities, rst.delivered),
        (0, 0, N as u64),
        "path death must be seamless (no loss, no discontinuity)"
    );
}
