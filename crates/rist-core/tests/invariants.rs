//! Phase-0 smoke test for the deterministic simulator.
//!
//! Proves the simulator wires to the real [`Flow`](rist_core::flow::Flow) seam,
//! advances the fake clock, and reports no invariant violations on the delivered
//! stream. The flow core is still stubbed, so nothing is delivered yet — the
//! four-invariant seed sweeps land in Phase 1 (WP1).

// Relaxed lints for the test harness: the simulator is internal test scaffolding,
// not public API, and uses deliberate numeric casts for the fake clock / PRNG.
// The simulator deliberately exposes a fuller API (dropped counts, clock
// accessors, path degradation) than the Phase-0 smoke test exercises; the WP1
// four-invariant sweeps use the rest.
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
use rist_core::clock::Timestamp;
use sim::{Fabric, InvariantOpts, LinkConfig};

#[test]
fn fabric_drives_the_seam_and_stays_quiescent() {
    let mut fab = Fabric::new(1, LinkConfig::perfect(), LinkConfig::perfect(), 0x00C0_FFEE);
    fab.enqueue_source(Timestamp::from_micros(0), Bytes::from_static(b"hello rist"));
    fab.enqueue_source(
        Timestamp::from_micros(1_000),
        Bytes::from_static(b"second packet"),
    );

    // The stub flow core never delivers, so this goes quiescent quickly.
    fab.run_until(|f| f.delivered().len() >= 2, 100);

    let violations = fab.check_invariants(&InvariantOpts::default());
    assert!(
        violations.is_empty(),
        "unexpected invariant violations: {violations:?}"
    );

    // Delivered is empty until WP1 implements the receiver ring + playout.
    assert_eq!(
        fab.delivered().len(),
        0,
        "the scaffold flow core should not deliver packets yet"
    );
    assert!(fab.delivered_seqs().is_empty());
}
