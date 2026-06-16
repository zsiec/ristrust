//! SMPTE 2022-7 bonding host layer: N paths feeding one [`rist_core::flow::Flow`].
//!
//! The packet-level merge already lives in the flow core: any copy of a sequence
//! — a fresh arrival, an ARQ resend, or a second 2022-7 path's duplicate — lands
//! in the one seq-indexed ring and is deduplicated by its `(seq, source_time)`
//! pair. **Bonding is just more paths feeding that same buffer.** This module owns
//! only the *host policy* the core deliberately leaves out: per-path liveness, the
//! sender's full-redundancy fan-out, and NACK-peer selection.
//!
//! [`Group`] is a pure, deterministic state machine (time enters only through
//! explicit `now` arguments), so it is unit-tested directly without any I/O. It is
//! a faithful port of ristgo's `internal/bonding`, which itself tracks libRIST's
//! `rist_nack_peer_preferred` selection and `RIST_PEER_WEIGHT_DUPLICATE` (weight
//! 0) full redundancy.

// The bonded driver consumes most of this API (`new`/`add_path`/`observe`/`tick`/
// `alive`/`duplicate_targets`/`select_nack_path`). Four members round out a
// coherent, unit-tested surface but have no consumer in the current Main-only
// driver: `observe_rtt`/`rtt` (the per-path RTT tie-break, fed once per-path
// RTT-echo sampling is wired), `should_duplicate` (the single-path form of
// `duplicate_targets`), and `len` (inspection). Reserved rather than removed so the
// port stays faithful to ristgo's `bonding.Group`.
#![allow(dead_code)]

use rist_core::clock::{Micros, Timestamp};
use rist_core::rtt::Estimator;

/// The weight that marks a path for full SMPTE 2022-7 duplication: the sender
/// transmits the identical packet (same seq and source time) on every such path.
/// Matches libRIST's `RIST_PEER_WEIGHT_DUPLICATE`.
pub(crate) const WEIGHT_DUPLICATE: u32 = 0;

/// One bonded path's selection and liveness state.
///
/// `weight`/`priority` are configured once; `rtt`, `last_seen`, `seen`, and `dead`
/// evolve as traffic arrives. `dead` is an edge-detection latch for one-shot death
/// logging only — authoritative liveness is [`Group::alive`], never this flag.
#[derive(Debug, Clone)]
struct Path {
    /// The stable 0-based path identity, matching the `path` argument the host
    /// feeds into [`rist_core::flow::Flow::feed`].
    index: u8,
    /// Load-sharing weight; [`WEIGHT_DUPLICATE`] (0) selects full 2022-7
    /// redundancy, `weight > 0` puts the path in the weighted load-share rotation.
    weight: u32,
    /// Remaining send credit for this weighted path in the current rotation round
    /// (libRIST `w_count`). Re-seeded to `weight` when the round refills or the
    /// weight changes; unused by duplicate-weight paths.
    w_count: u32,
    /// NACK-recovery priority: higher wins the NACK-peer election outright.
    priority: u32,
    /// The per-path RTT estimator; its raw last sample breaks priority ties.
    rtt: Estimator,
    /// When traffic was last observed on this path.
    last_seen: Timestamp,
    /// Whether this path has ever been observed.
    seen: bool,
    /// Edge-detection latch: set the tick a seen path crosses into silence so the
    /// death is reported once. Cleared on the next [`Group::observe`].
    dead: bool,
}

/// A group of bonded paths feeding one flow.
///
/// The host registers each path once with [`Group::add_path`], reports arrivals
/// with [`Group::observe`] and RTT samples with [`Group::observe_rtt`], and then
/// asks the group two questions: which paths to *transmit* a media packet on
/// ([`Group::duplicate_targets`]), and which path to *route a NACK* on
/// ([`Group::select_nack_path`]).
#[derive(Debug)]
pub(crate) struct Group {
    /// The registered paths, in registration (index) order.
    paths: Vec<Path>,
    /// Silence past this marks a seen path dead (libRIST `session_timeout`).
    timeout: Micros,
    /// Extra silence a SMPTE 2022-7 *duplicate* path keeps being transmitted on
    /// after it goes dead, before the sender prunes it from the fan-out — libRIST's
    /// `hard_dead` grace (`recovery_buffer`). A path is reported dead for liveness /
    /// NACK routing at the bare `timeout`, but its 2022-7 redundancy persists until
    /// `timeout + dup_grace`, so a brief return-path RTCP stall does not shed
    /// seamless protection a libRIST sender would keep. Weighted paths get no grace
    /// (their share redistributes at the bare timeout).
    dup_grace: Micros,
    /// The RTT clamp bounds applied to the NACK-selection tie-break.
    rtt_min: Micros,
    /// The upper RTT clamp bound.
    rtt_max: Micros,
}

impl Group {
    /// Builds an empty group. `session_timeout` is the silence after which a seen
    /// path is declared dead; `dup_grace` is the extra silence a 2022-7 duplicate
    /// path keeps being transmitted on past that (libRIST `hard_dead`);
    /// `rtt_min`/`rtt_max` clamp the per-path RTT used in NACK selection (the libRIST
    /// defaults are 2000 ms / 1000 ms / 5 ms / 500 ms).
    pub(crate) fn new(
        session_timeout: Micros,
        dup_grace: Micros,
        rtt_min: Micros,
        rtt_max: Micros,
    ) -> Group {
        Group {
            paths: Vec::new(),
            timeout: session_timeout,
            dup_grace,
            rtt_min,
            rtt_max,
        }
    }

    /// Registers a path. `index` is its stable identity (the flow `path`
    /// argument); `weight` of [`WEIGHT_DUPLICATE`] selects full redundancy;
    /// `priority` orders NACK-peer selection. A duplicate `index` is ignored.
    pub(crate) fn add_path(&mut self, index: u8, weight: u32, priority: u32) {
        if self.paths.iter().any(|p| p.index == index) {
            return;
        }
        self.paths.push(Path {
            index,
            weight,
            w_count: weight, // seed the rotation credit
            priority,
            rtt: Estimator::new(self.rtt_min),
            last_seen: Timestamp::ZERO,
            seen: false,
            dead: false,
        });
    }

    /// The number of registered paths.
    pub(crate) fn len(&self) -> usize {
        self.paths.len()
    }

    /// Records that traffic arrived on `index` at `now`, marking it seen and
    /// resurrecting it if it had been declared dead. Unknown indices are ignored.
    pub(crate) fn observe(&mut self, index: u8, now: Timestamp) {
        if let Some(p) = self.path_mut(index) {
            p.seen = true;
            p.last_seen = now;
            p.dead = false;
        }
    }

    /// Folds one RTT sample into `index`'s estimator (the raw last sample feeds the
    /// NACK-selection tie-break). Unknown indices are ignored.
    pub(crate) fn observe_rtt(&mut self, index: u8, sample: Micros) {
        if let Some(p) = self.path_mut(index) {
            p.rtt = p.rtt.observe(sample);
        }
    }

    /// Whether `index` is currently live: seen at least once and not silent past
    /// the session timeout.
    pub(crate) fn alive(&self, index: u8, now: Timestamp) -> bool {
        self.path(index)
            .is_some_and(|p| p.seen && (now - p.last_seen) <= self.timeout)
    }

    /// Advances liveness to `now` and returns the indices of paths transitioning
    /// from alive to dead *in this call* (edge-detected, reported once). A path
    /// reported dead here is resurrected by a later [`Group::observe`].
    pub(crate) fn tick(&mut self, now: Timestamp) -> Vec<u8> {
        let timeout = self.timeout;
        let mut died = Vec::new();
        for p in &mut self.paths {
            if !p.seen || p.dead {
                continue;
            }
            if (now - p.last_seen) > timeout {
                p.dead = true;
                died.push(p.index);
            }
        }
        died
    }

    /// The paths to transmit a media packet on for full 2022-7 redundancy: every
    /// [`WEIGHT_DUPLICATE`] path that is not *proven* dead. A never-seen path is
    /// included — the sender transmits before return traffic can prove liveness;
    /// only a path seen and then silent past the timeout is dropped.
    pub(crate) fn duplicate_targets(&self, now: Timestamp) -> Vec<u8> {
        self.paths
            .iter()
            .filter(|p| p.weight == WEIGHT_DUPLICATE && !self.dup_dead(p, now))
            .map(|p| p.index)
            .collect()
    }

    /// Whether a media packet should be transmitted on `index` this instant (the
    /// single-path form of [`Group::duplicate_targets`]).
    pub(crate) fn should_duplicate(&self, index: u8, now: Timestamp) -> bool {
        self.path(index)
            .is_some_and(|p| p.weight == WEIGHT_DUPLICATE && !self.dup_dead(p, now))
    }

    /// Whether any path is in the weighted load-share rotation (`weight > 0`). When
    /// false the sender duplicates to the [`WEIGHT_DUPLICATE`] paths alone.
    pub(crate) fn has_weighted(&self) -> bool {
        self.paths.iter().any(|p| p.weight > 0)
    }

    /// Elects the weighted load-share path to carry one media datagram, the libRIST
    /// weighted-send credit rotation: each round, every live weighted path is
    /// granted `weight` credits; the path with the most remaining credit is elected
    /// and spends one, so over a round a path carries `weight`-in-total of the
    /// datagrams. When the round is exhausted it refills the *live* weighted paths
    /// (a dead path is skipped and its share passes to the survivors) and re-elects.
    /// Returns `None` when there are no weighted paths or every weighted path is
    /// dead. Disjoint from [`Group::duplicate_targets`]: a duplicate path is never
    /// elected here, so no path is sent the same datagram twice.
    pub(crate) fn select_weighted(&mut self, now: Timestamp) -> Option<u8> {
        if !self.has_weighted() {
            return None;
        }
        let best = self.best_weighted(now)?; // None → every weighted path is dead
        if self.path(best).is_some_and(|p| p.w_count == 0) {
            // The round is exhausted among the live weighted paths: refill them and
            // re-elect. Dead paths stay empty, so their share passes to survivors.
            let timeout = self.timeout;
            for p in &mut self.paths {
                if p.weight > 0 && !(p.seen && (now - p.last_seen) > timeout) {
                    p.w_count = p.weight;
                }
            }
            let best = self.best_weighted(now)?;
            self.spend(best);
            return Some(best);
        }
        self.spend(best);
        Some(best)
    }

    /// The live weighted path with the most remaining credit; ties resolve to the
    /// earliest-registered. `None` when no weighted path is sendable.
    fn best_weighted(&self, now: Timestamp) -> Option<u8> {
        let mut best: Option<&Path> = None;
        for p in &self.paths {
            if p.weight == 0 || self.proven_dead(p, now) {
                continue;
            }
            if best.is_none_or(|b| p.w_count > b.w_count) {
                best = Some(p);
            }
        }
        best.map(|p| p.index)
    }

    /// Spends one rotation credit from `index` (saturating at 0).
    fn spend(&mut self, index: u8) {
        if let Some(p) = self.path_mut(index) {
            p.w_count = p.w_count.saturating_sub(1);
        }
    }

    /// Changes a path's load-share weight at runtime (libRIST weighted re-balance):
    /// the new weight takes effect from the next round, which restarts immediately
    /// so every path regains full credit. Unknown indices are ignored. A weight of
    /// [`WEIGHT_DUPLICATE`] moves the path back to full-redundancy duplication.
    pub(crate) fn set_weight(&mut self, index: u8, weight: u32) {
        if self.path(index).is_none() {
            return;
        }
        if let Some(p) = self.path_mut(index) {
            p.weight = weight;
        }
        // Restart the round at the new weights.
        for q in &mut self.paths {
            q.w_count = q.weight;
        }
    }

    /// Selects the path to route a NACK on, libRIST's `rist_nack_peer_preferred`:
    /// among live, addressable paths, the highest priority wins, ties broken by the
    /// lowest *raw* last-sample RTT (deliberately fresh, not the smoothed EWMA).
    /// When every path is dead it falls back to the most-recently-seen addressable
    /// path so feedback still has somewhere to go. `addr_known` excludes paths
    /// whose return address has not been learned. Returns `None` only when no
    /// registered path is usable.
    pub(crate) fn select_nack_path(
        &self,
        now: Timestamp,
        addr_known: impl Fn(u8) -> bool,
    ) -> Option<u8> {
        // Phase 1: prefer a live, addressable path.
        let mut best: Option<&Path> = None;
        for p in &self.paths {
            if !self.alive(p.index, now) || !addr_known(p.index) {
                continue;
            }
            if best.is_none_or(|b| self.preferred(p, b)) {
                best = Some(p);
            }
        }
        if let Some(b) = best {
            return Some(b.index);
        }

        // Phase 2: all dead — the most-recently-seen addressable path.
        let mut best: Option<&Path> = None;
        for p in &self.paths {
            if !p.seen || !addr_known(p.index) {
                continue;
            }
            if best.is_none_or(|b| p.last_seen > b.last_seen) {
                best = Some(p);
            }
        }
        best.map(|p| p.index)
    }

    /// The smoothed, clamped RTT for `index` (the sender's retransmit-gate basis);
    /// `rtt_min` when the path is unknown or unsampled.
    pub(crate) fn rtt(&self, index: u8) -> Micros {
        self.path(index)
            .map_or(self.rtt_min, |p| p.rtt.clamped(self.rtt_min, self.rtt_max))
    }

    /// True when `p` has been seen and is now silent past the bare session timeout —
    /// the dead state for liveness, NACK routing, and weighted load-share
    /// redistribution.
    fn proven_dead(&self, p: &Path, now: Timestamp) -> bool {
        p.seen && (now - p.last_seen) > self.timeout
    }

    /// True when a 2022-7 *duplicate* path has been silent past the hard-dead horizon
    /// (`timeout + dup_grace`, libRIST `hard_dead`) — the state that finally prunes it
    /// from the duplicate fan-out. The grace past [`proven_dead`](Self::proven_dead)
    /// keeps a flapping path's redundancy alive through a brief return-path stall.
    fn dup_dead(&self, p: &Path, now: Timestamp) -> bool {
        p.seen && (now - p.last_seen) > (self.timeout + self.dup_grace)
    }

    /// The NACK-selection ordering: higher priority wins; on a tie the lower raw
    /// last-sample RTT (clamped) wins.
    fn preferred(&self, cand: &Path, best: &Path) -> bool {
        match cand.priority.cmp(&best.priority) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => self.nack_rtt(cand) < self.nack_rtt(best),
        }
    }

    /// The raw last-sample RTT, clamped — the NACK tie-break value (not smoothed).
    fn nack_rtt(&self, p: &Path) -> Micros {
        p.rtt.last_clamped(self.rtt_min, self.rtt_max)
    }

    /// The path with `index`, if registered.
    fn path(&self, index: u8) -> Option<&Path> {
        self.paths.iter().find(|p| p.index == index)
    }

    /// The mutable path with `index`, if registered.
    fn path_mut(&mut self, index: u8) -> Option<&mut Path> {
        self.paths.iter_mut().find(|p| p.index == index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Micros = Micros::from_millis(2000);
    const DUP_GRACE: Micros = Micros::from_millis(1000);
    const RTT_MIN: Micros = Micros::from_millis(5);
    const RTT_MAX: Micros = Micros::from_millis(500);

    fn group(paths: &[(u8, u32, u32)]) -> Group {
        // The existing tests assert the bare-timeout death horizon; a zero grace keeps
        // the duplicate prune at the session timeout, as they expect.
        let mut g = Group::new(TIMEOUT, Micros::ZERO, RTT_MIN, RTT_MAX);
        for &(idx, weight, priority) in paths {
            g.add_path(idx, weight, priority);
        }
        g
    }

    #[test]
    fn duplicate_grace_lingers_past_the_bare_timeout() {
        // A duplicate path silent past the session timeout but within the 2022-7
        // grace (timeout + dup_grace) is still a duplicate target; a weighted path is
        // dropped at the bare timeout (its share redistributes immediately).
        let t0 = Timestamp::from_micros(1_000_000);
        let mut g = Group::new(TIMEOUT, DUP_GRACE, RTT_MIN, RTT_MAX);
        g.add_path(0, WEIGHT_DUPLICATE, 0);
        g.add_path(1, 1, 0); // weighted
        g.observe(0, t0);
        g.observe(1, t0);

        // Within (timeout, timeout + grace): the duplicate path lingers.
        let mid = t0 + TIMEOUT + Micros::from_millis(500);
        assert!(
            g.should_duplicate(0, mid),
            "duplicate path must linger through the 2022-7 grace"
        );
        assert_eq!(g.duplicate_targets(mid), vec![0]);
        // The weighted path is already dead at the bare timeout.
        assert!(
            !g.alive(1, mid),
            "weighted path is dead at the bare timeout"
        );

        // Past timeout + grace: the duplicate path is finally pruned.
        let late = t0 + TIMEOUT + DUP_GRACE + Micros::from_millis(1);
        assert!(
            !g.should_duplicate(0, late),
            "duplicate path pruned past the grace"
        );
        assert!(g.duplicate_targets(late).is_empty());
    }

    fn at(ms: u64) -> Timestamp {
        Timestamp::from_micros(ms * 1000)
    }

    #[test]
    fn add_path_ignores_duplicates() {
        let mut g = group(&[(0, 0, 0), (0, 0, 0)]);
        g.add_path(0, 7, 7);
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn select_weighted_splits_in_proportion() {
        // Paths 0 and 1 weighted 3:1. Over a four-credit round (3+1) path 0 carries
        // three datagrams to path 1's one; two rounds give 6:2.
        let mut g = group(&[(0, 3, 0), (1, 1, 0)]);
        let mut counts = [0u32; 2];
        for _ in 0..8 {
            let idx = g
                .select_weighted(at(0))
                .expect("a weighted path is elected");
            counts[idx as usize] += 1;
        }
        assert_eq!(counts, [6, 2], "weight 3:1 over two rounds");
    }

    #[test]
    fn select_weighted_is_none_when_all_duplicate() {
        let mut g = group(&[(0, 0, 0), (1, 0, 0)]);
        assert!(!g.has_weighted());
        assert_eq!(g.select_weighted(at(0)), None);
    }

    #[test]
    fn select_weighted_skips_a_dead_path() {
        // Two equal weighted paths; path 1 falls silent past the timeout, so every
        // election routes to the surviving path 0 (its share redistributes).
        let mut g = group(&[(0, 1, 0), (1, 1, 0)]);
        g.observe(0, at(0));
        g.observe(1, at(0));
        g.observe(0, at(3000)); // path 1 is now silent 3 s > the 2 s timeout
        for _ in 0..6 {
            assert_eq!(
                g.select_weighted(at(3000)),
                Some(0),
                "a dead weighted path must be skipped"
            );
        }
    }

    #[test]
    fn set_weight_rebalances_the_rotation() {
        let mut g = group(&[(0, 1, 0), (1, 1, 0)]); // starts 1:1
        g.set_weight(0, 3); // now 3:1
        let mut counts = [0u32; 2];
        for _ in 0..8 {
            counts[g.select_weighted(at(0)).expect("elected") as usize] += 1;
        }
        assert_eq!(counts, [6, 2]);
        // Moving a path back to duplicate removes it from the rotation.
        g.set_weight(0, WEIGHT_DUPLICATE);
        for _ in 0..4 {
            assert_eq!(
                g.select_weighted(at(0)),
                Some(1),
                "only path 1 stays weighted"
            );
        }
        assert!(
            g.should_duplicate(0, at(0)),
            "path 0 is a duplicate path again"
        );
    }

    #[test]
    fn alive_requires_seen_and_within_timeout() {
        let mut g = group(&[(0, 0, 0)]);
        // Never seen: not alive, not dead.
        assert!(!g.alive(0, at(0)));
        g.observe(0, at(100));
        assert!(g.alive(0, at(100)));
        assert!(g.alive(0, at(2100))); // exactly at the timeout boundary
        assert!(!g.alive(0, at(2101))); // one past
    }

    #[test]
    fn alive_unknown_index_is_false() {
        let g = group(&[(0, 0, 0)]);
        assert!(!g.alive(9, at(0)));
    }

    #[test]
    fn tick_edge_detects_death_once_then_resurrects() {
        let mut g = group(&[(0, 0, 0)]);
        g.observe(0, at(0));
        // Within timeout: no death.
        assert!(g.tick(at(2000)).is_empty());
        // Past timeout: reported once.
        assert_eq!(g.tick(at(2001)), vec![0]);
        // Already dead: not reported again.
        assert!(g.tick(at(5000)).is_empty());
        // Observe resurrects; it can die again later.
        g.observe(0, at(6000));
        assert!(g.alive(0, at(6000)));
        assert_eq!(g.tick(at(8001)), vec![0]);
    }

    #[test]
    fn tick_never_reports_unseen_paths() {
        let mut g = group(&[(0, 0, 0), (1, 0, 0)]);
        g.observe(0, at(0));
        // Path 1 was never seen; only path 0 (seen + silent) dies.
        assert_eq!(g.tick(at(2001)), vec![0]);
    }

    #[test]
    fn select_prefers_higher_priority() {
        let mut g = group(&[(0, 0, 1), (1, 0, 5)]);
        g.observe(0, at(0));
        g.observe(1, at(0));
        // Path 1 has higher priority despite any RTT.
        assert_eq!(g.select_nack_path(at(0), |_| true), Some(1));
    }

    #[test]
    fn select_tiebreaks_on_raw_last_rtt_not_smoothed() {
        // Equal priority. Path 0: many small samples then one big last sample →
        // low smoothed, high raw last. Path 1: many big then one small last →
        // high smoothed, low raw last. Raw-last selection must pick path 1.
        let mut g = group(&[(0, 0, 0), (1, 0, 0)]);
        g.observe(0, at(0));
        g.observe(1, at(0));
        for _ in 0..30 {
            g.observe_rtt(0, Micros::from_millis(10));
            g.observe_rtt(1, Micros::from_millis(200));
        }
        g.observe_rtt(0, Micros::from_millis(200)); // path 0 raw last = 200 ms
        g.observe_rtt(1, Micros::from_millis(10)); // path 1 raw last = 10 ms
        assert!(g.rtt(0) < g.rtt(1), "smoothed: path 0 should be lower");
        // But raw-last tie-break picks path 1 (fresher, lower).
        assert_eq!(g.select_nack_path(at(0), |_| true), Some(1));
    }

    #[test]
    fn select_skips_dead_paths() {
        let mut g = group(&[(0, 0, 9), (1, 0, 1)]);
        g.observe(0, at(0)); // high priority but goes silent
        g.observe(1, at(3000)); // lower priority but live
        // At t=3000 path 0 is dead (silent > 2000 ms); path 1 wins despite lower
        // priority.
        assert_eq!(g.select_nack_path(at(3000), |_| true), Some(1));
    }

    #[test]
    fn select_falls_back_to_most_recent_when_all_dead() {
        let mut g = group(&[(0, 0, 0), (1, 0, 0)]);
        g.observe(0, at(0));
        g.observe(1, at(500));
        // Far past both timeouts: both dead. Fallback = most-recently-seen (path 1).
        assert_eq!(g.select_nack_path(at(10_000), |_| true), Some(1));
    }

    #[test]
    fn select_respects_addr_known_predicate() {
        let mut g = group(&[(0, 0, 9), (1, 0, 1)]);
        g.observe(0, at(0));
        g.observe(1, at(0));
        // Path 0 is higher priority but its return address is unknown.
        assert_eq!(g.select_nack_path(at(0), |i| i == 1), Some(1));
    }

    #[test]
    fn select_excludes_never_seen_paths() {
        let g = group(&[(0, 0, 0)]);
        // Registered but never observed: no return address evidence, none selected.
        assert_eq!(g.select_nack_path(at(0), |_| true), None);
    }

    #[test]
    fn duplicate_targets_includes_unseen_and_live_excludes_proven_dead() {
        let mut g = group(&[(0, 0, 0), (1, 0, 0), (2, 0, 0)]);
        g.observe(0, at(0)); // will be proven dead by t=3000
        g.observe(1, at(3000)); // live at t=3000
        // path 2 never seen → still a target (sender blasts before liveness proven)
        assert_eq!(g.duplicate_targets(at(3000)), vec![1, 2]);
        assert!(!g.should_duplicate(0, at(3000)));
        assert!(g.should_duplicate(1, at(3000)));
        assert!(g.should_duplicate(2, at(3000)));
    }

    #[test]
    fn duplicate_targets_skips_weighted_paths() {
        // weight > 0 is load-balanced, not duplicated.
        let mut g = group(&[(0, WEIGHT_DUPLICATE, 0), (1, 3, 0)]);
        g.observe(0, at(0));
        g.observe(1, at(0));
        assert_eq!(g.duplicate_targets(at(0)), vec![0]);
        assert!(!g.should_duplicate(1, at(0)));
    }
}
