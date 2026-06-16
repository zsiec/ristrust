//! Host-side reassembly of an Advanced-profile payload the sender split across
//! consecutive sequences. Ported from ristgo `internal/session/reassembler.go`.
//!
//! The flow core delivers fragments in order, each carrying its [`FragRole`] and a
//! discontinuity flag; [`FragReassembler::push`] folds one fragment into the open
//! run and returns the whole payload on the closing [`FragRole::Last`]. A
//! [`FragRole::Standalone`] is a complete payload delivered as-is, so non-Advanced
//! sessions and unfragmented Advanced streams pass straight through untouched.
//!
//! A run is dropped — yielding no payload — whenever it cannot be completed
//! correctly: a [`FragRole::Middle`]/[`FragRole::Last`] arriving with no open run
//! (its [`FragRole::First`] was lost), or any fragment carrying a discontinuity (the
//! flow core skipped a sequence, so a fragment of this payload was lost and never
//! recovered). The application then sees the same gap any unrecovered loss produces.
//! Encountering a [`FragRole::First`] or [`FragRole::Standalone`] also abandons any
//! incomplete previous run (TR-06-3 §5).

use bytes::Bytes;

use rist_core::wire::FragRole;

/// Bounds the fragments one run may absorb before it is abandoned. It is also the
/// sender's per-write split cap (see [`crate::sender`]), so a well-behaved ristrust
/// sender never splits a write into more; a longer run is a peer that never sends
/// [`FragRole::Last`] and must not be allowed to grow the buffer without bound.
/// Keeping the two uses in one constant means they cannot drift apart.
pub(crate) const MAX_REASSEMBLY_FRAGMENTS: usize = 64;

/// Reassembles one in-order fragment run into a complete application payload. Owned
/// by a single driver task, it reuses its buffer across payloads and allocates only
/// when a run grows past the previous high-water mark.
#[derive(Debug, Default)]
pub(crate) struct FragReassembler {
    /// The bytes folded into the open run so far.
    buf: Vec<u8>,
    /// Whether a run is open (a [`FragRole::First`] was seen, no closing yet).
    active: bool,
    /// Fragments folded into the open run (bounds the buffer growth).
    count: usize,
}

impl FragReassembler {
    /// Folds one delivered fragment into the run. Returns `Some(payload)` when a
    /// payload completes — a [`FragRole::Last`] closing an open run, or a
    /// [`FragRole::Standalone`] — and `None` otherwise. `discontinuity` is the flow
    /// core's flag that one or more sequences immediately before this fragment were
    /// counted lost; it aborts any open run.
    pub(crate) fn push(
        &mut self,
        frag: FragRole,
        payload: Bytes,
        discontinuity: bool,
    ) -> Option<Bytes> {
        match frag {
            FragRole::First => {
                // Start a fresh run, abandoning any incomplete previous one. A
                // discontinuity here refers to a prior (already lost) payload, not
                // this run, so it does not invalidate the new run.
                self.buf.clear();
                self.buf.extend_from_slice(&payload);
                self.active = true;
                self.count = 1;
                None
            }
            FragRole::Middle => {
                if !self.active || discontinuity || self.count >= MAX_REASSEMBLY_FRAGMENTS {
                    self.reset(); // a lost fragment, or an over-long run, broke this payload
                    return None;
                }
                self.buf.extend_from_slice(&payload);
                self.count += 1;
                None
            }
            FragRole::Last => {
                if !self.active || discontinuity || self.count >= MAX_REASSEMBLY_FRAGMENTS {
                    self.reset();
                    return None;
                }
                self.buf.extend_from_slice(&payload);
                let out = Bytes::copy_from_slice(&self.buf);
                self.reset();
                Some(out)
            }
            FragRole::Standalone => {
                self.reset();
                Some(payload)
            }
        }
    }

    /// Discards any in-progress run.
    fn reset(&mut self) {
        self.buf.clear();
        self.active = false;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(bytes: &[u8]) -> Bytes {
        Bytes::copy_from_slice(bytes)
    }

    #[test]
    fn standalone_passes_through() {
        let mut r = FragReassembler::default();
        assert_eq!(
            r.push(FragRole::Standalone, b(&[1, 2, 3]), false),
            Some(b(&[1, 2, 3]))
        );
    }

    #[test]
    fn three_fragment_run_reassembles() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[1, 2]), false), None);
        assert_eq!(r.push(FragRole::Middle, b(&[3, 4]), false), None);
        assert_eq!(
            r.push(FragRole::Last, b(&[5, 6]), false),
            Some(b(&[1, 2, 3, 4, 5, 6]))
        );
    }

    #[test]
    fn two_fragment_run_reassembles() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[1, 2, 3]), false), None);
        assert_eq!(
            r.push(FragRole::Last, b(&[4, 5]), false),
            Some(b(&[1, 2, 3, 4, 5]))
        );
    }

    #[test]
    fn middle_without_first_is_dropped() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::Middle, b(&[1, 2]), false), None);
        assert_eq!(r.push(FragRole::Last, b(&[3, 4]), false), None);
    }

    #[test]
    fn last_without_first_is_dropped() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::Last, b(&[3, 4]), false), None);
    }

    #[test]
    fn discontinuity_aborts_open_run() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[1, 2]), false), None);
        // The middle fragment was lost: the next delivery carries a discontinuity.
        assert_eq!(r.push(FragRole::Last, b(&[5, 6]), true), None);
    }

    #[test]
    fn discontinuity_on_middle_aborts_run() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[1, 2]), false), None);
        assert_eq!(r.push(FragRole::Middle, b(&[3, 4]), true), None);
        // The run is dead; a later Last yields nothing (no open run).
        assert_eq!(r.push(FragRole::Last, b(&[5, 6]), false), None);
    }

    #[test]
    fn discontinuity_on_first_starts_run_anyway() {
        let mut r = FragReassembler::default();
        // The discontinuity refers to a prior payload, not this fresh run.
        assert_eq!(r.push(FragRole::First, b(&[1, 2]), true), None);
        assert_eq!(
            r.push(FragRole::Last, b(&[3, 4]), false),
            Some(b(&[1, 2, 3, 4]))
        );
    }

    #[test]
    fn first_abandons_previous_incomplete_run() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[9, 9]), false), None);
        // A new First arrives before the old run closed: the old bytes are dropped.
        assert_eq!(r.push(FragRole::First, b(&[1, 2]), false), None);
        assert_eq!(
            r.push(FragRole::Last, b(&[3, 4]), false),
            Some(b(&[1, 2, 3, 4]))
        );
    }

    #[test]
    fn standalone_abandons_previous_incomplete_run() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[9, 9]), false), None);
        assert_eq!(r.push(FragRole::Standalone, b(&[7]), false), Some(b(&[7])));
        // The abandoned run leaves no residue: a fresh run works.
        assert_eq!(r.push(FragRole::First, b(&[1]), false), None);
        assert_eq!(r.push(FragRole::Last, b(&[2]), false), Some(b(&[1, 2])));
    }

    #[test]
    fn over_long_run_is_abandoned() {
        let mut r = FragReassembler::default();
        assert_eq!(r.push(FragRole::First, b(&[0]), false), None);
        // Fold in MAX-1 more middles to reach the cap (count == MAX after these).
        for _ in 1..MAX_REASSEMBLY_FRAGMENTS {
            assert_eq!(r.push(FragRole::Middle, b(&[0]), false), None);
        }
        // The next fragment would exceed the cap: the run is abandoned.
        assert_eq!(r.push(FragRole::Middle, b(&[0]), false), None);
        assert_eq!(r.push(FragRole::Last, b(&[0]), false), None);
    }
}
