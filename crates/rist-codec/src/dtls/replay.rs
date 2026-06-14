//! The DTLS per-epoch anti-replay sliding window (RFC 6347 §4.1.2.6, ristgo
//! `replay.go`): a 64-bit bitmap tracking which of the most recent sequence
//! numbers have been seen, so duplicates and too-old records are rejected.

/// The width of the replay window (the number of recent sequence numbers tracked
/// below the high-water mark).
pub const REPLAY_WINDOW_SIZE: u64 = 64;

/// A sliding-window replay filter for one epoch.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    /// The highest accepted sequence number (the window's right edge); bit 0 of
    /// `bitmap` corresponds to this sequence.
    right: u64,
    /// A bitmap of accepted sequences: bit `i` is `right - i`.
    bitmap: u64,
    /// Whether any sequence has been accepted yet.
    seen: bool,
}

impl ReplayWindow {
    /// A fresh, empty window.
    #[must_use]
    pub fn new() -> ReplayWindow {
        ReplayWindow::default()
    }

    /// Whether `seq` is acceptable: new (beyond the window), or within the window
    /// and not already seen. Does not record it — call [`ReplayWindow::mark`] after
    /// the record authenticates.
    #[must_use]
    pub fn check(&self, seq: u64) -> bool {
        if !self.seen || seq > self.right {
            return true;
        }
        let diff = self.right - seq;
        if diff >= REPLAY_WINDOW_SIZE {
            return false; // too old: below the window
        }
        self.bitmap & (1u64 << diff) == 0
    }

    /// Records `seq` as accepted, sliding the window forward if it is new.
    pub fn mark(&mut self, seq: u64) {
        if !self.seen {
            self.seen = true;
            self.right = seq;
            self.bitmap = 1;
            return;
        }
        if seq > self.right {
            let shift = seq - self.right;
            if shift >= REPLAY_WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.right = seq;
        } else {
            let diff = self.right - seq;
            if diff < REPLAY_WINDOW_SIZE {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_new_and_rejects_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(w.check(10));
        w.mark(10);
        assert!(!w.check(10), "an exact duplicate is rejected");
        assert!(w.check(11));
        w.mark(11);
        assert!(!w.check(11));
    }

    #[test]
    fn accepts_in_window_out_of_order() {
        let mut w = ReplayWindow::new();
        w.mark(100);
        // An older but in-window, not-yet-seen sequence is accepted.
        assert!(w.check(98));
        w.mark(98);
        assert!(!w.check(98));
        // The one between is still acceptable.
        assert!(w.check(99));
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        w.mark(200);
        // Exactly the window width below the right edge is out of range.
        assert!(!w.check(200 - REPLAY_WINDOW_SIZE));
        // Just inside the window is fine.
        assert!(w.check(200 - REPLAY_WINDOW_SIZE + 1));
    }

    #[test]
    fn large_jump_resets_bitmap() {
        let mut w = ReplayWindow::new();
        w.mark(5);
        w.mark(5 + 2 * REPLAY_WINDOW_SIZE); // jump well past the window
        assert!(
            !w.check(5 + 2 * REPLAY_WINDOW_SIZE),
            "the new high is marked"
        );
        // The old sequence is now far below the window: rejected.
        assert!(!w.check(5));
    }
}
