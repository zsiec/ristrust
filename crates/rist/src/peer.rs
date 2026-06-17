//! One remote endpoint of a RIST flow: its media and RTCP return addresses and a
//! liveness clock.
//!
//! For the Simple profile a flow has a single peer; SMPTE 2022-7 bonding (WP5)
//! attaches several to one flow, which is why this is its own type. A `Peer` is
//! owned by the session driver loop — the only task that reads or writes it.
//! Ported from ristgo `internal/peer`.

use std::net::SocketAddr;

use rist_core::clock::{Micros, Timestamp};

/// A remote endpoint's addressing and liveness state.
#[derive(Debug)]
pub(crate) struct Peer {
    /// Where this side sends RTP. The receiver learns it from the source of
    /// inbound RTP; the sender is configured with it.
    media: Option<SocketAddr>,
    /// Where this side sends compound RTCP (NACKs, reports, echoes).
    rtcp: Option<SocketAddr>,
    timeout: Micros,
    last_seen: Timestamp,
    seen: bool,
}

impl Peer {
    /// A peer with the given session timeout. Addresses are filled in by the
    /// sender constructor or learned (receiver) via [`Peer::learn_media`] /
    /// [`Peer::learn_rtcp`].
    pub(crate) fn new(timeout: Micros) -> Peer {
        Peer {
            media: None,
            rtcp: None,
            timeout,
            last_seen: Timestamp::ZERO,
            seen: false,
        }
    }

    /// A peer with both return addresses known up front (the sender's view).
    pub(crate) fn with_addrs(timeout: Micros, media: SocketAddr, rtcp: SocketAddr) -> Peer {
        Peer {
            media: Some(media),
            rtcp: Some(rtcp),
            timeout,
            last_seen: Timestamp::ZERO,
            seen: false,
        }
    }

    /// Where this side sends RTP, if known.
    pub(crate) fn media(&self) -> Option<SocketAddr> {
        self.media
    }

    /// Where this side sends compound RTCP, if known.
    pub(crate) fn rtcp(&self) -> Option<SocketAddr> {
        self.rtcp
    }

    /// Records the peer's media return address if not already known.
    pub(crate) fn learn_media(&mut self, addr: SocketAddr) {
        if self.media.is_none() {
            self.media = Some(addr);
        }
    }

    /// Records the peer's RTCP return address if not already known. Once the media
    /// address is known, only an RTCP source on the same host (matching IP) is
    /// accepted: a RIST sender's RTCP and media originate from one host (the
    /// ports may differ, the IP does not), so this rejects an off-path datagram
    /// spoofed to the RTCP port that would otherwise redirect the receiver's NACK
    /// feedback to a victim — a low-factor reflection vector. Until media is
    /// known there is nothing to validate against, so first-source-wins applies.
    pub(crate) fn learn_rtcp(&mut self, addr: SocketAddr) {
        if self.rtcp.is_some() {
            return;
        }
        if let Some(media) = self.media
            && media.ip() != addr.ip()
        {
            return; // RTCP source on a different host than media: reject.
        }
        self.rtcp = Some(addr);
    }

    /// Marks that traffic arrived from the peer at `now`, resetting the liveness
    /// clock.
    pub(crate) fn observe(&mut self, now: Timestamp) {
        self.last_seen = now;
        self.seen = true;
    }

    /// The instant traffic was last seen from the peer (`Timestamp::ZERO` if never).
    /// Used by the caller-rebind path to tell whether a rebind recovered the stream
    /// (fresh traffic arrived after it) so the attempt counter can reset.
    pub(crate) fn last_seen(&self) -> Timestamp {
        if self.seen {
            self.last_seen
        } else {
            Timestamp::ZERO
        }
    }

    /// Replaces the peer's media and RTCP return addresses with `addr` — the
    /// deliberate override (unlike `learn_*`, which lock the first source) that
    /// migrates the tuple during a NAT source-port rebind recovery. The caller MUST
    /// gate it on forcing a fresh authentication (see the driver re-association path).
    /// It does NOT touch the liveness clock: the migration alone is not evidence of
    /// liveness, and the held re-auth that follows is bounded by the driver's re-auth
    /// deadline, not `last_seen` (which the migrated tuple's own datagrams would
    /// otherwise keep refreshing on a still-unproven peer).
    pub(crate) fn rebind(&mut self, addr: SocketAddr) {
        self.media = Some(addr);
        self.rtcp = Some(addr);
    }

    /// Whether the peer was seen at least once and has now been silent longer than
    /// `d`. The "dormant candidate" test for NAT-rebind re-association.
    pub(crate) fn silent_for(&self, now: Timestamp, d: Micros) -> bool {
        self.seen && (now - self.last_seen) > d
    }

    /// Whether the peer was once seen but has now been silent for longer than the
    /// session timeout — the condition for tearing the session down. A peer that
    /// has never been seen does not expire (the session is still forming).
    pub(crate) fn expired(&self, now: Timestamp) -> bool {
        self.silent_for(now, self.timeout)
    }

    /// The configured session timeout — the silence span after which the peer
    /// expires. Used by the caller-rebind path to size its (stricter) rebind silence
    /// threshold and backoff.
    pub(crate) fn timeout(&self) -> Micros {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    #[test]
    fn learn_is_first_source_wins() {
        let mut p = Peer::new(Micros::from_millis(2000));
        p.learn_media(addr([10, 0, 0, 1], 5000));
        p.learn_media(addr([10, 0, 0, 2], 6000));
        assert_eq!(p.media(), Some(addr([10, 0, 0, 1], 5000)));
    }

    #[test]
    fn learn_rtcp_rejects_off_host_source() {
        let mut p = Peer::new(Micros::from_millis(2000));
        p.learn_media(addr([10, 0, 0, 1], 5000));
        // A spoofed RTCP source on a different host is rejected.
        p.learn_rtcp(addr([10, 0, 0, 9], 5001));
        assert_eq!(p.rtcp(), None);
        // The genuine same-host RTCP source (different port, same IP) is accepted.
        p.learn_rtcp(addr([10, 0, 0, 1], 5001));
        assert_eq!(p.rtcp(), Some(addr([10, 0, 0, 1], 5001)));
    }

    #[test]
    fn expiry_requires_having_been_seen() {
        let mut p = Peer::new(Micros::from_millis(2000));
        // Never seen: never expires.
        assert!(!p.expired(Timestamp::from_micros(10_000_000)));
        p.observe(Timestamp::from_micros(1_000_000));
        // Within the timeout: alive.
        assert!(!p.expired(Timestamp::from_micros(2_500_000)));
        // Past the timeout: expired.
        assert!(p.expired(Timestamp::from_micros(3_100_000)));
    }
}
