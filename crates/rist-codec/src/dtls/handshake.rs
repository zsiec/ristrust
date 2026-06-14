//! The DTLS handshake fragment header and out-of-order fragment reassembly (RFC
//! 6347 §4.2.2 / §4.2.6, ristgo `handshake.go`). Handshake messages are carried in
//! `handshake` records, each prefixed with a 12-byte fragment header allowing a
//! single message to be split across datagrams and reassembled in order.

use std::collections::BTreeMap;

use super::DtlsError;
use super::messages::HandshakeType;
use super::vec::{Reader, Writer};

/// The fixed handshake fragment header length.
pub const HANDSHAKE_HEADER_LEN: usize = 12;
/// The maximum reassembled handshake message body (64 KiB).
pub const MAX_HANDSHAKE_BODY: usize = 1 << 16;
/// The cap on simultaneously-buffered partial messages (a reassembly DoS guard).
pub const MAX_PENDING_MESSAGES: usize = 8;

/// A DTLS handshake fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// The handshake message type.
    pub typ: HandshakeType,
    /// The total (reassembled) message length.
    pub length: u32,
    /// The message sequence number (monotonic per sender).
    pub message_seq: u16,
    /// This fragment's offset into the message.
    pub fragment_offset: u32,
    /// This fragment's length.
    pub fragment_length: u32,
}

impl FragmentHeader {
    /// Encodes the 12-byte header into `dst`.
    pub fn marshal(&self, dst: &mut Vec<u8>) {
        let mut w = Writer::new();
        w.u8(self.typ.as_u8());
        w.u24(self.length);
        w.u16(self.message_seq);
        w.u24(self.fragment_offset);
        w.u24(self.fragment_length);
        dst.extend_from_slice(w.as_slice());
    }

    /// Parses a 12-byte header from the front of `b`, returning it and the
    /// fragment payload slice that follows.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation, an unknown type, or a fragment that
    /// overruns the record.
    pub fn parse(b: &[u8]) -> Result<(FragmentHeader, &[u8]), DtlsError> {
        let mut r = Reader::new(b);
        let typ = HandshakeType::from_u8(r.u8()?)
            .ok_or(DtlsError::Malformed("handshake message type"))?;
        let length = r.u24()?;
        let message_seq = r.u16()?;
        let fragment_offset = r.u24()?;
        let fragment_length = r.u24()?;
        let payload = r.bytes(fragment_length as usize)?;
        Ok((
            FragmentHeader {
                typ,
                length,
                message_seq,
                fragment_offset,
                fragment_length,
            },
            payload,
        ))
    }
}

/// Reconstructs the canonical, unfragmented wire bytes of a complete handshake
/// message (header with `fragment_offset = 0`, `fragment_length = length`, then the
/// body) — the form hashed into the transcript (RFC 6347 §4.2.6).
#[must_use]
pub fn full_message_bytes(typ: HandshakeType, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
    FragmentHeader {
        typ,
        length: len,
        message_seq,
        fragment_offset: 0,
        fragment_length: len,
    }
    .marshal(&mut out);
    out.extend_from_slice(body);
    out
}

/// One in-progress message being reassembled from fragments.
#[derive(Debug)]
struct Partial {
    typ: HandshakeType,
    total_len: usize,
    body: Vec<u8>,
    received: Vec<bool>,
    have: usize,
    epoch: u16,
}

/// Buffers out-of-order handshake fragments and delivers complete messages in
/// `message_seq` order.
#[derive(Debug, Default)]
pub struct Reassembler {
    next: u16,
    pending: BTreeMap<u16, Partial>,
}

impl Reassembler {
    /// A fresh reassembler expecting `message_seq` 0 first.
    #[must_use]
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Buffers one fragment (received under record `epoch`). Fragments for
    /// already-delivered messages are ignored as duplicates.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on an inconsistent length, an out-of-range
    /// fragment, an oversize message, or too many simultaneously-pending messages.
    pub fn accept(
        &mut self,
        header: FragmentHeader,
        fragment: &[u8],
        epoch: u16,
    ) -> Result<(), DtlsError> {
        if header.message_seq < self.next {
            return Ok(()); // already delivered: a retransmission
        }
        let total = header.length as usize;
        if total > MAX_HANDSHAKE_BODY {
            return Err(DtlsError::Malformed("handshake message too large"));
        }
        let offset = header.fragment_offset as usize;
        let end = offset
            .checked_add(fragment.len())
            .ok_or(DtlsError::Malformed("fragment offset"))?;
        if end > total {
            return Err(DtlsError::Malformed("fragment overruns message"));
        }

        if !self.pending.contains_key(&header.message_seq)
            && self.pending.len() >= MAX_PENDING_MESSAGES
        {
            return Err(DtlsError::Malformed("too many pending handshake messages"));
        }
        let partial = self
            .pending
            .entry(header.message_seq)
            .or_insert_with(|| Partial {
                typ: header.typ,
                total_len: total,
                body: vec![0u8; total],
                received: vec![false; total],
                have: 0,
                epoch,
            });
        if partial.total_len != total || partial.typ != header.typ {
            return Err(DtlsError::Malformed("inconsistent handshake fragment"));
        }
        for (i, byte) in fragment.iter().enumerate() {
            let pos = offset + i;
            if !partial.received[pos] {
                partial.received[pos] = true;
                partial.body[pos] = *byte;
                partial.have += 1;
            }
        }
        Ok(())
    }

    /// Returns the next complete message in order, if available: its type, body,
    /// `message_seq`, and the record epoch its first fragment arrived under.
    ///
    /// # Panics
    /// Never; the internal `remove` is guarded by the readiness check above it.
    pub fn next_message(&mut self) -> Option<(HandshakeType, Vec<u8>, u16, u16)> {
        let seq = self.next;
        let ready = self
            .pending
            .get(&seq)
            .is_some_and(|p| p.have == p.total_len);
        if !ready {
            return None;
        }
        let p = self.pending.remove(&seq).expect("checked ready");
        self.next = self.next.wrapping_add(1);
        Some((p.typ, p.body, seq, p.epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(typ: HandshakeType, seq: u16, total: u32, off: u32, flen: u32) -> FragmentHeader {
        FragmentHeader {
            typ,
            length: total,
            message_seq: seq,
            fragment_offset: off,
            fragment_length: flen,
        }
    }

    #[test]
    fn fragment_header_round_trips() {
        let h = header(HandshakeType::ServerHello, 1, 40, 8, 16);
        let mut buf = Vec::new();
        h.marshal(&mut buf);
        buf.extend_from_slice(&[0xAB; 16]); // the fragment payload
        let (back, payload) = FragmentHeader::parse(&buf).unwrap();
        assert_eq!(back, h);
        assert_eq!(payload, &[0xAB; 16]);
    }

    #[test]
    fn reassembles_a_split_message_in_order() {
        let mut ra = Reassembler::new();
        // message_seq 0, total 10, delivered as two fragments out of order.
        ra.accept(
            header(HandshakeType::Finished, 0, 10, 5, 5),
            &[5, 6, 7, 8, 9],
            1,
        )
        .unwrap();
        assert!(ra.next_message().is_none(), "incomplete: nothing yet");
        ra.accept(
            header(HandshakeType::Finished, 0, 10, 0, 5),
            &[0, 1, 2, 3, 4],
            1,
        )
        .unwrap();
        let (typ, body, seq, epoch) = ra.next_message().unwrap();
        assert_eq!(typ, HandshakeType::Finished);
        assert_eq!(body, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(seq, 0);
        assert_eq!(epoch, 1);
    }

    #[test]
    fn buffers_out_of_order_message_seqs() {
        let mut ra = Reassembler::new();
        // Deliver seq 1 before seq 0.
        ra.accept(header(HandshakeType::ServerHelloDone, 1, 0, 0, 0), &[], 0)
            .unwrap();
        assert!(ra.next_message().is_none(), "seq 0 not yet delivered");
        ra.accept(header(HandshakeType::ServerHello, 0, 2, 0, 2), &[1, 2], 0)
            .unwrap();
        assert_eq!(ra.next_message().unwrap().0, HandshakeType::ServerHello);
        assert_eq!(ra.next_message().unwrap().0, HandshakeType::ServerHelloDone);
        assert!(ra.next_message().is_none());
    }

    #[test]
    fn ignores_duplicate_of_delivered_message() {
        let mut ra = Reassembler::new();
        ra.accept(header(HandshakeType::ServerHello, 0, 1, 0, 1), &[9], 0)
            .unwrap();
        ra.next_message().unwrap();
        // A retransmitted seq-0 fragment is silently ignored, not an error.
        ra.accept(header(HandshakeType::ServerHello, 0, 1, 0, 1), &[9], 0)
            .unwrap();
        assert!(ra.next_message().is_none());
    }

    #[test]
    fn rejects_too_many_pending() {
        let mut ra = Reassembler::new();
        let cap = u16::try_from(MAX_PENDING_MESSAGES).unwrap();
        for seq in 1..=cap {
            ra.accept(header(HandshakeType::Certificate, seq, 4, 0, 2), &[1, 2], 0)
                .unwrap();
        }
        // One past the cap (a new message_seq) is rejected.
        let over = cap + 1;
        assert!(
            ra.accept(
                header(HandshakeType::Certificate, over, 4, 0, 2),
                &[1, 2],
                0
            )
            .is_err()
        );
    }
}
