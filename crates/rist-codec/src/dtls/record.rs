//! The DTLS 1.2 record layer (RFC 6347 §4.1, ristgo `record.go`): the 13-byte
//! record header with an explicit epoch and 48-bit sequence number, and the
//! split of a datagram into its constituent records.

use super::DtlsError;

/// The fixed DTLS record header length.
pub const RECORD_HEADER_LEN: usize = 13;
/// The maximum record fragment length (TLS §6.2.1: `2^14`).
pub const MAX_RECORD_PAYLOAD: usize = 1 << 14;

/// The DTLS 1.2 wire version (one's-complement `{254, 253}`).
pub const VERSION_DTLS_1_2: [u8; 2] = [254, 253];
/// The DTLS 1.0 wire version (`{254, 255}`), used only in HelloVerifyRequest.
pub const VERSION_DTLS_1_0: [u8; 2] = [254, 255];

/// A DTLS record content type (RFC 6347 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// `change_cipher_spec` (20).
    ChangeCipherSpec = 20,
    /// `alert` (21).
    Alert = 21,
    /// `handshake` (22).
    Handshake = 22,
    /// `application_data` (23).
    ApplicationData = 23,
}

impl ContentType {
    /// The wire byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a content-type byte, or `None` for an unknown type.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<ContentType> {
        match b {
            20 => Some(ContentType::ChangeCipherSpec),
            21 => Some(ContentType::Alert),
            22 => Some(ContentType::Handshake),
            23 => Some(ContentType::ApplicationData),
            _ => None,
        }
    }
}

/// One DTLS record: a typed, versioned, epoch-and-sequence-tagged fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The content type.
    pub typ: ContentType,
    /// The protocol version (`{254, 253}` for DTLS 1.2).
    pub version: [u8; 2],
    /// The epoch (incremented on each cipher-spec change).
    pub epoch: u16,
    /// The 48-bit record sequence number (within the epoch).
    pub seq: u64,
    /// The record fragment (plaintext or AEAD-protected ciphertext).
    pub fragment: Vec<u8>,
}

/// Packs `(epoch, seq)` into the 64-bit value used as the AEAD nonce suffix and
/// the AAD `seq_num`: `epoch << 48 | (seq & 0xFFFF_FFFF_FFFF)`.
#[must_use]
pub fn seq_and_epoch(epoch: u16, seq: u64) -> u64 {
    (u64::from(epoch) << 48) | (seq & 0x0000_FFFF_FFFF_FFFF)
}

impl Record {
    /// Appends the 13-byte header and the fragment to `dst`.
    pub fn marshal(&self, dst: &mut Vec<u8>) {
        dst.push(self.typ.as_u8());
        dst.extend_from_slice(&self.version);
        dst.extend_from_slice(&self.epoch.to_be_bytes());
        // 48-bit sequence: the low 6 bytes of the big-endian u64.
        dst.extend_from_slice(&self.seq.to_be_bytes()[2..]);
        let len = u16::try_from(self.fragment.len()).unwrap_or(u16::MAX);
        dst.extend_from_slice(&len.to_be_bytes());
        dst.extend_from_slice(&self.fragment);
    }

    /// The marshalled size of this record (header + fragment).
    #[must_use]
    pub fn marshal_size(&self) -> usize {
        RECORD_HEADER_LEN + self.fragment.len()
    }

    /// Parses one record from the front of `b`, returning it and the number of
    /// bytes consumed.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] if `b` is too short for the header or the declared
    /// fragment length; the content type is not validated here (an unknown type
    /// parses with the raw bytes available via the error path).
    pub fn parse(b: &[u8]) -> Result<(Record, usize), DtlsError> {
        if b.len() < RECORD_HEADER_LEN {
            return Err(DtlsError::Malformed("record header"));
        }
        let typ = ContentType::from_u8(b[0]).ok_or(DtlsError::Malformed("record content type"))?;
        let version = [b[1], b[2]];
        let epoch = u16::from_be_bytes([b[3], b[4]]);
        let seq = u64::from_be_bytes([0, 0, b[5], b[6], b[7], b[8], b[9], b[10]]);
        let len = usize::from(u16::from_be_bytes([b[11], b[12]]));
        let end = RECORD_HEADER_LEN
            .checked_add(len)
            .ok_or(DtlsError::Malformed("record length"))?;
        if b.len() < end {
            return Err(DtlsError::Malformed("record fragment"));
        }
        let record = Record {
            typ,
            version,
            epoch,
            seq,
            fragment: b[RECORD_HEADER_LEN..end].to_vec(),
        };
        Ok((record, end))
    }
}

/// Splits one received datagram into its constituent records (DTLS packs several
/// records into one datagram).
///
/// # Errors
/// [`DtlsError::Malformed`] on a truncated or malformed record header/fragment.
pub fn split_records(datagram: &[u8]) -> Result<Vec<Record>, DtlsError> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let (record, n) = Record::parse(rest)?;
        out.push(record);
        rest = &rest[n..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_and_epoch_packs_high_word() {
        assert_eq!(seq_and_epoch(1, 5), (1u64 << 48) | 5);
        // The sequence is masked to 48 bits; the epoch occupies the top 16.
        assert_eq!(seq_and_epoch(0xABCD, 0x0000_FFFF_FFFF_FFFF) >> 48, 0xABCD);
    }

    #[test]
    fn record_round_trips() {
        let r = Record {
            typ: ContentType::Handshake,
            version: VERSION_DTLS_1_2,
            epoch: 1,
            seq: 0x0000_1234_5678_9ABC & 0x0000_FFFF_FFFF_FFFF,
            fragment: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let mut buf = Vec::new();
        r.marshal(&mut buf);
        assert_eq!(buf.len(), r.marshal_size());
        let (back, n) = Record::parse(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(back, r);
    }

    #[test]
    fn split_records_handles_multiple() {
        let a = Record {
            typ: ContentType::Handshake,
            version: VERSION_DTLS_1_2,
            epoch: 0,
            seq: 0,
            fragment: vec![1, 2, 3],
        };
        let b = Record {
            typ: ContentType::ChangeCipherSpec,
            version: VERSION_DTLS_1_2,
            epoch: 0,
            seq: 1,
            fragment: vec![1],
        };
        let mut buf = Vec::new();
        a.marshal(&mut buf);
        b.marshal(&mut buf);
        let records = split_records(&buf).unwrap();
        assert_eq!(records, vec![a, b]);
    }

    #[test]
    fn parse_rejects_truncation() {
        assert!(Record::parse(&[0u8; 5]).is_err());
        let mut buf = Vec::new();
        Record {
            typ: ContentType::Alert,
            version: VERSION_DTLS_1_2,
            epoch: 0,
            seq: 0,
            fragment: vec![0; 10],
        }
        .marshal(&mut buf);
        buf.truncate(buf.len() - 3); // chop the fragment tail
        assert!(Record::parse(&buf).is_err());
    }

    #[test]
    fn content_type_round_trips() {
        for t in [
            ContentType::ChangeCipherSpec,
            ContentType::Alert,
            ContentType::Handshake,
            ContentType::ApplicationData,
        ] {
            assert_eq!(ContentType::from_u8(t.as_u8()), Some(t));
        }
        assert_eq!(ContentType::from_u8(99), None);
    }
}
