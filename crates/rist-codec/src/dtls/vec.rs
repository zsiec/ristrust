//! A minimal TLS-vector reader/writer (the `cryptobyte` equivalent): fixed
//! big-endian integers and `u8`/`u16`/`u24`-length-prefixed vectors, the building
//! blocks of every TLS/DTLS handshake message and extension.

// Length backfills cast bounded vector lengths (handshake messages are well under
// 2^24) down to the prefix width; truncation cannot occur in practice.
#![allow(clippy::cast_possible_truncation)]

use super::DtlsError;

/// A forward-only writer that appends TLS-encoded values to an owned buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new, empty writer.
    #[must_use]
    pub fn new() -> Writer {
        Writer::default()
    }

    /// Consumes the writer, returning the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// The bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Appends a `u8`.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Appends a big-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Appends a big-endian 24-bit value (the low 3 bytes of `v`).
    pub fn u24(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes()[1..]);
    }

    /// Appends raw bytes.
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Writes a `u8`-length-prefixed vector whose body `f` appends.
    pub fn u8_vec(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.push(0);
        f(self);
        let len = self.buf.len() - at - 1;
        self.buf[at] = len as u8;
    }

    /// Writes a `u16`-length-prefixed vector whose body `f` appends.
    pub fn u16_vec(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        f(self);
        let len = (self.buf.len() - at - 2) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }

    /// Writes a `u24`-length-prefixed vector whose body `f` appends.
    pub fn u24_vec(&mut self, f: impl FnOnce(&mut Writer)) {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, 0]);
        f(self);
        let len = (self.buf.len() - at - 3) as u32;
        self.buf[at..at + 3].copy_from_slice(&len.to_be_bytes()[1..]);
    }
}

/// A cursor-based reader over a byte slice that decodes TLS-encoded values,
/// returning [`DtlsError::Malformed`] on truncation.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// The number of unread bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether all bytes have been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Reads `n` raw bytes.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] if fewer than `n` bytes remain.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DtlsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DtlsError::Malformed("length"))?;
        if end > self.buf.len() {
            return Err(DtlsError::Malformed("truncated"));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Reads a `u8`.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn u8(&mut self) -> Result<u8, DtlsError> {
        Ok(self.bytes(1)?[0])
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn u16(&mut self) -> Result<u16, DtlsError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads a big-endian 24-bit value into a `u32`.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn u24(&mut self) -> Result<u32, DtlsError> {
        let b = self.bytes(3)?;
        Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    /// Reads a `u8`-length-prefixed vector body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn u8_vec(&mut self) -> Result<&'a [u8], DtlsError> {
        let n = usize::from(self.u8()?);
        self.bytes(n)
    }

    /// Reads a `u16`-length-prefixed vector body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn u16_vec(&mut self) -> Result<&'a [u8], DtlsError> {
        let n = usize::from(self.u16()?);
        self.bytes(n)
    }

    /// Reads a `u24`-length-prefixed vector body.
    ///
    /// # Errors
    /// [`DtlsError::Malformed`] on truncation.
    pub fn u24_vec(&mut self) -> Result<&'a [u8], DtlsError> {
        let n = self.u24()? as usize;
        self.bytes(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip() {
        let mut w = Writer::new();
        w.u8(0x12);
        w.u16(0x3456);
        w.u24(0x0078_9ABC);
        let bytes = w.into_bytes();
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0x12);
        assert_eq!(r.u16().unwrap(), 0x3456);
        assert_eq!(r.u24().unwrap(), 0x0078_9ABC);
        assert!(r.is_empty());
    }

    #[test]
    fn length_prefixed_vectors_round_trip() {
        let mut w = Writer::new();
        w.u8_vec(|w| w.bytes(&[1, 2, 3]));
        w.u16_vec(|w| {
            w.u16(0xAAAA);
            w.u16(0xBBBB);
        });
        w.u24_vec(|w| w.bytes(&[9; 5]));
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8_vec().unwrap(), &[1, 2, 3]);
        let inner = r.u16_vec().unwrap();
        assert_eq!(inner, &[0xAA, 0xAA, 0xBB, 0xBB]);
        assert_eq!(r.u24_vec().unwrap(), &[9; 5]);
        assert!(r.is_empty());
    }

    #[test]
    fn reader_rejects_truncation() {
        let mut r = Reader::new(&[0x05]);
        assert!(r.u16().is_err());
        let mut r = Reader::new(&[0x03, 0x01]); // u8 length 3, only 1 byte follows
        assert!(r.u8_vec().is_err());
    }
}
