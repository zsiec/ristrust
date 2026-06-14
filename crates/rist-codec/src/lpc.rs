//! The LZ4 block-format codec used by the RIST Advanced Profile for payload
//! compression (LPC=1, LZ4), byte-compatible with libRIST v0.2.18-rc1.
//!
//! libRIST compresses and decompresses Advanced-Profile payloads with the raw LZ4
//! *block* format (NOT the LZ4 frame format): the send path calls
//! `LZ4_compress_default` and the receive path `LZ4_decompress_safe` with an
//! external, known decompressed bound. The block carries no length header, no magic
//! number, and no checksum — the decompressor relies on the caller-supplied output
//! bound to detect overruns. [`compress`] emits a raw LZ4 block and [`decompress`]
//! decodes one against a maximum-output bound.
//!
//! # LZ4 block format
//!
//! A block is a sequence of "sequences". Each sequence is: a token byte (high
//! nibble = literal length, low nibble = match length − 4), optional 255-continued
//! extra literal-length bytes, the literal bytes, a 2-byte little-endian match
//! offset, optional 255-continued extra match-length bytes, and a back-reference
//! copy. The shortest encodable match is 4 bytes ([`MIN_MATCH`]). The final
//! sequence is literals-only (token + literals, no offset/match). A back-reference
//! may overlap the bytes it produces (offset < match length), a run-length
//! expansion; [`decompress`] copies one byte at a time so overlap works.
//!
//! Ported from the published LZ4 block format (Yann Collet's reference lz4, BSD
//! 2-Clause; see `NOTICE.md`). The match finder is the simple LZ4 "fast"
//! single-table variant — its parameters affect only ratio, never decodability:
//! every block [`compress`] emits is a valid LZ4 block decodable by libRIST, and
//! [`decompress`] decodes any valid LZ4 block including those libRIST produces.
//!
//! Pure and panic-free: malformed, truncated, or hostile input to [`decompress`]
//! returns an error and never reads or writes out of bounds.

// Justification: the codec packs lengths/offsets into bytes and stores positions in
// the match finder's i32 hash table; those casts are deliberate and bounded by the
// field widths (the offset is ≤ 65535, positions fit the MTU-bounded input, and the
// `i32 -> usize` read is guarded by a `< 0` sentinel check). Error conditions are
// documented in the module-level prose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc
)]

/// Errors returned by [`decompress`]. `Display` strings are prefixed `"rist: lpc: "`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LpcError {
    /// The block is malformed: a length field or offset runs past the input, or a
    /// copy would read before the start of the produced output.
    #[error("rist: lpc: corrupt LZ4 block")]
    Corrupt,
    /// The decoded output would exceed the caller-supplied `max_out` bound.
    #[error("rist: lpc: decompressed output exceeds maximum")]
    OutputTooLarge,
}

/// The LZ4 MINMATCH: the shortest encodable match length.
pub const MIN_MATCH: usize = 4;

/// Trailing input bytes the LZ4 block format requires to be emitted as literals.
const LAST_LITERALS: usize = 5;

/// The offset from the end of input past which the match finder stops (a candidate
/// needs `MIN_MATCH` bytes plus `LAST_LITERALS` trailing literals).
const MF_LIMIT: usize = MIN_MATCH + LAST_LITERALS;

/// The smallest input the match finder scans; shorter inputs become one
/// literals-only sequence.
const MIN_LENGTH: usize = MF_LIMIT + 1;

/// Sizes the match-finder hash table (`1 << HASH_LOG` entries).
const HASH_LOG: u32 = 12;

/// The number of entries in the match-finder hash table.
const HASH_TABLE_SIZE: usize = 1 << HASH_LOG;

/// The maximum value a length nibble holds before extra continuation bytes, and the
/// value those bytes continue on.
const RUN_MASK: usize = 15;

/// The largest representable match offset (the 2-byte LE offset field).
const MAX_OFFSET: usize = 65535;

/// The maximum bytes a block produced by [`compress`] can occupy for an `n`-byte
/// input (`LZ4_compressBound`: n + n/255 + 16).
#[must_use]
pub fn compress_bound(n: usize) -> usize {
    n + n / 255 + 16
}

/// Reads a 255-continued length field at `sp`, returning `(total, advance)` or
/// `None` if the input ends mid-field.
fn read_length(src: &[u8], mut sp: usize) -> Option<(usize, usize)> {
    let n = src.len();
    let mut total = 0;
    let mut advance = 0;
    loop {
        if sp >= n {
            return None;
        }
        let b = src[sp];
        sp += 1;
        advance += 1;
        total += usize::from(b);
        if b != 255 {
            return Some((total, advance));
        }
    }
}

/// Decodes one raw LZ4 block from `src`, appending the decompressed bytes to `dst`.
/// The output may not exceed `max_out` bytes (the LZ4 block format carries no
/// decompressed length, so the caller supplies the bound). On error `dst` is left
/// unchanged.
pub fn decompress(dst: &mut Vec<u8>, src: &[u8], max_out: usize) -> Result<(), LpcError> {
    let mut out: Vec<u8> = Vec::with_capacity(max_out);
    let n = src.len();
    let mut sp = 0;

    while sp < n {
        let token = src[sp];
        sp += 1;

        // --- literals ---
        let mut lit_len = usize::from(token >> 4);
        if lit_len == RUN_MASK {
            let (extra, adv) = read_length(src, sp).ok_or(LpcError::Corrupt)?;
            lit_len += extra;
            sp += adv;
        }
        if lit_len > n - sp {
            return Err(LpcError::Corrupt);
        }
        if out.len() + lit_len > max_out {
            return Err(LpcError::OutputTooLarge);
        }
        out.extend_from_slice(&src[sp..sp + lit_len]);
        sp += lit_len;

        // The last sequence is literals-only and ends the block exactly here.
        if sp == n {
            break;
        }
        if sp + 2 > n {
            return Err(LpcError::Corrupt);
        }

        // --- match ---
        let offset = usize::from(u16::from_le_bytes([src[sp], src[sp + 1]]));
        sp += 2;
        if offset == 0 {
            return Err(LpcError::Corrupt);
        }
        let low = usize::from(token) & RUN_MASK;
        let mut match_len = low + MIN_MATCH;
        if low == RUN_MASK {
            let (extra, adv) = read_length(src, sp).ok_or(LpcError::Corrupt)?;
            match_len += extra;
            sp += adv;
        }
        if offset > out.len() {
            return Err(LpcError::Corrupt); // match source before the block start
        }
        let match_pos = out.len() - offset;
        if out.len() + match_len > max_out {
            return Err(LpcError::OutputTooLarge);
        }
        // Copy one byte at a time so an overlapping match expands correctly.
        for i in 0..match_len {
            let byte = out[match_pos + i];
            out.push(byte);
        }

        // A valid block terminates with a literals-only sequence; reaching the end
        // immediately after a match means no literals terminator (malformed).
        if sp == n {
            return Err(LpcError::Corrupt);
        }
    }

    dst.extend_from_slice(&out);
    Ok(())
}

/// A 4-byte little-endian load.
fn load32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// The match-finder hash of a 4-byte word.
fn hash(v: u32) -> u32 {
    v.wrapping_mul(2_654_435_761) >> (32 - HASH_LOG)
}

/// Appends a 255-continued length value to `dst`.
fn append_length(dst: &mut Vec<u8>, mut n: usize) {
    while n >= 255 {
        dst.push(255);
        n -= 255;
    }
    dst.push(n as u8);
}

/// Emits a token + literals + offset + (extra match length) sequence.
fn emit_sequence(
    dst: &mut Vec<u8>,
    literals: &[u8],
    lit_len: usize,
    offset: usize,
    match_len: usize,
) {
    let mtok = match_len - MIN_MATCH;
    let mut token = if lit_len >= RUN_MASK {
        (RUN_MASK << 4) as u8
    } else {
        (lit_len << 4) as u8
    };
    token |= if mtok >= RUN_MASK {
        RUN_MASK as u8
    } else {
        mtok as u8
    };
    dst.push(token);
    if lit_len >= RUN_MASK {
        append_length(dst, lit_len - RUN_MASK);
    }
    dst.extend_from_slice(literals);
    dst.push(offset as u8);
    dst.push((offset >> 8) as u8);
    if mtok >= RUN_MASK {
        append_length(dst, mtok - RUN_MASK);
    }
}

/// Emits a terminating literals-only sequence.
fn emit_last_literals(dst: &mut Vec<u8>, literals: &[u8]) {
    let lit_len = literals.len();
    if lit_len >= RUN_MASK {
        dst.push((RUN_MASK << 4) as u8);
        append_length(dst, lit_len - RUN_MASK);
    } else {
        dst.push((lit_len << 4) as u8);
    }
    dst.extend_from_slice(literals);
}

/// Compresses `src` into a raw LZ4 block, appending it to `dst`. The emitted block
/// is a valid LZ4 block decodable by the reference codec (and libRIST).
pub fn compress(dst: &mut Vec<u8>, src: &[u8]) {
    // Inputs too short to host a match are one literals-only sequence.
    if src.len() < MIN_LENGTH {
        emit_last_literals(dst, src);
        return;
    }

    let mut table = [-1i32; HASH_TABLE_SIZE];
    let mut anchor = 0usize;
    let mut ip = 0usize;
    let match_limit = src.len() - LAST_LITERALS;
    let search_limit = src.len() - MF_LIMIT;

    table[hash(load32(src, ip)) as usize] = ip as i32;
    ip += 1;

    while ip <= search_limit {
        let h = hash(load32(src, ip)) as usize;
        let r = table[h];
        table[h] = ip as i32;
        if r < 0 {
            ip += 1;
            continue;
        }
        let refp = r as usize;
        if ip - refp > MAX_OFFSET || load32(src, refp) != load32(src, ip) {
            ip += 1;
            continue;
        }

        // Extend the match forward as far as the data and match_limit allow.
        let mut m_end = ip + MIN_MATCH;
        let mut r_end = refp + MIN_MATCH;
        while m_end < match_limit && src[m_end] == src[r_end] {
            m_end += 1;
            r_end += 1;
        }
        let match_len = m_end - ip;
        let lit_len = ip - anchor;
        emit_sequence(dst, &src[anchor..ip], lit_len, ip - refp, match_len);

        ip = m_end;
        anchor = ip;

        // Record a hash for the position just before the new ip so an immediately
        // following overlapping repeat is discoverable (but do not overwrite
        // table[hash(ip)], or the next read would return ip's own position).
        if ip >= 1 && ip - 1 <= search_limit {
            table[hash(load32(src, ip - 1)) as usize] = (ip - 1) as i32;
        }
    }

    emit_last_literals(dst, &src[anchor..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// LZ4 blocks produced by libRIST's vendored reference lz4 (the exact
    /// `LZ4_compress_default` call its Advanced send path uses). Decompressing each
    /// must yield the recorded plaintext — proving this decoder reads libRIST's
    /// blocks, not only its own output.
    #[test]
    fn decompress_foreign_kat() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "repetitive",
                "6e68656c6c6f2006005c776f726c640600506c64212121",
                "68656c6c6f2068656c6c6f2068656c6c6f2068656c6c6f20776f726c6420776f726c6420776f726c6420776f726c64212121",
            ),
            ("literals_only", "4041424344", "41424344"),
            (
                "long_run_0x47",
                "1f470100ff78504747474747",
                &"47".repeat(400),
            ),
        ];
        for (name, block, plain) in cases {
            let mut out = Vec::new();
            decompress(&mut out, &hx(block), 2048).unwrap();
            assert_eq!(out, hx(plain), "{name}");
        }
    }

    #[test]
    fn round_trip() {
        let inputs: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"A".to_vec(),
            b"ABCD".to_vec(),
            b"hello hello hello hello world world world world!!!".to_vec(),
            vec![0x47; 400],
            (0..1316u32)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
                .collect(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
            {
                let mut v = Vec::new();
                for _ in 0..600 {
                    v.extend_from_slice(&[0xAB, 0xCD]);
                }
                v
            },
        ];
        for inp in &inputs {
            let mut block = Vec::new();
            compress(&mut block, inp);
            let mut out = Vec::new();
            decompress(&mut out, &block, inp.len() + 16).unwrap();
            assert_eq!(&out, inp, "round trip len {}", inp.len());
            // The block must never exceed the documented bound.
            assert!(
                block.len() <= compress_bound(inp.len()),
                "bound for {}",
                inp.len()
            );
        }
    }

    #[test]
    fn compress_appends_to_existing() {
        let mut dst = vec![0xDE, 0xAD];
        compress(&mut dst, b"compress me please, compress me please");
        let mut out = Vec::new();
        decompress(&mut out, &dst[2..], 256).unwrap();
        assert_eq!(out, b"compress me please, compress me please");
    }

    #[test]
    fn decompress_rejects_corrupt() {
        // Offset past the produced output.
        assert_eq!(
            decompress(&mut Vec::new(), &[0x50, 0x01, 0x02, 0x03, 0x00], 100),
            Err(LpcError::Corrupt)
        );
        // Literal length runs past the input.
        assert_eq!(
            decompress(&mut Vec::new(), &[0xF0], 100),
            Err(LpcError::Corrupt)
        );
        // Zero offset.
        assert_eq!(
            decompress(
                &mut Vec::new(),
                &[0x40, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00],
                100
            ),
            Err(LpcError::Corrupt)
        );
        // Output exceeds the bound.
        let mut block = Vec::new();
        compress(&mut block, &[0x55; 200]);
        assert_eq!(
            decompress(&mut Vec::new(), &block, 10),
            Err(LpcError::OutputTooLarge)
        );
    }

    #[test]
    fn decompress_leaves_dst_unchanged_on_error() {
        let mut dst = vec![1, 2, 3];
        let _ = decompress(&mut dst, &[0xF0], 100);
        assert_eq!(dst, [1, 2, 3]);
    }

    #[test]
    fn compress_bound_formula() {
        assert_eq!(compress_bound(0), 16);
        assert_eq!(compress_bound(255), 255 + 1 + 16);
        assert_eq!(compress_bound(1316), 1316 + 5 + 16);
    }
}
