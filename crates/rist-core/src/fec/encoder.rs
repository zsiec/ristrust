//! The FEC sender: clips each media packet into its row and column groups and
//! emits a [`Packet`] whenever a group fills.

// See the module-level note in `mod.rs`: the casts into the narrow FEC field
// widths and the wrap-aware sequence space are bounded by construction.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use bytes::Bytes;

use super::{Config, Direction, Packet, seq_add, seq_diff};

/// Accumulates the XOR of one row's or column's packets. `length_clip`, `pt_clip`,
/// and `ts_clip` recover the missing packet's length, payload type, and timestamp;
/// `payload_clip` recovers its payload.
struct Group {
    base: u32,
    collected: usize,
    length_clip: u16,
    pt_clip: u8,
    ts_clip: u32,
    payload_clip: Vec<u8>,
}

impl Group {
    fn new(base: u32, payload_size: usize) -> Self {
        Self {
            base,
            collected: 0,
            length_clip: 0,
            pt_clip: 0,
            ts_clip: 0,
            payload_clip: vec![0u8; payload_size],
        }
    }

    /// Reset the accumulator for a new group starting at `base`, reusing the buffer.
    fn reset(&mut self, base: u32) {
        self.base = base;
        self.collected = 0;
        self.length_clip = 0;
        self.pt_clip = 0;
        self.ts_clip = 0;
        self.payload_clip.iter_mut().for_each(|b| *b = 0);
    }

    /// XOR one packet's recoverable fields into the accumulator. A short payload is
    /// implicitly zero-padded to the matrix payload size; a long one is clipped.
    fn clip(&mut self, length: u16, pt: u8, ts: u32, payload: &[u8]) {
        self.length_clip ^= length;
        self.pt_clip ^= pt & 0x7f;
        self.ts_clip ^= ts;
        for (dst, &src) in self.payload_clip.iter_mut().zip(payload) {
            *dst ^= src;
        }
    }
}

/// Clips each media packet (in sequence order) into its row and column groups and
/// emits the FEC packets completed groups produce. Deterministic and
/// allocation-light: it reuses its group buffers across matrices.
#[derive(Debug)]
pub struct Encoder {
    cfg: Config,
    row: Group,
    /// One accumulator per column; empty when `rows <= 1` (no column FEC).
    cols: Vec<Group>,
    /// The base sequence of the current row group.
    row_base: u32,
}

// `Group` holds only plain fields; a manual Debug keeps the struct printable
// without exposing the (large) clip buffers.
impl core::fmt::Debug for Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Group")
            .field("base", &self.base)
            .field("collected", &self.collected)
            .field("payload_clip_len", &self.payload_clip.len())
            .finish_non_exhaustive()
    }
}

impl Encoder {
    /// Build an encoder for the matrix in `cfg`. `payload_size` is the largest
    /// protected payload (FEC payloads are this size); `isn` must be the sequence
    /// number of the first media packet pushed.
    #[must_use]
    pub fn new(cfg: Config, payload_size: usize, isn: u32) -> Self {
        let cols = if cfg.rows > 1 {
            (0..cfg.cols)
                .map(|i| Group::new(seq_add(isn, i as i64), payload_size))
                .collect()
        } else {
            Vec::new()
        };
        Self {
            cfg,
            row: Group::new(isn, payload_size),
            cols,
            row_base: isn,
        }
    }

    /// Clip one media packet (in sequence order) and return any FEC packets the
    /// completed groups produced (zero, one, or both a column and a row packet, in
    /// that order). The returned `Vec` is empty (no allocation) on the common path
    /// where no group fills.
    pub fn push(&mut self, s: u32, ts: u32, pt: u8, payload: &[u8]) -> Vec<Packet> {
        let mut out = Vec::new();
        let l = self.cfg.cols as i64;

        // Advance the row group if this packet starts a new row.
        if seq_diff(self.row_base, s) >= l {
            self.row_base = seq_add(self.row_base, l);
            self.row.reset(self.row_base);
        }
        let pos = seq_diff(self.row_base, s); // column index within the current row

        self.row.clip(payload.len() as u16, pt, ts, payload);
        self.row.collected += 1;

        if self.cfg.rows > 1 && pos >= 0 && (pos as usize) < self.cols.len() {
            let ci = pos as usize;
            let matrix = self.cfg.matrix_size() as i64;
            if seq_diff(self.cols[ci].base, s) >= matrix {
                let nb = seq_add(self.cols[ci].base, matrix);
                self.cols[ci].reset(nb);
            }
            self.cols[ci].clip(payload.len() as u16, pt, ts, payload);
            self.cols[ci].collected += 1;
            if self.cols[ci].collected >= self.cfg.rows {
                out.push(self.emit(ci, Direction::Column));
                let nb = seq_add(self.cols[ci].base, matrix);
                self.cols[ci].reset(nb);
            }
        }

        if self.row.collected >= self.cfg.cols {
            if !self.cfg.column_only {
                out.push(self.emit_row());
            }
            self.row_base = seq_add(self.row_base, l);
            self.row.reset(self.row_base);
        }
        out
    }

    /// Build a column FEC [`Packet`] from a completed column group: stride L over D
    /// members.
    fn emit(&self, ci: usize, dir: Direction) -> Packet {
        let g = &self.cols[ci];
        Packet {
            direction: dir,
            base: g.base,
            offset: self.cfg.cols as u16,
            na: self.cfg.rows as u16,
            length_recovery: g.length_clip,
            pt_recovery: g.pt_clip,
            ts_recovery: g.ts_clip,
            payload: Bytes::copy_from_slice(&g.payload_clip),
        }
    }

    /// Build a row FEC [`Packet`] from the completed row group: stride 1 over L
    /// members.
    fn emit_row(&self) -> Packet {
        let g = &self.row;
        Packet {
            direction: Direction::Row,
            base: g.base,
            offset: 1,
            na: self.cfg.cols as u16,
            length_recovery: g.length_clip,
            pt_recovery: g.pt_clip,
            ts_recovery: g.ts_clip,
            payload: Bytes::copy_from_slice(&g.payload_clip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Variant;
    use super::*;

    fn cfg(cols: usize, rows: usize, column_only: bool) -> Config {
        Config {
            cols,
            rows,
            column_only,
            variant: Variant::St20221,
        }
    }

    #[test]
    fn emits_column_then_row_with_expected_geometry() {
        // A 4x4 2-D matrix over the first matrix (isn..isn+15). Column FEC fires as
        // each column fills (every push at row D-1), the row FEC as each row fills.
        let mut enc = Encoder::new(cfg(4, 4, false), 200, 0);
        let mut cols = 0;
        let mut rows = 0;
        for s in 0..16u32 {
            for p in enc.push(s, s, 96, &[s as u8; 10]) {
                match p.direction {
                    Direction::Column => {
                        cols += 1;
                        assert_eq!(p.offset, 4, "column stride is L");
                        assert_eq!(p.na, 4, "column protects D members");
                    }
                    Direction::Row => {
                        rows += 1;
                        assert_eq!(p.offset, 1, "row stride is 1");
                        assert_eq!(p.na, 4, "row protects L members");
                    }
                }
            }
        }
        assert_eq!(cols, 4, "one column FEC per column");
        assert_eq!(rows, 4, "one row FEC per row");
    }

    #[test]
    fn column_only_suppresses_row_packets() {
        let mut enc = Encoder::new(cfg(4, 4, true), 200, 0);
        let mut cols = 0;
        for s in 0..16u32 {
            for p in enc.push(s, s, 96, &[s as u8; 10]) {
                assert_eq!(
                    p.direction,
                    Direction::Column,
                    "column-only emits no row FEC"
                );
                cols += 1;
            }
        }
        assert_eq!(cols, 4, "still one column FEC per column");
    }

    #[test]
    fn row_base_advances_across_the_seq_wrap() {
        // Start near the 32-bit wrap so the row base advance exercises wrap-aware
        // sequence arithmetic.
        let isn = u32::MAX - 5;
        let mut enc = Encoder::new(cfg(4, 4, true), 200, isn);
        let mut bases = Vec::new();
        for i in 0..16u32 {
            let s = seq_add(isn, i64::from(i));
            for p in enc.push(s, s, 96, &[s as u8; 10]) {
                bases.push(p.base);
            }
        }
        // Four columns, bases isn, isn+1, isn+2, isn+3 (wrapping past u32::MAX).
        assert_eq!(
            bases,
            vec![
                isn,
                isn.wrapping_add(1),
                isn.wrapping_add(2),
                isn.wrapping_add(3)
            ]
        );
    }
}
