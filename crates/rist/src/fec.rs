//! Host-side SMPTE ST 2022-1 / ST 2022-5 forward error correction wiring
//! (TR-06-2 §8.4, TR-06-3 §5.3.5). Ported from ristgo `internal/session/fec.go` +
//! the root `fec.go` public config.
//!
//! The deterministic matrix/XOR core lives in [`rist_core::fec`] and the wire header
//! in [`rist_codec::fec_header`]; this module is the host glue that drives them. It
//! owns the per-flow FEC encoder/decoder, feeds sent/received media through them, and
//! frames the emitted FEC packets onto the wire via the configured carriage:
//!
//! - **In-band (Advanced).** FEC is computed over the FULL wire datagram (after
//!   compression and PSK encryption, per TR-06-3 §5.3.5) so a recovery is the missing
//!   packet's exact bytes, re-injected through the normal decode path. Each FEC packet
//!   travels as an Advanced Type=Control message under the row/column control index;
//!   an over-MTU FEC control message is fragmented across consecutive control packets
//!   and reassembled by [`FecCtrlReassembler`].
//! - **Separate ports (Simple/Main).** FEC is standard ST 2022-1 over the inner RTP
//!   payload, carried as RTP packets on dedicated UDP ports (the media port + 2 for
//!   column, + 4 for row) — the carriage a conforming ST 2022-1 receiver
//!   (GStreamer/FFmpeg) interoperates with.
//!
//! Either way a recovered packet re-enters the one seq-indexed flow ring like an ARQ
//! retransmit — FEC is just another source of packets into the flow.

use bytes::Bytes;

use rist_codec::fec_header;
use rist_core::fec::{self, Recovered};
use rist_core::wire::FragRole;

use crate::config::Profile;
use crate::error::ConfigError;
use crate::reassembler::FragReassembler;

/// The SMPTE FEC wire format, re-exported from the deterministic core for use with
/// [`FecConfig`].
pub use rist_core::fec::Variant as FecVariant;

/// The RTP payload type stamped on the FEC's recovery field. ristrust does not use
/// it for delivery; a constant on both ends keeps the XOR consistent (libRIST 127).
pub(crate) const FEC_PT: u8 = 127;

/// Bounds the in-band control-message body carried in one FEC control packet so the
/// framed datagram stays within a typical MTU; a larger message (the Advanced
/// full-datagram FEC of a near-MTU payload) is fragmented across control packets.
pub(crate) const FEC_MAX_CTRL_BODY: usize = 1400;

/// The separate-port column FEC stream sits at the media port + 2 (the SMPTE 2022-1
/// convention).
pub(crate) const FEC_COLUMN_PORT_OFFSET: u16 = 2;

/// The separate-port row FEC stream sits at the media port + 4.
pub(crate) const FEC_ROW_PORT_OFFSET: u16 = 4;

/// The protected-payload buffer for the Simple/Main separate-port carriage, which
/// protects only the inner RTP payload (comfortably above the max media payload so
/// the XOR and the recovered-length check never truncate).
const FEC_RTP_PAYLOAD_SIZE: usize = 1500;

/// The protected-payload buffer for the Advanced in-band carriage, which protects
/// the full wire datagram (a near-MTU payload plus the Advanced header can exceed the
/// RTP payload size). Matches libRIST's `RIST_MAX_PACKET_SIZE` ceiling.
const FEC_ADV_PAYLOAD_SIZE: usize = 2048;

/// How SMPTE ST 2022-1 / ST 2022-5 FEC packets travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FecCarriage {
    /// Pick per profile: in-band for Advanced, separate-ports for Simple/Main.
    #[default]
    Default,
    /// Carry FEC as Advanced Type=Control messages on the data port (TR-06-3
    /// §5.3.5). Advanced profile only.
    InBand,
    /// Carry FEC as standard ST 2022-1 / ST 2022-5 RTP packets on dedicated UDP ports
    /// (media port + 2 column, + 4 row) — the interoperable GStreamer/FFmpeg carriage.
    SeparatePorts,
}

/// Forward-error-correction configuration: an L-columns by D-rows XOR matrix over the
/// media stream (TR-06-2 §8.4 / TR-06-3 §5.3.5).
///
/// By default it is 2-D (a column FEC packet per column and a row FEC packet per row),
/// recovering any single loss per row and per column and, by cascade, many 2-D loss
/// patterns. [`FecConfig::column_only`] keeps only the column FEC (1-D), roughly
/// halving the overhead. FEC complements ARQ: it recovers losses with no NACK round
/// trip, while ARQ remains the backstop for losses FEC cannot cover.
///
/// The matrix must satisfy the TR-06 limits for the chosen variant: for the default
/// ST 2022-1, L in `[1,20]` (column-only) or `[4,20]` (2-D), D in `[4,20]`, L·D ≤ 100;
/// for ST 2022-5, L in `[1,1020]` or `[4,1020]`, D in `[4,255]`, L·D ≤ 6000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecConfig {
    /// L: the matrix width (the spacing between a column's protected packets).
    pub columns: usize,
    /// D: the matrix height (the number of packets a column FEC packet protects).
    pub rows: usize,
    /// Suppress the row FEC, leaving 1-D column-only protection.
    pub column_only: bool,
    /// How the FEC packets are carried (the zero value picks a per-profile default).
    pub carriage: FecCarriage,
    /// The SMPTE FEC wire format (the zero value is ST 2022-1).
    pub variant: FecVariant,
}

impl Default for FecConfig {
    fn default() -> FecConfig {
        FecConfig {
            columns: 10,
            rows: 10,
            column_only: false,
            carriage: FecCarriage::Default,
            variant: FecVariant::St20221,
        }
    }
}

impl FecConfig {
    /// The effective carriage for `profile`, resolving [`FecCarriage::Default`]:
    /// in-band for Advanced, separate-ports for Simple/Main.
    pub(crate) fn resolved_separate_ports(&self, profile: Profile) -> bool {
        match self.carriage {
            FecCarriage::Default => profile != Profile::Advanced,
            FecCarriage::InBand => false,
            FecCarriage::SeparatePorts => true,
        }
    }

    /// Validates the matrix against the TR-06 bounds for the configured variant and
    /// the carriage against the profile (in-band is Advanced-only).
    ///
    /// # Errors
    /// Returns [`ConfigError::FecInvalid`] describing the first violation.
    pub(crate) fn validate(&self, profile: Profile) -> Result<(), ConfigError> {
        let invalid = |reason| Err(ConfigError::FecInvalid { reason });
        let (max_l, max_d, max_matrix) = match self.variant {
            FecVariant::St20221 => (20, 20, 100),
            FecVariant::St20225 => (1020, 255, 6000),
        };
        let min_l = if self.column_only { 1 } else { 4 };
        if self.columns < min_l || self.columns > max_l {
            return invalid("FEC columns (L) out of range for the variant");
        }
        if self.rows < 4 || self.rows > max_d {
            return invalid("FEC rows (D) out of range for the variant");
        }
        if self.columns * self.rows > max_matrix {
            return invalid("FEC matrix L*D exceeds the variant limit");
        }
        // In-band carriage rides the Advanced control plane; Simple/Main have no
        // in-band control messages, so they must use the separate-port carriage.
        if self.carriage == FecCarriage::InBand && profile != Profile::Advanced {
            return invalid("in-band FEC carriage requires the Advanced profile");
        }
        Ok(())
    }
}

/// The per-flow FEC engine: the encoder/decoder plus the carriage state (the
/// separate-port RTP sequence counters and the in-band control reassembler).
/// Loop-owned by a single driver task.
#[derive(Debug)]
pub(crate) struct FecState {
    core_cfg: fec::Config,
    variant: FecVariant,
    payload_size: usize,
    /// Built lazily from the first sent media's sequence (the matrix ISN).
    enc: Option<fec::Encoder>,
    /// Built lazily from the first received media's sequence (the window anchor).
    dec: Option<fec::Decoder>,
    /// Separate-port column / row FEC RTP sequence counters.
    col_seq: u16,
    row_seq: u16,
    /// Reassembles a fragmented in-band FEC control message.
    ctrl_reasm: FecCtrlReassembler,
    /// Media packets reconstructed by FEC (for stats / LQM, wired in 18f).
    recovered: u64,
}

impl FecState {
    /// Builds the FEC engine for `cfg` on `profile`. The protected-payload buffer is
    /// sized to the full wire datagram for the Advanced in-band carriage, or the inner
    /// RTP payload for the Simple/Main separate-port carriage.
    pub(crate) fn new(cfg: &FecConfig, profile: Profile) -> FecState {
        let payload_size = if profile == Profile::Advanced {
            FEC_ADV_PAYLOAD_SIZE
        } else {
            FEC_RTP_PAYLOAD_SIZE
        };
        FecState {
            core_cfg: fec::Config {
                cols: cfg.columns,
                rows: cfg.rows,
                column_only: cfg.column_only,
                variant: cfg.variant,
            },
            variant: cfg.variant,
            payload_size,
            enc: None,
            dec: None,
            col_seq: 0,
            row_seq: 0,
            ctrl_reasm: FecCtrlReassembler::default(),
            recovered: 0,
        }
    }

    /// The configured FEC wire format.
    pub(crate) fn variant(&self) -> FecVariant {
        self.variant
    }

    /// The number of media packets reconstructed by FEC so far.
    #[allow(dead_code)] // surfaced by stats / LQM in 18f
    pub(crate) fn recovered(&self) -> u64 {
        self.recovered
    }

    /// Clips one original (non-retransmit) media unit into the matrix and returns any
    /// FEC packets the completed groups produced. The caller passes the bytes the FEC
    /// protects (the full datagram for Advanced, the RTP payload for Simple/Main) with
    /// the matching `ts`/`pt` recovery inputs. Must be called in sequence order.
    pub(crate) fn clip(&mut self, seq: u32, ts: u32, pt: u8, payload: &[u8]) -> Vec<fec::Packet> {
        let payload_size = self.payload_size;
        let core_cfg = self.core_cfg;
        self.enc
            .get_or_insert_with(|| fec::Encoder::new(core_cfg, payload_size, seq))
            .push(seq, ts, pt, payload)
    }

    /// Feeds one received media unit into the decoder and returns any packets it
    /// allowed FEC to recover. The decoder is created lazily from the first received
    /// sequence (it self-corrects from there).
    pub(crate) fn recv_media(
        &mut self,
        seq: u32,
        ts: u32,
        pt: u8,
        ssrc: u32,
        payload: Bytes,
    ) -> Vec<Recovered> {
        let payload_size = self.payload_size;
        let core_cfg = self.core_cfg;
        let rec = self
            .dec
            .get_or_insert_with(|| fec::Decoder::new(core_cfg, payload_size, seq))
            .push_media(seq, ts, pt, ssrc, payload);
        self.recovered += rec.len() as u64;
        rec
    }

    /// Decodes one received FEC packet (the body after any carriage framing: the FEC
    /// header + recovery payload) and returns any packets it allowed FEC to recover.
    /// A no-op until media has been seen (the decoder needs an anchor).
    pub(crate) fn recv_fec(&mut self, body: &[u8]) -> Vec<Recovered> {
        let Some(dec) = self.dec.as_mut() else {
            return Vec::new(); // no media seen yet; cannot place the FEC group
        };
        let Ok(pkt) = fec_header::decode(body, self.variant) else {
            return Vec::new();
        };
        let rec = dec.push_fec(&pkt);
        self.recovered += rec.len() as u64;
        rec
    }

    /// Folds one fragmented in-band FEC control packet into the reassembler, returning
    /// the whole control message on the closing fragment.
    pub(crate) fn ctrl_reasm_push(
        &mut self,
        seq: u32,
        role: FragRole,
        payload: Bytes,
    ) -> Option<Bytes> {
        self.ctrl_reasm.push(seq, role, payload)
    }

    /// The next column FEC RTP sequence number (separate-port carriage), post-increment.
    pub(crate) fn next_col_seq(&mut self) -> u16 {
        let s = self.col_seq;
        self.col_seq = self.col_seq.wrapping_add(1);
        s
    }

    /// The next row FEC RTP sequence number (separate-port carriage), post-increment.
    pub(crate) fn next_row_seq(&mut self) -> u16 {
        let s = self.row_seq;
        self.row_seq = self.row_seq.wrapping_add(1);
        s
    }
}

/// Reassembles a fragmented in-band FEC control message (the only thing the Advanced
/// profile fragments besides media). Unlike media fragments, which the flow core
/// delivers with a discontinuity flag, FEC control fragments arrive raw, before the
/// flow, so this derives the discontinuity itself from a gap in the Advanced control
/// sequence number: the fragments of one FEC message are sent back-to-back, so
/// consecutive fragments carry consecutive sequence numbers, and a gap means a
/// fragment was lost — aborting the partial run so a dropped middle/last fragment
/// cannot fold two FEC messages together (TR-06-3 §5.3.5 → §5.2.3). Ported from ristgo
/// `internal/session/reassembler.go` `fecCtrlReassembler`.
#[derive(Debug, Default)]
pub(crate) struct FecCtrlReassembler {
    r: FragReassembler,
    last_seq: u32,
    have_seq: bool,
}

impl FecCtrlReassembler {
    /// Folds one FEC control fragment (carrying the Advanced control sequence `seq`
    /// and its F/L `role`) into the run, returning the whole FEC message on the
    /// closing fragment.
    pub(crate) fn push(&mut self, seq: u32, role: FragRole, payload: Bytes) -> Option<Bytes> {
        let discontinuity = self.have_seq && seq != self.last_seq.wrapping_add(1);
        self.last_seq = seq;
        self.have_seq = true;
        self.r.push(role, payload, discontinuity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_matrix_bounds_per_variant() {
        // ST 2022-1 2-D: L,D in [4,20], L*D <= 100.
        let ok = FecConfig {
            columns: 10,
            rows: 10,
            column_only: false,
            carriage: FecCarriage::SeparatePorts,
            variant: FecVariant::St20221,
        };
        assert!(ok.validate(Profile::Simple).is_ok());
        // L below the 2-D minimum of 4.
        let bad_l = FecConfig { columns: 3, ..ok };
        assert!(bad_l.validate(Profile::Simple).is_err());
        // Column-only relaxes L's minimum to 1.
        let col1 = FecConfig {
            columns: 1,
            column_only: true,
            ..ok
        };
        assert!(col1.validate(Profile::Simple).is_ok());
        // L*D over the ST 2022-1 limit of 100.
        let big = FecConfig {
            columns: 20,
            rows: 20,
            ..ok
        };
        assert!(big.validate(Profile::Simple).is_err());
        // The same matrix is fine under ST 2022-5 (limit 6000).
        let big5 = FecConfig {
            variant: FecVariant::St20225,
            ..big
        };
        assert!(big5.validate(Profile::Simple).is_ok());
    }

    #[test]
    fn validate_in_band_requires_advanced() {
        let cfg = FecConfig {
            carriage: FecCarriage::InBand,
            ..FecConfig::default()
        };
        assert!(cfg.validate(Profile::Simple).is_err());
        assert!(cfg.validate(Profile::Main).is_err());
        assert!(cfg.validate(Profile::Advanced).is_ok());
    }

    #[test]
    fn carriage_resolves_per_profile() {
        let def = FecConfig::default();
        assert!(def.resolved_separate_ports(Profile::Simple));
        assert!(def.resolved_separate_ports(Profile::Main));
        assert!(!def.resolved_separate_ports(Profile::Advanced)); // in-band
        let forced = FecConfig {
            carriage: FecCarriage::SeparatePorts,
            ..def
        };
        assert!(forced.resolved_separate_ports(Profile::Advanced));
    }

    #[test]
    fn ctrl_reassembler_derives_discontinuity_from_seq_gap() {
        let mut r = FecCtrlReassembler::default();
        // Two back-to-back fragments (seq 10, 11) reassemble.
        assert_eq!(r.push(10, FragRole::First, Bytes::from_static(b"ab")), None);
        assert_eq!(
            r.push(11, FragRole::Last, Bytes::from_static(b"cd")),
            Some(Bytes::from_static(b"abcd"))
        );
        // A seq gap before the closing fragment aborts the run (lost middle).
        assert_eq!(r.push(20, FragRole::First, Bytes::from_static(b"ef")), None);
        assert_eq!(r.push(22, FragRole::Last, Bytes::from_static(b"gh")), None);
    }

    #[test]
    fn round_trips_a_single_loss_in_band_style() {
        // A column-only matrix over the FULL "datagram" bytes (Advanced style): clip
        // each sent unit, drop one received unit, feed the rest + the column FEC, and
        // confirm the dropped unit is recovered byte-exact.
        let cfg = FecConfig {
            columns: 4,
            rows: 4,
            column_only: true,
            carriage: FecCarriage::InBand,
            variant: FecVariant::St20221,
        };
        let mut send = FecState::new(&cfg, Profile::Advanced);
        let mut recv = FecState::new(&cfg, Profile::Advanced);
        let datagram = |s: u32| -> Vec<u8> {
            let b = s.to_le_bytes()[0];
            (0..40u8).map(|i| b ^ i).collect()
        };

        let mut fecs = Vec::new();
        for s in 0..16u32 {
            for fp in send.clip(s, 0, 0, &datagram(s)) {
                // Carriage round-trip through the 18b header codec.
                let body = fec_header::encode(&fp, cfg.variant);
                fecs.push(body);
            }
        }
        // Feed all media except seq 5, then the FEC bodies.
        let mut recovered = Vec::new();
        for s in 0..16u32 {
            if s == 5 {
                continue;
            }
            recovered.extend(recv.recv_media(s, 0, 0, 0, Bytes::from(datagram(s))));
        }
        for body in &fecs {
            recovered.extend(recv.recv_fec(body));
        }
        assert_eq!(recovered.len(), 1, "exactly the one dropped unit recovered");
        assert_eq!(recovered[0].seq, 5);
        assert_eq!(recovered[0].payload.as_ref(), datagram(5).as_slice());
        assert_eq!(recv.recovered(), 1);
    }
}
