//! The `rist://` URL parser.
//!
//! [`parse_url`] turns a `rist://host:port?query` URL into a dial/listen address
//! (`host:port`) and a [`Config`] with the query parameters folded in. The
//! accepted parameter names match libRIST's (`parse_url_options`) so the same URL
//! works against ffmpeg/libRIST. A bare `host:port` (no scheme) is returned
//! unchanged. An unknown parameter is rejected (a typo fails loudly rather than
//! silently running with a default), matching libRIST and ristgo; the
//! valid-but-unimplemented libRIST keys are accept-and-ignored.
//!
//! To keep the dependency footprint minimal (the project's posture), the simple
//! `rist://` structure is hand-parsed rather than pulling in a general URL crate;
//! query values are percent-decoded.

use std::collections::HashMap;
use std::time::Duration;

use rist_codec::crypto::AesKeyBits;

use crate::config::{Config, Profile};
use crate::error::Error;
use crate::split::{MergeMode, SplitMode};
use crate::{CongestionMode, TimingMode};

/// A millisecond-valued query parameter ceiling: one week, far above any sane
/// RIST timing value yet far below where `Duration::from_millis` could approach
/// trouble. Matches ristgo's `maxURLMillis`.
const MAX_URL_MILLIS: u64 = 7 * 24 * 3600 * 1000;

/// Parses `raw` into a dial/listen address (`host:port`) and a [`Config`] with
/// the URL's query parameters applied over `base`. Callers typically pass
/// [`Config::default`](crate::config::Config::default) as `base`.
///
/// Accepted parameters (all durations in milliseconds): `buffer`, `buffer-min`,
/// `buffer-max`, `rtt`, `rtt-min`, `rtt-max`, `reorder-buffer`,
/// `session-timeout`, `keepalive` / `keepalive-interval`; `rtt-multiplier`,
/// `bandwidth` (kbps), `min-retries`, `max-retries`, `aes-type` (128/192/256),
/// `key-rotation`, `weight`, `virt-src-port`, `virt-dst-port`, `profile`,
/// `cname`, `secret`, `username`, `password`, `compression` (0/1), and the
/// multicast `miface`/`ttl`/`source`. `buffer` sets both buffer bounds and `rtt`
/// sets both RTT bounds; an explicit `-min`/`-max` always wins regardless of URL
/// order (a deliberate simplification of libRIST's order-dependent parsing).
///
/// # Errors
/// Returns [`Error::Url`] for an unsupported scheme, a missing port, or a query
/// parameter that is not a valid integer or is out of range. Semantic range
/// validation (e.g. the buffer 50 ms…30 s bound) is left to
/// [`Config::validate`](crate::config::Config::validate), which the constructors
/// call.
pub fn parse_url(raw: &str, base: Config) -> Result<(String, Config), Error> {
    let Some((scheme, rest)) = raw.split_once("://") else {
        // A bare host:port (no scheme) is returned unchanged.
        return Ok((raw.to_string(), base));
    };
    if scheme != "rist" {
        return Err(Error::Url(format!(
            "unsupported scheme {scheme:?} (want rist)"
        )));
    }

    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    // Strip any path: rist:// URLs carry no path, but tolerate a trailing one.
    let authority = authority.split('/').next().unwrap_or(authority);
    let addr = parse_authority(authority)?;

    let mut cfg = base;
    apply_query(&mut cfg, &parse_query(query))?;
    Ok((addr, cfg))
}

/// Splits an `host:port` (or `[v6]:port`) authority and returns it re-joined,
/// requiring a non-empty port. IPv6 hosts are re-bracketed.
fn parse_authority(authority: &str) -> Result<String, Error> {
    if let Some(after) = authority.strip_prefix('[') {
        // IPv6: [host]:port.
        let Some((host, tail)) = after.split_once(']') else {
            return Err(Error::Url("malformed IPv6 host (missing ])".into()));
        };
        let port = tail.strip_prefix(':').unwrap_or("");
        if port.is_empty() {
            return Err(Error::Url("rist url must include a port".into()));
        }
        return Ok(format!("[{host}]:{port}"));
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(Error::Url("rist url must include a port".into()));
    };
    if port.is_empty() || host.is_empty() {
        return Err(Error::Url("rist url must include a host and a port".into()));
    }
    Ok(format!("{host}:{port}"))
}

/// Parses a query string into a key→value map (first value wins on duplicates,
/// matching `url.Values.Get`), percent-decoding each value.
fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        map.entry(percent_decode(key))
            .or_insert_with(|| percent_decode(value));
    }
    map
}

/// Decodes `%XX` escapes and `+` (form-encoded space) in a query component.
/// Invalid escapes are passed through literally.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let byte = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                if let Some(byte) = byte {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Folds the parsed query parameters into `cfg`, in a fixed order so the explicit
/// `-min`/`-max` keys win over `buffer`/`rtt` regardless of URL order.
fn apply_query(cfg: &mut Config, q: &HashMap<String, String>) -> Result<(), Error> {
    reject_unknown_params(q)?;
    let millis = |key: &str| -> Result<Option<Duration>, Error> {
        match q.get(key) {
            None => Ok(None),
            Some(v) => {
                let n: i64 = v
                    .parse()
                    .map_err(|_| Error::Url(format!("{key}={v:?} is not an integer")))?;
                let out_of_range =
                    || Error::Url(format!("{key}={v:?} out of range (0..{MAX_URL_MILLIS} ms)"));
                let n = u64::try_from(n).map_err(|_| out_of_range())?;
                if n > MAX_URL_MILLIS {
                    return Err(out_of_range());
                }
                Ok(Some(Duration::from_millis(n)))
            }
        }
    };
    let int = |key: &str| -> Result<Option<i64>, Error> {
        match q.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse::<i64>()
                .map(Some)
                .map_err(|_| Error::Url(format!("{key}={v:?} is not an integer"))),
        }
    };

    // `buffer` / `rtt` set both bounds first; the explicit -min/-max keys below
    // then override them.
    if let Some(d) = millis("buffer")? {
        cfg.buffer_min = d;
        cfg.buffer_max = d;
    }
    if let Some(d) = millis("rtt")? {
        cfg.rtt_min = d;
        cfg.rtt_max = d;
    }
    for (key, dst) in [
        ("buffer-min", &mut cfg.buffer_min),
        ("buffer-max", &mut cfg.buffer_max),
        ("rtt-min", &mut cfg.rtt_min),
        ("rtt-max", &mut cfg.rtt_max),
        ("reorder-buffer", &mut cfg.reorder_buffer),
        ("session-timeout", &mut cfg.session_timeout),
    ] {
        if let Some(d) = millis(key)? {
            *dst = d;
        }
    }
    // `keepalive` (ristgo alias) then `keepalive-interval` (libRIST canonical):
    // the canonical key is applied last so it wins on conflict.
    if let Some(d) = millis("keepalive")? {
        cfg.keepalive_interval = d;
    }
    if let Some(d) = millis("keepalive-interval")? {
        cfg.keepalive_interval = d;
    }

    if let Some(n) = int("rtt-multiplier")? {
        cfg.rtt_multiplier = clamp_u32("rtt-multiplier", n)?;
    }
    if let Some(n) = int("bandwidth")? {
        cfg.max_bitrate_kbps = clamp_u32("bandwidth", n)?;
    }
    if let Some(n) = int("min-retries")? {
        cfg.min_retries = clamp_u32("min-retries", n)?;
    }
    if let Some(n) = int("max-retries")? {
        cfg.max_retries = clamp_u32("max-retries", n)?;
    }
    for (key, dst) in [
        ("virt-src-port", &mut cfg.virt_src_port),
        ("virt-dst-port", &mut cfg.virt_dst_port),
        ("local-port", &mut cfg.local_port),
    ] {
        if let Some(v) = q.get(key) {
            let n: i64 = v
                .parse()
                .map_err(|_| Error::Url(format!("{key}={v:?} is not a valid port")))?;
            *dst = u16::try_from(n)
                .map_err(|_| Error::Url(format!("{key}={v:?} is not a valid port")))?;
        }
    }
    apply_enum_params(cfg, q)?;
    apply_string_and_feature_params(cfg, q)?;
    Ok(())
}

/// Folds the string- and feature-valued query parameters (`cname`, `secret`, the
/// multicast `miface`/`ttl`/`source`, the EAP-SRP `username`/`password`,
/// `compression`, `key-rotation`, `weight`) into `cfg`. Split out of [`apply_query`]
/// to keep that function under the line cap.
fn apply_string_and_feature_params(
    cfg: &mut Config,
    q: &HashMap<String, String>,
) -> Result<(), Error> {
    let int = |key: &str| -> Result<Option<i64>, Error> {
        match q.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse::<i64>()
                .map(Some)
                .map_err(|_| Error::Url(format!("{key}={v:?} is not an integer"))),
        }
    };
    if let Some(v) = q.get("cname") {
        cfg.cname = Some(v.clone());
    }
    if let Some(v) = q.get("secret") {
        cfg.secret = Some(v.clone());
    }
    // Multicast options (libRIST: `miface` interface, `ttl` hop limit, `source`
    // SSM source filter).
    if let Some(v) = q.get("miface") {
        cfg.interface = Some(v.clone());
    }
    if let Some(n) = int("ttl")? {
        cfg.multicast_ttl =
            u8::try_from(n).map_err(|_| Error::Url(format!("ttl={n} must be 0..=255")))?;
    }
    if let Some(v) = q.get("source") {
        cfg.multicast_source = Some(v.clone());
    }
    // EAP-SRP credentials (Main profile): `username`/`password` enable
    // authentication together, mirroring `with_srp_credentials`.
    if let Some(v) = q.get("username") {
        cfg.srp_username = Some(v.clone());
    }
    if let Some(v) = q.get("password") {
        cfg.srp_password = Some(v.clone());
    }
    // `compression` (libRIST: enable LZ4, Advanced only) is `0`/`1`; any non-zero
    // value enables it. `Config::validate` rejects it off the Advanced profile.
    if let Some(n) = int("compression")? {
        cfg.compression = n != 0;
    }
    // `key-rotation`: packets per PSK nonce before rotating (Main/Advanced).
    if let Some(n) = int("key-rotation")? {
        cfg.key_rotation = clamp_u32("key-rotation", n)?;
    }
    // `srp-compat`: legacy (pre-0.2.16) SRP mode; any non-zero value enables it.
    if let Some(n) = int("srp-compat")? {
        cfg.srp_compat = n != 0;
    }
    // `weight`: the uniform 2022-7 bonding load-share weight (0 = full duplication).
    if let Some(n) = int("weight")? {
        cfg.weight = clamp_u32("weight", n)?;
    }
    Ok(())
}

/// Folds the enum-valued query parameters into `cfg`: `aes-type`, `profile`,
/// `congestion-control`, `timing-mode`, and `return-bandwidth` on libRIST's numbering,
/// plus the string-valued `split` (off|auto|half) and `merge` (off|pairs|auto) bonding
/// modes (libRIST spells these as words, not numbers). Split out of [`apply_query`] to
/// keep that function under the line cap.
fn apply_enum_params(cfg: &mut Config, q: &HashMap<String, String>) -> Result<(), Error> {
    let int = |key: &str| -> Result<Option<i64>, Error> {
        match q.get(key) {
            None => Ok(None),
            Some(v) => v
                .parse::<i64>()
                .map(Some)
                .map_err(|_| Error::Url(format!("{key}={v:?} is not an integer"))),
        }
    };
    if let Some(n) = int("aes-type")? {
        cfg.aes_key_bits = Some(match n {
            128 => AesKeyBits::Aes128,
            192 => AesKeyBits::Aes192,
            256 => AesKeyBits::Aes256,
            other => {
                return Err(Error::Url(format!(
                    "aes-type={other} must be 128, 192, or 256"
                )));
            }
        });
    }
    if let Some(n) = int("profile")? {
        cfg.profile = match n {
            0 => Profile::Simple,
            1 => Profile::Main,
            2 => Profile::Advanced,
            other => return Err(Error::Url(format!("profile={other} must be 0, 1, or 2"))),
        };
    }
    // libRIST `?recovery-depth=`: the Advanced recovery-ring exponent (0..=16). Range
    // is enforced by Config::validate; here we only reject a non-integer / negative.
    if let Some(n) = int("recovery-depth")? {
        let depth = u8::try_from(n)
            .ok()
            .filter(|d| *d <= crate::RECOVERY_DEPTH_MAX);
        match depth {
            Some(d) => cfg.recovery_depth = Some(d),
            None => {
                return Err(Error::Url(format!(
                    "recovery-depth={n} must be 0..={}",
                    crate::RECOVERY_DEPTH_MAX
                )));
            }
        }
    }
    // libRIST's numbering: 0=off, 1=normal, 2=aggressive (matches `congestion_control`
    // in `parse_url_options`).
    if let Some(n) = int("congestion-control")? {
        cfg.congestion_control = match n {
            0 => CongestionMode::Off,
            1 => CongestionMode::Normal,
            2 => CongestionMode::Aggressive,
            other => {
                return Err(Error::Url(format!(
                    "congestion-control={other} must be 0 (off), 1 (normal), or 2 (aggressive)"
                )));
            }
        };
    }
    // `return-bandwidth`: receiver NACK-channel cap in kbps (0 = unlimited).
    if let Some(n) = int("return-bandwidth")? {
        cfg.return_bandwidth = clamp_u32("return-bandwidth", n)?;
    }
    // `timing-mode` on libRIST's numbering: 0=source, 1=arrival, 2=rtc (mapped to
    // arrival, as ristgo does — ristrust has no separate RTC playout clock).
    if let Some(n) = int("timing-mode")? {
        cfg.timing_mode = match n {
            0 => TimingMode::Source,
            1 | 2 => TimingMode::Arrival,
            other => {
                return Err(Error::Url(format!(
                    "timing-mode={other} must be 0 (source), 1 (arrival), or 2 (rtc)"
                )));
            }
        };
    }
    // `split` (sender) — libRIST's string values: off | auto (alias `ts`) | half.
    if let Some(v) = q.get("split") {
        cfg.split_mode = match v.as_str() {
            "off" => SplitMode::Off,
            "auto" | "ts" => SplitMode::Auto,
            "half" => SplitMode::Half,
            other => {
                return Err(Error::Url(format!(
                    "split={other:?} must be off, auto, or half"
                )));
            }
        };
    }
    // `merge` (receiver) — libRIST's string values: off | pairs | auto.
    if let Some(v) = q.get("merge") {
        cfg.merge_mode = match v.as_str() {
            "off" => MergeMode::Off,
            "pairs" => MergeMode::Pairs,
            "auto" => MergeMode::Auto,
            other => {
                return Err(Error::Url(format!(
                    "merge={other:?} must be off, pairs, or auto"
                )));
            }
        };
    }
    Ok(())
}

/// The set of `rist://` query parameters [`parse_url`] accepts. It is every key
/// the `apply_*` helpers act on PLUS the libRIST parameters ristrust does not
/// implement but tolerates (accept-and-ignore) so a URL authored for libRIST is
/// not rejected over a valid-but-unsupported option. Any key absent here is treated
/// as a typo and rejected (see [`reject_unknown_params`]), matching libRIST and
/// ristgo.
const RECOGNIZED_URL_PARAMS: &[&str] = &[
    "buffer",
    "buffer-min",
    "buffer-max",
    "rtt",
    "rtt-min",
    "rtt-max",
    "rtt-multiplier",
    "reorder-buffer",
    "session-timeout",
    "keepalive",
    "keepalive-interval",
    "bandwidth",
    "return-bandwidth",
    "weight",
    "aes-type",
    "key-rotation",
    "min-retries",
    "max-retries",
    "recovery-depth",
    "virt-src-port",
    "virt-dst-port",
    "local-port",
    "profile",
    "cname",
    "secret",
    "username",
    "password",
    "compression",
    "miface",
    "ttl",
    "source",
    "congestion-control",
    "timing-mode",
    "split",
    "merge",
    // `srp-compat` (legacy pre-0.2.16 SRP mode) IS parsed and honored — see
    // `apply_string_and_feature_params` and `with_srp_compat`.
    "srp-compat",
    // Accepted-and-ignored for libRIST URL portability (recognized but not yet acted
    // on): `recovery-priority` per-peer NACK priority (per-path, set via the
    // `listen_bonded_priority` API rather than a per-session URL value) and
    // `reflector` one-to-many fan-out. Rejecting a valid libRIST URL over these is the
    // worse failure for portability.
    "recovery-priority",
    "reflector",
    "local-port",
];

/// Rejects any query parameter not in [`RECOGNIZED_URL_PARAMS`], so a typo'd key
/// fails loudly rather than silently running with a default (matching libRIST and
/// ristgo's `recognizedURLParams` gate).
fn reject_unknown_params(q: &HashMap<String, String>) -> Result<(), Error> {
    for key in q.keys() {
        if !RECOGNIZED_URL_PARAMS.contains(&key.as_str()) {
            return Err(Error::Url(format!("unknown parameter {key:?}")));
        }
    }
    Ok(())
}

/// Narrows a parsed integer to `u32`, erroring on a negative or overflowing value.
fn clamp_u32(key: &str, n: i64) -> Result<u32, Error> {
    u32::try_from(n).map_err(|_| Error::Url(format!("{key}={n} out of range")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn plain_addr_passes_through_unchanged() {
        let (addr, cfg) = parse_url("127.0.0.1:5000", Config::default()).unwrap();
        assert_eq!(addr, "127.0.0.1:5000");
        assert_eq!(cfg.buffer_min, Config::default().buffer_min);
    }

    #[test]
    fn params_fold_into_config() {
        let raw = "rist://host.example:5000?buffer=1200&rtt-min=20&rtt-max=80&reorder-buffer=10\
                   &cname=cam1&weight=3&profile=0&session-timeout=3000&keepalive=250&bandwidth=8000";
        let (addr, cfg) = parse_url(raw, Config::default()).unwrap();
        assert_eq!(addr, "host.example:5000");
        assert_eq!(cfg.buffer_min, ms(1200));
        assert_eq!(cfg.buffer_max, ms(1200));
        assert_eq!(cfg.rtt_min, ms(20));
        assert_eq!(cfg.rtt_max, ms(80));
        assert_eq!(cfg.reorder_buffer, ms(10));
        assert_eq!(cfg.cname.as_deref(), Some("cam1"));
        assert_eq!(cfg.profile, Profile::Simple);
        assert_eq!(cfg.session_timeout, ms(3000));
        assert_eq!(cfg.keepalive_interval, ms(250));
        assert_eq!(cfg.max_bitrate_kbps, 8000);
        cfg.validate().expect("parsed config must validate");
    }

    #[test]
    fn multicast_params_fold_into_config() {
        let (addr, cfg) = parse_url(
            "rist://239.1.2.3:5000?miface=lo0&ttl=16&source=10.0.0.7",
            Config::default(),
        )
        .unwrap();
        assert_eq!(addr, "239.1.2.3:5000");
        assert_eq!(cfg.interface.as_deref(), Some("lo0"));
        assert_eq!(cfg.multicast_ttl, 16);
        assert_eq!(cfg.multicast_source.as_deref(), Some("10.0.0.7"));
        // An out-of-range TTL is rejected, not silently truncated.
        assert!(parse_url("rist://239.1.2.3:5000?ttl=300", Config::default()).is_err());
    }

    #[test]
    fn congestion_control_uses_librist_numbering() {
        for (n, want) in [
            (0, CongestionMode::Off),
            (1, CongestionMode::Normal),
            (2, CongestionMode::Aggressive),
        ] {
            let raw = format!("rist://h:5000?congestion-control={n}");
            let (_, cfg) = parse_url(&raw, Config::default()).unwrap();
            assert_eq!(cfg.congestion_control, want, "congestion-control={n}");
        }
        // Out-of-range value is rejected, not silently clamped.
        assert!(parse_url("rist://h:5000?congestion-control=3", Config::default()).is_err());
    }

    #[test]
    fn timing_mode_and_return_bandwidth_fold_in() {
        for (n, want) in [
            (0, TimingMode::Source),
            (1, TimingMode::Arrival),
            (2, TimingMode::Arrival), // rtc maps to arrival
        ] {
            let raw = format!("rist://h:5000?timing-mode={n}");
            let (_, cfg) = parse_url(&raw, Config::default()).unwrap();
            assert_eq!(cfg.timing_mode, want, "timing-mode={n}");
        }
        assert!(parse_url("rist://h:5000?timing-mode=9", Config::default()).is_err());

        let (_, cfg) = parse_url("rist://h:5000?return-bandwidth=2000", Config::default()).unwrap();
        assert_eq!(cfg.return_bandwidth, 2000);
    }

    #[test]
    fn local_port_folds_in() {
        let (_, cfg) = parse_url("rist://h:5000?local-port=7000", Config::default()).unwrap();
        assert_eq!(cfg.local_port, 7000);
        // Default is ephemeral (0).
        assert_eq!(Config::default().local_port, 0);
        // Out-of-range (not a u16) is rejected.
        assert!(parse_url("rist://h:5000?local-port=99999", Config::default()).is_err());
    }

    #[test]
    fn split_and_merge_use_librist_string_values() {
        for (s, want) in [
            ("off", SplitMode::Off),
            ("auto", SplitMode::Auto),
            ("ts", SplitMode::Auto), // libRIST alias for auto
            ("half", SplitMode::Half),
        ] {
            let raw = format!("rist://h:5000?split={s}");
            let (_, cfg) = parse_url(&raw, Config::default()).unwrap();
            assert_eq!(cfg.split_mode, want, "split={s}");
        }
        for (s, want) in [
            ("off", MergeMode::Off),
            ("pairs", MergeMode::Pairs),
            ("auto", MergeMode::Auto),
        ] {
            let raw = format!("rist://h:5000?merge={s}");
            let (_, cfg) = parse_url(&raw, Config::default()).unwrap();
            assert_eq!(cfg.merge_mode, want, "merge={s}");
        }
        // Unknown mode strings are rejected, not silently ignored.
        assert!(parse_url("rist://h:5000?split=sometimes", Config::default()).is_err());
        assert!(parse_url("rist://h:5000?merge=both", Config::default()).is_err());
    }

    #[test]
    fn unknown_param_is_rejected_but_libwrist_extras_are_tolerated() {
        // A typo'd key fails loudly rather than silently defaulting.
        assert!(parse_url("rist://h:5000?bufer=1000", Config::default()).is_err());
        assert!(parse_url("rist://h:5000?timing_mode=1", Config::default()).is_err());
        // Valid-but-unimplemented libRIST keys are accepted (ignored) for URL portability.
        for raw in [
            "rist://h:5000?reflector=1",
            "rist://h:5000?local-port=7000",
            "rist://h:5000?recovery-priority=3",
            "rist://h:5000?srp-compat=1",
        ] {
            assert!(
                parse_url(raw, Config::default()).is_ok(),
                "{raw} must parse"
            );
        }
    }

    #[test]
    fn explicit_min_max_override_buffer_regardless_of_order() {
        for raw in [
            "rist://h:5000?buffer=1000&buffer-min=200&buffer-max=400",
            "rist://h:5000?buffer-min=200&buffer-max=400&buffer=1000",
        ] {
            let (_, cfg) = parse_url(raw, Config::default()).unwrap();
            assert_eq!(
                (cfg.buffer_min, cfg.buffer_max),
                (ms(200), ms(400)),
                "{raw}"
            );
        }
    }

    #[test]
    fn keepalive_canonical_and_retries_and_rtt() {
        let (_, cfg) = parse_url(
            "rist://h:5000?keepalive-interval=300&min-retries=8&max-retries=40&rtt=33&virt-src-port=1971",
            Config::default(),
        )
        .unwrap();
        assert_eq!(cfg.keepalive_interval, ms(300));
        assert_eq!((cfg.min_retries, cfg.max_retries), (8, 40));
        assert_eq!((cfg.rtt_min, cfg.rtt_max), (ms(33), ms(33)));
        assert_eq!(cfg.virt_src_port, 1971);
    }

    #[test]
    fn auth_compression_and_key_rotation_fold_in() {
        // Advanced so `compression` and the SRP credentials all validate.
        let (_, cfg) = parse_url(
            "rist://h:5000?profile=2&username=alice&password=s%40cret&compression=1&key-rotation=1000",
            Config::default(),
        )
        .unwrap();
        assert_eq!(cfg.srp_username.as_deref(), Some("alice"));
        assert_eq!(cfg.srp_password.as_deref(), Some("s@cret")); // percent-decoded
        assert!(cfg.compression);
        assert_eq!(cfg.key_rotation, 1000);
        cfg.validate().expect("parsed config must validate");

        // compression=0 disables it (and then it is valid on any profile).
        let (_, off) = parse_url("rist://h:5000?compression=0", Config::default()).unwrap();
        assert!(!off.compression);
    }

    #[test]
    fn aes_type_and_secret_percent_decoded() {
        let (_, cfg) = parse_url(
            "rist://h:5000?profile=1&secret=p%40ss&aes-type=128",
            Config::default(),
        )
        .unwrap();
        assert_eq!(cfg.profile, Profile::Main);
        assert_eq!(cfg.secret.as_deref(), Some("p@ss")); // percent-decoded
        assert_eq!(cfg.aes_key_bits, Some(AesKeyBits::Aes128));
    }

    #[test]
    fn aes_type_192_advanced() {
        // 192-bit AES is accepted (Advanced profile signals it via key_size_bits).
        let (_, cfg) = parse_url(
            "rist://h:5000?profile=2&secret=k&aes-type=192",
            Config::default(),
        )
        .unwrap();
        assert_eq!(cfg.aes_key_bits, Some(AesKeyBits::Aes192));
        assert!(cfg.validate().is_ok(), "192 is valid on Advanced");
        // …but rejected on Main, where the H bit cannot signal it.
        let (_, main) = parse_url(
            "rist://h:5000?profile=1&secret=k&aes-type=192",
            Config::default(),
        )
        .unwrap();
        assert!(main.validate().is_err(), "192 must be rejected on Main");
    }

    #[test]
    fn ipv6_authority() {
        let (addr, _) = parse_url("rist://[::1]:5000?buffer=500", Config::default()).unwrap();
        assert_eq!(addr, "[::1]:5000");
    }

    #[test]
    fn recovery_depth_folds_in() {
        // libRIST ?recovery-depth= (Advanced ring exponent) parses into recovery_depth.
        let (_, cfg) = parse_url(
            "rist://h:5000?profile=2&recovery-depth=4",
            Config::default(),
        )
        .unwrap();
        assert_eq!(cfg.profile, Profile::Advanced);
        assert_eq!(cfg.recovery_depth, Some(4));
        cfg.validate()
            .expect("recovery-depth=4 on Advanced validates");

        // Out-of-range and non-integer are rejected, not clamped.
        assert!(parse_url("rist://h:5000?recovery-depth=17", Config::default()).is_err());
        assert!(parse_url("rist://h:5000?recovery-depth=deep", Config::default()).is_err());
    }

    #[test]
    fn malformed_urls_error() {
        let cases = [
            "srt://h:5000",                      // bad scheme
            "rist://h",                          // no port
            "rist://h:5000?buffer=abc",          // non-integer buffer
            "rist://h:5000?rtt-min=fast",        // non-integer rtt-min
            "rist://h:5000?virt-dst-port=99999", // port out of range
            "rist://h:5000?aes-type=200",        // unsupported AES size (not 128/192/256)
            "rist://h:5000?profile=9",           // unknown profile
            "rist://h:5000?recovery-depth=17",   // recovery-depth out of range
        ];
        for raw in cases {
            assert!(
                matches!(parse_url(raw, Config::default()), Err(Error::Url(_))),
                "{raw} should be an Error::Url"
            );
        }
    }
}
