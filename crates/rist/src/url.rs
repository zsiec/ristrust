//! The `rist://` URL parser.
//!
//! [`parse_url`] turns a `rist://host:port?query` URL into a dial/listen address
//! (`host:port`) and a [`Config`] with the query parameters folded in. The
//! accepted parameter names match libRIST's (`parse_url_options`) so the same URL
//! works against ffmpeg/libRIST. A bare `host:port` (no scheme) is returned
//! unchanged. Unknown parameters are ignored, matching libRIST.
//!
//! To keep the dependency footprint minimal (the project's posture), the simple
//! `rist://` structure is hand-parsed rather than pulling in a general URL crate;
//! query values are percent-decoded.

use std::collections::HashMap;
use std::time::Duration;

use rist_codec::crypto::AesKeyBits;

use crate::CongestionMode;
use crate::config::{Config, Profile};
use crate::error::Error;

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
/// `bandwidth` (kbps), `min-retries`, `max-retries`, `aes-type` (128/256),
/// `virt-src-port`, `virt-dst-port`, `profile`, `cname`, `secret`. `buffer` sets
/// both buffer bounds and `rtt` sets both RTT bounds; an explicit `-min`/`-max`
/// always wins regardless of URL order (a deliberate simplification of libRIST's
/// order-dependent parsing). Parameters for later workpackages (`weight`,
/// `key-rotation`, `username`, `password`, `compression`) are accepted and
/// ignored for now.
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
    // `weight`, `key-rotation`, `username`, `password`, `compression` are known to
    // libRIST but have no Config home until bonding (WP5) / Main (WP3) / Advanced
    // (WP4); they are accepted and ignored for now.
    Ok(())
}

/// Folds the enum-valued query parameters (`aes-type`, `profile`,
/// `congestion-control`) into `cfg`, each on libRIST's numbering. Split out of
/// [`apply_query`] to keep that function under the line cap.
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
            256 => AesKeyBits::Aes256,
            other => return Err(Error::Url(format!("aes-type={other} must be 128 or 256"))),
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
    fn ipv6_authority() {
        let (addr, _) = parse_url("rist://[::1]:5000?buffer=500", Config::default()).unwrap();
        assert_eq!(addr, "[::1]:5000");
    }

    #[test]
    fn malformed_urls_error() {
        let cases = [
            "srt://h:5000",                      // bad scheme
            "rist://h",                          // no port
            "rist://h:5000?buffer=abc",          // non-integer buffer
            "rist://h:5000?rtt-min=fast",        // non-integer rtt-min
            "rist://h:5000?virt-dst-port=99999", // port out of range
            "rist://h:5000?aes-type=192",        // unsupported AES size
            "rist://h:5000?profile=9",           // unknown profile
        ];
        for raw in cases {
            assert!(
                matches!(parse_url(raw, Config::default()), Err(Error::Url(_))),
                "{raw} should be an Error::Url"
            );
        }
    }
}
