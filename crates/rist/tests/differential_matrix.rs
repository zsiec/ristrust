//! Exhaustive differential matrix: ristrust against the ristgo example
//! sender/receiver (the same-author, libRIST-interop-proven Go reference — the
//! project's second oracle), across every profile, encryption mode, and LZ4
//! compression, in both directions, clean and lossy.
//!
//! The committed `differential.rs` proves Simple-profile clean both ways; this
//! file widens that to Main/Advanced, AES-128/256 PSK, LZ4, and single-port lossy
//! ARQ recovery — the full wire-and-crypto interop surface ristrust shares with
//! ristgo. Behind the `differential` feature; needs the Go toolchain and the
//! ristgo source (`$RISTGO_DIR`), and skips gracefully when either is absent:
//!
//! ```text
//! RISTGO_DIR=~/dev/ristgo cargo test -p rist --features differential \
//!     --test differential_matrix -- --test-threads=1 --nocapture
//! ```
#![cfg(feature = "differential")]
#![allow(
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use rist::{
    AesKeyBits, Config, MergeMode, Profile, SplitMode, dial, dial_bonded, listen, listen_bonded,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout};

/// One RTP media payload: 7 MPEG-TS cells, libRIST's default chunk.
const CHUNK: usize = 1316;
/// Datagrams per run (~158 KB).
const N: usize = 120;
/// Shared PSK for the encrypted combos.
const SECRET: &str = "differential-matrix-passphrase";

// ---------------------------------------------------------------------------
// ristgo build + process helpers (mirrors differential.rs)
// ---------------------------------------------------------------------------

/// The ristgo source directory from `$RISTGO_DIR`, or `None` (skip).
fn ristgo_dir() -> Option<PathBuf> {
    let d = std::env::var("RISTGO_DIR").ok()?;
    let p = PathBuf::from(d);
    p.join("go.mod").is_file().then_some(p)
}

/// Builds a ristgo example binary to a temp path, or `None` (skip) when the Go
/// toolchain or ristgo source is absent or the build fails.
async fn build_ristgo(example: &str) -> Option<PathBuf> {
    let dir = ristgo_dir()?;
    let out = std::env::temp_dir().join(format!("ristgo-{example}-{}", std::process::id()));
    let status = Command::new("go")
        .args([
            "build",
            "-o",
            out.to_str().unwrap(),
            &format!("./examples/{example}"),
        ])
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .ok()?;
    status.success().then_some(out)
}

/// A free loopback even port (RIST media; RTCP takes the adjacent odd).
fn free_even_port() -> u16 {
    for _ in 0..100 {
        if let Ok(s) = StdUdpSocket::bind("127.0.0.1:0") {
            let even = s.local_addr().unwrap().port() & !1;
            if even != 0 {
                return even;
            }
        }
    }
    panic!("no free even port");
}

/// Blocks until something has bound `port` or the timeout elapses.
async fn wait_bound(port: u16, within: Duration) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if StdUdpSocket::bind(("127.0.0.1", port)).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A child killed when the guard drops.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.start_kill().ok();
    }
}

/// Deterministic pseudo-random media (an LCG; no `rand` dependency).
fn gen_data(chunks: usize) -> Vec<u8> {
    let mut v = vec![0u8; chunks * CHUNK];
    let mut x: u32 = 0x1234_5678;
    for b in &mut v {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    v
}

// ---------------------------------------------------------------------------
// Scenario: the knobs kept in sync between the ristrust Config and the ristgo URL
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Scenario {
    profile: Profile,
    profile_n: u8,
    secret: Option<&'static str>,
    aes: Option<AesKeyBits>,
    compression: bool,
    buffer_ms: u64,
    /// EAP-SRP credentials (`username`/`password`). When set with no `secret`, the
    /// media key is derived from the SRP session key K — the raw (no NUL-truncation)
    /// PBKDF2 path, exactly the interop case the session's raw-key fix targeted.
    srp: Option<(&'static str, &'static str)>,
    /// Negotiate the legacy unpadded EAPOL v2 SRP variant (libRIST `srp-compat`).
    srp_compat: bool,
    /// Packet-split bonding modes (libRIST `split=`/`merge=`). Applied to both ends:
    /// `split` is inert on whichever end is the receiver and `merge` is inert on the
    /// sender, so a single scenario exercises split→merge in both directions.
    split_mode: SplitMode,
    merge_mode: MergeMode,
}

impl Scenario {
    /// The ristrust `Config` for this scenario.
    fn cfg(self) -> Config {
        let mut c = Config::default()
            .with_profile(self.profile)
            .with_buffer(Duration::from_millis(self.buffer_ms));
        if let Some(s) = self.secret {
            c = c.with_secret(s);
        }
        if let Some(bits) = self.aes {
            c = c.with_aes_key_bits(bits);
        }
        if self.compression {
            c = c.with_compression(true);
        }
        if let Some((u, p)) = self.srp {
            c = c.with_srp_credentials(u, p);
        }
        if self.srp_compat {
            c = c.with_srp_compat(true);
        }
        c.with_split_mode(self.split_mode)
            .with_merge_mode(self.merge_mode)
    }

    /// The ristgo `rist://` query string. `sender` adds `compression=1`, which is a
    /// send-side choice (the receiver auto-detects the LPC flag per packet).
    fn query(self, sender: bool) -> String {
        use std::fmt::Write;
        let mut q = format!("?profile={}&buffer={}", self.profile_n, self.buffer_ms);
        if let Some(s) = self.secret {
            write!(q, "&secret={s}").unwrap();
        }
        if let Some(bits) = self.aes {
            let n = match bits {
                AesKeyBits::Aes128 => 128,
                AesKeyBits::Aes192 => 192,
                AesKeyBits::Aes256 => 256,
            };
            write!(q, "&aes-type={n}").unwrap();
        }
        if let Some((u, p)) = self.srp {
            write!(q, "&username={u}&password={p}").unwrap();
        }
        if self.srp_compat {
            q.push_str("&srp-compat=1");
        }
        if self.compression && sender {
            q.push_str("&compression=1");
        }
        // libRIST/ristgo spell split/merge as words (off|auto|half, off|pairs|auto).
        match self.split_mode {
            SplitMode::Auto => q.push_str("&split=auto"),
            SplitMode::Half => q.push_str("&split=half"),
            SplitMode::Off => {}
        }
        match self.merge_mode {
            MergeMode::Pairs => q.push_str("&merge=pairs"),
            MergeMode::Auto => q.push_str("&merge=auto"),
            MergeMode::Off => {}
        }
        q
    }
}

// ---------------------------------------------------------------------------
// Single-port lossy UDP proxy (Main/Advanced are GRE-over-one-port, so one
// bidirectional relay carries both media and the NACK feedback). Drops a
// deterministic fraction of sender->receiver datagrams to force ARQ recovery.
// ---------------------------------------------------------------------------

struct LossyProxy {
    front: u16,
    _task: tokio::task::JoinHandle<()>,
}

/// Relays `front` <-> `back`, dropping `loss` of the datagrams arriving from the
/// last sender side (sender->receiver), passing feedback the other way intact.
async fn start_single_port_lossy_proxy(back: u16, loss: f64, seed: u64) -> LossyProxy {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("proxy bind");
    let front = sock.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let back_addr = format!("127.0.0.1:{back}");
        let mut buf = vec![0u8; 65536];
        let mut x = seed | 1;
        let mut sender_addr: Option<std::net::SocketAddr> = None;
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let back_resolved: std::net::SocketAddr = back_addr.parse().unwrap();
            if from == back_resolved {
                // Feedback from the receiver -> back to the sender, never dropped.
                if let Some(s) = sender_addr {
                    let _ = sock.send_to(&buf[..n], s).await;
                }
            } else {
                // Media from the sender -> receiver, dropped with probability `loss`.
                sender_addr = Some(from);
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let r = (x >> 11) as f64 / (1u64 << 53) as f64;
                if r >= loss {
                    let _ = sock.send_to(&buf[..n], back_resolved).await;
                }
            }
        }
    });
    LossyProxy { front, _task: task }
}

// ---------------------------------------------------------------------------
// The two directional drivers
// ---------------------------------------------------------------------------

/// ristrust Sender -> ristgo receiver. `loss` > 0 inserts a lossy proxy (only
/// valid for single-port Main/Advanced). Asserts a byte-exact transfer.
async fn rx_from_ristrust_tx(label: &str, s: Scenario, loss: f64) {
    let Some(rx_bin) = build_ristgo("receiver").await else {
        eprintln!("differential[{label}]: ristgo/go toolchain not available; skipping");
        return;
    };
    let port = free_even_port();
    let url = format!("rist://:{port}{}", s.query(false));

    let mut child = Command::new(&rx_bin)
        .arg(&url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ristgo receiver");
    let mut stdout = child.stdout.take().expect("ristgo receiver stdout");
    let _guard = ChildGuard(child);
    wait_bound(port, Duration::from_secs(5)).await;

    // Dial the receiver directly, or via a lossy proxy in front of it.
    let dial_port = if loss > 0.0 {
        let proxy = start_single_port_lossy_proxy(port, loss, 0xD1FF_0001).await;
        let p = proxy.front;
        std::mem::forget(proxy); // keep the relay alive for the test's duration
        p
    } else {
        port
    };

    let sender = dial(&format!("127.0.0.1:{dial_port}"), s.cfg())
        .await
        .expect("dial ristgo receiver");

    let data = Arc::new(gen_data(N));
    let send_data = data.clone();
    let send = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(&send_data[i * CHUNK..(i + 1) * CHUNK])
                .await
                .expect("send");
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        sender
    });

    let want = N * CHUNK;
    // Clean requires the whole stream; lossy tolerates a few unrecovered tail
    // chunks (an abrupt stream end has no trailing traffic to carry the final
    // NACK), but a long *contiguous* recovered prefix is impossible without ARQ.
    let min_bytes = if loss > 0.0 { (N - 10) * CHUNK } else { want };
    let deadline = Instant::now() + Duration::from_secs(if loss > 0.0 { 20 } else { 30 });
    let mut got = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, stdout.read(&mut got[filled..])).await {
            Ok(Ok(n)) if n > 0 => filled += n,
            _ => break,
        }
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close");

    assert!(
        filled >= min_bytes,
        "[{label}] ristgo recovered {filled} of {want} bytes (min {min_bytes})"
    );
    assert_eq!(
        got[..filled],
        data[..filled],
        "[{label}] byte mismatch in the ristgo-received prefix"
    );
}

/// ristgo sender -> ristrust Receiver. `loss` > 0 inserts a lossy proxy (only
/// valid for single-port Main/Advanced). Asserts a byte-exact transfer.
async fn ristrust_rx_from_tx(label: &str, s: Scenario, loss: f64) {
    let Some(tx_bin) = build_ristgo("sender").await else {
        eprintln!("differential[{label}]: ristgo/go toolchain not available; skipping");
        return;
    };
    let port = free_even_port();

    let mut receiver = listen(&format!("127.0.0.1:{port}"), s.cfg())
        .await
        .expect("listen for ristgo sender");

    // ristgo sends to the receiver directly, or via a lossy proxy in front of it.
    let target_port = if loss > 0.0 {
        let proxy = start_single_port_lossy_proxy(port, loss, 0xD1FF_0002).await;
        let p = proxy.front;
        std::mem::forget(proxy);
        p
    } else {
        port
    };
    let url = format!("rist://127.0.0.1:{target_port}{}", s.query(true));

    let mut child = Command::new(&tx_bin)
        .arg(&url)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ristgo sender");
    let mut stdin = child.stdin.take().expect("ristgo sender stdin");
    let _guard = ChildGuard(child);

    let data = gen_data(N);
    let feed_data = data.clone();
    let feeder = tokio::spawn(async move {
        for i in 0..N {
            if stdin
                .write_all(&feed_data[i * CHUNK..(i + 1) * CHUNK])
                .await
                .is_err()
            {
                return stdin;
            }
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        let _ = stdin.flush().await;
        stdin
    });

    // Clean requires every payload; lossy tolerates a few unrecovered tail chunks
    // but a long contiguous prefix proves the NACK/retransmit path interoperated.
    let min_expected = if loss > 0.0 { N - 10 } else { N };
    let per_recv = Duration::from_secs(if loss > 0.0 { 8 } else { 30 });
    let mut got = Vec::with_capacity(N * CHUNK);
    let mut count = 0usize;
    for _ in 0..N {
        match timeout(per_recv, receiver.recv()).await {
            Ok(Ok(payload)) => {
                got.extend_from_slice(&payload);
                count += 1;
            }
            // Session closed, or the in-order cursor stalled on an unrecovered tail
            // gap — stop and assert on the contiguous prefix collected so far.
            _ => break,
        }
    }

    let _stdin = feeder.await.expect("feeder");
    receiver.close().await.expect("close");
    assert!(
        count >= min_expected,
        "[{label}] recovered {count}/{N} chunks (min {min_expected})"
    );
    assert_eq!(
        got.as_slice(),
        &data[..count * CHUNK],
        "[{label}] byte mismatch in the recovered prefix"
    );
}

// ---------------------------------------------------------------------------
// Scenario constructors
// ---------------------------------------------------------------------------

/// The shared scenario baseline (no encryption, no SRP, 300 ms buffer); each
/// constructor overrides only the fields it varies.
fn base(profile: Profile, profile_n: u8) -> Scenario {
    Scenario {
        profile,
        profile_n,
        secret: None,
        aes: None,
        compression: false,
        buffer_ms: 300,
        srp: None,
        srp_compat: false,
        split_mode: SplitMode::Off,
        merge_mode: MergeMode::Off,
    }
}
fn simple() -> Scenario {
    base(Profile::Simple, 0)
}
/// Split/merge bonding on a profile: `split=auto` + `merge=pairs` on both ends (each
/// inert in the wrong role), so a single scenario cross-validates ristrust-split →
/// ristgo-merge and ristgo-split → ristrust-merge byte-exact.
fn split_merge(profile: Profile, profile_n: u8) -> Scenario {
    Scenario {
        split_mode: SplitMode::Auto,
        merge_mode: MergeMode::Pairs,
        ..base(profile, profile_n)
    }
}
fn main_clear() -> Scenario {
    base(Profile::Main, 1)
}
fn main_aes(bits: AesKeyBits) -> Scenario {
    Scenario {
        secret: Some(SECRET),
        aes: Some(bits),
        ..base(Profile::Main, 1)
    }
}
fn adv_clear() -> Scenario {
    base(Profile::Advanced, 2)
}
fn adv_aes256() -> Scenario {
    Scenario {
        secret: Some(SECRET),
        aes: Some(AesKeyBits::Aes256),
        ..base(Profile::Advanced, 2)
    }
}
fn adv_lz4() -> Scenario {
    Scenario {
        compression: true,
        ..base(Profile::Advanced, 2)
    }
}

// EAP-SRP credentials shared by the SRP scenarios.
const SRP_USER: &str = "diff-srp-user";
const SRP_PASS: &str = "diff-srp-password";

// EAP-SRP cross-stack status (both single-flow and bonded, both fully interoperable):
//   - Combined PSK+SRP (a `secret` is set): the media rides one shared PSK key, SRP only
//     gates. Covered by single-flow main_srp and bonded bonded_main_srp_psk.
//   - Pure-SRP (no secret, use_key_as_passphrase): SRP authenticates and the media stays
//     CLEARTEXT; only the receiver→sender feedback is keyed with the session key K (the
//     authenticator keys its send, the authenticatee its recv — never the media direction).
//     This is libRIST's actual model (use_key authenticates; media encryption needs a PSK),
//     verified against libRIST in the interop suite. Covered by single-flow
//     main_srp_pure and bonded bonded_main_srp_pure; for bonded each path keys its own K.
// EAP-SRP is Main-only on both stacks, so there is no Advanced SRP case.

/// Main profile, EAP-SRP authentication with an AES-256 PSK secret (the libRIST-
/// interoperable combined mode): SRP gates the session, the secret keys the media.
fn main_srp() -> Scenario {
    Scenario {
        secret: Some(SECRET),
        aes: Some(AesKeyBits::Aes256),
        srp: Some((SRP_USER, SRP_PASS)),
        ..base(Profile::Main, 1)
    }
}
/// Main profile, pure-SRP (no secret): SRP authenticates, the media is cleartext, and only
/// the receiver→sender feedback is keyed with the session key K (libRIST's actual
/// use_key_as_passphrase model — not media encryption).
fn main_srp_pure() -> Scenario {
    Scenario {
        srp: Some((SRP_USER, SRP_PASS)),
        ..base(Profile::Main, 1)
    }
}
/// As [`main_srp`], but negotiating the legacy unpadded EAPOL v2 SRP variant
/// (libRIST `srp-compat`).
fn main_srp_legacy() -> Scenario {
    Scenario {
        secret: Some(SECRET),
        aes: Some(AesKeyBits::Aes256),
        srp: Some((SRP_USER, SRP_PASS)),
        srp_compat: true,
        ..base(Profile::Main, 1)
    }
}

// ---------------------------------------------------------------------------
// The matrix — clean, both directions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diff_simple_clear_ristgo_rx() {
    rx_from_ristrust_tx("simple/clear ristgo-rx", simple(), 0.0).await;
}
#[tokio::test]
async fn diff_simple_clear_ristrust_rx() {
    ristrust_rx_from_tx("simple/clear ristrust-rx", simple(), 0.0).await;
}

#[tokio::test]
async fn diff_main_clear_ristgo_rx() {
    rx_from_ristrust_tx("main/clear ristgo-rx", main_clear(), 0.0).await;
}
#[tokio::test]
async fn diff_main_clear_ristrust_rx() {
    ristrust_rx_from_tx("main/clear ristrust-rx", main_clear(), 0.0).await;
}

#[tokio::test]
async fn diff_main_aes128_ristgo_rx() {
    rx_from_ristrust_tx("main/aes128 ristgo-rx", main_aes(AesKeyBits::Aes128), 0.0).await;
}
#[tokio::test]
async fn diff_main_aes128_ristrust_rx() {
    ristrust_rx_from_tx("main/aes128 ristrust-rx", main_aes(AesKeyBits::Aes128), 0.0).await;
}

#[tokio::test]
async fn diff_main_aes256_ristgo_rx() {
    rx_from_ristrust_tx("main/aes256 ristgo-rx", main_aes(AesKeyBits::Aes256), 0.0).await;
}
#[tokio::test]
async fn diff_main_aes256_ristrust_rx() {
    ristrust_rx_from_tx("main/aes256 ristrust-rx", main_aes(AesKeyBits::Aes256), 0.0).await;
}

#[tokio::test]
async fn diff_adv_clear_ristgo_rx() {
    rx_from_ristrust_tx("adv/clear ristgo-rx", adv_clear(), 0.0).await;
}
#[tokio::test]
async fn diff_adv_clear_ristrust_rx() {
    ristrust_rx_from_tx("adv/clear ristrust-rx", adv_clear(), 0.0).await;
}

#[tokio::test]
async fn diff_adv_aes256_ristgo_rx() {
    rx_from_ristrust_tx("adv/aes256 ristgo-rx", adv_aes256(), 0.0).await;
}
#[tokio::test]
async fn diff_adv_aes256_ristrust_rx() {
    ristrust_rx_from_tx("adv/aes256 ristrust-rx", adv_aes256(), 0.0).await;
}

#[tokio::test]
async fn diff_adv_lz4_ristgo_rx() {
    rx_from_ristrust_tx("adv/lz4 ristgo-rx", adv_lz4(), 0.0).await;
}
#[tokio::test]
async fn diff_adv_lz4_ristrust_rx() {
    ristrust_rx_from_tx("adv/lz4 ristrust-rx", adv_lz4(), 0.0).await;
}

// ---------------------------------------------------------------------------
// Lossy ARQ recovery — single-port profiles, ~12% loss, both directions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diff_main_aes256_lossy_ristgo_rx() {
    rx_from_ristrust_tx(
        "main/aes256 lossy ristgo-rx",
        main_aes(AesKeyBits::Aes256),
        0.12,
    )
    .await;
}
#[tokio::test]
async fn diff_main_aes256_lossy_ristrust_rx() {
    ristrust_rx_from_tx(
        "main/aes256 lossy ristrust-rx",
        main_aes(AesKeyBits::Aes256),
        0.12,
    )
    .await;
}

#[tokio::test]
async fn diff_adv_clear_lossy_ristgo_rx() {
    rx_from_ristrust_tx("adv/clear lossy ristgo-rx", adv_clear(), 0.12).await;
}
#[tokio::test]
async fn diff_adv_clear_lossy_ristrust_rx() {
    ristrust_rx_from_tx("adv/clear lossy ristrust-rx", adv_clear(), 0.12).await;
}

// ---------------------------------------------------------------------------
// EAP-SRP authentication (Main profile, combined SRP+secret mode) — both
// directions. The sender authenticates as the SRP user; the receiver verifies and,
// once authenticated, the PSK secret keys the media. Modern (EAPOL v3) and legacy
// (EAPOL v2 / `srp-compat`) handshakes, clean and under ~12% loss.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diff_main_srp_ristgo_rx() {
    rx_from_ristrust_tx("main/srp ristgo-rx", main_srp(), 0.0).await;
}
#[tokio::test]
async fn diff_main_srp_pure_ristgo_rx() {
    rx_from_ristrust_tx("main/srp-pure ristgo-rx", main_srp_pure(), 0.0).await;
}
#[tokio::test]
async fn diff_main_srp_pure_ristrust_rx() {
    ristrust_rx_from_tx("main/srp-pure ristrust-rx", main_srp_pure(), 0.0).await;
}
#[tokio::test]
async fn diff_main_srp_ristrust_rx() {
    ristrust_rx_from_tx("main/srp ristrust-rx", main_srp(), 0.0).await;
}

#[tokio::test]
async fn diff_main_srp_legacy_ristgo_rx() {
    rx_from_ristrust_tx("main/srp-legacy ristgo-rx", main_srp_legacy(), 0.0).await;
}
#[tokio::test]
async fn diff_main_srp_legacy_ristrust_rx() {
    ristrust_rx_from_tx("main/srp-legacy ristrust-rx", main_srp_legacy(), 0.0).await;
}

// EAP-SRP under ~12% loss — the authenticated handshake must complete despite dropped
// EAPOL datagrams. EAP-SRP frames are not ARQ-protected, so this exercises the host
// retransmit timer (re-send the outstanding frame on the keepalive tick) and the EAP
// core's retransmit idempotency (a duplicate frame replays the cached reply instead of
// recomputing a fresh SRP ephemeral, which would desync) — on BOTH stacks. Before that
// fix this deadlocked at 0 bytes; it now recovers.
#[tokio::test]
async fn diff_main_srp_lossy_ristgo_rx() {
    rx_from_ristrust_tx("main/srp lossy ristgo-rx", main_srp(), 0.12).await;
}
#[tokio::test]
async fn diff_main_srp_lossy_ristrust_rx() {
    ristrust_rx_from_tx("main/srp lossy ristrust-rx", main_srp(), 0.12).await;
}

// ---------------------------------------------------------------------------
// Packet split/merge bonding (libRIST split=/merge=) — both directions, all three
// single-path profiles. split=auto on the sender spreads each payload across a
// consecutive sequence pair; merge=pairs on the receiver recombines it. Byte-exact
// delivery proves the two stacks agree on the split wire and recombine it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diff_simple_split_merge_ristgo_rx() {
    rx_from_ristrust_tx(
        "simple/split-merge ristgo-rx",
        split_merge(Profile::Simple, 0),
        0.0,
    )
    .await;
}
#[tokio::test]
async fn diff_simple_split_merge_ristrust_rx() {
    ristrust_rx_from_tx(
        "simple/split-merge ristrust-rx",
        split_merge(Profile::Simple, 0),
        0.0,
    )
    .await;
}
#[tokio::test]
async fn diff_main_split_merge_ristgo_rx() {
    rx_from_ristrust_tx(
        "main/split-merge ristgo-rx",
        split_merge(Profile::Main, 1),
        0.0,
    )
    .await;
}
#[tokio::test]
async fn diff_main_split_merge_ristrust_rx() {
    ristrust_rx_from_tx(
        "main/split-merge ristrust-rx",
        split_merge(Profile::Main, 1),
        0.0,
    )
    .await;
}
#[tokio::test]
async fn diff_adv_split_merge_ristgo_rx() {
    rx_from_ristrust_tx(
        "adv/split-merge ristgo-rx",
        split_merge(Profile::Advanced, 2),
        0.0,
    )
    .await;
}
#[tokio::test]
async fn diff_adv_split_merge_ristrust_rx() {
    ristrust_rx_from_tx(
        "adv/split-merge ristrust-rx",
        split_merge(Profile::Advanced, 2),
        0.0,
    )
    .await;
}

// ---------------------------------------------------------------------------
// SMPTE 2022-7 bonding — both directions, all three profiles. Driven by the
// URL-configurable ristgo `bonded-tx`/`bonded-rx` examples (the stock
// `bonded-sender` is fixed to default config). Each path is full redundancy, so a
// clean link must deliver every chunk after the receiver dedups across paths.
// ---------------------------------------------------------------------------

const BONDED_PATHS: usize = 2;

/// `n` distinct free even ports (RIST media; the Simple profile's RTCP takes the
/// adjacent odd). Sockets are held until all `n` are chosen so none repeat.
fn free_even_ports(n: usize) -> Vec<u16> {
    let mut held = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..(n * 50) {
        if ports.len() == n {
            break;
        }
        if let Ok(s) = StdUdpSocket::bind("127.0.0.1:0") {
            let even = s.local_addr().unwrap().port() & !1;
            // Keep a 2-port gap so an even port and the next path never collide with
            // a Simple-profile RTCP odd port.
            if even != 0 && ports.iter().all(|p: &u16| p.abs_diff(even) >= 4) {
                ports.push(even);
            }
            held.push(s);
        }
    }
    assert_eq!(ports.len(), n, "could not reserve {n} free even ports");
    ports
}

/// ristrust bonded Sender -> ristgo bonded receiver (`bonded-rx`). Byte-exact.
async fn bonded_rx_from_ristrust_tx(label: &str, s: Scenario, paths: usize) {
    let Some(rx_bin) = build_ristgo("bonded-rx").await else {
        eprintln!("differential[{label}]: ristgo/go toolchain not available; skipping");
        return;
    };
    let ports = free_even_ports(paths);
    let urls: Vec<String> = ports
        .iter()
        .map(|p| format!("rist://:{p}{}", s.query(false)))
        .collect();

    let mut child = Command::new(&rx_bin)
        .args(&urls)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ristgo bonded-rx");
    let mut stdout = child.stdout.take().expect("bonded-rx stdout");
    let _guard = ChildGuard(child);
    for p in &ports {
        wait_bound(*p, Duration::from_secs(5)).await;
    }

    let dests: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
    let refs: Vec<&str> = dests.iter().map(String::as_str).collect();
    let sender = dial_bonded(&refs, s.cfg())
        .await
        .expect("dial_bonded ristgo bonded-rx");

    let data = Arc::new(gen_data(N));
    let send_data = data.clone();
    let send = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(&send_data[i * CHUNK..(i + 1) * CHUNK])
                .await
                .expect("send");
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        sender
    });

    let want = N * CHUNK;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut got = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, stdout.read(&mut got[filled..])).await {
            Ok(Ok(n)) if n > 0 => filled += n,
            _ => break,
        }
    }
    let sender = send.await.expect("send task");
    sender.close().await.expect("close");

    assert_eq!(
        filled, want,
        "[{label}] ristgo bonded got {filled}/{want} bytes"
    );
    assert_eq!(
        got, *data,
        "[{label}] byte mismatch in the ristgo bonded stream"
    );
}

/// ristgo bonded sender (`bonded-tx`) -> ristrust bonded Receiver. Byte-exact.
async fn bonded_ristrust_rx_from_tx(label: &str, s: Scenario, paths: usize) {
    let Some(tx_bin) = build_ristgo("bonded-tx").await else {
        eprintln!("differential[{label}]: ristgo/go toolchain not available; skipping");
        return;
    };
    let ports = free_even_ports(paths);
    let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let mut receiver = listen_bonded(&refs, s.cfg())
        .await
        .expect("listen_bonded for ristgo bonded-tx");

    let urls: Vec<String> = ports
        .iter()
        .map(|p| format!("rist://127.0.0.1:{p}{}", s.query(true)))
        .collect();
    let mut child = Command::new(&tx_bin)
        .args(&urls)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ristgo bonded-tx");
    let mut stdin = child.stdin.take().expect("bonded-tx stdin");
    let _guard = ChildGuard(child);

    let data = gen_data(N);
    let feed_data = data.clone();
    let feeder = tokio::spawn(async move {
        for i in 0..N {
            if stdin
                .write_all(&feed_data[i * CHUNK..(i + 1) * CHUNK])
                .await
                .is_err()
            {
                return stdin;
            }
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
        let _ = stdin.flush().await;
        stdin
    });

    let mut got = Vec::with_capacity(N * CHUNK);
    let mut count = 0usize;
    for _ in 0..N {
        match timeout(Duration::from_secs(30), receiver.recv()).await {
            Ok(Ok(payload)) => {
                got.extend_from_slice(&payload);
                count += 1;
            }
            _ => break,
        }
    }
    let _stdin = feeder.await.expect("feeder");
    receiver.close().await.expect("close");

    assert_eq!(count, N, "[{label}] ristrust bonded got {count}/{N} chunks");
    assert_eq!(
        got.as_slice(),
        &data[..],
        "[{label}] byte mismatch in the bonded stream"
    );
}

fn bonded_main() -> Scenario {
    base(Profile::Main, 1)
}
fn bonded_simple() -> Scenario {
    base(Profile::Simple, 0)
}
fn bonded_advanced() -> Scenario {
    base(Profile::Advanced, 2)
}
fn bonded_main_aes() -> Scenario {
    Scenario {
        secret: Some(SECRET),
        aes: Some(AesKeyBits::Aes256),
        ..base(Profile::Main, 1)
    }
}
/// Main profile, bonded, combined PSK+SRP (a secret keys the media, SRP gates each path).
/// Cross-stack interoperable: both stacks carry every path on one shared PSK codec.
fn bonded_main_srp_psk() -> Scenario {
    Scenario {
        secret: Some(SECRET),
        aes: Some(AesKeyBits::Aes256),
        srp: Some((SRP_USER, SRP_PASS)),
        ..base(Profile::Main, 1)
    }
}
/// Main profile, bonded, pure-SRP (use_key_as_passphrase: SRP credentials, NO secret).
/// Each path derives its own session key K and keys its media with it on a per-path codec.
/// Implemented within each stack (ristrust↔ristrust and ristgo↔ristgo, covered by the
/// in-crate e2e tests) but NOT yet cross-stack interoperable — see the #[ignore]d tests.
fn bonded_main_srp_pure() -> Scenario {
    Scenario {
        srp: Some((SRP_USER, SRP_PASS)),
        ..base(Profile::Main, 1)
    }
}

#[tokio::test]
async fn diff_bonded_main_ristgo_rx() {
    bonded_rx_from_ristrust_tx("bonded main ristgo-rx", bonded_main(), BONDED_PATHS).await;
}
#[tokio::test]
async fn diff_bonded_main_ristrust_rx() {
    bonded_ristrust_rx_from_tx("bonded main ristrust-rx", bonded_main(), BONDED_PATHS).await;
}

#[tokio::test]
async fn diff_bonded_simple_ristgo_rx() {
    bonded_rx_from_ristrust_tx("bonded simple ristgo-rx", bonded_simple(), BONDED_PATHS).await;
}
#[tokio::test]
async fn diff_bonded_simple_ristrust_rx() {
    bonded_ristrust_rx_from_tx("bonded simple ristrust-rx", bonded_simple(), BONDED_PATHS).await;
}

#[tokio::test]
async fn diff_bonded_advanced_ristgo_rx() {
    bonded_rx_from_ristrust_tx("bonded advanced ristgo-rx", bonded_advanced(), BONDED_PATHS).await;
}
#[tokio::test]
async fn diff_bonded_advanced_ristrust_rx() {
    bonded_ristrust_rx_from_tx(
        "bonded advanced ristrust-rx",
        bonded_advanced(),
        BONDED_PATHS,
    )
    .await;
}

#[tokio::test]
async fn diff_bonded_main_aes_ristgo_rx() {
    bonded_rx_from_ristrust_tx("bonded main/aes ristgo-rx", bonded_main_aes(), BONDED_PATHS).await;
}
#[tokio::test]
async fn diff_bonded_main_aes_ristrust_rx() {
    bonded_ristrust_rx_from_tx(
        "bonded main/aes ristrust-rx",
        bonded_main_aes(),
        BONDED_PATHS,
    )
    .await;
}
#[tokio::test]
async fn diff_bonded_main_srp_psk_ristgo_rx() {
    bonded_rx_from_ristrust_tx(
        "bonded main PSK+SRP ristgo-rx",
        bonded_main_srp_psk(),
        BONDED_PATHS,
    )
    .await;
}
#[tokio::test]
async fn diff_bonded_main_srp_psk_ristrust_rx() {
    bonded_ristrust_rx_from_tx(
        "bonded main PSK+SRP ristrust-rx",
        bonded_main_srp_psk(),
        BONDED_PATHS,
    )
    .await;
}
// Pure-SRP (no-secret) bonding: each path authenticates with its own SRP handshake and
// keys ONLY the receiver→sender feedback direction with its session key K; the media stays
// cleartext (SRP authenticates, it does not encrypt — matching libRIST). Cross-stack
// interoperable both ways.
#[tokio::test]
async fn diff_bonded_main_srp_pure_ristgo_rx() {
    bonded_rx_from_ristrust_tx(
        "bonded main pure-SRP ristgo-rx",
        bonded_main_srp_pure(),
        BONDED_PATHS,
    )
    .await;
}
#[tokio::test]
async fn diff_bonded_main_srp_pure_ristrust_rx() {
    bonded_ristrust_rx_from_tx(
        "bonded main pure-SRP ristrust-rx",
        bonded_main_srp_pure(),
        BONDED_PATHS,
    )
    .await;
}
