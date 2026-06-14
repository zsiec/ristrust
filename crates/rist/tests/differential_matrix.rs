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

use rist::{AesKeyBits, Config, Profile, dial, listen};
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
        c
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
                AesKeyBits::Aes256 => 256,
            };
            write!(q, "&aes-type={n}").unwrap();
        }
        if self.compression && sender {
            q.push_str("&compression=1");
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

fn simple() -> Scenario {
    Scenario {
        profile: Profile::Simple,
        profile_n: 0,
        secret: None,
        aes: None,
        compression: false,
        buffer_ms: 300,
    }
}
fn main_clear() -> Scenario {
    Scenario {
        profile: Profile::Main,
        profile_n: 1,
        secret: None,
        aes: None,
        compression: false,
        buffer_ms: 300,
    }
}
fn main_aes(bits: AesKeyBits) -> Scenario {
    Scenario {
        profile: Profile::Main,
        profile_n: 1,
        secret: Some(SECRET),
        aes: Some(bits),
        compression: false,
        buffer_ms: 300,
    }
}
fn adv_clear() -> Scenario {
    Scenario {
        profile: Profile::Advanced,
        profile_n: 2,
        secret: None,
        aes: None,
        compression: false,
        buffer_ms: 300,
    }
}
fn adv_aes256() -> Scenario {
    Scenario {
        profile: Profile::Advanced,
        profile_n: 2,
        secret: Some(SECRET),
        aes: Some(AesKeyBits::Aes256),
        compression: false,
        buffer_ms: 300,
    }
}
fn adv_lz4() -> Scenario {
    Scenario {
        profile: Profile::Advanced,
        profile_n: 2,
        secret: None,
        aes: None,
        compression: true,
        buffer_ms: 300,
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

// SMPTE 2022-7 bonding is intentionally NOT in this matrix: ristrust (like
// libRIST) only bonds on the Main profile, but ristgo's `bonded-sender` example
// is hard-wired to Simple (no profile CLI knob), so it cannot drive a ristrust
// bonded receiver. Bonding interop is covered transitively instead — the Main
// GRE wire is proven byte-exact here (main/* combos), and ristrust's 2022-7
// dedup + seamless failover are proven against libRIST in `interop.rs`.
