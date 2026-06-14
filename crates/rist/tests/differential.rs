//! Differential tests: ristrust against the ristgo example sender/receiver — the
//! same-author, libRIST-interop-proven Go reference (the project's second
//! oracle). Behind the `differential` feature; needs the Go toolchain and the
//! ristgo source (`RISTGO_DIR`, else `~/dev/ristgo`), and skips gracefully when
//! either is absent.
//!
//! ```text
//! cargo test -p rist --features differential -- --nocapture
//! ```
//!
//! The ristgo examples carry media on stdin (sender) / stdout (receiver) in
//! 1316-byte RTP-sized chunks, so the harness pipes bytes through them and asserts
//! a byte-exact round trip both directions on a clean loopback.
#![cfg(feature = "differential")]

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use rist::{Config, dial, listen};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout};

const CHUNK: usize = 1316;
const N: usize = 150;

/// The ristgo source directory, or `None` (skip): `RISTGO_DIR`, else `~/dev/ristgo`.
fn ristgo_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("RISTGO_DIR") {
        let p = PathBuf::from(d);
        return p.join("go.mod").is_file().then_some(p);
    }
    let home = std::env::var_os("HOME")?;
    let p = PathBuf::from(home).join("dev/ristgo");
    p.join("go.mod").is_file().then_some(p)
}

/// Builds a ristgo example binary to a temp path, or returns `None` (skip) when
/// the Go toolchain or ristgo source is absent or the build fails.
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

/// Blocks until something has bound `port` (a probe bind fails) or the timeout.
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

/// ristrust Sender → ristgo receiver, clean. Proves ristrust's wire is byte-exact
/// with ristgo (the second oracle).
#[tokio::test]
async fn differential_ristgo_rx_from_ristrust_tx() {
    let Some(rx_bin) = build_ristgo("receiver").await else {
        eprintln!("differential: ristgo/go toolchain not available; skipping");
        return;
    };
    let port = free_even_port();

    let mut child = Command::new(&rx_bin)
        .arg(format!(":{port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ristgo receiver");
    let mut stdout = child.stdout.take().expect("ristgo receiver stdout");
    let _guard = ChildGuard(child);
    wait_bound(port, Duration::from_secs(5)).await;

    let cfg = Config::default().with_buffer(Duration::from_millis(200));
    let sender = dial(&format!("127.0.0.1:{port}"), cfg)
        .await
        .expect("dial ristgo receiver");

    let data = std::sync::Arc::new(gen_data(N));
    let send_data = data.clone();
    let send = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(&send_data[i * CHUNK..(i + 1) * CHUNK])
                .await
                .expect("send");
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        sender
    });

    // Read exactly N*CHUNK bytes of recovered media from ristgo's stdout.
    let want = N * CHUNK;
    let mut got = vec![0u8; want];
    let mut filled = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while filled < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, stdout.read(&mut got[filled..])).await {
            Ok(Ok(n)) if n > 0 => filled += n,
            _ => break, // EOF, read error, or timeout
        }
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close");

    assert_eq!(filled, want, "ristgo received {filled} of {want} bytes");
    assert_eq!(got, *data, "byte mismatch at the ristgo receiver");
}

/// ristgo sender → ristrust Receiver, clean. Proves ristrust decodes ristgo's
/// output byte-exactly.
#[tokio::test]
async fn differential_ristrust_rx_from_ristgo_tx() {
    let Some(tx_bin) = build_ristgo("sender").await else {
        eprintln!("differential: ristgo/go toolchain not available; skipping");
        return;
    };
    let port = free_even_port();

    let cfg = Config::default().with_buffer(Duration::from_millis(200));
    let mut receiver = listen(&format!("127.0.0.1:{port}"), cfg)
        .await
        .expect("listen for ristgo sender");

    let mut child = Command::new(&tx_bin)
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ristgo sender");
    let mut stdin = child.stdin.take().expect("ristgo sender stdin");
    let _guard = ChildGuard(child);

    let data = gen_data(N);
    // Feed ristgo's stdin; keep the handle open (no EOF) so the sender stays
    // alive through the receiver's playout rather than exiting after the data.
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
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let _ = stdin.flush().await;
        stdin
    });

    let mut got = Vec::with_capacity(N * CHUNK);
    for i in 0..N {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }

    let _stdin = feeder.await.expect("feeder"); // hold stdin until after collection
    receiver.close().await.expect("close");
    assert_eq!(got, data, "byte mismatch from the ristgo sender");
}
