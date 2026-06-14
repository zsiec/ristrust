//! Interop tests against the libRIST reference CLI tools (`ristsender` /
//! `ristreceiver`), Simple profile (VSF TR-06-1) — the byte-exact wire-interop
//! gate. Behind the `interop` feature so the default gauntlet never spawns
//! external processes:
//!
//! ```text
//! cargo test -p rist --features interop -- --nocapture
//! ```
//!
//! The tools are located at `$RISTGO_LIBRIST_TOOLS`, then
//! `~/dev/librist/build/tools`, then `$PATH`; each test skips (prints a notice
//! and returns) when they are absent, so the suite is safe to run anywhere.
//!
//! These two clean combos prove ristrust's Simple-profile RTP/RTCP is byte-exact
//! with libRIST both ways: ristrust → libRIST receiver, and libRIST sender →
//! ristrust. (The lossy combos that exercise the retransmit SSRC-toggle across
//! the wire build on these.)
#![cfg(feature = "interop")]

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rist::{Config, dial, listen};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

/// One RTP media payload: 7 MPEG-TS cells, libRIST's default chunk.
const CHUNK: usize = 1316;
/// Datagrams per clean run (~256 KB).
const N: usize = 200;

/// Locates a libRIST CLI tool, or returns `None` (the caller skips).
fn librist_tool(name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(dir) = std::env::var("RISTGO_LIBRIST_TOOLS") {
        candidates.push(PathBuf::from(dir).join(name));
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join("dev/librist/build/tools")
                .join(name),
        );
    }
    candidates.into_iter().find(|c| c.is_file()).or_else(|| {
        // Fall back to PATH.
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(name))
                .find(|c| c.is_file())
        })
    })
}

/// A free loopback even port (the RIST media port; RTCP takes the adjacent odd).
fn free_even_port() -> u16 {
    for _ in 0..100 {
        if let Ok(s) = StdUdpSocket::bind("127.0.0.1:0") {
            let p = s.local_addr().unwrap().port();
            let even = p & !1;
            if even != 0 {
                return even;
            }
        }
    }
    panic!("no free even port");
}

/// A free loopback UDP port not in `exclude`.
fn free_udp_port(exclude: &[u16]) -> u16 {
    for _ in 0..100 {
        if let Ok(s) = StdUdpSocket::bind("127.0.0.1:0") {
            let p = s.local_addr().unwrap().port();
            if !exclude.contains(&p) {
                return p;
            }
        }
    }
    panic!("no free udp port");
}

/// Blocks until a libRIST tool has bound `port` (a probe bind fails) or the
/// timeout elapses — replacing a fixed startup sleep so data is not fed early.
async fn wait_tool_ready(port: u16, within: Duration) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if StdUdpSocket::bind(("127.0.0.1", port)).is_err() {
            return; // port in use → the tool holds it
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    eprintln!("interop: timed out waiting for a libRIST tool to bind udp 127.0.0.1:{port}");
}

/// A spawned tool that is killed when the guard drops.
struct ToolGuard(Child);
impl Drop for ToolGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawns a libRIST tool with its output silenced.
fn spawn_tool(bin: &PathBuf, args: &[String]) -> ToolGuard {
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn libRIST tool");
    ToolGuard(child)
}

/// Deterministic pseudo-random media (an LCG, so no `rand` dependency).
fn gen_data(chunks: usize) -> Vec<u8> {
    let mut v = vec![0u8; chunks * CHUNK];
    let mut x: u32 = 0x1234_5678;
    for b in &mut v {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    v
}

/// ristrust Sender → libRIST `ristreceiver`, clean. Proves libRIST decodes
/// ristrust's Simple-profile RTP/RTCP byte-exactly.
#[tokio::test]
async fn interop_librist_rx_from_ristrust_tx() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_even_port();
    let cap_port = free_udp_port(&[rx_port, rx_port + 1]);

    // Capture socket for libRIST's UDP output (bound before the tool starts).
    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");

    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "0".into(),
            "-b".into(),
            "200".into(),
            "-i".into(),
            format!("rist://@127.0.0.1:{rx_port}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let cfg = Config::default().with_buffer(Duration::from_millis(200));
    let sender = dial(&format!("127.0.0.1:{rx_port}"), cfg)
        .await
        .expect("dial libRIST receiver");

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

    // Collect exactly N*CHUNK bytes of libRIST output.
    let want = N * CHUNK;
    let mut got = Vec::with_capacity(want);
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(20);
    while got.len() < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, cap.recv(&mut buf)).await {
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close");

    assert_eq!(
        got.len(),
        want,
        "libRIST received {} of {want} bytes",
        got.len()
    );
    assert_eq!(got, *data, "byte mismatch at the libRIST receiver");
}

/// libRIST `ristsender` → ristrust Receiver, clean. Proves ristrust decodes
/// libRIST's Simple-profile output byte-exactly.
#[tokio::test]
async fn interop_ristrust_rx_from_librist_tx() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let go_port = free_even_port();
    let feed_port = free_udp_port(&[go_port, go_port + 1]);

    let cfg = Config::default().with_buffer(Duration::from_millis(200));
    let mut receiver = listen(&format!("127.0.0.1:{go_port}"), cfg)
        .await
        .expect("listen for libRIST sender");

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "0".into(),
            "-b".into(),
            "200".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{go_port}"),
        ],
    );
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    let data = gen_data(N);
    let feed_data = data.clone();
    tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("bind feed");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("connect feed");
        for i in 0..N {
            let _ = feed.send(&feed_data[i * CHUNK..(i + 1) * CHUNK]).await;
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    });

    // Collect N payloads from the ristrust receiver.
    let mut got = Vec::with_capacity(N * CHUNK);
    for i in 0..N {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }

    receiver.close().await.expect("close");
    assert_eq!(got, data, "byte mismatch from the libRIST sender");
}
