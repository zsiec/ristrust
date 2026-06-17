//! Interop tests against the libRIST reference CLI tools (`ristsender` /
//! `ristreceiver`), Simple profile (VSF TR-06-1) — the byte-exact wire-interop
//! gate. Behind the `interop` feature so the default gauntlet never spawns
//! external processes:
//!
//! ```text
//! cargo test -p rist --features interop -- --nocapture
//! ```
//!
//! The tools are located via `$RISTGO_LIBRIST_TOOLS` (the libRIST `build/tools`
//! directory), then `$PATH`; each test skips (prints a notice and returns) when
//! they are absent, so the suite is safe to run anywhere.
//!
//! These two clean combos prove ristrust's Simple-profile RTP/RTCP is byte-exact
//! with libRIST both ways: ristrust → libRIST receiver, and libRIST sender →
//! ristrust. (The lossy combos that exercise the retransmit SSRC-toggle across
//! the wire build on these.)
#![cfg(feature = "interop")]
// Test-idiomatic lints: per-test `const RUN`/`const N` after `let` bindings, fake
// clock / index casts, and short loop/proxy variable names. Matches the allow
// blocks in the sim test files.
#![allow(
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::too_many_lines
)]

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rist::{
    AesKeyBits, Config, MergeMode, Profile, SplitMode, dial, dial_bonded, listen, listen_bonded,
};
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

/// Spawns a libRIST tool with its output silenced (or to `RIST_TOOL_LOG` when set,
/// for debugging).
fn spawn_tool(bin: &PathBuf, args: &[String]) -> ToolGuard {
    let mut cmd = Command::new(bin);
    cmd.args(args).stdout(Stdio::null());
    if let Ok(path) = std::env::var("RIST_TOOL_LOG") {
        let f = std::fs::File::create(&path).expect("tool log");
        cmd.stderr(Stdio::from(f));
    } else {
        cmd.stderr(Stdio::null());
    }
    ToolGuard(cmd.spawn().expect("spawn libRIST tool"))
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

// ---- lossy combos: the retransmit SSRC-toggle across the wire ----

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Datagrams per lossy run (more than the clean run, to ride out drops).
const LOSS_N: usize = 300;

/// A Simple-profile relay between a sender (which addresses the proxy) and a
/// receiver, dropping a fraction of forward MEDIA datagrams to force ARQ
/// recovery. RTCP is relayed reliably both ways, so NACKs and echoes always get
/// through — isolating recovery over a lossy media path. Ported from ristgo's
/// `lossyProxy`.
struct LossyProxy {
    dropped: std::sync::Arc<AtomicU64>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for LossyProxy {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl LossyProxy {
    /// Forward media datagrams dropped so far — a wire-independent witness that
    /// the loss path was exercised.
    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Binds the proxy on `proxy_port`/`proxy_port+1` and relays to the receiver on
/// `recv_port`/`recv_port+1`, dropping forward media with probability `loss`.
async fn start_lossy_proxy(proxy_port: u16, recv_port: u16, loss: f64, seed: u64) -> LossyProxy {
    let media = UdpSocket::bind(("127.0.0.1", proxy_port))
        .await
        .expect("proxy media bind");
    let rtcp = UdpSocket::bind(("127.0.0.1", proxy_port + 1))
        .await
        .expect("proxy rtcp bind");
    let recv_media: SocketAddr = format!("127.0.0.1:{recv_port}").parse().unwrap();
    let recv_rtcp: SocketAddr = format!("127.0.0.1:{}", recv_port + 1).parse().unwrap();
    let dropped = std::sync::Arc::new(AtomicU64::new(0));

    let media_dropped = dropped.clone();
    let media_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut s = seed;
        loop {
            let Ok((n, _src)) = media.recv_from(&mut buf).await else {
                return;
            };
            // SplitMix64 draw in [0, 1).
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            #[allow(clippy::cast_precision_loss)]
            let u = ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64;
            if u < loss {
                media_dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let _ = media.send_to(&buf[..n], recv_media).await;
        }
    });

    let rtcp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut sender_rtcp: Option<SocketAddr> = None;
        loop {
            let Ok((n, src)) = rtcp.recv_from(&mut buf).await else {
                return;
            };
            if src == recv_rtcp {
                if let Some(s) = sender_rtcp {
                    let _ = rtcp.send_to(&buf[..n], s).await;
                }
            } else {
                sender_rtcp = Some(src);
                let _ = rtcp.send_to(&buf[..n], recv_rtcp).await;
            }
        }
    });

    LossyProxy {
        dropped,
        tasks: vec![media_task, rtcp_task],
    }
}

/// A free even port distinct from `other`.
fn free_even_port_excluding(other: u16) -> u16 {
    loop {
        let p = free_even_port();
        if p != other {
            return p;
        }
    }
}

/// libRIST `ristsender` → lossy proxy → ristrust Receiver. libRIST retransmits on
/// ristrust's NACKs; ristrust must recognize libRIST's SSRC-LSB retransmits and
/// recover byte-exactly.
#[tokio::test]
async fn interop_ristrust_rx_lossy_recovery_from_librist_tx() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let go_port = free_even_port();
    let proxy_port = free_even_port_excluding(go_port);
    let feed_port = free_udp_port(&[go_port, go_port + 1, proxy_port, proxy_port + 1]);

    let cfg = Config::default().with_buffer(Duration::from_millis(700));
    let mut receiver = listen(&format!("127.0.0.1:{go_port}"), cfg)
        .await
        .expect("listen");
    let proxy = start_lossy_proxy(proxy_port, go_port, 0.10, 7).await;

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "0".into(),
            "-b".into(),
            "700".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{proxy_port}"),
        ],
    );
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    let data = gen_data(LOSS_N);
    let feed_data = data.clone();
    tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("feed bind");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("feed connect");
        for i in 0..LOSS_N {
            let _ = feed.send(&feed_data[i * CHUNK..(i + 1) * CHUNK]).await;
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        // Trailing flush so a dropped tail has a delivered successor to NACK.
        for _ in 0..24 {
            let _ = feed.send(&[0u8; CHUNK]).await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    let mut got = Vec::with_capacity(LOSS_N * CHUNK);
    for i in 0..LOSS_N {
        let payload = timeout(Duration::from_secs(25), receiver.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "timed out on payload {i} (dropped={}); ARQ recovery failed",
                    proxy.dropped()
                )
            })
            .expect("session open");
        got.extend_from_slice(&payload);
    }
    receiver.close().await.expect("close");

    assert_eq!(got, data, "lossy byte mismatch from libRIST sender");
    assert!(
        proxy.dropped() > 0,
        "proxy dropped no media — the loss/ARQ path was not exercised"
    );
}

/// ristrust Sender → lossy proxy → libRIST `ristreceiver`. ristrust retransmits
/// on libRIST's NACKs; libRIST must recognize ristrust's SSRC-LSB retransmits and
/// recover byte-exactly.
#[tokio::test]
async fn interop_librist_rx_lossy_recovery_from_ristrust_tx() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_even_port();
    let proxy_port = free_even_port_excluding(rx_port);
    let cap_port = free_udp_port(&[rx_port, rx_port + 1, proxy_port, proxy_port + 1]);

    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");
    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "0".into(),
            "-b".into(),
            "700".into(),
            "-i".into(),
            format!("rist://@127.0.0.1:{rx_port}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    let proxy = start_lossy_proxy(proxy_port, rx_port, 0.10, 9).await;
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let cfg = Config::default().with_buffer(Duration::from_millis(700));
    let sender = dial(&format!("127.0.0.1:{proxy_port}"), cfg)
        .await
        .expect("dial proxy");

    let data = std::sync::Arc::new(gen_data(LOSS_N));
    let send_data = data.clone();
    let send = tokio::spawn(async move {
        for i in 0..LOSS_N {
            sender
                .send(&send_data[i * CHUNK..(i + 1) * CHUNK])
                .await
                .expect("send");
            if i % 8 == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        for _ in 0..24 {
            sender.send(&[0u8; CHUNK]).await.expect("flush send");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        sender
    });

    let want = LOSS_N * CHUNK;
    let mut got = Vec::with_capacity(want);
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(25);
    while got.len() < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, cap.recv(&mut buf)).await {
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    let sender = send.await.expect("send task");
    sender.close().await.expect("close");

    assert!(
        got.len() >= want,
        "libRIST received {} of {want} bytes under loss",
        got.len()
    );
    assert_eq!(
        &got[..want],
        &data[..],
        "lossy byte mismatch at libRIST receiver"
    );
    assert!(
        proxy.dropped() > 0,
        "proxy dropped no media — the loss/ARQ path was not exercised"
    );
}

// ---- Main profile (VSF TR-06-2) PSK interop ----
//
// These clean combos prove ristrust's Main-profile GRE framing + PBKDF2/AES-CTR
// PSK is byte-exact with libRIST (`-p 1 -s <secret> -e <128|256>`) both ways, for
// each AES key size. Main multiplexes media and RTCP on one UDP port (no even/odd
// pair), so any free port works.

/// The pre-shared passphrase both ends derive their AES key from.
const MAIN_SECRET: &str = "ristrust-interop-secret";

/// A Main-profile PSK config: GRE tunnel, the shared secret, and the given key
/// size, with the buffer the libRIST tool is started with.
fn main_psk_cfg(bits: AesKeyBits, buffer_ms: u64) -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(buffer_ms))
        .with_secret(MAIN_SECRET)
        .with_aes_key_bits(bits)
}

/// ristrust Main Sender → libRIST `ristreceiver` (`-p 1`), PSK-encrypted. Proves
/// libRIST decrypts and decodes ristrust's GRE/AES-CTR output byte-exactly.
async fn main_librist_rx_from_ristrust_tx(bits: AesKeyBits, etype: &str) {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let cap_port = free_udp_port(&[rx_port]);

    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");
    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "1".into(),
            "-s".into(),
            MAIN_SECRET.into(),
            "-e".into(),
            etype.into(),
            "-b".into(),
            "200".into(),
            "-i".into(),
            format!("rist://@127.0.0.1:{rx_port}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let sender = dial(&format!("127.0.0.1:{rx_port}"), main_psk_cfg(bits, 200))
        .await
        .expect("dial libRIST main receiver");

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
        "libRIST main receiver got {} of {want} bytes ({etype}-bit)",
        got.len()
    );
    assert_eq!(
        got, *data,
        "byte mismatch at the libRIST main receiver ({etype}-bit)"
    );
}

/// libRIST `ristsender` (`-p 1`) → ristrust Main Receiver, PSK-encrypted. Proves
/// ristrust decrypts and decodes libRIST's GRE/AES-CTR output byte-exactly.
async fn main_ristrust_rx_from_librist_tx(bits: AesKeyBits, etype: &str) {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let feed_port = free_udp_port(&[rx_port]);

    let mut receiver = listen(&format!("127.0.0.1:{rx_port}"), main_psk_cfg(bits, 200))
        .await
        .expect("listen for libRIST main sender");

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "1".into(),
            "-s".into(),
            MAIN_SECRET.into(),
            "-e".into(),
            etype.into(),
            "-b".into(),
            "200".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{rx_port}"),
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

    let mut got = Vec::with_capacity(N * CHUNK);
    for i in 0..N {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i} ({etype}-bit)"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }

    receiver.close().await.expect("close");
    assert_eq!(
        got, data,
        "byte mismatch from the libRIST main sender ({etype}-bit)"
    );
}

#[tokio::test]
async fn interop_main_librist_rx_from_ristrust_tx_aes128() {
    main_librist_rx_from_ristrust_tx(AesKeyBits::Aes128, "128").await;
}

#[tokio::test]
async fn interop_main_librist_rx_from_ristrust_tx_aes256() {
    main_librist_rx_from_ristrust_tx(AesKeyBits::Aes256, "256").await;
}

#[tokio::test]
async fn interop_main_ristrust_rx_from_librist_tx_aes128() {
    main_ristrust_rx_from_librist_tx(AesKeyBits::Aes128, "128").await;
}

#[tokio::test]
async fn interop_main_ristrust_rx_from_librist_tx_aes256() {
    main_ristrust_rx_from_librist_tx(AesKeyBits::Aes256, "256").await;
}

// ---- Main profile EAP-SRP authentication interop ----
//
// These prove ristrust's EAP-SRP handshake (EAPOL/EAP framing + SRP-6a math + the
// post-auth passphrase exchange) interoperates with libRIST, and that authenticated
// media flows and decodes correctly. The data channel uses the combined PSK+SRP
// mode (the configured secret keys AES-256; SRP authenticates and gates). The
// libRIST sender carries credentials on the rist:// URL; the libRIST receiver
// verifies against an srpfile from `ristsrppasswd`.
//
// Media is verified by INDEX CONTIGUITY rather than a fixed byte prefix: each chunk
// carries a 4-byte big-endian index and a deterministic index-derived body, so the
// asserter proves the received stream is a contiguous, in-order, uncorrupted run —
// robust to the post-auth start offset and libRIST's playout buffering.

const SRP_USER: &str = "rist";
const SRP_PASS: &str = "mainprofile";

/// A Main-profile combined PSK + EAP-SRP config: the configured secret keys the
/// AES-256 data channel and the EAP-SRP handshake authenticates and gates it (the
/// libRIST-interoperable mode — libRIST sizes the receiver key from `-e`).
fn main_srp_cfg(buffer_ms: u64) -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(buffer_ms))
        .with_secret(MAIN_SECRET)
        .with_aes_key_bits(AesKeyBits::Aes256)
        .with_srp_credentials(SRP_USER, SRP_PASS)
}

/// One media chunk carrying its index (4-byte big-endian) and a deterministic
/// index-derived body, so a receiver can prove contiguity independent of where the
/// stream started.
fn indexed_chunk(i: u32) -> Vec<u8> {
    let mut c = vec![0u8; CHUNK];
    c[..4].copy_from_slice(&i.to_be_bytes());
    let mut x = i.wrapping_mul(2_654_435_761).wrapping_add(1);
    for b in &mut c[4..] {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    c
}

/// Asserts `stream` is a whole number of [`indexed_chunk`]s with strictly
/// contiguous increasing indices and exact bodies (no loss, reorder, dup, or
/// corruption), at least `min` chunks long.
fn assert_contiguous_chunks(stream: &[u8], min: usize, label: &str) {
    assert!(
        stream.len() >= min * CHUNK,
        "{label}: only {} of {} expected bytes (auth/decrypt failed)",
        stream.len(),
        min * CHUNK
    );
    assert_eq!(stream.len() % CHUNK, 0, "{label}: output not chunk-aligned");
    let chunks: Vec<&[u8]> = stream.chunks(CHUNK).collect();
    let first = u32::from_be_bytes([chunks[0][0], chunks[0][1], chunks[0][2], chunks[0][3]]);
    for (k, ch) in chunks.iter().enumerate() {
        let idx = first.wrapping_add(k as u32);
        assert_eq!(
            *ch,
            indexed_chunk(idx).as_slice(),
            "{label}: chunk {k} (index {idx}) mismatch — out of order or corrupt"
        );
    }
}

/// Writes an srpfile for `SRP_USER`/`SRP_PASS` via `ristsrppasswd`, returning its
/// path (kept alive by the returned guard), or `None` (skip) when the tool is
/// absent or fails.
fn make_srpfile() -> Option<(PathBuf, TempFileGuard)> {
    let tool = librist_tool("ristsrppasswd")?;
    let out = Command::new(&tool)
        .args([SRP_USER, SRP_PASS])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }
    let path = std::env::temp_dir().join(format!("ristrust-srp-{}.txt", std::process::id()));
    std::fs::write(&path, &out.stdout).ok()?;
    let guard = TempFileGuard(path.clone());
    Some((path, guard))
}

/// Deletes a temp file when dropped.
struct TempFileGuard(PathBuf);
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// libRIST `ristsender` (Main, SRP client) → ristrust Receiver (EAP-SRP
/// authenticator). Proves ristrust authenticates libRIST's SRP client and decrypts
/// its media correctly.
#[tokio::test]
async fn interop_main_srp_ristrust_rx_from_librist_tx() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let feed_port = free_udp_port(&[rx_port]);

    let mut receiver = listen(&format!("127.0.0.1:{rx_port}"), main_srp_cfg(300))
        .await
        .expect("listen for libRIST SRP sender");

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "1".into(),
            "-s".into(),
            MAIN_SECRET.into(),
            "-e".into(),
            "256".into(),
            "-b".into(),
            "300".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{rx_port}?username={SRP_USER}&password={SRP_PASS}"),
        ],
    );
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    // Continuously feed indexed chunks; libRIST forwards them once authenticated.
    let feeder = tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("bind feed");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("connect feed");
        let mut i: u32 = 0;
        loop {
            if feed.send(&indexed_chunk(i)).await.is_err() {
                return;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    // Collect a contiguous run of recovered chunks.
    const RUN: usize = 100;
    let mut got = Vec::with_capacity(RUN * CHUNK);
    for i in 0..RUN {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on SRP payload {i}; auth failed"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }
    feeder.abort();
    receiver.close().await.expect("close");
    assert_contiguous_chunks(&got, RUN, "libRIST SRP sender -> ristrust");
}

/// ristrust Sender (Main, SRP client) → libRIST `ristreceiver` (EAP-SRP
/// authenticator with an srpfile). Proves libRIST authenticates ristrust's SRP
/// client and decrypts its media correctly.
#[tokio::test]
async fn interop_main_srp_librist_rx_from_ristrust_tx() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let Some((srpfile, _guard)) = make_srpfile() else {
        eprintln!("interop: ristsrppasswd unavailable; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let cap_port = free_udp_port(&[rx_port]);

    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");
    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "1".into(),
            "-s".into(),
            MAIN_SECRET.into(),
            "-e".into(),
            "256".into(),
            "-b".into(),
            "300".into(),
            "-F".into(),
            srpfile.to_string_lossy().into_owned(),
            "-i".into(),
            format!("rist://@127.0.0.1:{rx_port}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let sender = dial(&format!("127.0.0.1:{rx_port}"), main_srp_cfg(300))
        .await
        .expect("dial libRIST SRP receiver");

    // Stream indexed chunks continuously; SRP gates until authenticated, then they
    // flow. libRIST outputs whole chunks to the capture socket.
    let send = tokio::spawn(async move {
        let mut i: u32 = 0;
        loop {
            if sender.send(&indexed_chunk(i)).await.is_err() {
                return sender;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 100;
    let want = RUN * CHUNK;
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
    send.abort();
    assert_contiguous_chunks(&got, RUN, "ristrust SRP sender -> libRIST");
}

// ---- Advanced profile (VSF TR-06-3) interop (libRIST -p 2) ----
//
// The Advanced profile is a GRE-substrate hybrid: a raw Main-profile GRE RTCP-SDES
// handshake under the PT=127 adv framing (Type=5 media, Type=4 control). These
// prove ristrust's adv header/control codec, the AES-CTR payload path, and the
// hybrid driver interoperate with libRIST `-p 2`, with authenticated/encrypted
// media flowing and decoding. Media is verified by contiguous indexed chunks.

/// An Advanced-profile interop config (the combined PSK keys the data; SRP gates).
fn adv_interop_cfg(secret: Option<&str>) -> Config {
    let mut cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_buffer(Duration::from_millis(300));
    if let Some(s) = secret {
        cfg = cfg.with_secret(s).with_aes_key_bits(AesKeyBits::Aes256);
    }
    cfg
}

/// ristrust Advanced Sender → libRIST `ristreceiver -p 2`. Proves libRIST decodes
/// ristrust's adv-framed media.
async fn adv_librist_rx_from_ristrust_tx(secret: Option<&str>) {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let cap_port = free_udp_port(&[rx_port]);
    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");

    let mut args = vec![
        "-p".into(),
        "2".into(),
        "-b".into(),
        "300".into(),
        "-i".into(),
        format!("rist://@127.0.0.1:{rx_port}"),
        "-o".into(),
        format!("udp://127.0.0.1:{cap_port}"),
    ];
    if let Some(s) = secret {
        args.extend(["-s".into(), s.into(), "-e".into(), "256".into()]);
    }
    let _tool = spawn_tool(&receiver_bin, &args);
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let sender = dial(&format!("127.0.0.1:{rx_port}"), adv_interop_cfg(secret))
        .await
        .expect("dial libRIST adv receiver");
    let send = tokio::spawn(async move {
        let mut i: u32 = 0;
        loop {
            if sender.send(&indexed_chunk(i)).await.is_err() {
                return sender;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 100;
    let want = RUN * CHUNK;
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
    send.abort();
    assert_contiguous_chunks(&got, RUN, "ristrust adv sender -> libRIST");
}

/// libRIST `ristsender -p 2` → ristrust Advanced Receiver. Proves ristrust decodes
/// libRIST's adv-framed media.
async fn adv_ristrust_rx_from_librist_tx(secret: Option<&str>) {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let feed_port = free_udp_port(&[rx_port]);

    let mut receiver = listen(&format!("127.0.0.1:{rx_port}"), adv_interop_cfg(secret))
        .await
        .expect("listen for libRIST adv sender");

    let mut args = vec![
        "-p".into(),
        "2".into(),
        "-b".into(),
        "300".into(),
        "-i".into(),
        format!("udp://@127.0.0.1:{feed_port}"),
        "-o".into(),
        format!("rist://127.0.0.1:{rx_port}"),
    ];
    if let Some(s) = secret {
        args.extend(["-s".into(), s.into(), "-e".into(), "256".into()]);
    }
    let _tool = spawn_tool(&sender_bin, &args);
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    let feeder = tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("bind feed");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("connect feed");
        let mut i: u32 = 0;
        loop {
            if feed.send(&indexed_chunk(i)).await.is_err() {
                return;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    const RUN: usize = 100;
    let mut got = Vec::with_capacity(RUN * CHUNK);
    for i in 0..RUN {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on adv payload {i}"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }
    feeder.abort();
    receiver.close().await.expect("close");
    assert_contiguous_chunks(&got, RUN, "libRIST adv sender -> ristrust");
}

#[tokio::test]
async fn interop_adv_librist_rx_from_ristrust_tx_clear() {
    adv_librist_rx_from_ristrust_tx(None).await;
}

#[tokio::test]
async fn interop_adv_ristrust_rx_from_librist_tx_clear() {
    adv_ristrust_rx_from_librist_tx(None).await;
}

#[tokio::test]
async fn interop_adv_librist_rx_from_ristrust_tx_aes256() {
    adv_librist_rx_from_ristrust_tx(Some(MAIN_SECRET)).await;
}

#[tokio::test]
async fn interop_adv_ristrust_rx_from_librist_tx_aes256() {
    adv_ristrust_rx_from_librist_tx(Some(MAIN_SECRET)).await;
}

/// A compressible indexed chunk: a 4-byte index then a run of one repeated byte
/// (so the LZ4 path actually shrinks it on the wire).
fn compressible_chunk(i: u32) -> Vec<u8> {
    let mut c = vec![(i & 0xFF) as u8; CHUNK];
    c[..4].copy_from_slice(&i.to_be_bytes());
    c
}

fn assert_contiguous_compressible(stream: &[u8], min: usize, label: &str) {
    assert!(
        stream.len() >= min * CHUNK,
        "{label}: only {} bytes",
        stream.len()
    );
    assert_eq!(stream.len() % CHUNK, 0, "{label}: not chunk-aligned");
    let chunks: Vec<&[u8]> = stream.chunks(CHUNK).collect();
    let first = u32::from_be_bytes([chunks[0][0], chunks[0][1], chunks[0][2], chunks[0][3]]);
    for (k, ch) in chunks.iter().enumerate() {
        let idx = first.wrapping_add(k as u32);
        assert_eq!(
            *ch,
            compressible_chunk(idx).as_slice(),
            "{label}: chunk {k} mismatch"
        );
    }
}

/// ristrust Advanced Sender with LZ4 compression → libRIST `ristreceiver -p 2`.
/// Proves libRIST decompresses ristrust's LZ4-compressed adv media.
#[tokio::test]
async fn interop_adv_librist_rx_from_ristrust_tx_lz4() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let cap_port = free_udp_port(&[rx_port]);
    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");

    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "2".into(),
            "-b".into(),
            "300".into(),
            "-i".into(),
            format!("rist://@127.0.0.1:{rx_port}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_buffer(Duration::from_millis(300))
        .with_compression(true);
    let sender = dial(&format!("127.0.0.1:{rx_port}"), cfg)
        .await
        .expect("dial");
    let send = tokio::spawn(async move {
        let mut i: u32 = 0;
        loop {
            if sender.send(&compressible_chunk(i)).await.is_err() {
                return sender;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 100;
    let want = RUN * CHUNK;
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
    send.abort();
    assert_contiguous_compressible(&got, RUN, "ristrust LZ4 adv sender -> libRIST");
}

/// A single-UDP-port lossy relay between a sender (which addresses the proxy) and a
/// receiver, dropping a fraction of forward MEDIA datagrams (those larger than 128
/// bytes) to force ARQ recovery. Control (NACK/echo/keepalive) and the reverse
/// direction relay reliably. For the Main/Advanced single-port profiles.
async fn start_single_port_lossy_proxy(
    proxy_port: u16,
    recv_port: u16,
    loss: f64,
    seed: u64,
) -> LossyProxy {
    let sock = UdpSocket::bind(("127.0.0.1", proxy_port))
        .await
        .expect("proxy bind");
    let recv_addr: SocketAddr = format!("127.0.0.1:{recv_port}").parse().unwrap();
    let dropped = std::sync::Arc::new(AtomicU64::new(0));
    let d = dropped.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut sender_addr: Option<SocketAddr> = None;
        let mut s = seed;
        loop {
            let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if src == recv_addr {
                if let Some(sa) = sender_addr {
                    let _ = sock.send_to(&buf[..n], sa).await;
                }
            } else {
                sender_addr = Some(src);
                if n > 128 {
                    s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
                    let mut z = s;
                    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                    #[allow(clippy::cast_precision_loss)]
                    let u = ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64;
                    if u < loss {
                        d.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                let _ = sock.send_to(&buf[..n], recv_addr).await;
            }
        }
    });
    LossyProxy {
        dropped,
        tasks: vec![task],
    }
}

/// ristrust Advanced Sender → single-port lossy proxy → libRIST `ristreceiver -p 2`.
/// libRIST NACKs the dropped adv media; ristrust retransmits and libRIST recovers.
#[tokio::test]
async fn interop_adv_librist_rx_lossy_recovery_from_ristrust_tx() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let proxy_port = free_udp_port(&[rx_port]);
    let cap_port = free_udp_port(&[rx_port, proxy_port]);
    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");

    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "2".into(),
            "-b".into(),
            "700".into(),
            "-i".into(),
            format!("rist://@127.0.0.1:{rx_port}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    let proxy = start_single_port_lossy_proxy(proxy_port, rx_port, 0.10, 0x5151).await;
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_buffer(Duration::from_millis(700));
    let sender = dial(&format!("127.0.0.1:{proxy_port}"), cfg)
        .await
        .expect("dial proxy");
    let send = tokio::spawn(async move {
        let mut i: u32 = 0;
        loop {
            if sender.send(&indexed_chunk(i)).await.is_err() {
                return sender;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 120;
    let want = RUN * CHUNK;
    let mut got = Vec::with_capacity(want);
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(25);
    while got.len() < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, cap.recv(&mut buf)).await {
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    send.abort();
    assert_contiguous_chunks(&got, RUN, "ristrust adv sender -> lossy -> libRIST");
    assert!(
        proxy.dropped() > 0,
        "proxy dropped no media — loss/ARQ path not exercised"
    );
}

/// libRIST `ristsender -p 2` → single-port lossy proxy → ristrust Advanced
/// Receiver. ristrust NACKs the dropped adv media; libRIST retransmits and ristrust
/// recovers byte-correct.
#[tokio::test]
async fn interop_adv_ristrust_rx_lossy_recovery_from_librist_tx() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let proxy_port = free_udp_port(&[rx_port]);
    let feed_port = free_udp_port(&[rx_port, proxy_port]);

    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_buffer(Duration::from_millis(700));
    let mut receiver = listen(&format!("127.0.0.1:{rx_port}"), cfg)
        .await
        .expect("listen");
    let proxy = start_single_port_lossy_proxy(proxy_port, rx_port, 0.10, 0x6262).await;

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "2".into(),
            "-b".into(),
            "700".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{proxy_port}"),
        ],
    );
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    let feeder = tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("bind feed");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("connect feed");
        let mut i: u32 = 0;
        loop {
            if feed.send(&indexed_chunk(i)).await.is_err() {
                return;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 120;
    let mut got = Vec::with_capacity(RUN * CHUNK);
    for i in 0..RUN {
        let payload = timeout(Duration::from_secs(25), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on lossy adv payload {i}"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }
    feeder.abort();
    receiver.close().await.expect("close");
    assert_contiguous_chunks(&got, RUN, "libRIST adv sender -> lossy -> ristrust");
    assert!(
        proxy.dropped() > 0,
        "proxy dropped no media — loss/ARQ path not exercised"
    );
}

// ---- SMPTE 2022-7 bonding interop (Main profile, weight=0 full redundancy) ----
//
// The bonding gate: a libRIST sender duplicating each packet across two weight=0
// output peers feeds a ristrust *bonded* receiver listening on both ports, which
// merges the redundant copies into one in-order stream (the `(seq, source_time)`
// dedup). The clean case proves the merge/dedup over the wire; the one-path media
// blackhole proves seamless redundancy (one path's media fully lost, the other
// carries the stream with no gap). The reverse direction drives a ristrust bonded
// sender into a libRIST receiver bonding two inputs.

/// A Main-profile config for bonded interop.
fn bonded_main_cfg(buffer_ms: u64) -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(buffer_ms))
}

/// libRIST `ristsender` (`-p 1`) with two `weight=0` output peers → ristrust bonded
/// Receiver merging both ports. Proves ristrust dedups the redundant 2022-7 copies
/// into one contiguous stream.
#[tokio::test]
async fn interop_bonded_ristrust_rx_two_weight0_from_librist_tx() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let p0 = free_udp_port(&[]);
    let p1 = free_udp_port(&[p0]);
    let feed_port = free_udp_port(&[p0, p1]);

    let addrs = [format!("127.0.0.1:{p0}"), format!("127.0.0.1:{p1}")];
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let mut receiver = listen_bonded(&refs, bonded_main_cfg(300))
        .await
        .expect("listen_bonded for libRIST 2022-7 sender");

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "1".into(),
            "-b".into(),
            "300".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{p0}?weight=0,rist://127.0.0.1:{p1}?weight=0"),
        ],
    );
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    let feeder = tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("bind feed");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("connect feed");
        let mut i: u32 = 0;
        loop {
            if feed.send(&indexed_chunk(i)).await.is_err() {
                return;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 100;
    let mut got = Vec::with_capacity(RUN * CHUNK);
    for i in 0..RUN {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on bonded payload {i}"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }
    feeder.abort();
    receiver.close().await.expect("close");
    assert_contiguous_chunks(&got, RUN, "libRIST 2022-7 weight=0 x2 -> ristrust bonded");
}

/// libRIST `ristsender` (`-p 1`) with two `weight=0` peers, one path's forward media
/// entirely blackholed by a single-port lossy proxy (control still flows) → ristrust
/// bonded Receiver. The surviving path must carry the whole stream with no gap:
/// seamless SMPTE 2022-7 redundancy across the wire.
#[tokio::test]
async fn interop_bonded_ristrust_rx_seamless_one_path_blackhole() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let p0 = free_udp_port(&[]); // healthy path
    let p1 = free_udp_port(&[p0]); // blackholed path (behind the proxy)
    let proxy_port = free_udp_port(&[p0, p1]);
    let feed_port = free_udp_port(&[p0, p1, proxy_port]);

    let addrs = [format!("127.0.0.1:{p0}"), format!("127.0.0.1:{p1}")];
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let mut receiver = listen_bonded(&refs, bonded_main_cfg(500))
        .await
        .expect("listen_bonded");

    // The proxy fronts path 1: it relays control both ways but drops 100% of forward
    // media (> 128 B), so libRIST keeps duplicating to path 1 while none of its media
    // arrives — path 0 must cover it.
    let proxy = start_single_port_lossy_proxy(proxy_port, p1, 1.0, 0xB07D).await;

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "1".into(),
            "-b".into(),
            "500".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            format!("rist://127.0.0.1:{p0}?weight=0,rist://127.0.0.1:{proxy_port}?weight=0"),
        ],
    );
    wait_tool_ready(feed_port, Duration::from_secs(5)).await;

    let feeder = tokio::spawn(async move {
        let feed = UdpSocket::bind("127.0.0.1:0").await.expect("bind feed");
        feed.connect(("127.0.0.1", feed_port))
            .await
            .expect("connect feed");
        let mut i: u32 = 0;
        loop {
            if feed.send(&indexed_chunk(i)).await.is_err() {
                return;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 100;
    let mut got = Vec::with_capacity(RUN * CHUNK);
    for i in 0..RUN {
        let payload = timeout(Duration::from_secs(25), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on seamless payload {i}"))
            .expect("session open");
        got.extend_from_slice(&payload);
    }
    feeder.abort();
    receiver.close().await.expect("close");
    assert_contiguous_chunks(
        &got,
        RUN,
        "libRIST 2022-7 one-path blackhole -> ristrust bonded",
    );
    assert!(
        proxy.dropped() > 0,
        "proxy dropped no media — the blackholed path was never exercised"
    );
}

/// ristrust bonded Sender (two weight=0 paths) → libRIST `ristreceiver` (`-p 1`)
/// bonding two inputs. libRIST merges the redundant copies and outputs the original
/// byte stream. Proves ristrust's full-redundancy fan-out interoperates as a 2022-7
/// source.
#[tokio::test]
async fn interop_bonded_librist_rx_from_ristrust_tx() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let p0 = free_udp_port(&[]);
    let p1 = free_udp_port(&[p0]);
    let cap_port = free_udp_port(&[p0, p1]);
    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");

    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "1".into(),
            "-b".into(),
            "300".into(),
            "-i".into(),
            format!("rist://@127.0.0.1:{p0},rist://@127.0.0.1:{p1}"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    // Give the libRIST receiver a moment to bind both input ports.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let addrs = [format!("127.0.0.1:{p0}"), format!("127.0.0.1:{p1}")];
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded(&refs, bonded_main_cfg(300))
        .await
        .expect("dial_bonded the libRIST receiver");

    // Stream indexed chunks; capture libRIST's merged UDP output and assert it is a
    // contiguous, deduplicated run.
    let sender_task = tokio::spawn(async move {
        let mut i: u32 = 0;
        loop {
            if sender.send(&indexed_chunk(i)).await.is_err() {
                return sender;
            }
            i = i.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    const RUN: usize = 80;
    let mut got = Vec::with_capacity(RUN * CHUNK);
    let mut buf = vec![0u8; 2048];
    for i in 0..RUN {
        let (n, _) = timeout(Duration::from_secs(20), cap.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timed out on libRIST merged output {i}"))
            .expect("capture recv");
        got.extend_from_slice(&buf[..n]);
    }
    sender_task.abort();
    assert_contiguous_chunks(&got, RUN, "ristrust bonded -> libRIST 2022-7 merge");
}

// ---- packet split/merge bonding (libRIST split=/merge=) ----
//
// Cleartext Main profile (`-p 1`). One side splits each payload across an even/odd
// sequence pair (same source time); the other recombines it. Proves ristrust's split
// is what libRIST's merge expects, and ristrust's merge recombines libRIST's split —
// byte-exact, and provably merged (not delivered as orphan halves).

/// A cleartext Main config with the given buffer.
fn main_clear_cfg(buffer_ms: u64) -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(buffer_ms))
}

/// libRIST `ristsender` (`-p 1`, `split=auto`) → ristrust Main Receiver (`merge=pairs`).
/// Proves ristrust's `Merger` recombines libRIST's real split output byte-exactly: with
/// merge active, N sends yield exactly N full-CHUNK deliveries equal to the input (a
/// failed merge would surface 2N half-CHUNK orphans and the byte stream would not line
/// up across N reads).
#[tokio::test]
async fn interop_split_ristrust_merge_from_librist_split() {
    let Some(sender_bin) = librist_tool("ristsender") else {
        eprintln!("interop: ristsender not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let feed_port = free_udp_port(&[rx_port]);

    let cfg = main_clear_cfg(200).with_merge_mode(MergeMode::Pairs);
    let mut receiver = listen(&format!("127.0.0.1:{rx_port}"), cfg)
        .await
        .expect("listen for libRIST split sender");

    let _tool = spawn_tool(
        &sender_bin,
        &[
            "-p".into(),
            "1".into(),
            "-b".into(),
            "200".into(),
            "-i".into(),
            format!("udp://@127.0.0.1:{feed_port}"),
            "-o".into(),
            // libRIST spells the split mode as a word (off|auto|half), not a number.
            format!("rist://127.0.0.1:{rx_port}?split=auto"),
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

    // N reads must reconstruct the whole stream: each read is a merged full CHUNK.
    let mut got = Vec::with_capacity(N * CHUNK);
    for i in 0..N {
        let payload = timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on merged payload {i}"))
            .expect("session open");
        assert_eq!(
            payload.len(),
            CHUNK,
            "payload {i} was not a recombined full chunk (merge failed)"
        );
        got.extend_from_slice(&payload);
    }

    receiver.close().await.expect("close");
    assert_eq!(got, data, "byte mismatch merging libRIST's split output");
}

/// ristrust Main Sender (`split=auto`) → libRIST `ristreceiver` (`-p 1`, `merge=pairs`).
/// Proves libRIST recombines ristrust's split pairs: the captured UDP output is the
/// original byte stream AND arrives as N full-CHUNK datagrams (a failed merge would
/// surface ~2N half-CHUNK datagrams).
#[tokio::test]
async fn interop_split_librist_merge_from_ristrust_split() {
    let Some(receiver_bin) = librist_tool("ristreceiver") else {
        eprintln!("interop: ristreceiver not found; skipping");
        return;
    };
    let rx_port = free_udp_port(&[]);
    let cap_port = free_udp_port(&[rx_port]);

    let cap = UdpSocket::bind(("127.0.0.1", cap_port))
        .await
        .expect("bind capture");
    let _tool = spawn_tool(
        &receiver_bin,
        &[
            "-p".into(),
            "1".into(),
            "-b".into(),
            "200".into(),
            "-i".into(),
            // libRIST spells the merge mode as a word (off|pairs|auto), not a number.
            format!("rist://@127.0.0.1:{rx_port}?merge=pairs"),
            "-o".into(),
            format!("udp://127.0.0.1:{cap_port}"),
        ],
    );
    wait_tool_ready(rx_port, Duration::from_secs(5)).await;

    let sender = dial(
        &format!("127.0.0.1:{rx_port}"),
        main_clear_cfg(200).with_split_mode(SplitMode::Auto),
    )
    .await
    .expect("dial libRIST merge receiver");

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

    // Count merged output datagrams: each full CHUNK is one recombined pair.
    let want = N * CHUNK;
    let mut got = Vec::with_capacity(want);
    let mut datagrams = 0usize;
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(20);
    while got.len() < want {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, cap.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                datagrams += 1;
                got.extend_from_slice(&buf[..n]);
            }
            _ => break,
        }
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close");

    assert_eq!(
        got.len(),
        want,
        "libRIST merged {} of {want} bytes",
        got.len()
    );
    assert_eq!(got, *data, "byte mismatch at the libRIST merge receiver");
    // Merge recombines each split pair, so the original chunk count comes back; an
    // unmerged stream would deliver about twice as many (half-size) datagrams.
    assert!(
        datagrams <= N + N / 8,
        "libRIST delivered {datagrams} datagrams for {N} payloads — split pairs were not merged"
    );
}
