//! End-to-end SMPTE ST 2022-1 forward-error-correction loopback (WP18c–18e):
//! a real `Sender` carries FEC-protected media to a real `Receiver` and a dropped
//! media packet is reconstructed by FEC — with NO ARQ round trip.
//!
//! Each recovery test runs in **one-way mode** (`with_one_way`), which disables the
//! NACK/retransmit plane entirely, so the only way a dropped packet can reach the
//! application is FEC recovery: if the byte-exact in-order stream survives a dropped
//! media datagram, FEC did it. Coverage: Advanced in-band (Type=Control, full
//! datagram, over-MTU fragmented control), Simple separate-port, Main separate-port,
//! and Main separate-port composed with null-packet deletion (the §8.6.2
//! canonicalization). FEC is carried as standard ST 2022-1 RTP on the dedicated
//! column (media + 2) / row (media + 4) ports — the GStreamer/FFmpeg carriage.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rist::{
    AsyncUdpSocket, Config, FecConfig, FecVariant, Profile, Receiver, Runtime, TokioRuntime,
    dial_bonded_with, dial_with, listen, listen_bonded,
};

/// The media index dropped in every recovery test — a row-interior packet, mid-stream
/// (matrix 1 of a 4-column matrix), away from the first-matrix anchor and the tail.
const DROP_AT: u64 = 21;

/// A 2-D FEC matrix that recovers any single loss quickly (the row FEC completes
/// within `columns` packets).
fn fec_2d() -> FecConfig {
    FecConfig {
        columns: 4,
        rows: 4,
        column_only: false,
        carriage: rist::FecCarriage::Default,
        variant: FecVariant::St20221,
    }
}

/// `n` distinct text payloads built from `body` (sized to control fragmentation).
fn text_payloads(n: usize, body: &str) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("fec-{i:05}-{body}").into_bytes())
        .collect()
}

/// Binds a receiver on an OS-chosen free even port (FEC needs the +2/+4 ports free).
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let mut candidate = probe.local_addr().expect("probe addr").port();
        drop(probe);
        // Simple/Main FEC needs an even media port (RTCP at +1, FEC at +2/+4).
        if !candidate.is_multiple_of(2) {
            candidate = candidate.wrapping_sub(1);
        }
        // The caller binds neighbour ports up to +4 (RTCP +1, column FEC +2, row FEC
        // +4), so +4 must stay a valid port — reject the top of the range, which would
        // otherwise wrap and fail the neighbour bind with "invalid argument".
        if !(2..=65_531).contains(&candidate) {
            continue;
        }
        if let Ok(r) = listen(&format!("127.0.0.1:{candidate}"), cfg.clone()).await {
            return (r, candidate);
        }
    }
    panic!("no free port for the receiver");
}

/// A predicate deciding whether to drop a given outbound datagram (true = drop).
type DropPred = Arc<dyn Fn(&[u8], SocketAddr) -> bool + Send + Sync>;

/// Drops exactly the [`DROP_AT`]-th Advanced DIRECT (Type=5) media datagram, never the
/// Type=4 FEC control or the Type=8 GRE substrate (identified by encapsulation type).
fn adv_media_pred() -> DropPred {
    let seen = Arc::new(AtomicU64::new(0));
    Arc::new(move |buf: &[u8], _dst| {
        if let Ok(p) = rist_codec::adv::parse(&Bytes::copy_from_slice(buf))
            && p.enc_type == rist_codec::adv::TYPE_DIRECT
        {
            return seen.fetch_add(1, Ordering::Relaxed) == DROP_AT;
        }
        false
    })
}

/// Drops exactly the [`DROP_AT`]-th datagram sent to the media `port` (Simple/Main
/// media), never the FEC on +2/+4 or the RTCP on +1.
fn port_media_pred(port: u16) -> DropPred {
    let seen = Arc::new(AtomicU64::new(0));
    Arc::new(move |_buf: &[u8], dst: SocketAddr| {
        if dst.port() == port {
            return seen.fetch_add(1, Ordering::Relaxed) == DROP_AT;
        }
        false
    })
}

/// A [`Runtime`] whose sockets drop datagrams for which `pred` returns true (applied
/// to the sender's transport only).
struct DropRuntime {
    pred: DropPred,
    dropped: Arc<AtomicU64>,
}

impl Runtime for DropRuntime {
    fn now(&self) -> Instant {
        TokioRuntime.now()
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        TokioRuntime.spawn(future);
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        TokioRuntime.sleep_until(deadline)
    }
    fn bind(&self, addr: SocketAddr) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(Arc::new(DropSocket {
            inner: TokioRuntime.bind(addr)?,
            pred: Arc::clone(&self.pred),
            dropped: Arc::clone(&self.dropped),
        }))
    }
}

struct DropSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    pred: DropPred,
    dropped: Arc<AtomicU64>,
}

// The predicate closure is opaque; a manual Debug keeps the socket printable.
impl std::fmt::Debug for DropSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for DropSocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if (self.pred)(buf, dest) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(buf.len())); // report success without transmitting
        }
        self.inner.poll_send(cx, buf, dest)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.inner.poll_recv(cx, buf)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// Runs a one-way FEC stream of `payloads` from a `DropRuntime`-wrapped sender to a
/// lossless receiver, asserting every payload (including the FEC-dropped one) arrives
/// in order, byte-exact, and that the drop actually fired. `make_pred` builds the drop
/// predicate from the receiver's media port (so a port-targeting predicate can use it).
async fn run_fec_recovery(
    cfg: Config,
    payloads: Vec<Vec<u8>>,
    make_pred: impl FnOnce(u16) -> DropPred,
) {
    let (mut receiver, port) = listen_free(&cfg).await;
    let dropped = Arc::new(AtomicU64::new(0));
    let rt = DropRuntime {
        pred: make_pred(port),
        dropped: Arc::clone(&dropped),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &rt)
        .await
        .expect("dial with the dropping runtime");

    let send_payloads = payloads.clone();
    let send_task = tokio::spawn(async move {
        for p in &send_payloads {
            sender.send(p).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Hold the sender open while the receiver drains (one-way: no close handshake).
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
    });

    for (i, want) in payloads.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}: FEC recovery did not converge"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            want.as_slice(),
            "payload {i} out of order or corrupt"
        );
    }

    assert!(
        dropped.load(Ordering::Relaxed) >= 1,
        "no media dropped — the FEC recovery path was not exercised"
    );

    let sender = send_task.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn adv_in_band_fec_recovers_a_dropped_media_packet() {
    // Advanced in-band: drop one DIRECT media datagram; the Type=4 FEC control survives
    // and reconstructs it. The ~1400-byte body makes the full-datagram FEC control
    // exceed the MTU cap, so each FEC packet is FRAGMENTED across two control packets
    // and the receiver must reassemble them (the fecCtrlReassembler path).
    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());
    run_fec_recovery(cfg, text_payloads(64, &"x".repeat(1400)), |_port| {
        adv_media_pred()
    })
    .await;
}

#[tokio::test]
async fn simple_separate_port_fec_recovers_a_dropped_media_packet() {
    // Simple separate-port: drop one media datagram (media port); the FEC RTP on the
    // column/row ports (+2/+4) survives and reconstructs it.
    let cfg = Config::default()
        .with_profile(Profile::Simple)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());
    run_fec_recovery(cfg, text_payloads(64, "simple-fec"), port_media_pred).await;
}

#[tokio::test]
async fn main_separate_port_fec_recovers_a_dropped_media_packet() {
    // Main separate-port: the GRE port carries media (one-way → no handshake), the FEC
    // RTP rides the +2/+4 ports. Drop one GRE-port media datagram; FEC recovers it.
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());
    run_fec_recovery(cfg, text_payloads(64, "main-fec"), port_media_pred).await;
}

// ---- Main FEC composed with null-packet deletion (TR-06-2 §8.6.2) ----

/// Bytes per MPEG-TS packet; TS packets per RTP media frame.
const TS: usize = 188;
const PER_FRAME: usize = 7;

/// One MPEG-TS null packet exactly as the receiver reconstructs it, so a payload whose
/// nulls are already canonical round-trips byte-exact through NPD suppress/expand.
fn canonical_null_ts() -> [u8; TS] {
    let mut p = [0xFFu8; TS];
    p[0] = 0x47;
    p[1] = 0x1F;
    p[2] = 0xFF;
    p[3] = 0x10;
    p
}

/// One non-null MPEG-TS packet with a seq-derived fill so distinct frames differ.
#[allow(clippy::cast_possible_truncation)]
fn content_ts(seq: usize) -> [u8; TS] {
    let mut p = [0u8; TS];
    p[0] = 0x47;
    p[1] = 0x01;
    p[2] = 0x00;
    p[3] = 0x10;
    for (i, b) in p.iter_mut().enumerate().skip(4) {
        *b = (seq * 31 + i) as u8;
    }
    p
}

/// `frames` MPEG-TS media frames (one content + six canonical-null TS packets each).
fn ts_frames(frames: usize) -> Vec<Vec<u8>> {
    (0..frames)
        .map(|f| {
            let content = f % PER_FRAME;
            let mut frame = Vec::with_capacity(TS * PER_FRAME);
            for i in 0..PER_FRAME {
                if i == content {
                    frame.extend_from_slice(&content_ts(f));
                } else {
                    frame.extend_from_slice(&canonical_null_ts());
                }
            }
            frame
        })
        .collect()
}

#[tokio::test]
async fn main_fec_with_npd_recovers_a_dropped_frame() {
    // FEC composes with null-packet deletion: the sender suppresses nulls on the media
    // wire but computes FEC over the canonicalized (suppress→expand) payload, which is
    // exactly what the receiver reconstructs (§8.6.2). A dropped media frame is then
    // recovered byte-exact even though the media and FEC carry different byte counts.
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_one_way(true)
        .with_null_packet_deletion(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());
    run_fec_recovery(cfg, ts_frames(64), port_media_pred).await;
}

/// Binds an `n`-path bonded receiver on distinct OS-chosen even ports (FEC needs the
/// +2/+4 ports per path free), returning the receiver and the path address strings.
async fn listen_free_bonded(cfg: &Config, n: usize) -> (Receiver, Vec<String>) {
    'attempt: for _ in 0..64 {
        let mut ports = Vec::with_capacity(n);
        for _ in 0..n {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
            let mut p = probe.local_addr().expect("probe addr").port();
            drop(probe);
            if !p.is_multiple_of(2) {
                p = p.wrapping_sub(1);
            }
            // Each bonded path binds neighbour FEC ports up to +4 (column +2, row +4),
            // so +4 must stay valid — reject the top of the range.
            if !(2..=65_531).contains(&p) || ports.contains(&p) {
                continue 'attempt;
            }
            ports.push(p);
        }
        let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
        let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        if let Ok(r) = listen_bonded(&refs, cfg.clone()).await {
            return (r, addrs);
        }
    }
    panic!("no free ports for the bonded receiver");
}

/// Drops both copies (every path) of media sequence [`DROP_AT`] — a correlated loss
/// 2022-7 duplication cannot cover. The sender fans each sequence to both paths
/// consecutively, so the two datagrams of sequence K are at media-count 2K and 2K+1.
fn bonded_correlated_pred(media_ports: Vec<u16>) -> DropPred {
    let seen = Arc::new(AtomicU64::new(0));
    Arc::new(move |_buf: &[u8], dst: SocketAddr| {
        if media_ports.contains(&dst.port()) {
            let n = seen.fetch_add(1, Ordering::Relaxed);
            return n == 2 * DROP_AT || n == 2 * DROP_AT + 1;
        }
        false
    })
}

#[tokio::test]
async fn bonded_fec_recovers_correlated_loss() {
    // The case bonding alone cannot handle: a media sequence lost on EVERY path at
    // once. 2022-7 duplication has no surviving copy, so only FEC (fanned across the
    // same paths, feeding the one shared decoder) can recover it. One-way (no ARQ).
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());
    let (mut receiver, addrs) = listen_free_bonded(&cfg, 2).await;
    let media_ports: Vec<u16> = addrs
        .iter()
        .map(|a| a.parse::<SocketAddr>().expect("addr").port())
        .collect();
    let dropped = Arc::new(AtomicU64::new(0));
    let rt = DropRuntime {
        pred: bonded_correlated_pred(media_ports),
        dropped: Arc::clone(&dropped),
    };
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded_with(&refs, cfg.clone(), &rt)
        .await
        .expect("dial the bonded receiver");

    let payloads = text_payloads(64, "bonded-fec");
    let send_payloads = payloads.clone();
    let send_task = tokio::spawn(async move {
        for p in &send_payloads {
            sender.send(p).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
    });
    for (i, want) in payloads.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}: bonded FEC did not converge"))
            .expect("session open");
        assert_eq!(got.as_ref(), want.as_slice(), "payload {i}");
    }
    assert!(
        dropped.load(Ordering::Relaxed) >= 2,
        "the correlated pair (both paths) was not dropped — test not exercised"
    );
    let stats = receiver.stats();
    assert!(
        stats.fec_recovered >= 1,
        "bonded FEC recovery not counted: {stats:?}"
    );
    let sender = send_task.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn fec_recovered_count_surfaces_in_stats() {
    // After FEC reconstructs a dropped packet, the receiver's Stats.fec_recovered
    // counts it — distinct from the ARQ `recovered` counter, which stays 0 in one-way
    // mode (no NACK plane). Proves the WP18f Stats wiring end to end.
    let cfg = Config::default()
        .with_profile(Profile::Simple)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());
    let (mut receiver, port) = listen_free(&cfg).await;
    let dropped = Arc::new(AtomicU64::new(0));
    let rt = DropRuntime {
        pred: port_media_pred(port),
        dropped: Arc::clone(&dropped),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &rt)
        .await
        .expect("dial");
    let payloads = text_payloads(64, "stats-fec");
    let send_payloads = payloads.clone();
    let send_task = tokio::spawn(async move {
        for p in &send_payloads {
            sender.send(p).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
    });
    for (i, want) in payloads.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session open");
        assert_eq!(got.as_ref(), want.as_slice(), "payload {i}");
    }
    let stats = receiver.stats();
    assert!(
        stats.fec_recovered >= 1,
        "FEC recovery not counted: {stats:?}"
    );
    assert_eq!(
        stats.recovered, 0,
        "one-way mode has no ARQ recovery: {stats:?}"
    );
    let sender = send_task.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn fec_clean_loopback_does_not_disturb_the_stream() {
    // FEC enabled, no loss: the extra FEC traffic must not perturb ordinary in-order
    // delivery on any profile.
    for profile in [Profile::Advanced, Profile::Main, Profile::Simple] {
        let cfg = Config::default()
            .with_profile(profile)
            .with_buffer(Duration::from_millis(200))
            .with_fec(fec_2d());
        let (mut receiver, port) = listen_free(&cfg).await;
        let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &TokioRuntime)
            .await
            .expect("dial");
        let mk = |i: usize| format!("clean-{i:05}-{}", "x".repeat(40)).into_bytes();
        let send_task = tokio::spawn(async move {
            for i in 0..40usize {
                sender.send(&mk(i)).await.expect("send");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            sender
        });
        for i in 0..40usize {
            let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
                .await
                .unwrap_or_else(|_| panic!("{profile:?}: timed out on payload {i}"))
                .expect("session open");
            assert_eq!(got.as_ref(), mk(i).as_slice(), "{profile:?} payload {i}");
        }
        let sender = send_task.await.expect("send task");
        sender.close().await.ok();
        receiver.close().await.expect("close receiver");
    }
}

#[tokio::test]
async fn invalid_fec_matrix_is_rejected() {
    // L*D over the ST 2022-1 limit (100) is rejected at dial.
    let bad = FecConfig {
        columns: 20,
        rows: 20,
        column_only: false,
        carriage: rist::FecCarriage::SeparatePorts,
        variant: FecVariant::St20221,
    };
    let cfg = Config::default().with_fec(bad);
    assert!(
        dial_with("127.0.0.1:5000", cfg, &TokioRuntime)
            .await
            .is_err(),
        "an over-large FEC matrix must be rejected"
    );
}
