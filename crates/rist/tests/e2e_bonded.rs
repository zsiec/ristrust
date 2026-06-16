//! End-to-end SMPTE 2022-7 bonding loopback: a real bonded `Sender` transmits the
//! identical media on N Main-profile GRE paths to a real bonded `Receiver` that
//! merges them. The clean tests prove the host plumbing carries media over real
//! UDP and the receiver dedups the redundant copies (each payload delivered exactly
//! once, in order). The blackhole test proves full redundancy: with one path's
//! forward media entirely dropped, the other carries the stream seamlessly. The
//! packet-level merge itself is proven exhaustively by the rist-core bonding sim.
//!
//! The bonded sender sources every path from one shared socket (so a multiplexing
//! receiver can key the paths into one flow by source address), so the test runtime
//! attributes each media datagram to a path by its *destination* address — the
//! per-path remote — not by which socket sent it. [`PathTapRuntime`] is that tap.

// The per-path byte counts are cast to f64 for the ratio asserts; the counts are
// far below 2^53, so precision-loss does not apply.
#![allow(clippy::cast_precision_loss)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rist::{
    AsyncUdpSocket, Config, Profile, Receiver, Runtime, TokioRuntime, dial_bonded_weighted_with,
    dial_bonded_with, listen_bonded,
};

/// A Main-profile bonded base config with a short recovery buffer.
fn bonded_cfg() -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200))
}

/// Binds a bonded receiver on `n` OS-chosen free Main ports, returning it and the
/// `rist://IP:port` strings a sender dials.
async fn listen_free_bonded(cfg: &Config, n: usize) -> (Receiver, Vec<String>) {
    'attempt: for _ in 0..64 {
        let mut ports = Vec::with_capacity(n);
        for _ in 0..n {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
            let p = probe.local_addr().expect("probe addr").port();
            drop(probe);
            if p == 0 || ports.contains(&p) {
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

/// Drives `n` distinct payloads over the bonded sender → receiver and asserts each
/// arrives once, in order, byte-exact. `make_rt` builds the sender's runtime from the
/// resolved per-path destinations (so a [`PathTapRuntime`] can blackhole one path's
/// media by its remote address).
async fn run_bonded(
    cfg: Config,
    paths: usize,
    n: usize,
    body: &str,
    make_rt: impl FnOnce(Vec<SocketAddr>) -> Arc<dyn Runtime>,
) {
    let (mut receiver, addrs) = listen_free_bonded(&cfg, paths).await;
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let dests: Vec<SocketAddr> = addrs
        .iter()
        .map(|a| a.parse().expect("dest addr"))
        .collect();
    let rt = make_rt(dests);
    let sender = dial_bonded_with(&refs, cfg.clone(), rt.as_ref())
        .await
        .expect("dial the bonded receiver");

    let body = body.to_string();
    let mk = move |i: usize| format!("bond-{i:05}-{body}").into_bytes();
    let send_mk = mk.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..n {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} out of order or corrupt"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn bonded_two_paths_clean_merges_and_dedups() {
    // Both paths deliver every packet; the receiver must dedup to deliver each once.
    run_bonded(bonded_cfg(), 2, 60, "payload", |_| Arc::new(TokioRuntime)).await;
}

#[tokio::test]
async fn bonded_three_paths_clean() {
    run_bonded(bonded_cfg(), 3, 60, "triple", |_| Arc::new(TokioRuntime)).await;
}

#[tokio::test]
async fn bonded_two_paths_aes256() {
    run_bonded(
        bonded_cfg().with_secret("bond-secret"),
        2,
        60,
        "encrypted",
        |_| Arc::new(TokioRuntime),
    )
    .await;
}

#[tokio::test]
async fn bonded_survives_one_path_blackhole() {
    // Path 0's forward media (everything sent to its remote) is entirely dropped; the
    // redundant copy on path 1 must carry the whole stream with no loss and no
    // discontinuity (seamless 2022-7). The body is padded past MEDIA_THRESHOLD so each
    // media datagram is actually subject to the blackhole.
    let body = "x".repeat(200);
    run_bonded(bonded_cfg(), 2, 60, &body, |dests| {
        Arc::new(PathTapRuntime::blackholing(dests, 0))
    })
    .await;
}

/// Datagrams larger than this are treated as media; GRE handshakes and keepalives
/// stay well below it, so they are never counted nor blackholed.
const MEDIA_THRESHOLD: usize = 128;

/// The per-path tap state shared between a [`PathTapRuntime`] and the sockets it
/// binds: the ordered per-path destinations, a media-byte counter per path, and an
/// optional blackhole target. The bonded sender shares one source socket across all
/// paths, so a datagram's path is identified by its *destination* (the per-path
/// remote), not by which socket sent it.
#[derive(Debug)]
struct PathTap {
    /// Per-path remote addresses, in path order; `dests[i]` is path `i`.
    dests: Vec<SocketAddr>,
    /// Media bytes attributed to each path, parallel to `dests`.
    counters: Vec<AtomicU64>,
    /// If `Some(i)`, path `i`'s forward media is silently dropped.
    blackhole: Option<usize>,
}

impl PathTap {
    /// The path index a media datagram bound for `dest` belongs to, if any.
    fn path_of(&self, dest: SocketAddr) -> Option<usize> {
        self.dests.iter().position(|d| *d == dest)
    }
}

/// A [`Runtime`] that taps the bonded sender's shared socket, attributing each
/// media-sized datagram to a path by its destination (the per-path remote). It
/// totals per-path media bytes — the witness that weighted load-share split the
/// stream across the paths — and can blackhole one path's forward media to prove
/// 2022-7 redundancy, all while small control traffic flows on every path.
#[derive(Debug)]
struct PathTapRuntime {
    tap: Arc<PathTap>,
}

impl PathTapRuntime {
    /// A counting-only tap over the given per-path destinations.
    fn new(dests: Vec<SocketAddr>) -> PathTapRuntime {
        PathTapRuntime::with_blackhole(dests, None)
    }
    /// A tap that also blackholes path `target`'s forward media.
    fn blackholing(dests: Vec<SocketAddr>, target: usize) -> PathTapRuntime {
        PathTapRuntime::with_blackhole(dests, Some(target))
    }
    fn with_blackhole(dests: Vec<SocketAddr>, blackhole: Option<usize>) -> PathTapRuntime {
        let counters = dests.iter().map(|_| AtomicU64::new(0)).collect();
        PathTapRuntime {
            tap: Arc::new(PathTap {
                dests,
                counters,
                blackhole,
            }),
        }
    }
    /// The per-path media byte counts, in path order.
    fn counts(&self) -> Vec<u64> {
        self.tap
            .counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    }
}

impl Runtime for PathTapRuntime {
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
        let inner = TokioRuntime.bind(addr)?;
        Ok(Arc::new(PathTapSocket {
            inner,
            tap: Arc::clone(&self.tap),
        }))
    }
}

/// A socket that, for each media-sized send, attributes the datagram to its
/// destination path: it totals the bytes and, if that path is blackholed, drops the
/// datagram (reporting success so the host proceeds). Control traffic and all
/// receives pass through untouched.
#[derive(Debug)]
struct PathTapSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    tap: Arc<PathTap>,
}

impl AsyncUdpSocket for PathTapSocket {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> std::task::Poll<io::Result<usize>> {
        let path = if buf.len() > MEDIA_THRESHOLD {
            self.tap.path_of(dest)
        } else {
            None
        };
        if let Some(i) = path
            && self.tap.blackhole == Some(i)
        {
            // The load-share scheduler chose this path, so count it, then drop the
            // datagram on the floor and report success so the host proceeds.
            self.tap.counters[i].fetch_add(buf.len() as u64, Ordering::Relaxed);
            return std::task::Poll::Ready(Ok(buf.len()));
        }
        let r = self.inner.poll_send(cx, buf, dest);
        if let (Some(i), std::task::Poll::Ready(Ok(n))) = (path, &r) {
            self.tap.counters[i].fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<(usize, SocketAddr)>> {
        self.inner.poll_recv(cx, buf)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// Drives a weighted bonded sender (per-path or runtime-set weights) through a
/// counting tap runtime, asserts the receiver merges all `N` payloads in order, and
/// returns the per-path media byte counts (keyed by destination).
async fn run_weighted(
    rt: Arc<PathTapRuntime>,
    sender: rist::Sender,
    mut receiver: Receiver,
    n: usize,
) -> Vec<u64> {
    let body = "x".repeat(200); // >128 so each media datagram is loss-eligible/counted
    let mk = move |i: usize| format!("w-{i:04}-{body}").into_bytes();
    let send_mk = mk.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..n {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });
    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} corrupt or out of order"
        );
    }
    let sender = send_task.await.expect("send task");
    let counts = rt.counts();
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
    counts
}

#[tokio::test]
async fn bonded_weighted_load_share_splits_three_to_one() {
    let cfg = bonded_cfg();
    let (receiver, refs) = listen_free_bonded(&cfg, 2).await;
    let dests: Vec<SocketAddr> = refs.iter().map(|a| a.parse().expect("dest addr")).collect();
    let rt = Arc::new(PathTapRuntime::new(dests));
    // Path 0 weight 3, path 1 weight 1: path 0 carries ~three quarters of the stream.
    let peers: Vec<(&str, u32)> = vec![(refs[0].as_str(), 3), (refs[1].as_str(), 1)];
    let sender = dial_bonded_weighted_with(&peers, cfg.clone(), rt.as_ref())
        .await
        .expect("dial weighted bonded");
    let counts = run_weighted(Arc::clone(&rt), sender, receiver, 120).await;

    assert!(
        counts[0] > 0 && counts[1] > 0,
        "a weighted path carried no media: {counts:?} (load not shared)"
    );
    #[allow(clippy::cast_precision_loss)]
    let ratio = counts[0] as f64 / counts[1] as f64;
    assert!(
        (2.3..=4.5).contains(&ratio),
        "weighted split {counts:?} (ratio {ratio:.2}), want ~3:1; ~1:1 would be duplication"
    );
}

#[tokio::test]
async fn bonded_set_weight_rebalances_at_runtime() {
    let cfg = bonded_cfg().with_weight(1); // start uniform 1:1
    let (receiver, refs) = listen_free_bonded(&cfg, 2).await;
    let dests: Vec<SocketAddr> = refs.iter().map(|a| a.parse().expect("dest addr")).collect();
    let rt = Arc::new(PathTapRuntime::new(dests));
    let addrs: Vec<&str> = refs.iter().map(String::as_str).collect();
    let sender = dial_bonded_with(&addrs, cfg.clone(), rt.as_ref())
        .await
        .expect("dial bonded");
    // Rebalance to 3:1 before the stream really gets going.
    sender.set_weight(0, 3).await.expect("set_weight");
    let counts = run_weighted(Arc::clone(&rt), sender, receiver, 120).await;

    assert!(
        counts[0] > 0 && counts[1] > 0,
        "a path carried no media: {counts:?}"
    );
    #[allow(clippy::cast_precision_loss)]
    let ratio = counts[0] as f64 / counts[1] as f64;
    assert!(
        ratio > 2.0,
        "set_weight did not rebalance: {counts:?} (ratio {ratio:.2}), want path 0 favored"
    );
}
