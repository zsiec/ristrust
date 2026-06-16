//! End-to-end SMPTE 2022-7 bonding loopback: a real bonded `Sender` transmits the
//! identical media on N Main-profile GRE paths to a real bonded `Receiver` that
//! merges them. The clean tests prove the host plumbing carries media over real
//! UDP and the receiver dedups the redundant copies (each payload delivered exactly
//! once, in order). The blackhole test proves full redundancy: with one path's
//! forward media entirely dropped, the other carries the stream seamlessly. The
//! packet-level merge itself is proven exhaustively by the rist-core bonding sim.

// The blackhole runtime takes the top 53 bits before the f64 cast; precision-loss
// does not apply, and the bind counter casts are bounded.
#![allow(clippy::cast_precision_loss)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
/// arrives once, in order, byte-exact. `rt` supplies the sender's path sockets
/// (a `BlackholePathRuntime` can kill one path).
async fn run_bonded(cfg: Config, paths: usize, n: usize, body: &str, rt: Arc<dyn Runtime>) {
    let (mut receiver, addrs) = listen_free_bonded(&cfg, paths).await;
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
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
    run_bonded(bonded_cfg(), 2, 60, "payload", Arc::new(TokioRuntime)).await;
}

#[tokio::test]
async fn bonded_three_paths_clean() {
    run_bonded(bonded_cfg(), 3, 60, "triple", Arc::new(TokioRuntime)).await;
}

#[tokio::test]
async fn bonded_two_paths_aes256() {
    run_bonded(
        bonded_cfg().with_secret("bond-secret"),
        2,
        60,
        "encrypted",
        Arc::new(TokioRuntime),
    )
    .await;
}

#[tokio::test]
async fn bonded_survives_one_path_blackhole() {
    // Path 0's forward media is entirely dropped; the redundant copy on path 1 must
    // carry the whole stream with no loss and no discontinuity (seamless 2022-7).
    let rt = Arc::new(BlackholePathRuntime::new(0));
    run_bonded(bonded_cfg(), 2, 60, "redundant", rt).await;
}

/// A [`Runtime`] whose `target`-th bound socket silently drops outbound *media*
/// datagrams (those larger than [`MEDIA_THRESHOLD`]); every other socket and all
/// small control traffic pass through. Used to blackhole one bonded path's forward
/// media while its GRE handshake/keepalive still flow, so liveness holds and only
/// the media redundancy is under test.
#[derive(Debug)]
struct BlackholePathRuntime {
    target: usize,
    bound: AtomicUsize,
}

impl BlackholePathRuntime {
    fn new(target: usize) -> BlackholePathRuntime {
        BlackholePathRuntime {
            target,
            bound: AtomicUsize::new(0),
        }
    }
}

/// Datagrams larger than this are treated as media and subject to the blackhole;
/// GRE handshakes and keepalives stay well below it.
const MEDIA_THRESHOLD: usize = 128;

impl Runtime for BlackholePathRuntime {
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
        let nth = self.bound.fetch_add(1, Ordering::Relaxed);
        if nth == self.target {
            Ok(Arc::new(BlackholeSocket { inner }))
        } else {
            Ok(inner)
        }
    }
}

/// A socket that drops every media-sized send (the blackholed path's forward
/// media) but passes control traffic and all receives.
#[derive(Debug)]
struct BlackholeSocket {
    inner: Arc<dyn AsyncUdpSocket>,
}

impl AsyncUdpSocket for BlackholeSocket {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> std::task::Poll<io::Result<usize>> {
        if buf.len() > MEDIA_THRESHOLD {
            return std::task::Poll::Ready(Ok(buf.len())); // drop, report success
        }
        self.inner.poll_send(cx, buf, dest)
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

/// A [`Runtime`] that totals the media-sized datagrams each bound socket transmits,
/// one counter per `bind` in call order. The bonded sender binds one socket per path
/// in path order, so `counters()[i]` is path `i`'s media count — the witness that
/// weighted load-share split the stream across the paths.
#[derive(Debug, Default)]
struct CountingPathRuntime {
    counters: Mutex<Vec<Arc<AtomicU64>>>,
}

impl CountingPathRuntime {
    fn new() -> CountingPathRuntime {
        CountingPathRuntime::default()
    }
    /// The per-path media counters, in path (bind) order.
    fn counters(&self) -> Vec<Arc<AtomicU64>> {
        self.counters.lock().expect("counters").clone()
    }
}

impl Runtime for CountingPathRuntime {
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
        let counter = Arc::new(AtomicU64::new(0));
        self.counters
            .lock()
            .expect("counters")
            .push(Arc::clone(&counter));
        Ok(Arc::new(CountingPathSocket { inner, counter }))
    }
}

/// A socket that adds each media-sized send to its path counter.
#[derive(Debug)]
struct CountingPathSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    counter: Arc<AtomicU64>,
}

impl AsyncUdpSocket for CountingPathSocket {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> std::task::Poll<io::Result<usize>> {
        let r = self.inner.poll_send(cx, buf, dest);
        if let std::task::Poll::Ready(Ok(n)) = &r
            && buf.len() > MEDIA_THRESHOLD
        {
            self.counter.fetch_add(*n as u64, Ordering::Relaxed);
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
/// counting runtime, asserts the receiver merges all `N` payloads in order, and
/// returns the per-path media byte counts.
async fn run_weighted(
    rt: Arc<CountingPathRuntime>,
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
    let counts: Vec<u64> = rt
        .counters()
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
    counts
}

#[tokio::test]
async fn bonded_weighted_load_share_splits_three_to_one() {
    let cfg = bonded_cfg();
    let (receiver, refs) = listen_free_bonded(&cfg, 2).await;
    let rt = Arc::new(CountingPathRuntime::new());
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
    let rt = Arc::new(CountingPathRuntime::new());
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
