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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rist::{
    AsyncUdpSocket, Config, Profile, Receiver, Runtime, TokioRuntime, dial_bonded_with,
    listen_bonded,
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
