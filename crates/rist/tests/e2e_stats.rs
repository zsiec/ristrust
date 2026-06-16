//! End-to-end coverage of the public [`Stats`](rist::Stats) API: that a `Sender`'s
//! and `Receiver`'s `stats()` snapshots reflect real session work over UDP loopback.
//! The clean-transfer and one-way cases live in `e2e_loopback`; this suite locks in
//! the harder-to-reach counters — the ARQ recovery counts under two-way loss, the
//! SMPTE 2022-7 duplicate count under bonding, and the contract that each role zeroes
//! the other role's fields.

// The loss-injecting PRNG takes the top 53 bits before the `f64` cast (exactly
// representable); the precision-loss lint does not apply to that idiom.
#![allow(clippy::cast_precision_loss)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rist::{
    AsyncUdpSocket, Config, Profile, Receiver, Runtime, Stats, TokioRuntime, dial, dial_bonded,
    dial_with, listen, listen_bonded,
};

/// Datagrams larger than this are treated as media and subject to loss; RTCP
/// compounds (reports + SDES + NACK + echo) stay well below it.
const MEDIA_THRESHOLD: usize = 128;

/// Binds a Simple receiver on an OS-chosen free even port.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let candidate = probe.local_addr().expect("probe addr").port() & !1;
        drop(probe);
        if candidate == 0 {
            continue;
        }
        if let Ok(r) = listen(&format!("127.0.0.1:{candidate}"), cfg.clone()).await {
            return (r, candidate);
        }
    }
    panic!("could not find a free even port for the receiver");
}

/// Binds a bonded (Main-profile) receiver on `n` OS-chosen free ports.
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

#[tokio::test]
async fn stats_count_arq_recovery_under_two_way_loss() {
    const N: usize = 30; // payloads whose in-order delivery is asserted
    const FLUSH: usize = 8; // trailing packets so the last asserted packet's NACK fires
    let body = "x".repeat(160); // >128 so each media datagram is loss-eligible

    let cfg = Config::default().with_buffer(Duration::from_millis(300));
    let (mut receiver, port) = listen_free(&cfg).await; // lossless receiver
    let lossy = LossyRuntime {
        loss: 0.15,
        next_seed: AtomicU64::new(0x57A7_5EED),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &lossy)
        .await
        .expect("dial with the lossy runtime");

    let payload = move |i: usize| format!("arq-{i:04}-{body}").into_bytes();
    let mk = payload.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..N + FLUSH {
            sender.send(&payload(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        // Keep the sender alive (its stats live on its task) while the receiver drains.
        tokio::time::sleep(Duration::from_millis(200)).await;
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}: ARQ did not converge"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} out of order or corrupt"
        );
    }

    let sender = send_task.await.expect("send task");
    let rx = receiver.stats();
    let tx = sender.stats();
    // With 15% forward loss fully recovered in order, the recovery counters moved.
    assert!(rx.received >= N as u64, "received {} (< {N})", rx.received);
    assert!(
        rx.delivered >= N as u64,
        "delivered {} (< {N})",
        rx.delivered
    );
    assert!(rx.nacks_sent > 0, "receiver sent no NACKs despite loss");
    assert!(rx.recovered > 0, "receiver recovered nothing despite loss");
    assert!(
        tx.retransmitted > 0,
        "sender retransmitted nothing despite NACKs"
    );
    assert!(tx.sent >= N as u64, "sender sent {} (< {N})", tx.sent);

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn stats_count_2022_7_duplicates_when_bonded() {
    const N: usize = 60;
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200));
    let (mut receiver, addrs) = listen_free_bonded(&cfg, 2).await;
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded(&refs, cfg.clone())
        .await
        .expect("dial the bonded receiver");

    let mk = |i: usize| format!("dup-{i:04}").into_bytes();
    let send_mk = mk;
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
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
    let rx = receiver.stats();
    // Two full-redundancy paths deliver every packet twice; the receiver dedups the
    // second copy of each by (seq, source_time), so the duplicate counter climbs while
    // each payload is still delivered exactly once.
    assert!(
        rx.delivered >= N as u64,
        "delivered {} (< {N})",
        rx.delivered
    );
    assert!(
        rx.duplicates > 0,
        "no 2022-7 duplicates counted: {} (the redundant path was not deduped)",
        rx.duplicates
    );
    assert!(sender.stats().sent >= N as u64, "sender sent < {N}");

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn stats_zero_the_other_role_fields() {
    const N: usize = 20;
    let cfg = Config::default().with_buffer(Duration::from_millis(100));
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the receiver");

    let send_task = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(format!("role-{i:03}").as_bytes())
                .await
                .expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });
    for i in 0..N {
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
    }
    // Let the final drain publish the latest snapshot on both ends.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let sender = send_task.await.expect("send task");

    // The sender populates only sender-half fields; every receiver-half field is zero.
    let tx = sender.stats();
    assert!(tx.sent >= N as u64, "sender sent {} (< {N})", tx.sent);
    assert_eq!(
        (
            tx.received,
            tx.delivered,
            tx.lost,
            tx.recovered,
            tx.fec_recovered,
            tx.duplicates,
            tx.reordered,
            tx.nacks_sent,
            tx.abandoned,
            tx.discontinuities,
        ),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        "sender snapshot has non-zero receiver-half fields: {tx:?}"
    );

    // The receiver populates only receiver-half fields; every sender-half field is zero.
    let rx = receiver.stats();
    assert!(
        rx.delivered >= N as u64,
        "receiver delivered {} (< {N})",
        rx.delivered
    );
    assert_eq!(
        (
            rx.sent,
            rx.retransmitted,
            rx.retransmit_skipped,
            rx.retransmit_suppressed,
        ),
        (0, 0, 0, 0),
        "receiver snapshot has non-zero sender-half fields: {rx:?}"
    );

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[test]
fn default_stats_is_all_zero() {
    // The pre-publish snapshot a handle reads before any session work is all zero.
    assert_eq!(Stats::default(), Stats::default());
    let z = Stats::default();
    assert_eq!(
        (z.sent, z.received, z.delivered, z.recovered, z.duplicates),
        (0, 0, 0, 0, 0)
    );
}

/// A [`Runtime`] whose UDP sockets drop a fraction of *forward media* datagrams
/// (those larger than [`MEDIA_THRESHOLD`]); the small RTCP return path (NACKs, echoes)
/// passes through losslessly, so recovery converges. Applied to the sender only.
struct LossyRuntime {
    loss: f64,
    next_seed: AtomicU64,
}

impl Runtime for LossyRuntime {
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
        let seed = self
            .next_seed
            .fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
        Ok(Arc::new(LossySocket {
            inner,
            loss: self.loss,
            rng: Mutex::new(seed),
        }))
    }
}

/// A socket that drops large (media) sends with a seeded probability.
#[derive(Debug)]
struct LossySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    loss: f64,
    rng: Mutex<u64>,
}

impl LossySocket {
    /// One SplitMix64 draw in `[0, 1)`.
    fn unit(&self) -> f64 {
        let mut s = self.rng.lock().expect("rng");
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
    }
}

impl AsyncUdpSocket for LossySocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        if buf.len() > MEDIA_THRESHOLD && self.unit() < self.loss {
            return Poll::Ready(Ok(buf.len())); // drop: report success without sending
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
