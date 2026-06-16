//! End-to-end Simple-profile loopback: a real `Sender` transmits media over UDP
//! to a real `Receiver` on loopback, and every payload arrives in order with its
//! bytes intact — the first proof the whole host (codec strategy + driver pump +
//! sockets) carries media end to end. A second test injects forward-media loss to
//! prove ARQ recovers it over real sockets.

// The loss-injecting PRNG takes the top 53 bits before the `f64` cast (exactly
// representable); the precision-loss lint does not apply to that idiom.
#![allow(clippy::cast_precision_loss)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rist::{AsyncUdpSocket, Config, Receiver, Runtime, TokioRuntime, dial, dial_with, listen};

/// Binds a receiver on an OS-chosen *free even* port (the Simple profile requires
/// an even media port; `listen` rejects 0), retrying to dodge the small race
/// between probing a free port and binding it.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let candidate = probe.local_addr().expect("probe addr").port() & !1; // round to even
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

#[tokio::test]
async fn simple_loopback_delivers_all_payloads_in_order() {
    const N: usize = 50;

    // A short recovery buffer keeps the test quick: a packet is played out
    // ~100 ms after it arrives rather than the 1 s default.
    let cfg = Config::default().with_buffer(Duration::from_millis(100));

    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the receiver");

    // Send N distinct payloads, lightly spaced to mimic a CBR source.
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            let payload = format!("ristrust-payload-{i:04}").into_bytes();
            sender.send(&payload).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });

    // Receive N payloads; assert exact order and byte integrity (each payload is
    // unique, so equality is a full integrity check).
    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for payload {i}"))
            .expect("session stayed open");
        let want = format!("ristrust-payload-{i:04}");
        assert_eq!(
            got.as_ref(),
            want.as_bytes(),
            "payload {i} mismatch (out of order or corrupt)"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn stats_reflect_a_clean_transfer() {
    const N: usize = 20;
    let cfg = Config::default().with_buffer(Duration::from_millis(100));
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the receiver");

    let send_task = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(format!("stats-{i:03}").as_bytes())
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
    // Give the final drain a moment to publish the latest snapshot.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sender = send_task.await.expect("send task");
    let tx = sender.stats();
    let rx = receiver.stats();
    assert!(tx.sent >= N as u64, "sender sent {} (< {N})", tx.sent);
    assert!(
        rx.delivered >= N as u64,
        "receiver delivered {} (< {N})",
        rx.delivered
    );
    assert_eq!(rx.lost, 0, "a clean transfer must lose nothing");
    // Cross-role fields are zero: a sender has no delivered, a receiver no sent.
    assert_eq!(tx.delivered, 0);
    assert_eq!(rx.sent, 0);

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

/// A [`Runtime`] whose UDP sockets drop a fraction of *forward media* datagrams
/// (those larger than [`MEDIA_THRESHOLD`]). RTCP compounds — NACKs, echoes,
/// reports — are small and pass through losslessly, so the receiver's NACK
/// return path always reaches the sender and recovery converges. Applied only to
/// the sender's transport in the lossy test.
struct LossyRuntime {
    loss: f64,
    next_seed: AtomicU64,
}

/// Datagrams larger than this are treated as media and subject to loss; RTCP
/// compounds (reports + SDES + NACK + echo) stay well below it.
const MEDIA_THRESHOLD: usize = 128;

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
            // Drop: report success without transmitting (the datagram is lost).
            return Poll::Ready(Ok(buf.len()));
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

#[tokio::test]
async fn simple_loopback_recovers_lossy_media_via_arq() {
    const N: usize = 30; // payloads whose in-order delivery is asserted
    const FLUSH: usize = 8; // trailing packets so the last asserted packet has a
    // successor to trigger its NACK (pure ARQ cannot recover a lost tail)
    let body = "x".repeat(160); // >128 so each media datagram is loss-eligible

    // A 300 ms recovery buffer leaves ample time for NACK round trips on loopback.
    let cfg = Config::default().with_buffer(Duration::from_millis(300));
    let (mut receiver, port) = listen_free(&cfg).await; // lossless receiver

    let lossy = LossyRuntime {
        loss: 0.15,
        next_seed: AtomicU64::new(0x00C0_FFEE),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &lossy)
        .await
        .expect("dial with the lossy runtime");

    let payload = move |i: usize| format!("lossy-{i:04}-{body}").into_bytes();
    let send_task = tokio::spawn(async move {
        for i in 0..N + FLUSH {
            sender.send(&payload(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    let want = |i: usize| format!("lossy-{i:04}-{}", "x".repeat(160));
    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}: ARQ recovery did not converge"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            want(i).as_bytes(),
            "payload {i} out of order or corrupt"
        );
    }

    // ARQ must actually have done work: with 15% forward loss the receiver
    // recovered at least one packet (a build with retransmission disabled would
    // hang and time out above, but assert it explicitly too).
    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}
