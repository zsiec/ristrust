//! End-to-end source-adaptation closed loop (VSF TR-06-4 Part 1): a Main-profile
//! receiver with source adaptation enabled emits periodic Link Quality Messages;
//! the sender feeds each to its AIMD controller and reports the new encoder-rate
//! target to a callback. Under injected forward-media loss the reported rate backs
//! off; on a clean link it holds at the ceiling. This proves the whole host loop —
//! receiver stats → LQM → RR extension → wire → sender decode → controller →
//! callback — closes and is monotone in loss. The controller arithmetic itself is
//! proven exhaustively by the rist-codec adapt unit tests.

// The loss PRNG takes the top 53 bits before the f64 cast; precision-loss does not
// apply to that idiom. The chunk index fits a u32 by construction.
#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rist::{AsyncUdpSocket, Config, Profile, Receiver, Runtime, TokioRuntime, dial_with, listen};

/// A config for `profile` with source adaptation on, a short keepalive (so Link
/// Quality Messages report every 100 ms), and a short recovery buffer.
fn adapt_cfg(profile: Profile) -> Config {
    Config::default()
        .with_profile(profile)
        .with_buffer(Duration::from_millis(200))
        .with_keepalive(Duration::from_millis(100))
        .with_source_adaptation(true)
}

/// Binds a Main receiver on an OS-chosen free port.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let candidate = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if candidate == 0 {
            continue;
        }
        if let Ok(r) = listen(&format!("127.0.0.1:{candidate}"), cfg.clone()).await {
            return (r, candidate);
        }
    }
    panic!("no free port for the adaptation receiver");
}

/// Runs a closed-loop session for `run` payloads (160-byte bodies, loss-eligible),
/// returning the sequence of encoder-rate targets the sender's callback reported.
/// `rt` supplies the sender's sockets (a `LossyRuntime` injects forward loss).
async fn run_adapt(profile: Profile, rt: &dyn Runtime, run: usize) -> Vec<u32> {
    let cfg = adapt_cfg(profile);
    let (mut receiver, port) = listen_free(&cfg).await;

    let rates = Arc::new(Mutex::new(Vec::<u32>::new()));
    let rec = rates.clone();
    let send_cfg = cfg
        .clone()
        .with_rate_callback(move |kbps| rec.lock().expect("rates").push(kbps));
    let sender = dial_with(&format!("127.0.0.1:{port}"), send_cfg, rt)
        .await
        .expect("dial the adaptation receiver");

    let body = vec![b'x'; 160];
    let send_task = tokio::spawn(async move {
        for i in 0..run {
            let mut p = body.clone();
            p[..4].copy_from_slice(&(i as u32).to_be_bytes());
            if sender.send(&p).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    // Drain whatever the receiver delivers (it need not be complete under loss).
    let drain = tokio::spawn(async move {
        for _ in 0..run {
            if tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .is_err()
            {
                break;
            }
        }
        receiver
    });

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    let receiver = drain.await.expect("drain task");
    receiver.close().await.expect("close receiver");

    rates.lock().expect("rates").clone()
}

#[tokio::test]
async fn adapt_clean_link_holds_at_ceiling() {
    // No loss: the receiver reports clean LQMs, the controller probes up, and the
    // reported rate stays pinned at the configured ceiling.
    let rates = run_adapt(Profile::Main, &TokioRuntime, 400).await;
    assert!(
        !rates.is_empty(),
        "no Link Quality Messages closed the loop on a clean link"
    );
    let max = Config::default().max_bitrate_kbps;
    assert!(
        rates.iter().all(|&r| r == max),
        "clean link should hold at the ceiling {max}, saw {rates:?}"
    );
}

/// Asserts that sustained forward-media loss on `profile` drives the reported
/// encoder rate well below the ceiling — the closed loop works on this profile.
async fn assert_backs_off_under_loss(profile: Profile, seed: u64) {
    let lossy = LossyRuntime {
        loss: 0.20,
        next_seed: AtomicU64::new(seed),
    };
    let rates = run_adapt(profile, &lossy, 600).await;
    assert!(
        rates.len() >= 3,
        "{profile:?}: expected several reporting periods, got {} reports",
        rates.len()
    );
    let max = Config::default().max_bitrate_kbps;
    let &min_rate = rates.iter().min().expect("at least one rate");
    assert!(
        min_rate < max / 2,
        "{profile:?}: sustained loss should back off well below {max}; min was {min_rate} ({rates:?})"
    );
}

#[tokio::test]
async fn adapt_backs_off_under_loss_main() {
    assert_backs_off_under_loss(Profile::Main, 0x5EED_1234).await;
}

#[tokio::test]
async fn adapt_backs_off_under_loss_simple() {
    assert_backs_off_under_loss(Profile::Simple, 0x5EED_5678).await;
}

#[tokio::test]
async fn adapt_backs_off_under_loss_advanced() {
    assert_backs_off_under_loss(Profile::Advanced, 0x5EED_9ABC).await;
}

/// A [`Runtime`] whose UDP sockets drop a fraction of forward *media* datagrams
/// (those larger than [`MEDIA_THRESHOLD`]); small GRE control/keepalive/LQM
/// datagrams pass losslessly so the LQM return path always reaches the sender.
struct LossyRuntime {
    loss: f64,
    next_seed: AtomicU64,
}

/// Datagrams larger than this are treated as media and subject to loss.
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
