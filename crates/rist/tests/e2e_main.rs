//! End-to-end Main-profile (VSF TR-06-2) loopback: a real `Sender` tunnels media
//! over GRE-on-UDP to a real `Receiver` on a single loopback port — cleartext and
//! PSK-encrypted (AES-128 and AES-256) — and every payload arrives in order with
//! its bytes intact. This is the first proof the Main host (GRE framing + PSK
//! crypto + single-port driver) carries media end to end. A lossy variant proves
//! ARQ recovers dropped media through the encrypted tunnel.

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
    AesKeyBits, AsyncUdpSocket, Config, Error, Profile, Receiver, Runtime, TokioRuntime, dial_with,
    listen,
};

/// A Main-profile base config with a short recovery buffer (fast playout) and the
/// optional PSK secret/key size.
fn main_cfg(secret: Option<(&str, AesKeyBits)>) -> Config {
    let mut cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150));
    if let Some((s, bits)) = secret {
        cfg = cfg.with_secret(s).with_aes_key_bits(bits);
    }
    cfg
}

/// Binds a Main-profile receiver on an OS-chosen free port (any port is valid for
/// the single-port Main transport), retrying past the probe/bind race.
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
    panic!("could not find a free port for the Main receiver");
}

/// Drives `N` distinct payloads sender → receiver and asserts in-order byte
/// integrity, over the given runtime (lossless `TokioRuntime` unless overridden).
async fn run_loopback(cfg: Config, rt: &dyn Runtime, n: usize, flush: usize, body: &str) {
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), rt)
        .await
        .expect("dial the Main receiver");

    let body = body.to_string();
    let mk = move |i: usize| format!("main-{i:04}-{body}").into_bytes();
    let send_mk = mk.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..n + flush {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
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
            "payload {i} out of order or corrupt"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn main_loopback_cleartext_delivers_in_order() {
    run_loopback(main_cfg(None), &TokioRuntime, 50, 0, "payload").await;
}

#[tokio::test]
async fn main_windowed_buffer_negotiates_and_delivers() {
    // A windowed recovery buffer (min != max) turns on GRE-v2 buffer negotiation:
    // the sender advertises its max recovery buffer, the receiver auto-scales its
    // playout buffer toward smoothedRTT*multiplier within [min, max]. The stream
    // must still deliver in order and byte-exact through that path. (Algorithm
    // correctness is pinned by the rist-core auto-scale KAT; this guards the wire +
    // session plumbing.)
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer_range(Duration::from_millis(150), Duration::from_millis(400));
    run_loopback(cfg, &TokioRuntime, 60, 0, "windowed").await;
}

#[tokio::test]
async fn main_loopback_aes128_delivers_in_order() {
    run_loopback(
        main_cfg(Some(("hunter2-128", AesKeyBits::Aes128))),
        &TokioRuntime,
        50,
        0,
        "encrypted-128",
    )
    .await;
}

#[tokio::test]
async fn main_loopback_aes256_delivers_in_order() {
    run_loopback(
        main_cfg(Some(("hunter2-256", AesKeyBits::Aes256))),
        &TokioRuntime,
        50,
        0,
        "encrypted-256",
    )
    .await;
}

#[tokio::test]
async fn main_loopback_authenticated_srp_delivers_in_order() {
    // EAP-SRP auth gates the data channel: the sender holds media until the
    // handshake authenticates it, then media flows in order. Combined with PSK so
    // the authenticated + encrypted Main path is exercised end to end.
    let cfg = main_cfg(Some(("psk-secret", AesKeyBits::Aes128)))
        .with_srp_credentials("rist", "mainprofile");
    run_loopback(cfg, &TokioRuntime, 50, 0, "authenticated").await;
}

#[tokio::test]
async fn main_loopback_srp_only_keys_media_from_session_key() {
    // No explicit PSK secret: after EAP-SRP authenticates, the data channel re-keys
    // purely from the SRP session key K, and media flows encrypted under it. This is
    // a ristrust↔ristrust mode: a libRIST *listener* cannot receive it — its keysize
    // gate checks the parent peer's key, which only `-s` configures, not the
    // SRP-derived key (the interop suite uses the combined PSK+SRP mode instead).
    let cfg = main_cfg(None).with_srp_credentials("rist", "mainprofile");
    run_loopback(cfg, &TokioRuntime, 50, 0, "srp-keyed").await;
}

#[tokio::test]
async fn main_loopback_srp_wrong_password_surfaces_auth_error() {
    // The sender authenticates with the wrong password: the handshake fails, the
    // data channel never opens, no media is delivered, and the session is torn down
    // with the specific `Error::Auth` (surfaced by `recv`) rather than a bare
    // timeout. A short keepalive makes the authenticator's failed-handshake check
    // (which runs on the keepalive tick) surface promptly.
    let recv_cfg = main_cfg(None)
        .with_srp_credentials("rist", "right-password")
        .with_keepalive(Duration::from_millis(100));
    let (mut receiver, port) = listen_free(&recv_cfg).await;
    let send_cfg = main_cfg(None)
        .with_srp_credentials("rist", "wrong-password")
        .with_keepalive(Duration::from_millis(100));
    let sender = dial_with(&format!("127.0.0.1:{port}"), send_cfg, &TokioRuntime)
        .await
        .expect("dial");
    // The EAP-SRP handshake runs and fails; the receiver (authenticator) tears the
    // session down and `recv` reports it as an authentication failure, not a hang.
    let got = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("a failed handshake must resolve recv, not hang");
    assert!(
        matches!(got, Err(Error::Auth)),
        "expected Error::Auth on a failed handshake, got {got:?}"
    );
    sender.close().await.ok();
    receiver.close().await.expect("close");
}

#[tokio::test]
async fn send_surfaces_session_timeout_after_peer_goes_silent() {
    // Once the sender has seen the receiver, a peer that falls silent past
    // `session_timeout` tears the session down, and `send` reports the specific
    // `Error::SessionTimeout` rather than a bare `Error::Closed`.
    let cfg = main_cfg(None)
        .with_keepalive(Duration::from_millis(50))
        .with_session_timeout(Duration::from_millis(150));
    let (receiver, port) = listen_free(&cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &TokioRuntime)
        .await
        .expect("dial");

    // One exchange so the sender observes the receiver (the peer becomes "seen";
    // an unseen peer never expires).
    sender.send(b"hello-peer").await.expect("first send");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The receiver goes away; nothing answers the sender from now on.
    receiver.close().await.expect("close receiver");

    // Within a few session timeouts the sender's peer expires and sends fail with
    // the specific SessionTimeout error.
    let mut got = None;
    for _ in 0..250 {
        if let Err(e) = sender.send(b"into-the-void").await {
            got = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        matches!(got, Some(Error::SessionTimeout)),
        "expected Error::SessionTimeout after peer silence, got {got:?}"
    );
}

#[tokio::test]
async fn main_loopback_recovers_lossy_media_via_arq() {
    // Encrypted tunnel + forward-media loss: ARQ must recover through the PSK path.
    let cfg = main_cfg(Some(("lossy-secret", AesKeyBits::Aes256)))
        .with_buffer(Duration::from_millis(300));
    let lossy = LossyRuntime {
        loss: 0.15,
        next_seed: AtomicU64::new(0x00C0_FFEE),
    };
    // 30 asserted payloads + 8 flush so the last asserted packet has a successor to
    // trigger its NACK; body > 128 bytes so each media datagram is loss-eligible.
    run_loopback(cfg, &lossy, 30, 8, &"x".repeat(160)).await;
}

/// A [`Runtime`] whose UDP sockets drop a fraction of *forward media* datagrams
/// (those larger than [`MEDIA_THRESHOLD`]). GRE-framed RTCP compounds — NACKs,
/// echoes, reports, keepalives — are small and pass through losslessly, so the
/// receiver's NACK return path always reaches the sender and recovery converges.
struct LossyRuntime {
    loss: f64,
    next_seed: AtomicU64,
}

/// Datagrams larger than this are treated as media and subject to loss; GRE-framed
/// RTCP compounds and keepalives stay well below it.
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
            return Poll::Ready(Ok(buf.len())); // drop: report success without transmitting
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
