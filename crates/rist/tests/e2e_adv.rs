//! End-to-end Advanced-profile (VSF TR-06-3) loopback: a real `Sender` carries
//! media over the single-port RTP/PT=127 hybrid to a real `Receiver` — cleartext,
//! PSK-encrypted (AES-128/256), LZ4-compressed, and authenticated — and every
//! payload arrives in order with its bytes intact. This proves the Advanced host
//! (adv header + control codec, LZ4, AES-CTR payload, the GRE-substrate driver)
//! carries media end to end. A final test injects 25% forward-media loss and
//! proves the Advanced native NACK control plane recovers it byte-exact.

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
    AesKeyBits, AsyncUdpSocket, Config, Profile, Receiver, Runtime, TokioRuntime, dial_with, listen,
};

/// An Advanced-profile base config with a short recovery buffer.
fn adv_cfg() -> Config {
    Config::default()
        .with_profile(Profile::Advanced)
        .with_buffer(Duration::from_millis(150))
}

/// Binds an Advanced receiver on an OS-chosen free port.
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
    panic!("no free port for the Advanced receiver");
}

/// Drives `n` distinct payloads sender → receiver and asserts in-order byte
/// integrity.
async fn run_loopback(cfg: Config, n: usize, body: &str) {
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &TokioRuntime)
        .await
        .expect("dial the Advanced receiver");

    let body = body.to_string();
    let mk = move |i: usize| format!("adv-{i:05}-{body}").into_bytes();
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
            "payload {i} out of order or corrupt"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn adv_loopback_cleartext() {
    run_loopback(adv_cfg(), 50, "payload").await;
}

#[tokio::test]
async fn adv_loopback_lz4_compressed() {
    // A repetitive body so LZ4 actually shrinks it.
    run_loopback(adv_cfg().with_compression(true), 50, &"x".repeat(200)).await;
}

#[tokio::test]
async fn adv_loopback_aes128() {
    run_loopback(
        adv_cfg()
            .with_secret("adv-128")
            .with_aes_key_bits(AesKeyBits::Aes128),
        50,
        "encrypted-128",
    )
    .await;
}

#[tokio::test]
async fn adv_loopback_aes256_lz4() {
    run_loopback(
        adv_cfg()
            .with_secret("adv-256")
            .with_aes_key_bits(AesKeyBits::Aes256)
            .with_compression(true),
        50,
        &"compress-and-encrypt-".repeat(8),
    )
    .await;
}

#[tokio::test]
async fn adv_loopback_authenticated_srp() {
    // EAP-SRP gates the data channel; combined with PSK so the authenticated +
    // encrypted Advanced path is exercised end to end.
    run_loopback(
        adv_cfg()
            .with_secret("adv-psk")
            .with_aes_key_bits(AesKeyBits::Aes256)
            .with_srp_credentials("rist", "mainprofile"),
        50,
        "authenticated",
    )
    .await;
}

// ---- heavy-loss (25%) Advanced ARQ recovery ----
//
// This is the recovery the interop suite cannot prove against libRIST: libRIST's
// own Advanced sender does not reliably recover 25% loss (libRIST<->libRIST also
// drops packets at this rate — its Advanced RTT-echo *response* handler mis-scales
// the round-trip `>>16` instead of `>>32`, inflating its `last_rtt` ~15× and
// tripping its `delta < rtt` re-NACK suppression gate, so a doubly-dropped packet
// — common at 25%, rare at 10% — is never re-sent). ristrust sidesteps poisoning a
// libRIST peer by dropping inbound Advanced RTT-echo requests (see
// `driver_adv::drops_adv_echo_request`); here, ristrust<->ristrust, the flow core
// re-NACKs correctly and the sender suppresses duplicate retransmits within one
// RTT, so the loss/ARQ round trip stays tight and recovery is complete. A 500 ms
// buffer gives ample room on loopback; a trailing flush gives a dropped tail a
// delivered successor (pure ARQ cannot recover a lost tail).

/// Datagrams larger than this are treated as media and subject to loss; Advanced
/// control (Type=4 NACK/echo), keepalives, and the GRE handshake stay below it.
const MEDIA_THRESHOLD: usize = 128;

/// A [`Runtime`] whose UDP sockets drop a fraction of *forward media* datagrams
/// (those larger than [`MEDIA_THRESHOLD`]); small control compounds pass through
/// losslessly so the NACK return path always reaches the sender. Applied only to
/// the sender's transport. `dropped` counts the media datagrams actually dropped,
/// so the test can assert the loss/ARQ path was exercised (there is no public
/// `Stats` API yet — that lands in WP12).
struct LossyRuntime {
    loss: f64,
    next_seed: AtomicU64,
    dropped: Arc<AtomicU64>,
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
            dropped: Arc::clone(&self.dropped),
        }))
    }
}

/// A socket that drops large (media) sends with a seeded probability.
#[derive(Debug)]
struct LossySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    loss: f64,
    rng: Mutex<u64>,
    dropped: Arc<AtomicU64>,
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
            self.dropped.fetch_add(1, Ordering::Relaxed);
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
async fn adv_recovers_heavy_loss_via_arq() {
    const N: usize = 100; // payloads whose in-order delivery is asserted
    const FLUSH: usize = 24; // trailing packets so the last asserted payload has a
    // delivered successor to trigger its NACK (pure ARQ cannot recover a lost tail)
    // A >128-byte body so each media datagram is loss-eligible; distinct per index.
    let body = "advanced-heavy-loss-recovery-".repeat(8);

    // A 500 ms buffer leaves ample room for the deeper retransmit chains a quarter
    // loss produces (a retransmit can itself be dropped, needing a re-NACK).
    let cfg = adv_cfg().with_buffer(Duration::from_millis(500));
    let (mut receiver, port) = listen_free(&cfg).await; // lossless receiver

    let dropped = Arc::new(AtomicU64::new(0));
    let lossy = LossyRuntime {
        loss: 0.25,
        next_seed: AtomicU64::new(0x00C0_FFEE),
        dropped: Arc::clone(&dropped),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &lossy)
        .await
        .expect("dial with the lossy runtime");

    let mk = move |i: usize| format!("adv-{i:05}-{body}").into_bytes();
    let send_mk = mk.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..N + FLUSH {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(20), receiver.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("timed out on payload {i}: 25% ARQ recovery did not converge")
            })
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} out of order or corrupt under 25% loss"
        );
    }

    // The loss/ARQ path must actually have been exercised: at 25% forward media
    // loss over N+FLUSH datagrams the socket dropped at least one (and every
    // dropped payload above was recovered byte-exact by the Advanced NACK plane).
    assert!(
        dropped.load(Ordering::Relaxed) > 0,
        "no media dropped — the loss/ARQ path was not exercised"
    );

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn flow_attribute_round_trips_to_callback() {
    // The Advanced sender writes a flow attribute; the receiver surfaces it through
    // its configured callback (a fire-and-forget side channel, not media).
    let attr = br#"{"name":"cam-1","gop":60}"#.to_vec();
    let attrs = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let sink = Arc::clone(&attrs);
    let rx_cfg =
        adv_cfg().with_flow_attr_callback(move |json| sink.lock().expect("sink").push(json));
    let (mut receiver, port) = listen_free(&rx_cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), adv_cfg(), &TokioRuntime)
        .await
        .expect("dial the Advanced receiver");

    // One media payload warms the session, then the flow attribute is written.
    sender.send(b"adv-media-warmup").await.expect("send media");
    let got = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("media did not arrive")
        .expect("session open");
    assert_eq!(got.as_ref(), b"adv-media-warmup");
    sender
        .write_flow_attribute(&attr)
        .await
        .expect("write flow attr");

    // The attribute arrives out-of-band; poll until the callback has fired.
    for _ in 0..100 {
        if !attrs.lock().expect("recv").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Scope the guard so it is dropped before the awaits below.
    {
        let got = attrs.lock().expect("recv");
        assert_eq!(
            got.len(),
            1,
            "expected exactly one flow attribute, got {got:?}"
        );
        assert_eq!(got[0], attr, "flow attribute payload mismatch");
    }

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn write_flow_attribute_rejected_off_advanced() {
    // A non-Advanced sender has no flow-attribute channel.
    let sender = dial_with("127.0.0.1:5000", Config::default(), &TokioRuntime)
        .await
        .expect("dial simple");
    assert!(matches!(
        sender.write_flow_attribute(b"x").await,
        Err(rist::Error::FlowAttrUnsupported)
    ));
    sender.close().await.ok();
}
