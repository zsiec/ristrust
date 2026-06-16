//! End-to-end SMPTE ST 2022-1 forward-error-correction loopback (WP18c + WP18d):
//! a real `Sender` carries FEC-protected media to a real `Receiver` and a dropped
//! media packet is reconstructed by FEC — with NO ARQ round trip.
//!
//! Each recovery test runs in **one-way mode** (`with_one_way`), which disables the
//! NACK/retransmit plane entirely, so the only way a dropped packet can reach the
//! application is FEC recovery: if the byte-exact in-order stream survives a dropped
//! media datagram, FEC did it. The Advanced profile carries FEC in-band (Type=Control
//! messages over the full wire datagram); the Simple profile carries it as standard
//! ST 2022-1 RTP on the dedicated column (media + 2) / row (media + 4) ports — the
//! interoperable GStreamer/FFmpeg carriage.

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
    dial_with, listen,
};

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

/// Binds a receiver on an OS-chosen free even port (FEC needs the +2/+4 ports free
/// too, so a small gap above the candidate is left implicitly by probing).
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let mut candidate = probe.local_addr().expect("probe addr").port();
        drop(probe);
        // The Simple profile requires an even media port (RTCP at +1, FEC at +2/+4).
        if !candidate.is_multiple_of(2) {
            candidate = candidate.wrapping_sub(1);
        }
        if candidate < 2 {
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

/// A [`Runtime`] whose sockets drop datagrams for which `pred` returns true (used to
/// drop exactly one media datagram while letting FEC and control through). Applied to
/// the sender's transport only.
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

/// Runs a one-way FEC stream of `n` payloads from a `DropRuntime`-wrapped sender to a
/// lossless receiver, asserting every payload (including the FEC-dropped one) arrives
/// in order, byte-exact, and that the drop actually fired.
async fn run_fec_recovery(
    cfg: Config,
    n: usize,
    body: String,
    pred: DropPred,
    dropped: Arc<AtomicU64>,
) {
    let (mut receiver, port) = listen_free(&cfg).await;
    let rt = DropRuntime {
        pred,
        dropped: Arc::clone(&dropped),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &rt)
        .await
        .expect("dial with the dropping runtime");

    let mk = move |i: usize| format!("fec-{i:05}-{body}").into_bytes();
    let send_mk = mk.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..n {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Hold the sender open while the receiver drains (one-way: no close handshake).
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
    });

    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}: FEC recovery did not converge"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
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
    // Drop exactly one Advanced DIRECT (Type=5) media datagram; the in-band Type=4
    // FEC control survives and reconstructs it. One-way (no ARQ) proves it was FEC.
    // The ~1400-byte body makes the full-datagram FEC control exceed the 1400-byte
    // MTU cap, so each FEC packet is FRAGMENTED across two consecutive control packets
    // and the receiver must reassemble them (the fecCtrlReassembler path).
    const DROP_AT: u64 = 21; // a row-interior media packet, mid-stream
    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());

    let seen = Arc::new(AtomicU64::new(0));
    let seen_p = Arc::clone(&seen);
    let pred: DropPred = Arc::new(move |buf: &[u8], _dst| {
        // Identify DIRECT media by the Advanced encapsulation type; never drop the
        // Type=4 FEC control or the Type=8 GRE substrate.
        if let Ok(p) = rist_codec::adv::parse(&Bytes::copy_from_slice(buf))
            && p.enc_type == rist_codec::adv::TYPE_DIRECT
        {
            return seen_p.fetch_add(1, Ordering::Relaxed) == DROP_AT;
        }
        false
    });
    let dropped = Arc::new(AtomicU64::new(0));
    run_fec_recovery(cfg, 64, "x".repeat(1400), pred, dropped).await;
}

#[tokio::test]
async fn simple_separate_port_fec_recovers_a_dropped_media_packet() {
    // Drop exactly one Simple media datagram (sent to the media port); the FEC RTP on
    // the column/row ports (+2/+4) survives and reconstructs it. One-way (no ARQ).
    const DROP_AT: u64 = 21;
    let cfg = Config::default()
        .with_profile(Profile::Simple)
        .with_one_way(true)
        .with_buffer(Duration::from_millis(500))
        .with_fec(fec_2d());

    // listen_free binds an even port; capture it so the predicate can target media.
    let (mut receiver, port) = listen_free(&cfg).await;
    let seen = Arc::new(AtomicU64::new(0));
    let seen_p = Arc::clone(&seen);
    let pred: DropPred = Arc::new(move |_buf: &[u8], dst: SocketAddr| {
        // Media goes to the media port; FEC goes to +2/+4 (kept), RTCP to +1.
        if dst.port() == port {
            return seen_p.fetch_add(1, Ordering::Relaxed) == DROP_AT;
        }
        false
    });
    let dropped = Arc::new(AtomicU64::new(0));
    let rt = DropRuntime {
        pred,
        dropped: Arc::clone(&dropped),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &rt)
        .await
        .expect("dial with the dropping runtime");

    let body = "fec-protected-media-payload-".repeat(6);
    let mk = move |i: usize| format!("fec-{i:05}-{body}").into_bytes();
    let send_mk = mk.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..64usize {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
    });
    for i in 0..64usize {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("timed out on payload {i}: separate-port FEC did not converge")
            })
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
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
async fn fec_clean_loopback_does_not_disturb_the_stream() {
    // FEC enabled, no loss: the extra FEC traffic (in-band control / separate-port
    // RTP) must not perturb ordinary in-order delivery on either profile.
    for profile in [Profile::Advanced, Profile::Simple] {
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
