//! End-to-end Main-profile (VSF TR-06-2) null-packet deletion on the send path:
//! with `Config::with_null_packet_deletion`, a `Sender` suppresses null MPEG-TS
//! packets and signals their positions in the RIST NPD RTP extension; the
//! `Receiver` reconstructs them byte-exact. A counting runtime witnesses that NPD
//! actually shrank the stream on the wire (the same payload sends far fewer media
//! bytes with NPD on than off), cleartext and AES-256.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rist::{
    AesKeyBits, AsyncUdpSocket, Config, Profile, Receiver, Runtime, TokioRuntime, dial_with, listen,
};

/// Bytes per MPEG-TS packet (the 188-byte form NPD acts on).
const TS: usize = 188;
/// TS packets per RTP media frame (7 × 188 = 1316, the canonical RTP TS payload).
const PER_FRAME: usize = 7;
/// Bytes per media frame.
const FRAME: usize = TS * PER_FRAME;
/// Datagrams larger than this are media; small control compounds stay below it.
const MEDIA_THRESHOLD: usize = 128;

/// One MPEG-TS null packet byte-for-byte as the receiver reconstructs it: 0x47
/// sync, PID 0x1FFF (the null PID), adaptation/flags byte 0x10, then 0xFF fill.
/// Because reconstruction is canonical, a payload whose nulls are already in this
/// exact form round-trips byte-exact through NPD suppression and expansion.
fn canonical_null_ts() -> [u8; TS] {
    let mut p = [0xFFu8; TS];
    p[0] = 0x47;
    p[1] = 0x1F;
    p[2] = 0xFF;
    p[3] = 0x10;
    p
}

/// One non-null MPEG-TS packet: 0x47 sync, PID 0x0100 (not the null PID), then a
/// seq-derived fill so distinct packets differ. NPD passes it through unchanged.
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

/// `frames` media frames of 7 TS packets each: one content packet at a rotating
/// position and six canonical null packets, so NPD suppresses 6 of every 7 — a
/// dramatic, easily-witnessed reduction — and the rotating position exercises the
/// full 7-bit null bitmap.
fn build_frames(frames: usize) -> Vec<Vec<u8>> {
    (0..frames)
        .map(|f| {
            let content = f % PER_FRAME;
            let mut frame = Vec::with_capacity(FRAME);
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

/// A [`Runtime`] that totals the bytes its sockets transmit in media-sized
/// datagrams — the witness that NPD shrank the wire. Wraps [`TokioRuntime`].
struct CountingRuntime {
    sent: Arc<AtomicU64>,
}

impl Runtime for CountingRuntime {
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
        Ok(Arc::new(CountingSocket {
            inner: TokioRuntime.bind(addr)?,
            sent: Arc::clone(&self.sent),
        }))
    }
}

/// A socket that adds each media-sized send to a shared total.
#[derive(Debug)]
struct CountingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    sent: Arc<AtomicU64>,
}

impl AsyncUdpSocket for CountingSocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        dest: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let r = self.inner.poll_send(cx, buf, dest);
        if let Poll::Ready(Ok(n)) = &r
            && buf.len() > MEDIA_THRESHOLD
        {
            self.sent.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
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

/// Binds a Main-profile receiver on an OS-chosen free port, retrying past the
/// probe/bind race.
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

/// Runs one Main-profile loopback: the sender (NPD per `npd_on`) writes each frame
/// as one `send`, the receiver reassembles, and the function asserts byte-exact
/// delivery and returns the media bytes the sender put on the wire.
async fn stream_npd_main(secret: Option<&str>, npd_on: bool, frames: &[Vec<u8>]) -> u64 {
    let mut cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_null_packet_deletion(npd_on);
    if let Some(s) = secret {
        cfg = cfg.with_secret(s).with_aes_key_bits(AesKeyBits::Aes256);
    }
    cfg.validate().expect("config valid");

    let (mut receiver, port) = listen_free(&cfg).await;
    let sent = Arc::new(AtomicU64::new(0));
    let rt = CountingRuntime {
        sent: Arc::clone(&sent),
    };
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &rt)
        .await
        .expect("dial the Main receiver");

    let send_frames = frames.to_vec();
    let send_task = tokio::spawn(async move {
        for frame in &send_frames {
            sender.send(frame).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for (i, want) in frames.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on frame {i}"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            want.as_slice(),
            "frame {i} not reconstructed byte-exact (npd_on={npd_on})"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
    sent.load(Ordering::Relaxed)
}

#[tokio::test]
async fn npd_send_path_shrinks_wire_and_round_trips_cleartext() {
    // 14 frames: each of the 7 null-bitmap positions exercised twice.
    let frames = build_frames(14);
    let off = stream_npd_main(None, false, &frames).await;
    let on = stream_npd_main(None, true, &frames).await;
    assert!(off > 0 && on > 0, "no media counted (off={off} on={on})");
    // 6 of every 7 TS packets are suppressed, so NPD must shrink the media wire
    // dramatically — well under half the bytes even with framing overhead.
    assert!(
        on * 2 < off,
        "NPD did not shrink the wire: {on} bytes with NPD vs {off} without"
    );
}

#[tokio::test]
async fn npd_send_path_round_trips_aes256() {
    let frames = build_frames(7);
    let off = stream_npd_main(Some("npd-256"), false, &frames).await;
    let on = stream_npd_main(Some("npd-256"), true, &frames).await;
    assert!(
        on * 2 < off,
        "NPD did not shrink the encrypted wire: {on} vs {off}"
    );
}
