//! End-to-end NAT source-port rebind recovery on an authenticated Main EAP-SRP
//! session (mirrors libRIST issue #188, SRP only). A reversed-role listener-sender
//! (the authenticatee) serves a caller-receiver (the authenticator) through a proxy
//! that, mid-stream, moves the receiver's traffic to a NEW source tuple — exactly a
//! dynamic-NAT source-port rebind. The listener detects the moved tuple only after
//! the old one goes dormant, forces a fresh EAP-SRP re-auth (a replay/forger could
//! not complete it), migrates the peer, and the stream is delivered in order —
//! recovering what a locked-address session would have lost to a session timeout.
//!
//! Three behaviours are pinned: the happy-path recovery; an adversarial forger from a
//! foreign tuple that must NOT displace a live session; and a stalled re-auth that
//! must tear the session down at the bounded deadline rather than wedge it open.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rist::{Config, Error, Profile, Sender, dial_receiver, listen_sender};
use tokio::net::UdpSocket;

/// A reversed-role Main config with EAP-SRP (no PSK secret, so the data channel
/// re-keys to the SRP session key K — the encrypted RTCP that carries the CNAME the
/// rebind trigger validates) and a short keepalive (`2×` = the dormancy threshold).
fn srp_cfg(buffer_ms: u64, keepalive_ms: u64) -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(buffer_ms))
        .with_keepalive(Duration::from_millis(keepalive_ms))
        .with_srp_credentials("rist", "nat-rebind")
}

/// Binds a reversed-role listener-sender on an OS-chosen free port, returning it and
/// the port a caller-receiver (or the rebind proxy) dials.
async fn listen_sender_free(cfg: &Config) -> (Sender, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if port == 0 {
            continue;
        }
        if let Ok(s) = listen_sender(&format!("127.0.0.1:{port}"), cfg.clone()).await {
            return (s, port);
        }
    }
    panic!("no free port for the listener-sender");
}

/// The mutable half of the proxy's back path: the socket whose source the listener
/// sees, and a cancel flag that stops its reader the instant the socket is swapped.
struct BackState {
    sock: Arc<UdpSocket>,
    cancel: Arc<AtomicBool>,
}

/// A relay between a caller-receiver and a listener-sender. `rebind` swaps the socket
/// it uses toward the listener, so the listener sees the receiver's traffic arrive
/// from a NEW source tuple — the NAT source-port rebind a dynamic-NAT caller suffers.
/// `block_back` suppresses the listener→caller direction, stalling a re-auth.
struct RebindProxy {
    front: Arc<UdpSocket>,
    listener: SocketAddr,
    caller: Arc<Mutex<Option<SocketAddr>>>,
    block_back: Arc<AtomicBool>,
    back: Arc<Mutex<BackState>>,
    front_port: u16,
}

impl RebindProxy {
    /// Starts a proxy in front of the listener-sender on `listener_port`, returning it
    /// and the front port the caller-receiver dials.
    async fn start(listener_port: u16) -> Arc<RebindProxy> {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("front bind"));
        let front_port = front.local_addr().expect("front addr").port();
        let back0 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("back bind"));
        let cancel0 = Arc::new(AtomicBool::new(false));
        let listener = format!("127.0.0.1:{listener_port}")
            .parse()
            .expect("listener addr");
        let p = Arc::new(RebindProxy {
            front,
            listener,
            caller: Arc::new(Mutex::new(None)),
            block_back: Arc::new(AtomicBool::new(false)),
            back: Arc::new(Mutex::new(BackState {
                sock: back0.clone(),
                cancel: cancel0.clone(),
            })),
            front_port,
        });
        tokio::spawn(forward(
            p.front.clone(),
            p.listener,
            p.caller.clone(),
            p.back.clone(),
        ));
        spawn_back_reader(
            p.front.clone(),
            back0,
            p.caller.clone(),
            p.block_back.clone(),
            cancel0,
        );
        p
    }

    /// Swaps the back socket so the listener sees a new source tuple (and stops the
    /// old reader so nothing keeps flowing on the abandoned tuple — that silence is
    /// what eventually trips the dormancy gate).
    async fn rebind(&self) {
        let nb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("rebind bind"));
        let new_cancel = Arc::new(AtomicBool::new(false));
        {
            let mut g = self.back.lock().unwrap();
            g.cancel.store(true, Ordering::Relaxed);
            g.sock = nb.clone();
            g.cancel = new_cancel.clone();
        }
        spawn_back_reader(
            self.front.clone(),
            nb,
            self.caller.clone(),
            self.block_back.clone(),
            new_cancel,
        );
    }

    /// Suppresses the listener→caller relay, so a forced re-auth's EAPOL never reaches
    /// the caller and the handshake cannot complete.
    fn block_back(&self) {
        self.block_back.store(true, Ordering::Relaxed);
    }
}

/// Relays caller→proxy→listener, learning the caller's address from each datagram.
async fn forward(
    front: Arc<UdpSocket>,
    listener: SocketAddr,
    caller: Arc<Mutex<Option<SocketAddr>>>,
    back: Arc<Mutex<BackState>>,
) {
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, src)) = front.recv_from(&mut buf).await else {
            return;
        };
        let sock = {
            *caller.lock().unwrap() = Some(src);
            back.lock().unwrap().sock.clone()
        };
        let _ = sock.send_to(&buf[..n], listener).await;
    }
}

/// Relays listener→proxy→caller on one back socket until its `cancel` flag is set
/// (the socket was swapped by a rebind). A set `block` flag drops the relay,
/// stalling the listener→caller direction without ending the reader.
fn spawn_back_reader(
    front: Arc<UdpSocket>,
    back: Arc<UdpSocket>,
    caller: Arc<Mutex<Option<SocketAddr>>>,
    block: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((n, _)) = back.recv_from(&mut buf).await else {
                return;
            };
            if cancel.load(Ordering::Relaxed) {
                return; // this socket was abandoned by a rebind: stop relaying it.
            }
            if block.load(Ordering::Relaxed) {
                continue;
            }
            let c = *caller.lock().unwrap();
            if let Some(c) = c {
                let _ = front.send_to(&buf[..n], c).await;
            }
        }
    });
}

#[tokio::test]
async fn nat_rebind_srp_recovers_after_source_port_change() {
    const N: usize = 400;
    const REBIND_AT: usize = 60;
    // A generous buffer so ARQ recovers the gap the dormancy window drops; a 100ms
    // keepalive means a 200ms dormancy threshold before the moved tuple is honored.
    let cfg = srp_cfg(2000, 100);
    let (sender, listener_port) = listen_sender_free(&cfg).await;
    let proxy = RebindProxy::start(listener_port).await;
    let mut receiver = dial_receiver(&format!("127.0.0.1:{}", proxy.front_port), cfg.clone())
        .await
        .expect("dial through the proxy");

    let payload = |i: usize| format!("nat-{i:04}-{}", "z".repeat(160)).into_bytes();

    let send_proxy = proxy.clone();
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            if sender.send(&payload(i)).await.is_err() {
                break;
            }
            if i == REBIND_AT {
                // Move the receiver's traffic to a fresh source tuple mid-stream.
                send_proxy.rebind().await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i} (delivered before stall)"))
            .expect("session stayed open across the rebind");
        assert_eq!(
            got.as_ref(),
            payload(i).as_slice(),
            "payload {i} out of order or corrupt after the rebind"
        );
    }

    // The recovery must have actually been exercised: ARQ healed the gap the dormancy
    // window dropped while the migration + re-auth completed.
    assert!(
        receiver.stats().recovered > 0,
        "no ARQ recovery — the rebind gap was not exercised (test no longer covers the path)"
    );

    let sender = send_task.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close receiver");
    drop(proxy);
}

#[tokio::test]
async fn nat_rebind_forger_cannot_hijack_live_session() {
    const N: usize = 200;
    // While an authenticated EAP-SRP stream is live, a third party floods the
    // listener-sender from a DIFFERENT source tuple. Because the established peer is
    // not dormant and the forged datagrams do not decode under the session key, the
    // re-association gate refuses them — the peer is never displaced and the stream is
    // delivered in order. (A forger that waited for dormancy still could not complete
    // the forced re-auth; this proves the live-session case, the easiest to attempt.)
    let cfg = srp_cfg(800, 100);
    let (sender, listener_port) = listen_sender_free(&cfg).await;
    let mut receiver = dial_receiver(&format!("127.0.0.1:{listener_port}"), cfg.clone())
        .await
        .expect("dial the listener-sender");

    let payload = |i: usize| format!("forge-{i:04}-{}", "y".repeat(120)).into_bytes();

    // Establish + authenticate first (media only flows once authenticated), so the
    // listener's peer is locked to the genuine caller before the forger appears.
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            if sender.send(&payload(i)).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
        sender
    });

    let first = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
        .await
        .expect("first payload before timeout")
        .expect("session open");
    assert_eq!(first.as_ref(), payload(0).as_slice());

    // The forger: a separate socket spraying garbage at the listener-sender from its
    // own tuple. None of it decodes under the session key.
    let forger = UdpSocket::bind("127.0.0.1:0").await.expect("forger bind");
    forger
        .connect(format!("127.0.0.1:{listener_port}"))
        .await
        .expect("forger connect");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_forge = stop.clone();
    let forge_task = tokio::spawn(async move {
        let junk = [0xABu8; 200];
        while !stop_forge.load(Ordering::Relaxed) {
            let _ = forger.send(&junk).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    });

    for i in 1..N {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("forged flood disrupted delivery at {i}"))
            .expect("session stayed open under the forged flood");
        assert_eq!(got.as_ref(), payload(i).as_slice(), "payload {i} corrupt");
    }

    stop.store(true, Ordering::Relaxed);
    forge_task.await.expect("forge task");
    let sender = send_task.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn nat_rebind_stalled_reauth_tears_down_at_deadline() {
    // A genuine rebind trigger forces a re-auth, but the listener→caller direction is
    // blocked so the handshake can never complete. The session must NOT wedge open on
    // the unproven tuple: it is torn down at the bounded re-auth deadline
    // (max(recovery_buffer_max, 4×keepalive)), and the sender surfaces the timeout.
    let cfg = srp_cfg(800, 100); // reauth deadline = max(800ms, 400ms) = 800ms
    let (sender, listener_port) = listen_sender_free(&cfg).await;
    let proxy = RebindProxy::start(listener_port).await;
    let mut receiver = dial_receiver(&format!("127.0.0.1:{}", proxy.front_port), cfg.clone())
        .await
        .expect("dial through the proxy");

    let payload = |i: usize| format!("hold-{i:04}").into_bytes();

    // Establish + authenticate, draining a few payloads so the peer + CNAME are known.
    let send_proxy = proxy.clone();
    let send_task = tokio::spawn(async move {
        let mut err = None;
        for i in 0..2000usize {
            if let Err(e) = sender.send(&payload(i)).await {
                err = Some(e);
                break;
            }
            if i == 20 {
                // Block the return path, then move the tuple: the trigger reaches the
                // listener (caller→listener is open) but the re-auth EAPOL cannot get
                // back, so the handshake stalls and must time out.
                send_proxy.block_back();
                send_proxy.rebind().await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        (sender, err)
    });

    // Drain whatever arrives before the stall; the receiver eventually stops.
    let mut delivered = 0usize;
    while (tokio::time::timeout(Duration::from_secs(3), receiver.recv()).await)
        .is_ok_and(|r| r.is_ok())
    {
        delivered += 1;
        if delivered > 25 {
            break;
        }
    }
    assert!(delivered > 0, "no media delivered before the stall");

    let (sender, err) = tokio::time::timeout(Duration::from_secs(8), send_task)
        .await
        .expect("the stalled re-auth must tear the session down, not hang")
        .expect("send task");
    assert!(
        matches!(err, Some(Error::SessionTimeout)),
        "expected Error::SessionTimeout from the bounded re-auth deadline, got {err:?}"
    );
    sender.close().await.ok();
    receiver.close().await.ok();
    drop(proxy);
}
