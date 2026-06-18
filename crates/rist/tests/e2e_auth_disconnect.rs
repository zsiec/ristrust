//! Auth-handler follow-ups (libRIST `rist_auth_handler_set`): the disconnect callback
//! (fired when a connected peer's session ends) on a single-flow Main receiver, and the
//! connect callback on a bonded receiver (the gate fires once when the bonded session
//! first authenticates).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rist::{
    Config, ConnectInfo, Profile, TokioRuntime, dial_bonded, dial_with, listen, listen_bonded,
};

/// A free port via an ephemeral probe (retried by the caller on bind race).
fn free_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
    let p = s.local_addr().expect("addr").port();
    drop(s);
    p
}

#[tokio::test]
async fn disconnect_callback_fires_when_session_times_out() {
    // Connect with a connect callback (accept + record), stream, then close the sender so
    // the receiver times out — its run loop breaks and fires the disconnect callback with
    // the same ConnectInfo. (close() aborts the task with no cleanup, so the disconnect
    // fires on the natural session-timeout teardown, mirroring libRIST's disconn_cb.)
    let connected: Arc<Mutex<Option<ConnectInfo>>> = Arc::new(Mutex::new(None));
    let disconnected: Arc<Mutex<Option<ConnectInfo>>> = Arc::new(Mutex::new(None));
    let c1 = Arc::clone(&connected);
    let d1 = Arc::clone(&disconnected);

    let recv_cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_keepalive(Duration::from_millis(100))
        .with_session_timeout(Duration::from_millis(400))
        .with_srp_credentials("alice", "pw")
        .with_connect_callback(move |i: &ConnectInfo| {
            *c1.lock().unwrap() = Some(i.clone());
            true
        })
        .with_disconnect_callback(move |i: &ConnectInfo| {
            *d1.lock().unwrap() = Some(i.clone());
        });

    // Bind the receiver (retry past the probe/bind race).
    let (mut receiver, port) = loop {
        let p = free_port();
        if let Ok(r) = listen(&format!("127.0.0.1:{p}"), recv_cfg.clone()).await {
            break (r, p);
        }
    };
    let send_cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_keepalive(Duration::from_millis(100))
        .with_session_timeout(Duration::from_millis(400))
        .with_srp_credentials("alice", "pw");
    let sender = dial_with(&format!("127.0.0.1:{port}"), send_cfg, &TokioRuntime)
        .await
        .expect("dial");

    // Stream until at least one payload is delivered (proving the connect succeeded).
    for i in 0..20 {
        sender
            .send(format!("d-{i}").as_bytes())
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let first = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("not timed out")
        .expect("delivered");
    assert!(!first.is_empty());
    assert_eq!(
        connected
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|i| i.username.clone()),
        Some("alice".to_string()),
        "connect callback should have fired with the username"
    );

    // Close the sender; the receiver times out, breaks, and fires the disconnect callback.
    sender.close().await.ok();
    loop {
        let polled = tokio::time::timeout(Duration::from_secs(3), receiver.recv()).await;
        let Ok(inner) = polled else {
            panic!("receiver never timed out after the sender closed");
        };
        if inner.is_err() {
            break; // session ended (the expected timeout teardown)
        }
        // else: drained a buffered payload; keep going.
    }
    let info = disconnected
        .lock()
        .unwrap()
        .clone()
        .expect("disconnect callback should have fired on session end");
    assert_eq!(info.username.as_deref(), Some("alice"));
    receiver.close().await.expect("close");
}

#[tokio::test]
async fn bonded_connect_callback_admits_and_observes() {
    // A bonded receiver with a connect callback: the bonded session authenticates over its
    // paths and the gate fires once with the authenticated username; the stream delivers.
    let seen: Arc<Mutex<Option<ConnectInfo>>> = Arc::new(Mutex::new(None));
    let seen_cb = Arc::clone(&seen);

    let recv_cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200))
        .with_secret("psk")
        .with_srp_credentials("carol", "pw")
        .with_connect_callback(move |i: &ConnectInfo| {
            *seen_cb.lock().unwrap() = Some(i.clone());
            true
        });
    let send_cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200))
        .with_secret("psk")
        .with_srp_credentials("carol", "pw");

    // Two bonded paths on distinct free ports (retry past the bind race).
    let (mut receiver, addrs) = loop {
        let p1 = free_port();
        let p2 = free_port();
        if p1 == p2 {
            continue;
        }
        let addrs = [format!("127.0.0.1:{p1}"), format!("127.0.0.1:{p2}")];
        let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        if let Ok(r) = listen_bonded(&refs, recv_cfg.clone()).await {
            break (r, addrs);
        }
    };
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded(&refs, send_cfg).await.expect("dial bonded");

    let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i.wrapping_add(1); 200]).collect();
    let send_frames = frames.clone();
    let driver = tokio::spawn(async move {
        for f in &send_frames {
            sender.send(f).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        // keep the sender alive a moment so the receiver drains
        tokio::time::sleep(Duration::from_millis(200)).await;
        sender
    });

    for (i, want) in frames.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out at frame {i}"))
            .expect("session open");
        assert_eq!(got.as_ref(), want.as_slice(), "frame {i}");
    }
    let sender = driver.await.expect("driver");

    let info = seen
        .lock()
        .unwrap()
        .clone()
        .expect("bonded connect callback should have fired");
    assert_eq!(info.username.as_deref(), Some("carol"));
    assert!(info.remote.ip().is_loopback());

    sender.close().await.ok();
    receiver.close().await.expect("close");
}
