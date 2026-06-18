//! Auth-handler connect callback (libRIST `rist_auth_handler_set`) + multi-user SRP
//! (`rist_enable_eap_srp_2`) over a Main-profile loopback: a listener configured with
//! several SRP users authenticates whichever one connects, and a connection callback
//! gates (accepts / rejects) the authenticated identity.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rist::{Config, ConnectInfo, Error, Profile, Receiver, TokioRuntime, dial_with, listen};

/// A Main-profile, SRP-only base config (no PSK; the data channel keys from the SRP
/// session key — a ristrust↔ristrust mode) with a short buffer + keepalive.
fn auth_cfg() -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_keepalive(Duration::from_millis(100))
}

/// Binds a Main receiver on an OS-chosen free port, retrying past the probe/bind race.
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
    panic!("no free port for the Main receiver");
}

/// Streams `n` payloads sender → receiver and asserts in-order byte integrity.
async fn expect_delivers(mut receiver: Receiver, send_cfg: Config, port: u16, n: usize) {
    let sender = dial_with(&format!("127.0.0.1:{port}"), send_cfg, &TokioRuntime)
        .await
        .expect("dial");
    let mk = |i: usize| format!("auth-{i:04}").into_bytes();
    let send = tokio::spawn(async move {
        for i in 0..n + 8 {
            sender.send(&mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });
    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} corrupt/out of order"
        );
    }
    let sender = send.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close");
}

#[tokio::test]
async fn multi_user_srp_authenticates_any_configured_user() {
    // The listener is configured with two users; a sender authenticating as the SECOND
    // one succeeds — the authenticator looks the verifier up by the presented username.
    let recv_cfg = auth_cfg().with_srp_users([
        ("alice".to_string(), "alice-pw".to_string()),
        ("bob".to_string(), "bob-pw".to_string()),
    ]);
    let (receiver, port) = listen_free(&recv_cfg).await;
    let send_cfg = auth_cfg().with_srp_credentials("bob", "bob-pw");
    expect_delivers(receiver, send_cfg, port, 40).await;
}

#[tokio::test]
async fn connect_callback_accepts_and_observes_identity() {
    // The connect callback accepts and records the authenticated ConnectInfo; the
    // stream then delivers, and the callback saw the right username + a loopback remote.
    let seen: Arc<Mutex<Option<ConnectInfo>>> = Arc::new(Mutex::new(None));
    let seen_cb = Arc::clone(&seen);
    let recv_cfg = auth_cfg()
        .with_srp_credentials("alice", "alice-pw")
        .with_connect_callback(move |info: &ConnectInfo| {
            *seen_cb.lock().unwrap() = Some(info.clone());
            true
        });
    let (receiver, port) = listen_free(&recv_cfg).await;
    let send_cfg = auth_cfg().with_srp_credentials("alice", "alice-pw");
    expect_delivers(receiver, send_cfg, port, 40).await;

    let info = seen
        .lock()
        .unwrap()
        .clone()
        .expect("connect callback fired");
    assert_eq!(info.username.as_deref(), Some("alice"));
    assert!(
        info.remote.ip().is_loopback(),
        "remote should be loopback: {info:?}"
    );
}

#[tokio::test]
async fn connect_callback_rejects_unwanted_user() {
    // The listener accepts two users but the connect callback admits only "alice"; a
    // sender authenticating as "bob" is rejected — the session is torn down and `recv`
    // reports an auth failure (not a hang). The callback observed "bob".
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let seen_cb = Arc::clone(&seen);
    let recv_cfg = auth_cfg()
        .with_srp_users([
            ("alice".to_string(), "alice-pw".to_string()),
            ("bob".to_string(), "bob-pw".to_string()),
        ])
        .with_connect_callback(move |info: &ConnectInfo| {
            *seen_cb.lock().unwrap() = info.username.clone();
            info.username.as_deref() == Some("alice")
        });
    let (mut receiver, port) = listen_free(&recv_cfg).await;
    let send_cfg = auth_cfg().with_srp_credentials("bob", "bob-pw");
    let sender = dial_with(&format!("127.0.0.1:{port}"), send_cfg, &TokioRuntime)
        .await
        .expect("dial");

    let got = tokio::time::timeout(Duration::from_secs(6), receiver.recv())
        .await
        .expect("a rejected connection must resolve recv, not hang");
    assert!(
        matches!(got, Err(Error::Auth)),
        "expected Error::Auth on a rejected peer, got {got:?}"
    );
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("bob"),
        "callback should have seen the rejected username"
    );
    sender.close().await.ok();
    receiver.close().await.expect("close");
}
