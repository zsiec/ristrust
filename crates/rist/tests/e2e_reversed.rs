//! End-to-end reversed-role transport: the media *sender* listens and the media
//! *receiver* dials it (the inverse of the usual roles), for pull / NAT-traversal
//! topologies. The caller-receiver announces itself; the listener-sender learns the
//! return address and then streams media, held until the caller connects. Main and
//! Advanced profiles, cleartext and PSK-encrypted.

use std::time::Duration;

use rist::{AesKeyBits, Config, Profile, Sender, dial_receiver, listen_sender};

/// A reversed-role base config for `profile` with a short recovery buffer.
fn rev_cfg(profile: Profile, secret: Option<&str>) -> Config {
    let mut c = Config::default()
        .with_profile(profile)
        .with_buffer(Duration::from_millis(150));
    if let Some(s) = secret {
        c = c.with_secret(s).with_aes_key_bits(AesKeyBits::Aes256);
    }
    c
}

/// Binds a listener-sender on an OS-chosen free port, returning it and the port a
/// caller-receiver dials.
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

/// Drives `N` payloads from a listener-sender to a caller-receiver and asserts
/// in-order byte integrity.
async fn reversed_round_trip(profile: Profile, secret: Option<&str>) {
    const N: usize = 30;
    let cfg = rev_cfg(profile, secret);
    let (sender, port) = listen_sender_free(&cfg).await;
    let mut receiver = dial_receiver(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the listener-sender");

    // The sender's media is held until the caller-receiver announces itself, then
    // flows; the buffered writes drain in order.
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(format!("rev-{i:03}").as_bytes())
                .await
                .expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(got.as_ref(), format!("rev-{i:03}").as_bytes());
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn reversed_role_delivers_cleartext() {
    reversed_round_trip(Profile::Main, None).await;
}

#[tokio::test]
async fn reversed_role_delivers_aes256() {
    reversed_round_trip(Profile::Main, Some("reversed-secret")).await;
}

#[tokio::test]
async fn reversed_role_delivers_advanced_cleartext() {
    reversed_round_trip(Profile::Advanced, None).await;
}

#[tokio::test]
async fn reversed_role_delivers_advanced_aes256() {
    reversed_round_trip(Profile::Advanced, Some("reversed-adv-secret")).await;
}

#[tokio::test]
async fn reversed_role_delivers_simple() {
    // Simple reversed-role: the listener-sender learns the caller's even media port from
    // its odd RTCP announcement and streams to it, held until the caller is known.
    reversed_round_trip(Profile::Simple, None).await;
}

#[tokio::test]
async fn reversed_role_delivers_authenticated_srp() {
    // EAP-SRP over the reversed-role transport: the listener-sender is the
    // authenticatee and opens its EAPOL-START once the caller-receiver (the
    // authenticator) announces itself; media is held until the handshake
    // authenticates, then flows in order. Combined with a PSK so the
    // authenticated + encrypted reversed-role path is exercised end to end.
    const N: usize = 30;
    let cfg = rev_cfg(Profile::Main, Some("rev-psk")).with_srp_credentials("rist", "reversed");
    let (sender, port) = listen_sender_free(&cfg).await;
    let mut receiver = dial_receiver(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the listener-sender");

    let send_task = tokio::spawn(async move {
        for i in 0..N {
            sender
                .send(format!("rev-srp-{i:03}").as_bytes())
                .await
                .expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(got.as_ref(), format!("rev-srp-{i:03}").as_bytes());
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}
