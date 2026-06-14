//! End-to-end Advanced-profile (VSF TR-06-3) loopback: a real `Sender` carries
//! media over the single-port RTP/PT=127 hybrid to a real `Receiver` — cleartext,
//! PSK-encrypted (AES-128/256), LZ4-compressed, and authenticated — and every
//! payload arrives in order with its bytes intact. This proves the Advanced host
//! (adv header + control codec, LZ4, AES-CTR payload, the GRE-substrate driver)
//! carries media end to end.

use std::time::Duration;

use rist::{AesKeyBits, Config, Profile, Receiver, TokioRuntime, dial_with, listen};

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
