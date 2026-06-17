//! End-to-end out-of-band passthrough (TR-06-2 GRE OOB): a `Sender` tunnels an
//! out-of-band datagram alongside the media stream and the `Receiver` reads it back
//! byte-exact, on the Main and Advanced profiles, cleartext and PSK-encrypted. OOB
//! bypasses the flow core (no ARQ/reorder); it rides the GRE substrate with a
//! non-reserved protocol type.

use std::time::Duration;

use rist::{
    AesKeyBits, Config, Error, OOB_PROTOCOL_IP, Profile, Receiver, TokioRuntime, dial_with, listen,
};

/// A single-port (Main/Advanced) base config with a short recovery buffer.
fn cfg(profile: Profile, secret: Option<&str>) -> Config {
    let mut c = Config::default()
        .with_profile(profile)
        .with_buffer(Duration::from_millis(150));
    if let Some(s) = secret {
        c = c.with_secret(s).with_aes_key_bits(AesKeyBits::Aes256);
    }
    c
}

/// Binds a Main/Advanced receiver on an OS-chosen free port.
async fn listen_free(c: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if port == 0 {
            continue;
        }
        if let Ok(r) = listen(&format!("127.0.0.1:{port}"), c.clone()).await {
            return (r, port);
        }
    }
    panic!("no free port for the receiver");
}

/// Drives one OOB datagram (under `proto`) sender → receiver and asserts it arrives
/// byte-exact with its protocol type, on the given profile/secret.
async fn oob_round_trip(profile: Profile, secret: Option<&str>, proto: u16) {
    let c = cfg(profile, secret);
    let (mut receiver, port) = listen_free(&c).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), c.clone(), &TokioRuntime)
        .await
        .expect("dial");

    // A media warm-up establishes the session before the OOB datagram.
    sender.send(b"media-warmup").await.expect("send media");
    let _ = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("media did not arrive")
        .expect("session open");

    let payload = b"out-of-band-tunnel-payload";
    sender
        .write_oob_typed(proto, payload)
        .await
        .expect("write oob");

    let (got_proto, got) = tokio::time::timeout(Duration::from_secs(5), receiver.read_oob_typed())
        .await
        .expect("oob did not arrive")
        .expect("oob channel open");
    assert_eq!(got_proto, proto, "OOB protocol type mismatch");
    assert_eq!(got.as_ref(), payload, "OOB payload mismatch");

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

/// Drives one OOB datagram receiver → sender (the reverse direction) and asserts it
/// arrives byte-exact, on the given profile/secret.
async fn reverse_oob_round_trip(profile: Profile, secret: Option<&str>) {
    let c = cfg(profile, secret);
    let (mut receiver, port) = listen_free(&c).await;
    let mut sender = dial_with(&format!("127.0.0.1:{port}"), c.clone(), &TokioRuntime)
        .await
        .expect("dial");

    // Warm up so the receiver learns the sender's return address (reverse OOB is
    // dropped until the peer is known).
    sender.send(b"media-warmup").await.expect("send media");
    let _ = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("media did not arrive")
        .expect("session open");

    let payload = b"reverse-oob-from-the-receiver";
    receiver
        .write_oob(payload)
        .await
        .expect("receiver write oob");

    let (got_proto, got) = tokio::time::timeout(Duration::from_secs(5), sender.read_oob_typed())
        .await
        .expect("reverse oob did not arrive")
        .expect("sender oob channel open");
    assert_eq!(
        got_proto, OOB_PROTOCOL_IP,
        "reverse OOB protocol type mismatch"
    );
    assert_eq!(got.as_ref(), payload, "reverse OOB payload mismatch");

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn reverse_oob_round_trips_main_cleartext() {
    reverse_oob_round_trip(Profile::Main, None).await;
}

#[tokio::test]
async fn reverse_oob_round_trips_main_aes256() {
    reverse_oob_round_trip(Profile::Main, Some("rev-oob-secret")).await;
}

#[tokio::test]
async fn reverse_oob_round_trips_advanced() {
    reverse_oob_round_trip(Profile::Advanced, Some("rev-adv-oob")).await;
}

#[tokio::test]
async fn receiver_write_oob_rejected_on_simple() {
    // A Simple-profile receiver has no OOB side channel.
    let (rx, _port) = {
        let c = Config::default(); // Simple
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
        let mut port = probe.local_addr().expect("addr").port();
        if !port.is_multiple_of(2) {
            port = port.wrapping_sub(1);
        }
        drop(probe);
        let r = listen(&format!("127.0.0.1:{port}"), c)
            .await
            .expect("listen simple");
        (r, port)
    };
    assert!(matches!(
        rx.write_oob(b"x").await,
        Err(Error::OobUnsupported)
    ));
    rx.close().await.ok();
}

#[tokio::test]
async fn oob_round_trips_main_cleartext() {
    oob_round_trip(Profile::Main, None, OOB_PROTOCOL_IP).await;
}

#[tokio::test]
async fn oob_round_trips_main_aes256() {
    oob_round_trip(Profile::Main, Some("oob-secret"), OOB_PROTOCOL_IP).await;
}

#[tokio::test]
async fn oob_round_trips_advanced() {
    oob_round_trip(Profile::Advanced, Some("adv-oob"), OOB_PROTOCOL_IP).await;
}

#[tokio::test]
async fn oob_typed_tunnels_a_custom_protocol() {
    // An arbitrary non-reserved EtherType tunnels between two ristrust peers.
    oob_round_trip(Profile::Main, None, 0x88B7).await;
}

#[tokio::test]
async fn write_oob_rejected_on_simple() {
    let sender = dial_with("127.0.0.1:5000", Config::default(), &TokioRuntime)
        .await
        .expect("dial simple");
    assert!(matches!(
        sender.write_oob(b"x").await,
        Err(Error::OobUnsupported)
    ));
    sender.close().await.ok();
}

#[tokio::test]
async fn write_oob_typed_rejects_a_reserved_protocol() {
    let (_rx, port) = listen_free(&cfg(Profile::Main, None)).await;
    let sender = dial_with(
        &format!("127.0.0.1:{port}"),
        cfg(Profile::Main, None),
        &TokioRuntime,
    )
    .await
    .expect("dial main");
    // 0x88B6 = PROTO_REDUCED, one RIST reserves for its own framing.
    assert!(matches!(
        sender.write_oob_typed(0x88B6, b"x").await,
        Err(Error::OobProtocol(0x88B6))
    ));
    sender.close().await.ok();
}
