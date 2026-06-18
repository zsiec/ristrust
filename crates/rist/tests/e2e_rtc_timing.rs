//! RTC timing mode (libRIST `RIST_TIMING_MODE_RTC`) over a Main-profile loopback: the
//! sender stamps `source_time` from the NTP wall clock and the receiver paces playout by
//! it (skipping the 32-bit source-clock wrap re-anchor), delivering in order and
//! byte-exact. Scheduling stays on the monotonic clock, so this is a no-NTP-jump variant.

use std::time::Duration;

use rist::{Config, Profile, Receiver, TimingMode, TokioRuntime, dial_with, listen};

/// A Main-profile RTC-timing config with a short recovery buffer.
fn rtc_cfg() -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_timing_mode(TimingMode::Rtc)
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

#[tokio::test]
async fn rtc_timing_delivers_in_order() {
    let cfg = rtc_cfg();
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &TokioRuntime)
        .await
        .expect("dial the RTC-timing receiver");

    let n = 60usize;
    let mk = |i: usize| format!("rtc-{i:04}-payload").into_bytes();
    let send_mk = mk;
    let send = tokio::spawn(async move {
        for i in 0..n + 8 {
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
            "payload {i} out of order/corrupt"
        );
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn rtc_timing_recovers_loss() {
    // The wall-clock source_time still paces playout, and ARQ recovers dropped media
    // through the RTC path: every payload arrives in order.
    let cfg = rtc_cfg().with_buffer(Duration::from_millis(250));
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), cfg.clone(), &TokioRuntime)
        .await
        .expect("dial");

    let n = 100usize;
    let mk = |i: usize| format!("rtc-loss-{i:05}").into_bytes();
    let send_mk = mk;
    let send = tokio::spawn(async move {
        for i in 0..n + 12 {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });

    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(12), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} out of order/corrupt"
        );
    }
    let sender = send.await.expect("send task");
    sender.close().await.ok();
    receiver.close().await.expect("close");
}
