//! Per-block media submit: `Sender::send_block` with an explicit sequence number
//! and source timestamp (libRIST `RIST_DATA_FLAGS_USE_SEQ` + `ts_ntp`). The payload
//! must still round-trip byte-exact, and a non-Main sender must reject the call. This
//! is the foundation a transparent reflector uses to preserve an upstream flow's
//! `(seq, source_time)`.

use std::time::Duration;

use rist::{Config, Error, Profile, Receiver, dial, listen};

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

#[tokio::test]
async fn send_block_with_explicit_seq_and_ts_round_trips() {
    let cfg = Config::default().with_profile(Profile::Main);
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the Main receiver");

    // 30 frames submitted with an app-chosen, monotonically increasing sequence base
    // far from the flow's auto start, and an app-supplied source timestamp. A relay
    // would feed an upstream flow's values here; we just prove the path delivers.
    let frames: Vec<Vec<u8>> = (0..30u32).map(|i| vec![(i & 0xff) as u8; 188]).collect();
    let send_frames = frames.clone();
    let send_task = tokio::spawn(async move {
        // NTP-64: a fixed app-chosen second anchor, advancing ~3 ms per frame in the
        // fractional low 32 bits (1 ms ≈ 2^32/1000) so source-timed playout paces the
        // frames a few ms apart rather than seconds.
        let base = 2_500_000_000u64 << 32;
        let step = (1u64 << 32) / 1000 * 3; // ~3 ms in NTP-64 fraction
        for (i, frame) in send_frames.iter().enumerate() {
            let i = u32::try_from(i).expect("frame index fits u32");
            let seq = 100_000 + i;
            let source_time = base + u64::from(i) * step;
            sender
                .send_block(frame, Some(seq), Some(source_time))
                .await
                .expect("send_block");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for (i, want) in frames.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on frame {i}"))
            .expect("session stayed open");
        assert_eq!(got.as_ref(), want.as_slice(), "frame {i} not byte-exact");
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn send_block_falls_back_to_auto_seq_and_ts() {
    // None overrides behave exactly like Sender::send (auto sequence + now timestamp).
    let cfg = Config::default().with_profile(Profile::Main);
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial");

    let frames: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let send_frames = frames.clone();
    let send_task = tokio::spawn(async move {
        for frame in &send_frames {
            sender
                .send_block(frame, None, None)
                .await
                .expect("send_block");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for (i, want) in frames.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on frame {i}"))
            .expect("open");
        assert_eq!(got.as_ref(), want.as_slice(), "frame {i}");
    }
    send_task.await.expect("task").close().await.expect("close");
    receiver.close().await.expect("close");
}

#[tokio::test]
async fn send_block_rejected_on_non_main_profile() {
    // Per-block submit is wired for the single-socket Main profile; a Simple sender
    // has no block channel.
    let sender = dial("127.0.0.1:5000", Config::default())
        .await
        .expect("dial");
    assert!(matches!(
        sender.send_block(b"x", Some(1), None).await,
        Err(Error::Unimplemented(_))
    ));
    sender.close().await.expect("close");
}
