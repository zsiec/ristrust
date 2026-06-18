//! Runtime setters: changing NACK type, the recovery-buffer RTT multiplier, and
//! null-packet deletion on a live session (the libRIST `rist_receiver_nack_type_set`
//! / `rist_recovery_rtt_multiplier_set` / `rist_sender_npd_enable` family). Each is a
//! control command applied to the running driver/flow; the stream must keep delivering
//! byte-exact across the change. The profile/range guards are checked too.

use std::time::Duration;

use rist::{Config, Error, NackType, Profile, Receiver, dial, listen};

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

/// A windowed-buffer Main config so the RTT-multiplier setter is eligible to act.
fn main_windowed_cfg() -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer_range(Duration::from_millis(200), Duration::from_millis(1000))
}

#[tokio::test]
async fn main_runtime_setters_keep_stream_byte_exact() {
    let cfg = main_windowed_cfg();
    cfg.validate().expect("config valid");
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the Main receiver");

    // Flip every runtime knob before the stream gets going. All three must succeed on a
    // single-flow Main session.
    receiver
        .set_nack_type(NackType::Bitmask)
        .await
        .expect("set_nack_type");
    receiver
        .set_rtt_multiplier(3)
        .await
        .expect("set_rtt_multiplier");
    sender
        .set_null_packet_deletion(true)
        .await
        .expect("set_null_packet_deletion");

    // 188-byte MPEG-TS-sized frames with a distinct fill per frame; NPD passes
    // non-null packets through unchanged, so delivery stays byte-exact.
    let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let send_frames = frames.clone();
    let send_task = tokio::spawn(async move {
        for frame in &send_frames {
            sender.send(frame).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        // Toggle NPD back off mid-late to prove a second runtime change also lands.
        sender
            .set_null_packet_deletion(false)
            .await
            .expect("disable npd");
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
async fn set_rtt_multiplier_rejects_out_of_range() {
    let cfg = main_windowed_cfg();
    let (receiver, _port) = listen_free(&cfg).await;
    // 0 and 101 are outside the accepted 1..=100 range (libRIST requires >= 1).
    assert!(matches!(
        receiver.set_rtt_multiplier(0).await,
        Err(Error::Config(_))
    ));
    assert!(matches!(
        receiver.set_rtt_multiplier(101).await,
        Err(Error::Config(_))
    ));
    // A boundary value is accepted.
    receiver.set_rtt_multiplier(1).await.expect("min accepted");
    receiver
        .set_rtt_multiplier(100)
        .await
        .expect("max accepted");
    receiver.close().await.expect("close");
}

#[tokio::test]
async fn npd_setter_rejects_non_main_profile() {
    // NPD is a Main-profile feature; a Simple sender has no NPD command channel.
    let cfg = Config::default(); // Simple by default
    let sender = dial("127.0.0.1:5000", cfg).await.expect("dial");
    assert!(matches!(
        sender.set_null_packet_deletion(true).await,
        Err(Error::Unimplemented(_))
    ));
    sender.close().await.expect("close");
}
