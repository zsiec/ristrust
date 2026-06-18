//! Per-packet block delivery on the receive side (libRIST `rist_receiver_data_block`):
//! `Receiver::recv_block` yields each recovered packet as a `DataBlock` carrying its
//! sequence, source timestamp, and the virtual ports decoded from the Main GRE
//! reduced-overhead header — proving per-packet metadata flows decode → core → app.

use std::time::Duration;

use rist::{Config, Error, Profile, Receiver, TokioRuntime, dial_with, listen};

/// A Main config with non-default virtual ports + a short buffer.
fn block_cfg() -> Config {
    let mut cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150));
    cfg.virt_src_port = 5000;
    cfg.virt_dst_port = 6000;
    cfg
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
async fn recv_block_surfaces_seq_source_time_and_virt_ports() {
    let recv_cfg = block_cfg().with_block_delivery(true);
    let (mut receiver, port) = listen_free(&recv_cfg).await;
    let sender = dial_with(&format!("127.0.0.1:{port}"), block_cfg(), &TokioRuntime)
        .await
        .expect("dial");

    let n = 40usize;
    let mk = |i: usize| format!("block-{i:04}").into_bytes();
    let send_mk = mk;
    let send = tokio::spawn(async move {
        for i in 0..n + 8 {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    let mut prev_seq: Option<u32> = None;
    for i in 0..n {
        let blk = tokio::time::timeout(Duration::from_secs(10), receiver.recv_block())
            .await
            .unwrap_or_else(|_| panic!("timed out on block {i}"))
            .expect("session open");
        assert_eq!(blk.payload.as_ref(), mk(i).as_slice(), "block {i} payload");
        // The virtual ports decoded from the GRE reduced header match what the sender set.
        assert_eq!(blk.virt_src_port, 5000, "block {i} virt_src_port");
        assert_eq!(blk.virt_dst_port, 6000, "block {i} virt_dst_port");
        assert_ne!(blk.source_time, 0, "block {i} carries a source timestamp");
        // Sequences advance by one per in-order packet (per-packet granularity).
        if let Some(p) = prev_seq {
            assert_eq!(blk.seq, p.wrapping_add(1), "block {i} seq not contiguous");
        }
        prev_seq = Some(blk.seq);
    }

    // recv is unavailable on a block-delivery receiver.
    assert!(matches!(
        receiver.recv().await,
        Err(Error::Unimplemented(_))
    ));

    let sender = send.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn recv_block_rejected_without_block_delivery() {
    // A plain (payload) receiver has no block channel: recv_block returns Unimplemented.
    let (mut receiver, _port) = listen_free(&block_cfg()).await;
    assert!(matches!(
        receiver.recv_block().await,
        Err(Error::Unimplemented(_))
    ));
    receiver.close().await.expect("close");
}

#[tokio::test]
async fn block_delivery_rejected_off_main() {
    // Block delivery is wired for the Main GRE reduced header only.
    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_block_delivery(true);
    assert!(
        cfg.validate().is_err(),
        "block delivery off Main must not validate"
    );
}
