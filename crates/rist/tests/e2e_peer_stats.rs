//! Per-peer (per-path) statistics: a non-bonded session reports exactly one peer
//! mirroring the flow; a bonded session reports one peer per path with its own
//! received/sent counters, RTT, and liveness.

use std::time::Duration;

use rist::{Config, Profile, Receiver, dial, dial_bonded, listen, listen_bonded};

/// Binds a Main receiver on a free port, retrying past the probe/bind race.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if port != 0
            && let Ok(r) = listen(&format!("127.0.0.1:{port}"), cfg.clone()).await
        {
            return (r, port);
        }
    }
    panic!("no free port for the Main receiver");
}

#[tokio::test]
async fn single_path_reports_one_peer_mirroring_the_flow() {
    let cfg = Config::default().with_profile(Profile::Main);
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial");

    let frames: Vec<Vec<u8>> = (0..30u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let send_frames = frames.clone();
    let send_task = tokio::spawn(async move {
        for f in &send_frames {
            sender.send(f).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });
    for (i, want) in frames.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on frame {i}"))
            .expect("open");
        assert_eq!(got.as_ref(), want.as_slice());
    }
    let sender = send_task.await.expect("task");

    // Receiver: exactly one peer, mirroring the flow's received counters, alive.
    let rs = receiver.stats();
    assert_eq!(rs.peers.len(), 1, "single-path receiver has one peer");
    assert_eq!(
        rs.peers[0].received, rs.received,
        "peer mirrors flow received"
    );
    assert_eq!(rs.peers[0].received_bytes, rs.received_bytes);
    assert!(rs.peers[0].alive);
    assert_eq!(rs.peers[0].weight, 0);

    // Sender: one peer mirroring the flow's sent counters.
    let ss = sender.stats();
    assert_eq!(ss.peers.len(), 1, "single-path sender has one peer");
    assert_eq!(ss.peers[0].sent, ss.sent, "peer mirrors flow sent");
    assert!(ss.peers[0].sent > 0);

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

/// Binds a 2-path bonded receiver on free Main ports, returning it + the dial addrs.
async fn listen_free_bonded(cfg: &Config) -> (Receiver, Vec<String>) {
    'attempt: for _ in 0..64 {
        let mut ports = Vec::new();
        for _ in 0..2 {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
            let p = probe.local_addr().expect("addr").port();
            drop(probe);
            if p == 0 || ports.contains(&p) {
                continue 'attempt;
            }
            ports.push(p);
        }
        let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
        let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        if let Ok(r) = listen_bonded(&refs, cfg.clone()).await {
            return (r, addrs);
        }
    }
    panic!("no free ports for the bonded receiver");
}

#[tokio::test]
async fn bonded_reports_one_peer_per_path_with_counters() {
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200));
    let (mut receiver, addrs) = listen_free_bonded(&cfg).await;
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded(&refs, cfg.clone()).await.expect("dial bonded");

    let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let send_frames = frames.clone();
    let send_task = tokio::spawn(async move {
        for f in &send_frames {
            sender.send(f).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });
    for (i, want) in frames.iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("open");
        assert_eq!(got.as_ref(), want.as_slice());
    }
    let sender = send_task.await.expect("task");

    // Receiver: one peer per path; full 2022-7 duplication means each path delivered
    // media, so both peers carry received packets and are alive.
    let rs = receiver.stats();
    assert_eq!(rs.peers.len(), 2, "two bonded paths -> two peers");
    for (i, p) in rs.peers.iter().enumerate() {
        assert!(p.received > 0, "receiver path {i} carried no media: {p:?}");
        assert!(p.alive, "receiver path {i} not alive");
    }

    // Sender: one peer per path; full duplication means each path sent the stream.
    let ss = sender.stats();
    assert_eq!(ss.peers.len(), 2, "two bonded paths -> two peers");
    for (i, p) in ss.peers.iter().enumerate() {
        assert!(p.sent > 0, "sender path {i} sent nothing: {p:?}");
    }

    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}
