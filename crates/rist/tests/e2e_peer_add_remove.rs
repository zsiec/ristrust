//! Runtime peer add/remove on a bonded sender (libRIST rist_peer_create/_destroy):
//! a bonded sender starts on a subset of paths and adds a destination at runtime; the
//! newly-added path then carries media (witnessed by the receiver's per-path stats).
//! Removing a path returns cleanly and the stream stays healthy.

use std::time::Duration;

use rist::{Config, Error, Profile, Receiver, dial_bonded, listen_bonded};

/// Binds a 3-path bonded receiver on free Main ports, returning it + the dial addrs.
async fn listen_free_bonded(cfg: &Config, n: usize) -> (Receiver, Vec<String>) {
    'attempt: for _ in 0..64 {
        let mut ports = Vec::new();
        for _ in 0..n {
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
async fn add_path_routes_media_to_a_new_destination() {
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200));

    // The receiver listens on three paths; the sender starts on the first two.
    let (mut receiver, addrs) = listen_free_bonded(&cfg, 3).await;
    let start: Vec<&str> = addrs[..2].iter().map(String::as_str).collect();
    let sender = dial_bonded(&start, cfg.clone())
        .await
        .expect("dial bonded (2 paths)");

    // Stream the first half over the two initial paths.
    let frames: Vec<Vec<u8>> = (0..80u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let mut next = 0;

    // Drive: send the stream in two halves; add the third path between them.
    let send_first = frames[..40].to_vec();
    let send_rest = frames[40..].to_vec();
    let third = addrs[2].clone();

    let driver = tokio::spawn(async move {
        for f in &send_first {
            sender.send(f).await.expect("send first half");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        // Add the third destination at runtime (index 2 — the next free index).
        sender.add_path(2, &third, 0).await.expect("add_path");
        for f in &send_rest {
            sender.send(f).await.expect("send second half");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for want in &frames {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out at frame {next}"))
            .expect("session open");
        assert_eq!(got.as_ref(), want.as_slice(), "frame {next} not byte-exact");
        next += 1;
    }
    let sender = driver.await.expect("driver task");

    // The receiver now has three peers; the third (runtime-added) path carried media.
    let rs = receiver.stats();
    assert_eq!(
        rs.peers.len(),
        3,
        "third path should have registered a peer"
    );
    assert!(
        rs.peers[2].received > 0,
        "runtime-added path carried no media: {:?}",
        rs.peers[2]
    );

    // Remove a path at runtime; the stream is already delivered, so just prove it
    // returns cleanly and the sender survives.
    sender.remove_path(2).await.expect("remove_path");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn add_remove_path_rejected_on_non_bonded() {
    let sender = rist::dial("127.0.0.1:5000", Config::default())
        .await
        .expect("dial");
    assert!(matches!(
        sender.add_path(1, "127.0.0.1:5002", 0).await,
        Err(Error::Unimplemented(_))
    ));
    assert!(matches!(
        sender.remove_path(1).await,
        Err(Error::Unimplemented(_))
    ));
    sender.close().await.expect("close");
}
