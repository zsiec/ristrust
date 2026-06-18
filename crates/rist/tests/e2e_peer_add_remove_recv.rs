//! Runtime peer add/remove on a bonded RECEIVER (libRIST rist_peer_create/_destroy):
//! a bonded receiver starts on a subset of its input paths and binds another at
//! runtime; the newly-bound path then receives media (witnessed by per-path stats).

use std::time::Duration;

use rist::{Config, Error, Profile, dial_bonded, listen_bonded};

/// Three free Main ports (distinct), for a bonded sender→receiver topology.
fn three_free_ports() -> [u16; 3] {
    let mut ports = Vec::new();
    while ports.len() < 3 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
        let p = probe.local_addr().expect("addr").port();
        drop(probe);
        if p != 0 && !ports.contains(&p) {
            ports.push(p);
        }
    }
    [ports[0], ports[1], ports[2]]
}

#[tokio::test]
async fn receiver_add_path_binds_a_new_input_at_runtime() {
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200));

    // Bind the receiver on the first two ports (retry past the probe/bind race), and
    // dial the sender to all three. The third destination has no listener until the
    // receiver binds it at runtime.
    let (mut receiver, addrs) = 'attempt: loop {
        let ports = three_free_ports();
        let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
        let first2: Vec<&str> = addrs[..2].iter().map(String::as_str).collect();
        if let Ok(r) = listen_bonded(&first2, cfg.clone()).await {
            break 'attempt (r, addrs);
        }
    };
    let all: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded(&all, cfg.clone()).await.expect("dial bonded");

    let frames: Vec<Vec<u8>> = (0..80u8).map(|i| vec![i.wrapping_add(1); 188]).collect();
    let send_first = frames[..40].to_vec();
    let send_rest = frames[40..].to_vec();
    let driver = tokio::spawn(async move {
        for f in &send_first {
            sender.send(f).await.expect("send first half");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        for f in &send_rest {
            sender.send(f).await.expect("send second half");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    let mut next = 0;
    let mut added = false;
    for want in &frames {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out at frame {next}"))
            .expect("session open");
        assert_eq!(got.as_ref(), want.as_slice(), "frame {next} not byte-exact");
        next += 1;
        // Bind the third input path partway through the stream.
        if !added && next >= 20 {
            receiver
                .add_path(2, &addrs[2], 0)
                .await
                .expect("receiver add_path");
            added = true;
        }
    }
    let sender = driver.await.expect("driver");

    // The receiver now has three peers; the runtime-bound third path received media.
    let rs = receiver.stats();
    assert_eq!(rs.peers.len(), 3, "third input path should have a peer");
    assert!(
        rs.peers[2].received > 0,
        "runtime-bound input path received no media: {:?}",
        rs.peers[2]
    );

    receiver.remove_path(2).await.expect("receiver remove_path");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn receiver_add_remove_rejected_on_non_bonded() {
    let cfg = Config::default().with_profile(Profile::Main);
    let port = three_free_ports()[0];
    let receiver = rist::listen(&format!("127.0.0.1:{port}"), cfg)
        .await
        .expect("listen");
    assert!(matches!(
        receiver.add_path(1, "127.0.0.1:5050", 0).await,
        Err(Error::Unimplemented(_))
    ));
    assert!(matches!(
        receiver.remove_path(1).await,
        Err(Error::Unimplemented(_))
    ));
    receiver.close().await.expect("close");
}
