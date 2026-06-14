//! End-to-end Simple-profile loopback: a real `Sender` transmits media over UDP
//! to a real `Receiver` on loopback, and every payload arrives in order with its
//! bytes intact — the first proof the whole host (codec strategy + driver pump +
//! sockets) carries media end to end.

use std::time::Duration;

use rist::{Config, Receiver, dial, listen};

/// Binds a receiver on an OS-chosen *free even* port (the Simple profile requires
/// an even media port; `listen` rejects 0), retrying to dodge the small race
/// between probing a free port and binding it.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let candidate = probe.local_addr().expect("probe addr").port() & !1; // round to even
        drop(probe);
        if candidate == 0 {
            continue;
        }
        if let Ok(r) = listen(&format!("127.0.0.1:{candidate}"), cfg.clone()).await {
            return (r, candidate);
        }
    }
    panic!("could not find a free even port for the receiver");
}

#[tokio::test]
async fn simple_loopback_delivers_all_payloads_in_order() {
    const N: usize = 50;

    // A short recovery buffer keeps the test quick: a packet is played out
    // ~100 ms after it arrives rather than the 1 s default.
    let cfg = Config::default().with_buffer(Duration::from_millis(100));

    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial the receiver");

    // Send N distinct payloads, lightly spaced to mimic a CBR source.
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            let payload = format!("ristrust-payload-{i:04}").into_bytes();
            sender.send(&payload).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });

    // Receive N payloads; assert exact order and byte integrity (each payload is
    // unique, so equality is a full integrity check).
    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for payload {i}"))
            .expect("session stayed open");
        let want = format!("ristrust-payload-{i:04}");
        assert_eq!(
            got.as_ref(),
            want.as_bytes(),
            "payload {i} mismatch (out of order or corrupt)"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}
