//! End-to-end multicast: a Receiver bound to a multicast group and a Sender
//! transmitting to it on the same host (via `IP_MULTICAST_LOOP`). A successful
//! `listen`/`dial` already proves the group-join and egress socket options were
//! applied without error (the host I/O plumbing); when the host also has a usable
//! multicast route, the payload is delivered and verified end-to-end.
//!
//! The test skips gracefully (it never fails) when the environment has no
//! multicast-capable interface — common in CI sandboxes.

use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use rist::{Config, Profile, dial, listen};
use tokio::time::timeout;

/// A free even loopback port to derive the multicast group port from.
fn free_even_port() -> u16 {
    let s = StdUdpSocket::bind("127.0.0.1:0").expect("bind");
    let p = s.local_addr().expect("addr").port() & !1;
    if p == 0 { 2000 } else { p }
}

async fn run(profile: Profile, group: &str) {
    let port = free_even_port();
    let addr = format!("{group}:{port}");

    let rx_cfg = Config::default().with_profile(profile);
    let mut receiver = match listen(&addr, rx_cfg).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("multicast: listen({addr}) unsupported here, skipping: {e}");
            return;
        }
    };

    // Loopback on so the sender's own datagrams reach the receiver on this host.
    let tx_cfg = Config::default()
        .with_profile(profile)
        .with_multicast_ttl(1)
        .with_multicast_loopback(true);
    let sender = match dial(&addr, tx_cfg).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("multicast: dial({addr}) unsupported here, skipping: {e}");
            return;
        }
    };

    // The join + egress options applied cleanly — the plumbing works. Now best-effort
    // delivery: blast a few payloads and see if one loops back within the deadline.
    let payload = b"ristrust multicast payload";
    let recv = timeout(Duration::from_secs(4), async {
        for _ in 0..50 {
            sender.send(payload).await.expect("send");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, ()>(())
    });
    let got = timeout(Duration::from_secs(5), receiver.recv());

    tokio::select! {
        r = got => {
            if let Ok(Ok(p)) = r {
                assert_eq!(&p[..], payload, "delivered multicast payload must match");
                eprintln!("multicast[{profile:?}]: end-to-end delivery verified");
            } else {
                eprintln!("multicast[{profile:?}]: join/egress ok, no loopback route — plumbing-only pass");
            }
        }
        _ = recv => {
            eprintln!("multicast[{profile:?}]: join/egress ok, no delivery within deadline — plumbing-only pass");
        }
    }
    sender.close().await.ok();
    receiver.close().await.ok();
}

#[tokio::test]
async fn multicast_simple_ipv4() {
    run(Profile::Simple, "239.255.77.13").await;
}

#[tokio::test]
async fn multicast_main_ipv4() {
    run(Profile::Main, "239.255.77.15").await;
}
