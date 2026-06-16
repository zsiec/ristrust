//! End-to-end multi-flow multiplexing (WP19b): two Simple-profile senders with
//! distinct SSRCs stream into ONE bound `MultiReceiver` port, which demultiplexes
//! them by RTP SSRC into two independent `Receiver`s surfaced via `accept`. Each
//! flow delivers its own stream, in order and byte-exact — proving the injected-feed
//! seam (WP19a) carries N flows off one shared socket read.

use std::time::Duration;

use rist::{Config, FecCarriage, FecConfig, FecVariant, Profile, Receiver, dial, listen_multi};

/// Binds a `MultiReceiver` on an OS-chosen free even port.
async fn listen_multi_free(cfg: Config) -> (rist::MultiReceiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let mut p = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if !p.is_multiple_of(2) {
            p = p.wrapping_sub(1);
        }
        if p < 2 {
            continue;
        }
        if let Ok(m) = listen_multi(&format!("127.0.0.1:{p}"), cfg.clone()).await {
            return (m, p);
        }
    }
    panic!("no free port for the multi-receiver");
}

/// Reads up to `n` payloads from a flow's receiver (stopping early if it closes).
async fn collect(mut rx: Receiver, n: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(Ok(b)) => out.push(b.to_vec()),
            _ => break,
        }
    }
    rx.close().await.ok();
    out
}

/// Whether `got` is exactly the `tag` stream `[tag-00000, tag-00001, ...]` of length `n`.
fn is_stream(got: &[Vec<u8>], tag: &str, n: usize) -> bool {
    got.len() == n
        && got
            .iter()
            .enumerate()
            .all(|(i, p)| p.as_slice() == format!("{tag}-{i:05}").into_bytes().as_slice())
}

#[tokio::test]
async fn multi_demuxes_two_simple_flows_by_ssrc() {
    const N: usize = 40;
    let cfg = Config::default().with_buffer(Duration::from_millis(200));
    let (mut mrx, port) = listen_multi_free(cfg.clone()).await;

    // Two senders dial the one multi-receiver port; each gets its own random SSRC.
    let addr = format!("127.0.0.1:{port}");
    let sender_a = dial(&addr, cfg.clone()).await.expect("dial A");
    let sender_b = dial(&addr, cfg.clone()).await.expect("dial B");

    let send_stream = |sender: rist::Sender, tag: &'static str| {
        tokio::spawn(async move {
            for i in 0..N {
                sender
                    .send(&format!("{tag}-{i:05}").into_bytes())
                    .await
                    .expect("send");
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            // Keep the sender alive while the receiver drains.
            tokio::time::sleep(Duration::from_millis(300)).await;
            sender
        })
    };
    let ta = send_stream(sender_a, "A");
    let tb = send_stream(sender_b, "B");

    // Accept both flows (in arrival order), then collect each concurrently.
    let r1 = tokio::time::timeout(Duration::from_secs(5), mrx.accept())
        .await
        .expect("first flow did not appear")
        .expect("accept r1");
    let r2 = tokio::time::timeout(Duration::from_secs(5), mrx.accept())
        .await
        .expect("second flow did not appear")
        .expect("accept r2");
    let c1 = tokio::spawn(collect(r1, N));
    let c2 = tokio::spawn(collect(r2, N));
    let got = [c1.await.expect("c1"), c2.await.expect("c2")];

    // One accepted flow is the A stream, the other the B stream — each in order.
    assert!(
        got.iter().any(|s| is_stream(s, "A", N)),
        "the A stream was not delivered intact: {:?}",
        got.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert!(
        got.iter().any(|s| is_stream(s, "B", N)),
        "the B stream was not delivered intact"
    );

    let _ = ta.await;
    let _ = tb.await;
    mrx.close().await.expect("close multi");
}

#[tokio::test]
async fn listen_multi_rejects_fec() {
    // Separate-port FEC and SSRC demux conflict (FEC is one stream on fixed ports).
    let cfg = Config::default().with_fec(FecConfig {
        columns: 4,
        rows: 4,
        column_only: false,
        carriage: FecCarriage::SeparatePorts,
        variant: FecVariant::St20221,
    });
    assert!(
        listen_multi("127.0.0.1:5050", cfg).await.is_err(),
        "multi-flow + FEC must be rejected"
    );
}

#[tokio::test]
async fn listen_multi_rejects_non_simple() {
    // Source-address demux for Main/Advanced lands in a later sub-phase.
    let cfg = Config::default().with_profile(Profile::Main);
    assert!(
        matches!(
            listen_multi("127.0.0.1:5052", cfg).await,
            Err(rist::Error::Unimplemented(_))
        ),
        "Main-profile multi-flow is not yet supported"
    );
}
