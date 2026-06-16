//! End-to-end multi-flow multiplexing (WP19): two senders stream into ONE bound
//! `MultiReceiver`, which demultiplexes them into two independent `Receiver`s
//! surfaced via `accept`. Each flow delivers its own stream, in order and byte-exact
//! — proving the injected-feed seam (WP19a) carries N flows off one shared socket
//! read. Simple keys by RTP SSRC; Main/Advanced key by source address; the bonded
//! variant keys each SMPTE 2022-7 sender by its single source address, merging the
//! redundant copies across all its path ports into one flow.

use std::time::Duration;

use rist::{
    Config, FecCarriage, FecConfig, FecVariant, Profile, Receiver, dial, dial_bonded, listen_multi,
    listen_multi_bonded,
};

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

/// Binds a bonded `MultiReceiver` on `n` OS-chosen free Main ports, returning it and
/// the `IP:port` strings a bonded sender dials.
async fn listen_multi_bonded_free(cfg: Config, n: usize) -> (rist::MultiReceiver, Vec<String>) {
    'attempt: for _ in 0..64 {
        let mut ports = Vec::with_capacity(n);
        for _ in 0..n {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
            let p = probe.local_addr().expect("probe addr").port();
            drop(probe);
            if p == 0 || ports.contains(&p) {
                continue 'attempt;
            }
            ports.push(p);
        }
        let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
        let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
        if let Ok(m) = listen_multi_bonded(&refs, cfg.clone()).await {
            return (m, addrs);
        }
    }
    panic!("no free ports for the bonded multi-receiver");
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

/// Streams two distinct flows into one `MultiReceiver` for the given profile and
/// asserts each is demultiplexed to its own in-order, byte-exact `Receiver`. Simple
/// keys by SSRC (two random sender SSRCs); Main/Advanced key by source address (two
/// distinct ephemeral source ports).
async fn run_multi(cfg: Config) {
    let (mrx, port) = listen_multi_free(cfg.clone()).await;
    // Two senders dial the one multi-receiver port.
    let addr = format!("127.0.0.1:{port}");
    let sender_a = dial(&addr, cfg.clone()).await.expect("dial A");
    let sender_b = dial(&addr, cfg.clone()).await.expect("dial B");
    drive_two_flows(mrx, sender_a, sender_b).await;
}

/// Drives two already-dialed senders with distinct `A`/`B` streams into one
/// `MultiReceiver`, accepts both flows, and asserts each is demultiplexed to its own
/// in-order, byte-exact `Receiver`. Shared by the single-path and bonded demux tests.
async fn drive_two_flows(
    mut mrx: rist::MultiReceiver,
    sender_a: rist::Sender,
    sender_b: rist::Sender,
) {
    const N: usize = 40;
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
async fn multi_demuxes_two_simple_flows_by_ssrc() {
    // Simple profile: two senders' distinct RTP SSRCs demultiplex into two flows.
    run_multi(Config::default().with_buffer(Duration::from_millis(200))).await;
}

#[tokio::test]
async fn multi_demuxes_two_main_flows_by_source() {
    // Main profile: two senders on distinct ephemeral source ports demultiplex into
    // two flows by source address (each with its own GRE substrate).
    run_multi(
        Config::default()
            .with_profile(Profile::Main)
            .with_buffer(Duration::from_millis(200)),
    )
    .await;
}

#[tokio::test]
async fn multi_demuxes_two_main_psk_flows_by_source() {
    // Main + PSK: each per-source flow decrypts independently under its own key.
    run_multi(
        Config::default()
            .with_profile(Profile::Main)
            .with_secret("multi-psk")
            .with_buffer(Duration::from_millis(200)),
    )
    .await;
}

#[tokio::test]
async fn multi_demuxes_two_advanced_flows_by_source() {
    // Advanced profile: two senders demultiplex by source address into two flows.
    run_multi(
        Config::default()
            .with_profile(Profile::Advanced)
            .with_buffer(Duration::from_millis(200)),
    )
    .await;
}

#[tokio::test]
async fn multi_demuxes_two_bonded_flows_by_source() {
    // Two SMPTE 2022-7 bonded senders, each sourcing all its paths from one socket,
    // stream into one bonded MultiReceiver across the same two path ports. The demux
    // keys each sender by its single source address into its own bonded flow, merging
    // the redundant copies arriving on both paths.
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200));
    let (mrx, addrs) = listen_multi_bonded_free(cfg.clone(), 2).await;
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender_a = dial_bonded(&refs, cfg.clone())
        .await
        .expect("dial bonded A");
    let sender_b = dial_bonded(&refs, cfg.clone())
        .await
        .expect("dial bonded B");
    drive_two_flows(mrx, sender_a, sender_b).await;
}

#[tokio::test]
async fn listen_multi_bonded_rejects_non_main() {
    // Bonding rides the Main GRE substrate; a Simple-profile bonded multi-receiver is
    // rejected up front.
    let cfg = Config::default().with_buffer(Duration::from_millis(200));
    assert!(
        listen_multi_bonded(&["127.0.0.1:5052", "127.0.0.1:5054"], cfg)
            .await
            .is_err(),
        "bonded multi-flow must require the Main profile"
    );
}

#[tokio::test]
async fn listen_multi_rejects_fec() {
    // FEC and multi-flow demux conflict (FEC is one stream, not per-flow).
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
