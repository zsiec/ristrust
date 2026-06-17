//! End-to-end packet split/merge bonding (libRIST `split=`/`merge=`) over real UDP
//! loopback, on every profile. A `split=`-configured sender spreads each application
//! payload across a consecutive even/odd sequence pair (same source time); a
//! `merge=`-configured receiver recombines the pair into the original payload. The
//! tests prove the round trip is byte-exact on Simple, Main (cleartext + AES),
//! Advanced, and bonded Main/Simple, and that `merge=auto` activates off the GRE
//! keepalive's pair-split (L) bit on the Main profile.

use std::time::Duration;

use rist::{
    Config, MergeMode, Profile, Receiver, SplitMode, dial, dial_bonded, listen, listen_bonded,
};

/// Binds a receiver on an OS-chosen free *even* port (the Simple profile requires an
/// even media port; `listen` rejects 0), retrying past the probe/bind race.
async fn listen_free(cfg: &Config) -> (Receiver, u16) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let candidate = probe.local_addr().expect("probe addr").port() & !1;
        drop(probe);
        if candidate == 0 {
            continue;
        }
        if let Ok(r) = listen(&format!("127.0.0.1:{candidate}"), cfg.clone()).await {
            return (r, candidate);
        }
    }
    panic!("no free even port for the receiver");
}

/// `n` distinct application payloads. Index `i` yields a TS-aligned 2×188-byte buffer
/// (so `split=auto` exercises the MPEG-TS-boundary path), uniquely keyed by `i` so an
/// equality check is a full integrity check.
fn payload(i: usize) -> Vec<u8> {
    let mut p = vec![0u8; 2 * 188];
    p[0] = 0x47; // MPEG-TS sync byte
    let tag = format!("split-merge-{i:05}");
    p[1..=tag.len()].copy_from_slice(tag.as_bytes());
    p
}

/// Drives `n` payloads over a single-path split→merge session built from `cfg` and
/// asserts each arrives once, in order, byte-exact (the merge recombines every pair).
async fn run_pairs(cfg: Config, n: usize) {
    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial");

    let send = tokio::spawn(async move {
        for i in 0..n {
            sender.send(&payload(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sender
    });

    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            payload(i).as_slice(),
            "payload {i} out of order, corrupt, or unmerged"
        );
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn simple_split_half_merge_pairs_round_trips() {
    let cfg = Config::default()
        .with_buffer(Duration::from_millis(120))
        .with_split_mode(SplitMode::Half)
        .with_merge_mode(MergeMode::Pairs);
    run_pairs(cfg, 50).await;
}

#[tokio::test]
async fn main_split_auto_merge_pairs_round_trips() {
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_split_mode(SplitMode::Auto)
        .with_merge_mode(MergeMode::Pairs);
    run_pairs(cfg, 50).await;
}

#[tokio::test]
async fn main_split_merge_round_trips_with_aes() {
    // Split (host layer) composes with PSK encryption (codec layer): the halves are
    // encrypted, the receiver decrypts then merges.
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_secret("split-secret")
        .with_split_mode(SplitMode::Half)
        .with_merge_mode(MergeMode::Pairs);
    run_pairs(cfg, 50).await;
}

#[tokio::test]
async fn advanced_split_merge_round_trips() {
    // On Advanced, split sends each half as a Standalone packet (bypassing F/L
    // fragmentation); the receiver's reassembler passes them through and the merger
    // recombines the pair.
    let cfg = Config::default()
        .with_profile(Profile::Advanced)
        .with_buffer(Duration::from_millis(150))
        .with_split_mode(SplitMode::Auto)
        .with_merge_mode(MergeMode::Pairs);
    run_pairs(cfg, 50).await;
}

#[tokio::test]
async fn main_merge_auto_enables_off_the_keepalive_l_bit() {
    // merge=auto stays dormant until the sender's GRE keepalive advertises pair-split
    // (the L bit). Before it enables, a pair may be delivered as two orphan halves;
    // after, pairs merge. Either way the concatenated output byte stream equals the
    // concatenated input — the robust steady-state invariant. We additionally require
    // that *some* payload merged exactly (proving auto did engage), tolerating startup
    // orphans.
    const N: usize = 60;
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(150))
        .with_split_mode(SplitMode::Half)
        .with_merge_mode(MergeMode::Auto);

    let (mut receiver, port) = listen_free(&cfg).await;
    let sender = dial(&format!("127.0.0.1:{port}"), cfg.clone())
        .await
        .expect("dial");

    let send = tokio::spawn(async move {
        for i in 0..N {
            sender.send(&payload(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    // The expected concatenated byte stream.
    let mut want = Vec::new();
    for i in 0..N {
        want.extend_from_slice(&payload(i));
    }

    let mut got = Vec::new();
    let mut merged_any = false;
    // Drain until the concatenated output covers the whole input (orphans make the
    // delivery count vary, so we drain by byte length, not message count).
    while got.len() < want.len() {
        let m = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("merge=auto delivery timed out")
            .expect("session stayed open");
        if m.len() == 2 * 188 {
            merged_any = true; // a full pair was recombined
        }
        got.extend_from_slice(&m);
    }
    assert_eq!(got, want, "merge=auto byte stream diverged");
    assert!(
        merged_any,
        "merge=auto never engaged (no pair merged off the keepalive L bit)"
    );

    let sender = send.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

/// Binds `n` even ports for a bonded receiver, retrying past the probe/bind race.
async fn listen_free_bonded(cfg: &Config, n: usize) -> (Receiver, Vec<String>) {
    'attempt: for _ in 0..64 {
        let mut ports = Vec::with_capacity(n);
        for _ in 0..n {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
            let p = probe.local_addr().expect("probe addr").port() & !1;
            drop(probe);
            if p == 0 || ports.contains(&p) || ports.contains(&(p + 1)) {
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

/// Drives `n` payloads over a 2-path bonded split→merge session and asserts byte-exact
/// in-order delivery (the 2022-7 merge dedups path copies; the split merge recombines
/// the pair).
async fn run_bonded_pairs(cfg: Config, n: usize) {
    let (mut receiver, addrs) = listen_free_bonded(&cfg, 2).await;
    let refs: Vec<&str> = addrs.iter().map(String::as_str).collect();
    let sender = dial_bonded(&refs, cfg.clone()).await.expect("dial bonded");

    let send = tokio::spawn(async move {
        for i in 0..n {
            sender.send(&payload(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        sender
    });

    for i in 0..n {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            payload(i).as_slice(),
            "bonded payload {i} out of order, corrupt, or unmerged"
        );
    }

    let sender = send.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn bonded_main_split_merge_round_trips() {
    // Bonding over two 2022-7 paths plus split/merge: each payload's two halves fan out
    // (redundantly) across both paths; the receiver dedups by (seq, source_time) then
    // merges the pair.
    let cfg = Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200))
        .with_split_mode(SplitMode::Auto)
        .with_merge_mode(MergeMode::Pairs);
    run_bonded_pairs(cfg, 50).await;
}
