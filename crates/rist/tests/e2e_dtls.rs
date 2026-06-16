//! End-to-end DTLS 1.2 over the Main profile (feature `dtls`): a real DTLS-client
//! sender streams to a real DTLS-server receiver over UDP loopback, the GRE media
//! travelling as DTLS application records. Proves the host bridge (a worker thread
//! owning the blocking DTLS `Conn`, plaintext shuttled over channels) carries a
//! recovered, in-order, byte-exact stream through the encrypted tunnel — for both PSK
//! and ECDHE-ECDSA key exchange. Not a libRIST interop gate (libRIST has no DTLS).
#![cfg(feature = "dtls")]

use std::time::Duration;

use rist::{Config, DtlsConfig, DtlsIdentity, Profile, Receiver, dial, listen};

/// A Main-profile config with a short recovery buffer and the given DTLS config.
fn dtls_cfg(dtls: DtlsConfig) -> Config {
    Config::default()
        .with_profile(Profile::Main)
        .with_buffer(Duration::from_millis(200))
        .with_dtls(dtls)
}

/// Binds a DTLS-server receiver on an OS-chosen free port with `server`, returning it
/// and the `IP:port` a client dials.
async fn listen_dtls_free(server: DtlsConfig) -> (Receiver, String) {
    for _ in 0..64 {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let p = probe.local_addr().expect("probe addr").port();
        drop(probe);
        if p == 0 {
            continue;
        }
        let addr = format!("127.0.0.1:{p}");
        if let Ok(r) = listen(&addr, dtls_cfg(server.clone())).await {
            return (r, addr);
        }
    }
    panic!("no free port for the DTLS receiver");
}

/// Streams `N` distinct payloads from a DTLS-client sender to a DTLS-server receiver
/// and asserts each arrives once, in order, byte-exact — proving the handshake
/// completed and media flowed through the tunnel.
async fn run_dtls(server: DtlsConfig, client: DtlsConfig) {
    const N: usize = 40;
    let (mut receiver, addr) = listen_dtls_free(server).await;
    let sender = dial(&addr, dtls_cfg(client))
        .await
        .expect("dial the DTLS receiver");

    let mk = |i: usize| format!("dtls-{i:05}").into_bytes();
    let send_mk = mk;
    let send_task = tokio::spawn(async move {
        for i in 0..N {
            sender.send(&send_mk(i)).await.expect("send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Keep the sender (and its DTLS tunnel) alive while the receiver drains.
        tokio::time::sleep(Duration::from_millis(300)).await;
        sender
    });

    for i in 0..N {
        let got = tokio::time::timeout(Duration::from_secs(15), receiver.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out on payload {i}"))
            .expect("session stayed open");
        assert_eq!(
            got.as_ref(),
            mk(i).as_slice(),
            "payload {i} corrupt or reordered"
        );
    }

    let sender = send_task.await.expect("send task");
    sender.close().await.expect("close sender");
    receiver.close().await.expect("close receiver");
}

#[tokio::test]
async fn dtls_psk_stream_recovers_in_order() {
    // TLS_PSK_WITH_AES_128_GCM_SHA256: both ends share the identity + key.
    let psk = || DtlsConfig::psk(b"ristrust".to_vec(), b"a-shared-dtls-secret".to_vec());
    run_dtls(psk(), psk()).await;
}

#[tokio::test]
async fn dtls_ecdhe_insecure_stream_recovers_in_order() {
    // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: the server presents a self-signed
    // ECDSA P-256 certificate; the (insecure) client accepts any peer certificate.
    let identity = DtlsIdentity::generate("ristrust-dtls").expect("self-signed identity");
    run_dtls(
        DtlsConfig::ecdhe_server(identity),
        DtlsConfig::ecdhe_client_insecure(),
    )
    .await;
}
