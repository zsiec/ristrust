//! The Prometheus `/metrics` exporter (libRIST `prometheus-exporter`): a real HTTP GET
//! against [`rist::prometheus::serve`] returns the encoded stats, and other paths 404.

use rist::Stats;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Issues one HTTP/1.1 request line to `addr` and returns the full response (the server
/// sends `Connection: close`, so read to EOF).
async fn http_get(addr: std::net::SocketAddr, line: &str) -> String {
    let mut conn = TcpStream::connect(addr).await.expect("connect");
    conn.write_all(format!("{line}\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut resp = Vec::new();
    conn.read_to_end(&mut resp).await.expect("read response");
    String::from_utf8_lossy(&resp).into_owned()
}

#[tokio::test]
async fn serve_metrics_over_http() {
    // A stats source with a couple of recognizable values.
    let stats_fn = || {
        let mut s = Stats::default();
        s.received = 4242;
        s.delivered = 4200;
        s.quality = 0.97;
        s
    };
    let (addr, task) = rist::prometheus::serve("127.0.0.1:0".parse().unwrap(), stats_fn)
        .await
        .expect("bind exporter");

    // GET /metrics -> 200 with the encoded metrics.
    let resp = http_get(addr, "GET /metrics HTTP/1.1").await;
    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "status: {}",
        &resp[..resp.len().min(40)]
    );
    assert!(resp.contains("Content-Type: text/plain; version=0.0.4"));
    assert!(resp.contains("rist_client_flow_received_packets 4242"));
    assert!(resp.contains("rist_client_flow_quality_ratio 0.97"));

    // GET / -> 404 (only /metrics is served).
    let other = http_get(addr, "GET / HTTP/1.1").await;
    assert!(
        other.starts_with("HTTP/1.1 404"),
        "expected 404, got {}",
        &other[..other.len().min(40)]
    );

    task.abort();
}
