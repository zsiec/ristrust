//! A Prometheus text-format exporter for session [`Stats`] (libRIST's
//! `prometheus-exporter`). [`encode`] renders a stats snapshot as the Prometheus text
//! exposition format (the RIST-specific part); [`serve`] runs a minimal HTTP `/metrics`
//! endpoint over tokio (no extra HTTP dependency) that calls a stats closure on each
//! scrape. Metric names follow libRIST's `rist_client_flow_*` / `rist_peer_*` convention.
//!
//! ```no_run
//! # async fn ex(receiver: rist::Receiver) -> std::io::Result<()> {
//! let addr = "0.0.0.0:9100".parse().unwrap();
//! let (bound, _task) = rist::prometheus::serve(addr, move || receiver.stats()).await?;
//! eprintln!("metrics on http://{bound}/metrics");
//! # Ok(()) }
//! ```

use std::fmt::Write as _;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::Stats;

/// Appends one counter metric (HELP + TYPE + value) in the Prometheus text format.
fn counter(o: &mut String, name: &str, help: &str, v: u64) {
    let _ = write!(
        o,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"
    );
}

/// Appends one gauge metric (HELP + TYPE + value).
fn gauge(o: &mut String, name: &str, help: &str, v: f64) {
    let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}\n");
}

/// Renders a [`Stats`] snapshot as a Prometheus text-exposition document (content type
/// `text/plain; version=0.0.4`). Counters are cumulative session totals; gauges are the
/// current RTT / bitrate / quality / inter-arrival / buffer values. Per-peer metrics
/// (bonded paths) carry a `peer="<index>"` label.
// A flat list emitting one metric per field; splitting it would only scatter the table.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn encode(s: &Stats) -> String {
    let mut o = String::with_capacity(2048);
    counter(
        &mut o,
        "rist_client_flow_received_packets",
        "Media packets received.",
        s.received,
    );
    counter(
        &mut o,
        "rist_client_flow_delivered_packets",
        "Media packets delivered in order.",
        s.delivered,
    );
    counter(
        &mut o,
        "rist_client_flow_lost_packets",
        "Packets abandoned as unrecoverable.",
        s.lost,
    );
    counter(
        &mut o,
        "rist_client_flow_recovered_packets",
        "Packets recovered by ARQ or FEC.",
        s.recovered,
    );
    counter(
        &mut o,
        "rist_client_flow_recovered_one_retry_packets",
        "Packets recovered on the first retry.",
        s.recovered_one_retry,
    );
    counter(
        &mut o,
        "rist_client_flow_reordered_packets",
        "Packets that arrived out of order.",
        s.reordered,
    );
    counter(
        &mut o,
        "rist_client_flow_sent_packets",
        "Media packets sent (sender).",
        s.sent,
    );
    counter(
        &mut o,
        "rist_client_flow_nacks_sent",
        "NACK requests emitted (receiver).",
        s.nacks_sent,
    );
    gauge(
        &mut o,
        "rist_client_flow_missing_packets",
        "Packets currently outstanding awaiting recovery.",
        f64_from(s.missing),
    );
    gauge(
        &mut o,
        "rist_client_flow_rtt_seconds",
        "Smoothed round-trip time.",
        s.rtt.as_secs_f64(),
    );
    gauge(
        &mut o,
        "rist_client_flow_bandwidth_bps",
        "Media bitrate, bits per second.",
        f64_from(s.bandwidth_bps),
    );
    gauge(
        &mut o,
        "rist_client_flow_retry_bandwidth_bps",
        "Retransmission bitrate, bits per second.",
        f64_from(s.retry_bandwidth_bps),
    );
    gauge(
        &mut o,
        "rist_client_flow_quality_ratio",
        "Delivery quality ratio (0..1).",
        s.quality,
    );
    gauge(
        &mut o,
        "rist_client_flow_min_iat_seconds",
        "Minimum inter-packet arrival interval.",
        s.inter_packet_min.as_secs_f64(),
    );
    gauge(
        &mut o,
        "rist_client_flow_cur_iat_seconds",
        "Current inter-packet arrival interval.",
        s.inter_packet_cur.as_secs_f64(),
    );
    gauge(
        &mut o,
        "rist_client_flow_max_iat_seconds",
        "Maximum inter-packet arrival interval.",
        s.inter_packet_max.as_secs_f64(),
    );
    gauge(
        &mut o,
        "rist_client_flow_avg_buffer_time_seconds",
        "Average playout buffer depth.",
        s.avg_buffer_time.as_secs_f64(),
    );
    gauge(
        &mut o,
        "rist_client_flow_peers",
        "Number of bonded peers.",
        f64_from(s.peers.len() as u64),
    );
    encode_peers(&mut o, s);
    o
}

/// Appends the per-peer (bonded path) metrics, each `name{peer="<index>"} value` with a
/// single HELP/TYPE header. A no-op for a single-path session (no peers).
fn encode_peers(o: &mut String, s: &Stats) {
    if s.peers.is_empty() {
        return;
    }
    // (name, type, help, extractor) emitted as one block per metric.
    let _ = writeln!(
        o,
        "# HELP rist_peer_rtt_seconds Per-peer smoothed round-trip time.\n# TYPE rist_peer_rtt_seconds gauge"
    );
    for (i, p) in s.peers.iter().enumerate() {
        let _ = writeln!(
            o,
            "rist_peer_rtt_seconds{{peer=\"{i}\"}} {}",
            p.rtt.as_secs_f64()
        );
    }
    peer_counter(
        o,
        "rist_peer_received_packets",
        "Per-peer media packets received.",
        s,
        |p| p.received,
    );
    peer_counter(
        o,
        "rist_peer_received_bytes",
        "Per-peer media bytes received.",
        s,
        |p| p.received_bytes,
    );
    peer_counter(
        o,
        "rist_peer_sent_packets",
        "Per-peer media packets sent.",
        s,
        |p| p.sent,
    );
    peer_counter(
        o,
        "rist_peer_sent_bytes",
        "Per-peer media bytes sent.",
        s,
        |p| p.sent_bytes,
    );
    peer_counter(
        o,
        "rist_peer_retransmitted_packets",
        "Per-peer retransmitted packets.",
        s,
        |p| p.retransmitted,
    );
}

/// Appends one per-peer counter metric: a HELP/TYPE header then one labelled value per peer.
fn peer_counter(
    o: &mut String,
    name: &str,
    help: &str,
    s: &Stats,
    f: impl Fn(&crate::PeerStats) -> u64,
) {
    let _ = write!(o, "# HELP {name} {help}\n# TYPE {name} counter\n");
    for (i, p) in s.peers.iter().enumerate() {
        let _ = writeln!(o, "{name}{{peer=\"{i}\"}} {}", f(p));
    }
}

/// `u64 -> f64` for gauge values, isolating the one lossy cast.
#[allow(clippy::cast_precision_loss)]
fn f64_from(v: u64) -> f64 {
    v as f64
}

/// Serves the Prometheus `/metrics` endpoint on `addr`, calling `stats` to snapshot the
/// current counters on each scrape. Returns the bound address (resolving an ephemeral
/// `:0` port) and the server task handle (abort it to stop). A minimal HTTP/1.1 responder
/// built on tokio — no HTTP-framework dependency: it answers `GET /metrics` with the
/// metrics text and any other request with `404`.
///
/// # Errors
/// Returns an I/O error if `addr` cannot be bound.
pub async fn serve<F>(addr: SocketAddr, stats: F) -> std::io::Result<(SocketAddr, JoinHandle<()>)>
where
    F: Fn() -> Stats + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            // Read the request head (best-effort, one read): we only need the request
            // line to route. Prometheus sends a small GET; 2 KiB covers the head.
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = &buf[..n];
            let body = if request_targets_metrics(head) {
                encode(&stats())
            } else {
                let resp =
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp).await;
                continue;
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    Ok((bound, task))
}

/// Whether the HTTP request head is `GET /metrics` (the prometheus scrape). The request
/// line is `METHOD SP TARGET SP VERSION`; match the target path prefix.
fn request_targets_metrics(head: &[u8]) -> bool {
    let line = head
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(head);
    let mut parts = line.split(|&b| b == b' ');
    let method = parts.next().unwrap_or(b"");
    let target = parts.next().unwrap_or(b"");
    method == b"GET" && (target == b"/metrics" || target.starts_with(b"/metrics?"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_routing() {
        assert!(request_targets_metrics(
            b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"
        ));
        assert!(request_targets_metrics(b"GET /metrics?x=1 HTTP/1.1\r\n"));
        assert!(!request_targets_metrics(b"GET / HTTP/1.1\r\n"));
        assert!(!request_targets_metrics(b"POST /metrics HTTP/1.1\r\n"));
        assert!(!request_targets_metrics(b""));
    }

    #[test]
    fn encode_emits_well_formed_metrics() {
        let s = Stats {
            received: 100,
            delivered: 98,
            lost: 2,
            rtt: std::time::Duration::from_millis(20),
            quality: 0.98,
            ..Default::default()
        };
        let out = encode(&s);
        // Each metric has HELP + TYPE + a value line; values render.
        assert!(out.contains("# TYPE rist_client_flow_received_packets counter\nrist_client_flow_received_packets 100\n"));
        assert!(out.contains(
            "# TYPE rist_client_flow_rtt_seconds gauge\nrist_client_flow_rtt_seconds 0.02\n"
        ));
        assert!(out.contains("rist_client_flow_quality_ratio 0.98\n"));
        // No peers => no per-peer block.
        assert!(!out.contains("rist_peer_"));
        // Every HELP is paired with a TYPE.
        assert_eq!(
            out.matches("# HELP ").count(),
            out.matches("# TYPE ").count()
        );
    }
}
