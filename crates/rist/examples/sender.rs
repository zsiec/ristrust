//! Minimal RIST sender: reads media from stdin and transmits it to a RIST
//! receiver in RTP-sized (1316-byte) chunks. The argument is a `host:port`
//! address or a full `rist://host:port?…` URL (so `profile`, `secret`, `buffer`,
//! and the other query knobs all work).
//!
//! ```text
//! cat stream.ts | cargo run --release --example sender -- 'rist://127.0.0.1:5000?profile=1'
//! ```

use rist::{Config, dial, parse_url};
use tokio::io::{AsyncRead, AsyncReadExt};

/// One RTP media payload: 7 MPEG-TS cells, the RIST default.
const CHUNK: usize = 1316;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sender <host:port | rist://url>");
        std::process::exit(2);
    });
    let (addr, cfg) = parse_url(&arg, Config::default()).unwrap_or_else(|e| {
        eprintln!("sender: {e}");
        std::process::exit(1);
    });
    let sender = dial(&addr, cfg).await.unwrap_or_else(|e| {
        eprintln!("sender: {e}");
        std::process::exit(1);
    });

    let mut stdin = tokio::io::stdin();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = read_chunk(&mut stdin, &mut buf).await;
        if n == 0 {
            break; // clean EOF
        }
        if let Err(e) = sender.send(&buf[..n]).await {
            eprintln!("sender: {e}");
            break;
        }
    }
    let _ = sender.close().await;
}

/// Reads up to `buf.len()` bytes, tolerating short reads, so every send carries a
/// full chunk except possibly the last. Returns the count (`0` = clean EOF).
async fn read_chunk<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    filled
}
