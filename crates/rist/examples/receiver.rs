//! Minimal RIST receiver: recovers a RIST media stream and writes the payloads to
//! stdout. The argument is a `host:port` bind address or a full `rist://host:port?…`
//! URL (so `profile`, `secret`, `buffer`, and the other query knobs all work).
//!
//! ```text
//! cargo run --release --example receiver -- 'rist://:5000?profile=1' | ffplay -
//! ```

use rist::{Config, listen, parse_url};
use tokio::io::{AsyncWriteExt, stdout};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: receiver <host:port | rist://url>");
        std::process::exit(2);
    });
    let (addr, cfg) = parse_url(&arg, Config::default()).unwrap_or_else(|e| {
        eprintln!("receiver: {e}");
        std::process::exit(1);
    });
    let mut receiver = listen(&addr, cfg).await.unwrap_or_else(|e| {
        eprintln!("receiver: {e}");
        std::process::exit(1);
    });

    let mut out = stdout();
    while let Ok(payload) = receiver.recv().await {
        if out.write_all(&payload).await.is_err() {
            break; // downstream closed the pipe (e.g. the consumer exited)
        }
    }
    let _ = out.flush().await;
    let _ = receiver.close().await;
}
