//! rist2rist: a RIST → RIST relay (libRIST's `rist2rist` tool). It receives a
//! Main-profile RIST stream on the input and re-transmits every recovered packet —
//! preserving its sequence and source timestamp — to one or more RIST outputs, so a
//! downstream peer recovers an identical flow. Built on [`rist::reflect`].
//!
//! The input is a `host:port` or a full `rist://host:port?…` URL (the query knobs —
//! `profile`, `secret`, `buffer`, … — configure the whole relay). Each output is a
//! `host:port` destination, dialed with the input's configuration.
//!
//! ```text
//! cargo run --release --example rist2rist -- \
//!     'rist://0.0.0.0:5000?profile=1&secret=hunter2' 203.0.113.5:6000 198.51.100.9:6000
//! ```
//!
//! Relays until interrupted (Ctrl-C).

use rist::{Config, Profile, reflect};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: rist2rist <input host:port|rist://url> <output host:port> [<output>...]");
        std::process::exit(2);
    }
    let input = args[0].clone();
    let outputs: Vec<&str> = args[1..].iter().map(String::as_str).collect();

    // The reflector is Main-profile; default to it so a bare input addr works (a
    // `profile=` query knob in the input URL still overrides).
    let cfg = Config::default().with_profile(Profile::Main);
    let reflector = reflect(&input, &outputs, cfg).await.unwrap_or_else(|e| {
        eprintln!("rist2rist: {e}");
        std::process::exit(1);
    });
    let local = reflector
        .local_addr()
        .map_or_else(|_| input.clone(), |a| a.to_string());
    eprintln!(
        "rist2rist: relaying {local} -> {} output(s); Ctrl-C to stop",
        reflector.output_count()
    );

    // Run until interrupted; then tear the relay down cleanly.
    let _ = tokio::signal::ctrl_c().await;
    let _ = reflector.close().await;
}
