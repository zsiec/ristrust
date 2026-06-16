//! The logging contract: how an application consumes ristrust's diagnostics.
//!
//! ristrust logs through the [`tracing`] crate — the idiomatic Rust logging facade —
//! rather than a bespoke callback. `tracing` *is* the hook: an application installs a
//! [`Subscriber`](https://docs.rs/tracing/latest/tracing/trait.Subscriber.html) (for
//! example via [`tracing-subscriber`](https://docs.rs/tracing-subscriber)) and receives
//! every event, with full control over filtering, formatting, and routing. ristrust
//! installs no subscriber of its own, so when none is installed there is zero overhead.
//!
//! # Categories (targets)
//!
//! Every event carries a **target** in the `rist::*` namespace naming the subsystem it
//! belongs to — the analog of libRIST's / ristgo's `LogCategory`, and a stable contract
//! decoupled from the internal module layout. Filter on it (e.g. `RUST_LOG=rist::crypto=warn`)
//! or reference the constant programmatically. The categories:
//!
//! | Target | Constant | Covers |
//! |---|---|---|
//! | `rist::general` | [`GENERAL`] | messages not tied to a specific subsystem |
//! | `rist::config`  | [`CONFIG`]  | configuration parsing and validation |
//! | `rist::session` | [`SESSION`] | session formation, dial/listen, keepalive, out-of-band data |
//! | `rist::flow`    | [`FLOW`]    | the ARQ core: buffering, NACKs, playout |
//! | `rist::rtcp`    | [`RTCP`]    | RTCP / feedback send-receive (SR/RR/SDES/NACK/LQM) |
//! | `rist::socket`  | [`SOCKET`]  | UDP media/FEC datagram I/O |
//! | `rist::crypto`  | [`CRYPTO`]  | PSK encryption, key rotation, EAP-SRP, DTLS, decode-key mismatch |
//! | `rist::bonding` | [`BONDING`] | SMPTE 2022-7 multipath formation and path liveness |
//!
//! Two notes on what is *not* logged, by design:
//! - **The deterministic core never logs.** `rist-core` has no I/O and no clock, so
//!   flow-level visibility (loss, recovery, reordering, …) is surfaced through
//!   [`Stats`](crate::Stats), not the `rist::flow` target — which therefore rarely, if
//!   ever, carries an event. It is part of the contract for completeness.
//! - **Configuration errors are returned, not logged.** A bad [`Config`](crate::Config)
//!   fails [`validate`](crate::Config::validate) with a [`ConfigError`](crate::ConfigError);
//!   `rist::config` exists for parity but is similarly quiet.
//!
//! # Levels
//!
//! ristrust uses `tracing` levels per their usual meaning; they map onto ristgo's
//! `LogLevel` as: [`ERROR`](tracing::Level::ERROR) ↔ `LogError`,
//! [`WARN`](tracing::Level::WARN) ↔ `LogWarning`, [`INFO`](tracing::Level::INFO) ↔
//! `LogNote`, [`DEBUG`](tracing::Level::DEBUG) ↔ `LogDebug`. In practice the host emits
//! `WARN` for unexpected-but-recoverable conditions (a likely key mismatch, a dropped
//! flow) and `DEBUG` for routine per-packet diagnostics (an encode/transmit hiccup, a
//! session dialed); `rist-core` emits nothing.
//!
//! # Installing a subscriber
//!
//! Any `tracing` subscriber works. A common setup with `tracing-subscriber`:
//!
//! ```ignore
//! use tracing_subscriber::{EnvFilter, fmt};
//! // Honour RUST_LOG, e.g. RUST_LOG="rist::crypto=warn,rist::session=info"
//! fmt().with_env_filter(EnvFilter::from_default_env()).init();
//! ```
//!
//! To bridge into an application's own logger (the shape of ristgo's `Logger`
//! callback — `fn(level, category, message)`), install a custom
//! [`Layer`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/trait.Layer.html)
//! that reads each event's `metadata().level()` and `metadata().target()` and forwards
//! to the callback; the target *is* the category.

/// The `rist::general` target: messages not tied to a specific subsystem.
pub const GENERAL: &str = "rist::general";
/// The `rist::config` target: configuration parsing and validation.
pub const CONFIG: &str = "rist::config";
/// The `rist::session` target: session formation, dial/listen, keepalive, and
/// out-of-band data.
pub const SESSION: &str = "rist::session";
/// The `rist::flow` target: the ARQ core (buffering, NACKs, playout). The sans-I/O
/// core does not log, so flow visibility is via [`Stats`](crate::Stats) instead.
pub const FLOW: &str = "rist::flow";
/// The `rist::rtcp` target: RTCP / feedback send-receive (SR/RR/SDES/NACK/LQM).
pub const RTCP: &str = "rist::rtcp";
/// The `rist::socket` target: UDP media and FEC datagram I/O.
pub const SOCKET: &str = "rist::socket";
/// The `rist::crypto` target: PSK encryption, key rotation, EAP-SRP, DTLS, and
/// decode failures that signal a key mismatch.
pub const CRYPTO: &str = "rist::crypto";
/// The `rist::bonding` target: SMPTE 2022-7 multipath formation and path liveness.
pub const BONDING: &str = "rist::bonding";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_the_documented_rist_namespace() {
        // The public contract: each category is its `rist::<name>` target string.
        for (target, name) in [
            (GENERAL, "general"),
            (CONFIG, "config"),
            (SESSION, "session"),
            (FLOW, "flow"),
            (RTCP, "rtcp"),
            (SOCKET, "socket"),
            (CRYPTO, "crypto"),
            (BONDING, "bonding"),
        ] {
            assert_eq!(target, format!("rist::{name}"));
        }
    }
}
