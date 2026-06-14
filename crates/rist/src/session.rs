//! The per-flow goroutine-equivalent host (scaffolding).
//!
//! Phase 2 (WP2) builds the session: a task that owns the real clock and timer
//! wheel, runs the profile codec strategy, drives [`rist_core::flow::Flow`], and
//! performs the drained [`Output`](rist_core::flow::Output) effects on the wire.
//! It is a thin, dumb pump — no protocol logic lives here.
