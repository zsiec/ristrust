//! The async driver loop (scaffolding).
//!
//! Phase 2 (WP2): a `select!` loop multiplexing socket readiness, timer
//! deadlines, and application commands. Each iteration captures `now`, feeds the
//! flow core, drains its effects (send datagrams, arm/clear timers), and surfaces
//! its events to the application channels.
