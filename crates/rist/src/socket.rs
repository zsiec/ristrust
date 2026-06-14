//! UDP socket wiring (scaffolding).
//!
//! Phase 2 (WP2): the even/odd port pair (Simple profile) and single port
//! (Main/Advanced), address learning from inbound traffic, and demultiplexing by
//! source address / flow id. Built on the [`AsyncUdpSocket`](crate::runtime::AsyncUdpSocket)
//! abstraction.
