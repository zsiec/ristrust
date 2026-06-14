//! EAP-over-GRE SRP authentication state machine (Main profile).
//!
//! Scaffolding (Phase 3 / WP3). A sans-I/O Authenticatee/Authenticator state
//! machine over the EAPOL/EAP framing libRIST uses
//! (START→IDENTITY→CHALLENGE→…→SUCCESS), driving [`crate::srp`]. The terminal
//! handshake defers SUCCESS to the client's closing ack, matching libRIST.
