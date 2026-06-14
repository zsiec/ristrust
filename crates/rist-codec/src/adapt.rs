//! Source-adaptation Link Quality Message + rate controller (TR-06-4 Part 1).
//!
//! Scaffolding (Phase 6 / WP6). The 44-byte LQM (Figure 2: eleven 32-bit
//! big-endian counters) and an AIMD rate controller (monotone in loss). The
//! profile-specific encapsulation lives in the session layer (Simple/Main RR
//! profile extension; Advanced control index 0x0002/0x0003). No libRIST
//! reference exists, so the bar is spec conformance + closed-loop simulation.
