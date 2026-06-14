# ristrust

A pure-Rust implementation of **RIST** (Reliable Internet Stream Transport — the
VSF **TR-06** family), the broadcast industry's open standard for reliable
low-latency video over lossy IP.

> **Status: feature-complete.** All three RIST profiles (Simple / Main /
> Advanced), SMPTE 2022-7 bonding, and source adaptation are implemented and
> interoperate with libRIST byte-for-byte — 20 sender/receiver combinations
> across the profiles, clean and lossy. DTLS 1.2 is optional and feature-gated.
> See the feature table below.

## Why

There is no native-Rust RIST today — the only mature implementation is the C
library [libRIST](https://code.videolan.org/rist/librist), embedded in
FFmpeg / VLC / GStreamer. ristrust fills that gap, and is built as a faithful
translation of its feature-complete Go sibling, `ristgo`, which already
interoperates with libRIST across all three profiles. That gives this project
**two oracles**: a same-architecture reference implementation (`ristgo`) and the
C interop ground truth (`libRIST`).

## Architecture

ristrust is a **sans-I/O deterministic core** with a thin async host around it —
the same philosophy as [srtrust](https://github.com/zsiec/srtrust).

The protocol's ARQ + reordering + de-duplication + RTT/NACK cadence + **SMPTE
2022-7 multipath merge** live in a pure state machine that never touches a clock,
a socket, or a task. Time enters as an explicit argument; side effects leave as
returned values that a tokio host drains and performs on the wire. The whole core
is therefore exhaustively testable on a seeded fake-clock network simulator.

Three crates, layered so the core's profile-agnostic boundary is a **compile-time
guarantee**, not a lint:

| Crate | Role | Depends on |
|---|---|---|
| **`rist-core`** | The sans-I/O deterministic core + the normalized "narrow waist" types (`MediaPacket`, `Feedback`). | `bytes` only |
| **`rist-codec`** | The profile codecs (RTP/RTCP, GRE, Advanced) + crypto, all pure functions. | `rist-core` + RustCrypto |
| **`rist`** | The tokio I/O host and the public `Sender`/`Receiver` API. | both + tokio |

`rist-core` physically cannot import a codec or tokio — so a profile detail can
never leak into the core. New profile behavior is a new enum variant at the
waist, caught everywhere it must be handled by an exhaustive `match`.

## What's implemented

| Area | Status |
|---|---|
| `rist-core` — wrap-aware seq, RTT EWMA, the flow core, the N-path simulator + four invariants | ✅ |
| Simple Profile (RTP/RTCP) + tokio host | ✅ |
| Main Profile — GRE tunnel, PSK AES-CTR (128/256-bit), EAP-SRP auth | ✅ |
| Advanced Profile (TR-06-3) — compact header, LZ4, control messages | ✅ |
| Bonding / SMPTE 2022-7 multipath | ✅ |
| Multicast — group join (ASM + source-specific), egress interface / TTL / loopback (`miface`/`ttl`/`source`) | ✅ |
| Source adaptation (TR-06-4 Part 1) — Link Quality Messages + AIMD rate control | ✅ |
| Congestion control — `recovery_maxbitrate` retransmit pacing (off / normal / aggressive) | ✅ |
| libRIST interop (20 combinations) + ristgo differential, both byte-exact | ✅ |
| DTLS 1.2 transport security (PSK + ECDHE-ECDSA) | ✅ optional, `--features dtls` |

## Design principles

- **Pure Rust, no FFI.** `#![forbid(unsafe_code)]` workspace-wide; crypto is
  RustCrypto; no OpenSSL / aws-lc / ring. The dependency posture is enforced by
  `cargo deny`.
- **No panics in library code.** Every decoder returns `Result` and is fuzzed to
  never panic on arbitrary bytes.
- **Determinism is testable.** Every flow/bonding test asserts four invariants —
  no duplicate delivered, in-order output, nothing past deadline, completeness
  under recoverable loss — over a seeded seed sweep, reproducible by seed.

## Development

```sh
just gauntlet     # build + test + clippy + fmt + doc + deny + import-gate
just test         # cargo test --workspace
just interop      # interop suite vs libRIST tools (when present)
```

## License

[MIT](LICENSE). Third-party ports are attributed in [NOTICE.md](NOTICE.md).
