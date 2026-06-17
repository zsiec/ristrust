# ristrust

A pure-Rust implementation of **RIST** (Reliable Internet Stream Transport — the
VSF **TR-06** family), the broadcast industry's open standard for reliable
low-latency video over lossy IP.

> **Status: feature-complete, pre-1.0.** All three RIST profiles (Simple / Main /
> Advanced), SMPTE 2022-7 bonding, FEC, source adaptation, reversed-role and
> multi-flow transport are implemented and interoperate with libRIST byte-for-byte
> — 22 sender/receiver combinations across the profiles, clean and lossy — and
> with the `ristgo` reference across a 38-case differential matrix. DTLS 1.2 is
> optional and feature-gated. See the feature matrix below.

## Why

There is no native-Rust RIST today — the only mature implementation is the C
library [libRIST](https://code.videolan.org/rist/librist), embedded in
FFmpeg / VLC / GStreamer. ristrust fills that gap, and is built as a faithful
translation of its feature-complete Go sibling, `ristgo`, which already
interoperates with libRIST across all three profiles. That gives this project
**two oracles**: a same-architecture reference implementation (`ristgo`) and the
C interop ground truth (`libRIST`).

## Quick start

A sender reads media and writes it to the network; a receiver recovers it in
order. Both are `async` over tokio.

```rust,no_run
use rist::{dial, listen, Config, Profile};

# async fn sender() -> Result<(), rist::Error> {
// Sender — Main profile with a PSK passphrase.
let cfg = Config::default().with_profile(Profile::Main).with_secret("hunter2");
let tx = dial("198.51.100.7:5000", cfg).await?;
tx.send(b"transport-stream payload").await?;
# Ok(()) }

# async fn receiver() -> Result<(), rist::Error> {
// Receiver — same profile and secret.
let cfg = Config::default().with_profile(Profile::Main).with_secret("hunter2");
let mut rx = listen("0.0.0.0:5000", cfg).await?;
let media = rx.recv().await?;
# Ok(()) }
```

Configuration can also come from a `rist://` URL (the libRIST CLI convention):

```rust,no_run
# async fn ex() -> Result<(), rist::Error> {
use rist::{dial, parse_url};
let (addr, cfg) = parse_url("rist://198.51.100.7:5000?profile=1&secret=hunter2&aes-type=256")?;
let tx = dial(&addr, cfg).await?;
# Ok(()) }
```

Runnable versions live in [`crates/rist/examples`](crates/rist/examples).

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

## Feature matrix

Every feature, the profiles it applies to, and its spec section. ✅ = implemented
and tested; — = not applicable to that profile.

| Feature | Simple | Main | Advanced | Spec |
|---|:--:|:--:|:--:|---|
| RTP media + compound RTCP control | ✅ | ✅ | ✅ | TR-06-1/-2/-3 |
| ARQ retransmission (range + bitmask NACK, RTT echo) | ✅ | ✅ | ✅ | TR-06-1 §5 |
| Wrap-aware 16↔32-bit sequence widening | ✅ | ✅ | ✅ | TR-06-1 §5.1 |
| Source-clock-wrap re-anchor (long-stream stability) | ✅ | ✅ | ✅ | libRIST parity |
| GRE-over-UDP single-port tunnel + keepalive | — | ✅ | ✅ | TR-06-2 §4 |
| PSK encryption — AES-CTR, 128 / 256-bit | — | ✅ | ✅ | TR-06-2 §6 |
| EAP-SRP authentication (modern v3 + legacy `srp-compat` v2) | — | ✅ | — | TR-06-2 §6.3 |
| EAP-SRP NAT source-port rebind recovery + handshake retransmission | — | ✅ | — | libRIST parity |
| Advanced compact header, control messages, fragmentation | — | — | ✅ | TR-06-3 §5 |
| LZ4 payload compression (LPC) | — | — | ✅ | TR-06-3 §5.3.6 |
| Authenticated AEAD PSK modes 3/4/5 † | — | — | ✅ | TR-06-3 §8 |
| SMPTE 2022-7 bonding (full redundancy + weighted load-share) | ✅ | ✅ | ✅ | TR-06-2 §7 |
| Packet split/merge bonding (`split=`/`merge=`) | ✅ | ✅ | ✅ | libRIST parity |
| FEC — SMPTE ST 2022-1 / ST 2022-5 (1-D + 2-D XOR) | ✅ | ✅ | ✅ | TR-06-2 §8.4 |
| Source adaptation — Link Quality Messages + AIMD rate control | ✅ | ✅ | ✅ | TR-06-4 Part 1 |
| Congestion control — `recovery_maxbitrate` retransmit pacing | ✅ | ✅ | ✅ | libRIST parity |
| Null-packet deletion (NPD) | — | ✅ | — | TR-06-2 §8.6 |
| Reversed-role transport (listener-sender / caller-receiver) | ✅ | ✅ | ✅ | libRIST parity |
| Multi-flow demux (one socket, many flows) + bonded multi-flow | ✅ | ✅ | ✅ | libRIST parity |
| Out-of-band tunnel (reverse-direction OOB datagrams) | — | ✅ | ✅ | TR-06-2 GRE passthrough |
| Multicast — ASM + IPv4 source-specific, egress iface / TTL / loopback | ✅ | ✅ | ✅ | — |
| DTLS 1.2 transport security ‡ | — | ✅ | — | TR-06-2 §6.2 |

† **AEAD modes 3/4/5** (AES-CTR-HMAC, AES-GCM, ChaCha20-Poly1305) are a ristgo
extension, not libRIST: they ship as a KAT-anchored crypto primitive
(`rist_codec::aead`) and are **not wired onto the wire codec** (the codec stays
AES-CTR-only for interop, matching ristgo). The 12-byte AEAD nonce framing is
interop-unvalidated. See [Limitations](#limitations).

‡ **DTLS** is optional (`--features dtls`) and not a libRIST interop gate (libRIST
has no DTLS). It implements the full TR-06-2 §6.2 mandatory suite set —
ECDHE-ECDSA and ECDHE-RSA with AES-128/256-GCM, `RSA_WITH_NULL_SHA256`, and the
PSK suite — plus **mutual (client-certificate) authentication**, validated against
OpenSSL `s_server`/`s_client -dtls1_2`.

## Connection roles, bonding, and multi-flow

The default roles are sender-dials / receiver-listens, but RIST also allows the
reverse, and one socket can carry many flows:

```rust,no_run
# async fn ex() -> Result<(), rist::Error> {
use rist::{dial_bonded, listen_bonded, listen_sender, dial_receiver, listen_multi, Config};

// SMPTE 2022-7 bonding — N paths feeding one deduplicated flow.
let cfg = Config::default();
let tx = dial_bonded(&["198.51.100.7:5000", "203.0.113.7:5000"], cfg.clone()).await?;
let rx = listen_bonded(&["0.0.0.0:5000", "0.0.0.0:5001"], cfg.clone()).await?;

// Reversed roles — the sender listens, the receiver dials.
let listening_sender = listen_sender("0.0.0.0:5000", cfg.clone()).await?;
let dialing_receiver = dial_receiver("198.51.100.7:5000", cfg.clone()).await?;

// Multi-flow — one listener demultiplexes many senders into separate flows.
let multi = listen_multi("0.0.0.0:5000", cfg).await?;
# Ok(()) }
```

Bonding is **full redundancy** by default (every path carries every packet; the
core dedups by `(seq, source_time)`); per-path weights enable load-sharing
(`dial_bonded_weighted`). FEC composes with bonding, and Advanced fragmentation
composes with everything.

## Encryption and authentication (Main / Advanced)

- **PSK** — set a passphrase with `with_secret` (or `?secret=`); the AES-CTR key
  is `PBKDF2-HMAC-SHA256(passphrase, nonce)`, 256-bit by default (`with_aes_key_bits` /
  `?aes-type=128|256`).
- **EAP-SRP** — set credentials with `with_srp_credentials` (or
  `?username=&password=`); a sender authenticates, a receiver verifies. Use it
  alongside a `secret` (the libRIST-interoperable combined mode), or alone
  (`use_key_as_passphrase`, a ristrust↔ristrust mode). `with_srp_compat` /
  `?srp-compat=1` selects the legacy EAPOL v2 handshake for old peers. The
  handshake retransmits under loss and recovers a NAT source-port rebind.

## FEC, source adaptation, OOB, multicast

```rust,no_run
# async fn ex() -> Result<(), rist::Error> {
use rist::{Config, FecConfig, Profile};
// 10×10 2-D ST 2022-1 FEC (the default matrix). FEC recovers losses with no NACK
// round trip; ARQ remains the backstop.
let cfg = Config::default().with_profile(Profile::Main).with_fec(FecConfig::default());
# Ok(()) }
```

- **Source adaptation** (TR-06-4 Part 1): a receiver emits Link Quality Messages;
  a sender drives an AIMD controller and an encoder-rate callback (`RateCallback`).
- **Out-of-band tunnel**: both roles can read/write reverse-direction OOB
  datagrams alongside media.
- **Multicast**: bind/destination on a group address; `?miface=`/`?ttl=`/`?source=`
  select egress interface, TTL, and an IGMPv3/MLDv2 source filter (see
  [Limitations](#limitations) for IPv6 SSM).

## `rist://` URL parameters

`parse_url` accepts the libRIST parameter set; an unrecognized key is rejected
(a typo fails loudly rather than being silently ignored):

`profile`, `secret`, `aes-type`, `key-rotation`, `username`, `password`,
`srp-compat`, `cname`, `compression`, `buffer` (`buffer-min`/`buffer-max`),
`rtt` (`rtt-min`/`rtt-max`/`rtt-multiplier`), `reorder-buffer`, `session-timeout`,
`keepalive` (`keepalive-interval`), `bandwidth`, `return-bandwidth`, `weight`,
`min-retries`/`max-retries`, `virt-src-port`/`virt-dst-port`, `recovery-priority`,
`congestion-control`, `timing-mode`, `split` (`off`/`auto`/`half`),
`merge` (`off`/`pairs`/`auto`), `miface`, `ttl`, `source`, `reflector`,
`local-port`.

## Limitations

- **IPv6 source-specific multicast (SSM) receive is not supported.** `socket2`
  exposes no portable `MCAST_JOIN_SOURCE_GROUP` for IPv6, and ristrust is
  `#![forbid(unsafe_code)]`, so an IPv6 SSM join returns
  `io::ErrorKind::Unsupported`. IPv4 SSM and IPv4/IPv6 ASM all work.
- **Advanced AEAD modes 3/4/5 are a tested primitive, not a wire feature** — see
  the † note above; the Advanced wire codec is AES-CTR-only, matching libRIST and
  ristgo.
- **DTLS is not a libRIST interop gate** (libRIST has no DTLS); it is validated
  against OpenSSL and ristgo only, behind `--features dtls`.

## Interoperability

- **libRIST** v0.2.18-rc1 — 22 sender/receiver combinations across Simple / Main /
  Advanced, clean and lossy, byte-exact recovery, including packet split/merge both
  directions (behind `--features interop`, graceful-skip when the tools are absent).
- **ristgo** — a 38-case differential matrix (profiles × clear/AES-128/AES-256/LZ4
  × both directions × clean+lossy, plus all-profile bonding, EAP-SRP, and packet
  split/merge), driven by the ristgo example binaries (behind `--features
  differential`, needs `$RISTGO_DIR`).

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor checklist.

## License

[MIT](LICENSE). Third-party ports are attributed in [NOTICE.md](NOTICE.md).
