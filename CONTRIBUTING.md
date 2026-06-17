# Contributing to ristrust

Thanks for your interest. ristrust is a faithful translation of `ristgo`'s
libRIST-proven behavior into a sans-I/O Rust core; the bar is correctness,
determinism, and interop, in that order. The architecture overview is in the
[README](README.md) and the API reference is the rendered `cargo doc`
(crate-level `//!` docs and per-item docs); the ground rules below are binding.

## The gauntlet

Every change must pass all of the following before it is considered done. The
[`justfile`](justfile) wraps them as `just gauntlet`:

```sh
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings   # pedantic is on at warn
cargo fmt --all --check
cargo deny check                                         # the dependency allowlist gate
RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps
cargo tree -p rist-core                                  # import gate: must show only `bytes` (+ std)
```

Feature-gated code must also pass under its feature:
`cargo test -p rist-codec --features dtls` and, when touching the codecs,
`cargo test -p rist --features differential` (needs `$RISTGO_DIR` + the Go
toolchain; graceful-skips otherwise) and `--features interop` (needs the libRIST
CLI tools).

## Ground rules

- **Pure Rust, no FFI.** `#![forbid(unsafe_code)]` is workspace-wide. No OpenSSL /
  aws-lc / ring — crypto is RustCrypto. Adding any dependency means updating
  `deny.toml` with a justification; `cargo deny check` is the CI-enforced gate.
- **The import gate is a crate boundary.** `rist-core` depends on nothing but
  `bytes`; it physically cannot import a codec, crypto, or tokio. New profile
  behavior is a new `wire` enum variant (caught everywhere by an exhaustive
  `match`), never a profile branch inside `flow`. Keep `rist-core` and `rist-codec`
  surfaces small (`unreachable_pub` is on).
- **No panics in library code.** Malformed bytes, short buffers, and peer protocol
  violations return `Result`; arbitrary input to any decoder must never panic
  (fuzz enforces this). `todo!()`/`unimplemented!()` only in unreleased scaffolding.
- **Document every public item.** `///` on every public item, `//!` on every
  crate; public enums are `#[non_exhaustive]`; `thiserror` for errors with
  `Display` prefixed `"rist: "`. The core never logs (`tracing` is host-only).
- **Test discipline.** Table-driven unit tests + dedicated edge tests; `cargo fuzz`
  round-trip + no-panic on `seq` and every wire codec; `proptest` for arithmetic /
  arrival-order invariants; the seeded N-path `Fabric` simulator asserts the four
  invariants (no duplicate delivered, in-order, nothing past deadline, completeness
  under recoverable loss) reproducibly by seed. Target ~0.9:1 test:source overall,
  ~2:1 in the critical modules (`seq`, `rtp`, `rtcp`, `flow`, `gre`, `crypto`).
  Where ristgo has golden vectors / KATs, port them verbatim as Rust fixtures.

## Commits

Plain, descriptive commit messages. **No `Co-Authored-By` or any AI-attribution
lines in any commit message** (carried from ristgo).

## License

By contributing you agree your work is licensed under the project's [MIT](LICENSE)
license. Third-party ports are attributed in [NOTICE.md](NOTICE.md).
