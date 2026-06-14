# ristrust task runner. `just <recipe>`; `just` lists recipes.

# Run the full checkpoint gauntlet (mirrors CI + the ORCHESTRATION protocol).
gauntlet: build test clippy fmt-check doc deny import-gate
	@echo "gauntlet: all green"

build:
	cargo build --workspace --all-targets

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

deny:
	cargo deny check

# Assert the rist-core import gate: the sans-I/O core must not depend on any
# codec, host, or I/O crate. The crate boundary already enforces this, but this
# fails loudly with a readable message if someone adds a forbidden dependency.
import-gate:
	@echo "checking rist-core import gate..."
	@! cargo tree -p rist-core --edges normal --prefix none 2>/dev/null \
		| grep -E '^(rist-codec|rist|tokio|socket2|quinn-udp|aes|ctr|aes-gcm|chacha20poly1305|pbkdf2|hmac|sha2) ' \
		&& echo "rist-core import gate: OK (depends only on bytes + std)" \
		|| (echo "rist-core import gate VIOLATED: a forbidden dependency leaked into the core" && exit 1)

# Interop suite (requires libRIST tools on PATH or via RISTGO_LIBRIST_TOOLS).
interop:
	cargo test --workspace --features interop -- --nocapture
