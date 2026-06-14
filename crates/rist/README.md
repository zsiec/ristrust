# rist

The tokio I/O host and public API for
[ristrust](https://github.com/zsiec/ristrust). This is the crate applications
depend on.

It owns the real clock, the timer wheel, the UDP sockets, and the async tasks,
and it drives the deterministic [`rist-core`](../rist-core) flow through the
profile codecs in [`rist-codec`](../rist-codec). The host is a thin, dumb pump:
all protocol logic lives in the core.

```rust,no_run
# async fn ex() -> Result<(), rist::Error> {
use rist::{dial, Config, Profile};

let cfg = Config::default().with_profile(Profile::Simple);
let _sender = dial("127.0.0.1:5000", cfg).await?;
// sender.send(&payload).await?;   // media path lands in WP2
# Ok(()) }
```

> **Status: early scaffolding.** `Config`, validation, the `Runtime` abstraction,
> and connection setup (socket binding) are in place; the media/control event
> loop and the `Sender`/`Receiver` data paths land in Phase 2 (WP2). See the
> workspace `PLAN.md`.
