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
let sender = dial("127.0.0.1:5000", cfg).await?;
sender.send(b"media payload").await?;
# Ok(()) }
```

The crate exposes `dial` / `listen` (and the bonded `dial_bonded` / `listen_bonded`)
constructors returning a `Sender` / `Receiver`, plus `parse_url` for `rist://`
URLs. All three profiles, 2022-7 bonding, source adaptation, and multicast
(group join + egress interface/TTL, via a group bind/destination address and the
`miface`/`ttl`/`source` URL knobs) are supported; DTLS 1.2 is available behind the
`dtls` feature.
