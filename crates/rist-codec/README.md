# rist-codec

The RIST profile codecs and crypto for
[ristrust](https://github.com/zsiec/ristrust): pure functions that decode inbound
datagrams into, and encode outbound datagrams from, the
[`rist-core`](../rist-core) narrow-waist types (`MediaPacket`, `Feedback`).

Every profile speaks a different dialect; this crate owns all of them so the core
stays profile-agnostic. It performs no I/O and reads no clock.

- `rtp` / `rtcp` — Simple/Main RTP media and compound RTCP control.
- `gre` — Main profile GRE-over-UDP tunnel framing.
- `adv` — Advanced (TR-06-3) compact header + control messages.
- `crypto` — PSK key derivation and ciphers (AES-CTR, AEAD).
- `npd` — null-packet deletion.
- `lpc` — LZ4 block compression (Advanced LPC).
- `srp` / `eap` — EAP-SRP authentication (Main profile).
- `adapt` — TR-06-4 Link Quality Message + rate controller.

Most modules are scaffolding today; see the workspace `PLAN.md` roadmap. `crypto`
ships the PSK key-derivation primitive (PBKDF2-HMAC-SHA256) used by the Main and
Advanced profiles.
