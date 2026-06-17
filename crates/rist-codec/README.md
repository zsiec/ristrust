# rist-codec

The RIST profile codecs and crypto for
[ristrust](https://github.com/zsiec/ristrust): pure functions that decode inbound
datagrams into, and encode outbound datagrams from, the
[`rist-core`](../rist-core) narrow-waist types (`MediaPacket`, `Feedback`).

Every profile speaks a different dialect; this crate owns all of them so the core
stays profile-agnostic. It performs no I/O and reads no clock.

- `rtp` / `rtcp` — Simple/Main RTP media and compound RTCP control.
- `gre` — Main profile GRE-over-UDP tunnel framing.
- `adv` — Advanced (TR-06-3) compact header, fragmentation + control messages.
- `crypto` — PSK key derivation (PBKDF2-HMAC-SHA256) + AES-CTR ciphers.
- `aead` — Advanced authenticated PSK modes 3/4/5 (AES-CTR-HMAC, AES-GCM,
  ChaCha20-Poly1305). KAT-anchored; a ristgo extension, not wired onto the wire
  codec (the Advanced codec stays AES-CTR-only for libRIST interop).
- `fec_header` — SMPTE ST 2022-1 / ST 2022-5 FEC packet framing.
- `npd` — null-packet deletion.
- `lpc` — LZ4 block compression (Advanced LPC).
- `srp` / `eap` — EAP-SRP authentication (Main profile), with retransmit-idempotent
  handshake recovery under loss.
- `adapt` — TR-06-4 Link Quality Message + rate controller.
- `dtls` — optional DTLS 1.2, behind the `dtls` feature: the full TR-06-2 §6.2
  suite set (PSK, ECDHE-ECDSA and ECDHE-RSA AES-128/256-GCM, `RSA_WITH_NULL_SHA256`)
  plus mutual (client-certificate) authentication.

All modules are implemented; the `crypto` PSK key-derivation primitive
(PBKDF2-HMAC-SHA256) feeds the Main and Advanced profile ciphers. Every codec is
fuzzed for round-trip stability and no-panic on arbitrary input.
