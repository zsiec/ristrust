# rist-core

The sans-I/O deterministic core of [ristrust](https://github.com/zsiec/ristrust),
plus the normalized "narrow waist" types every RIST profile codec encodes and
decodes through.

This crate is a pure, deterministic state machine: it never reads a clock, opens
a socket, or spawns a task. Time enters as an explicit `now: Timestamp` argument;
side effects leave as returned values (`Output` / `Event`) that the host drains
and performs. That is what makes the whole protocol exhaustively testable on a
seeded fake-clock network simulator.

It depends on nothing but `bytes`. The crate boundary *is* the architecture's
import gate: a profile detail cannot leak into the core, because the codecs live
in a downstream crate.

- `clock` — `Timestamp` / `Micros` newtypes; the core's notion of time.
- `seq` — wrap-aware 16- and 32-bit sequence-number arithmetic.
- `rtt` — the `eight_times_rtt` EWMA estimator.
- `wire` — the narrow waist: `MediaPacket` and the `Feedback` enum.
- `flow` — the deterministic ARQ + reorder + dedup + SMPTE 2022-7 merge core.

See the workspace `PLAN.md` for the full architecture.
