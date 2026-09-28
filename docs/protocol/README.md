# Protocol design reference

Permanent design and compatibility reference for the Reflex/Denuvo
protocol LinUwUx implements. Where the code and these docs disagree, that's
a bug in one of them — fix the discrepancy rather than trusting whichever
was written more recently.

- [`compatibility-overview.md`](compatibility-overview.md) — what this
  project is for, what currently works, and the true state of
  `LINUWUX_SYSCALL_HACK` today.
- [`syscall-routing.md`](syscall-routing.md) — the target design for syscall
  routing: goal, invariants, and the three routing boundaries in source.
- [`game-quirks.md`](game-quirks.md) — per-title CPU identity / KUSER
  recipe / dispatch protocol differences, backing `protocol/quirks.rs`.
- [`topspin-investigation.md`](topspin-investigation.md) — the one open
  compatibility issue currently gating full `LINUWUX_SYSCALL_HACK` removal.
- [`umip.md`](umip.md) — the unprivileged SGDT interception primitive and
  the coverage requirement before enabling UMIP compatibility.

See `docs/ARCHITECTURE.md` (repo root `docs/`) for how these map onto the
current source layout.
