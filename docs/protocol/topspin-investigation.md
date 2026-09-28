# Open issue: TopSpin crash with the legacy syscall hack removed

This is a conclusions-only summary. It exists so `LINUWUX_SYSCALL_HACK`
removal (tracked in the syscall-routing plan) stays gated on this being
resolved, without carrying the full blow-by-blow investigation log into
permanent history. The detailed trace history lives outside this repo.

## Status

Unresolved. With `LINUWUX_SYSCALL_HACK` off (the target, KUSER-route-only
behavior described in [`syscall-routing.md`](syscall-routing.md)), TopSpin
reaches a successful `NtFreeVirtualMemory(MEM_RELEASE)` release and then
faults inside Wine's `ntdll!A_SHAFinal` reading `[RCX+0x30]` with `RCX=0`
(access violation `0xc0000005`). With the hack on, the same launch passes
that point and continues.

## What's established

- The KUSER route choice (hack on/off) is the variable that determines
  whether the crash is reached — not a red herring.
- The matched `NtFreeVirtualMemory` release itself succeeds identically in
  both modes (same arguments, same Wine-reported status and output fields).
  Routing that one release directly to Wine, skipping Reflex's ordinary
  replay of it, does **not** prevent the crash — so that release in
  isolation is not the cause.
- No individual syscall has been proven causal. The crash is in the
  post-return, user-mode continuation after a syscall boundary that itself
  completes normally in both modes — i.e. the divergence is not yet located
  in the syscall ABI handoff itself.
- A previously-suspected five-call cleanup sequence
  (`NtReadFile`/`NtCreateFile`/`NtProtectVirtualMemory`/
  `NtFreeVirtualMemory`/`NtClose`) was **not** observed as one contiguous
  sequence in the paired traces that were supposed to establish it; treat
  that theory as unconfirmed, not as a lead to keep pursuing as stated.

## What's still needed

A bounded instruction trace from the release syscall's return boundary
forward into the caller, captured in both hack-on and hack-off runs,
comparing the first differing RIP, registers, flags, and stack slots up to
the point that either continues normally or reaches `A_SHAFinal`. This needs
a real Wine/Proton run against the actual game to capture — it can't be
produced or verified from source alone.

## Unconfirmed lead: `int 2e` and the cleanup sequence

A later recollection (secondhand, not verified against a trace) connects
the five-call cleanup sequence above to whether the syscall stub involved
ends in an `int 2e` gate. `int2e.rs`'s fallback chain is a plausible
mechanism for *some* crash of this shape: its last-resort strategy
(`patch_to_syscall`) permanently rewrites `int 2e` to `syscall` in the
game's own code when its bounded private-trampoline table
(`TRAMPOLINE_CAPACITY`) is exhausted, and anti-tamper code hashing or
verifying its own bytes could plausibly react to that with a deliberately
displaced crash. This was checked directly: `TRAMPOLINE_CAPACITY` is
already 16384 (raised from an original 1024, with a comment describing a
matching real TopSpin incident) — but that specific, already-shipped fix
was confirmed **not** to be this one. Whether some other aspect of `int
2e` handling is involved in the `A_SHAFinal` crash is still unconfirmed.
Do not treat this section as a lead to implement against; it needs a real
trace to become one.

## Why this blocks hack removal

[`syscall-routing.md`](syscall-routing.md)'s invariant 4 requires the
KUSER-route path to match the direct syscall ABI exactly on bypass. TopSpin
is the one title where that hasn't been verified end-to-end yet: something
between the release's return and `A_SHAFinal` behaves differently with the
hack off, and it isn't yet known whether that's a real ABI-parity bug in the
bridge or a difference in the game's own control flow. Removing the hack
project-wide before this is resolved risks reintroducing a regression for
this specific title with no fallback.
