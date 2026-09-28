# Per-title protocol differences

Reference table of how each supported title's Reflex client differs in CPU
identity, `KUSER_SHARED_DATA` recipe, and dispatch protocol. This is the
data behind `protocol/quirks.rs` (see `docs/ARCHITECTURE.md`) — when a new
title needs a special case, it should extend this table (and the matching
row in `protocol/quirks.rs`), not add an inline literal to dispatch code.

Titles covered: ACBFR, BGE, FC6, NFSPB, TopSpin, SMT5V, Hatsune Miku,
LADPYIH. BL4 is working in current gameplay testing, but its protocol
differences have not been recorded in this table. BL4-1.10 has not been
separately confirmed.

## CPU identity

| Title | VMX brand | SVM brand | VMX leaf 1 `ECX` | SVM leaf 1 `ECX` |
| --- | --- | --- | --- | --- |
| ACBFR | DenuvOwO | DenuvOwO | `01faebff` | `00f8220b` |
| BGE | DenuvOwO | DenuvOwO | `01faebff` | `00f8220b` |
| FC6 | DenuvOwO | DenuvOwO | `01faebff` | `00f8220b` |
| NFSPB | DenuvOwO | DenuvOwO | `01faebff` | `00f8220b` |
| TopSpin | DenuvOwO | DenuvOwO | `01faebff` | `00f8220b` |
| SMT5V | i9-10900K | Ryzen 9 5900X | `7bfafbff` | `7ad8320b` |
| Hatsune Miku | i9-10900K | Ryzen 9 5900X | `7bfafbff` | `7ad8320b` |
| LADPYIH | i9-10900K | Ryzen 9 5900X | `7bfafbff` | `7ad8320b` |

Every title returns `0x40000001` as the maximum hypervisor leaf and `Hv#0`
from that leaf. The VMX and SVM implementations differ in host-specific CPU
identity and vendor string, not in the purpose of the protocol.

## `KUSER_SHARED_DATA` recipes

| Recipe | Titles | Defining behavior |
| --- | --- | --- |
| Resume family | ACBFR, BGE, FC6, NFSPB, TopSpin | Feature image at `0x260..0x2b0`, seven feature bytes forced off, XSTATE ranges zeroed, ready marker `0xffc=0x13371337`. |
| Dispatch family | Hatsune Miku, LADPYIH, SMT5V | Header write at `0`, overlapping `0x260..0x290` stores, fixed data at `0x2d0`, `0x2e8`, `0x2f4`, `0x378`, `0x3c0`; no ready marker or broad XSTATE clear. |

Within the resume family, only the root string differs: ACBFR and NFSPB
write a full `C:\\Windows` field, BGE and FC6 leave it alone, and TopSpin
writes only trailing `ws` at `0x40`. BGE and FC6 use byte-identical source.
Hatsune Miku and LADPYIH use byte-identical source. SMT5V shares the
dispatch-family KUSER writer despite a reduced CPUID control surface.

## Reflex protocol

| Title | Identity | CPUID control shape | Handler arrangement | Client syscall selectors |
| --- | --- | --- | --- | --- |
| ACBFR | DR3/DR7 | `336933 → 1337`, optional client-only `336967` | One ResumeTarget handler | Handler also hides debug-register use. |
| BGE | CR3 | `69696969 → 336933 → 1337` | One ResumeTarget handler | `13371337`, `13371338`. |
| FC6 | CR3 | `69696969 → 336933 → 1337` | One ResumeTarget handler | `13371337`, `13371338`. |
| NFSPB | DR3/DR7 | `336933 → 1337`, optional client-only `336967` | One ResumeTarget handler | `0xffe`, `0xfff`, and five local context/thread selectors. |
| TopSpin | CR3 | FC6 sequence plus conditional `336967` | One ResumeTarget handler | Resume handler and bypass replay. |
| SMT5V | CR3 | FC6 sequence | One ResumeTarget handler | `13371337`, `13371338`, split entirely inside Reflex. |
| Hatsune Miku | CR3 | `69696969 → 693369 → 336933/43 → 336934/44 → 1337` | Two dispatch slots | `693369` has no source branch; slots are `ffe`, `fff`. |
| LADPYIH | CR3 | Hatsune Miku sequence | Two dispatch slots | `693369` has no source branch; slots are `ffe`, `fff`. |

`0x1337` carries a PID in `RDX`; it is not a KUSER protocol command. The
ResumeTarget clients use `XMM5=0x1337133713371337` to replay the real
syscall. The explicit dual-dispatch form instead enters registered result
stubs through `sysretq`; it additionally requires `r10 == 0` for the system
slot and a canonical user `RCX` for both slots.

## Conclusions

CPU brand, KUSER recipe, and CPUID control shape are related but are not the
same classification axis — record them independently rather than deriving
one from another. SMT5V is the counterexample: it has the i9/Ryzen CPU
identity and dispatch-family KUSER lineage, while its actual hypervisor
handshake is ResumeTarget-only.

The CPU feature-probe sequence preceding registration is not a reliable
presentation selector either: SMT5V, TopSpin, and Hatsune Miku all end their
client-local probe with `CPUID(7, 1)` before `0x69696969`, but TopSpin is
modern-CPU-identity and the other two are legacy-lineage; FC6 instead ends
on `CPUID(1, 0)` and is modern. Treat pre-registration CPUID behavior and
transient register state as unreliable classification signals.
