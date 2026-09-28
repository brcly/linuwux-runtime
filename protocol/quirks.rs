//! Per-title reference data for the Reflex protocol differences documented
//! in `docs/protocol/game-quirks.md`. This is *reference* data, not a
//! dispatch table: LinUwUx's actual protocol logic (CPU vendor/AVX
//! detection, KUSER recipe selection, Reflex identity-scope tracking) is
//! already driven by live CPUID/registration probing — see `cpuid.rs` and
//! `reflex/state.rs` — not by branching on which title is running. What
//! this table is for:
//!
//! - a single, compiled (so it can't silently drift from the runtime code
//!   the way a comment can) place to record which combination of the three
//!   independent axes below a supported title exercises, for a contributor
//!   adding a new title to check against;
//! - naming any constant that genuinely is title-specific, like a debug
//!   trace's syscall service number, instead of leaving it as an unexplained
//!   literal in dispatch code.
//!
//! `docs/protocol/game-quirks.md`'s "Conclusions" section is the important
//! caveat: these three axes are related but independent — do not infer one
//! from another, and do not add code that does.

/// The CPU identity family a title's Reflex client presents — see
/// `docs/protocol/game-quirks.md`'s "CPU identity" table. Selected at
/// runtime by `protocol::cpuid::CpuPresentation`, not looked up from this
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuIdentityFamily {
    /// `DenuvOwO` brand string, the default modern presentation.
    Denuvo,
    /// Legacy-CPU brand strings (i9-10900K / Ryzen 9 5900X).
    Modern,
}

/// Which `KUSER_SHARED_DATA` byte-write recipe a title's Reflex client
/// expects — see `docs/protocol/game-quirks.md`'s "KUSER_SHARED_DATA
/// recipes" table and `protocol::kuser::Recipe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KuserRecipeFamily {
    Resume,
    Dispatch,
}

/// How a title's Reflex client proves it is running in the registered
/// target process — see `protocol::reflex::IdentityScope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflexIdentityScope {
    Cr3,
    DebugRegister,
}

/// Whether a title's Reflex client registers one resume-target handler, or
/// the explicit dual-dispatch form — see `protocol::reflex::Routing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchArrangement {
    SingleResumeTarget,
    DualDispatch,
}

/// One row of `docs/protocol/game-quirks.md`'s tables.
#[derive(Debug, Clone, Copy)]
pub struct Title {
    pub name: &'static str,
    pub cpu_identity: CpuIdentityFamily,
    pub kuser_recipe: KuserRecipeFamily,
    pub identity_scope: ReflexIdentityScope,
    pub dispatch: DispatchArrangement,
}

pub const TITLES: &[Title] = &[
    Title {
        name: "ACBFR",
        cpu_identity: CpuIdentityFamily::Denuvo,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::DebugRegister,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "BGE",
        cpu_identity: CpuIdentityFamily::Denuvo,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "FC6",
        cpu_identity: CpuIdentityFamily::Denuvo,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "NFSPB",
        cpu_identity: CpuIdentityFamily::Denuvo,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::DebugRegister,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "TopSpin",
        cpu_identity: CpuIdentityFamily::Denuvo,
        kuser_recipe: KuserRecipeFamily::Resume,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "SMT5V",
        // The counterexample docs/protocol/game-quirks.md's Conclusions
        // section calls out: modern CPU identity and dispatch-family KUSER
        // lineage, but a ResumeTarget-only handshake. Do not "simplify" this
        // row to match the other Modern-identity titles.
        cpu_identity: CpuIdentityFamily::Modern,
        kuser_recipe: KuserRecipeFamily::Dispatch,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::SingleResumeTarget,
    },
    Title {
        name: "Hatsune Miku",
        cpu_identity: CpuIdentityFamily::Modern,
        kuser_recipe: KuserRecipeFamily::Dispatch,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::DualDispatch,
    },
    Title {
        name: "LADPYIH",
        cpu_identity: CpuIdentityFamily::Modern,
        kuser_recipe: KuserRecipeFamily::Dispatch,
        identity_scope: ReflexIdentityScope::Cr3,
        dispatch: DispatchArrangement::DualDispatch,
    },
];

#[cfg(test)]
mod tests {
    use super::TITLES;

    #[test]
    fn every_supported_title_is_present_once() {
        let expected = [
            "ACBFR",
            "BGE",
            "FC6",
            "NFSPB",
            "TopSpin",
            "SMT5V",
            "Hatsune Miku",
            "LADPYIH",
        ];
        assert_eq!(TITLES.len(), expected.len());
        for name in expected {
            assert_eq!(
                TITLES.iter().filter(|title| title.name == name).count(),
                1,
                "{name} should appear exactly once"
            );
        }
    }
}
