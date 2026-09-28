//! The Reflex registration/routing state machine: [`State`] tracks how a
//! title's Reflex client has registered itself (unregistered, resume-target,
//! or dual-dispatch — see `docs/protocol/game-quirks.md`'s "handler
//! arrangement" column) from the control-leaf CPUID sequence in
//! [`State::handle_cpuid`], and answers "does a trapped syscall belong to
//! Reflex, and where does it go" from [`State::route_syscall`].
//!
//! This is pure decision logic: it has no idea how a CPUID trap or syscall
//! trap actually reaches it, or how to patch memory. Everything with a side
//! effect (KUSER patching, logging, yielding, reading/writing the CPU
//! presentation) goes through the [`Host`] trait, which
//! `runtime/src/reflex.rs`'s `RuntimeHost` implements by calling back into
//! the unsafe runtime crate. That indirection is what keeps this file
//! `#![forbid(unsafe_code)]` and unit-testable (see the `tests` module
//! below) despite driving genuinely unsafe machinery.
use core::ffi::CStr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::control::{
    ARM_TARGET_CR3, CLIENT_SESSION_MARKER, DISPATCH_BYPASS_SYSCALL, REGISTER_ATTRIBUTES_HANDLER,
    REGISTER_ATTRIBUTES_SYSCALL_ID, REGISTER_RESUME_HANDLER, REGISTER_SYSTEM_SYSCALL_ID,
    REGISTER_TARGET_PID, SET_TIME, SINGLE_DISPATCH_SELECTORS, USER_RCX_MAX,
};

const TRANSITION_WAIT_LIMIT: u32 = 4096;

fn cpuid_argument(leaf: u32, rcx: u64, rdx: u64) -> u64 {
    if leaf == REGISTER_TARGET_PID {
        rdx
    } else {
        rcx
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Routing {
    Unregistered,
    ResumeTarget,
    DualDispatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityScope {
    Unobserved,
    Process,
    DebugRegisterThread,
}

#[repr(u32)]
enum IdentityState {
    Unobserved,
    Process,
    DebugRegisterThread,
}

impl IdentityState {
    fn load(value: &AtomicU32) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::Unobserved,
            1 => Self::Process,
            2 => Self::DebugRegisterThread,
            _ => unreachable!("invalid Reflex identity scope"),
        }
    }

    fn store(self, value: &AtomicU32) {
        value.store(self as u32, Ordering::Release);
    }

    fn public(self) -> IdentityScope {
        match self {
            Self::Unobserved => IdentityScope::Unobserved,
            Self::Process => IdentityScope::Process,
            Self::DebugRegisterThread => IdentityScope::DebugRegisterThread,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum SyscallConvention {
    ResumeReplay,
    SelectorDispatch,
    DualDispatch,
}

impl SyscallConvention {
    fn load(value: &AtomicU32) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::ResumeReplay,
            1 => Self::SelectorDispatch,
            2 => Self::DualDispatch,
            _ => unreachable!("invalid Reflex syscall convention"),
        }
    }

    fn store(self, value: &AtomicU32) {
        value.store(self as u32, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum RoutingState {
    Unregistered,
    ResumeTarget,
    DualDispatch,
    RegisteringResumeTarget,
    RegisteringDualDispatch,
    PromotingDualDispatch,
}

impl RoutingState {
    fn load(value: &AtomicU32) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::Unregistered,
            1 => Self::ResumeTarget,
            2 => Self::DualDispatch,
            3 => Self::RegisteringResumeTarget,
            4 => Self::RegisteringDualDispatch,
            5 => Self::PromotingDualDispatch,
            _ => unreachable!("invalid Reflex routing state"),
        }
    }

    fn store(self, value: &AtomicU32) {
        value.store(self as u32, Ordering::Release);
    }

    fn stable(self) -> Routing {
        match self {
            Self::ResumeTarget => Routing::ResumeTarget,
            Self::DualDispatch => Routing::DualDispatch,
            Self::Unregistered
            | Self::RegisteringResumeTarget
            | Self::RegisteringDualDispatch
            | Self::PromotingDualDispatch => Routing::Unregistered,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Action {
    Native = 0,
    Consumed = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRoute {
    pub target: u64,
    pub rax_is_resume: bool,
}

pub use crate::kuser::Recipe as KuserRecipe;

pub trait Host {
    fn set_offset(&self, filetime: u64);
    fn select_legacy_presentation(&self);
    fn legacy_presentation_active(&self) -> bool;
    fn selector_kuser_recipe(&self) -> KuserRecipe;
    fn patch_kuser(&self, recipe: KuserRecipe) -> bool;
    fn set_hwprofile_guid(&self) {}
    fn yield_thread(&self) {
        core::hint::spin_loop();
    }
    fn log(&self, message: &'static CStr);
    fn log_hex(&self, prefix: &'static CStr, value: u64);
}

#[derive(Debug)]
struct DispatchRegistrations {
    system_target: AtomicU64,
    system_id: AtomicU32,
    attributes_target: AtomicU64,
    attributes_id: AtomicU32,
}

impl DispatchRegistrations {
    const fn new() -> Self {
        Self {
            system_target: AtomicU64::new(0),
            system_id: AtomicU32::new(u32::MAX),
            attributes_target: AtomicU64::new(0),
            attributes_id: AtomicU32::new(u32::MAX),
        }
    }
}

#[derive(Debug)]
pub struct State {
    routing: AtomicU32,
    identity: AtomicU32,
    target_pid: AtomicU64,
    syscall_convention: AtomicU32,
    resume_target: AtomicU64,
    dispatch: DispatchRegistrations,
}

impl State {
    pub const fn new() -> Self {
        Self {
            routing: AtomicU32::new(RoutingState::Unregistered as u32),
            identity: AtomicU32::new(IdentityState::Unobserved as u32),
            target_pid: AtomicU64::new(0),
            syscall_convention: AtomicU32::new(SyscallConvention::ResumeReplay as u32),
            resume_target: AtomicU64::new(0),
            dispatch: DispatchRegistrations::new(),
        }
    }

    pub fn routing(&self) -> Routing {
        RoutingState::load(&self.routing).stable()
    }

    pub fn identity_scope(&self) -> IdentityScope {
        IdentityState::load(&self.identity).public()
    }

    pub fn target_pid(&self) -> Option<u64> {
        let target = self.target_pid.load(Ordering::Acquire);
        (target != 0).then_some(target)
    }

    pub fn has_registered_target_process(&self) -> bool {
        self.target_pid.load(Ordering::Acquire) != 0 && self.routing() != Routing::Unregistered
    }

    pub fn resume_identity_unarmed(&self) -> bool {
        self.routing() != Routing::DualDispatch && self.resume_target.load(Ordering::Acquire) == 0
    }

    fn kuser_recipe(&self, host: &impl Host) -> KuserRecipe {
        match SyscallConvention::load(&self.syscall_convention) {
            SyscallConvention::ResumeReplay => KuserRecipe::Resume,
            SyscallConvention::SelectorDispatch => host.selector_kuser_recipe(),
            SyscallConvention::DualDispatch => KuserRecipe::Dispatch,
        }
    }

    fn log_control(host: &impl Host, leaf: u32, argument: u64) {
        host.log_hex(c"reflex control leaf=", u64::from(leaf));
        host.log_hex(c"reflex control argument=", argument);
    }

    fn wait_for_transition(&self, host: &impl Host) -> bool {
        for _ in 0..TRANSITION_WAIT_LIMIT {
            if !matches!(
                RoutingState::load(&self.routing),
                RoutingState::RegisteringResumeTarget
                    | RoutingState::RegisteringDualDispatch
                    | RoutingState::PromotingDualDispatch
            ) {
                return true;
            }
            host.yield_thread();
        }
        false
    }

    fn activate_dual_dispatch(&self, host: &impl Host) -> bool {
        loop {
            match RoutingState::load(&self.routing) {
                RoutingState::DualDispatch => return true,
                RoutingState::Unregistered => match self.routing.compare_exchange_weak(
                    RoutingState::Unregistered as u32,
                    RoutingState::RegisteringDualDispatch as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                RoutingState::ResumeTarget => match self.routing.compare_exchange_weak(
                    RoutingState::ResumeTarget as u32,
                    RoutingState::PromotingDualDispatch as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                RoutingState::RegisteringResumeTarget
                | RoutingState::RegisteringDualDispatch
                | RoutingState::PromotingDualDispatch => {
                    if !self.wait_for_transition(host) {
                        return false;
                    }
                }
            }
        }
        let target = self.resume_target.load(Ordering::Acquire);
        if self.dispatch.system_target.load(Ordering::Acquire) == 0 {
            self.dispatch.system_target.store(target, Ordering::Release);
        }
        SyscallConvention::DualDispatch.store(&self.syscall_convention);
        RoutingState::DualDispatch.store(&self.routing);
        host.select_legacy_presentation();
        host.log(c"reflex CPU presentation=legacy dual-dispatch");
        host.log(c"reflex routing=dual-dispatch active");
        true
    }

    fn register_resume_target(&self, target: u64, host: &impl Host) -> bool {
        loop {
            match RoutingState::load(&self.routing) {
                RoutingState::DualDispatch => {
                    self.dispatch.system_target.store(target, Ordering::Release);
                    return true;
                }
                RoutingState::ResumeTarget => {
                    if !host.patch_kuser(self.kuser_recipe(host)) {
                        host.log(c"reflex KUSER patch failed");
                        return false;
                    }
                    self.resume_target.store(target, Ordering::Release);
                    host.log(c"reflex routing=resume-target registered");
                    host.log_hex(c"reflex resume handler=", target);
                    return true;
                }
                RoutingState::Unregistered => match self.routing.compare_exchange_weak(
                    RoutingState::Unregistered as u32,
                    RoutingState::RegisteringResumeTarget as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                RoutingState::RegisteringResumeTarget
                | RoutingState::RegisteringDualDispatch
                | RoutingState::PromotingDualDispatch => {
                    if !self.wait_for_transition(host) {
                        return false;
                    }
                }
            }
        }
        self.resume_target.store(target, Ordering::Release);
        if host.legacy_presentation_active() {
            SyscallConvention::SelectorDispatch.store(&self.syscall_convention);
        }
        RoutingState::ResumeTarget.store(&self.routing);
        host.log(c"reflex routing=resume-target registered");
        host.log_hex(c"reflex resume handler=", target);
        true
    }

    /// Handle a Reflex control CPUID with its incoming RCX and RDX values.
    /// The client protocol uses RCX for selector payloads, but `0x1337`
    /// registers the process ID from RDX.
    pub fn handle_cpuid(&self, leaf: u32, rcx: u64, rdx: u64, host: &impl Host) -> Action {
        let argument = cpuid_argument(leaf, rcx, rdx);
        match leaf {
            ARM_TARGET_CR3 => {
                Self::log_control(host, leaf, argument);
                IdentityState::Process.store(&self.identity);
                if self.routing() == Routing::ResumeTarget {
                    return Action::Native;
                }
                host.log(c"reflex CR3 identity armed");
            }
            CLIENT_SESSION_MARKER => {
                Self::log_control(host, leaf, argument);
                return Action::Native;
            }
            REGISTER_RESUME_HANDLER => {
                Self::log_control(host, leaf, argument);
                if self
                    .identity
                    .compare_exchange(
                        IdentityState::Unobserved as u32,
                        IdentityState::DebugRegisterThread as u32,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    host.log(c"reflex debug-register thread identity inferred");
                }
                host.set_hwprofile_guid();
                if self.routing() == Routing::Unregistered {
                    host.log(c"reflex routing=resume-target inferred");
                }
                if !self.register_resume_target(argument, host) {
                    return Action::Native;
                }
            }
            SET_TIME => {
                Self::log_control(host, leaf, argument);
                host.set_offset(argument << 32);
            }
            REGISTER_TARGET_PID => {
                if self.routing() == Routing::Unregistered {
                    return Action::Native;
                }
                self.target_pid.store(argument, Ordering::Release);
                host.log_hex(c"reflex target pid=", argument);
                let recipe = self.kuser_recipe(host);
                host.log(match recipe {
                    KuserRecipe::Dispatch => c"reflex KUSER recipe=dispatch",
                    KuserRecipe::Selector => c"reflex KUSER recipe=selector",
                    KuserRecipe::Resume => c"reflex KUSER recipe=resume",
                });
                if !host.patch_kuser(recipe) {
                    host.log(c"reflex KUSER patch failed");
                    return Action::Native;
                }
                host.log(c"reflex KUSER patch ready");
            }
            REGISTER_SYSTEM_SYSCALL_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_dual_dispatch(host) {
                    return Action::Native;
                }
                self.dispatch
                    .system_id
                    .store(argument as u32, Ordering::Release);
            }
            REGISTER_ATTRIBUTES_HANDLER => {
                Self::log_control(host, leaf, argument);
                if !self.activate_dual_dispatch(host) {
                    return Action::Native;
                }
                self.dispatch
                    .attributes_target
                    .store(argument, Ordering::Release);
            }
            REGISTER_ATTRIBUTES_SYSCALL_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_dual_dispatch(host) {
                    return Action::Native;
                }
                self.dispatch
                    .attributes_id
                    .store(argument as u32, Ordering::Release);
            }
            _ => return Action::Native,
        }
        Action::Consumed
    }

    pub fn route_syscall(&self, number: u64, r10: i64, rcx: u64) -> Option<SyscallRoute> {
        if matches!(
            RoutingState::load(&self.routing),
            RoutingState::Unregistered | RoutingState::RegisteringDualDispatch
        ) {
            return None;
        }
        let (selected, rax_is_resume) = match SyscallConvention::load(&self.syscall_convention) {
            SyscallConvention::ResumeReplay => (self.resume_target.load(Ordering::Acquire), true),
            SyscallConvention::SelectorDispatch => {
                if !SINGLE_DISPATCH_SELECTORS.contains(&number) || rcx > USER_RCX_MAX {
                    return None;
                }
                (self.resume_target.load(Ordering::Acquire), false)
            }
            SyscallConvention::DualDispatch => {
                if number == DISPATCH_BYPASS_SYSCALL {
                    return None;
                }
                let selected = if number as u32 == self.dispatch.system_id.load(Ordering::Acquire) {
                    if r10 != 0 || rcx > USER_RCX_MAX {
                        return None;
                    }
                    self.dispatch.system_target.load(Ordering::Acquire)
                } else if number as u32 == self.dispatch.attributes_id.load(Ordering::Acquire)
                    && rcx <= USER_RCX_MAX
                {
                    self.dispatch.attributes_target.load(Ordering::Acquire)
                } else {
                    return None;
                };
                (selected, false)
            }
        };
        (selected != 0).then_some(SyscallRoute {
            target: selected,
            rax_is_resume,
        })
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use super::{REGISTER_RESUME_HANDLER, REGISTER_TARGET_PID, SET_TIME, cpuid_argument};

    #[test]
    fn target_pid_uses_rdx_while_other_control_payloads_use_rcx() {
        assert_eq!(cpuid_argument(REGISTER_TARGET_PID, 0xdead, 0xbeef), 0xbeef);
        assert_eq!(
            cpuid_argument(REGISTER_RESUME_HANDLER, 0xdead, 0xbeef),
            0xdead
        );
        assert_eq!(cpuid_argument(SET_TIME, 0xdead, 0xbeef), 0xdead);
    }

    #[test]
    fn syscall_identity_matches_registered_windows_process_id() {
        let state = super::State::new();
        assert!(!state.has_registered_target_process());
        state.target_pid.store(0x150, Ordering::Release);
        assert!(!state.has_registered_target_process());
        state
            .routing
            .store(super::RoutingState::ResumeTarget as u32, Ordering::Release);
        assert!(state.has_registered_target_process());
    }
}
