use core::ffi::CStr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::control::{
    ARM_TARGET_CR3, CLIENT_SESSION_MARKER, DISPATCH_BYPASS_SYSCALL, REGISTER_ATTRIBUTES_HANDLER,
    REGISTER_ATTRIBUTES_SYSCALL_ID, REGISTER_RESUME_HANDLER, REGISTER_SYSTEM_SYSCALL_ID,
    REGISTER_TARGET_PID, SET_TIME, SINGLE_DISPATCH_SELECTORS, USER_RCX_MAX,
};

const TRANSITION_WAIT_LIMIT: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Routing {
    Unregistered,
    ResumeTarget,
    DualDispatch,
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
    syscall_convention: AtomicU32,
    resume_target: AtomicU64,
    dispatch: DispatchRegistrations,
}

impl State {
    pub const fn new() -> Self {
        Self {
            routing: AtomicU32::new(RoutingState::Unregistered as u32),
            syscall_convention: AtomicU32::new(SyscallConvention::ResumeReplay as u32),
            resume_target: AtomicU64::new(0),
            dispatch: DispatchRegistrations::new(),
        }
    }

    pub fn routing(&self) -> Routing {
        RoutingState::load(&self.routing).stable()
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

    pub fn handle_cpuid(&self, leaf: u32, argument: u64, host: &impl Host) -> Action {
        match leaf {
            ARM_TARGET_CR3 => {
                Self::log_control(host, leaf, argument);
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
