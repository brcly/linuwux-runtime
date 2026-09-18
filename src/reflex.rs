use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub const ARM_TARGET: u32 = 0x0033_6933;
pub const SET_TIME: u32 = 0x0033_6967;
pub const DISPATCH_SYSTEM_ID: u32 = 0x0033_6943;
pub const DISPATCH_ATTRIBUTES_TARGET: u32 = 0x0033_6934;
pub const DISPATCH_ATTRIBUTES_ID: u32 = 0x0033_6944;
pub const DISPATCH_INIT: u32 = 0x6969_6969;
pub const DISPATCH_SESSION: u32 = 0x0069_3369;
pub const KUSER_PROBE: u32 = 0x1337;
pub const SYSCALL_BYPASS_MAGIC: u64 = 0x1337_1337_1337_1337;
const SINGLE_DISPATCH_SELECTORS: [u64; 2] = [0x1337_1337, 0x1337_1338];
const DISPATCH_USER_RCX_MAX: u64 = 0x7fff_ffff_ffff;
const DISPATCH_BYPASS_SYSCALL: u64 = 0x7fff_ffff_ffff;
const PROTOCOL_WAIT_LIMIT: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Unregistered,
    ResumeTarget,
    Dispatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum ProtocolState {
    Unregistered,
    ResumeTarget,
    Dispatch,
    InitializingResumeTarget,
    InitializingDispatch,
    TransitioningToDispatch,
}

impl ProtocolState {
    fn load(value: &AtomicU32) -> Self {
        match value.load(Ordering::Acquire) {
            0 => Self::Unregistered,
            1 => Self::ResumeTarget,
            2 => Self::Dispatch,
            3 => Self::InitializingResumeTarget,
            4 => Self::InitializingDispatch,
            5 => Self::TransitioningToDispatch,
            _ => unreachable!("invalid Reflex protocol state"),
        }
    }

    fn store(self, value: &AtomicU32) {
        value.store(self as u32, Ordering::Release);
    }

    fn stable(self) -> Protocol {
        match self {
            Self::ResumeTarget => Protocol::ResumeTarget,
            Self::Dispatch => Protocol::Dispatch,
            Self::Unregistered
            | Self::InitializingResumeTarget
            | Self::InitializingDispatch
            | Self::TransitioningToDispatch => Protocol::Unregistered,
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

pub use crate::kuser::Profile as KuserProfile;

pub trait Host {
    fn activate_dispatch_cpuid(&self);
    fn set_offset(&self, filetime: u64);
    fn patch_kuser(&self, profile: KuserProfile) -> bool;
    fn set_hwprofile_guid(&self) {}
    fn yield_thread(&self) {
        core::hint::spin_loop();
    }
    fn log(&self, message: &'static CStr);
    fn log_hex(&self, prefix: &'static CStr, value: u64);
}

#[derive(Debug)]
struct DispatchState {
    query_system_target: AtomicU64,
    query_system_id: AtomicU32,
    query_attributes_target: AtomicU64,
    query_attributes_id: AtomicU32,
    dual: AtomicBool,
}

impl DispatchState {
    const fn new() -> Self {
        Self {
            query_system_target: AtomicU64::new(0),
            query_system_id: AtomicU32::new(u32::MAX),
            query_attributes_target: AtomicU64::new(0),
            query_attributes_id: AtomicU32::new(u32::MAX),
            dual: AtomicBool::new(false),
        }
    }
}

#[derive(Debug)]
pub struct State {
    protocol: AtomicU32,
    resume_target: AtomicU64,
    dispatch: DispatchState,
}

impl State {
    pub const fn new() -> Self {
        Self {
            protocol: AtomicU32::new(ProtocolState::Unregistered as u32),
            resume_target: AtomicU64::new(0),
            dispatch: DispatchState::new(),
        }
    }

    pub fn protocol(&self) -> Protocol {
        ProtocolState::load(&self.protocol).stable()
    }

    pub fn resume_identity_unarmed(&self) -> bool {
        self.protocol() != Protocol::Dispatch && self.resume_target.load(Ordering::Acquire) == 0
    }

    fn log_control(host: &impl Host, leaf: u32, argument: u64) {
        host.log_hex(c"reflex control leaf=", u64::from(leaf));
        host.log_hex(c"reflex control argument=", argument);
    }

    fn wait_for_transition(&self, host: &impl Host) -> bool {
        for _ in 0..PROTOCOL_WAIT_LIMIT {
            if !matches!(
                ProtocolState::load(&self.protocol),
                ProtocolState::InitializingResumeTarget
                    | ProtocolState::InitializingDispatch
                    | ProtocolState::TransitioningToDispatch
            ) {
                return true;
            }
            host.yield_thread();
        }
        false
    }

    fn activate_dispatch(&self, host: &impl Host) -> bool {
        loop {
            match ProtocolState::load(&self.protocol) {
                ProtocolState::Dispatch => return true,
                ProtocolState::Unregistered => match self.protocol.compare_exchange_weak(
                    ProtocolState::Unregistered as u32,
                    ProtocolState::InitializingDispatch as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                ProtocolState::ResumeTarget => match self.protocol.compare_exchange_weak(
                    ProtocolState::ResumeTarget as u32,
                    ProtocolState::TransitioningToDispatch as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                ProtocolState::InitializingResumeTarget
                | ProtocolState::InitializingDispatch
                | ProtocolState::TransitioningToDispatch => {
                    if !self.wait_for_transition(host) {
                        return false;
                    }
                    continue;
                }
            }
        }
        let target = self.resume_target.load(Ordering::Acquire);
        if self.dispatch.query_system_target.load(Ordering::Acquire) == 0 {
            self.dispatch
                .query_system_target
                .store(target, Ordering::Release);
        }
        host.activate_dispatch_cpuid();
        ProtocolState::Dispatch.store(&self.protocol);
        host.log(c"reflex protocol=dispatch active");
        true
    }

    fn dispatch_profile(&self) -> KuserProfile {
        if self.dispatch.dual.load(Ordering::Acquire) {
            KuserProfile::DualDispatch
        } else {
            KuserProfile::SingleDispatch
        }
    }

    // Deliberately does not call host.patch_kuser() here: the protocol may
    // still be unconfirmed (a title can upgrade Unregistered/ResumeTarget to
    // Dispatch via a later DISPATCH_SYSTEM_ID/DISPATCH_ATTRIBUTES_* leaf).
    // ResumeTarget's KUSER bytes zero-fill a range DualDispatch/SingleDispatch
    // never restore, so patching here and again later leaves a permanently
    // corrupted hybrid page for genuine dispatch titles. The KUSER_PROBE
    // handler is the single point that applies whichever profile is final.
    fn register_resume_target(&self, target: u64, host: &impl Host) -> bool {
        loop {
            match ProtocolState::load(&self.protocol) {
                ProtocolState::Dispatch => {
                    self.dispatch
                        .query_system_target
                        .store(target, Ordering::Release);
                    return true;
                }
                ProtocolState::ResumeTarget => {
                    if !host.patch_kuser(KuserProfile::ResumeTarget) {
                        host.log(c"reflex KUSER patch failed");
                        return false;
                    }
                    self.resume_target.store(target, Ordering::Release);
                    host.log(c"reflex protocol=resume-target registered");
                    host.log_hex(c"reflex TargetSysHandler=", target);
                    return true;
                }
                ProtocolState::Unregistered => match self.protocol.compare_exchange_weak(
                    ProtocolState::Unregistered as u32,
                    ProtocolState::InitializingResumeTarget as u32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                ProtocolState::InitializingResumeTarget
                | ProtocolState::InitializingDispatch
                | ProtocolState::TransitioningToDispatch => {
                    if !self.wait_for_transition(host) {
                        return false;
                    }
                    continue;
                }
            }
        }
        self.resume_target.store(target, Ordering::Release);
        ProtocolState::ResumeTarget.store(&self.protocol);
        host.log(c"reflex protocol=resume-target registered");
        host.log_hex(c"reflex TargetSysHandler=", target);
        true
    }

    pub fn handle_cpuid(&self, leaf: u32, argument: u64, host: &impl Host) -> Action {
        if leaf == KUSER_PROBE && self.protocol() != Protocol::Unregistered {
            Self::log_control(host, leaf, argument);
            host.log(c"reflex KUSER probe observed");
        }
        match leaf {
            DISPATCH_INIT => {
                Self::log_control(host, leaf, argument);
                if self.protocol() == Protocol::ResumeTarget {
                    return Action::Native;
                }
                host.log(c"reflex dispatch-init observed");
            }
            DISPATCH_SESSION => {
                Self::log_control(host, leaf, argument);
            }
            ARM_TARGET => {
                Self::log_control(host, leaf, argument);
                host.set_hwprofile_guid();
                if self.protocol() == Protocol::Unregistered {
                    host.log(c"reflex protocol=resume-target inferred");
                }
                if !self.register_resume_target(argument, host) {
                    return Action::Native;
                }
            }
            SET_TIME => {
                Self::log_control(host, leaf, argument);
                host.set_offset(argument << 32);
            }
            KUSER_PROBE => {
                let profile = match self.protocol() {
                    Protocol::ResumeTarget => KuserProfile::ResumeTarget,
                    Protocol::Dispatch => self.dispatch_profile(),
                    Protocol::Unregistered => return Action::Native,
                };
                if profile == KuserProfile::SingleDispatch
                    && self.dispatch.query_system_target.load(Ordering::Acquire) == 0
                {
                    return Action::Consumed;
                }
                host.log(match profile {
                    KuserProfile::SingleDispatch => c"reflex KUSER recipe=single-dispatch",
                    KuserProfile::DualDispatch => c"reflex KUSER recipe=dual-dispatch",
                    KuserProfile::ResumeTarget => c"reflex KUSER recipe=resume-target",
                });
                if !host.patch_kuser(profile) {
                    host.log(c"reflex KUSER patch failed");
                    return Action::Native;
                }
                host.log(c"reflex KUSER patch ready");
            }
            DISPATCH_SYSTEM_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_dispatch(host) {
                    return Action::Native;
                }
                self.dispatch
                    .query_system_id
                    .store(argument as u32, Ordering::Release);
                self.dispatch.dual.store(true, Ordering::Release);
            }
            DISPATCH_ATTRIBUTES_TARGET => {
                Self::log_control(host, leaf, argument);
                if !self.activate_dispatch(host) {
                    return Action::Native;
                }
                self.dispatch
                    .query_attributes_target
                    .store(argument, Ordering::Release);
                self.dispatch.dual.store(true, Ordering::Release);
            }
            DISPATCH_ATTRIBUTES_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_dispatch(host) {
                    return Action::Native;
                }
                self.dispatch
                    .query_attributes_id
                    .store(argument as u32, Ordering::Release);
                self.dispatch.dual.store(true, Ordering::Release);
            }
            _ => return Action::Native,
        }
        Action::Consumed
    }

    pub fn route_syscall(&self, number: u64, r10: i64, rcx: u64) -> Option<SyscallRoute> {
        let state = ProtocolState::load(&self.protocol);
        let protocol = match state {
            ProtocolState::ResumeTarget => Protocol::ResumeTarget,
            ProtocolState::Dispatch => Protocol::Dispatch,
            ProtocolState::InitializingResumeTarget
                if self.resume_target.load(Ordering::Acquire) != 0 =>
            {
                Protocol::ResumeTarget
            }
            _ => Protocol::Unregistered,
        };
        if protocol == Protocol::Unregistered {
            return None;
        }
        let mut selected = self.resume_target.load(Ordering::Acquire);
        if protocol == Protocol::Dispatch {
            if number == DISPATCH_BYPASS_SYSCALL {
                return None;
            }
            if self.dispatch.dual.load(Ordering::Acquire) {
                if number as u32 == self.dispatch.query_system_id.load(Ordering::Acquire) {
                    if r10 != 0 || rcx > DISPATCH_USER_RCX_MAX {
                        return None;
                    }
                    selected = self.dispatch.query_system_target.load(Ordering::Acquire);
                } else if number as u32 == self.dispatch.query_attributes_id.load(Ordering::Acquire)
                    && rcx <= DISPATCH_USER_RCX_MAX
                {
                    selected = self
                        .dispatch
                        .query_attributes_target
                        .load(Ordering::Acquire);
                } else {
                    return None;
                }
            } else {
                if !SINGLE_DISPATCH_SELECTORS.contains(&number) || rcx > DISPATCH_USER_RCX_MAX {
                    return None;
                }
                selected = self.dispatch.query_system_target.load(Ordering::Acquire);
            }
            if selected == 0 {
                return None;
            }
        }
        if selected == 0 {
            None
        } else {
            Some(SyscallRoute {
                target: selected,
                rax_is_resume: protocol == Protocol::ResumeTarget,
            })
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
