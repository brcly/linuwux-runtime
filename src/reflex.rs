use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub const ARM_TARGET: u32 = 0x0033_6933;
pub const SET_TIME: u32 = 0x0033_6967;
pub const LEGACY_QUERY_SYSTEM_ID: u32 = 0x0033_6943;
pub const LEGACY_QUERY_ATTRIBUTES_TARGET: u32 = 0x0033_6934;
pub const LEGACY_QUERY_ATTRIBUTES_ID: u32 = 0x0033_6944;
pub const LEGACY_INIT: u32 = 0x6969_6969;
pub const KUSER_PROBE: u32 = 0x1337;
pub const SYSCALL_BYPASS_MAGIC: u64 = 0x1337_1337_1337_1337;
const LEGACY_SINGLE_DISPATCH: [u64; 2] = [0x1337_1337, 0x1337_1338];
const LEGACY_USER_RCX_MAX: u64 = 0x7fff_ffff_ffff;
const LEGACY_BYPASS_SYSCALL: u64 = 0x7fff_ffff_ffff;
const PROTOCOL_UNREGISTERED: u32 = 0;
const PROTOCOL_MODERN: u32 = 1;
const PROTOCOL_LEGACY: u32 = 2;
const PROTOCOL_INITIALIZING_MODERN: u32 = 3;
const PROTOCOL_INITIALIZING_LEGACY: u32 = 4;
const PROTOCOL_TRANSITIONING_TO_LEGACY: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Unregistered,
    Modern,
    Legacy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Action {
    Native = 0,
    Consumed = 1,
}

pub use crate::kuser::Profile as KuserProfile;

pub trait Host {
    fn activate_legacy_cpuid(&self);
    fn set_offset(&self, filetime: u64);
    fn patch_kuser(&self, profile: KuserProfile) -> bool;
    fn set_hwprofile_guid(&self) {}
    fn log(&self, message: &'static CStr);
    fn log_hex(&self, prefix: &'static CStr, value: u64);
}

#[derive(Debug)]
pub struct State {
    protocol: AtomicU32,
    modern_target: AtomicU64,
    legacy_query_system_target: AtomicU64,
    legacy_query_system_id: AtomicU32,
    legacy_query_attributes_target: AtomicU64,
    legacy_query_attributes_id: AtomicU32,
    active_legacy_target: AtomicU64,
    legacy_dual: AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            protocol: AtomicU32::new(PROTOCOL_UNREGISTERED),
            modern_target: AtomicU64::new(0),
            legacy_query_system_target: AtomicU64::new(0),
            legacy_query_system_id: AtomicU32::new(u32::MAX),
            legacy_query_attributes_target: AtomicU64::new(0),
            legacy_query_attributes_id: AtomicU32::new(u32::MAX),
            active_legacy_target: AtomicU64::new(0),
            legacy_dual: AtomicBool::new(false),
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self.protocol.load(Ordering::Acquire) {
            PROTOCOL_MODERN => Protocol::Modern,
            PROTOCOL_LEGACY => Protocol::Legacy,
            _ => Protocol::Unregistered,
        }
    }

    pub fn modern_identity_unarmed(&self) -> bool {
        self.protocol() != Protocol::Legacy && self.modern_target.load(Ordering::Acquire) == 0
    }

    fn log_control(host: &impl Host, leaf: u32, argument: u64) {
        host.log_hex(c"reflex control leaf=", u64::from(leaf));
        host.log_hex(c"reflex control argument=", argument);
    }

    fn activate_legacy(&self, host: &impl Host) -> bool {
        loop {
            match self.protocol.load(Ordering::Acquire) {
                PROTOCOL_LEGACY => return true,
                PROTOCOL_UNREGISTERED => match self.protocol.compare_exchange_weak(
                    PROTOCOL_UNREGISTERED,
                    PROTOCOL_INITIALIZING_LEGACY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                PROTOCOL_MODERN => match self.protocol.compare_exchange_weak(
                    PROTOCOL_MODERN,
                    PROTOCOL_TRANSITIONING_TO_LEGACY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                PROTOCOL_INITIALIZING_MODERN
                | PROTOCOL_INITIALIZING_LEGACY
                | PROTOCOL_TRANSITIONING_TO_LEGACY => {
                    return false;
                }
                _ => unreachable!("invalid Reflex protocol state"),
            }
        }
        let target = self.modern_target.load(Ordering::Acquire);
        if self.legacy_query_system_target.load(Ordering::Acquire) == 0 {
            self.legacy_query_system_target
                .store(target, Ordering::Release);
        }
        host.activate_legacy_cpuid();
        self.protocol.store(PROTOCOL_LEGACY, Ordering::Release);
        host.log(c"reflex protocol=legacy active");
        true
    }

    fn legacy_profile(&self) -> KuserProfile {
        if self.legacy_dual.load(Ordering::Acquire) {
            KuserProfile::LegacyDual
        } else {
            KuserProfile::LegacySingle
        }
    }

    fn register_modern(&self, target: u64, host: &impl Host) -> bool {
        loop {
            match self.protocol.load(Ordering::Acquire) {
                PROTOCOL_LEGACY => {
                    self.legacy_query_system_target
                        .store(target, Ordering::Release);
                    return true;
                }
                PROTOCOL_MODERN => {
                    if !host.patch_kuser(KuserProfile::Modern) {
                        host.log(c"reflex KUSER patch failed");
                        return false;
                    }
                    self.modern_target.store(target, Ordering::Release);
                    self.active_legacy_target.store(target, Ordering::Release);
                    host.log(c"reflex protocol=modern registered");
                    host.log_hex(c"reflex TargetSysHandler=", target);
                    return true;
                }
                PROTOCOL_UNREGISTERED => match self.protocol.compare_exchange_weak(
                    PROTOCOL_UNREGISTERED,
                    PROTOCOL_INITIALIZING_MODERN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(_) => continue,
                },
                PROTOCOL_INITIALIZING_MODERN
                | PROTOCOL_INITIALIZING_LEGACY
                | PROTOCOL_TRANSITIONING_TO_LEGACY => {
                    return false;
                }
                _ => unreachable!("invalid Reflex protocol state"),
            }
        }
        if !host.patch_kuser(KuserProfile::Modern) {
            self.protocol
                .store(PROTOCOL_UNREGISTERED, Ordering::Release);
            host.log(c"reflex KUSER patch failed");
            return false;
        }
        self.modern_target.store(target, Ordering::Release);
        self.active_legacy_target.store(target, Ordering::Release);
        self.protocol.store(PROTOCOL_MODERN, Ordering::Release);
        host.log(c"reflex KUSER patch ready");
        host.log(c"reflex protocol=modern registered");
        host.log_hex(c"reflex TargetSysHandler=", target);
        true
    }

    pub fn hint_denuvowo(&self, host: &impl Host) {
        if self
            .protocol
            .compare_exchange(
                PROTOCOL_UNREGISTERED,
                PROTOCOL_MODERN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            host.log(c"reflex protocol=DenuvOwO enabled");
        }
    }

    pub fn handle_cpuid(&self, leaf: u32, argument: u64, host: &impl Host) -> Action {
        if leaf == KUSER_PROBE && self.protocol() != Protocol::Unregistered {
            Self::log_control(host, leaf, argument);
            host.log(c"reflex KUSER probe observed");
        }
        match leaf {
            LEGACY_INIT => {
                Self::log_control(host, leaf, argument);
                if self.protocol() == Protocol::Modern {
                    return Action::Native;
                }
                if !self.activate_legacy(host) {
                    return Action::Native;
                }
            }
            ARM_TARGET => {
                Self::log_control(host, leaf, argument);
                host.set_hwprofile_guid();
                if !self.register_modern(argument, host) {
                    return Action::Native;
                }
            }
            SET_TIME => {
                Self::log_control(host, leaf, argument);
                host.set_offset(argument << 32);
            }
            KUSER_PROBE => {
                if self.protocol() != Protocol::Legacy {
                    return Action::Native;
                }
                let profile = self.legacy_profile();
                if profile == KuserProfile::LegacySingle
                    && self.legacy_query_system_target.load(Ordering::Acquire) == 0
                {
                    return Action::Consumed;
                }
                host.log(match profile {
                    KuserProfile::LegacySingle => c"reflex KUSER recipe=legacy-single",
                    KuserProfile::LegacyDual => c"reflex KUSER recipe=legacy-dual",
                    KuserProfile::Modern => c"reflex KUSER recipe=modern",
                });
                if !host.patch_kuser(profile) {
                    host.log(c"reflex KUSER patch failed");
                    return Action::Native;
                }
                host.log(c"reflex KUSER patch ready");
            }
            LEGACY_QUERY_SYSTEM_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_legacy(host) {
                    return Action::Native;
                }
                self.legacy_query_system_id
                    .store(argument as u32, Ordering::Release);
                self.legacy_dual.store(true, Ordering::Release);
            }
            LEGACY_QUERY_ATTRIBUTES_TARGET => {
                Self::log_control(host, leaf, argument);
                if !self.activate_legacy(host) {
                    return Action::Native;
                }
                self.legacy_query_attributes_target
                    .store(argument, Ordering::Release);
                self.legacy_dual.store(true, Ordering::Release);
            }
            LEGACY_QUERY_ATTRIBUTES_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_legacy(host) {
                    return Action::Native;
                }
                self.legacy_query_attributes_id
                    .store(argument as u32, Ordering::Release);
                self.legacy_dual.store(true, Ordering::Release);
            }
            _ => return Action::Native,
        }
        Action::Consumed
    }

    pub fn route_syscall(&self, number: u64, r10: i64, rcx: u64) -> Option<u64> {
        let protocol = self.protocol();
        if protocol == Protocol::Unregistered {
            return None;
        }
        let mut selected = self.modern_target.load(Ordering::Acquire);
        if selected == 0
            && self.active_legacy_target.load(Ordering::Acquire) == 0
            && self.legacy_query_system_target.load(Ordering::Acquire) == 0
        {
            return None;
        }
        if protocol == Protocol::Legacy {
            if number == LEGACY_BYPASS_SYSCALL {
                return None;
            }
            if self.legacy_dual.load(Ordering::Acquire) {
                if number as u32 == self.legacy_query_system_id.load(Ordering::Acquire) {
                    if r10 != 0 || rcx > LEGACY_USER_RCX_MAX {
                        return None;
                    }
                    selected = self.legacy_query_system_target.load(Ordering::Acquire);
                } else if number as u32 == self.legacy_query_attributes_id.load(Ordering::Acquire)
                    && rcx <= LEGACY_USER_RCX_MAX
                {
                    selected = self.legacy_query_attributes_target.load(Ordering::Acquire);
                } else {
                    return None;
                }
            } else {
                if !LEGACY_SINGLE_DISPATCH.contains(&number) || rcx > LEGACY_USER_RCX_MAX {
                    return None;
                }
                selected = self.legacy_query_system_target.load(Ordering::Acquire);
            }
            if selected == 0 {
                return None;
            }
            self.active_legacy_target.store(selected, Ordering::Release);
        } else if selected == 0 {
            selected = self.active_legacy_target.load(Ordering::Acquire);
        }
        if selected == 0 { None } else { Some(selected) }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
