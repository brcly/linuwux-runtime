use core::ffi::CStr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const REGISTER_TARGET: u32 = 0x0033_6933;
pub const SET_TIME: u32 = 0x0033_6967;
pub const LEGACY_QUERY_SYSTEM_ID: u32 = 0x0033_6943;
pub const LEGACY_QUERY_ATTRIBUTES_TARGET: u32 = 0x0033_6934;
pub const LEGACY_QUERY_ATTRIBUTES_ID: u32 = 0x0033_6944;
pub const LEGACY_INIT: u32 = 0x6969_6969;
pub const KUSER_PROBE: u32 = 0x1337;
pub const SYSCALL_BYPASS_MAGIC: u64 = 0x1337_1337_1337_1337;
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
    fn log(&self, message: &'static CStr);
    fn log_hex(&self, prefix: &'static CStr, value: u64);
}

#[derive(Debug)]
pub struct State {
    protocol: AtomicU32,
    modern_target: AtomicU64,
    legacy_query_system_target: AtomicU64,
    legacy_query_system_id: AtomicU64,
    legacy_query_attributes_target: AtomicU64,
    legacy_query_attributes_id: AtomicU64,
    active_legacy_target: AtomicU64,
}

impl State {
    pub const fn new() -> Self {
        Self {
            protocol: AtomicU32::new(PROTOCOL_UNREGISTERED),
            modern_target: AtomicU64::new(0),
            legacy_query_system_target: AtomicU64::new(0),
            legacy_query_system_id: AtomicU64::new(0),
            legacy_query_attributes_target: AtomicU64::new(0),
            legacy_query_attributes_id: AtomicU64::new(0),
            active_legacy_target: AtomicU64::new(0),
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self.protocol.load(Ordering::Acquire) {
            PROTOCOL_MODERN => Protocol::Modern,
            PROTOCOL_LEGACY => Protocol::Legacy,
            _ => Protocol::Unregistered,
        }
    }

    fn log_control(host: &impl Host, leaf: u32, argument: u64) {
        host.log_hex(c"reflex control leaf=", u64::from(leaf));
        host.log_hex(c"reflex control argument=", argument);
    }

    fn activate_legacy(&self, host: &impl Host) -> bool {
        let rollback = loop {
            match self.protocol.load(Ordering::Acquire) {
                PROTOCOL_LEGACY => return true,
                PROTOCOL_UNREGISTERED => match self.protocol.compare_exchange_weak(
                    PROTOCOL_UNREGISTERED,
                    PROTOCOL_INITIALIZING_LEGACY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break PROTOCOL_UNREGISTERED,
                    Err(_) => continue,
                },
                PROTOCOL_MODERN => match self.protocol.compare_exchange_weak(
                    PROTOCOL_MODERN,
                    PROTOCOL_TRANSITIONING_TO_LEGACY,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break PROTOCOL_MODERN,
                    Err(_) => continue,
                },
                PROTOCOL_INITIALIZING_MODERN
                | PROTOCOL_INITIALIZING_LEGACY
                | PROTOCOL_TRANSITIONING_TO_LEGACY => {
                    return false;
                }
                _ => unreachable!("invalid Reflex protocol state"),
            }
        };
        if !host.patch_kuser(KuserProfile::Legacy) {
            self.protocol.store(rollback, Ordering::Release);
            host.log(c"reflex KUSER patch failed");
            return false;
        }
        let target = self.modern_target.load(Ordering::Acquire);
        if self.legacy_query_system_target.load(Ordering::Acquire) == 0 {
            self.legacy_query_system_target
                .store(target, Ordering::Release);
        }
        host.activate_legacy_cpuid();
        self.protocol.store(PROTOCOL_LEGACY, Ordering::Release);
        host.log(c"reflex KUSER patch ready");
        host.log(c"reflex protocol=legacy active");
        true
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

    pub fn handle_cpuid(&self, leaf: u32, argument: u64, host: &impl Host) -> Action {
        if leaf == KUSER_PROBE && self.protocol() != Protocol::Unregistered {
            Self::log_control(host, leaf, argument);
            host.log(c"reflex KUSER probe observed");
        }
        match leaf {
            LEGACY_INIT => {
                Self::log_control(host, leaf, argument);
                if self.protocol() != Protocol::Modern && !self.activate_legacy(host) {
                    return Action::Native;
                }
            }
            REGISTER_TARGET => {
                Self::log_control(host, leaf, argument);
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
                if !host.patch_kuser(KuserProfile::Legacy) {
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
                    .store(argument, Ordering::Release);
            }
            LEGACY_QUERY_ATTRIBUTES_TARGET => {
                Self::log_control(host, leaf, argument);
                if !self.activate_legacy(host) {
                    return Action::Native;
                }
                self.legacy_query_attributes_target
                    .store(argument, Ordering::Release);
            }
            LEGACY_QUERY_ATTRIBUTES_ID => {
                Self::log_control(host, leaf, argument);
                if !self.activate_legacy(host) {
                    return Action::Native;
                }
                self.legacy_query_attributes_id
                    .store(argument, Ordering::Release);
            }
            _ => return Action::Native,
        }
        Action::Consumed
    }

    pub fn route_syscall(&self, number: u64, r10: i64) -> Option<u64> {
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
            if number == self.legacy_query_system_id.load(Ordering::Acquire) {
                if r10 > 0 {
                    return None;
                }
                selected = self.legacy_query_system_target.load(Ordering::Acquire);
            } else if number == self.legacy_query_attributes_id.load(Ordering::Acquire) {
                selected = self.legacy_query_attributes_target.load(Ordering::Acquire);
            } else {
                return None;
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
