//! CPUID reply tables and the process-wide CPU identity they're chosen from.
//!
//! A CPUID leaf's canned reply depends on three independent things: the host
//! CPU vendor (detected once, real hardware), whether Proton has AVX enabled
//! (`PROTON_AVX`), and the [`CpuPresentation`] — modern ("Denuvo") by
//! default, or [`CpuPresentation::Legacy`] for a title whose Reflex protocol
//! (see `docs/protocol/game-quirks.md`) or KUSER dispatch recipe needs an
//! older-looking CPU. [`ActiveCpuIdentity`] holds that identity as a single
//! atomic so `runtime/src/cpuid.rs`'s SIGSEGV handler can read/update it
//! without a lock. This file only builds replies and encodes/decodes that
//! state; it has no idea how a CPUID trap actually reaches it.
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Registers {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl Registers {
    pub const fn new(eax: u32, ebx: u32, ecx: u32, edx: u32) -> Self {
        Self { eax, ebx, ecx, edx }
    }
}

/// CPUID replies used by the AMD SimpleSvm artifact profile. The hypervisor
/// source gates these values on a caller signature; the runtime applies them
/// when `artifact.dll` is mapped on an AMD host.
pub fn artifact_amd_reply(leaf: u32) -> Option<Registers> {
    match leaf {
        // SimpleSvm clears FMA3, XSAVE, OSXSAVE, AVX, F16C, and RDRAND from
        // 0x7ef8320b before returning the feature word.
        1 => Some(Registers::new(
            0x00a2_0f12,
            0x0010_0800,
            0x00f8_220b,
            0x178b_fbff,
        )),
        // Preserve the source's MSVC multi-character constants as the exact
        // register values assigned by the hypervisor.
        0x8000_0002 => Some(Registers::new(
            0x3230_4744,
            0x4254_5253,
            0x464d_3450,
            0x2020_2041,
        )),
        0x8000_0003 => Some(Registers::new(
            0x2020_2020,
            0x2020_2020,
            0x2020_2020,
            0x2020_2020,
        )),
        0x8000_0004 => Some(Registers::new(
            0x2020_2020,
            0x2020_2020,
            0x2020_2020,
            0x0020_2020,
        )),
        _ => None,
    }
}

/// CPUID replies used by the Intel HyperDbg artifact profile. The runtime
/// preserves the native APIC-ID byte of leaf 1 EBX after selecting this reply.
pub fn artifact_intel_reply(leaf: u32) -> Option<Registers> {
    match leaf {
        // HyperDbg clears FMA3, AES, XSAVE, OSXSAVE, AVX, F16C, and RDRAND.
        1 => Some(Registers::new(
            0x000a_0655,
            0x0020_0800,
            0x01fa_ebff,
            0xbfeb_fbff,
        )),
        // Intel(R) Pentium(R) CPU 4425Y @ 1.70GHz, as assigned by the
        // source's MSVC multi-character constants.
        0x8000_0002 => Some(Registers::new(
            0x6574_6e49,
            0x2952_286c,
            0x6e65_5020,
            0x6d75_6974,
        )),
        0x8000_0003 => Some(Registers::new(
            0x2029_5228,
            0x2055_5043,
            0x3532_3434,
            0x2040_2059,
        )),
        0x8000_0004 => Some(Registers::new(0x3037_2e31, 0x007a_4847, 0, 0)),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Unknown,
    Intel,
    Amd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CpuPresentation {
    Denuvo = 0,
    Legacy = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuIdentity {
    vendor: Vendor,
    avx_enabled: bool,
    presentation: CpuPresentation,
}

const MODERN_BRAND: [u32; 12] = [
    0x756e_6544,
    0x4f77_4f76,
    0x5550_4320,
    0x3120_4020,
    0x2037_3333,
    0x007a_4847,
    0,
    0,
    0,
    0,
    0,
    0,
];
const LEGACY_INTEL_BRAND: [u32; 12] = [
    0x6574_6e49,
    0x2952_286c,
    0x726f_4320,
    0x4d54_2865,
    0x3969_2029,
    0x3930_312d,
    0x204b_3030,
    0x2055_5043,
    0x2e33_2040,
    0x4847_3037,
    0x0000_007a,
    0,
];
const LEGACY_AMD_BRAND: [u32; 12] = [
    0x2044_4d41,
    0x657a_7952,
    0x2039_206e,
    0x3030_3935,
    0x3231_2058,
    0x726f_432d,
    0x7250_2065,
    0x7365_636f,
    0x2072_6f73,
    0x2020_2020,
    0x2020_2020,
    0x0020_2020,
];

impl CpuIdentity {
    pub const fn denuvo(vendor: Vendor, avx_enabled: bool) -> Self {
        Self {
            vendor,
            avx_enabled,
            presentation: CpuPresentation::Denuvo,
        }
    }

    pub const fn vendor(self) -> Vendor {
        self.vendor
    }

    pub const fn presentation(self) -> CpuPresentation {
        self.presentation
    }

    pub const fn with_presentation(self, presentation: CpuPresentation) -> Self {
        Self {
            presentation,
            ..self
        }
    }

    pub fn fixed_reply(self, leaf: u32) -> Option<Registers> {
        let reply = match leaf {
            1 => self.leaf1(),
            0x4000_0000 => match self.vendor {
                Vendor::Unknown => Registers::default(),
                Vendor::Intel => Registers::new(0x4000_0001, 0x6570_7948, 0x6762_4472, 0),
                Vendor::Amd => Registers::new(0x4000_0001, 0x706d_6953, 0x7653_656c, 0x2020_206d),
            },
            0x4000_0001 => match self.vendor {
                Vendor::Unknown => Registers::default(),
                Vendor::Intel | Vendor::Amd => Registers::new(0x3023_7648, 0, 0, 0),
            },
            0x8000_0002..=0x8000_0004 => {
                let brand = match (self.presentation, self.vendor) {
                    (CpuPresentation::Legacy, Vendor::Intel) => &LEGACY_INTEL_BRAND,
                    (CpuPresentation::Legacy, Vendor::Amd | Vendor::Unknown) => &LEGACY_AMD_BRAND,
                    (CpuPresentation::Denuvo, _) => &MODERN_BRAND,
                };
                let offset = ((leaf - 0x8000_0002) * 4) as usize;
                Registers::new(
                    brand[offset],
                    brand[offset + 1],
                    brand[offset + 2],
                    brand[offset + 3],
                )
            }
            _ => return None,
        };
        Some(reply)
    }

    fn leaf1(self) -> Registers {
        match (self.presentation, self.vendor, self.avx_enabled) {
            (CpuPresentation::Denuvo, Vendor::Unknown, _) => Registers::default(),
            (CpuPresentation::Denuvo, Vendor::Intel, false) => {
                Registers::new(0x000a_0655, 0x0020_0800, 0x01fa_ebff, 0xbfeb_fbff)
            }
            (CpuPresentation::Denuvo, Vendor::Intel, true)
            | (CpuPresentation::Legacy, Vendor::Intel, _) => {
                Registers::new(0x000a_0655, 0x0020_0800, 0x7bfa_fbff, 0xbfeb_fbff)
            }
            (CpuPresentation::Denuvo, Vendor::Amd, false) => {
                Registers::new(0x00a2_0f12, 0x0010_0800, 0x00f8_220b, 0x178b_fbff)
            }
            (CpuPresentation::Denuvo, Vendor::Amd, true) => {
                Registers::new(0x00a2_0f12, 0x0010_0800, 0x7ad8_320b, 0x178b_fbff)
            }
            (CpuPresentation::Legacy, Vendor::Amd, _) => {
                Registers::new(0x00a2_0f10, 0x0018_0800, 0x7ad8_320b, 0x178b_fbff)
            }
            (CpuPresentation::Legacy, Vendor::Unknown, _) => {
                Registers::new(0x00a2_0f10, 0x0018_0800, 0x7ad8_320b, 0)
            }
        }
    }

    const fn encode(self) -> u32 {
        let vendor = match self.vendor {
            Vendor::Unknown => 0,
            Vendor::Intel => 1,
            Vendor::Amd => 2,
        };
        let avx_enabled = if self.avx_enabled { 1 } else { 0 };
        vendor | (avx_enabled << 2) | (self.presentation as u32) << 3
    }

    const fn decode(raw: u32) -> Self {
        let vendor = match raw & 0b11 {
            1 => Vendor::Intel,
            2 => Vendor::Amd,
            _ => Vendor::Unknown,
        };
        let presentation = if raw & (1 << 3) == 0 {
            CpuPresentation::Denuvo
        } else {
            CpuPresentation::Legacy
        };
        Self {
            vendor,
            avx_enabled: raw & (1 << 2) != 0,
            presentation,
        }
    }
}

impl Vendor {
    pub fn from_leaf0(registers: Registers) -> Self {
        match (registers.ebx, registers.edx, registers.ecx) {
            (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Self::Intel,
            (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Self::Amd,
            _ => Self::Unknown,
        }
    }
}

pub fn proton_avx_enabled(value: Option<&[u8]>) -> bool {
    value == Some(b"1".as_slice())
}

const WINE_SYSTEM_RIP_MIN: u64 = 0x0000_6fff_ff00_0000;
const WINE_SYSTEM_RIP_MAX: u64 = 0x0000_7000_0000_0000;

pub fn is_wine_system_rip(address: u64) -> bool {
    (WINE_SYSTEM_RIP_MIN..WINE_SYSTEM_RIP_MAX).contains(&address)
}

#[derive(Debug)]
pub struct ActiveCpuIdentity {
    raw_identity: AtomicU32,
}

impl ActiveCpuIdentity {
    pub const fn new() -> Self {
        Self {
            raw_identity: AtomicU32::new(CpuIdentity::denuvo(Vendor::Unknown, false).encode()),
        }
    }

    pub fn load(&self) -> CpuIdentity {
        CpuIdentity::decode(self.raw_identity.load(Ordering::Acquire))
    }

    pub fn configure_host(&self, vendor: Vendor, avx_enabled: bool) {
        loop {
            let current = self.raw_identity.load(Ordering::Acquire);
            let presentation = CpuIdentity::decode(current).presentation();
            let next = CpuIdentity::denuvo(vendor, avx_enabled)
                .with_presentation(presentation)
                .encode();
            if self
                .raw_identity
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn select_legacy_presentation(&self) {
        loop {
            let current = self.raw_identity.load(Ordering::Acquire);
            let next = CpuIdentity::decode(current)
                .with_presentation(CpuPresentation::Legacy)
                .encode();
            if self
                .raw_identity
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn fixed_reply(&self, leaf: u32) -> Option<Registers> {
        self.load().fixed_reply(leaf)
    }
}

impl Default for ActiveCpuIdentity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::{Registers, artifact_amd_reply, artifact_intel_reply};

    #[test]
    fn artifact_amd_profile_matches_simple_svm_cpu_registers() {
        assert_eq!(
            artifact_amd_reply(1),
            Some(Registers::new(
                0x00a2_0f12,
                0x0010_0800,
                0x00f8_220b,
                0x178b_fbff,
            ))
        );
        assert_eq!(
            artifact_amd_reply(0x8000_0002),
            Some(Registers::new(
                0x3230_4744,
                0x4254_5253,
                0x464d_3450,
                0x2020_2041,
            ))
        );
        assert_eq!(
            artifact_amd_reply(0x8000_0003),
            Some(Registers::new(
                0x2020_2020,
                0x2020_2020,
                0x2020_2020,
                0x2020_2020,
            ))
        );
        assert_eq!(
            artifact_amd_reply(0x8000_0004),
            Some(Registers::new(
                0x2020_2020,
                0x2020_2020,
                0x2020_2020,
                0x0020_2020,
            ))
        );
        assert_eq!(artifact_amd_reply(7), None);
    }

    #[test]
    fn artifact_intel_profile_matches_hyperdbg_cpu_registers() {
        assert_eq!(
            artifact_intel_reply(1),
            Some(Registers::new(
                0x000a_0655,
                0x0020_0800,
                0x01fa_ebff,
                0xbfeb_fbff,
            ))
        );
        assert_eq!(
            artifact_intel_reply(0x8000_0002),
            Some(Registers::new(
                0x6574_6e49,
                0x2952_286c,
                0x6e65_5020,
                0x6d75_6974,
            ))
        );
        assert_eq!(
            artifact_intel_reply(0x8000_0003),
            Some(Registers::new(
                0x2029_5228,
                0x2055_5043,
                0x3532_3434,
                0x2040_2059,
            ))
        );
        assert_eq!(
            artifact_intel_reply(0x8000_0004),
            Some(Registers::new(0x3037_2e31, 0x007a_4847, 0, 0))
        );
        assert_eq!(artifact_intel_reply(7), None);
    }
}
