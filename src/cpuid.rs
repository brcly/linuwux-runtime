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
    const fn new(eax: u32, ebx: u32, ecx: u32, edx: u32) -> Self {
        Self { eax, ebx, ecx, edx }
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
pub enum Profile {
    Unknown = 0,
    Intel = 1,
    IntelAvx = 2,
    Amd = 3,
    AmdAvx = 4,
    LegacyIntel = 5,
    LegacyAmd = 6,
    LegacyUnknown = 7,
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

impl Profile {
    pub fn modern(vendor: Vendor, avx_enabled: bool) -> Self {
        match (vendor, avx_enabled) {
            (Vendor::Unknown, _) => Self::Unknown,
            (Vendor::Intel, false) => Self::Intel,
            (Vendor::Intel, true) => Self::IntelAvx,
            (Vendor::Amd, false) => Self::Amd,
            (Vendor::Amd, true) => Self::AmdAvx,
        }
    }

    pub fn vendor(self) -> Vendor {
        match self {
            Self::Unknown | Self::LegacyUnknown => Vendor::Unknown,
            Self::Intel | Self::IntelAvx | Self::LegacyIntel => Vendor::Intel,
            Self::Amd | Self::AmdAvx | Self::LegacyAmd => Vendor::Amd,
        }
    }

    pub fn legacy(self) -> Self {
        match self.vendor() {
            Vendor::Unknown => Self::LegacyUnknown,
            Vendor::Intel => Self::LegacyIntel,
            Vendor::Amd => Self::LegacyAmd,
        }
    }

    pub fn fixed_reply(self, leaf: u32) -> Option<Registers> {
        let reply = match leaf {
            1 => self.leaf1(),
            0x4000_0000 => match self.vendor() {
                Vendor::Unknown => Registers::default(),
                Vendor::Intel => Registers::new(0x4000_0001, 0x6570_7948, 0x6762_4472, 0),
                Vendor::Amd => Registers::new(0x4000_0001, 0x706d_6953, 0x7653_656c, 0x2020_206d),
            },
            0x4000_0001 => match self.vendor() {
                Vendor::Unknown => Registers::default(),
                Vendor::Intel | Vendor::Amd => Registers::new(0x3023_7648, 0, 0, 0),
            },
            0x8000_0002..=0x8000_0004 => {
                let brand = match self {
                    Self::LegacyIntel => &LEGACY_INTEL_BRAND,
                    Self::LegacyAmd | Self::LegacyUnknown => &LEGACY_AMD_BRAND,
                    _ => &MODERN_BRAND,
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
        match self {
            Self::Unknown => Registers::default(),
            Self::Intel => Registers::new(0x000a_0655, 0x0020_0800, 0x01fa_ebff, 0xbfeb_fbff),
            Self::IntelAvx | Self::LegacyIntel => {
                Registers::new(0x000a_0655, 0x0020_0800, 0x7bfa_fbff, 0xbfeb_fbff)
            }
            Self::Amd => Registers::new(0x00a2_0f12, 0x0010_0800, 0x00f8_220b, 0x178b_fbff),
            Self::AmdAvx => Registers::new(0x00a2_0f12, 0x0010_0800, 0x7ad8_320b, 0x178b_fbff),
            Self::LegacyAmd => Registers::new(0x00a2_0f10, 0x0018_0800, 0x7ad8_320b, 0x178b_fbff),
            Self::LegacyUnknown => Registers::new(0x00a2_0f10, 0x0018_0800, 0x7ad8_320b, 0),
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

pub fn redirect_all_enabled(value: Option<&[u8]>) -> bool {
    value == Some(b"1".as_slice())
}

const WINE_SYSTEM_RIP_MIN: u64 = 0x0000_6fff_ff00_0000;
const WINE_SYSTEM_RIP_MAX: u64 = 0x0000_7000_0000_0000;

pub fn is_wine_system_rip(address: u64) -> bool {
    (WINE_SYSTEM_RIP_MIN..WINE_SYSTEM_RIP_MAX).contains(&address)
}

#[derive(Debug)]
pub struct ActiveProfile {
    raw_profile: AtomicU32,
}

impl ActiveProfile {
    pub const fn new() -> Self {
        Self {
            raw_profile: AtomicU32::new(Profile::Unknown as u32),
        }
    }

    pub fn load(&self) -> Profile {
        match self.raw_profile.load(Ordering::Acquire) {
            1 => Profile::Intel,
            2 => Profile::IntelAvx,
            3 => Profile::Amd,
            4 => Profile::AmdAvx,
            5 => Profile::LegacyIntel,
            6 => Profile::LegacyAmd,
            7 => Profile::LegacyUnknown,
            _ => Profile::Unknown,
        }
    }

    pub fn configure(&self, vendor: Vendor, avx_enabled: bool) {
        self.raw_profile.store(
            Profile::modern(vendor, avx_enabled) as u32,
            Ordering::Release,
        );
    }

    pub fn activate_legacy(&self) {
        self.raw_profile
            .store(self.load().legacy() as u32, Ordering::Release);
    }

    pub fn fixed_reply(&self, leaf: u32) -> Option<Registers> {
        self.load().fixed_reply(leaf)
    }
}

impl Default for ActiveProfile {
    fn default() -> Self {
        Self::new()
    }
}
