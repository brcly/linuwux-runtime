pub const HW_PROFILE_VALUE_NAME: &[u8] = b"HwProfileGuid";

pub const HW_PROFILE_VALUE: &[u8] = b"{12345678-1234-1234-1234-123456789012}";

pub const HW_PROFILE_KEY_PATH: &[&[u8]] = &[
    b"\\Registry",
    b"Machine",
    b"System",
    b"CurrentControlSet",
    b"Control",
    b"IDConfigDB",
    b"Hardware Profiles",
    b"0001",
];

pub fn utf16_nul_encode(ascii: &[u8], out: &mut [u16]) -> Option<usize> {
    if ascii.len() + 1 > out.len() {
        return None;
    }
    for (slot, &byte) in ascii.iter().enumerate() {
        out[slot] = u16::from(byte);
    }
    out[ascii.len()] = 0;
    Some(ascii.len() + 1)
}
