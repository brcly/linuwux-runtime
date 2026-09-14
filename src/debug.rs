pub const CAPACITY: usize = 512;

pub fn enabled(value: Option<&[u8]>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != b"0")
}

pub struct Line {
    bytes: [u8; CAPACITY],
    length: usize,
}

impl Line {
    pub fn new(pid: u64, thread_id: Option<u64>) -> Self {
        let mut line = Self {
            bytes: [0; CAPACITY],
            length: 0,
        };
        line.append(b"[linuwux] pid=");
        line.number(pid, false);
        if let Some(tid) = thread_id {
            line.append(b" linux_tid=");
            line.number(tid, false);
        }
        line.append(b" ");
        line
    }

    pub fn remaining(&self) -> usize {
        (CAPACITY - 1).saturating_sub(self.length)
    }

    pub fn push(&mut self, byte: u8) {
        if self.remaining() != 0 {
            self.bytes[self.length] = byte;
            self.length += 1;
        }
    }

    pub fn append(&mut self, text: &[u8]) {
        let count = text.len().min(self.remaining());
        self.bytes[self.length..self.length + count].copy_from_slice(&text[..count]);
        self.length += count;
    }

    pub fn number(&mut self, mut value: u64, hex: bool) {
        let base = if hex { 16 } else { 10 };
        let mut digits = [0; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b"0123456789abcdef"[(value % base) as usize];
            value /= base;
            if value == 0 {
                break;
            }
        }
        self.append(&digits[start..]);
    }

    pub fn finish(&mut self, force_newline: bool) -> &[u8] {
        if self.length < CAPACITY
            && (force_newline || self.length == 0 || self.bytes[self.length - 1] != b'\n')
        {
            self.bytes[self.length] = b'\n';
            self.length += 1;
        }
        &self.bytes[..self.length]
    }
}
