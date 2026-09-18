pub const ANCESTRY_LIMIT: usize = 64;

pub fn is_gamescope_path(path: &[u8]) -> bool {
    path.rsplit(|&byte| byte == b'/').next() == Some(b"gamescope".as_slice())
}

pub fn desktop_list_has_gamescope(list: &[u8]) -> bool {
    let mut start = 0;
    while start < list.len() {
        while start < list.len() && (list[start] == b':' || list[start].is_ascii_whitespace()) {
            start += 1;
        }
        let mut end = start;
        while end < list.len() && list[end] != b':' && !list[end].is_ascii_whitespace() {
            end += 1;
        }
        if &list[start..end] == b"gamescope" {
            return true;
        }
        start = end;
    }
    false
}

pub fn is_gamescope_session(current_desktop: &[u8], session_desktop: &[u8]) -> bool {
    desktop_list_has_gamescope(current_desktop) || desktop_list_has_gamescope(session_desktop)
}

pub fn preload_has_path(list: &[u8], path: &[u8], is_space: impl Fn(u8) -> bool) -> bool {
    !path.is_empty()
        && list
            .split(|&byte| byte == b':' || is_space(byte))
            .any(|token| token == path)
}

pub fn preserved_length(value_length: usize, path_length: usize) -> Option<usize> {
    let maximum = usize::MAX.checked_sub(path_length)?.checked_sub(2)?;
    if value_length > maximum {
        return None;
    }
    Some(value_length + usize::from(value_length != 0) + path_length + 1)
}

pub fn parent_process_id(line: &[u8]) -> Option<i32> {
    let mut value = line.strip_prefix(b"PPid:")?;
    while value
        .first()
        .is_some_and(|b| matches!(*b, b' ' | b'\t'..=b'\r'))
    {
        value = &value[1..];
    }
    let negative = value.first() == Some(&b'-');
    if negative || value.first() == Some(&b'+') {
        value = &value[1..];
    }
    let count = value.iter().take_while(|b| b.is_ascii_digit()).count();
    if count == 0 {
        return None;
    }
    let mut result = 0i32;
    for &byte in &value[..count] {
        result = result
            .checked_mul(10)?
            .checked_add(i32::from(byte - b'0'))?;
    }
    if negative && result != 0 {
        None
    } else {
        Some(result)
    }
}
