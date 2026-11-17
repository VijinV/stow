//! Protects the S3 secret key at rest.
//! - Windows: DPAPI (CryptProtectData), bound to the current user account.
//! - macOS: the login Keychain (generic password item).
//! - Linux: stored in config.json, which is created with 0600 permissions.
//! The stored form is a tagged string: "dpapi:<b64>", "keychain:<account>", or "plain:<secret>".

pub fn b64encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((data.len() + 2) / 3 * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

pub fn b64decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        } as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(windows)]
mod os {
    #[repr(C)]
    struct Blob {
        len: u32,
        data: *mut u8,
    }
    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(i: *const Blob, d: *const u16, e: *const Blob, r: *mut u8, p: *mut u8, f: u32, o: *mut Blob) -> i32;
        fn CryptUnprotectData(i: *const Blob, d: *mut *mut u16, e: *const Blob, r: *mut u8, p: *mut u8, f: u32, o: *mut Blob) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(p: *mut u8) -> *mut u8;
    }
    const UI_FORBIDDEN: u32 = 1;
    fn call(input: &[u8], protect: bool) -> Option<Vec<u8>> {
        let i = Blob { len: input.len() as u32, data: input.as_ptr() as *mut u8 };
        let mut o = Blob { len: 0, data: std::ptr::null_mut() };
        let ok = unsafe {
            if protect {
                CryptProtectData(&i, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), UI_FORBIDDEN, &mut o)
            } else {
                CryptUnprotectData(&i, std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), UI_FORBIDDEN, &mut o)
            }
        };
        if ok == 0 || o.data.is_null() {
            return None;
        }
        let v = unsafe { std::slice::from_raw_parts(o.data, o.len as usize).to_vec() };
        unsafe { LocalFree(o.data) };
        Some(v)
    }
    pub fn protect(secret: &str, _account: &str) -> Option<String> {
        call(secret.as_bytes(), true).map(|v| format!("dpapi:{}", super::b64encode(&v)))
    }
    pub fn unprotect(stored: &str) -> Option<String> {
        let b = super::b64decode(stored.strip_prefix("dpapi:")?)?;
        String::from_utf8(call(&b, false)?).ok()
    }
}

#[cfg(target_os = "macos")]
mod os {
    // Legacy-but-supported Keychain C API: simple (char*, len) arguments, no CoreFoundation needed.
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecKeychainAddGenericPassword(kc: *const u8, sl: u32, s: *const u8, al: u32, a: *const u8, pl: u32, p: *const u8, item: *mut *mut u8) -> i32;
        fn SecKeychainFindGenericPassword(kc: *const u8, sl: u32, s: *const u8, al: u32, a: *const u8, pl: *mut u32, p: *mut *mut u8, item: *mut *mut u8) -> i32;
        fn SecKeychainItemModifyAttributesAndData(item: *mut u8, attrs: *const u8, l: u32, d: *const u8) -> i32;
        fn SecKeychainItemFreeContent(attrs: *mut u8, data: *mut u8) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(p: *mut u8);
    }
    const SERVICE: &str = "Backup Taker S3";
    pub fn protect(secret: &str, account: &str) -> Option<String> {
        let account = if account.is_empty() { "default" } else { account };
        let mut item: *mut u8 = std::ptr::null_mut();
        let mut plen = 0u32;
        let mut pdata: *mut u8 = std::ptr::null_mut();
        unsafe {
            let st = SecKeychainFindGenericPassword(
                std::ptr::null(), SERVICE.len() as u32, SERVICE.as_ptr(), account.len() as u32, account.as_ptr(),
                &mut plen, &mut pdata, &mut item,
            );
            let ok = if st == 0 && !item.is_null() {
                SecKeychainItemFreeContent(std::ptr::null_mut(), pdata);
                let r = SecKeychainItemModifyAttributesAndData(item, std::ptr::null(), secret.len() as u32, secret.as_ptr());
                CFRelease(item);
                r == 0
            } else {
                SecKeychainAddGenericPassword(
                    std::ptr::null(), SERVICE.len() as u32, SERVICE.as_ptr(), account.len() as u32, account.as_ptr(),
                    secret.len() as u32, secret.as_ptr(), std::ptr::null_mut(),
                ) == 0
            };
            if ok { Some(format!("keychain:{}", account)) } else { None }
        }
    }
    pub fn unprotect(stored: &str) -> Option<String> {
        let account = stored.strip_prefix("keychain:")?;
        let mut plen = 0u32;
        let mut pdata: *mut u8 = std::ptr::null_mut();
        unsafe {
            let st = SecKeychainFindGenericPassword(
                std::ptr::null(), SERVICE.len() as u32, SERVICE.as_ptr(), account.len() as u32, account.as_ptr(),
                &mut plen, &mut pdata, std::ptr::null_mut(),
            );
            if st != 0 || pdata.is_null() {
                return None;
            }
            let v = std::slice::from_raw_parts(pdata, plen as usize).to_vec();
            SecKeychainItemFreeContent(std::ptr::null_mut(), pdata);
            String::from_utf8(v).ok()
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod os {
    pub fn protect(_secret: &str, _account: &str) -> Option<String> {
        None
    }
    pub fn unprotect(_stored: &str) -> Option<String> {
        None
    }
}

/// Convert a secret into its at-rest form.
pub fn protect(secret: &str, account: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    if std::env::var_os("BACKUP_TAKER_PLAIN_SECRETS").is_none() {
        if let Some(s) = os::protect(secret, account) {
            return s;
        }
    }
    format!("plain:{}", secret)
}

/// Recover a secret from its at-rest form.
pub fn unprotect(stored: &str) -> String {
    if let Some(p) = stored.strip_prefix("plain:") {
        return p.to_string();
    }
    if stored.is_empty() {
        return String::new();
    }
    os::unprotect(stored).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn b64() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(b64decode(&b64encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(b64encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64encode(b"fo"), "Zm8=");
    }
    #[test]
    fn plain_roundtrip_linux() {
        let s = protect("abc/def+ghi", "AKIA");
        assert_eq!(unprotect(&s), "abc/def+ghi");
    }
}
