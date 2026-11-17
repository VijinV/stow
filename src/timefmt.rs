//! Date/time helpers (no external crates): civil-from-days conversion and local UTC offset via OS FFI.
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// (year, month, day) from days since 1970-01-01 (Howard Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(unix)]
pub fn local_offset_secs(t: i64) -> i64 {
    // struct tm is at least 9 ints followed (on Linux/macOS/BSD) by long tm_gmtoff.
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: i64,
        tm_zone: *const u8,
        _pad: [u64; 4],
    }
    extern "C" {
        fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
    }
    let mut tm: Tm = unsafe { std::mem::zeroed() };
    let r = unsafe { localtime_r(&t, &mut tm) };
    if r.is_null() {
        0
    } else {
        tm.tm_gmtoff
    }
}

#[cfg(windows)]
pub fn local_offset_secs(_t: i64) -> i64 {
    #[repr(C)]
    struct Tzi {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: [u16; 8],
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: [u16; 8],
        daylight_bias: i32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTimeZoneInformation(tz: *mut Tzi) -> u32;
    }
    let mut tz: Tzi = unsafe { std::mem::zeroed() };
    let r = unsafe { GetTimeZoneInformation(&mut tz) };
    let bias = match r {
        1 => tz.bias + tz.standard_bias,
        2 => tz.bias + tz.daylight_bias,
        _ => tz.bias,
    };
    -(bias as i64) * 60
}

#[cfg(not(any(unix, windows)))]
pub fn local_offset_secs(_t: i64) -> i64 {
    0
}

/// "2026-11-17 14:05" in local time.
pub fn format_local(t: i64) -> String {
    if t <= 0 {
        return "never".into();
    }
    let lt = t + local_offset_secs(t);
    let (y, m, d) = civil_from_days(lt.div_euclid(86400));
    let s = lt.rem_euclid(86400);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, s / 3600, (s / 60) % 60)
}

/// Human "3 min ago" style relative time.
pub fn ago(t: i64) -> String {
    if t <= 0 {
        return "never".into();
    }
    let d = now_secs() - t;
    if d < 0 {
        return format_local(t);
    }
    match d {
        0..=44 => "just now".into(),
        45..=5399 => format!("{} min ago", ((d + 30) / 60).max(1)),
        5400..=86399 => format!("{} h ago", (d + 1800) / 3600),
        _ => format_local(t),
    }
}

pub fn human_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs / 60) % 60)
    }
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", n)
    } else if v < 10.0 {
        format!("{:.2} {}", v, U[i])
    } else if v < 100.0 {
        format!("{:.1} {}", v, U[i])
    } else {
        format!("{:.0} {}", v, U[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn civil() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
    #[test]
    fn bytes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.50 KB");
        assert_eq!(human_bytes(150 * 1024 * 1024), "150 MB");
    }
}
