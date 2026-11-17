//! Minimal UTC calendar helpers (no time zone database needed).
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 -> (year, month 1-12, day 1-31). Proleptic Gregorian.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) -> days since 1970-01-01.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

pub fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Broken-down UTC time: (year, month, day, hour, minute, second).
pub fn utc_parts(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, secs / 3600, secs / 60 % 60, secs % 60)
}

/// `YYYYMMDDTHHMMSSZ` as used by SigV4.
pub fn amz_date(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(unix);
    format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", y, mo, d, h, mi, s)
}

/// `YYYY-MM-DDTHH:MM:SSZ`
pub fn iso8601(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(unix);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Parse an IMF-fixdate HTTP date: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = match s.find(',') {
        Some(i) => s[i + 1..].trim(),
        None => s,
    };
    let mut it = s.split_whitespace();
    let d: u32 = it.next()?.parse().ok()?;
    let mon = it.next()?;
    let m = MONTHS.iter().position(|x| x.eq_ignore_ascii_case(mon))? as u32 + 1;
    let y: i64 = it.next()?.parse().ok()?;
    let t = it.next()?;
    let mut tp = t.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let se: i64 = tp.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Parse ISO-8601 UTC timestamps like `2013-09-17T18:07:53.000Z` or `20130917T180753Z`.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let digits: Vec<u32> = {
        let s = s.trim();
        let main = s.split('.').next()?.trim_end_matches('Z');
        let mut v = Vec::new();
        let mut cur = String::new();
        for c in main.chars() {
            if c.is_ascii_digit() {
                cur.push(c);
            } else if !cur.is_empty() {
                v.push(cur.clone());
                cur.clear();
            }
        }
        if !cur.is_empty() {
            v.push(cur);
        }
        if v.len() == 2 && v[0].len() == 8 && v[1].len() == 6 {
            let a = &v[0];
            let b = &v[1];
            vec![
                a[0..4].parse().ok()?, a[4..6].parse().ok()?, a[6..8].parse().ok()?,
                b[0..2].parse().ok()?, b[2..4].parse().ok()?, b[4..6].parse().ok()?,
            ]
        } else {
            v.iter().take(6).map(|x| x.parse().ok()).collect::<Option<Vec<u32>>>()?
        }
    };
    if digits.len() < 6 || !(1..=12).contains(&digits[1]) {
        return None;
    }
    Some(
        days_from_civil(digits[0] as i64, digits[1], digits[2]) * 86_400
            + digits[3] as i64 * 3600
            + digits[4] as i64 * 60
            + digits[5] as i64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        for d in [-800_000i64, -1, 0, 1, 59, 60, 11_016, 20_000, 2_932_896] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(parse_iso8601("2015-08-30T12:36:00.000Z"), Some(1_440_938_160));
        assert_eq!(parse_iso8601("20150830T123600Z"), Some(1_440_938_160));
    }
}
