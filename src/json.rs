//! Minimal JSON value, parser and pretty serializer (RFC 8259), written from scratch.
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    pub fn set(&mut self, k: &str, v: impl Into<Json>) {
        if let Json::Obj(m) = self {
            m.insert(k.to_string(), v.into());
        }
    }
    pub fn str_or(&self, k: &str, d: &str) -> String {
        match self.get(k) {
            Some(Json::Str(s)) => s.clone(),
            _ => d.to_string(),
        }
    }
    pub fn bool_or(&self, k: &str, d: bool) -> bool {
        match self.get(k) {
            Some(Json::Bool(b)) => *b,
            _ => d,
        }
    }
    pub fn num_or(&self, k: &str, d: f64) -> f64 {
        match self.get(k) {
            Some(Json::Num(n)) => *n,
            _ => d,
        }
    }
    pub fn arr(&self, k: &str) -> &[Json] {
        match self.get(k) {
            Some(Json::Arr(a)) => a,
            _ => &[],
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> Result<Json, String> {
        let mut p = Parser { s: s.as_bytes(), i: 0 };
        p.ws();
        let v = p.value(0)?;
        p.ws();
        if p.i != p.s.len() {
            return Err(format!("trailing characters at byte {}", p.i));
        }
        Ok(v)
    }

    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        write_val(self, &mut out, 0, true);
        out.push('\n');
        out
    }
    pub fn to_string_compact(&self) -> String {
        let mut out = String::new();
        write_val(self, &mut out, 0, false);
        out
    }
}

impl From<&str> for Json {
    fn from(s: &str) -> Json {
        Json::Str(s.to_string())
    }
}
impl From<String> for Json {
    fn from(s: String) -> Json {
        Json::Str(s)
    }
}
impl From<bool> for Json {
    fn from(b: bool) -> Json {
        Json::Bool(b)
    }
}
impl From<f64> for Json {
    fn from(n: f64) -> Json {
        Json::Num(n)
    }
}
impl From<u64> for Json {
    fn from(n: u64) -> Json {
        Json::Num(n as f64)
    }
}
impl From<u32> for Json {
    fn from(n: u32) -> Json {
        Json::Num(n as f64)
    }
}
impl From<Vec<Json>> for Json {
    fn from(v: Vec<Json>) -> Json {
        Json::Arr(v)
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

fn write_val(v: &Json, out: &mut String, depth: usize, pretty: bool) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => {
            if n.is_finite() {
                if n.fract() == 0.0 && n.abs() < 9.0e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{}", n);
                }
            } else {
                out.push_str("null");
            }
        }
        Json::Str(s) => write_str(s, out),
        Json::Arr(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    indent(out, depth + 1);
                }
                write_val(x, out, depth + 1, pretty);
            }
            if pretty {
                out.push('\n');
                indent(out, depth);
            }
            out.push(']');
        }
        Json::Obj(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if pretty {
                    out.push('\n');
                    indent(out, depth + 1);
                }
                write_str(k, out);
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                write_val(x, out, depth + 1, pretty);
            }
            if pretty {
                out.push('\n');
                indent(out, depth);
            }
            out.push('}');
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn err<T>(&self, m: &str) -> Result<T, String> {
        Err(format!("{} at byte {}", m, self.i))
    }
    fn lit(&mut self, w: &str, v: Json) -> Result<Json, String> {
        if self.s[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Ok(v)
        } else {
            self.err("invalid literal")
        }
    }
    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > 128 {
            return self.err("nesting too deep");
        }
        match self.s.get(self.i) {
            None => self.err("unexpected end"),
            Some(b'n') => self.lit("null", Json::Null),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(a));
                        }
                        _ => return self.err("expected , or ]"),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m = BTreeMap::new();
                self.ws();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return self.err("expected key");
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s.get(self.i) != Some(&b':') {
                        return self.err("expected :");
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    m.insert(k, v);
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(m));
                        }
                        _ => return self.err("expected , or }"),
                    }
                }
            }
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                let st = self.i;
                self.i += 1;
                while self.i < self.s.len() && matches!(self.s[self.i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.s[st..self.i]).unwrap();
                t.parse::<f64>().map(Json::Num).or_else(|_| self.err("bad number"))
            }
            _ => self.err("unexpected character"),
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.s.len() {
            return self.err("bad \\u escape");
        }
        let t = std::str::from_utf8(&self.s[self.i..self.i + 4]).map_err(|_| "bad utf8".to_string())?;
        let v = u32::from_str_radix(t, 16).or_else(|_| self.err("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let c = match self.s.get(self.i) {
                None => return self.err("unterminated string"),
                Some(c) => *c,
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *self.s.get(self.i).ok_or("unterminated escape")?;
                    self.i += 1;
                    let ch: u32 = match e {
                        b'"' => 0x22,
                        b'\\' => 0x5c,
                        b'/' => 0x2f,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => 10,
                        b'r' => 13,
                        b't' => 9,
                        b'u' => {
                            let mut v = self.hex4()?;
                            if (0xD800..0xDC00).contains(&v) && self.s[self.i..].starts_with(b"\\u") {
                                self.i += 2;
                                let lo = self.hex4()?;
                                if (0xDC00..0xE000).contains(&lo) {
                                    v = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00);
                                } else {
                                    v = 0xFFFD;
                                }
                            }
                            v
                        }
                        _ => return self.err("bad escape"),
                    };
                    let ch = char::from_u32(ch).unwrap_or('\u{FFFD}');
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
        String::from_utf8(out).or_else(|_| self.err("invalid utf-8 in string"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let src = r#"{"a": [1, 2.5, -3e2, true, false, null], "b": "x\"y\\z\né😀", "c": {}}"#;
        let v = Json::parse(src).unwrap();
        assert_eq!(v.get("b").unwrap().as_str().unwrap(), "x\"y\\z\né😀");
        assert_eq!(v.arr("a")[2], Json::Num(-300.0));
        let again = Json::parse(&v.to_string_pretty()).unwrap();
        assert_eq!(v, again);
        assert_eq!(Json::parse(&v.to_string_compact()).unwrap(), v);
    }
    #[test]
    fn errors() {
        for bad in ["", "{", "[1,]", "{\"a\" 1}", "tru", "\"abc", "1 2"] {
            assert!(Json::parse(bad).is_err(), "{bad}");
        }
    }
}
