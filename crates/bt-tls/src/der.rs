//! Minimal DER (ASN.1) reader.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerError(pub &'static str);

pub type Result<T> = std::result::Result<T, DerError>;

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    /// The complete encoding including tag and length.
    pub raw: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }
    pub fn read(&mut self) -> Result<Tlv<'a>> {
        let start = self.pos;
        let d = self.data;
        let tag = *d.get(self.pos).ok_or(DerError("truncated tag"))?;
        if tag & 0x1f == 0x1f {
            return Err(DerError("high tag numbers unsupported"));
        }
        self.pos += 1;
        let l0 = *d.get(self.pos).ok_or(DerError("truncated length"))?;
        self.pos += 1;
        let len = if l0 < 0x80 {
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(DerError("bad length"));
            }
            let mut len = 0usize;
            for _ in 0..n {
                len = len << 8 | *d.get(self.pos).ok_or(DerError("truncated length"))? as usize;
                self.pos += 1;
            }
            len
        };
        let end = self.pos.checked_add(len).ok_or(DerError("overflow"))?;
        if end > d.len() {
            return Err(DerError("truncated value"));
        }
        let value = &d[self.pos..end];
        self.pos = end;
        Ok(Tlv { tag, value, raw: &d[start..end] })
    }
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let t = self.read()?;
        if t.tag != tag {
            return Err(DerError("unexpected tag"));
        }
        Ok(t.value)
    }
    /// Reads an element only if it has the given tag.
    pub fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.expect(tag)?))
        } else {
            Ok(None)
        }
    }
    pub fn sequence(&mut self) -> Result<Reader<'a>> {
        Ok(Reader::new(self.expect(SEQUENCE)?))
    }
}

/// Strips the leading zero of a positive DER INTEGER.
pub fn unsigned_int(v: &[u8]) -> Result<&[u8]> {
    if v.is_empty() {
        return Err(DerError("empty integer"));
    }
    if v[0] & 0x80 != 0 {
        return Err(DerError("negative integer"));
    }
    let mut v = v;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    Ok(v)
}

/// BIT STRING contents without the unused-bits byte (must be 0).
pub fn bit_string(v: &[u8]) -> Result<&[u8]> {
    match v.first() {
        Some(0) => Ok(&v[1..]),
        _ => Err(DerError("unsupported bit string")),
    }
}

/// Dotted-string form of an OID (for messages/tests).
pub fn oid_to_string(v: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut acc: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        acc = acc << 7 | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() && i < v.len() {
                let first = (acc / 40).min(2);
                parts.push(first);
                parts.push(acc - first * 40);
            } else {
                parts.push(acc);
            }
            acc = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}
