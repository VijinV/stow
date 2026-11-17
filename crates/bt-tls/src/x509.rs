//! X.509 certificate parsing and server chain validation (RFC 5280 subset).
use crate::crypto::ecdsa::{self, Curve};
use crate::crypto::hash::HashAlg;
use crate::crypto::rsa::RsaPublicKey;
use crate::der::{self, Reader};
use crate::roots::RootStore;

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_EC_PUBKEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXT_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const EXT_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
/// Critical extensions we accept without enforcing beyond parsing.
const KNOWN_CRITICAL: &[&[u8]] = &[
    EXT_BASIC_CONSTRAINTS,
    EXT_KEY_USAGE,
    EXT_SAN,
    EXT_EKU,
    &[0x55, 0x1d, 0x1e], // nameConstraints
    &[0x55, 0x1d, 0x20], // certificatePolicies
    &[0x55, 0x1d, 0x24], // policyConstraints
    &[0x55, 0x1d, 0x36], // inhibitAnyPolicy
];

#[derive(Clone, Debug)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Ec(Curve, Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1(HashAlg),
    RsaPss(HashAlg),
    Ecdsa(HashAlg),
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub raw: Vec<u8>,
    pub tbs: Vec<u8>,
    pub sig_alg: Option<SigAlg>,
    pub signature: Vec<u8>,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub public_key: Option<PublicKey>,
    pub is_ca: bool,
    pub dns_names: Vec<String>,
    pub ip_addrs: Vec<Vec<u8>>,
    /// None = no EKU extension
    pub server_auth_eku: Option<bool>,
    pub unknown_critical: bool,
}

fn err(m: &'static str) -> String {
    m.to_string()
}

pub fn parse_spki(spki: &[u8]) -> Result<PublicKey, String> {
    let mut r = Reader::new(spki);
    let mut s = r.sequence().map_err(|_| err("bad SubjectPublicKeyInfo"))?;
    let mut alg = s.sequence().map_err(|_| err("bad key algorithm"))?;
    let oid = alg.expect(der::OID).map_err(|_| err("bad key algorithm"))?;
    let key = der::bit_string(s.expect(der::BIT_STRING).map_err(|_| err("bad key"))?).map_err(|_| err("bad key"))?;
    if oid == OID_RSA {
        RsaPublicKey::from_pkcs1_der(key).map(PublicKey::Rsa).ok_or_else(|| err("bad RSA key"))
    } else if oid == OID_EC_PUBKEY {
        let curve = alg.expect(der::OID).map_err(|_| err("bad EC parameters"))?;
        let c = if curve == OID_P256 {
            Curve::P256
        } else if curve == OID_P384 {
            Curve::P384
        } else {
            return Err(err("unsupported elliptic curve"));
        };
        if key.len() != 1 + 2 * c.field_len() || key[0] != 4 {
            return Err(err("unsupported EC point encoding"));
        }
        Ok(PublicKey::Ec(c, key.to_vec()))
    } else {
        Err(format!("unsupported public key algorithm {}", der::oid_to_string(oid)))
    }
}

fn hash_from_oid(o: &[u8]) -> Option<HashAlg> {
    if o == OID_SHA256 {
        Some(HashAlg::Sha256)
    } else if o == OID_SHA384 {
        Some(HashAlg::Sha384)
    } else if o == OID_SHA512 {
        Some(HashAlg::Sha512)
    } else {
        None
    }
}

/// Parses an AlgorithmIdentifier for a signature. None = unsupported.
fn parse_sig_alg(alg_seq: &[u8]) -> Option<SigAlg> {
    let mut r = Reader::new(alg_seq);
    let oid = r.expect(der::OID).ok()?;
    Some(match oid {
        o if o == OID_SHA256_RSA => SigAlg::RsaPkcs1(HashAlg::Sha256),
        o if o == OID_SHA384_RSA => SigAlg::RsaPkcs1(HashAlg::Sha384),
        o if o == OID_SHA512_RSA => SigAlg::RsaPkcs1(HashAlg::Sha512),
        o if o == OID_ECDSA_SHA256 => SigAlg::Ecdsa(HashAlg::Sha256),
        o if o == OID_ECDSA_SHA384 => SigAlg::Ecdsa(HashAlg::Sha384),
        o if o == OID_ECDSA_SHA512 => SigAlg::Ecdsa(HashAlg::Sha512),
        o if o == OID_RSA_PSS => {
            // RSASSA-PSS-params: [0] hashAlgorithm (default SHA-1: unsupported)
            let mut p = r.sequence().ok()?;
            let h = p.optional(0xa0).ok()??;
            let mut hr = Reader::new(h);
            let mut ha = hr.sequence().ok()?;
            SigAlg::RsaPss(hash_from_oid(ha.expect(der::OID).ok()?)?)
        }
        _ => return None,
    })
}

fn parse_time(tag: u8, v: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(v).ok()?;
    let digits = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse::<i64>().ok() };
    let (y, rest) = match tag {
        der::UTC_TIME => {
            let yy = digits(0, 2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        der::GENERALIZED_TIME => (digits(0, 4)?, 4),
        _ => return None,
    };
    if !s.ends_with('Z') || s.len() != rest + 11 {
        return None;
    }
    let mo = digits(rest, rest + 2)?;
    let d = digits(rest + 2, rest + 4)?;
    let h = digits(rest + 4, rest + 6)?;
    let mi = digits(rest + 6, rest + 8)?;
    let se = digits(rest + 8, rest + 10)?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

impl Certificate {
    pub fn parse(raw: &[u8]) -> Result<Certificate, String> {
        Self::parse_inner(raw).map_err(|e| format!("TLS: could not parse certificate ({e})"))
    }

    fn parse_inner(raw: &[u8]) -> Result<Certificate, String> {
        let bad = |_| err("malformed");
        let mut top = Reader::new(raw);
        let mut cert = top.sequence().map_err(bad)?;
        if !top.is_empty() {
            return Err(err("trailing data"));
        }
        let tbs_tlv = cert.read().map_err(bad)?;
        if tbs_tlv.tag != der::SEQUENCE {
            return Err(err("malformed"));
        }
        let outer_alg = cert.expect(der::SEQUENCE).map_err(bad)?;
        let signature = der::bit_string(cert.expect(der::BIT_STRING).map_err(bad)?).map_err(bad)?.to_vec();

        let mut tbs = Reader::new(tbs_tlv.value);
        let _version = tbs.optional(0xa0).map_err(bad)?;
        let _serial = tbs.expect(der::INTEGER).map_err(bad)?;
        let inner_alg = tbs.expect(der::SEQUENCE).map_err(bad)?;
        if inner_alg != outer_alg {
            return Err(err("signature algorithm mismatch"));
        }
        let issuer = tbs.read().map_err(bad)?.raw.to_vec();
        let mut validity = tbs.sequence().map_err(bad)?;
        let nb = validity.read().map_err(bad)?;
        let na = validity.read().map_err(bad)?;
        let not_before = parse_time(nb.tag, nb.value).ok_or_else(|| err("bad time"))?;
        let not_after = parse_time(na.tag, na.value).ok_or_else(|| err("bad time"))?;
        let subject = tbs.read().map_err(bad)?.raw.to_vec();
        let spki = tbs.read().map_err(bad)?;
        let public_key = parse_spki(spki.raw).ok();

        let mut c = Certificate {
            raw: raw.to_vec(),
            tbs: tbs_tlv.raw.to_vec(),
            sig_alg: parse_sig_alg(outer_alg),
            signature,
            issuer,
            subject,
            not_before,
            not_after,
            public_key,
            is_ca: false,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            server_auth_eku: None,
            unknown_critical: false,
        };

        // skip issuerUniqueID [1] / subjectUniqueID [2]
        let _ = tbs.optional(0x81).map_err(bad)?;
        let _ = tbs.optional(0x82).map_err(bad)?;
        if let Some(exts) = tbs.optional(0xa3).map_err(bad)? {
            let mut er = Reader::new(exts);
            let mut list = er.sequence().map_err(bad)?;
            while !list.is_empty() {
                let mut ext = list.sequence().map_err(bad)?;
                let oid = ext.expect(der::OID).map_err(bad)?;
                let critical = match ext.optional(der::BOOLEAN).map_err(bad)? {
                    Some(v) => v.first() == Some(&0xff),
                    None => false,
                };
                let val = ext.expect(der::OCTET_STRING).map_err(bad)?;
                if critical && !KNOWN_CRITICAL.contains(&oid) {
                    c.unknown_critical = true;
                }
                if oid == EXT_BASIC_CONSTRAINTS {
                    let mut r = Reader::new(val);
                    let mut s = r.sequence().map_err(bad)?;
                    if let Some(v) = s.optional(der::BOOLEAN).map_err(bad)? {
                        c.is_ca = v.first() == Some(&0xff);
                    }
                } else if oid == EXT_SAN {
                    let mut r = Reader::new(val);
                    let mut s = r.sequence().map_err(bad)?;
                    while !s.is_empty() {
                        let n = s.read().map_err(bad)?;
                        match n.tag {
                            0x82 => {
                                if let Ok(name) = std::str::from_utf8(n.value) {
                                    c.dns_names.push(name.to_ascii_lowercase());
                                }
                            }
                            0x87 => c.ip_addrs.push(n.value.to_vec()),
                            _ => {}
                        }
                    }
                } else if oid == EXT_EKU {
                    let mut r = Reader::new(val);
                    let mut s = r.sequence().map_err(bad)?;
                    let mut ok = false;
                    while !s.is_empty() {
                        let o = s.expect(der::OID).map_err(bad)?;
                        if o == EKU_SERVER_AUTH || o == EKU_ANY {
                            ok = true;
                        }
                    }
                    c.server_auth_eku = Some(ok);
                }
            }
        }
        Ok(c)
    }

    /// Verifies that `self` was signed by `issuer_key`.
    pub fn verify_signed_by(&self, issuer_key: &PublicKey) -> bool {
        match self.sig_alg {
            Some(alg) => verify_signature(issuer_key, alg, &self.tbs, &self.signature),
            None => false,
        }
    }

    pub fn subject_cn(&self) -> String {
        name_cn(&self.subject).unwrap_or_else(|| "?".into())
    }
}

pub fn verify_signature(key: &PublicKey, alg: SigAlg, msg: &[u8], sig: &[u8]) -> bool {
    match (key, alg) {
        (PublicKey::Rsa(k), SigAlg::RsaPkcs1(h)) => k.verify_pkcs1v15(h, &h.hash(msg), sig),
        (PublicKey::Rsa(k), SigAlg::RsaPss(h)) => k.verify_pss(h, &h.hash(msg), sig, None),
        (PublicKey::Ec(c, pt), SigAlg::Ecdsa(h)) => ecdsa::verify(*c, pt, &h.hash(msg), sig),
        _ => false,
    }
}

/// Extracts the CommonName from an encoded Name (for messages only).
pub fn name_cn(name: &[u8]) -> Option<String> {
    let mut r = Reader::new(name);
    let mut seq = r.sequence().ok()?;
    let mut cn = None;
    while !seq.is_empty() {
        let mut set = Reader::new(seq.expect(der::SET).ok()?);
        while !set.is_empty() {
            let mut atv = set.sequence().ok()?;
            let oid = atv.expect(der::OID).ok()?;
            let v = atv.read().ok()?;
            if oid == OID_CN {
                cn = Some(String::from_utf8_lossy(v.value).into_owned());
            }
        }
    }
    cn
}

/// Canonical form of a Name for comparison (string types folded, case-insensitive).
pub fn name_canonical(name: &[u8]) -> Option<Vec<(Vec<u8>, String)>> {
    let mut r = Reader::new(name);
    let mut seq = r.sequence().ok()?;
    let mut out = Vec::new();
    while !seq.is_empty() {
        let mut set = Reader::new(seq.expect(der::SET).ok()?);
        while !set.is_empty() {
            let mut atv = set.sequence().ok()?;
            let oid = atv.expect(der::OID).ok()?.to_vec();
            let v = atv.read().ok()?;
            let s = String::from_utf8_lossy(v.value).split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
            out.push((oid, s));
        }
    }
    Some(out)
}

pub fn names_equal(a: &[u8], b: &[u8]) -> bool {
    a == b || (name_canonical(a).is_some() && name_canonical(a) == name_canonical(b))
}

/// Hostname check against the SAN (RFC 6125; wildcard only as the whole left-most label).
pub fn matches_host(cert: &Certificate, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
        let bytes = match ip {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        };
        return cert.ip_addrs.iter().any(|a| *a == bytes);
    }
    cert.dns_names.iter().any(|pat| {
        let pat = pat.trim_end_matches('.');
        if let Some(suffix) = pat.strip_prefix("*.") {
            match host.split_once('.') {
                Some((first, rest)) => !first.is_empty() && rest == suffix && suffix.contains('.'),
                None => false,
            }
        } else {
            pat == host
        }
    })
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validates a server certificate chain (leaf first). Returns the parsed leaf.
pub fn verify_server_chain(chain: &[Vec<u8>], roots: &RootStore, host: &str, now: i64) -> Result<Certificate, String> {
    let leaf_raw = chain.first().ok_or_else(|| err("TLS: server sent no certificate"))?;
    let leaf = Certificate::parse(leaf_raw)?;
    if now < leaf.not_before {
        return Err(format!("TLS: certificate for '{}' is not yet valid", leaf.subject_cn()));
    }
    if now > leaf.not_after {
        return Err(format!("TLS: certificate has expired (certificate for '{}')", leaf.subject_cn()));
    }
    if !matches_host(&leaf, host) {
        let names = if leaf.dns_names.is_empty() { leaf.subject_cn() } else { leaf.dns_names.join(", ") };
        return Err(format!("TLS: hostname mismatch: certificate is for [{names}], not '{host}'"));
    }
    if leaf.server_auth_eku == Some(false) {
        return Err(err("TLS: certificate is not valid for server authentication"));
    }
    if leaf.unknown_critical {
        return Err(err("TLS: certificate has an unsupported critical extension"));
    }
    // A directly trusted (e.g. self-signed, user-added) certificate.
    if roots.contains_exact(leaf_raw) {
        return Ok(leaf);
    }
    let mut inters: Vec<Option<Certificate>> = chain[1..].iter().map(|c| Certificate::parse(c).ok()).collect();
    let mut used = vec![false; inters.len()];
    let mut best_err = None;
    if build(&leaf, roots, &mut inters, &mut used, now, 0, &mut best_err) {
        return Ok(leaf);
    }
    Err(best_err.unwrap_or_else(|| {
        let issuer = name_cn(&leaf.issuer).unwrap_or_default();
        if names_equal(&leaf.issuer, &leaf.subject) {
            format!("TLS: unknown issuer: self-signed certificate '{}' is not trusted", leaf.subject_cn())
        } else {
            format!("TLS: unknown issuer: no trusted root for certificate issued by '{issuer}'")
        }
    }))
}

fn build(
    cur: &Certificate,
    roots: &RootStore,
    inters: &mut Vec<Option<Certificate>>,
    used: &mut Vec<bool>,
    now: i64,
    depth: usize,
    best_err: &mut Option<String>,
) -> bool {
    if depth > 8 {
        return false;
    }
    for a in roots.anchors_for(&cur.issuer) {
        if cur.verify_signed_by(&a.key) {
            return true;
        }
    }
    for i in 0..inters.len() {
        if used[i] {
            continue;
        }
        let cand = match &inters[i] {
            Some(c) if names_equal(&c.subject, &cur.issuer) => c.clone(),
            _ => continue,
        };
        if !cand.is_ca {
            continue;
        }
        if now > cand.not_after {
            *best_err = Some(format!("TLS: certificate has expired (intermediate '{}')", cand.subject_cn()));
            continue;
        }
        if now < cand.not_before || cand.unknown_critical {
            continue;
        }
        let key = match &cand.public_key {
            Some(k) => k.clone(),
            None => continue,
        };
        if !cur.verify_signed_by(&key) {
            *best_err = Some(format!("TLS: bad signature on certificate '{}'", cur.subject_cn()));
            continue;
        }
        used[i] = true;
        if build(&cand, roots, inters, used, now, depth + 1, best_err) {
            return true;
        }
        used[i] = false;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn civil() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(parse_time(der::UTC_TIME, b"491231235959Z"), Some(days_from_civil(2049, 12, 31) * 86400 + 86399));
        assert_eq!(parse_time(der::GENERALIZED_TIME, b"20500101000000Z"), Some(days_from_civil(2050, 1, 1) * 86400));
    }
    #[test]
    fn wildcard() {
        let mut c = Certificate {
            raw: vec![], tbs: vec![], sig_alg: None, signature: vec![], issuer: vec![], subject: vec![],
            not_before: 0, not_after: 0, public_key: None, is_ca: false,
            dns_names: vec!["*.s3.amazonaws.com".into(), "example.org".into()],
            ip_addrs: vec![vec![127, 0, 0, 1]], server_auth_eku: None, unknown_critical: false,
        };
        assert!(matches_host(&c, "bucket.s3.amazonaws.com"));
        assert!(matches_host(&c, "Example.ORG."));
        assert!(!matches_host(&c, "s3.amazonaws.com"));
        assert!(!matches_host(&c, "a.b.s3.amazonaws.com"));
        assert!(matches_host(&c, "127.0.0.1"));
        assert!(!matches_host(&c, "127.0.0.2"));
        c.dns_names = vec!["*.com".into()];
        assert!(!matches_host(&c, "foo.com"));
    }
}
