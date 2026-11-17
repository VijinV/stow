//! RSA signature verification: PKCS#1 v1.5 and PSS (RFC 8017).
use super::bigint::BigUint;
use super::hash::HashAlg;
use crate::der;

#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
    /// modulus length in bytes
    pub k: usize,
}

impl RsaPublicKey {
    pub fn new(n_be: &[u8], e_be: &[u8]) -> Option<Self> {
        let n = BigUint::from_be_bytes(n_be);
        let e = BigUint::from_be_bytes(e_be);
        let bits = n.bits();
        if !(1024..=16384).contains(&bits) || e.is_zero() || !e.is_odd() || !n.is_odd() {
            return None;
        }
        Some(RsaPublicKey { k: (bits + 7) / 8, n, e })
    }

    /// Parses RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    pub fn from_pkcs1_der(d: &[u8]) -> Option<Self> {
        let mut r = der::Reader::new(d);
        let mut s = r.sequence().ok()?;
        let n = der::unsigned_int(s.expect(der::INTEGER).ok()?).ok()?;
        let e = der::unsigned_int(s.expect(der::INTEGER).ok()?).ok()?;
        Self::new(n, e)
    }

    fn public_op(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = BigUint::from_be_bytes(sig);
        if s >= self.n {
            return None;
        }
        Some(s.modpow(&self.e, &self.n).to_be_bytes(self.k))
    }

    /// PKCS#1 v1.5 with DigestInfo. `digest` is the message hash.
    pub fn verify_pkcs1v15(&self, alg: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        let prefix: &[u8] = match alg {
            HashAlg::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            HashAlg::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            HashAlg::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        };
        if digest.len() != alg.output_len() {
            return false;
        }
        let em = match self.public_op(sig) {
            Some(e) => e,
            None => return false,
        };
        let t_len = prefix.len() + digest.len();
        if self.k < t_len + 11 {
            return false;
        }
        let mut expected = vec![0u8; self.k];
        expected[1] = 1;
        for b in &mut expected[2..self.k - t_len - 1] {
            *b = 0xff;
        }
        expected[self.k - t_len..self.k - digest.len()].copy_from_slice(prefix);
        expected[self.k - digest.len()..].copy_from_slice(digest);
        em == expected
    }

    /// RSASSA-PSS with MGF1 using the same hash. `salt_len`: None = accept any.
    pub fn verify_pss(&self, alg: HashAlg, digest: &[u8], sig: &[u8], salt_len: Option<usize>) -> bool {
        let h_len = alg.output_len();
        if digest.len() != h_len {
            return false;
        }
        let mod_bits = self.n.bits();
        let em_bits = mod_bits - 1;
        let em_len = (em_bits + 7) / 8;
        let full = match self.public_op(sig) {
            Some(e) => e,
            None => return false,
        };
        // full has k bytes; if em_len == k-1 the first byte must be zero
        let em = if em_len < self.k {
            if full[..self.k - em_len].iter().any(|&b| b != 0) {
                return false;
            }
            &full[self.k - em_len..]
        } else {
            &full[..]
        };
        if em_len < h_len + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let db_len = em_len - h_len - 1;
        let masked_db = &em[..db_len];
        let h = &em[db_len..db_len + h_len];
        let top_bits = 8 * em_len - em_bits;
        if top_bits > 0 && masked_db[0] & (0xffu8 << (8 - top_bits)) != 0 {
            return false;
        }
        let mask = mgf1(alg, h, db_len);
        let mut db: Vec<u8> = masked_db.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect();
        if top_bits > 0 {
            db[0] &= 0xff >> top_bits;
        }
        let sep = match db.iter().position(|&b| b != 0) {
            Some(i) if db[i] == 0x01 => i,
            _ => return false,
        };
        let salt = &db[sep + 1..];
        if let Some(sl) = salt_len {
            if salt.len() != sl {
                return false;
            }
        }
        let mut hs = alg.hasher();
        hs.update(&[0u8; 8]);
        hs.update(digest);
        hs.update(salt);
        hs.finalize() == h
    }
}

pub fn mgf1(alg: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + alg.output_len());
    let mut c = 0u32;
    while out.len() < len {
        let mut h = alg.hasher();
        h.update(seed);
        h.update(&c.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        c += 1;
    }
    out.truncate(len);
    out
}
