//! Arbitrary-precision unsigned integers (for signature *verification* only:
//! operations are not constant-time and must never touch secrets).
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    /// little-endian 64-bit limbs, no trailing zero limbs
    d: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        BigUint { d: Vec::new() }
    }
    pub fn from_u64(v: u64) -> Self {
        let mut b = BigUint { d: vec![v] };
        b.norm();
        b
    }
    fn norm(&mut self) {
        while self.d.last() == Some(&0) {
            self.d.pop();
        }
    }
    pub fn from_be_bytes(b: &[u8]) -> Self {
        let mut d = Vec::with_capacity(b.len() / 8 + 1);
        for chunk in b.rchunks(8) {
            let mut t = [0u8; 8];
            t[8 - chunk.len()..].copy_from_slice(chunk);
            d.push(u64::from_be_bytes(t));
        }
        let mut r = BigUint { d };
        r.norm();
        r
    }
    /// Big-endian bytes, left-padded with zeros to `len` (or minimal length if too short).
    pub fn to_be_bytes(&self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.d.len() * 8);
        for l in self.d.iter().rev() {
            out.extend_from_slice(&l.to_be_bytes());
        }
        let first = out.iter().position(|&x| x != 0).unwrap_or(out.len());
        let out = &out[first..];
        if out.len() >= len {
            return out.to_vec();
        }
        let mut r = vec![0u8; len - out.len()];
        r.extend_from_slice(out);
        r
    }
    pub fn is_zero(&self) -> bool {
        self.d.is_empty()
    }
    pub fn is_odd(&self) -> bool {
        self.d.first().map_or(false, |x| x & 1 == 1)
    }
    pub fn bits(&self) -> usize {
        match self.d.last() {
            None => 0,
            Some(&t) => self.d.len() * 64 - t.leading_zeros() as usize,
        }
    }
    pub fn bit(&self, i: usize) -> bool {
        self.d.get(i / 64).map_or(false, |l| (l >> (i % 64)) & 1 == 1)
    }

    pub fn add(&self, o: &BigUint) -> BigUint {
        let n = self.d.len().max(o.d.len());
        let mut d = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = *self.d.get(i).unwrap_or(&0);
            let b = *o.d.get(i).unwrap_or(&0);
            let (s1, c1) = a.overflowing_add(b);
            let (s2, c2) = s1.overflowing_add(carry);
            d.push(s2);
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            d.push(carry);
        }
        BigUint { d }
    }

    /// self - o; panics if o > self.
    pub fn sub(&self, o: &BigUint) -> BigUint {
        assert!(*self >= *o, "BigUint subtraction underflow");
        let mut d = Vec::with_capacity(self.d.len());
        let mut borrow = 0u64;
        for i in 0..self.d.len() {
            let a = self.d[i];
            let b = *o.d.get(i).unwrap_or(&0);
            let (s1, b1) = a.overflowing_sub(b);
            let (s2, b2) = s1.overflowing_sub(borrow);
            d.push(s2);
            borrow = (b1 as u64) + (b2 as u64);
        }
        let mut r = BigUint { d };
        r.norm();
        r
    }

    pub fn mul(&self, o: &BigUint) -> BigUint {
        if self.is_zero() || o.is_zero() {
            return BigUint::zero();
        }
        let mut d = vec![0u64; self.d.len() + o.d.len()];
        for (i, &a) in self.d.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in o.d.iter().enumerate() {
                let t = a as u128 * b as u128 + d[i + j] as u128 + carry;
                d[i + j] = t as u64;
                carry = t >> 64;
            }
            d[i + o.d.len()] = carry as u64;
        }
        let mut r = BigUint { d };
        r.norm();
        r
    }

    pub fn shl(&self, bits: usize) -> BigUint {
        if self.is_zero() {
            return BigUint::zero();
        }
        let limbs = bits / 64;
        let b = bits % 64;
        let mut d = vec![0u64; limbs];
        if b == 0 {
            d.extend_from_slice(&self.d);
        } else {
            let mut carry = 0u64;
            for &l in &self.d {
                d.push((l << b) | carry);
                carry = l >> (64 - b);
            }
            d.push(carry);
        }
        let mut r = BigUint { d };
        r.norm();
        r
    }

    pub fn shr(&self, bits: usize) -> BigUint {
        let limbs = bits / 64;
        if limbs >= self.d.len() {
            return BigUint::zero();
        }
        let b = bits % 64;
        let src = &self.d[limbs..];
        let mut d = Vec::with_capacity(src.len());
        for i in 0..src.len() {
            let lo = src[i] >> b;
            let hi = if b > 0 && i + 1 < src.len() { src[i + 1] << (64 - b) } else { 0 };
            d.push(lo | hi);
        }
        let mut r = BigUint { d };
        r.norm();
        r
    }

    /// (quotient, remainder). Panics on division by zero.
    pub fn divrem(&self, v: &BigUint) -> (BigUint, BigUint) {
        assert!(!v.is_zero(), "division by zero");
        if self < v {
            return (BigUint::zero(), self.clone());
        }
        if v.d.len() == 1 {
            let dv = v.d[0] as u128;
            let mut q = vec![0u64; self.d.len()];
            let mut r = 0u128;
            for i in (0..self.d.len()).rev() {
                let cur = (r << 64) | self.d[i] as u128;
                q[i] = (cur / dv) as u64;
                r = cur % dv;
            }
            let mut q = BigUint { d: q };
            q.norm();
            return (q, BigUint::from_u64(r as u64));
        }
        // Knuth algorithm D
        let s = v.d.last().unwrap().leading_zeros() as usize;
        let vn = v.shl(s).d;
        let mut un = self.shl(s).d;
        if un.len() == self.d.len() {
            un.push(0);
        }
        let n = vn.len();
        let m = un.len() - n - 1;
        let mut q = vec![0u64; m + 1];
        let b: u128 = 1 << 64;
        for j in (0..=m).rev() {
            let num = ((un[j + n] as u128) << 64) | un[j + n - 1] as u128;
            let mut qhat = num / vn[n - 1] as u128;
            let mut rhat = num % vn[n - 1] as u128;
            while qhat >= b || qhat * vn[n - 2] as u128 > ((rhat << 64) | un[j + n - 2] as u128) {
                qhat -= 1;
                rhat += vn[n - 1] as u128;
                if rhat >= b {
                    break;
                }
            }
            // multiply and subtract
            let mut borrow: i128 = 0;
            let mut carry: u128 = 0;
            for i in 0..n {
                let p = qhat * vn[i] as u128 + carry;
                carry = p >> 64;
                let t = un[i + j] as i128 - borrow - (p as u64) as i128;
                un[i + j] = t as u64;
                borrow = if t < 0 { 1 } else { 0 };
            }
            let t = un[j + n] as i128 - borrow - carry as i128;
            un[j + n] = t as u64;
            if t < 0 {
                qhat -= 1;
                let mut c = 0u128;
                for i in 0..n {
                    let s2 = un[i + j] as u128 + vn[i] as u128 + c;
                    un[i + j] = s2 as u64;
                    c = s2 >> 64;
                }
                un[j + n] = un[j + n].wrapping_add(c as u64);
            }
            q[j] = qhat as u64;
        }
        let mut q = BigUint { d: q };
        q.norm();
        un.truncate(n);
        let mut r = BigUint { d: un };
        r.norm();
        (q, r.shr(s))
    }

    pub fn rem(&self, m: &BigUint) -> BigUint {
        self.divrem(m).1
    }

    pub fn modmul(&self, o: &BigUint, m: &BigUint) -> BigUint {
        self.mul(o).rem(m)
    }

    pub fn modadd(&self, o: &BigUint, m: &BigUint) -> BigUint {
        let s = self.add(o);
        if s >= *m { s.sub(m) } else { s }
    }

    /// (self - o) mod m, both inputs already reduced.
    pub fn modsub(&self, o: &BigUint, m: &BigUint) -> BigUint {
        if self >= o { self.sub(o) } else { self.add(m).sub(o) }
    }

    pub fn modpow(&self, e: &BigUint, m: &BigUint) -> BigUint {
        let mut result = BigUint::from_u64(1).rem(m);
        let base = self.rem(m);
        for i in (0..e.bits()).rev() {
            result = result.modmul(&result, m);
            if e.bit(i) {
                result = result.modmul(&base, m);
            }
        }
        result
    }

    /// Inverse modulo a prime p (Fermat).
    pub fn modinv_prime(&self, p: &BigUint) -> BigUint {
        self.modpow(&p.sub(&BigUint::from_u64(2)), p)
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for BigUint {
    fn cmp(&self, o: &Self) -> Ordering {
        if self.d.len() != o.d.len() {
            return self.d.len().cmp(&o.d.len());
        }
        for i in (0..self.d.len()).rev() {
            match self.d[i].cmp(&o.d[i]) {
                Ordering::Equal => continue,
                x => return x,
            }
        }
        Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256::sha256;

    fn rnd(seed: u32, len: usize) -> BigUint {
        let mut v = Vec::new();
        let mut c = 0u32;
        while v.len() < len {
            let mut s = seed.to_be_bytes().to_vec();
            s.extend_from_slice(&c.to_be_bytes());
            v.extend_from_slice(&sha256(&s));
            c += 1;
        }
        v.truncate(len);
        BigUint::from_be_bytes(&v)
    }

    #[test]
    fn roundtrip_bytes() {
        let b = BigUint::from_be_bytes(&[0, 0, 1, 2, 3]);
        assert_eq!(b.to_be_bytes(0), vec![1, 2, 3]);
        assert_eq!(b.to_be_bytes(5), vec![0, 0, 1, 2, 3]);
        assert_eq!(BigUint::from_be_bytes(&[]).bits(), 0);
    }

    #[test]
    fn divrem_identity() {
        for seed in 0..300u32 {
            let ul = 1 + (seed as usize * 7) % 130;
            let vl = 1 + (seed as usize * 13) % 70;
            let u = rnd(seed, ul);
            let mut v = rnd(seed + 1000, vl);
            if v.is_zero() {
                v = BigUint::from_u64(3);
            }
            let (q, r) = u.divrem(&v);
            assert!(r < v);
            assert_eq!(q.mul(&v).add(&r), u, "seed {seed}");
        }
        // edge: values that stress qhat correction
        let v = BigUint::from_be_bytes(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let u = BigUint::from_be_bytes(&[0xff; 48]);
        let (q, r) = u.divrem(&v);
        assert_eq!(q.mul(&v).add(&r), u);
    }

    #[test]
    fn modpow_small() {
        let m = BigUint::from_u64(1_000_000_007);
        let r = BigUint::from_u64(2).modpow(&BigUint::from_u64(1_000_000_005), &m);
        assert_eq!(r, BigUint::from_u64(500000004)); // inverse of 2
        let r = BigUint::from_u64(3).modpow(&BigUint::from_u64(200), &BigUint::from_u64(1000));
        assert_eq!(r, BigUint::from_u64(1)); // 3^200 mod 1000 = 1
    }

    #[test]
    fn shifts() {
        let a = rnd(5, 40);
        for s in [0, 1, 63, 64, 65, 130] {
            assert_eq!(a.shl(s).shr(s), a);
        }
    }
}
