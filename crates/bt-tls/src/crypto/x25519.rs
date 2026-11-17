//! X25519 Diffie-Hellman (RFC 7748). Constant-time: 51-bit limbs, Montgomery
//! ladder with masked conditional swaps, no secret-dependent branches.

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const MASK51: u64 = (1 << 51) - 1;

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut t = [0u8; 8];
            t.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(t)
        };
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51, // top bit (bit 255) dropped
        ])
    }

    fn carry(mut self) -> Fe {
        let l = &mut self.0;
        let mut c;
        c = l[0] >> 51; l[0] &= MASK51; l[1] += c;
        c = l[1] >> 51; l[1] &= MASK51; l[2] += c;
        c = l[2] >> 51; l[2] &= MASK51; l[3] += c;
        c = l[3] >> 51; l[3] &= MASK51; l[4] += c;
        c = l[4] >> 51; l[4] &= MASK51; l[0] += c * 19;
        c = l[0] >> 51; l[0] &= MASK51; l[1] += c;
        self
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut t = self.carry().carry().0;
        // Fully reduce: compute t + 19, see if it overflows 2^255.
        let mut q = (t[0] + 19) >> 51;
        q = (t[1] + q) >> 51;
        q = (t[2] + q) >> 51;
        q = (t[3] + q) >> 51;
        q = (t[4] + q) >> 51;
        t[0] += 19 * q;
        let mut c;
        c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
        c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
        c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
        c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
        t[4] &= MASK51;
        let mut out = [0u8; 32];
        let w0 = t[0] | (t[1] << 51);
        let w1 = (t[1] >> 13) | (t[2] << 38);
        let w2 = (t[2] >> 26) | (t[3] << 25);
        let w3 = (t[3] >> 39) | (t[4] << 12);
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    fn add(self, o: Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + o.0[i];
        }
        Fe(r).carry()
    }

    fn sub(self, o: Fe) -> Fe {
        // add 4p to avoid underflow
        const P4: [u64; 5] = [0x1fffffffffffb4, 0x1ffffffffffffc, 0x1ffffffffffffc, 0x1ffffffffffffc, 0x1ffffffffffffc];
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = (self.0[i] + P4[i]) - o.0[i];
        }
        Fe(r).carry()
    }

    fn mul(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        let r0 = m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1);
        let r1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2);
        let r2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3);
        let r3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4);
        let r4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        Self::reduce_wide([r0, r1, r2, r3, r4])
    }

    fn reduce_wide(r: [u128; 5]) -> Fe {
        let m51 = MASK51 as u128;
        let mut r = r;
        let c = r[0] >> 51; r[0] &= m51; r[1] += c;
        let c = r[1] >> 51; r[1] &= m51; r[2] += c;
        let c = r[2] >> 51; r[2] &= m51; r[3] += c;
        let c = r[3] >> 51; r[3] &= m51; r[4] += c;
        let c = r[4] >> 51; r[4] &= m51; r[0] += c * 19;
        let c = r[0] >> 51; r[0] &= m51; r[1] += c;
        Fe([r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64, r[4] as u64])
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    fn mul_small(self, k: u64) -> Fe {
        let mut r = [0u128; 5];
        for i in 0..5 {
            r[i] = self.0[i] as u128 * k as u128;
        }
        Self::reduce_wide(r)
    }

    fn pow2k(mut self, k: usize) -> Fe {
        for _ in 0..k {
            self = self.square();
        }
        self
    }

    /// z^(p-2)
    fn invert(self) -> Fe {
        let z = self;
        let z2 = z.square();
        let z9 = z2.pow2k(2).mul(z);
        let z11 = z9.mul(z2);
        let z2_5_0 = z11.square().mul(z9);
        let z2_10_0 = z2_5_0.pow2k(5).mul(z2_5_0);
        let z2_20_0 = z2_10_0.pow2k(10).mul(z2_10_0);
        let z2_40_0 = z2_20_0.pow2k(20).mul(z2_20_0);
        let z2_50_0 = z2_40_0.pow2k(10).mul(z2_10_0);
        let z2_100_0 = z2_50_0.pow2k(50).mul(z2_50_0);
        let z2_200_0 = z2_100_0.pow2k(100).mul(z2_100_0);
        let z2_250_0 = z2_200_0.pow2k(50).mul(z2_50_0);
        z2_250_0.pow2k(5).mul(z11)
    }

    fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }
}

/// Computes X25519(scalar, u).
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= kt;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = kt;
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121665)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    x2.mul(z2.invert()).to_bytes()
}

pub const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASEPOINT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::{hex, unhex};
    fn a32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&unhex(s).unwrap());
        a
    }
    #[test]
    fn rfc7748_vectors() {
        let k = a32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = a32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(hex(&x25519(&k, &u)), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let k = a32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = a32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(hex(&x25519(&k, &u)), "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }
    #[test]
    fn rfc7748_iterated() {
        let mut k = BASEPOINT;
        let mut u = BASEPOINT;
        for i in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(hex(&k), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            }
        }
        assert_eq!(hex(&k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    }
    #[test]
    fn rfc7748_dh() {
        let a = a32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = a32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(hex(&public_key(&a)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(hex(&public_key(&b)), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let s1 = x25519(&a, &public_key(&b));
        let s2 = x25519(&b, &public_key(&a));
        assert_eq!(s1, s2);
        assert_eq!(hex(&s1), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    }
}
