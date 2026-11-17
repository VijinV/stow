//! ECDSA signature verification over NIST P-256 and P-384 (FIPS 186-4).
//! Verification only (public data): uses the variable-time BigUint.
use super::bigint::BigUint;
use crate::der;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

struct Params {
    p: BigUint,
    n: BigUint,
    b: BigUint,
    gx: BigUint,
    gy: BigUint,
    len: usize,
}

fn h(s: &str) -> BigUint {
    BigUint::from_be_bytes(&super::util::unhex(s).unwrap())
}

impl Curve {
    fn params(self) -> Params {
        match self {
            Curve::P256 => Params {
                p: h("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                n: h("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
                b: h("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                gx: h("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                gy: h("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                len: 32,
            },
            Curve::P384 => Params {
                p: h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
                n: h("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
                b: h("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
                gx: h("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
                gy: h("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
                len: 48,
            },
        }
    }
    pub fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }
}

#[derive(Clone)]
struct Jac {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

struct Ctx {
    pr: Params,
}

impl Ctx {
    fn m(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.modmul(b, &self.pr.p)
    }
    fn add(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.modadd(b, &self.pr.p)
    }
    fn sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        a.modsub(b, &self.pr.p)
    }
    fn small(&self, a: &BigUint, k: u64) -> BigUint {
        a.mul(&BigUint::from_u64(k)).rem(&self.pr.p)
    }

    fn on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        let p = &self.pr.p;
        if x >= p || y >= p {
            return false;
        }
        let y2 = self.m(y, y);
        let x3 = self.m(&self.m(x, x), x);
        let rhs = self.add(&self.sub(&x3, &self.small(x, 3)), &self.pr.b);
        y2 == rhs
    }

    fn double(&self, a: &Jac) -> Jac {
        if a.z.is_zero() || a.y.is_zero() {
            return Jac { x: BigUint::from_u64(1), y: BigUint::from_u64(1), z: BigUint::zero() };
        }
        let delta = self.m(&a.z, &a.z);
        let gamma = self.m(&a.y, &a.y);
        let beta = self.m(&a.x, &gamma);
        let alpha = self.small(&self.m(&self.sub(&a.x, &delta), &self.add(&a.x, &delta)), 3);
        let x3 = self.sub(&self.m(&alpha, &alpha), &self.small(&beta, 8));
        let yz = self.add(&a.y, &a.z);
        let z3 = self.sub(&self.sub(&self.m(&yz, &yz), &gamma), &delta);
        let y3 = self.sub(&self.m(&alpha, &self.sub(&self.small(&beta, 4), &x3)), &self.small(&self.m(&gamma, &gamma), 8));
        Jac { x: x3, y: y3, z: z3 }
    }

    fn addp(&self, a: &Jac, b: &Jac) -> Jac {
        if a.z.is_zero() {
            return b.clone();
        }
        if b.z.is_zero() {
            return a.clone();
        }
        let z1z1 = self.m(&a.z, &a.z);
        let z2z2 = self.m(&b.z, &b.z);
        let u1 = self.m(&a.x, &z2z2);
        let u2 = self.m(&b.x, &z1z1);
        let s1 = self.m(&self.m(&a.y, &b.z), &z2z2);
        let s2 = self.m(&self.m(&b.y, &a.z), &z1z1);
        let hh = self.sub(&u2, &u1);
        let r = self.small(&self.sub(&s2, &s1), 2);
        if hh.is_zero() {
            if r.is_zero() {
                return self.double(a);
            }
            return Jac { x: BigUint::from_u64(1), y: BigUint::from_u64(1), z: BigUint::zero() };
        }
        let h2 = self.small(&hh, 2);
        let i = self.m(&h2, &h2);
        let j = self.m(&hh, &i);
        let v = self.m(&u1, &i);
        let x3 = self.sub(&self.sub(&self.m(&r, &r), &j), &self.small(&v, 2));
        let y3 = self.sub(&self.m(&r, &self.sub(&v, &x3)), &self.small(&self.m(&s1, &j), 2));
        let zs = self.add(&a.z, &b.z);
        let z3 = self.m(&self.sub(&self.sub(&self.m(&zs, &zs), &z1z1), &z2z2), &hh);
        Jac { x: x3, y: y3, z: z3 }
    }

    fn affine_x(&self, a: &Jac) -> Option<BigUint> {
        if a.z.is_zero() {
            return None;
        }
        let zi = a.z.modinv_prime(&self.pr.p);
        let zi2 = self.m(&zi, &zi);
        Some(self.m(&a.x, &zi2))
    }
}

/// Verifies a DER-encoded ECDSA signature. `pubkey` is an uncompressed SEC1 point (04||X||Y),
/// `digest` the message hash (truncated as required).
pub fn verify(curve: Curve, pubkey: &[u8], digest: &[u8], der_sig: &[u8]) -> bool {
    let mut r = der::Reader::new(der_sig);
    let parsed = (|| {
        let mut s = r.sequence().ok()?;
        let rr = der::unsigned_int(s.expect(der::INTEGER).ok()?).ok()?;
        let ss = der::unsigned_int(s.expect(der::INTEGER).ok()?).ok()?;
        if !s.is_empty() {
            return None;
        }
        Some((rr.to_vec(), ss.to_vec()))
    })();
    if !r.is_empty() {
        return false;
    }
    match parsed {
        Some((rr, ss)) => verify_raw(curve, pubkey, digest, &rr, &ss),
        None => false,
    }
}

pub fn verify_raw(curve: Curve, pubkey: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let ctx = Ctx { pr: curve.params() };
    let len = ctx.pr.len;
    if pubkey.len() != 1 + 2 * len || pubkey[0] != 4 {
        return false;
    }
    let qx = BigUint::from_be_bytes(&pubkey[1..1 + len]);
    let qy = BigUint::from_be_bytes(&pubkey[1 + len..]);
    if !ctx.on_curve(&qx, &qy) {
        return false;
    }
    let n = &ctx.pr.n;
    let r = BigUint::from_be_bytes(r);
    let s = BigUint::from_be_bytes(s);
    if r.is_zero() || s.is_zero() || r >= *n || s >= *n {
        return false;
    }
    // n bit length is a multiple of 8 for both curves: truncate to len bytes
    let d = if digest.len() > len { &digest[..len] } else { digest };
    let e = BigUint::from_be_bytes(d).rem(n);
    let w = s.modinv_prime(n);
    let u1 = e.modmul(&w, n);
    let u2 = r.modmul(&w, n);
    let g = Jac { x: ctx.pr.gx.clone(), y: ctx.pr.gy.clone(), z: BigUint::from_u64(1) };
    let q = Jac { x: qx, y: qy, z: BigUint::from_u64(1) };
    let gq = ctx.addp(&g, &q);
    let mut acc = Jac { x: BigUint::from_u64(1), y: BigUint::from_u64(1), z: BigUint::zero() };
    let bits = u1.bits().max(u2.bits());
    for i in (0..bits).rev() {
        acc = ctx.double(&acc);
        match (u1.bit(i), u2.bit(i)) {
            (true, true) => acc = ctx.addp(&acc, &gq),
            (true, false) => acc = ctx.addp(&acc, &g),
            (false, true) => acc = ctx.addp(&acc, &q),
            _ => {}
        }
    }
    match ctx.affine_x(&acc) {
        Some(x) => x.rem(n) == r,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generators_on_curve() {
        for c in [Curve::P256, Curve::P384] {
            let ctx = Ctx { pr: c.params() };
            assert!(ctx.on_curve(&ctx.pr.gx, &ctx.pr.gy));
            // n*G = infinity, check (n-1)*G has x == Gx
            let g = Jac { x: ctx.pr.gx.clone(), y: ctx.pr.gy.clone(), z: BigUint::from_u64(1) };
            let k = ctx.pr.n.sub(&BigUint::from_u64(1));
            let mut acc = Jac { x: BigUint::from_u64(1), y: BigUint::from_u64(1), z: BigUint::zero() };
            for i in (0..k.bits()).rev() {
                acc = ctx.double(&acc);
                if k.bit(i) {
                    acc = ctx.addp(&acc, &g);
                }
            }
            assert_eq!(ctx.affine_x(&acc).unwrap(), ctx.pr.gx);
        }
    }
}
