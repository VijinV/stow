//! AES-128/256-GCM (FIPS-197, NIST SP 800-38D).
//!
//! Block encryption uses AES-NI on x86_64 or the ARMv8 crypto extension on
//! aarch64 when the CPU has it (constant time). Otherwise it falls back to a
//! portable *table-based* S-box implementation, which is NOT constant-time with
//! respect to cache timing; the TLS client prefers ChaCha20-Poly1305 so this
//! path is only used if a server refuses ChaCha20 on a CPU without AES
//! instructions. The key schedule always uses a constant-time S-box scan.
//! GHASH uses a constant-time carry-less multiply built from integer multiplies.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Constant-time S-box lookup (scans the whole table).
fn sbox_ct(x: u8) -> u8 {
    let mut r = 0u8;
    for (i, &v) in SBOX.iter().enumerate() {
        let eq = ((i as u8 ^ x) as u32).wrapping_sub(1) >> 31; // 1 if equal
        r |= v & (0u8.wrapping_sub(eq as u8));
    }
    r
}

#[derive(Clone)]
pub struct Aes {
    rk: [[u8; 16]; 15],
    rounds: usize,
    #[allow(dead_code)]
    hw: bool,
}

impl Aes {
    /// Key must be 16 or 32 bytes.
    pub fn new(key: &[u8]) -> Aes {
        let nk = key.len() / 4;
        assert!(nk == 4 || nk == 8, "AES key must be 128 or 256 bits");
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut w = vec![[0u8; 4]; total];
        for i in 0..nk {
            w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
        }
        let mut rcon = 1u8;
        for i in nk..total {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [sbox_ct(t[1]) ^ rcon, sbox_ct(t[2]), sbox_ct(t[3]), sbox_ct(t[0])];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = [sbox_ct(t[0]), sbox_ct(t[1]), sbox_ct(t[2]), sbox_ct(t[3])];
            }
            for j in 0..4 {
                w[i][j] = w[i - nk][j] ^ t[j];
            }
        }
        let mut rk = [[0u8; 16]; 15];
        for r in 0..=rounds {
            for c in 0..4 {
                rk[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        Aes { rk, rounds, hw: hw_available() }
    }

    pub fn encrypt_block(&self, b: &mut [u8; 16]) {
        #[cfg(target_arch = "x86_64")]
        if self.hw {
            unsafe { return self.encrypt_aesni(b) };
        }
        #[cfg(target_arch = "aarch64")]
        if self.hw {
            unsafe { return self.encrypt_armv8(b) };
        }
        self.encrypt_soft(b)
    }

    fn encrypt_soft(&self, s: &mut [u8; 16]) {
        xor16(s, &self.rk[0]);
        for r in 1..=self.rounds {
            for x in s.iter_mut() {
                *x = SBOX[*x as usize]; // table lookup (see module docs)
            }
            // ShiftRows (state is column-major: s[row + 4*col])
            let t = *s;
            for row in 1..4 {
                for col in 0..4 {
                    s[row + 4 * col] = t[row + 4 * ((col + row) % 4)];
                }
            }
            if r != self.rounds {
                for col in 0..4 {
                    let a = [s[4 * col], s[4 * col + 1], s[4 * col + 2], s[4 * col + 3]];
                    let all = a[0] ^ a[1] ^ a[2] ^ a[3];
                    for i in 0..4 {
                        s[4 * col + i] = a[i] ^ all ^ xtime(a[i] ^ a[(i + 1) % 4]);
                    }
                }
            }
            xor16(s, &self.rk[r]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_aesni(&self, b: &mut [u8; 16]) {
        use std::arch::x86_64::*;
        let mut st = _mm_loadu_si128(b.as_ptr() as *const __m128i);
        st = _mm_xor_si128(st, _mm_loadu_si128(self.rk[0].as_ptr() as *const __m128i));
        for r in 1..self.rounds {
            st = _mm_aesenc_si128(st, _mm_loadu_si128(self.rk[r].as_ptr() as *const __m128i));
        }
        st = _mm_aesenclast_si128(st, _mm_loadu_si128(self.rk[self.rounds].as_ptr() as *const __m128i));
        _mm_storeu_si128(b.as_mut_ptr() as *mut __m128i, st);
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes,neon")]
    unsafe fn encrypt_armv8(&self, b: &mut [u8; 16]) {
        use std::arch::aarch64::*;
        let mut st = vld1q_u8(b.as_ptr());
        for r in 0..self.rounds - 1 {
            st = vaesmcq_u8(vaeseq_u8(st, vld1q_u8(self.rk[r].as_ptr())));
        }
        st = vaeseq_u8(st, vld1q_u8(self.rk[self.rounds - 1].as_ptr()));
        st = veorq_u8(st, vld1q_u8(self.rk[self.rounds].as_ptr()));
        vst1q_u8(b.as_mut_ptr(), st);
    }
}

fn hw_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return std::arch::is_aarch64_feature_detected!("aes");
    }
    #[allow(unreachable_code)]
    false
}

#[inline(always)]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & 0u8.wrapping_sub(x >> 7))
}

#[inline(always)]
fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// Constant-time 32x32 -> 64 carry-less multiply (integer multiplies with holes).
#[inline(always)]
fn clmul32(x: u32, y: u32) -> u64 {
    let x = x as u64;
    let y = y as u64;
    let (x0, x1, x2, x3) = (x & 0x1111_1111, x & 0x2222_2222, x & 0x4444_4444, x & 0x8888_8888);
    let (y0, y1, y2, y3) = (y & 0x1111_1111, y & 0x2222_2222, y & 0x4444_4444, y & 0x8888_8888);
    let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    (z0 & 0x1111_1111_1111_1111) | (z1 & 0x2222_2222_2222_2222) | (z2 & 0x4444_4444_4444_4444) | (z3 & 0x8888_8888_8888_8888)
}

/// 128x128 -> 256 carry-less multiply. Returns (low, high).
fn clmul128(a: u128, b: u128) -> (u128, u128) {
    let aw = [a as u32, (a >> 32) as u32, (a >> 64) as u32, (a >> 96) as u32];
    let bw = [b as u32, (b >> 32) as u32, (b >> 64) as u32, (b >> 96) as u32];
    let mut lo = 0u128;
    let mut hi = 0u128;
    for i in 0..4 {
        for j in 0..4 {
            let p = clmul32(aw[i], bw[j]) as u128;
            let sh = 32 * (i + j);
            if sh < 128 {
                lo ^= p << sh;
                if sh > 64 {
                    hi ^= p >> (128 - sh);
                }
            } else {
                hi ^= p << (sh - 128);
            }
        }
    }
    (lo, hi)
}

/// Hardware carry-less multiply availability (PCLMULQDQ / PMULL).
fn clmul_hw() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return std::arch::is_x86_feature_detected!("pclmulqdq") && std::arch::is_x86_feature_detected!("sse2");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return std::arch::is_aarch64_feature_detected!("aes");
    }
    #[allow(unreachable_code)]
    false
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul64_hw(a: u64, b: u64) -> u128 {
    use std::arch::x86_64::*;
    let r = _mm_clmulepi64_si128(_mm_set_epi64x(0, a as i64), _mm_set_epi64x(0, b as i64), 0x00);
    let mut o = [0u64; 2];
    _mm_storeu_si128(o.as_mut_ptr() as *mut __m128i, r);
    (o[1] as u128) << 64 | o[0] as u128
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes,neon")]
unsafe fn clmul64_hw(a: u64, b: u64) -> u128 {
    std::arch::aarch64::vmull_p64(a, b)
}

/// 128x128 -> 256 carry-less multiply with hardware 64-bit products (Karatsuba).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
unsafe fn clmul128_hw(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64_hw(a0, b0);
    let hi = clmul64_hw(a1, b1);
    let mid = clmul64_hw(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    (lo ^ (mid << 64), hi ^ (mid >> 64))
}

/// Multiply in the bit-reversed domain (operands already `reverse_bits`ed) and reduce
/// modulo x^128 + x^7 + x^2 + x + 1.
#[inline(always)]
fn reduce(lo: u128, hi: u128) -> u128 {
    let t = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let o = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    lo ^ t ^ o ^ (o << 1) ^ (o << 2) ^ (o << 7)
}

/// GF(2^128) multiply in GCM's bit-reflected convention (reference form).
#[allow(dead_code)]
fn gf_mul(x: u128, h: u128) -> u128 {
    let (lo, hi) = clmul128(x.reverse_bits(), h.reverse_bits());
    reduce(lo, hi).reverse_bits()
}

struct Ghash {
    /// H and the accumulator, both kept bit-reversed so blocks only need one reversal.
    h_rev: u128,
    y_rev: u128,
    hw: bool,
}

impl Ghash {
    fn new(h: u128, hw: bool) -> Self {
        Ghash { h_rev: h.reverse_bits(), y_rev: 0, hw }
    }

    #[inline(always)]
    fn block(&mut self, x: u128) {
        let a = self.y_rev ^ x.reverse_bits();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if self.hw {
            let (lo, hi) = unsafe { clmul128_hw(a, self.h_rev) };
            self.y_rev = reduce(lo, hi);
            return;
        }
        let (lo, hi) = clmul128(a, self.h_rev);
        self.y_rev = reduce(lo, hi);
    }

    fn update_padded(&mut self, data: &[u8]) {
        for c in data.chunks(16) {
            let mut b = [0u8; 16];
            b[..c.len()].copy_from_slice(c);
            self.block(u128::from_be_bytes(b));
        }
    }

    fn result(&self) -> u128 {
        self.y_rev.reverse_bits()
    }
}

pub struct AesGcm {
    aes: Aes,
    h: u128,
    clmul: bool,
}

impl AesGcm {
    /// 16-byte key = AES-128-GCM, 32-byte key = AES-256-GCM.
    pub fn new(key: &[u8]) -> Self {
        let aes = Aes::new(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        AesGcm { aes, h: u128::from_be_bytes(h), clmul: clmul_hw() }
    }

    fn ctr(&self, nonce: &[u8; 12], data: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        if self.aes.hw {
            return unsafe { self.ctr_aesni(nonce, data) };
        }
        let mut ctr = [0u8; 16];
        ctr[..12].copy_from_slice(nonce);
        let mut n = 2u32;
        for c in data.chunks_mut(16) {
            ctr[12..].copy_from_slice(&n.to_be_bytes());
            let mut ks = ctr;
            self.aes.encrypt_block(&mut ks);
            for (d, k) in c.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
            n = n.wrapping_add(1);
        }
    }

    /// AES-NI CTR mode, 8 blocks in flight.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn ctr_aesni(&self, nonce: &[u8; 12], data: &mut [u8]) {
        use std::arch::x86_64::*;
        let rk: Vec<__m128i> = (0..=self.aes.rounds).map(|r| _mm_loadu_si128(self.aes.rk[r].as_ptr() as *const __m128i)).collect();
        let mut base = [0u8; 16];
        base[..12].copy_from_slice(nonce);
        let mut n = 2u32;
        let mut chunks = data.chunks_mut(128);
        for chunk in &mut chunks {
            let mut blocks = [_mm_setzero_si128(); 8];
            let nb = (chunk.len() + 15) / 16;
            for i in 0..nb {
                base[12..].copy_from_slice(&n.wrapping_add(i as u32).to_be_bytes());
                blocks[i] = _mm_xor_si128(_mm_loadu_si128(base.as_ptr() as *const __m128i), rk[0]);
            }
            for r in 1..self.aes.rounds {
                for b in blocks.iter_mut().take(nb) {
                    *b = _mm_aesenc_si128(*b, rk[r]);
                }
            }
            for b in blocks.iter_mut().take(nb) {
                *b = _mm_aesenclast_si128(*b, rk[self.aes.rounds]);
            }
            for i in 0..nb {
                let clen = chunk.len();
                let c = &mut chunk[16 * i..(16 * i + 16).min(clen)];
                if c.len() == 16 {
                    let v = _mm_xor_si128(_mm_loadu_si128(c.as_ptr() as *const __m128i), blocks[i]);
                    _mm_storeu_si128(c.as_mut_ptr() as *mut __m128i, v);
                } else {
                    let mut ks = [0u8; 16];
                    _mm_storeu_si128(ks.as_mut_ptr() as *mut __m128i, blocks[i]);
                    for (d, k) in c.iter_mut().zip(ks.iter()) {
                        *d ^= k;
                    }
                }
            }
            n = n.wrapping_add(nb as u32);
        }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let mut g = Ghash::new(self.h, self.clmul);
        g.update_padded(aad);
        g.update_padded(ct);
        let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
        g.block(lens);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        self.aes.encrypt_block(&mut j0);
        (g.result() ^ u128::from_be_bytes(j0)).to_be_bytes()
    }

    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        self.ctr(nonce, data);
        self.tag(nonce, aad, data)
    }

    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        let t = self.tag(nonce, aad, data);
        if !super::util::ct_eq(&t, tag) {
            return false;
        }
        self.ctr(nonce, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::{hex, unhex};

    #[test]
    fn sbox_ct_matches() {
        for i in 0..=255u8 {
            assert_eq!(sbox_ct(i), SBOX[i as usize]);
        }
    }

    #[test]
    fn fips197() {
        let key = unhex("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut b: [u8; 16] = unhex("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
        let a = Aes::new(&key);
        let mut b2 = b;
        a.encrypt_block(&mut b);
        assert_eq!(hex(&b), "69c4e0d86a7b0430d8cdb78070b4c55a");
        a.encrypt_soft(&mut b2);
        assert_eq!(hex(&b2), "69c4e0d86a7b0430d8cdb78070b4c55a");
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let a = Aes::new(&key);
        let mut b: [u8; 16] = unhex("00112233445566778899aabbccddeeff").unwrap().try_into().unwrap();
        let mut b2 = b;
        a.encrypt_block(&mut b);
        a.encrypt_soft(&mut b2);
        assert_eq!(hex(&b), "8ea2b7ca516745bfeafc49904b496089");
        assert_eq!(hex(&b2), "8ea2b7ca516745bfeafc49904b496089");
    }

    fn check(key: &str, iv: &str, pt: &str, aad: &str, ct: &str, tag: &str) {
        let g = AesGcm::new(&unhex(key).unwrap());
        let nonce: [u8; 12] = unhex(iv).unwrap().try_into().unwrap();
        let aad = unhex(aad).unwrap();
        let mut d = unhex(pt).unwrap();
        let t = g.seal(&nonce, &aad, &mut d);
        assert_eq!(hex(&d), ct);
        assert_eq!(hex(&t), tag);
        assert!(g.open(&nonce, &aad, &mut d, &t));
        assert_eq!(hex(&d), pt);
        let mut bad = t;
        bad[15] ^= 0x80;
        assert!(!g.open(&nonce, &aad, &mut d.clone(), &bad));
    }

    #[test]
    fn ghash_hw_matches_soft() {
        let mut x = 0x0123456789abcdef_fedcba9876543210u128;
        let h = 0x66e94bd4ef8a2c3b_884cfa59ca342b2eu128;
        for _ in 0..200 {
            let mut a = Ghash::new(h, clmul_hw());
            let mut b = Ghash::new(h, false);
            a.block(x);
            b.block(x);
            a.block(x ^ 77);
            b.block(x ^ 77);
            assert_eq!(a.result(), b.result());
            assert_eq!(b.result(), gf_mul(gf_mul(x, h) ^ (x ^ 77), h));
            x = x.wrapping_mul(0x9e3779b97f4a7c15f39cc0605cedc835).rotate_left(17);
        }
    }

    #[test]
    fn gcm_soft_paths() {
        // force the portable AES + GHASH paths and compare to the dispatching version
        let key = unhex("feffe9928665731c6d6a8f9467308308").unwrap();
        let fast = AesGcm::new(&key);
        let mut slow = AesGcm::new(&key);
        slow.aes.hw = false;
        slow.clmul = false;
        for len in [0usize, 1, 15, 16, 17, 127, 128, 129, 1000, 4099] {
            let mut a: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut b = a.clone();
            let n = [3u8; 12];
            assert_eq!(fast.seal(&n, b"aad", &mut a), slow.seal(&n, b"aad", &mut b), "len {len}");
            assert_eq!(a, b);
        }
    }

    #[test]
    fn gcm_spec_vectors() {
        // McGrew & Viega GCM spec / NIST test cases 1-4 (AES-128) and 13-16 (AES-256)
        check("00000000000000000000000000000000", "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
        check("00000000000000000000000000000000", "000000000000000000000000", "00000000000000000000000000000000", "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf");
        check("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4");
        check("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47");
        check("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "", "", "", "530f8afbc74536b9a963b4f1c4cb738b");
        check("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "00000000000000000000000000000000", "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919");
        check("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b");
    }
}
