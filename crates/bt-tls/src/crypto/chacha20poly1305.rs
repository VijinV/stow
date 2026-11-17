//! ChaCha20-Poly1305 AEAD (RFC 8439). Constant-time (ARX + 44-bit-limb Poly1305).

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([nonce[4 * i], nonce[4 * i + 1], nonce[4 * i + 2], nonce[4 * i + 3]]);
    }
    s
}

#[inline(always)]
fn block_words(init: &[u32; 16]) -> [u32; 16] {
    let mut x = *init;
    for _ in 0..10 {
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 1, 5, 9, 13);
        qr(&mut x, 2, 6, 10, 14);
        qr(&mut x, 3, 7, 11, 15);
        qr(&mut x, 0, 5, 10, 15);
        qr(&mut x, 1, 6, 11, 12);
        qr(&mut x, 2, 7, 8, 13);
        qr(&mut x, 3, 4, 9, 14);
    }
    for i in 0..16 {
        x[i] = x[i].wrapping_add(init[i]);
    }
    x
}

/// One ChaCha20 keystream block.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let w = block_words(&init_state(key, counter, nonce));
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&w[i].to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream starting at block `counter`.
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut st = init_state(key, counter, nonce);
    for chunk in data.chunks_mut(64) {
        let w = block_words(&st);
        if chunk.len() == 64 {
            for i in 0..16 {
                let v = u32::from_le_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]) ^ w[i];
                chunk[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
            }
        } else {
            let mut ks = [0u8; 64];
            for i in 0..16 {
                ks[4 * i..4 * i + 4].copy_from_slice(&w[i].to_le_bytes());
            }
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= k;
            }
        }
        st[12] = st[12].wrapping_add(1);
    }
}

/// Poly1305 one-time authenticator (44/44/42-bit limbs).
pub struct Poly1305 {
    r: [u64; 3],
    s: [u64; 3], // r*20 precomputed for limbs 1,2
    h: [u64; 3],
    pad: [u64; 2],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        let r0 = t0 & 0xffc0fffffff;
        let r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
        let r2 = (t1 >> 24) & 0x00ffffffc0f;
        Poly1305 {
            r: [r0, r1, r2],
            s: [0, r1 * (5 << 2), r2 * (5 << 2)],
            h: [0; 3],
            pad: [
                u64::from_le_bytes(key[16..24].try_into().unwrap()),
                u64::from_le_bytes(key[24..32].try_into().unwrap()),
            ],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    #[inline(always)]
    fn blocks(&mut self, m: &[u8], hibit: u64) {
        let [r0, r1, r2] = self.r;
        let s1 = self.s[1];
        let s2 = self.s[2];
        let [mut h0, mut h1, mut h2] = self.h;
        for blk in m.chunks_exact(16) {
            let t0 = u64::from_le_bytes(blk[0..8].try_into().unwrap());
            let t1 = u64::from_le_bytes(blk[8..16].try_into().unwrap());
            h0 += t0 & 0xfffffffffff;
            h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffff;
            h2 += ((t1 >> 24) & 0x3ffffffffff) | hibit;
            let m = |a: u64, b: u64| a as u128 * b as u128;
            let d0 = m(h0, r0) + m(h1, s2) + m(h2, s1);
            let d1 = m(h0, r1) + m(h1, r0) + m(h2, s2);
            let d2 = m(h0, r2) + m(h1, r1) + m(h2, r0);
            let mut c = (d0 >> 44) as u64;
            h0 = d0 as u64 & 0xfffffffffff;
            let d1 = d1 + c as u128;
            c = (d1 >> 44) as u64;
            h1 = d1 as u64 & 0xfffffffffff;
            let d2 = d2 + c as u128;
            c = (d2 >> 42) as u64;
            h2 = d2 as u64 & 0x3ffffffffff;
            h0 += c * 5;
            c = h0 >> 44;
            h0 &= 0xfffffffffff;
            h1 += c;
        }
        self.h = [h0, h1, h2];
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let b = self.buf;
                self.blocks(&b, 1 << 40);
                self.buf_len = 0;
            }
        }
        let full = data.len() & !15;
        if full > 0 {
            self.blocks(&data[..full], 1 << 40);
        }
        let rest = &data[full..];
        if !rest.is_empty() {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.buf_len = rest.len();
        }
    }

    /// Feeds zero padding up to a multiple of 16 bytes (AEAD construction).
    pub fn pad16(&mut self) {
        if self.buf_len > 0 {
            for b in &mut self.buf[self.buf_len..] {
                *b = 0;
            }
            let b = self.buf;
            self.blocks(&b, 1 << 40);
            self.buf_len = 0;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut b = [0u8; 16];
            b[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            b[self.buf_len] = 1;
            self.blocks(&b, 0);
        }
        let [mut h0, mut h1, mut h2] = self.h;
        let mut c;
        c = h1 >> 44; h1 &= 0xfffffffffff; h2 += c;
        c = h2 >> 42; h2 &= 0x3ffffffffff; h0 += c * 5;
        c = h0 >> 44; h0 &= 0xfffffffffff; h1 += c;
        c = h1 >> 44; h1 &= 0xfffffffffff; h2 += c;
        c = h2 >> 42; h2 &= 0x3ffffffffff; h0 += c * 5;
        c = h0 >> 44; h0 &= 0xfffffffffff; h1 += c;
        // compute h + -p
        let mut g0 = h0 + 5;
        c = g0 >> 44; g0 &= 0xfffffffffff;
        let mut g1 = h1 + c;
        c = g1 >> 44; g1 &= 0xfffffffffff;
        let g2 = (h2 + c).wrapping_sub(1 << 42);
        // select h if h < p, else g
        let mask = (g2 >> 63).wrapping_sub(1); // all ones if g2 did not underflow
        let g0 = g0 & mask; let g1 = g1 & mask; let g2 = g2 & mask;
        let nm = !mask;
        h0 = (h0 & nm) | g0;
        h1 = (h1 & nm) | g1;
        h2 = (h2 & nm) | g2;
        // h = h + pad
        let t0 = self.pad[0];
        let t1 = self.pad[1];
        h0 += t0 & 0xfffffffffff;
        c = h0 >> 44; h0 &= 0xfffffffffff;
        h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c;
        c = h1 >> 44; h1 &= 0xfffffffffff;
        h2 += ((t1 >> 24) & 0x3ffffffffff) + c;
        h2 &= 0x3ffffffffff;
        let o0 = h0 | (h1 << 44);
        let o1 = (h1 >> 20) | (h2 << 24);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&o0.to_le_bytes());
        out[8..].copy_from_slice(&o1.to_le_bytes());
        out
    }
}

pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(key);
    p.update(msg);
    p.finalize()
}

fn compute_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    let mut p = Poly1305::new(&otk);
    p.update(aad);
    p.pad16();
    p.update(ct);
    p.pad16();
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    p.update(&lens);
    p.finalize()
}

pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }
    /// Encrypts in place, returns the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        chacha20_xor(&self.key, 1, nonce, data);
        compute_tag(&self.key, nonce, aad, data)
    }
    /// Verifies the tag then decrypts in place. Returns false (data untouched) on failure.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        let t = compute_tag(&self.key, nonce, aad, data);
        if !super::util::ct_eq(&t, tag) {
            return false;
        }
        chacha20_xor(&self.key, 1, nonce, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::{hex, unhex};

    #[test]
    fn rfc8439_block() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = unhex("000000090000004a00000000").unwrap().try_into().unwrap();
        let b = chacha20_block(&key, 1, &nonce);
        assert_eq!(hex(&b), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }

    #[test]
    fn rfc8439_poly1305() {
        let key: [u8; 32] = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap().try_into().unwrap();
        assert_eq!(hex(&poly1305(&key, b"Cryptographic Forum Research Group")), "a8061dc1305136c6c22b8baf0c0127a9");
        // incremental splits
        let msg = b"Cryptographic Forum Research Group";
        for s in 0..msg.len() {
            let mut p = Poly1305::new(&key);
            p.update(&msg[..s]);
            p.update(&msg[s..]);
            assert_eq!(hex(&p.finalize()), "a8061dc1305136c6c22b8baf0c0127a9");
        }
        // edge: h near p (RFC 8439 A.3 #11-ish): key r=1? Use test vector 5: r=2, s=0, msg = ff*16
        let mut k = [0u8; 32];
        k[0] = 2;
        assert_eq!(hex(&poly1305(&k, &[0xff; 16])), "03000000000000000000000000000000");
        // vector 6: key r=2, s = ff*16, msg = 02 00..
        let mut k = [0u8; 32];
        k[0] = 2;
        for b in &mut k[16..] { *b = 0xff; }
        let mut m = [0u8; 16];
        m[0] = 2;
        assert_eq!(hex(&poly1305(&k, &m)), "03000000000000000000000000000000");
        // vector 7: r=1, msg = ff*16 || f0 ff*15 || 11 00*15 -> 05 00..
        let mut k = [0u8; 32];
        k[0] = 1;
        let mut m = vec![0xffu8; 16];
        m.push(0xf0); m.extend_from_slice(&[0xff; 15]);
        m.push(0x11); m.extend_from_slice(&[0; 15]);
        assert_eq!(hex(&poly1305(&k, &m)), "05000000000000000000000000000000");
    }

    #[test]
    fn rfc8439_aead() {
        let key: [u8; 32] = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap().try_into().unwrap();
        let nonce: [u8; 12] = unhex("070000004041424344454647").unwrap().try_into().unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = pt.to_vec();
        let a = ChaCha20Poly1305::new(&key);
        let tag = a.seal(&nonce, &aad, &mut data);
        assert_eq!(hex(&data), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");
        assert!(a.open(&nonce, &aad, &mut data, &tag));
        assert_eq!(&data[..], &pt[..]);
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!a.open(&nonce, &aad, &mut data.clone(), &bad));
    }
}
