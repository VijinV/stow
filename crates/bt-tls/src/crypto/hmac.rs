//! HMAC (RFC 2104) over SHA-256 / SHA-384 / SHA-512.
use super::hash::{HashAlg, Hasher};
use super::sha256::Sha256;

pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&super::sha256::sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        let mut outer = Sha256::new();
        outer.update(&opad);
        HmacSha256 { inner, outer }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    pub fn finalize(self) -> [u8; 32] {
        let ih = self.inner.finalize();
        let mut o = self.outer;
        o.update(&ih);
        o.finalize()
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

/// Generic HMAC over a runtime-selected hash.
pub struct Hmac {
    inner: Hasher,
    outer: Hasher,
}

impl Hmac {
    pub fn new(alg: HashAlg, key: &[u8]) -> Self {
        let bl = alg.block_len();
        let mut k = vec![0u8; bl];
        if key.len() > bl {
            let d = alg.hash(key);
            k[..d.len()].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = alg.hasher();
        let mut outer = alg.hasher();
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        inner.update(&ipad);
        outer.update(&opad);
        Hmac { inner, outer }
    }
    pub fn update(&mut self, d: &[u8]) {
        self.inner.update(d);
    }
    pub fn finalize(self) -> Vec<u8> {
        let ih = self.inner.finalize();
        let mut o = self.outer;
        o.update(&ih);
        o.finalize()
    }
}

pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = Hmac::new(alg, key);
    h.update(data);
    h.finalize()
}

pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let mut o = [0u8; 48];
    o.copy_from_slice(&hmac(HashAlg::Sha384, key, data));
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::hex;
    #[test]
    fn rfc4231() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        assert_eq!(
            hex(&hmac_sha384(&[0x0b; 20], b"Hi There")),
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        );
        assert_eq!(
            hex(&hmac(HashAlg::Sha512, &[0x0b; 20], b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        assert_eq!(
            hex(&hmac(HashAlg::Sha384, &[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        );
        assert_eq!(hex(&hmac(HashAlg::Sha256, b"Jefe", b"what do ya want for nothing?")), hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")));
    }
}
