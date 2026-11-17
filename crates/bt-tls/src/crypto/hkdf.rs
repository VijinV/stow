//! HKDF (RFC 5869).
use super::hash::HashAlg;
use super::hmac::{hmac, Hmac};

pub fn extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zero;
    let salt = if salt.is_empty() {
        zero = vec![0u8; alg.output_len()];
        &zero[..]
    } else {
        salt
    };
    hmac(alg, salt, ikm)
}

pub fn expand(alg: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 255 * alg.output_len());
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut h = Hmac::new(alg, prk);
        h.update(&t);
        h.update(info);
        h.update(&[i]);
        t = h.finalize();
        let take = (len - out.len()).min(t.len());
        out.extend_from_slice(&t[..take]);
        i = i.wrapping_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::{hex, unhex};
    #[test]
    fn rfc5869() {
        // Test case 1
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c").unwrap();
        let info = unhex("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let prk = extract(HashAlg::Sha256, &salt, &ikm);
        assert_eq!(hex(&prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert_eq!(hex(&expand(HashAlg::Sha256, &prk, &info, 42)), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        // Test case 3 (empty salt / info)
        let prk = extract(HashAlg::Sha256, &[], &ikm);
        assert_eq!(hex(&prk), "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        assert_eq!(hex(&expand(HashAlg::Sha256, &prk, &[], 42)), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
        // Test case 2 (long inputs)
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        let prk = extract(HashAlg::Sha256, &salt, &ikm);
        assert_eq!(hex(&prk), "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        assert_eq!(hex(&expand(HashAlg::Sha256, &prk, &info, 82)), "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }
}
