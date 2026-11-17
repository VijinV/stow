//! Runtime-selectable hash functions (used by HMAC/HKDF/TLS/signatures).
use super::{sha256::Sha256, sha512::{Sha384, Sha512}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone)]
pub enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
    pub fn block_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 64,
            _ => 128,
        }
    }
    pub fn hasher(self) -> Hasher {
        match self {
            HashAlg::Sha256 => Hasher::Sha256(Sha256::new()),
            HashAlg::Sha384 => Hasher::Sha384(Sha384::new()),
            HashAlg::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut h = self.hasher();
        h.update(data);
        h.finalize()
    }
}

impl Hasher {
    pub fn update(&mut self, d: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(d),
            Hasher::Sha384(h) => h.update(d),
            Hasher::Sha512(h) => h.update(d),
        }
    }
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}
