//! RSA / ECDSA / X.509 tests against vectors generated with the openssl CLI.
use bt_tls::crypto::hash::HashAlg;
use bt_tls::x509::{self, parse_spki, verify_signature, Certificate, PublicKey, SigAlg};
use bt_tls::RootStore;

macro_rules! data {
    ($f:expr) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $f))
    };
}

const MSG: &[u8] = data!("msg.bin");

fn key(d: &[u8]) -> PublicKey {
    parse_spki(d).expect("spki")
}

fn check(k: &PublicKey, alg: SigAlg, sig: &[u8]) {
    assert!(verify_signature(k, alg, MSG, sig), "{alg:?} should verify");
    let mut bad_msg = MSG.to_vec();
    bad_msg[3] ^= 1;
    assert!(!verify_signature(k, alg, &bad_msg, sig), "{alg:?} must reject modified message");
    let mut bad_sig = sig.to_vec();
    let i = bad_sig.len() - 5;
    bad_sig[i] ^= 0x40;
    assert!(!verify_signature(k, alg, MSG, &bad_sig), "{alg:?} must reject modified signature");
}

#[test]
fn rsa_pkcs1() {
    let k2 = key(data!("rsa2048.pub.der"));
    let k3 = key(data!("rsa3072.pub.der"));
    check(&k2, SigAlg::RsaPkcs1(HashAlg::Sha256), data!("rsa2048_pkcs1_sha256.sig"));
    check(&k2, SigAlg::RsaPkcs1(HashAlg::Sha384), data!("rsa2048_pkcs1_sha384.sig"));
    check(&k3, SigAlg::RsaPkcs1(HashAlg::Sha512), data!("rsa3072_pkcs1_sha512.sig"));
    // wrong hash / wrong key
    assert!(!verify_signature(&k2, SigAlg::RsaPkcs1(HashAlg::Sha384), MSG, data!("rsa2048_pkcs1_sha256.sig")));
    assert!(!verify_signature(&k3, SigAlg::RsaPkcs1(HashAlg::Sha256), MSG, data!("rsa2048_pkcs1_sha256.sig")));
    // PKCS1 signature must not pass as PSS
    assert!(!verify_signature(&k2, SigAlg::RsaPss(HashAlg::Sha256), MSG, data!("rsa2048_pkcs1_sha256.sig")));
}

#[test]
fn rsa_pss() {
    let k2 = key(data!("rsa2048.pub.der"));
    let k3 = key(data!("rsa3072.pub.der"));
    check(&k2, SigAlg::RsaPss(HashAlg::Sha256), data!("rsa2048_pss_sha256.sig"));
    check(&k2, SigAlg::RsaPss(HashAlg::Sha512), data!("rsa2048_pss_sha512.sig"));
    check(&k3, SigAlg::RsaPss(HashAlg::Sha384), data!("rsa3072_pss_sha384.sig"));
    if let PublicKey::Rsa(r) = &k2 {
        let d = HashAlg::Sha256.hash(MSG);
        assert!(r.verify_pss(HashAlg::Sha256, &d, data!("rsa2048_pss_sha256.sig"), Some(32)));
        assert!(!r.verify_pss(HashAlg::Sha256, &d, data!("rsa2048_pss_sha256.sig"), Some(20)));
    } else {
        panic!()
    }
}

#[test]
fn ecdsa() {
    let p256 = key(data!("p256.pub.der"));
    let p384 = key(data!("p384.pub.der"));
    check(&p256, SigAlg::Ecdsa(HashAlg::Sha256), data!("p256_sha256.sig"));
    check(&p256, SigAlg::Ecdsa(HashAlg::Sha384), data!("p256_sha384.sig"));
    check(&p384, SigAlg::Ecdsa(HashAlg::Sha384), data!("p384_sha384.sig"));
    check(&p384, SigAlg::Ecdsa(HashAlg::Sha256), data!("p384_sha256.sig"));
    assert!(!verify_signature(&p384, SigAlg::Ecdsa(HashAlg::Sha256), MSG, data!("p256_sha256.sig")));
}

fn pem_chain(pem: &str) -> Vec<Vec<u8>> {
    pem.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|b| bt_tls::crypto::base64::decode(b.split("-----END").next().unwrap()).unwrap())
        .collect()
}

#[test]
fn s3_chain_validates() {
    let chain = pem_chain(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/s3_chain.pem")));
    let leaf = Certificate::parse(&chain[0]).unwrap();
    let now = leaf.not_before + 86400;
    let roots = RootStore::builtin();
    assert!(roots.len() >= 15, "builtin roots: {}", roots.len());
    x509::verify_server_chain(&chain, &roots, "s3.amazonaws.com", now).unwrap();
    // Out-of-order chain still builds.
    let reordered = vec![chain[0].clone(), chain[2].clone(), chain[1].clone()];
    x509::verify_server_chain(&reordered, &roots, "s3.amazonaws.com", now).unwrap();
    // Hostname mismatch
    let e = x509::verify_server_chain(&chain, &roots, "example.com", now).unwrap_err();
    assert!(e.contains("hostname mismatch"), "{e}");
    // Expired
    let e = x509::verify_server_chain(&chain, &roots, "s3.amazonaws.com", leaf.not_after + 10).unwrap_err();
    assert!(e.contains("expired"), "{e}");
    // Unknown issuer (empty store)
    let e = x509::verify_server_chain(&chain, &RootStore::empty(), "s3.amazonaws.com", now).unwrap_err();
    assert!(e.contains("unknown issuer"), "{e}");
    // Missing intermediate
    let e = x509::verify_server_chain(&chain[..1], &roots, "s3.amazonaws.com", now).unwrap_err();
    assert!(e.contains("unknown issuer"), "{e}");
    // Tampered leaf signature
    let mut bad = chain.clone();
    let n = bad[0].len();
    bad[0][n - 3] ^= 1;
    assert!(x509::verify_server_chain(&bad, &roots, "s3.amazonaws.com", now).is_err());
}

#[test]
fn system_roots_load() {
    let r = RootStore::system();
    assert!(r.len() > 50, "system roots: {}", r.len());
}
