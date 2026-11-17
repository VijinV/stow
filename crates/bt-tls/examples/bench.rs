//! Release-mode throughput of the record ciphers and hashes.
//! cargo run --release -p bt-tls --example bench
use bt_tls::crypto::{aes_gcm::AesGcm, chacha20poly1305::ChaCha20Poly1305, md5, sha256};
use std::time::Instant;

fn mbps(bytes: usize, t: Instant) -> f64 {
    bytes as f64 / t.elapsed().as_secs_f64() / 1e6
}

fn main() {
    let total = 256 << 20;
    let mut rec = vec![0x5au8; 16384];
    let nonce = [1u8; 12];
    let c = ChaCha20Poly1305::new(&[7u8; 32]);
    let t = Instant::now();
    for _ in 0..total / rec.len() {
        std::hint::black_box(c.seal(&nonce, &[0; 5], &mut rec));
    }
    println!("ChaCha20-Poly1305 seal: {:.0} MB/s", mbps(total, t));
    for (name, key) in [("AES-128-GCM", vec![7u8; 16]), ("AES-256-GCM", vec![7u8; 32])] {
        let g = AesGcm::new(&key);
        let t = Instant::now();
        let n = 64 << 20;
        for _ in 0..n / rec.len() {
            std::hint::black_box(g.seal(&nonce, &[0; 5], &mut rec));
        }
        println!("{name} seal: {:.0} MB/s", mbps(n, t));
    }
    let t = Instant::now();
    let mut h = sha256::Sha256::new();
    for _ in 0..total / rec.len() {
        h.update(&rec);
    }
    std::hint::black_box(h.finalize());
    println!("SHA-256: {:.0} MB/s", mbps(total, t));
    let t = Instant::now();
    let mut h = md5::Md5::new();
    for _ in 0..total / rec.len() {
        h.update(&rec);
    }
    std::hint::black_box(h.finalize());
    println!("MD5: {:.0} MB/s", mbps(total, t));
}
