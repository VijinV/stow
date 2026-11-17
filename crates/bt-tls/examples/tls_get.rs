//! Fetches `/` (or a path) over TLS 1.3 and prints the response head.
//! Usage: cargo run -p bt-tls --example tls_get -- HOST [PORT] [PATH] [CA_PEM]
use bt_tls::{RootStore, TlsStream};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let host = a.get(1).expect("usage: tls_get HOST [PORT] [PATH] [CA_PEM]");
    let port: u16 = a.get(2).map(|p| p.parse().unwrap()).unwrap_or(443);
    let path = a.get(3).map(|s| s.as_str()).unwrap_or("/");
    let mut roots = RootStore::system();
    if let Some(ca) = a.get(4) {
        roots.add_pem_file(std::path::Path::new(ca)).unwrap();
    }
    let t = std::time::Instant::now();
    let mut s = match TlsStream::connect(host, port, &Arc::new(roots), Duration::from_secs(15)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("handshake ok in {:?} using {}", t.elapsed(), s.cipher_suite());
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let r = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    for l in text.lines().take(12) {
        println!("{l}");
    }
    eprintln!("received {} bytes ({:?})", buf.len(), r.err());
}
