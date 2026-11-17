//! Live TLS tests against public servers. Run with: cargo test -p bt-tls --test live -- --ignored
use bt_tls::{RootStore, TlsStream};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

fn get(host: &str) -> Result<(String, String), String> {
    let roots = Arc::new(RootStore::system());
    let mut s = TlsStream::connect(host, 443, &roots, Duration::from_secs(15)).map_err(|e| e.to_string())?;
    let suite = s.cipher_suite().to_string();
    write!(s, "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: bt-tls-test\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                // some servers close without close_notify after Connection: close
                if buf.is_empty() {
                    return Err(e.to_string());
                }
                break;
            }
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    s.close();
    let text = String::from_utf8_lossy(&buf);
    Ok((text.lines().next().unwrap_or("").to_string(), suite))
}

#[test]
#[ignore]
fn live_good_hosts() {
    for h in [
        "s3.amazonaws.com", "s3.ap-south-1.amazonaws.com", "www.google.com", "www.cloudflare.com", "github.com",
        // other S3-compatible providers
        "s3.us-west-002.backblazeb2.com", "s3.wasabisys.com", "storage.googleapis.com", "nyc3.digitaloceanspaces.com",
    ] {
        let (status, suite) = get(h).unwrap_or_else(|e| panic!("{h}: {e}"));
        println!("{h}: {status} [{suite}]");
        assert!(status.starts_with("HTTP/1.1 "), "{h}: {status}");
    }
}

#[test]
#[ignore]
fn live_bad_hosts() {
    // Expired certificate on a TLS 1.3 server.
    let e = get("expired-rsa-dv.ssl.com").unwrap_err();
    println!("expired-rsa-dv.ssl.com: {e}");
    assert!(e.contains("expired"), "{e}");
    // Hostname mismatch: talk to github.com but ask for another name.
    let sock = std::net::TcpStream::connect(("github.com", 443)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let e = TlsStream::handshake(sock, "not-github.example.com", &RootStore::system()).err().unwrap().to_string();
    println!("github.com as not-github.example.com: {e}");
    assert!(e.contains("hostname mismatch") || e.contains("alert"), "{e}");
    // Untrusted root: no anchors.
    let e = TlsStream::connect("www.google.com", 443, &Arc::new(RootStore::empty()), Duration::from_secs(15)).err().unwrap().to_string();
    println!("google with empty root store: {e}");
    assert!(e.contains("unknown issuer"), "{e}");
    // badssl.com only speaks TLS <= 1.2: must fail with a clear message.
    for h in ["expired.badssl.com", "self-signed.badssl.com", "untrusted-root.badssl.com", "wrong.host.badssl.com"] {
        let e = get(h).unwrap_err();
        println!("{h}: {e}");
        assert!(e.contains("TLS 1.3") || e.contains("expired") || e.contains("unknown issuer") || e.contains("hostname"), "{h}: {e}");
    }
}
