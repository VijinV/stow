//! End-to-end tests against `openssl s_server -tls1_3` with a throwaway test CA.
//! Skipped (with a message) if the `openssl` binary is not available.
use bt_tls::crypto::sha256::sha256;
use bt_tls::{RootStore, TlsStream};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl").args(args).current_dir(dir).output().expect("openssl");
    assert!(out.status.success(), "openssl {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
}

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().map(|o| o.status.success()).unwrap_or(false)
}

/// Builds a CA and leaf certificates once per test run.
fn pki() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("bt-tls-pki-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = &dir;
        std::fs::write(d.join("leaf.ext"), "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
        std::fs::write(d.join("inter.ext"), "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n").unwrap();
        openssl(d, &["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=bt-tls Test Root", "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE"]);
        // Intermediate CA (P-256) signed by the root
        openssl(d, &["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "inter.key", "-out", "inter.csr", "-subj", "/CN=bt-tls Test Intermediate"]);
        openssl(d, &["x509", "-req", "-in", "inter.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "inter.pem", "-days", "30", "-extfile", "inter.ext"]);
        let leaf = |name: &str, keyspec: &[&str], extra: &[&str], ca: &str| {
            let mut a = vec!["req", "-newkey"];
            a.extend_from_slice(keyspec);
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let pem = format!("{name}.pem");
            a.extend_from_slice(&["-nodes", "-keyout", &key, "-out", &csr, "-subj", "/CN=localhost"]);
            openssl(d, &a);
            let cakey = format!("{ca}.key");
            let capem = format!("{ca}.pem");
            let mut b = vec!["x509", "-req", "-in", &csr, "-CA", &capem, "-CAkey", &cakey, "-CAcreateserial", "-out", &pem, "-extfile", "leaf.ext"];
            b.extend_from_slice(extra);
            openssl(d, &b);
        };
        leaf("rsa", &["rsa:2048"], &["-days", "30"], "ca");
        leaf("p256", &["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], &["-days", "30"], "ca");
        leaf("p384", &["ec", "-pkeyopt", "ec_paramgen_curve:P-384"], &["-days", "30"], "ca");
        leaf("viainter", &["ec", "-pkeyopt", "ec_paramgen_curve:P-384"], &["-days", "30"], "inter");
        leaf("expired", &["rsa:2048"], &["-not_before", "20200101000000Z", "-not_after", "20210101000000Z"], "ca");
        openssl(d, &["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "self.key", "-out", "self.pem", "-subj", "/CN=localhost", "-days", "30", "-addext", "subjectAltName=DNS:localhost"]);
        let big: Vec<u8> = (0..1_048_576u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        std::fs::write(d.join("big.bin"), &big).unwrap();
        dir
    })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// openssl servers are started one at a time to keep ports and output simple
static LOCK: Mutex<()> = Mutex::new(());

fn roots() -> Arc<RootStore> {
    let mut r = RootStore::empty();
    assert_eq!(r.add_pem_file(&pki().join("ca.pem")).unwrap(), 1);
    Arc::new(r)
}

/// Starts s_server, waiting for the port without consuming its single accept.
fn start_ready(cert: &str, suite: &str, mode: &[&str], chain: Option<&str>, stdout: Stdio) -> Server {
    let dir = pki();
    let port = free_port();
    let p = port.to_string();
    let key = format!("{}.key", cert.trim_end_matches(".pem"));
    let mut args = vec!["s_server", "-accept", &p, "-tls1_3", "-ciphersuites", suite, "-cert", cert, "-key", &key, "-naccept", "1"];
    if let Some(c) = chain {
        args.extend_from_slice(&["-cert_chain", c]);
    }
    args.extend_from_slice(mode);
    let child = Command::new("openssl").args(&args).current_dir(dir).stdin(Stdio::piped()).stdout(stdout).stderr(Stdio::null()).spawn().unwrap();
    // poll /proc/net/tcp-free approach: retry connect inside the test with backoff instead
    std::thread::sleep(Duration::from_millis(300));
    Server { child, port }
}

fn connect_retry(port: u16, host: &str, roots: &Arc<RootStore>) -> std::io::Result<TlsStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(20)))?;
                return TlsStream::handshake(s, host, roots);
            }
            Err(e) => {
                if Instant::now() > deadline {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

const SUITES: [&str; 3] = ["TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"];

#[test]
fn download_1mb_all_keys_and_suites() {
    if !have_openssl() {
        eprintln!("openssl not found; skipping");
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let want = sha256(&std::fs::read(pki().join("big.bin")).unwrap());
    let roots = roots();
    for (cert, chain) in [("rsa.pem", None), ("p256.pem", None), ("p384.pem", None), ("viainter.pem", Some("inter.pem"))] {
        for suite in SUITES {
            let srv = start_ready(cert, suite, &["-HTTP"], chain, Stdio::null());
            let mut s = connect_retry(srv.port, "localhost", &roots).unwrap_or_else(|e| panic!("{cert} {suite}: {e}"));
            assert_eq!(s.cipher_suite(), suite);
            s.write_all(b"GET /big.bin HTTP/1.0\r\n\r\n").unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap_or_else(|e| panic!("{cert} {suite}: {e}"));
            // s_server -HTTP sends a header only for some file types
            let body_at = if buf.starts_with(b"HTTP/") { buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4 } else { 0 };
            assert_eq!(buf.len() - body_at, 1_048_576, "{cert} {suite}");
            assert_eq!(sha256(&buf[body_at..]), want, "{cert} {suite}");
            println!("ok download {cert} {suite}");
        }
    }
}

#[test]
fn upload_1mb_all_suites() {
    if !have_openssl() {
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let data = std::fs::read(pki().join("big.bin")).unwrap();
    let roots = roots();
    for suite in SUITES {
        let out_path = pki().join(format!("upload-{suite}.bin"));
        let f = std::fs::File::create(&out_path).unwrap();
        let mut srv = start_ready("p256.pem", suite, &["-quiet"], None, Stdio::from(f));
        let mut s = connect_retry(srv.port, "127.0.0.1", &roots).unwrap();
        s.write_all(&data).unwrap();
        s.flush().unwrap();
        s.close();
        // wait for s_server to finish writing
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let n = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
            if n >= data.len() as u64 || Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = srv.child.kill();
        let got = std::fs::read(&out_path).unwrap();
        assert_eq!(got.len(), data.len(), "{suite}");
        assert!(got == data, "{suite}: upload corrupted");
        println!("ok upload {suite}");
    }
}

#[test]
fn rejects_bad_certificates() {
    if !have_openssl() {
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let roots = roots();
    let cases: [(&str, &str, &str); 4] = [
        ("expired.pem", "localhost", "expired"),
        ("rsa.pem", "wrong.example", "hostname mismatch"),
        ("self.pem", "localhost", "unknown issuer"),
        ("viainter.pem", "localhost", "unknown issuer"), // intermediate not sent
    ];
    for (cert, host, want) in cases {
        let srv = start_ready(cert, SUITES[0], &["-HTTP"], None, Stdio::null());
        let e = match connect_retry(srv.port, host, &roots) {
            Ok(_) => panic!("{cert}/{host} unexpectedly accepted"),
            Err(e) => e.to_string(),
        };
        println!("{cert}/{host}: {e}");
        assert!(e.contains(want), "{cert}/{host}: {e}");
    }
    // A self-signed certificate explicitly added to the store is accepted.
    let mut r = RootStore::empty();
    r.add_pem_file(&pki().join("self.pem")).unwrap();
    let srv = start_ready("self.pem", SUITES[1], &["-HTTP"], None, Stdio::null());
    connect_retry(srv.port, "localhost", &Arc::new(r)).expect("explicitly trusted self-signed cert");
}

#[test]
fn key_update_from_server() {
    if !have_openssl() {
        return;
    }
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // s_server: typing "K" on stdin sends a KeyUpdate requesting an update; "k" without.
    let roots = roots();
    let mut srv = start_ready("p256.pem", SUITES[0], &[], None, Stdio::null());
    let mut s = connect_retry(srv.port, "localhost", &roots).unwrap();
    s.write_all(b"hello\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    {
        let stdin = srv.child.stdin.as_mut().unwrap();
        stdin.write_all(b"K\n").unwrap();
        stdin.flush().unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    {
        let stdin = srv.child.stdin.as_mut().unwrap();
        stdin.write_all(b"after-update\n").unwrap();
        stdin.flush().unwrap();
    }
    let mut got = Vec::new();
    let mut b = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(10);
    while !String::from_utf8_lossy(&got).contains("after-update") && Instant::now() < deadline {
        let n = s.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&b[..n]);
    }
    assert!(String::from_utf8_lossy(&got).contains("after-update"), "{:?}", String::from_utf8_lossy(&got));
    // our side updated its write key in response; the server must still read us
    s.write_all(b"still-talking\n").unwrap();
}

