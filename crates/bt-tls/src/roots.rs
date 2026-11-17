//! Trust anchors: loaded from the operating system plus a small built-in fallback set.
use crate::crypto::sha256::sha256;
use crate::x509::{names_equal, Certificate, PublicKey};
use std::path::Path;

pub struct Anchor {
    pub subject: Vec<u8>,
    pub key: PublicKey,
    pub fingerprint: [u8; 32],
}

#[derive(Default)]
pub struct RootStore {
    anchors: Vec<Anchor>,
}

const FALLBACK_PEM: &str = include_str!("data/fallback_roots.pem");

impl RootStore {
    pub fn empty() -> Self {
        RootStore { anchors: Vec::new() }
    }

    /// The operating system's trusted roots (plus the built-in fallback set).
    pub fn system() -> Self {
        let mut s = RootStore::empty();
        s.load_os();
        // Windows populates its ROOT store lazily, and some systems have no bundle:
        // always add the small fallback set (duplicates are skipped).
        s.add_pem(FALLBACK_PEM);
        s
    }

    /// Only the built-in fallback roots (useful for tests).
    pub fn builtin() -> Self {
        let mut s = RootStore::empty();
        s.add_pem(FALLBACK_PEM);
        s
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn load_os(&mut self) {
        if let Ok(f) = std::env::var("SSL_CERT_FILE") {
            let _ = self.add_pem_file(Path::new(&f));
        }
        for p in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
            "/usr/local/share/certs/ca-root-nss.crt",
            "/etc/certs/ca-certificates.crt",
        ] {
            if let Ok(n) = self.add_pem_file(Path::new(p)) {
                if n > 0 {
                    return;
                }
            }
        }
        // Fall back to a directory of individual PEM files.
        if let Ok(rd) = std::fs::read_dir("/etc/ssl/certs") {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().map_or(false, |x| x == "pem" || x == "crt") {
                    let _ = self.add_pem_file(&p);
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn load_os(&mut self) {
        if let Ok(f) = std::env::var("SSL_CERT_FILE") {
            let _ = self.add_pem_file(Path::new(&f));
        }
        // Apple ships the system trust bundle as PEM here (kept in sync with the keychain roots).
        for p in ["/etc/ssl/cert.pem", "/private/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem", "/opt/homebrew/etc/ca-certificates/cert.pem"] {
            if let Ok(n) = self.add_pem_file(Path::new(p)) {
                if n > 0 {
                    return;
                }
            }
        }
    }

    #[cfg(windows)]
    fn load_os(&mut self) {
        use core::ffi::c_void;
        #[repr(C)]
        struct CertContext {
            encoding: u32,
            encoded: *const u8,
            encoded_len: u32,
            info: *mut c_void,
            store: *mut c_void,
        }
        #[link(name = "crypt32")]
        extern "system" {
            fn CertOpenSystemStoreW(prov: usize, name: *const u16) -> *mut c_void;
            fn CertEnumCertificatesInStore(store: *mut c_void, prev: *const CertContext) -> *const CertContext;
            fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
        }
        for name in ["ROOT", "CA"] {
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe {
                let store = CertOpenSystemStoreW(0, wide.as_ptr());
                if store.is_null() {
                    continue;
                }
                let mut ctx: *const CertContext = core::ptr::null();
                loop {
                    ctx = CertEnumCertificatesInStore(store, ctx);
                    if ctx.is_null() {
                        break;
                    }
                    let c = &*ctx;
                    // only the ROOT store holds anchors; CA holds intermediates which we skip
                    if name == "ROOT" && c.encoding & 1 == 1 && !c.encoded.is_null() {
                        let der = core::slice::from_raw_parts(c.encoded, c.encoded_len as usize);
                        self.add_der(der);
                    }
                }
                CertCloseStore(store, 0);
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn load_os(&mut self) {}

    /// Adds every CERTIFICATE block in a PEM string. Returns how many were added.
    pub fn add_pem(&mut self, pem: &str) -> usize {
        let mut n = 0;
        let mut rest = pem;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let after = &rest[start + 27..];
            let end = match after.find("-----END CERTIFICATE-----") {
                Some(e) => e,
                None => break,
            };
            if let Some(der) = crate::crypto::base64::decode(&after[..end]) {
                if self.add_der(&der) {
                    n += 1;
                }
            }
            rest = &after[end + 25..];
        }
        n
    }

    pub fn add_pem_file(&mut self, path: &Path) -> std::io::Result<usize> {
        let s = std::fs::read(path)?;
        Ok(self.add_pem(&String::from_utf8_lossy(&s)))
    }

    /// Adds a DER certificate as a trust anchor. Returns false if unparsable or duplicate.
    pub fn add_der(&mut self, der: &[u8]) -> bool {
        let fp = sha256(der);
        if self.anchors.iter().any(|a| a.fingerprint == fp) {
            return false;
        }
        let c = match Certificate::parse(der) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let key = match c.public_key {
            Some(k) => k,
            None => return false,
        };
        self.anchors.push(Anchor { subject: c.subject, key, fingerprint: fp });
        true
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn anchors_for<'a>(&'a self, issuer: &'a [u8]) -> impl Iterator<Item = &'a Anchor> + 'a {
        self.anchors.iter().filter(move |a| names_equal(&a.subject, issuer))
    }

    pub fn contains_exact(&self, der: &[u8]) -> bool {
        let fp = sha256(der);
        self.anchors.iter().any(|a| a.fingerprint == fp)
    }
}
