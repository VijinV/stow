//! Glue between the backup engine and the S3 client, with TLS provided by bt-tls.
use crate::config::{Config, S3Settings};
use crate::engine::Storage;
use bt_s3::{S3Client, S3Config, Stream, TlsConnector, UploadOptions};
use bt_tls::{RootStore, TlsStream};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// TLS connector backed by our own TLS 1.3 client.
pub struct BtTls {
    roots: Arc<RootStore>,
}

impl TlsConnector for BtTls {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> std::io::Result<Box<dyn Stream>> {
        Ok(Box::new(TlsStream::connect(host, port, &self.roots, timeout)?))
    }
}

/// System roots are loaded once; an extra CA file (self-hosted S3) is added on top.
fn roots(ca_file: &str) -> Result<Arc<RootStore>, String> {
    static CACHE: OnceLock<Mutex<Vec<(String, Arc<RootStore>)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut c = cache.lock().unwrap();
    if let Some((_, r)) = c.iter().find(|(k, _)| k == ca_file) {
        return Ok(r.clone());
    }
    let mut store = RootStore::system();
    if !ca_file.trim().is_empty() {
        let n = store
            .add_pem_file(Path::new(ca_file.trim()))
            .map_err(|e| format!("Cannot read CA certificate file {}: {}", ca_file, e))?;
        if n == 0 {
            return Err(format!("No certificates found in {}", ca_file));
        }
    }
    if store.len() == 0 {
        return Err("No trusted root certificates were found on this system.".into());
    }
    let r = Arc::new(store);
    c.push((ca_file.to_string(), r.clone()));
    Ok(r)
}

pub fn s3_config(s: &S3Settings) -> S3Config {
    S3Config {
        endpoint: s.endpoint.trim().to_string(),
        region: s.region.trim().to_string(),
        bucket: s.bucket.trim().to_string(),
        access_key: s.access_key.trim().to_string(),
        secret_key: s.secret_key.trim().to_string(),
        session_token: None,
        path_style: s.path_style,
    }
}

pub fn client(s: &S3Settings) -> Result<S3Client, String> {
    let cfg = s3_config(s);
    S3Client::validate_config(&cfg)?;
    let tls = Arc::new(BtTls { roots: roots(&s.ca_file)? });
    Ok(S3Client::new(cfg, tls))
}

/// Verify credentials + bucket. Returns a friendly summary or a friendly error.
pub fn test_connection(s: &S3Settings) -> Result<String, String> {
    if s.bucket.trim().is_empty() {
        return Err("Enter a bucket name.".into());
    }
    if s.access_key.trim().is_empty() || s.secret_key.trim().is_empty() {
        return Err("Enter your Access Key ID and Secret Access Key.".into());
    }
    let c = client(s)?;
    c.check_access().map_err(|e| e.to_string())
}

/// List the buckets these credentials can see (to help pick one).
pub fn list_buckets(s: &S3Settings) -> Result<Vec<String>, String> {
    let c = client(s)?;
    c.list_buckets().map_err(|e| e.to_string())
}

pub struct S3Storage {
    client: S3Client,
    opts: UploadOptions,
}

impl S3Storage {
    pub fn new(cfg: &Config) -> Result<S3Storage, String> {
        let client = client(&cfg.s3)?;
        let mut opts = UploadOptions::default();
        if !cfg.s3.storage_class.trim().is_empty() {
            opts.storage_class = Some(cfg.s3.storage_class.trim().to_string());
        }
        Ok(S3Storage { client, opts })
    }
}

fn mtime_meta(path: &Path) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Ok(t) = std::fs::metadata(path).and_then(|m| m.modified()) {
        if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
            v.push(("mtime".to_string(), d.as_secs().to_string()));
        }
    }
    v
}

impl Storage for S3Storage {
    fn upload_file(&self, key: &str, path: &Path, progress: &mut dyn FnMut(u64), cancel: &AtomicBool) -> Result<String, String> {
        let mut opts = self.opts.clone();
        opts.metadata = mtime_meta(path);
        self.client.upload_file(key, path, &opts, progress, cancel).map_err(|e| e.to_string())
    }
}
