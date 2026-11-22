//! Glue between the backup engine and the S3 client, with TLS provided by bt-tls.
use crate::config::{Config, S3Settings};
use crate::engine::Storage;
use bt_s3::{S3Client, S3Config, Stream, TlsConnector, UploadBudget, UploadOptions};
use bt_tls::{RootStore, TlsStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[path = "remote_resume.rs"]
mod resume;

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
pub(crate) fn roots(ca_file: &str) -> Result<Arc<RootStore>, String> {
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

pub fn validate_encryption(s: &S3Settings) -> Result<(), String> {
    if s.client_encryption { crate::file_crypto::validate_key(&s.recovery_key)?; }
    encryption_options(s).validate()
}
fn encryption_options(s: &S3Settings) -> UploadOptions {
    UploadOptions {
        server_encryption: (!s.server_encryption.trim().is_empty()).then(|| s.server_encryption.trim().to_string()),
        kms_key_id: (!s.kms_key_id.trim().is_empty()).then(|| s.kms_key_id.trim().to_string()),
        ..Default::default()
    }
}

pub fn client(s: &S3Settings) -> Result<S3Client, String> {
    if let Some(target) = &s.managed {
        return scoped_client(s, target.read_credentials("browse"));
    }
    validate_encryption(s)?;
    let cfg = s3_config(s);
    S3Client::validate_config(&cfg)?;
    let tls = Arc::new(BtTls { roots: roots(&s.ca_file)? });
    Ok(S3Client::new(cfg, tls))
}

pub(crate) fn scoped_client(s: &S3Settings, provider: Arc<dyn bt_s3::CredentialProvider>) -> Result<S3Client, String> {
    validate_encryption(s)?;
    Ok(S3Client::new(s3_config(s), Arc::new(BtTls { roots: roots("")? })).with_credentials(provider))
}

pub(crate) fn dashboard_http() -> Result<bt_s3::http::HttpClient, String> {
    let mut http = bt_s3::http::HttpClient::new(Arc::new(BtTls { roots: roots("")? }));
    http.connect_timeout = Duration::from_secs(4);
    http.io_timeout = Duration::from_secs(4);
    // The policy request can be 32 KiB before it is wrapped in a run reply.
    http.max_response_bytes = 64 * 1024;
    Ok(http)
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
    recovery_key: Option<String>,
    resume_root: PathBuf,
}

pub(crate) fn upload_resume_dir() -> PathBuf {
    crate::paths::app_dir().join(".upload-resume.tmp")
}

impl S3Storage {
    pub fn new(cfg: &Config) -> Result<S3Storage, String> {
        Self::from_client(cfg, client(&cfg.s3)?)
    }

    pub(crate) fn from_client(cfg: &Config, client: S3Client) -> Result<Self, String> {
        let mut opts = encryption_options(&cfg.s3);
        let limit = cfg.parallel_uploads.clamp(1, 16) as usize;
        opts.upload_budget = Some(Arc::new(UploadBudget::new(limit)));
        opts.multipart_parallelism = limit.min(4);
        opts.retain_completed_checkpoint = true;
        if !cfg.s3.storage_class.trim().is_empty() {
            opts.storage_class = Some(cfg.s3.storage_class.trim().to_string());
        }
        Ok(S3Storage {
            client,
            opts,
            recovery_key: cfg.s3.client_encryption.then(|| cfg.s3.recovery_key.clone()),
            resume_root: cfg.s3.managed.as_ref().map_or_else(upload_resume_dir, |target| upload_resume_dir().join(target.scope())),
        })
    }
}

fn mtime_meta(metadata: &std::fs::Metadata) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Ok(t) = metadata.modified() {
        if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
            v.push(("mtime".to_string(), d.as_secs().to_string()));
        }
    }
    v
}

impl Storage for S3Storage {
    fn upload_file(&self, key: &str, path: &Path, progress: &mut dyn FnMut(u64), cancel: &AtomicBool) -> Result<String, String> {
        let mut opts = self.opts.clone();
        let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
        let source_size = metadata.len();
        opts.metadata = mtime_meta(&metadata);
        if self.recovery_key.is_some() {
            opts.metadata.push(("bt-encrypted".into(), "BTENC001".into()));
        }
        let destination = self.client.upload_destination_id(key);
        let estimated_size = if self.recovery_key.is_some() {
            crate::file_crypto::encrypted_size(source_size)
        } else {
            source_size
        };
        let has_state = self.resume_root.join(&destination).try_exists().map_err(|e| e.to_string())?;
        if !opts.uses_multipart(estimated_size) && !has_state {
            if let Some(recovery_key) = &self.recovery_key {
                let (temp, file) = crate::file_crypto::private_temp(&std::env::temp_dir())?;
                drop(file);
                crate::file_crypto::encrypt_file_cancel(path, &temp.0, recovery_key, cancel)?;
                return self.upload_encrypted(key, &temp.0, source_size, &opts, progress, cancel);
            }
            return self.client.upload_file(key, path, &opts, progress, cancel).map_err(|e| e.to_string());
        }
        let slot = resume::ResumeSlot::lock(&self.resume_root, &destination, cancel)?;
        if let Some(recovery_key) = &self.recovery_key {
            let (payload, source_size) = slot.encrypted_source(path, recovery_key, &opts, cancel)?;
            let size = std::fs::metadata(&payload).map_err(|e| e.to_string())?.len();
            let multipart = opts.uses_multipart(size);
            opts.multipart_checkpoint = Some(slot.checkpoint(multipart)?);
            let result = self.upload_encrypted(key, &payload, source_size, &opts, progress, cancel);
            if !multipart {
                let _ = slot.clear_ciphertext();
            }
            result
        } else {
            // A policy change to plaintext invalidates the cached envelope.
            slot.clear_ciphertext().map_err(|e| format!("Could not clear encrypted upload resume data: {e}"))?;
            opts.multipart_checkpoint = Some(slot.checkpoint(opts.uses_multipart(source_size))?);
            self.client.upload_file(key, path, &opts, progress, cancel).map_err(|e| e.to_string())
        }
    }

    fn index_committed(&self, key: &str) {
        let destination = self.client.upload_destination_id(key);
        if !self.resume_root.join(&destination).exists() {
            return;
        }
        let result = resume::ResumeSlot::lock(&self.resume_root, &destination, &AtomicBool::new(false))
            .and_then(|slot| slot.clear_completed());
        if let Err(error) = result {
            crate::engine::log_line(&format!("Could not clear saved upload receipt for {key}: {error}"));
        }
    }
}

impl S3Storage {
    fn upload_encrypted(
        &self,
        key: &str,
        payload: &Path,
        mut remaining: u64,
        opts: &UploadOptions,
        progress: &mut dyn FnMut(u64),
        cancel: &AtomicBool,
    ) -> Result<String, String> {
        self.client.upload_file(key, payload, opts, &mut |bytes| {
            let delta = bytes.min(remaining);
            remaining -= delta;
            if delta > 0 {
                progress(delta);
            }
        }, cancel).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a local S3-compatible endpoint"]
    fn encrypted_storage_resumes_and_restores_original_bytes() {
        use std::fs;
        use std::sync::atomic::Ordering;

        let id = bt_tls::crypto::util::hex(&bt_tls::crypto::random::array::<16>().unwrap());
        let root = std::env::temp_dir().join(format!("stow-encrypted-resume-{id}"));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let bytes = vec![0x5a; (11 << 20) + 123];
        fs::write(&source, &bytes).unwrap();
        let recovery_key = crate::file_crypto::generate_key().unwrap();
        let mut cfg = Config::default();
        cfg.s3.endpoint = std::env::var("BT_S3_ENDPOINTS").ok()
            .and_then(|endpoints| endpoints.split(',').next().map(|e| e.trim().to_owned()))
            .unwrap_or_else(|| "http://127.0.0.1:9000".into());
        cfg.s3.bucket = format!("stow-encrypted-{id}");
        cfg.s3.access_key = std::env::var("BT_S3_KEY").unwrap_or_else(|_| "testkey".into());
        cfg.s3.secret_key = std::env::var("BT_S3_SECRET").unwrap_or_else(|_| "testsecret123".into());
        cfg.s3.client_encryption = true;
        cfg.s3.recovery_key = recovery_key.clone();

        let storage = || {
            let mut s = S3Storage::new(&cfg).unwrap();
            s.resume_root = root.join("state");
            s.opts.multipart_threshold = 5 << 20;
            s.opts.part_size = 5 << 20;
            s.opts.multipart_parallelism = 1;
            s
        };
        let cancel = AtomicBool::new(false);
        {
            let first = storage();
            first.client.create_bucket().unwrap();
            let res = first.upload_file("file", &source, &mut |n| {
                assert_eq!(n, 5 << 20);
                cancel.store(true, Ordering::Relaxed);
            }, &cancel);
            assert!(res.unwrap_err().contains("Cancelled"));
            assert_eq!(first.client.list_multipart_uploads("").unwrap().len(), 1);
        }
        cancel.store(false, Ordering::Relaxed);
        let second = storage();
        let state = second.resume_root.join(second.client.upload_destination_id("file"));
        assert!(state.join("ciphertext").is_file());
        let mut sent = 0;
        let etag = second.upload_file("file", &source, &mut |n| sent += n, &cancel).unwrap();
        assert_eq!(sent, bytes.len() as u64);
        assert!(state.join("multipart").is_file());
        assert!(state.join("ciphertext").is_file());
        assert!(second.client.list_multipart_uploads("").unwrap().is_empty());
        let meta = second.client.object_metadata("file").unwrap();
        assert!(meta.iter().any(|(key, value)| key == "bt-encrypted" && value == "BTENC001"));
        // A restart after S3 completed, but before Stow saved its index, recovers the same upload.
        let third = storage();
        assert_eq!(third.upload_file("file", &source, &mut |_| {}, &cancel).unwrap(), etag);
        assert_eq!(third.client.object_metadata("file").unwrap(), meta);
        third.index_committed("file");
        assert!(!state.exists());
        let downloaded = root.join("downloaded");
        second.client.get_object_to_file("file", &downloaded, &mut |_| {}, &cancel).unwrap();
        let restored = root.join("restored");
        assert!(crate::file_crypto::decrypt_file(&downloaded, &restored, &recovery_key).unwrap());
        assert_eq!(fs::read(restored).unwrap(), bytes);
        second.client.delete_object("file").unwrap();
        second.client.delete_bucket().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_bad_encryption_configuration_before_network_access() {
        let mut settings = S3Settings::default();
        settings.client_encryption = true;
        assert!(validate_encryption(&settings).is_err());
        settings.recovery_key = "ab".repeat(32);
        assert!(validate_encryption(&settings).is_ok());
        settings.server_encryption = "AES256".into();
        settings.kms_key_id = "key".into();
        assert!(validate_encryption(&settings).is_err());
        settings.server_encryption = "aws:kms".into();
        assert!(validate_encryption(&settings).is_ok());
    }
}
