//! S3 API client.
use crate::error::S3Error;
use crate::http::{Body, HttpClient, Request, Response, TlsConnector, Url};
use crate::sigv4::{self, Credentials, EMPTY_SHA256};
use crate::{time, xml};
use bt_tls::crypto::sha256::Sha256;
use bt_tls::crypto::util::hex;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S3Config {
    /// Custom endpoint URL (e.g. `http://127.0.0.1:9000`); empty = Amazon S3.
    pub endpoint: String,
    /// Region; empty = auto-detect (starts with us-east-1).
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    /// Force path-style addressing (`endpoint/bucket/key`).
    pub path_style: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
    /// ETag without surrounding quotes.
    pub etag: String,
    pub last_modified: String,
}

#[derive(Clone, Debug)]
pub struct UploadOptions {
    pub part_size: u64,
    pub multipart_threshold: u64,
    pub content_type: Option<String>,
    pub metadata: Vec<(String, String)>,
    pub storage_class: Option<String>,
}

impl Default for UploadOptions {
    fn default() -> Self {
        UploadOptions {
            part_size: 16 * 1024 * 1024,
            multipart_threshold: 32 * 1024 * 1024,
            content_type: None,
            metadata: Vec::new(),
            storage_class: None,
        }
    }
}

/// Re-openable request body (needed for retries).
pub use crate::http::Body as BodySource;

pub struct BytesBody<'a>(pub &'a [u8]);
impl Body for BytesBody<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn open(&self) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(self.0))
    }
}

/// A byte range of a file on disk.
pub struct FileRange {
    pub path: PathBuf,
    pub offset: u64,
    pub len: u64,
}
impl Body for FileRange {
    fn len(&self) -> u64 {
        self.len
    }
    fn open(&self) -> io::Result<Box<dyn Read + '_>> {
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(self.offset))?;
        Ok(Box::new(f.take(self.len)))
    }
}

fn hash_body(b: &dyn Body) -> io::Result<String> {
    let mut r = b.open()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    if total != b.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "file changed size while reading"));
    }
    Ok(hex(&h.finalize()))
}

enum Target<'a> {
    Service,
    Bucket,
    Object(&'a str),
}

trait Sink: Write {
    fn reset(&mut self) -> io::Result<()>;
}
impl Sink for File {
    fn reset(&mut self) -> io::Result<()> {
        self.set_len(0)?;
        self.seek(SeekFrom::Start(0)).map(|_| ())
    }
}

struct Call<'a> {
    method: &'a str,
    target: Target<'a>,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Option<&'a dyn Body>,
    cancel: Option<&'a AtomicBool>,
}

impl<'a> Call<'a> {
    fn new(method: &'a str, target: Target<'a>) -> Self {
        Call { method, target, query: Vec::new(), headers: Vec::new(), body: None, cancel: None }
    }
    fn q(mut self, k: &str, v: &str) -> Self {
        self.query.push((k.into(), v.into()));
        self
    }
    fn h(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

const MAX_ATTEMPTS: u32 = 6;

pub struct S3Client {
    cfg: S3Config,
    endpoint: Option<Url>,
    region: RwLock<String>,
    clock_skew: AtomicI64,
    http: HttpClient,
}

fn strip_quotes(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

impl S3Client {
    pub fn new(cfg: S3Config, tls: Arc<dyn TlsConnector>) -> S3Client {
        let endpoint = if cfg.endpoint.trim().is_empty() {
            None
        } else {
            let e = cfg.endpoint.trim();
            let e = if e.contains("://") { e.to_string() } else { format!("https://{}", e) };
            Url::parse(&e).ok()
        };
        let region = if cfg.region.trim().is_empty() { "us-east-1".to_string() } else { cfg.region.trim().to_string() };
        S3Client { cfg, endpoint, region: RwLock::new(region), clock_skew: AtomicI64::new(0), http: HttpClient::new(tls) }
    }

    /// Validate the endpoint URL of a config; Err(message) if malformed.
    pub fn validate_config(cfg: &S3Config) -> Result<(), String> {
        if cfg.bucket.trim().is_empty() {
            return Err("Bucket name is required".into());
        }
        if cfg.access_key.trim().is_empty() || cfg.secret_key.is_empty() {
            return Err("Access Key and Secret Key are required".into());
        }
        if !cfg.endpoint.trim().is_empty() {
            let e = cfg.endpoint.trim();
            let e = if e.contains("://") { e.to_string() } else { format!("https://{}", e) };
            Url::parse(&e)?;
        }
        Ok(())
    }

    pub fn config(&self) -> &S3Config {
        &self.cfg
    }

    pub fn region(&self) -> String {
        self.region.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_region(&self, r: &str) {
        *self.region.write().unwrap_or_else(|e| e.into_inner()) = r.to_string();
    }

    fn uses_path_style(&self) -> bool {
        match &self.endpoint {
            None => self.cfg.path_style || self.cfg.bucket.contains('.'),
            Some(e) => self.cfg.path_style || e.is_ip_or_localhost(),
        }
    }

    /// Build the URL and canonical URI for a target.
    fn build_url(&self, target: &Target, query: &[(String, String)], region: &str) -> (Url, String) {
        let bucket = &self.cfg.bucket;
        let path_style = self.uses_path_style();
        let (scheme, base_host, port, base_path) = match &self.endpoint {
            None => {
                let suffix = if region.starts_with("cn-") { "amazonaws.com.cn" } else { "amazonaws.com" };
                ("https".to_string(), format!("s3.{}.{}", region, suffix), 443, String::new())
            }
            Some(e) => (e.scheme.clone(), e.host.clone(), e.port, e.path.trim_end_matches('/').to_string()),
        };
        let (host, path) = match target {
            Target::Service => (base_host, format!("{}/", base_path)),
            Target::Bucket if path_style => (base_host, format!("{}/{}", base_path, sigv4::uri_encode(bucket, false))),
            Target::Bucket => (format!("{}.{}", bucket, base_host), format!("{}/", base_path)),
            Target::Object(k) if path_style => (
                base_host,
                format!("{}/{}/{}", base_path, sigv4::uri_encode(bucket, false), sigv4::uri_encode(k, true)),
            ),
            Target::Object(k) => (format!("{}.{}", bucket, base_host), format!("{}/{}", base_path, sigv4::uri_encode(k, true))),
        };
        let url = Url { scheme, host: host.to_ascii_lowercase(), port, path: path.clone(), query: sigv4::canonical_query(query) };
        (url, path)
    }

    fn backoff(&self, attempt: u32, cancel: Option<&AtomicBool>) -> Result<(), S3Error> {
        let base = 250u64 << attempt.min(5);
        let jitter = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0) as u64) % (base / 2 + 1);
        let total = (base + jitter).min(10_000);
        let mut slept = 0;
        while slept < total {
            if cancel.map(|c| c.load(Ordering::Relaxed)).unwrap_or(false) {
                return Err(S3Error::cancelled());
            }
            std::thread::sleep(Duration::from_millis(50));
            slept += 50;
        }
        Ok(())
    }

    /// Perform a signed request with retries, region redirect and clock-skew handling.
    fn call(&self, c: &Call, mut sink: Option<&mut dyn Sink>, progress: &mut dyn FnMut(u64)) -> Result<Response, S3Error> {
        let is_cancelled = || c.cancel.map(|x| x.load(Ordering::Relaxed)).unwrap_or(false);
        let payload_hash = match c.body {
            None => EMPTY_SHA256.to_string(),
            Some(b) => hash_body(b).map_err(|e| S3Error::local(&e))?,
        };
        let creds = Credentials {
            access_key: self.cfg.access_key.trim(),
            secret_key: self.cfg.secret_key.trim(),
            session_token: self.cfg.session_token.as_deref(),
        };
        let mut high = 0u64;
        let mut attempt = 0u32;
        let mut region_retries = 0;
        let mut skew_retried = false;
        loop {
            if is_cancelled() {
                return Err(S3Error::cancelled());
            }
            attempt += 1;
            let region = self.region();
            let (url, curi) = self.build_url(&c.target, &c.query, &region);
            let mut headers = c.headers.clone();
            headers.push(("host".into(), url.host_header()));
            headers.push(("x-amz-content-sha256".into(), payload_hash.clone()));
            let now = time::now_unix() + self.clock_skew.load(Ordering::Relaxed);
            sigv4::sign(c.method, &curi, &c.query, &mut headers, &payload_hash, &creds, &region, "s3", &time::amz_date(now));
            if let Some(s) = sink.as_mut() {
                s.reset().map_err(|e| S3Error::local(&e))?;
            }
            let mut sent = 0u64;
            let mut prog = |n: u64| {
                sent += n;
                if sent > high {
                    progress(sent - high);
                    high = sent;
                }
            };
            let req = Request { method: c.method, url: &url, headers: &headers, body: c.body, cancel: c.cancel };
            let s: Option<&mut dyn Write> = match sink {
                Some(ref mut s) => Some(&mut **s as &mut dyn Write),
                None => None,
            };
            let resp = match self.http.send(&req, s, &mut prog) {
                Ok(r) => r,
                Err(e) => {
                    if is_cancelled() {
                        return Err(S3Error::cancelled());
                    }
                    let local = e.kind() == io::ErrorKind::UnexpectedEof && e.to_string().contains("file");
                    if local {
                        return Err(S3Error::local(&e));
                    }
                    if attempt < MAX_ATTEMPTS && e.kind() != io::ErrorKind::Unsupported {
                        self.backoff(attempt, c.cancel)?;
                        continue;
                    }
                    return Err(S3Error::network(&e));
                }
            };
            if (200..300).contains(&resp.status) {
                // CompleteMultipartUpload / CopyObject can return 200 with an error body.
                if resp.body.starts_with(b"<?xml") || resp.body.starts_with(b"<Error") {
                    if let Ok(doc) = xml::parse(&resp.body_text()) {
                        if doc.name == "Error" {
                            let err = error_from_doc(resp.status, &doc);
                            if attempt < MAX_ATTEMPTS && is_retryable_code(&err.code) {
                                self.backoff(attempt, c.cancel)?;
                                continue;
                            }
                            return Err(err);
                        }
                    }
                }
                return Ok(resp);
            }
            let (err, region_hint, server_time) = parse_error(&resp, c.method == "HEAD");
            if let Some(r) = region_hint {
                if r != region && region_retries < 2 {
                    region_retries += 1;
                    self.set_region(&r);
                    continue;
                }
            }
            if err.code == "RequestTimeTooSkewed" && !skew_retried {
                let server = server_time
                    .as_deref()
                    .and_then(time::parse_iso8601)
                    .or_else(|| resp.header("date").and_then(time::parse_http_date));
                if let Some(t) = server {
                    self.clock_skew.store(t - time::now_unix(), Ordering::Relaxed);
                    skew_retried = true;
                    continue;
                }
            }
            if attempt < MAX_ATTEMPTS
                && (matches!(resp.status, 500 | 502 | 503 | 504 | 429) || is_retryable_code(&err.code))
            {
                self.backoff(attempt, c.cancel)?;
                continue;
            }
            return Err(err);
        }
    }

    fn call_simple(&self, c: &Call) -> Result<Response, S3Error> {
        self.call(c, None, &mut |_| {})
    }

    /// Validate credentials and bucket access; detects and caches the bucket region.
    pub fn check_access(&self) -> Result<String, S3Error> {
        if let Err(m) = Self::validate_config(&self.cfg) {
            return Err(S3Error::new(0, "InvalidConfig", m));
        }
        let resp = self.call_simple(&Call::new("GET", Target::Bucket).q("list-type", "2").q("max-keys", "1"))?;
        if let Some(r) = resp.header("x-amz-bucket-region") {
            if !r.is_empty() && r != self.region() {
                self.set_region(r);
            }
        }
        let doc = xml::parse(&resp.body_text()).map_err(|e| S3Error::new(resp.status, "BadResponse", e))?;
        let has = doc.child_text("KeyCount").map(|k| k != "0").unwrap_or_else(|| doc.child("Contents").is_some());
        Ok(format!(
            "Connected to bucket '{}' (region {}){}",
            self.cfg.bucket,
            self.region(),
            if has { "" } else { " — bucket is empty" }
        ))
    }

    pub fn list_buckets(&self) -> Result<Vec<String>, S3Error> {
        let resp = self.call_simple(&Call::new("GET", Target::Service))?;
        let doc = xml::parse(&resp.body_text()).map_err(|e| S3Error::new(resp.status, "BadResponse", e))?;
        Ok(doc
            .child("Buckets")
            .map(|b| b.children_named("Bucket").filter_map(|x| x.child_text("Name").map(String::from)).collect())
            .unwrap_or_default())
    }

    /// Create the configured bucket (mostly for tests / first-time setup).
    pub fn create_bucket(&self) -> Result<(), S3Error> {
        let region = self.region();
        let body;
        let bb;
        let mut c = Call::new("PUT", Target::Bucket);
        if self.endpoint.is_none() && region != "us-east-1" {
            body = format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><LocationConstraint>{}</LocationConstraint></CreateBucketConfiguration>",
                xml::escape(&region)
            );
            bb = BytesBody(body.as_bytes());
            c.body = Some(&bb);
        }
        match self.call_simple(&c) {
            Ok(_) => Ok(()),
            Err(e) if e.code == "BucketAlreadyOwnedByYou" => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn delete_bucket(&self) -> Result<(), S3Error> {
        self.call_simple(&Call::new("DELETE", Target::Bucket)).map(|_| ())
    }

    fn object_headers(c: &mut Call, ct: Option<&str>, opts: Option<&UploadOptions>) {
        c.headers.push(("content-type".into(), ct.unwrap_or("application/octet-stream").into()));
        if let Some(o) = opts {
            for (k, v) in &o.metadata {
                c.headers.push((format!("x-amz-meta-{}", k.to_ascii_lowercase()), v.clone()));
            }
            if let Some(sc) = &o.storage_class {
                if !sc.is_empty() {
                    c.headers.push(("x-amz-storage-class".into(), sc.clone()));
                }
            }
        }
    }

    pub fn put_object_bytes(&self, key: &str, data: &[u8], content_type: Option<&str>) -> Result<String, S3Error> {
        let body = BytesBody(data);
        let mut c = Call::new("PUT", Target::Object(key));
        Self::object_headers(&mut c, content_type, None);
        c.body = Some(&body);
        let r = self.call_simple(&c)?;
        Ok(strip_quotes(r.header("etag").unwrap_or("")))
    }

    /// Upload a file, streaming it from disk. Uses multipart above the threshold.
    pub fn upload_file(
        &self,
        key: &str,
        path: &Path,
        opts: &UploadOptions,
        progress: &mut dyn FnMut(u64),
        cancel: &AtomicBool,
    ) -> Result<String, S3Error> {
        let size = fs::metadata(path).map_err(|e| S3Error::local(&e))?.len();
        let ct = opts.content_type.as_deref();
        if size < opts.multipart_threshold.max(5 * 1024 * 1024) {
            let body = FileRange { path: path.to_path_buf(), offset: 0, len: size };
            let mut c = Call::new("PUT", Target::Object(key));
            Self::object_headers(&mut c, ct, Some(opts));
            c.body = Some(&body);
            c.cancel = Some(cancel);
            let r = self.call(&c, None, progress)?;
            return Ok(strip_quotes(r.header("etag").unwrap_or("")));
        }

        // Multipart: at most 10,000 parts of >= 5 MiB.
        const MIB: u64 = 1024 * 1024;
        let mut part = opts.part_size.max(5 * MIB);
        let min_for_count = size.div_ceil(10_000);
        if part < min_for_count {
            part = min_for_count.div_ceil(MIB) * MIB;
        }
        let mut c = Call::new("POST", Target::Object(key)).q("uploads", "");
        Self::object_headers(&mut c, ct, Some(opts));
        c.cancel = Some(cancel);
        let r = self.call_simple(&c)?;
        let doc = xml::parse(&r.body_text()).map_err(|e| S3Error::new(r.status, "BadResponse", e))?;
        let upload_id = doc
            .child_text("UploadId")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| S3Error::new(r.status, "BadResponse", "no UploadId in CreateMultipartUpload response"))?
            .to_string();

        let result = (|| -> Result<String, S3Error> {
            let mut etags = Vec::new();
            let mut offset = 0u64;
            let mut n = 1u32;
            while offset < size {
                if cancel.load(Ordering::Relaxed) {
                    return Err(S3Error::cancelled());
                }
                let len = part.min(size - offset);
                let body = FileRange { path: path.to_path_buf(), offset, len };
                let ns = n.to_string();
                let mut c = Call::new("PUT", Target::Object(key)).q("partNumber", &ns).q("uploadId", &upload_id);
                c.body = Some(&body);
                c.cancel = Some(cancel);
                let r = self.call(&c, None, progress)?;
                let etag = r
                    .header("etag")
                    .ok_or_else(|| S3Error::new(r.status, "BadResponse", "UploadPart response without ETag"))?;
                etags.push((n, etag.to_string()));
                offset += len;
                n += 1;
            }
            let mut body = String::from("<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
            for (n, e) in &etags {
                body.push_str(&format!("<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>", n, xml::escape(e)));
            }
            body.push_str("</CompleteMultipartUpload>");
            let bb = BytesBody(body.as_bytes());
            let mut c = Call::new("POST", Target::Object(key)).q("uploadId", &upload_id).h("content-type", "application/xml");
            c.body = Some(&bb);
            let r = self.call_simple(&c)?;
            let doc = xml::parse(&r.body_text()).map_err(|e| S3Error::new(r.status, "BadResponse", e))?;
            Ok(strip_quotes(doc.child_text("ETag").unwrap_or("")))
        })();
        if result.is_err() {
            let _ = self.abort_multipart(key, &upload_id);
        }
        result
    }

    pub fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<(), S3Error> {
        self.call_simple(&Call::new("DELETE", Target::Object(key)).q("uploadId", upload_id)).map(|_| ())
    }

    /// List in-progress multipart uploads as (key, upload id).
    pub fn list_multipart_uploads(&self, prefix: &str) -> Result<Vec<(String, String)>, S3Error> {
        let r = self.call_simple(&Call::new("GET", Target::Bucket).q("uploads", "").q("prefix", prefix))?;
        let doc = xml::parse(&r.body_text()).map_err(|e| S3Error::new(r.status, "BadResponse", e))?;
        Ok(doc
            .children_named("Upload")
            .map(|u| (u.child_text("Key").unwrap_or("").to_string(), u.child_text("UploadId").unwrap_or("").to_string()))
            .collect())
    }

    pub fn head_object(&self, key: &str) -> Result<Option<ObjectInfo>, S3Error> {
        match self.call_simple(&Call::new("HEAD", Target::Object(key))) {
            Ok(r) => Ok(Some(ObjectInfo {
                key: key.to_string(),
                size: r.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0),
                etag: strip_quotes(r.header("etag").unwrap_or("")),
                last_modified: r.header("last-modified").unwrap_or("").to_string(),
            })),
            Err(e) if e.status == 404 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// One page of ListObjectsV2. Returns (objects, next continuation token).
    pub fn list_objects_page(
        &self,
        prefix: &str,
        max_keys: u32,
        token: Option<&str>,
    ) -> Result<(Vec<ObjectInfo>, Option<String>), S3Error> {
        let mk = max_keys.to_string();
        let mut c = Call::new("GET", Target::Bucket).q("list-type", "2").q("max-keys", &mk);
        if !prefix.is_empty() {
            c = c.q("prefix", prefix);
        }
        if let Some(t) = token {
            c = c.q("continuation-token", t);
        }
        let r = self.call_simple(&c)?;
        let doc = xml::parse(&r.body_text()).map_err(|e| S3Error::new(r.status, "BadResponse", e))?;
        let items = doc
            .children_named("Contents")
            .map(|e| ObjectInfo {
                key: e.child_text("Key").unwrap_or("").to_string(),
                size: e.child_text("Size").and_then(|s| s.trim().parse().ok()).unwrap_or(0),
                etag: strip_quotes(e.child_text("ETag").unwrap_or("")),
                last_modified: e.child_text("LastModified").unwrap_or("").to_string(),
            })
            .collect();
        let truncated = doc.child_text("IsTruncated").map(|s| s.trim() == "true").unwrap_or(false);
        let next = doc.child_text("NextContinuationToken").filter(|s| !s.is_empty()).map(String::from);
        Ok((items, if truncated { next } else { None }))
    }

    /// List all objects under a prefix (follows pagination).
    pub fn list_objects(&self, prefix: &str) -> Result<Vec<ObjectInfo>, S3Error> {
        let mut all = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let (items, next) = self.list_objects_page(prefix, 1000, token.as_deref())?;
            all.extend(items);
            match next {
                Some(t) if Some(&t) != token.as_ref() => token = Some(t),
                _ => return Ok(all),
            }
        }
    }

    /// Download an object to `dest` (written to a temp file then renamed).
    pub fn get_object_to_file(
        &self,
        key: &str,
        dest: &Path,
        progress: &mut dyn FnMut(u64),
        cancel: &AtomicBool,
    ) -> Result<(), S3Error> {
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| S3Error::local(&e))?;
            }
        }
        let mut tmp = dest.as_os_str().to_owned();
        tmp.push(".btpart");
        let tmp = PathBuf::from(tmp);
        let mut f = File::create(&tmp).map_err(|e| S3Error::local(&e))?;
        let mut c = Call::new("GET", Target::Object(key));
        c.cancel = Some(cancel);
        let res = self.call(&c, Some(&mut f), progress).and_then(|_| f.sync_all().map_err(|e| S3Error::local(&e)));
        drop(f);
        match res {
            Ok(()) => {
                if dest.exists() {
                    let _ = fs::remove_file(dest);
                }
                fs::rename(&tmp, dest).map_err(|e| S3Error::local(&e))
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    /// Fetch a (small) object into memory.
    pub fn get_object_bytes(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        Ok(self.call_simple(&Call::new("GET", Target::Object(key)))?.body)
    }

    pub fn delete_object(&self, key: &str) -> Result<(), S3Error> {
        self.call_simple(&Call::new("DELETE", Target::Object(key))).map(|_| ())
    }
}

fn is_retryable_code(code: &str) -> bool {
    matches!(code, "RequestTimeout" | "SlowDown" | "InternalError" | "ServiceUnavailable" | "TooManyRequests" | "OperationAborted")
}

fn error_from_doc(status: u16, doc: &xml::Element) -> S3Error {
    let code = doc.child_text("Code").unwrap_or("").to_string();
    let mut message = doc.child_text("Message").unwrap_or("").to_string();
    if let Some(ep) = doc.child_text("Endpoint") {
        message = format!("{} (endpoint: {})", message, ep);
    }
    S3Error { status, code: if code.is_empty() { format!("HTTP{}", status) } else { code }, message }
}

/// Returns (error, region hint, server time).
fn parse_error(resp: &Response, is_head: bool) -> (S3Error, Option<String>, Option<String>) {
    let mut region = resp.header("x-amz-bucket-region").filter(|s| !s.is_empty()).map(String::from);
    let mut server_time = None;
    let err = match (is_head, xml::parse(&resp.body_text())) {
        (false, Ok(doc)) if doc.name == "Error" => {
            if region.is_none() {
                region = doc.child_text("Region").filter(|s| !s.is_empty()).map(String::from);
            }
            server_time = doc.child_text("ServerTime").map(String::from);
            error_from_doc(resp.status, &doc)
        }
        _ => {
            let code = match resp.status {
                301 => "PermanentRedirect",
                400 => "BadRequest",
                403 => "Forbidden",
                404 => "NotFound",
                405 => "MethodNotAllowed",
                409 => "Conflict",
                429 => "TooManyRequests",
                500 => "InternalError",
                503 => "ServiceUnavailable",
                _ => "",
            };
            let code = if code.is_empty() { format!("HTTP{}", resp.status) } else { code.to_string() };
            let body = resp.body_text();
            let msg = if body.trim().is_empty() { resp.reason.clone() } else { body.chars().take(300).collect() };
            S3Error { status: resp.status, code, message: msg }
        }
    };
    (err, region, server_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::NoTls;

    fn client(endpoint: &str, bucket: &str, path_style: bool) -> S3Client {
        S3Client::new(
            S3Config { endpoint: endpoint.into(), bucket: bucket.into(), path_style, ..Default::default() },
            Arc::new(NoTls),
        )
    }

    #[test]
    fn addressing() {
        let c = client("", "my-bucket", false);
        let (u, p) = c.build_url(&Target::Object("dir/a b+c.txt"), &[], "eu-west-1");
        assert_eq!(u.to_string(), "https://my-bucket.s3.eu-west-1.amazonaws.com/dir/a%20b%2Bc.txt");
        assert_eq!(p, "/dir/a%20b%2Bc.txt");
        let c = client("", "my.dotted.bucket", false);
        let (u, _) = c.build_url(&Target::Bucket, &[("list-type".into(), "2".into())], "us-east-1");
        assert_eq!(u.to_string(), "https://s3.us-east-1.amazonaws.com/my.dotted.bucket?list-type=2");
        let c = client("http://127.0.0.1:9000", "b", false);
        let (u, _) = c.build_url(&Target::Object("k"), &[], "us-east-1");
        assert_eq!(u.to_string(), "http://127.0.0.1:9000/b/k");
        let c = client("https://acct.r2.cloudflarestorage.com", "b", true);
        let (u, _) = c.build_url(&Target::Object("k"), &[], "auto");
        assert_eq!(u.to_string(), "https://acct.r2.cloudflarestorage.com/b/k");
        let c = client("s3.wasabisys.com", "b", false);
        let (u, _) = c.build_url(&Target::Object("k"), &[], "us-east-1");
        assert_eq!(u.to_string(), "https://b.s3.wasabisys.com/k");
        let (u, _) = c.build_url(&Target::Service, &[], "us-east-1");
        assert_eq!(u.to_string(), "https://s3.wasabisys.com/");
    }

    #[test]
    fn error_parsing() {
        let resp = Response {
            status: 400,
            reason: "Bad Request".into(),
            headers: vec![],
            body: b"<?xml version=\"1.0\"?><Error><Code>AuthorizationHeaderMalformed</Code><Message>wrong region</Message><Region>eu-central-1</Region></Error>".to_vec(),
        };
        let (e, r, _) = parse_error(&resp, false);
        assert_eq!(e.code, "AuthorizationHeaderMalformed");
        assert_eq!(r.as_deref(), Some("eu-central-1"));
        let resp = Response { status: 301, reason: "Moved".into(), headers: vec![("x-amz-bucket-region".into(), "ap-south-1".into())], body: vec![] };
        let (e, r, _) = parse_error(&resp, true);
        assert_eq!((e.code.as_str(), r.as_deref()), ("PermanentRedirect", Some("ap-south-1")));
        let e = S3Error::new(403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.");
        assert!(e.to_string().starts_with("The Access Key ID is not valid:"));
    }
}
