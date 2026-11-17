//! Private, short-lived browser previews of downloaded S3 objects.
//! Call `open` on a worker: it downloads and (where necessary) decrypts before opening.
//! No credentials or object URLs are sent to the browser. The local session supports
//! byte-range seeking, expires after 15 minutes, and owns its temporary plaintext.
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const LIFETIME: Duration = Duration::from_secs(15 * 60);
const TEXT_LIMIT: u64 = 2 * 1024 * 1024;
static SESSIONS: AtomicUsize = AtomicUsize::new(0);
static STOPPING: AtomicBool = AtomicBool::new(false);
static CACHES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static WORKERS: Mutex<Vec<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());

/// Call after the GUI loop returns, before exiting, to remove active plaintext caches.
pub fn shutdown() {
    STOPPING.store(true, Ordering::SeqCst);
    let workers: Vec<_> = WORKERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .drain(..)
        .collect();
    for worker in workers {
        let _ = worker.join();
    }
    let paths = CACHES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for path in paths {
        let _ = fs::remove_dir_all(path);
    }
}

struct Session;
impl Session {
    fn acquire() -> Result<Self, String> {
        SESSIONS
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < 3).then_some(n + 1)
            })
            .map(|_| Self)
            .map_err(|_| "Three previews are already open. Wait for a preview to expire.".into())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        SESSIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn random_token() -> io::Result<String> {
    let bytes = bt_tls::crypto::random::array::<32>()?;
    Ok(bt_tls::crypto::util::hex(&bytes))
}

/// Owned private cache. Every error path and normal server shutdown removes it.
struct Cache(PathBuf);
impl Cache {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("backup-taker-preview-{}", random_token()?));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        CACHES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.clone());
        Ok(Self(path))
    }
}
impl Drop for Cache {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        CACHES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|p| p != &self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Image,
    Video,
    Audio,
    Pdf,
    Text,
}
fn media_type(key: &str) -> Option<(&'static str, Kind)> {
    let ext = key
        .rsplit('/')
        .next()?
        .rsplit_once('.')?
        .1
        .to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" => ("image/jpeg", Kind::Image),
        "png" => ("image/png", Kind::Image),
        "gif" => ("image/gif", Kind::Image),
        "webp" => ("image/webp", Kind::Image),
        "avif" => ("image/avif", Kind::Image),
        "bmp" => ("image/bmp", Kind::Image),
        "mp4" | "m4v" => ("video/mp4", Kind::Video),
        "webm" => ("video/webm", Kind::Video),
        "ogv" => ("video/ogg", Kind::Video),
        "mov" => ("video/quicktime", Kind::Video),
        "mp3" => ("audio/mpeg", Kind::Audio),
        "m4a" => ("audio/mp4", Kind::Audio),
        "ogg" | "oga" => ("audio/ogg", Kind::Audio),
        "wav" => ("audio/wav", Kind::Audio),
        "flac" => ("audio/flac", Kind::Audio),
        "pdf" => ("application/pdf", Kind::Pdf),
        "txt" | "log" | "csv" | "md" | "json" | "xml" | "toml" | "yaml" | "yml" => {
            ("text/plain; charset=utf-8", Kind::Text)
        }
        _ => return None,
    })
}

/// Download a selected supported object and open a private browser preview.
/// Browser codec support varies. The full object is cached before playback.
pub fn open(
    settings: &crate::config::S3Settings,
    object: &bt_s3::ObjectInfo,
    cancel: &AtomicBool,
) -> Result<String, String> {
    if STOPPING.load(Ordering::SeqCst) || cancel.load(Ordering::SeqCst) {
        return Err("Preview cancelled.".into());
    }
    let (mime, kind) = media_type(&object.key).ok_or_else(||
        "Preview supports common images, video, audio, PDF and text files. Restore this file to open it locally.".to_string())?;
    if kind == Kind::Text && object.size > TEXT_LIMIT + 1024 * 1024 {
        return Err(
            "Text preview is limited to 2 MiB. Restore this file to view it locally.".into(),
        );
    }
    let session = Session::acquire()?;
    let cache = Cache::new().map_err(|_| "Cannot create a private preview cache.".to_string())?;
    let downloaded = cache.0.join("download");
    let plain = cache.0.join("plain");
    let client = crate::remote::client(settings)
        .map_err(|_| "Cannot configure S3 for preview. Check the storage settings.".to_string())?;
    let metadata = client.object_metadata(&object.key).map_err(|_| {
        "Cannot inspect this object for preview. Check the connection and object permissions."
            .to_string()
    })?;
    // Do not expose endpoint/server diagnostic text (which can echo credentials).
    client
        .get_object_to_file(&object.key, &downloaded, &mut |_| {}, cancel)
        .map_err(|_| {
            "Cannot download this object for preview. Check the connection and object permissions."
                .to_string()
        })?;
    validate_envelope(&downloaded, &metadata)?;
    crate::file_crypto::decrypt_file_cancel(&downloaded, &plain, &settings.recovery_key, cancel)
        .map_err(|_| {
            "Cannot decrypt this preview. Check the recovery key and file integrity.".to_string()
        })?;
    fs::remove_file(downloaded)
        .map_err(|_| "Cannot prepare the private preview cache.".to_string())?;
    if kind == Kind::Text
        && fs::metadata(&plain)
            .map_err(|_| "Cannot read preview.".to_string())?
            .len()
            > TEXT_LIMIT
    {
        return Err(
            "Text preview is limited to 2 MiB. Restore this file to view it locally.".into(),
        );
    }
    if cancel.load(Ordering::SeqCst) {
        return Err("Preview cancelled.".into());
    }
    let token = random_token().map_err(|_| "Cannot generate a secure preview URL.".to_string())?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "Cannot start the private preview server.".to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "Cannot configure the private preview server.".to_string())?;
    let port = listener
        .local_addr()
        .map_err(|_| "Cannot read preview server address.".to_string())?
        .port();
    let url = format!("http://127.0.0.1:{port}/{token}/");
    let name = object.key.clone();
    let mut workers = WORKERS.lock().unwrap_or_else(|e| e.into_inner());
    if STOPPING.load(Ordering::SeqCst) {
        return Err("The application is closing.".into());
    }
    let worker = std::thread::Builder::new()
        .name("private-preview".into())
        .spawn(move || {
            let _session = session;
            serve(listener, cache, token, name, mime, kind, LIFETIME);
        })
        .map_err(|_| "Cannot start preview worker.".to_string())?;
    workers.retain(|worker| !worker.is_finished());
    workers.push(worker);
    drop(workers);
    bt_gui::open_url(&url);
    Ok("Preview opened in your browser. Its private cache expires in 15 minutes; playback depends on browser codec support.".into())
}

// A damaged encrypted header must not silently downgrade to a plaintext preview.
fn validate_envelope(path: &std::path::Path, metadata: &[(String, String)]) -> Result<(), String> {
    if let Some((_, marker)) = metadata.iter().find(|(key, _)| key == "bt-encrypted") {
        if marker != "BTENC001"
            || !crate::file_crypto::is_encrypted_file(path)
                .map_err(|_| "Cannot inspect the encrypted preview.".to_string())?
        {
            return Err(
                "This encrypted object's header is missing, damaged or unsupported.".into(),
            );
        }
    }
    Ok(())
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
fn viewer(name: &str, token: &str, kind: Kind, text: Option<&str>) -> String {
    let source = format!("/{token}/data");
    let content = match kind {
        Kind::Image => format!("<img src=\"{source}\" alt=\"Preview\">"),
        Kind::Video => format!("<video controls preload=\"metadata\" src=\"{source}\"></video>"),
        Kind::Audio => format!("<audio controls preload=\"metadata\" src=\"{source}\"></audio>"),
        Kind::Pdf => format!("<iframe title=\"PDF preview\" src=\"{source}\"></iframe>"),
        Kind::Text => format!("<pre>{}</pre>", escape(text.unwrap_or_default())),
    };
    format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>Backup Taker preview</title><style>body{{background:#18202b;color:#e8edf4;font:16px system-ui;margin:24px}}h1{{font-size:20px;overflow-wrap:anywhere}}img,video{{max-width:100%;max-height:80vh}}iframe{{width:100%;height:80vh;border:0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}p{{color:#adb9c9}}</style></head><body><h1>{}</h1><p>Private preview · expires after 15 minutes · browser codec support may vary</p>{content}</body></html>", escape(name))
}

/// Single RFC 7233 byte range, inclusive. Multi-range requests are rejected.
fn byte_range(header: Option<&str>, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(value) = header else { return Ok(None) };
    if size == 0 {
        return Err(());
    }
    let value = value.strip_prefix("bytes=").ok_or(())?;
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let count: u64 = end.parse().map_err(|_| ())?;
        if count == 0 {
            return Err(());
        }
        return Ok(Some((size.saturating_sub(count), size - 1)));
    }
    let start: u64 = start.parse().map_err(|_| ())?;
    let end: u64 = if end.is_empty() {
        size - 1
    } else {
        end.parse().map_err(|_| ())?
    };
    if start >= size || end < start {
        return Err(());
    }
    Ok(Some((start, end.min(size - 1))))
}

struct Request {
    head: bool,
    data: bool,
    range: Option<String>,
}
fn parse_request(raw: &str, token: &str, port: u16) -> Result<Request, ()> {
    let mut lines = raw.split("\r\n");
    let first: Vec<_> = lines.next().ok_or(())?.split_whitespace().collect();
    if first.len() != 3 || !matches!(first[0], "GET" | "HEAD") || first[2] != "HTTP/1.1" {
        return Err(());
    }
    let data = if first[1] == format!("/{token}/") {
        false
    } else if first[1] == format!("/{token}/data") {
        true
    } else {
        return Err(());
    };
    let expected_host = format!("127.0.0.1:{port}");
    let expected_origin = format!("http://{expected_host}");
    let mut host = false;
    let mut range = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').ok_or(())?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                if host || value != expected_host {
                    return Err(());
                }
                host = true;
            }
            "origin" => {
                if value != expected_origin {
                    return Err(());
                }
            }
            "sec-fetch-site" => {
                if !matches!(value, "same-origin" | "none") {
                    return Err(());
                }
            }
            "range" => {
                if range.is_some() {
                    return Err(());
                }
                range = Some(value.to_string());
            }
            "content-length" => {
                if value != "0" {
                    return Err(());
                }
            }
            "transfer-encoding" => return Err(()),
            _ => {}
        }
    }
    if !host {
        return Err(());
    }
    Ok(Request {
        head: first[0] == "HEAD",
        data,
        range,
    })
}

fn headers(
    stream: &mut TcpStream,
    status: &str,
    mime: &str,
    length: u64,
    extra: &str,
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {length}\r\nConnection: close\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Security-Policy: default-src 'none'; img-src 'self'; media-src 'self'; frame-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'\r\n{extra}\r\n")
}

fn handle(
    stream: &mut TcpStream,
    cache: &Cache,
    token: &str,
    name: &str,
    mime: &str,
    kind: Kind,
    port: u16,
    expires: Instant,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut raw = Vec::new();
    let header_deadline = expires.min(Instant::now() + Duration::from_secs(5));
    // Reading one byte avoids consuming a body/pipelined request. Limit headers and wall time.
    while raw.len() < 16 * 1024
        && Instant::now() < header_deadline
        && !STOPPING.load(Ordering::SeqCst)
    {
        let mut byte = [0];
        if stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !raw.ends_with(b"\r\n\r\n") || Instant::now() >= header_deadline {
        return headers(stream, "408 Request Timeout", "text/plain", 0, "");
    }
    let request = match std::str::from_utf8(&raw)
        .ok()
        .and_then(|raw| parse_request(raw, token, port).ok())
    {
        Some(request) => request,
        None => return headers(stream, "403 Forbidden", "text/plain", 0, ""),
    };
    if !request.data {
        let text = if kind == Kind::Text {
            Some(String::from_utf8_lossy(&fs::read(cache.0.join("plain"))?).into_owned())
        } else {
            None
        };
        let html = viewer(name, token, kind, text.as_deref());
        headers(
            stream,
            "200 OK",
            "text/html; charset=utf-8",
            html.len() as u64,
            "",
        )?;
        if !request.head {
            stream.write_all(html.as_bytes())?;
        }
        return Ok(());
    }
    // Text is exposed only inside escaped HTML, never as potentially executable markup.
    if kind == Kind::Text {
        return headers(stream, "404 Not Found", "text/plain", 0, "");
    }
    let mut file = File::open(cache.0.join("plain"))?;
    let size = file.metadata()?.len();
    let range = match byte_range(request.range.as_deref(), size) {
        Ok(range) => range,
        Err(()) => {
            return headers(
                stream,
                "416 Range Not Satisfiable",
                mime,
                0,
                &format!("Content-Range: bytes */{size}\r\n"),
            )
        }
    };
    let (start, length, status, extra) = match range {
        Some((start, end)) => (
            start,
            end - start + 1,
            "206 Partial Content",
            format!("Accept-Ranges: bytes\r\nContent-Range: bytes {start}-{end}/{size}\r\n"),
        ),
        None => (0, size, "200 OK", "Accept-Ranges: bytes\r\n".into()),
    };
    headers(stream, status, mime, length, &extra)?;
    if request.head {
        return Ok(());
    }
    file.seek(SeekFrom::Start(start))?;
    let mut remaining = length;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 && Instant::now() < expires && !STOPPING.load(Ordering::SeqCst) {
        let want = remaining.min(buffer.len() as u64) as usize;
        let n = file.read(&mut buffer[..want])?;
        if n == 0 {
            break;
        }
        stream.write_all(&buffer[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

fn serve(
    listener: TcpListener,
    cache: Cache,
    token: String,
    name: String,
    mime: &'static str,
    kind: Kind,
    lifetime: Duration,
) {
    let expires = Instant::now() + lifetime;
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => return,
    };
    while Instant::now() < expires && !STOPPING.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, addr)) if addr.ip().is_loopback() => {
                let _ = handle(
                    &mut stream,
                    &cache,
                    &token,
                    &name,
                    mime,
                    kind,
                    port,
                    expires,
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_allowlisted_types_render() {
        assert_eq!(media_type("photo.JPEG"), Some(("image/jpeg", Kind::Image)));
        assert_eq!(
            media_type("folder/movie.mp4"),
            Some(("video/mp4", Kind::Video))
        );
        assert_eq!(
            media_type("log.txt"),
            Some(("text/plain; charset=utf-8", Kind::Text))
        );
        for name in [
            "bad.html",
            "bad.svg",
            "bad.exe",
            "no-extension",
            "bad.xhtml",
        ] {
            assert!(media_type(name).is_none(), "{name}");
        }
    }

    #[test]
    fn names_and_text_are_escaped() {
        assert_eq!(escape("<script>\"&'"), "&lt;script&gt;&quot;&amp;&#39;");
        let html = viewer(
            "<img src=x>",
            "abc",
            Kind::Text,
            Some("</pre><script>alert(1)</script>"),
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;/pre&gt;"));
        assert!(html.contains("&lt;img src=x&gt;"));
    }

    #[test]
    fn ranges_cover_seek_suffix_and_invalid_requests() {
        assert_eq!(byte_range(None, 10), Ok(None));
        assert_eq!(byte_range(Some("bytes=2-5"), 10), Ok(Some((2, 5))));
        assert_eq!(byte_range(Some("bytes=2-999"), 10), Ok(Some((2, 9))));
        assert_eq!(byte_range(Some("bytes=8-"), 10), Ok(Some((8, 9))));
        assert_eq!(byte_range(Some("bytes=-3"), 10), Ok(Some((7, 9))));
        assert_eq!(byte_range(Some("bytes=-999"), 10), Ok(Some((0, 9))));
        for range in [
            "bytes=10-",
            "bytes=5-2",
            "bytes=-0",
            "bytes=0-1,3-5",
            "items=0-2",
            "bytes=a-b",
        ] {
            assert!(byte_range(Some(range), 10).is_err(), "{range}");
        }
        assert!(byte_range(Some("bytes=0-"), 0).is_err());
    }

    #[test]
    fn authentication_rejects_paths_and_cross_origin_requests() {
        let request = |path: &str, extra: &str| {
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n{extra}\r\n")
        };
        assert!(parse_request(&request("/secret/data", ""), "secret", 1234).is_ok());
        for path in [
            "/",
            "/wrong/data",
            "/secret/data?x=1",
            "/secret/../data",
            "/secret/%64ata",
        ] {
            assert!(parse_request(&request(path, ""), "secret", 1234).is_err());
        }
        assert!(parse_request(
            &request("/secret/", "Origin: https://evil.test\r\n"),
            "secret",
            1234
        )
        .is_err());
        assert!(parse_request(
            &request("/secret/", "Sec-Fetch-Site: cross-site\r\n"),
            "secret",
            1234
        )
        .is_err());
        assert!(parse_request(
            "GET /secret/ HTTP/1.1\r\nHost: evil.test\r\n\r\n",
            "secret",
            1234
        )
        .is_err());
    }

    #[test]
    fn cache_cleanup_on_drop_and_expiration() {
        let cache = Cache::new().unwrap();
        let path = cache.0.clone();
        std::fs::write(path.join("plain"), b"sensitive").unwrap();
        drop(cache);
        assert!(!path.exists());
        let cache = Cache::new().unwrap();
        let path = cache.0.clone();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        serve(
            listener,
            cache,
            "token".into(),
            "name".into(),
            "image/png",
            Kind::Image,
            Duration::ZERO,
        );
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;

    fn response(method: &str, range: &str, path: &str) -> Vec<u8> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let cache = Cache::new().unwrap();
        fs::write(cache.0.join("plain"), b"0123456789").unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle(
                &mut stream,
                &cache,
                "secret",
                "movie.mp4",
                "video/mp4",
                Kind::Video,
                port,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{range}\r\n"
        )
        .unwrap();
        let mut result = Vec::new();
        stream.read_to_end(&mut result).unwrap();
        worker.join().unwrap();
        result
    }

    #[test]
    fn byte_serving_head_and_unauthorized_over_real_socket() {
        let result =
            String::from_utf8(response("GET", "Range: bytes=2-5\r\n", "/secret/data")).unwrap();
        assert!(result.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(result.contains("Content-Range: bytes 2-5/10\r\n"));
        assert!(result.contains("Content-Length: 4\r\n"));
        assert!(result.ends_with("\r\n\r\n2345"));
        let result = String::from_utf8(response("HEAD", "", "/secret/data")).unwrap();
        assert!(result.contains("Content-Length: 10\r\n"));
        assert!(result.ends_with("\r\n\r\n"));
        let result =
            String::from_utf8(response("GET", "Range: bytes=10-\r\n", "/secret/data")).unwrap();
        assert!(result.starts_with("HTTP/1.1 416 "));
        assert!(result.contains("Content-Range: bytes */10\r\n"));
        let result = String::from_utf8(response("GET", "", "/wrong/data")).unwrap();
        assert!(result.starts_with("HTTP/1.1 403 "));
        assert!(!result.contains("0123456789"));
    }

    #[test]
    fn private_cache_permissions() {
        let cache = Cache::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&cache.0).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            cache.0.file_name().unwrap().to_string_lossy().len(),
            "backup-taker-preview-".len() + 64
        );
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    #[test]
    fn encrypted_metadata_cannot_downgrade_to_plaintext() {
        let cache = Cache::new().unwrap();
        let path = cache.0.join("object");
        fs::write(&path, b"untrusted plaintext").unwrap();
        assert!(validate_envelope(&path, &[]).is_ok());
        assert!(validate_envelope(&path, &[("bt-encrypted".into(), "BTENC001".into())]).is_err());
        let key = crate::file_crypto::generate_key().unwrap();
        let enc = cache.0.join("enc");
        crate::file_crypto::encrypt_file(&path, &enc, &key).unwrap();
        assert!(validate_envelope(&enc, &[("bt-encrypted".into(), "BTENC001".into())]).is_ok());
        assert!(validate_envelope(&enc, &[("bt-encrypted".into(), "unknown".into())]).is_err());
    }
}

#[cfg(test)]
mod cancel_tests {
    #[test]
    fn pre_cancelled_preview_does_not_connect_or_open_browser() {
        let s = crate::config::S3Settings::default();
        let object = bt_s3::ObjectInfo {
            key: "photo.png".into(),
            ..Default::default()
        };
        let error = super::open(&s, &object, &super::AtomicBool::new(true)).unwrap_err();
        assert!(error.contains("cancelled"));
    }
}
