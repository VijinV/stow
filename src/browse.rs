//! Bucket inventory and safe, non-overwriting restores.
use crate::config::S3Settings;
use bt_s3::ObjectInfo;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

#[derive(Clone, Debug)]
pub struct BrowserEntry {
    pub name: String,
    pub key: String,
    pub is_folder: bool,
    pub size: u64,
    pub last_modified: String,
}

/// Inventory covers the entire bucket, including keys outside the upload prefix.
pub fn inventory(settings: &S3Settings) -> Result<Vec<ObjectInfo>, String> {
    crate::remote::client(settings)?
        .list_objects("")
        .map_err(|e| e.to_string())
}

fn folder_prefix(prefix: &str) -> String {
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", prefix.trim_end_matches('/'))
    }
}

pub fn entries(objects: &[ObjectInfo], prefix: &str) -> Vec<BrowserEntry> {
    let prefix = folder_prefix(prefix);
    let mut grouped: BTreeMap<(bool, String), BrowserEntry> = BTreeMap::new();
    for o in objects {
        let Some(rest) = o.key.strip_prefix(&prefix) else {
            continue;
        };
        if rest.is_empty() {
            continue;
        }
        let (name, is_folder) = match rest.split_once('/') {
            Some((name, _)) => (name, true),
            None => (rest, false),
        };
        if name.is_empty() {
            continue;
        }
        let e = grouped
            .entry((!is_folder, name.to_string()))
            .or_insert_with(|| BrowserEntry {
                name: name.into(),
                key: format!("{prefix}{name}{}", if is_folder { "/" } else { "" }),
                is_folder,
                size: 0,
                last_modified: String::new(),
            });
        e.size = e.size.saturating_add(o.size);
        if o.last_modified > e.last_modified {
            e.last_modified = o.last_modified.clone();
        }
    }
    grouped.into_values().collect()
}

#[derive(Clone, Debug, Default)]
pub struct RestoreProgress {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub current: String,
    pub finished: bool,
    pub error: Option<String>,
}

fn safe_relative(s: &str) -> Result<PathBuf, String> {
    if s.is_empty() || s.contains('\\') || s.chars().any(|c| c.is_control()) {
        return Err(format!("Unsafe object path: {s:?}"));
    }
    for c in s.split('/') {
        let base = c.split('.').next().unwrap_or("").to_ascii_uppercase();
        if c.is_empty()
            || c == "."
            || c == ".."
            || c.ends_with(['.', ' '])
            || c.chars()
                .any(|v| matches!(v, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
            || matches!(
                base.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && matches!(base.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(format!("Unsafe object path: {s:?}"));
        }
    }
    Ok(PathBuf::from(s))
}

struct Staging(PathBuf);
impl Staging {
    fn new(parent: &Path) -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let p = parent.join(format!(
                ".backup-restore-{}-{time}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut b = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            match b.create(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("Cannot allocate a private restore directory".into())
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn restore(
    settings: &S3Settings,
    objects: Vec<ObjectInfo>,
    prefix: &str,
    dest: &Path,
    progress: Arc<Mutex<RestoreProgress>>,
    cancel: Arc<AtomicBool>,
) -> Result<String, String> {
    // Construct the client inside the worker so failures also finish the progress state.
    restore_with(
        objects,
        prefix,
        dest,
        &progress,
        &cancel,
        &settings.recovery_key,
        |key, path, cb| {
            let client = crate::remote::client(settings)?;
            let metadata = client.object_metadata(key).map_err(|e| e.to_string())?;
            let marker = metadata
                .iter()
                .find(|(name, _)| name == "bt-encrypted")
                .map(|(_, value)| value.as_str());
            client
                .get_object_to_file(key, path, cb, &cancel)
                .map_err(|e| e.to_string())?;
            if let Some(marker) = marker {
                if marker != "BTENC001" {
                    return Err(format!("Unsupported encrypted object format: {marker}"));
                }
            }
            if marker.is_some() && !crate::file_crypto::is_encrypted_file(path)? {
                return Err(
                    "Object is marked encrypted but its encryption envelope is missing or corrupt"
                        .into(),
                );
            }
            Ok(())
        },
    )
}

fn restore_with<F>(
    objects: Vec<ObjectInfo>,
    prefix: &str,
    dest: &Path,
    progress: &Arc<Mutex<RestoreProgress>>,
    cancel: &AtomicBool,
    recovery_key: &str,
    mut download: F,
) -> Result<String, String>
where
    F: FnMut(&str, &Path, &mut dyn FnMut(u64)) -> Result<(), String>,
{
    let files: Vec<_> = objects
        .into_iter()
        .filter(|o| !o.key.ends_with('/'))
        .collect();
    *progress.lock().unwrap() = RestoreProgress {
        files_total: files.len() as u64,
        bytes_total: files.iter().fold(0u64, |n, o| n.saturating_add(o.size)),
        ..Default::default()
    };
    let result: Result<String, String> = (|| {
        let prefix = folder_prefix(prefix);
        // Validate every key before downloading or creating output files.
        let mut selected = Vec::new();
        for o in files {
            let relative = o
                .key
                .strip_prefix(&prefix)
                .ok_or_else(|| format!("Object {} is outside the selected folder", o.key))?;
            selected.push((safe_relative(relative)?, o));
        }
        let meta = fs::symlink_metadata(dest).map_err(|e| format!("Restore destination: {e}"))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Restore destination must be a real directory".into());
        }
        let dest = fs::canonicalize(dest).map_err(|e| e.to_string())?;
        let staging = Staging::new(&dest)?;
        for (relative, o) in selected {
            if cancel.load(Ordering::Relaxed) {
                return Err("Restore cancelled".into());
            }
            progress.lock().unwrap().current = o.key.clone();
            let source = staging.0.join("download");
            let output = staging.0.join("plain");
            let before = progress.lock().unwrap().bytes_done;
            let mut received = 0u64;
            download(&o.key, &source, &mut |n| {
                received = received.saturating_add(n);
                let mut p = progress.lock().unwrap();
                p.bytes_done = before.saturating_add(received.min(o.size));
            })
            .map_err(|e| format!("{}: {e}", o.key))?;
            if cancel.load(Ordering::Relaxed) {
                return Err("Restore cancelled".into());
            }
            crate::file_crypto::decrypt_file_cancel(&source, &output, recovery_key, cancel)
                .map_err(|e| format!("{}: {e}", o.key))?;
            if cancel.load(Ordering::Relaxed) {
                return Err("Restore cancelled".into());
            }
            publish(&output, &dest, &relative).map_err(|e| format!("{}: {e}", o.key))?;
            fs::remove_file(&source).map_err(|e| e.to_string())?;
            fs::remove_file(&output).map_err(|e| e.to_string())?;
            let mut p = progress.lock().unwrap();
            p.files_done += 1;
            p.bytes_done = before.saturating_add(o.size);
        }
        Ok(format!(
            "Restored {} files",
            progress.lock().unwrap().files_done
        ))
    })();
    let mut p = progress.lock().unwrap();
    p.finished = true;
    if let Err(ref e) = result {
        p.error = Some(format!(
            "{e}. {} of {} files restored; completed files were kept.",
            p.files_done, p.files_total
        ));
    }
    result.map_err(|_| p.error.clone().unwrap())
}

// Linux uses directory descriptors and O_NOFOLLOW throughout: a concurrent rename
// or symlink replacement cannot redirect writes outside the selected directory.
#[cfg(target_os = "linux")]
fn publish(source: &Path, dest: &Path, relative: &Path) -> Result<(), String> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };
    unsafe extern "C" {
        fn openat(fd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        fn mkdirat(fd: i32, path: *const std::ffi::c_char, mode: u32) -> i32;
        fn linkat(
            fd: i32,
            source: *const std::ffi::c_char,
            destfd: i32,
            dest: *const std::ffi::c_char,
            flags: i32,
        ) -> i32;
    }
    let err = || std::io::Error::last_os_error().to_string();
    use std::os::unix::fs::OpenOptionsExt;
    let mut dir = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0o200000 | 0o400000)
        .open(dest)
        .map_err(|e| e.to_string())?;
    let parts: Vec<_> = relative.components().collect();
    for part in &parts[..parts.len() - 1] {
        let name = CString::new(part.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        unsafe {
            mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700);
        }
        let fd = unsafe {
            openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                0o200000 | 0o400000 | 0o2000000,
            )
        };
        if fd < 0 {
            return Err(format!(
                "Unsafe or inaccessible restore directory: {}",
                err()
            ));
        }
        dir = unsafe { fs::File::from_raw_fd(fd) };
    }
    let src = CString::new(source.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let name =
        CString::new(parts.last().unwrap().as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    if unsafe { linkat(-100, src.as_ptr(), dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(format!(
            "Cannot restore without overwriting an existing file: {}",
            err()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn publish(source: &Path, dest: &Path, relative: &Path) -> Result<(), String> {
    let mut parent = dest.to_path_buf();
    let parts: Vec<_> = relative.components().collect();
    for part in &parts[..parts.len() - 1] {
        parent.push(part);
        match fs::create_dir(&parent) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.to_string()),
        }
        let m = fs::symlink_metadata(&parent).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("Unsafe restore directory".into());
        }
    }
    fs::hard_link(source, dest.join(relative))
        .map_err(|e| format!("Cannot restore without overwriting an existing file: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn obj(key: &str, size: u64) -> bt_s3::ObjectInfo {
        bt_s3::ObjectInfo {
            key: key.into(),
            size,
            ..Default::default()
        }
    }
    #[test]
    fn immediate_folders_aggregate_and_respect_boundaries() {
        let e = entries(
            &[
                obj("a/z.txt", 2),
                obj("a/sub/x", 3),
                obj("a/sub/y", 4),
                obj("ab/no", 99),
            ],
            "a",
        );
        assert_eq!(e.len(), 2);
        assert!(e[0].is_folder);
        assert_eq!((e[0].key.as_str(), e[0].size), ("a/sub/", 7));
        assert_eq!(e[1].name, "z.txt");
    }
    #[test]
    fn unsafe_relative_paths_are_rejected() {
        for path in [
            "../x", "a/../x", "/x", "a\\x", "C:x", "a//x", "a/./x", "NUL.txt", "a/COM1", "x.",
            "x ", "x\0",
        ] {
            assert!(safe_relative(path).is_err(), "accepted {path:?}");
        }
        assert!(safe_relative("Photos/été 1.jpg").is_ok());
    }
    fn temp() -> Staging {
        Staging::new(&std::env::temp_dir()).unwrap()
    }
    fn state() -> Arc<Mutex<RestoreProgress>> {
        Arc::new(Mutex::new(RestoreProgress::default()))
    }
    fn bytes_download(_: &str, path: &Path, progress: &mut dyn FnMut(u64)) -> Result<(), String> {
        fs::write(path, b"restored bytes").map_err(|e| e.to_string())?;
        progress(4);
        progress(10);
        Ok(())
    }
    #[test]
    fn restores_original_bytes_and_reports_progress() {
        let d = temp();
        let p = state();
        restore_with(
            vec![obj("root/nested/file", 14)],
            "root/",
            &d.0,
            &p,
            &AtomicBool::new(false),
            "",
            bytes_download,
        )
        .unwrap();
        assert_eq!(
            fs::read(d.0.join("nested/file")).unwrap(),
            b"restored bytes"
        );
        let p = p.lock().unwrap();
        assert_eq!(
            (p.files_done, p.files_total, p.bytes_done, p.bytes_total),
            (1, 1, 14, 14)
        );
        assert!(p.finished && p.error.is_none());
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    }
    #[test]
    fn overwrite_refusal_keeps_original_and_cleans_staging() {
        let d = temp();
        let p = state();
        fs::write(d.0.join("file"), b"keep me").unwrap();
        assert!(restore_with(
            vec![obj("file", 14)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(false),
            "",
            bytes_download
        )
        .is_err());
        assert_eq!(fs::read(d.0.join("file")).unwrap(), b"keep me");
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
        let p = p.lock().unwrap();
        assert!(p.finished && p.error.is_some());
        assert_eq!(p.files_done, 0);
    }
    #[test]
    fn cancellation_and_prefix_failure_never_publish() {
        let d = temp();
        let p = state();
        assert!(restore_with(
            vec![obj("ab/file", 14)],
            "a/",
            &d.0,
            &p,
            &AtomicBool::new(false),
            "",
            bytes_download
        )
        .is_err());
        assert!(restore_with(
            vec![obj("file", 14)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(true),
            "",
            bytes_download
        )
        .is_err());
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 0);
        assert!(p.lock().unwrap().finished);
    }
    #[test]
    fn partial_failure_preserves_completed_files_and_explains_count() {
        let d = temp();
        let p = state();
        let e = restore_with(
            vec![obj("first", 14), obj("second", 14)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(false),
            "",
            |key, path, cb| {
                if key == "second" {
                    Err("connection lost".into())
                } else {
                    bytes_download(key, path, cb)
                }
            },
        )
        .unwrap_err();
        assert!(e.contains("1 of 2 files restored"));
        assert_eq!(fs::read(d.0.join("first")).unwrap(), b"restored bytes");
        assert!(!d.0.join("second").exists());
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_directory_and_file_are_never_followed() {
        use std::os::unix::fs::symlink;
        let d = temp();
        let outside = temp();
        let p = state();
        symlink(&outside.0, d.0.join("link")).unwrap();
        assert!(restore_with(
            vec![obj("link/file", 14)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(false),
            "",
            bytes_download
        )
        .is_err());
        assert!(!outside.0.join("file").exists());
        symlink(outside.0.join("file"), d.0.join("file")).unwrap();
        assert!(restore_with(
            vec![obj("file", 14)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(false),
            "",
            bytes_download
        )
        .is_err());
        assert!(!outside.0.join("file").exists());
    }
    #[test]
    fn encrypted_download_is_decrypted_before_publication() {
        let d = temp();
        let fixtures = temp();
        let p = state();
        let key = crate::file_crypto::generate_key().unwrap();
        let source = fixtures.0.join("original");
        let cipher = fixtures.0.join("encrypted");
        fs::write(&source, b"secret recovered contents").unwrap();
        crate::file_crypto::encrypt_file(&source, &cipher, &key).unwrap();
        let size = fs::metadata(&cipher).unwrap().len();
        restore_with(
            vec![obj("file", size)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(false),
            &key,
            |_, path, cb| {
                fs::copy(&cipher, path).map_err(|e| e.to_string())?;
                cb(size);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            fs::read(d.0.join("file")).unwrap(),
            b"secret recovered contents"
        );
        let wrong = crate::file_crypto::generate_key().unwrap();
        assert!(restore_with(
            vec![obj("wrong", size)],
            "",
            &d.0,
            &p,
            &AtomicBool::new(false),
            &wrong,
            |_, path, cb| {
                fs::copy(&cipher, path).map_err(|e| e.to_string())?;
                cb(size);
                Ok(())
            }
        )
        .is_err());
        assert!(!d.0.join("wrong").exists());
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    }
    #[test]
    fn cancellation_after_download_does_not_publish_plaintext() {
        let d = temp();
        let p = state();
        let cancel = AtomicBool::new(false);
        assert!(restore_with(
            vec![obj("file", 14)],
            "",
            &d.0,
            &p,
            &cancel,
            "",
            |key, path, cb| {
                bytes_download(key, path, cb)?;
                cancel.store(true, Ordering::Relaxed);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 0);
        assert_eq!(p.lock().unwrap().files_done, 0);
    }
    #[test]
    fn s3_download_restores_missing_file_without_live_credentials() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for method in ["HEAD", "GET"] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                assert!(String::from_utf8_lossy(&request)
                    .starts_with(&format!("{method} /bucket/root/file ")));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
                if method == "GET" {
                    stream.write_all(b"restored bytes").unwrap();
                }
            }
        });
        let settings = S3Settings {
            endpoint: format!("http://{address}"),
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            path_style: true,
            ..Default::default()
        };
        let d = temp();
        let p = state();
        restore(
            &settings,
            vec![obj("root/file", 14)],
            "root/",
            &d.0,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(fs::read(d.0.join("file")).unwrap(), b"restored bytes");
        assert!(p.lock().unwrap().finished);
    }
    fn assert_marked_download_refused(marker: &str) {
        let marker = marker.to_string();
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || loop {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            if request.starts_with(b"HEAD ") {
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 14\r\nx-amz-meta-bt-encrypted: {marker}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
            } else {
                assert!(request.starts_with(b"GET "));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\ncorrupt cipher").unwrap();
                break;
            }
        });
        let settings = S3Settings {
            endpoint: format!("http://{address}"),
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            path_style: true,
            ..Default::default()
        };
        let d = temp();
        let p = state();
        let result = restore(
            &settings,
            vec![obj("file", 14)],
            "",
            &d.0,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        server.join().unwrap();
        assert!(
            result.is_err(),
            "marked ciphertext with a corrupt envelope was restored as plaintext"
        );
        assert!(result.unwrap_err().contains("encrypted"));
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 0);
        let p = p.lock().unwrap();
        assert!(p.finished && p.error.is_some());
        assert_eq!(p.files_done, 0);
    }
    #[test]
    fn marked_encrypted_object_with_corrupt_magic_is_never_published() {
        assert_marked_download_refused("BTENC001");
    }
    #[test]
    fn unknown_encryption_marker_is_never_published() {
        assert_marked_download_refused("BTENC002");
    }
}
