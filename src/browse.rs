//! Bucket inventory and safe, non-overwriting restores.
use crate::config::S3Settings;
use bt_s3::{ObjectInfo, ObjectVersion, ObjectVersionsPage, S3Error, VersionCursor};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
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

/// Standalone inventory covers the bucket. Managed inventory starts at the device prefix.
pub fn inventory(settings: &S3Settings) -> Result<Vec<ObjectInfo>, String> {
    crate::remote::client(settings)?
        .list_objects(if settings.managed.is_some() { &settings.prefix } else { "" })
        .map_err(|e| e.to_string())
}

pub fn version_page(
    settings: &S3Settings,
    prefix: &str,
    exact: bool,
    cursor: Option<&VersionCursor>,
    cancel: &AtomicBool,
) -> Result<ObjectVersionsPage, String> {
    if settings.managed.is_some() && !prefix.starts_with(&settings.prefix) {
        return Err("Choose an object or folder within this device’s managed storage.".into());
    }
    let mut page = crate::remote::client(settings)?
        .list_object_versions_page(prefix, 100, cursor, cancel)
        .map_err(|e| version_error("Could not list file versions", "s3:ListBucketVersions", e))?;
    if exact {
        // Exact matches are contiguous in S3's key order. A cursor on the
        // requested key can still lead to older versions or delete markers.
        if page.versions.iter().any(|v| v.object.key.as_str() > prefix)
            || page.next.as_ref().is_some_and(|next| next.key() > prefix)
        {
            page.next = None;
        }
        page.versions.retain(|v| v.object.key == prefix);
    }
    Ok(page)
}

fn version_error(action: &str, permission: &str, error: S3Error) -> String {
    if matches!(error.code.as_str(), "AccessDenied" | "Forbidden") {
        format!("{action}. Check the {permission} permission. {error}")
    } else if matches!(error.status, 405 | 501)
        || matches!(
            error.code.as_str(),
            "NotImplemented" | "NotSupported" | "UnsupportedOperation"
        )
    {
        format!("{action}. The storage provider rejected the version operation. {error}")
    } else {
        format!("{action}. {error}")
    }
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

fn create_staging_dir(parent: &Path) -> Result<PathBuf, String> {
    for _ in 0..100 {
        let path = parent.join(format!(
            ".backup-restore-{}",
            crate::file_crypto::generate_key()?
        ));
        #[cfg(unix)]
        let created = {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&path)
        };
        #[cfg(not(unix))]
        let created = fs::create_dir(&path);
        match created {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("Cannot allocate a private restore directory".into())
}

#[cfg(any(test, not(target_os = "linux")))]
struct TempDir(PathBuf);

#[cfg(any(test, not(target_os = "linux")))]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
use linux_restore::Staging;

#[cfg(not(target_os = "linux"))]
struct Staging {
    dest: PathBuf,
    dir: TempDir,
}

#[cfg(not(target_os = "linux"))]
impl Staging {
    fn new(dest: &Path) -> Result<Self, String> {
        let meta = fs::symlink_metadata(dest).map_err(|e| format!("Restore destination: {e}"))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Restore destination must be a real directory".into());
        }
        let dest = fs::canonicalize(dest).map_err(|e| e.to_string())?;
        let dir = TempDir(create_staging_dir(&dest)?);
        Ok(Self { dest, dir })
    }

    fn path(&self) -> &Path {
        &self.dir.0
    }

    fn publish(&self, source: &Path, relative: &Path) -> Result<(), String> {
        let mut parent = self.dest.clone();
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
        fs::hard_link(source, self.dest.join(relative))
            .map_err(|e| format!("Cannot restore without overwriting an existing file: {e}"))
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
            client
                .get_object_to_file(key, path, cb, &cancel)
                .map_err(|e| e.to_string())?;
            check_encryption_marker(&metadata, path)
        },
    )
}

pub fn restore_version(
    settings: &S3Settings,
    version: ObjectVersion,
    dest: &Path,
    progress: Arc<Mutex<RestoreProgress>>,
    cancel: Arc<AtomicBool>,
) -> Result<String, String> {
    let prefix = version
        .object
        .key
        .rsplit_once('/')
        .map_or("", |(prefix, _)| prefix);
    restore_with(
        vec![version.object.clone()],
        prefix,
        dest,
        &progress,
        &cancel,
        &settings.recovery_key,
        |_, path, cb| {
            let client = crate::remote::client(settings)?;
            let metadata = client
                .get_object_version_to_file(&version, path, cb, &cancel)
                .map_err(|e| {
                    version_error(
                        "Could not download the file version",
                        "s3:GetObjectVersion",
                        e,
                    )
                })?;
            check_encryption_marker(&metadata, path)
        },
    )
}

fn check_encryption_marker(metadata: &[(String, String)], path: &Path) -> Result<(), String> {
    if let Some((_, marker)) = metadata.iter().find(|(name, _)| name == "bt-encrypted") {
        if marker != "BTENC001" {
            return Err(format!("Unsupported encrypted object format: {marker}"));
        }
        if !crate::file_crypto::is_encrypted_file(path)? {
            return Err(
                "Object is marked encrypted but its encryption envelope is missing or corrupt"
                    .into(),
            );
        }
    }
    Ok(())
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
        let staging = Staging::new(dest)?;
        for (relative, o) in selected {
            if cancel.load(Ordering::Relaxed) {
                return Err("Restore cancelled".into());
            }
            progress.lock().unwrap().current = o.key.clone();
            let source = staging.path().join("download");
            let output = staging.path().join("plain");
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
            staging
                .publish(&output, &relative)
                .map_err(|e| format!("{}: {e}", o.key))?;
            fs::remove_file(&source).map_err(|e| e.to_string())?;
            fs::remove_file(&output).map_err(|e| e.to_string())?;
            let mut p = progress.lock().unwrap();
            p.files_done += 1;
            p.bytes_done = before.saturating_add(o.size);
        }
        let count = progress.lock().unwrap().files_done;
        let noun = if count == 1 { "file" } else { "files" };
        Ok(format!("Restored {count} {noun}"))
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

#[cfg(target_os = "linux")]
mod linux_restore {
    use super::create_staging_dir;
    use std::{
        ffi::CString,
        fs::{self, DirBuilder, File, OpenOptions},
        io,
        os::{
            fd::AsRawFd,
            unix::{
                ffi::OsStrExt,
                fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            },
        },
        path::{Path, PathBuf},
    };

    #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
    const O_PATH: i32 = 0x1000000;
    #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
    const O_PATH: i32 = 0o10000000;
    const O_NOFOLLOW: i32 = if cfg!(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "m68k",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )) {
        0o100000
    } else {
        0o400000
    };
    const AT_FDCWD: i32 = -100;
    const AT_SYMLINK_FOLLOW: i32 = 0x400;

    unsafe extern "C" {
        fn geteuid() -> u32;
        fn linkat(
            fd: i32,
            source: *const std::ffi::c_char,
            destfd: i32,
            dest: *const std::ffi::c_char,
            flags: i32,
        ) -> i32;
    }

    fn open_path(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH | O_NOFOLLOW)
            .open(path)
    }

    fn open_dir(path: &Path) -> io::Result<File> {
        let dir = open_path(path)?;
        if !dir.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Expected a real directory",
            ));
        }
        Ok(dir)
    }

    fn fd_path(file: &File) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
    }

    pub(super) struct Staging {
        dest: File,
        dir: File,
        entry: PathBuf,
        path: PathBuf,
    }

    impl Staging {
        pub(super) fn new(dest: &Path) -> Result<Self, String> {
            // Strip trailing separators and "." so the last directory entry
            // is the one opened without following symlinks.
            let dest_path: PathBuf = dest.components().collect();
            let dest = open_dir(&dest_path).map_err(|e| format!("Restore destination: {e}"))?;
            let entry = create_staging_dir(&fd_path(&dest))?;
            let dir = open_dir(&entry).map_err(|e| format!("Restore staging directory: {e}"))?;
            let metadata = dir.metadata().map_err(|e| e.to_string())?;
            let path = fd_path(&dir);

            // mkdir and open are separate. Only trust a private, empty
            // directory owned by this user before the path-based helpers run.
            if metadata.uid() != unsafe { geteuid() }
                || metadata.mode() & 0o777 != 0o700
                || fs::read_dir(&path)
                    .map_err(|e| e.to_string())?
                    .next()
                    .is_some()
            {
                return Err("Restore staging directory is not private and empty".into());
            }

            Ok(Self {
                dest,
                dir,
                entry,
                path,
            })
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }

        pub(super) fn publish(&self, source: &Path, relative: &Path) -> Result<(), String> {
            let source = open_path(source).map_err(|e| e.to_string())?;
            if !source.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("Restore source must be a regular file".into());
            }
            let mut dir = self.dest.try_clone().map_err(|e| e.to_string())?;
            let parts: Vec<_> = relative.components().collect();
            for part in &parts[..parts.len() - 1] {
                let child = fd_path(&dir).join(part);
                match DirBuilder::new().mode(0o700).create(&child) {
                    Ok(()) => (),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                    Err(e) => return Err(e.to_string()),
                }
                dir = open_dir(&child)
                    .map_err(|e| format!("Unsafe or inaccessible restore directory: {e}"))?;
            }
            let src =
                CString::new(fd_path(&source).as_os_str().as_bytes()).map_err(|e| e.to_string())?;
            let name = CString::new(parts.last().unwrap().as_os_str().as_bytes())
                .map_err(|e| e.to_string())?;
            // Follow the proc descriptor link to the open inode. linkat
            // atomically fails if the destination name is occupied.
            if unsafe {
                linkat(
                    AT_FDCWD,
                    src.as_ptr(),
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    AT_SYMLINK_FOLLOW,
                )
            } != 0
            {
                return Err(format!(
                    "Cannot restore without overwriting an existing file: {}",
                    io::Error::last_os_error()
                ));
            }
            Ok(())
        }
    }

    impl Drop for Staging {
        fn drop(&mut self) {
            // Remove files from the pinned directory even if it was moved.
            if let Ok(staged) = fs::read_dir(&self.path) {
                for entry in staged.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            // Linux removes a directory by name. Check identity and use
            // non-recursive removal so a name race cannot remove a tree.
            if let (Ok(current), Ok(opened)) =
                (fs::symlink_metadata(&self.entry), self.dir.metadata())
            {
                if (current.dev(), current.ino()) == (opened.dev(), opened.ino()) {
                    let _ = fs::remove_dir(&self.entry);
                }
            }
        }
    }
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
    fn temp() -> TempDir {
        TempDir(create_staging_dir(&std::env::temp_dir()).unwrap())
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
    fn exact_version_history_keeps_markers_and_stops_at_sibling_keys() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for (entry, next_key, next_id) in [
                (
                    "<DeleteMarker><Key>file</Key><VersionId>deleted</VersionId><IsLatest>true</IsLatest></DeleteMarker>",
                    "file",
                    "deleted",
                ),
                (
                    "<Version><Key>file</Key><VersionId>old</VersionId><IsLatest>false</IsLatest><Size>14</Size></Version><DeleteMarker><Key>file-copy</Key><VersionId>sibling</VersionId><IsLatest>true</IsLatest></DeleteMarker>",
                    "file-copy",
                    "sibling",
                ),
                ("", "file-copy", "sibling"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("GET /bucket?"));
                assert!(line.contains("prefix=file"));
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let body = format!(
                    "<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>{next_key}</NextKeyMarker><NextVersionIdMarker>{next_id}</NextVersionIdMarker>{entry}</ListVersionsResult>"
                );
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let settings = S3Settings {
            endpoint: format!("http://{address}"),
            bucket: "bucket".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            path_style: true,
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let first = version_page(&settings, "file", true, None, &cancel).unwrap();
        let last = version_page(&settings, "file", true, first.next.as_ref(), &cancel).unwrap();
        let empty = version_page(&settings, "file", true, None, &cancel).unwrap();
        server.join().unwrap();

        assert_eq!(first.versions.len(), 1);
        assert!(first.versions[0].is_delete_marker);
        assert!(first.next.is_some());
        assert_eq!(last.versions.len(), 1);
        assert_eq!(last.versions[0].version_id, "old");
        assert!(last.next.is_none());
        assert!(empty.versions.is_empty());
        assert!(empty.next.is_none());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn restore_keeps_using_staging_directory_after_rename() {
        let dest = temp();
        let renamed = dest.0.join("renamed-stage");
        restore_with(
            vec![obj("file", 14)],
            "",
            &dest.0,
            &state(),
            &AtomicBool::new(false),
            "",
            |key, path, cb| {
                let entry = fs::read_dir(&dest.0).unwrap().next().unwrap().unwrap();
                fs::rename(entry.path(), &renamed).unwrap();
                bytes_download(key, path, cb)
            },
        )
        .unwrap();
        assert_eq!(fs::read(dest.0.join("file")).unwrap(), b"restored bytes");
        assert_eq!(fs::read_dir(renamed).unwrap().count(), 0);
    }
    #[test]
    fn restores_exact_encrypted_version_with_identity_and_no_overwrite_checks() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let fixtures = temp();
        let recovery_key = crate::file_crypto::generate_key().unwrap();
        let original = fixtures.0.join("original");
        let cipher = fixtures.0.join("encrypted");
        let historical = b"older version before deletion";
        fs::write(&original, historical).unwrap();
        crate::file_crypto::encrypt_file(&original, &cipher, &recovery_key).unwrap();
        let bytes = fs::read(cipher).unwrap();
        let size = bytes.len() as u64;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for version in ["old+/=%2F&", "old+/=%2F&", "current"] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(
                    line.trim_end(),
                    "GET /bucket/root/caf%C3%A9%20%2B.txt?versionId=old%2B%2F%3D%252F%26 HTTP/1.1"
                );
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let body = if version == "current" {
                    b"other bytes"
                } else {
                    bytes.as_slice()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nx-amz-version-id: {version}\r\nx-amz-meta-bt-encrypted: BTENC001\r\n\r\n",
                    body.len(),
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });
        let settings = S3Settings {
            endpoint: format!("http://{address}"),
            bucket: "bucket".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
            path_style: true,
            recovery_key,
            ..Default::default()
        };
        let version = bt_s3::ObjectVersion {
            object: obj("root/café +.txt", size),
            version_id: "old+/=%2F&".into(),
            is_latest: false,
            is_delete_marker: false,
        };
        let d = temp();
        let p = state();
        restore_version(
            &settings,
            version.clone(),
            &d.0,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(fs::read(d.0.join("café +.txt")).unwrap(), historical);
        assert_eq!(p.lock().unwrap().files_done, 1);
        fs::write(d.0.join("café +.txt"), b"keep local edits").unwrap();
        let error = restore_version(
            &settings,
            version.clone(),
            &d.0,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap_err();
        assert!(error.contains("existing file"));
        let error = restore_version(
            &settings,
            version,
            &d.0,
            p.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap_err();
        assert!(error.contains("did not confirm the requested version"));
        assert_eq!(
            fs::read(d.0.join("café +.txt")).unwrap(),
            b"keep local edits"
        );
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
        assert_eq!(p.lock().unwrap().files_done, 0);
        server.join().unwrap();
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
