//! Backup engine: scan folders, compare with the upload index, upload new/changed files in parallel.
use crate::config::Config;
use crate::glob;
use crate::json::Json;
use crate::paths;
use crate::timefmt::now_secs;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Where backups go. Implemented for S3 (`remote::S3Storage`) and a local directory (tests).
pub trait Storage: Send + Sync {
    /// Upload a file to `key`; returns an ETag / version tag. `progress` gets byte deltas.
    fn upload_file(&self, key: &str, path: &Path, progress: &mut dyn FnMut(u64), cancel: &AtomicBool) -> Result<String, String>;
}

/// Copies files into a directory. Used by tests and for dry runs.
pub struct LocalDirStorage(pub PathBuf);

impl Storage for LocalDirStorage {
    fn upload_file(&self, key: &str, path: &Path, progress: &mut dyn FnMut(u64), cancel: &AtomicBool) -> Result<String, String> {
        let dest = self.0.join(key);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let mut src = std::fs::File::open(path).map_err(|e| e.to_string())?;
        let mut out = std::fs::File::create(&dest).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            if cancel.load(Ordering::Relaxed) {
                drop(out);
                let _ = std::fs::remove_file(&dest);
                return Err("cancelled".into());
            }
            let n = std::io::Read::read(&mut src, &mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            progress(n as u64);
        }
        Ok("local".into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Scanning,
    Uploading,
    Finished,
    FinishedWithErrors,
    Failed,
    Cancelled,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Scanning => "scanning",
            Phase::Uploading => "uploading",
            Phase::Finished => "finished",
            Phase::FinishedWithErrors => "finished_with_errors",
            Phase::Failed => "failed",
            Phase::Cancelled => "cancelled",
        }
    }
    pub fn from_str(s: &str) -> Phase {
        match s {
            "scanning" => Phase::Scanning,
            "uploading" => Phase::Uploading,
            "finished" => Phase::Finished,
            "finished_with_errors" => Phase::FinishedWithErrors,
            "failed" => Phase::Failed,
            "cancelled" => Phase::Cancelled,
            _ => Phase::Idle,
        }
    }
    pub fn is_running(self) -> bool {
        matches!(self, Phase::Scanning | Phase::Uploading)
    }
}

#[derive(Clone, Debug)]
pub struct Progress {
    pub phase: Phase,
    pub trigger: String,
    pub started: i64,
    pub finished: i64,
    pub files_found: u64,
    pub files_to_upload: u64,
    pub files_uploaded: u64,
    pub files_skipped: u64,
    pub files_failed: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub current: Vec<String>,
    pub errors: Vec<String>,
    pub message: String,
}

impl Default for Progress {
    fn default() -> Self {
        Progress {
            phase: Phase::Idle,
            trigger: String::new(),
            started: 0,
            finished: 0,
            files_found: 0,
            files_to_upload: 0,
            files_uploaded: 0,
            files_skipped: 0,
            files_failed: 0,
            bytes_total: 0,
            bytes_done: 0,
            current: Vec::new(),
            errors: Vec::new(),
            message: String::new(),
        }
    }
}

const MAX_ERRORS_KEPT: usize = 500;

impl Progress {
    fn error(&mut self, e: String) {
        if self.errors.len() < MAX_ERRORS_KEPT {
            self.errors.push(e);
        }
    }

    pub fn to_json(&self) -> Json {
        let mut j = Json::obj();
        j.set("phase", self.phase.as_str());
        j.set("trigger", self.trigger.as_str());
        j.set("started", self.started as f64);
        j.set("finished", self.finished as f64);
        j.set("files_found", self.files_found);
        j.set("files_to_upload", self.files_to_upload);
        j.set("files_uploaded", self.files_uploaded);
        j.set("files_skipped", self.files_skipped);
        j.set("files_failed", self.files_failed);
        j.set("bytes_total", self.bytes_total);
        j.set("bytes_done", self.bytes_done);
        j.set("message", self.message.as_str());
        j.set("current", Json::Arr(self.current.iter().map(|s| Json::from(s.as_str())).collect()));
        j.set("errors", Json::Arr(self.errors.iter().take(50).map(|s| Json::from(s.as_str())).collect()));
        j
    }

    pub fn from_json(j: &Json) -> Progress {
        let n = |k: &str| j.num_or(k, 0.0) as u64;
        Progress {
            phase: Phase::from_str(&j.str_or("phase", "idle")),
            trigger: j.str_or("trigger", ""),
            started: j.num_or("started", 0.0) as i64,
            finished: j.num_or("finished", 0.0) as i64,
            files_found: n("files_found"),
            files_to_upload: n("files_to_upload"),
            files_uploaded: n("files_uploaded"),
            files_skipped: n("files_skipped"),
            files_failed: n("files_failed"),
            bytes_total: n("bytes_total"),
            bytes_done: n("bytes_done"),
            current: j.arr("current").iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            errors: j.arr("errors").iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            message: j.str_or("message", ""),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Upload index: remembers what was uploaded (size + mtime) so unchanged files are skipped.

#[derive(Clone, Debug, PartialEq)]
pub struct IndexEntry {
    pub size: u64,
    pub mtime_ns: i128,
    pub etag: String,
}

pub struct UploadIndex {
    pub path: PathBuf,
    pub entries: HashMap<String, IndexEntry>,
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n").replace('\r', "\\r")
}
fn unesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('t') => o.push('\t'),
                Some('n') => o.push('\n'),
                Some('r') => o.push('\r'),
                Some(x) => o.push(x),
                None => {}
            }
        } else {
            o.push(c);
        }
    }
    o
}

impl UploadIndex {
    /// One index per destination (endpoint + bucket), so switching buckets re-uploads.
    pub fn path_for(cfg: &Config) -> PathBuf {
        let id = format!("{}|{}", cfg.s3.endpoint.trim(), cfg.s3.bucket.trim());
        let h = bt_tls::crypto::util::hex(&bt_tls::crypto::sha256::sha256(id.as_bytes()));
        paths::app_dir().join(format!("index-{}.tsv", &h[..16]))
    }

    pub fn load(path: PathBuf) -> UploadIndex {
        let mut entries = HashMap::new();
        if let Ok(s) = std::fs::read_to_string(&path) {
            for line in s.lines() {
                let f: Vec<&str> = line.split('\t').collect();
                if f.len() == 4 {
                    if let (Ok(size), Ok(mt)) = (f[1].parse(), f[2].parse()) {
                        entries.insert(unesc(f[0]), IndexEntry { size, mtime_ns: mt, etag: unesc(f[3]) });
                    }
                }
            }
        }
        UploadIndex { path, entries }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let mut s = String::with_capacity(self.entries.len() * 80);
        let mut keys: Vec<&String> = self.entries.keys().collect();
        keys.sort();
        for k in keys {
            let e = &self.entries[k];
            s.push_str(&format!("{}\t{}\t{}\t{}\n", esc(k), e.size, e.mtime_ns, esc(&e.etag)));
        }
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        paths::write_private(&self.path, s.as_bytes())
    }
}

// ---------------------------------------------------------------------------------------------
// Scanning

#[derive(Clone, Debug)]
pub struct FileJob {
    pub path: PathBuf,
    pub key: String,
    pub size: u64,
    pub mtime_ns: i128,
}

fn mtime_ns(md: &std::fs::Metadata) -> i128 {
    md.modified()
        .ok()
        .map(|t| match t.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        })
        .unwrap_or(0)
}

fn is_hidden(name: &str, _md: &std::fs::Metadata) -> bool {
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if _md.file_attributes() & 0x2 != 0 {
            return true;
        }
    }
    false
}

/// Walk one folder. Calls `on_file` for each included regular file, `on_err` for problems.
pub fn scan_folder(
    root: &Path,
    key_prefix: &str,
    excludes: &[String],
    skip_hidden: bool,
    cancel: &AtomicBool,
    on_file: &mut dyn FnMut(FileJob),
    on_err: &mut dyn FnMut(String),
) {
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                on_err(format!("{}: {}", dir.display(), e));
                continue;
            }
        };
        let mut items: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        items.sort_by_key(|e| e.file_name());
        for ent in items {
            let name = ent.file_name().to_string_lossy().to_string();
            let rel_path = if rel.is_empty() { name.clone() } else { format!("{}/{}", rel, name) };
            // symlink_metadata: never follow symlinks (avoids loops and escaping the folder)
            let md = match std::fs::symlink_metadata(ent.path()) {
                Ok(m) => m,
                Err(e) => {
                    on_err(format!("{}: {}", ent.path().display(), e));
                    continue;
                }
            };
            if md.file_type().is_symlink() {
                continue;
            }
            if skip_hidden && is_hidden(&name, &md) {
                continue;
            }
            if excludes.iter().any(|p| glob::matches(p, &rel_path)) {
                continue;
            }
            if md.is_dir() {
                stack.push((ent.path(), rel_path));
            } else if md.is_file() {
                on_file(FileJob { path: ent.path(), key: format!("{}{}", key_prefix, rel_path), size: md.len(), mtime_ns: mtime_ns(&md) });
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Run lock + shared status file (lets the GUI see a scheduled run happening in another process).

pub struct RunLock {
    path: PathBuf,
}

const LOCK_STALE_SECS: i64 = 120;

impl RunLock {
    pub fn path() -> PathBuf {
        paths::app_dir().join("run.lock")
    }
    pub fn acquire() -> Result<RunLock, String> {
        let dir = paths::ensure_app_dir().map_err(|e| e.to_string())?;
        let path = dir.join("run.lock");
        for _ in 0..2 {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    let _ = f.write_all(Progress::default().to_json().to_string_compact().as_bytes());
                    return Ok(RunLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Self::is_stale(&path) {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    return Err("Another backup is already running.".into());
                }
                Err(e) => return Err(format!("cannot create lock file: {}", e)),
            }
        }
        Err("Another backup is already running.".into())
    }
    fn is_stale(path: &Path) -> bool {
        let age = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(i64::MAX);
        age > LOCK_STALE_SECS
    }
    /// Heartbeat: rewrite the lock with current progress (also refreshes its mtime).
    pub fn update(&self, p: &Progress) {
        let _ = std::fs::write(&self.path, p.to_json().to_string_compact());
    }
    /// Progress of a run happening in any process, if one is active.
    pub fn read_active() -> Option<Progress> {
        let path = Self::path();
        if Self::is_stale(&path) {
            return None;
        }
        let s = std::fs::read_to_string(&path).ok()?;
        Json::parse(&s).ok().map(|j| Progress::from_json(&j))
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------------------------
// History

pub fn history_path() -> PathBuf {
    paths::app_dir().join("history.jsonl")
}

pub fn append_history(p: &Progress) {
    let path = history_path();
    let mut lines: Vec<String> = std::fs::read_to_string(&path).unwrap_or_default().lines().map(String::from).collect();
    lines.push(p.to_json().to_string_compact());
    let keep = lines.len().saturating_sub(200);
    let _ = paths::ensure_app_dir();
    let _ = paths::write_private(&path, (lines[keep..].join("\n") + "\n").as_bytes());
}

/// Most recent first.
pub fn load_history() -> Vec<Progress> {
    let mut v: Vec<Progress> = std::fs::read_to_string(history_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| Json::parse(l).ok())
        .map(|j| Progress::from_json(&j))
        .collect();
    v.reverse();
    v
}

pub fn log_line(msg: &str) {
    let dir = match paths::ensure_app_dir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.join("backup.log");
    if std::fs::metadata(&path).map(|m| m.len() > 5 * 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::rename(&path, dir.join("backup.log.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {}", crate::timefmt::format_local(now_secs()), msg);
    }
}

// ---------------------------------------------------------------------------------------------
// The run itself

pub struct Shared {
    pub progress: Mutex<Progress>,
    pub cancel: AtomicBool,
}

impl Shared {
    pub fn new() -> Arc<Shared> {
        Arc::new(Shared { progress: Mutex::new(Progress::default()), cancel: AtomicBool::new(false) })
    }
    pub fn snapshot(&self) -> Progress {
        self.progress.lock().unwrap().clone()
    }
}

/// Run a complete backup. Blocks until finished. Progress is published in `shared`.
pub fn run_backup(cfg: &Config, storage: Arc<dyn Storage>, shared: Arc<Shared>, trigger: &str) -> Progress {
    shared.cancel.store(false, Ordering::SeqCst);
    {
        let mut p = shared.progress.lock().unwrap();
        *p = Progress { phase: Phase::Scanning, trigger: trigger.into(), started: now_secs(), message: "Preparing…".into(), ..Default::default() };
    }
    let finish = |phase: Phase, msg: String| -> Progress {
        let mut p = shared.progress.lock().unwrap();
        p.phase = phase;
        p.finished = now_secs();
        p.message = msg;
        p.current.clear();
        let out = p.clone();
        drop(p);
        log_line(&format!(
            "backup {} ({}): uploaded {}, unchanged {}, failed {}, {} — {}",
            phase.as_str(), trigger, out.files_uploaded, out.files_skipped, out.files_failed,
            crate::timefmt::human_bytes(out.bytes_done), out.message
        ));
        append_history(&out);
        out
    };

    let lock = match RunLock::acquire() {
        Ok(l) => l,
        Err(e) => return finish(Phase::Failed, e),
    };
    let folders: Vec<_> = cfg.folders.iter().filter(|f| f.enabled).cloned().collect();
    if folders.is_empty() {
        return finish(Phase::Failed, "No folders selected for backup.".into());
    }
    log_line(&format!("backup started ({}), {} folder(s)", trigger, folders.len()));

    // --- scan
    let index_path = UploadIndex::path_for(cfg);
    let index = Arc::new(Mutex::new(UploadIndex::load(index_path)));
    let mut queue: VecDeque<FileJob> = VecDeque::new();
    let mut last_beat = Instant::now();
    for f in &folders {
        let root = PathBuf::from(&f.path);
        if !root.is_dir() {
            let mut p = shared.progress.lock().unwrap();
            p.error(format!("Folder not found: {}", f.path));
            p.files_failed += 1;
            continue;
        }
        let prefix = cfg.remote_root(f);
        let idx = index.lock().unwrap();
        scan_folder(
            &root,
            &prefix,
            &cfg.excludes,
            cfg.skip_hidden,
            &shared.cancel,
            &mut |job| {
                let mut p = shared.progress.lock().unwrap();
                p.files_found += 1;
                let unchanged = idx.entries.get(&job.key).map(|e| e.size == job.size && e.mtime_ns == job.mtime_ns).unwrap_or(false);
                if unchanged {
                    p.files_skipped += 1;
                } else {
                    p.files_to_upload += 1;
                    p.bytes_total += job.size;
                    queue.push_back(job);
                }
                if p.files_found % 500 == 0 {
                    p.message = format!("Scanning… {} files", p.files_found);
                }
                if last_beat.elapsed() > Duration::from_secs(2) {
                    lock.update(&p);
                    last_beat = Instant::now();
                }
            },
            &mut |e| shared.progress.lock().unwrap().error(e),
        );
    }
    if shared.cancel.load(Ordering::SeqCst) {
        return finish(Phase::Cancelled, "Backup cancelled.".into());
    }

    // --- upload
    {
        let mut p = shared.progress.lock().unwrap();
        p.phase = Phase::Uploading;
        p.message = if p.files_to_upload == 0 {
            "Everything is up to date.".into()
        } else {
            format!("Uploading {} files ({})", p.files_to_upload, crate::timefmt::human_bytes(p.bytes_total))
        };
        lock.update(&p);
    }
    let queue = Arc::new(Mutex::new(queue));
    let workers = cfg.parallel_uploads.clamp(1, 16) as usize;
    let dirty = Arc::new(AtomicBool::new(false));
    let fatal: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (queue, shared, storage, index, dirty, fatal) =
            (queue.clone(), shared.clone(), storage.clone(), index.clone(), dirty.clone(), fatal.clone());
        handles.push(std::thread::spawn(move || {
            let mut consecutive_failures = 0;
            loop {
                if shared.cancel.load(Ordering::Relaxed) {
                    return;
                }
                let job = match queue.lock().unwrap().pop_front() {
                    Some(j) => j,
                    None => return,
                };
                let short = job.key.clone();
                shared.progress.lock().unwrap().current.push(short.clone());
                // Re-stat: the file may have changed since the scan.
                let (size, mt) = match std::fs::metadata(&job.path) {
                    Ok(m) => (m.len(), mtime_ns(&m)),
                    Err(e) => {
                        let mut p = shared.progress.lock().unwrap();
                        p.current.retain(|c| c != &short);
                        p.files_failed += 1;
                        p.bytes_total = p.bytes_total.saturating_sub(job.size);
                        p.error(format!("{}: {}", job.path.display(), e));
                        continue;
                    }
                };
                if size != job.size {
                    let mut p = shared.progress.lock().unwrap();
                    p.bytes_total = p.bytes_total.saturating_sub(job.size) + size;
                }
                let mut sent = 0u64;
                let res = storage.upload_file(
                    &job.key,
                    &job.path,
                    &mut |d| {
                        sent += d;
                        shared.progress.lock().unwrap().bytes_done += d;
                    },
                    &shared.cancel,
                );
                let mut p = shared.progress.lock().unwrap();
                p.current.retain(|c| c != &short);
                match res {
                    Ok(etag) => {
                        consecutive_failures = 0;
                        p.files_uploaded += 1;
                        // account for bytes not reported (e.g. retries reset) so totals line up
                        if sent < size {
                            p.bytes_done += size - sent;
                        }
                        drop(p);
                        index.lock().unwrap().entries.insert(job.key.clone(), IndexEntry { size, mtime_ns: mt, etag });
                        dirty.store(true, Ordering::Relaxed);
                    }
                    Err(e) => {
                        p.bytes_done = p.bytes_done.saturating_sub(sent);
                        p.bytes_total = p.bytes_total.saturating_sub(size);
                        if shared.cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        p.files_failed += 1;
                        p.error(format!("{}: {}", job.path.display(), e));
                        consecutive_failures += 1;
                        // Credentials/bucket problems fail every file the same way: stop early.
                        let lower = e.to_lowercase();
                        if consecutive_failures >= 3
                            && (lower.contains("access denied") || lower.contains("accessdenied") || lower.contains("invalidaccesskeyid")
                                || lower.contains("signaturedoesnotmatch") || lower.contains("nosuchbucket")
                                || lower.contains("access key") || lower.contains("secret key") || lower.contains("does not exist"))
                        {
                            *fatal.lock().unwrap() = Some(e);
                            shared.cancel.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                }
            }
        }));
    }
    // Heartbeat + periodic index save while workers run.
    let mut last_save = Instant::now();
    loop {
        if handles.iter().all(|h| h.is_finished()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
        if last_beat.elapsed() > Duration::from_secs(2) {
            lock.update(&shared.progress.lock().unwrap());
            last_beat = Instant::now();
        }
        if last_save.elapsed() > Duration::from_secs(20) && dirty.swap(false, Ordering::Relaxed) {
            let _ = index.lock().unwrap().save();
            last_save = Instant::now();
        }
    }
    for h in handles {
        let _ = h.join();
    }
    let save_err = index.lock().unwrap().save().err();
    if let Some(e) = fatal.lock().unwrap().take() {
        return finish(Phase::Failed, format!("Backup stopped: {}", e));
    }
    if shared.cancel.load(Ordering::SeqCst) {
        return finish(Phase::Cancelled, "Backup cancelled.".into());
    }
    if let Some(e) = save_err {
        shared.progress.lock().unwrap().error(format!("Could not save upload index: {}", e));
    }
    let p = shared.snapshot();
    if p.files_failed > 0 || !p.errors.is_empty() {
        let n = p.files_failed.max(p.errors.len() as u64);
        finish(Phase::FinishedWithErrors, format!("Backup finished with {} problem(s).", n))
    } else if p.files_uploaded == 0 {
        finish(Phase::Finished, "Everything was already backed up.".into())
    } else {
        finish(Phase::Finished, format!("Backed up {} file(s).", p.files_uploaded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::sync::atomic::AtomicUsize;

    pub(crate) fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bt-test-{}-{}-{}", name, std::process::id(), now_secs()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct FlakyStorage {
        inner: LocalDirStorage,
        calls: AtomicUsize,
        fail_name: &'static str,
    }
    impl Storage for FlakyStorage {
        fn upload_file(&self, key: &str, path: &Path, pr: &mut dyn FnMut(u64), c: &AtomicBool) -> Result<String, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if key.ends_with(self.fail_name) {
                return Err("simulated network error".into());
            }
            self.inner.upload_file(key, path, pr, c)
        }
    }

    #[test]
    fn full_and_incremental() {
        let home = tmpdir("home");
        std::env::set_var("BACKUP_TAKER_HOME", &home);
        std::env::set_var("BACKUP_TAKER_PLAIN_SECRETS", "1");
        let src = tmpdir("src");
        let dst = tmpdir("dst");
        std::fs::create_dir_all(src.join("sub/deeper")).unwrap();
        std::fs::create_dir_all(src.join("node_modules/x")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::write(src.join("sub/b.bin"), vec![7u8; 300_000]).unwrap();
        std::fs::write(src.join("sub/deeper/ü n i.txt"), b"unicode").unwrap();
        std::fs::write(src.join("sub/skip.tmp"), b"tmp").unwrap();
        std::fs::write(src.join("node_modules/x/y.js"), b"js").unwrap();
        std::fs::write(src.join("bad.dat"), b"bad").unwrap();

        let mut cfg = Config::default();
        cfg.device_name = "pc".into();
        cfg.s3.bucket = "bucket".into();
        cfg.excludes.push("node_modules".into());
        cfg.add_folder(src.to_str().unwrap());
        let label = cfg.folders[0].label.clone();

        let storage = Arc::new(FlakyStorage { inner: LocalDirStorage(dst.clone()), calls: AtomicUsize::new(0), fail_name: "bad.dat" });
        let shared = Shared::new();
        let p = run_backup(&cfg, storage.clone(), shared.clone(), "test");
        assert_eq!(p.phase, Phase::FinishedWithErrors, "{:?}", p);
        assert_eq!(p.files_found, 4);
        assert_eq!(p.files_uploaded, 3);
        assert_eq!(p.files_failed, 1);
        let root = dst.join("pc").join(&label);
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(root.join("sub/b.bin")).unwrap().len(), 300_000);
        assert!(root.join("sub/deeper/ü n i.txt").exists());
        assert!(!root.join("sub/skip.tmp").exists());
        assert!(!root.join("node_modules").exists());
        assert!(!RunLock::path().exists(), "lock released");

        // Second run: only the failed file is retried.
        let before = storage.calls.load(Ordering::SeqCst);
        let p2 = run_backup(&cfg, storage.clone(), shared.clone(), "test");
        assert_eq!(storage.calls.load(Ordering::SeqCst) - before, 1);
        assert_eq!(p2.files_skipped, 3);

        // Modify a file -> re-uploaded.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(src.join("a.txt"), b"hello again").unwrap();
        std::fs::remove_file(src.join("bad.dat")).unwrap();
        let p3 = run_backup(&cfg, storage.clone(), shared.clone(), "test");
        assert_eq!(p3.phase, Phase::Finished, "{:?}", p3);
        assert_eq!(p3.files_uploaded, 1);
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), b"hello again");
        assert_eq!(load_history().len(), 3);

        // A held lock blocks a concurrent run.
        let l = RunLock::acquire().unwrap();
        let p4 = run_backup(&cfg, storage.clone(), shared.clone(), "test");
        assert_eq!(p4.phase, Phase::Failed);
        drop(l);
        std::env::remove_var("BACKUP_TAKER_HOME");
    }

    #[test]
    fn index_escaping() {
        let d = tmpdir("idx");
        let mut ix = UploadIndex::load(d.join("i.tsv"));
        ix.entries.insert("a\tb\nc\\d".into(), IndexEntry { size: 5, mtime_ns: -12, etag: "\"x\"".into() });
        ix.save().unwrap();
        let back = UploadIndex::load(d.join("i.tsv"));
        assert_eq!(back.entries, ix.entries);
    }
}
