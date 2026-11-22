//! Backup engine: scan folders, compare with the upload index, upload new/changed files in parallel.
use crate::config::{Config, Folder, DEV_ARTIFACT_DIRS};
use crate::glob;
use crate::json::Json;
use crate::paths;
use crate::timefmt::now_secs;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Where backups go. Implemented for S3 (`remote::S3Storage`) and a local directory (tests).
pub trait Storage: Send + Sync {
    /// Upload a file to `key`; returns an ETag / version tag. `progress` gets byte deltas.
    fn upload_file(&self, key: &str, path: &Path, progress: &mut dyn FnMut(u64), cancel: &AtomicBool) -> Result<String, String>;

    /// Release any upload receipt after the corresponding index entry is durable.
    fn index_committed(&self, _key: &str) {}
}

/// Copies files into a directory for tests.
#[cfg(test)]
pub struct LocalDirStorage(pub PathBuf);

#[cfg(test)]
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
    pub bytes_skipped: u64,
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
            bytes_skipped: 0,
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
        j.set("bytes_skipped", self.bytes_skipped);
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
            bytes_skipped: n("bytes_skipped"),
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
    policy: String,
    pending_receipts: Vec<String>,
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
        if let Some(target) = &cfg.s3.managed {
            return paths::app_dir().join(format!("index-managed-{}.tsv", target.scope()));
        }
        let id = format!("{}|{}", cfg.s3.endpoint.trim(), cfg.s3.bucket.trim());
        let h = bt_tls::crypto::util::hex(&bt_tls::crypto::sha256::sha256(id.as_bytes()));
        paths::app_dir().join(format!("index-{}.tsv", &h[..16]))
    }

    pub fn for_preview(cfg: &Config) -> UploadIndex {
        Self::load_for_path(Self::path_for(cfg), cfg).0
    }

    pub fn load(path: PathBuf) -> UploadIndex {
        Self::read(path.clone(), false).unwrap_or_else(|_| UploadIndex {
            path,
            entries: HashMap::new(),
            policy: String::new(),
            pending_receipts: Vec::new(),
        })
    }

    pub fn load_checked(path: PathBuf) -> std::io::Result<UploadIndex> {
        Self::read(path, true)
    }

    fn read(path: PathBuf, strict: bool) -> std::io::Result<UploadIndex> {
        let mut entries = HashMap::new();
        let mut policy = String::new();
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        for (i, line) in contents.lines().enumerate() {
            if let Some(value) = line.strip_prefix("# encryption-policy:") {
                policy = value.to_string();
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if let [key, size, mtime, etag] = fields.as_slice() {
                if let (Ok(size), Ok(mtime_ns)) = (size.parse(), mtime.parse()) {
                    entries.insert(unesc(key), IndexEntry { size, mtime_ns, etag: unesc(etag) });
                    continue;
                }
            }
            if strict && !line.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid upload index entry at line {}", i + 1),
                ));
            }
        }
        Ok(UploadIndex { path, entries, policy, pending_receipts: Vec::new() })
    }

    pub fn policy_id(cfg: &Config) -> String {
        let key = if cfg.s3.client_encryption { cfg.s3.recovery_key.trim().to_ascii_lowercase() } else { String::new() };
        let policy = format!("{}|{}|{}|{}", cfg.s3.client_encryption, key, cfg.s3.server_encryption.trim(), cfg.s3.kms_key_id.trim());
        let policy = if cfg.s3.managed.is_some() { format!("{policy}|{}", cfg.s3.storage_class) } else { policy };
        bt_tls::crypto::util::hex(&bt_tls::crypto::sha256::sha256(policy.as_bytes()))
    }

    pub fn matches_policy(&self, cfg: &Config) -> bool {
        self.policy == Self::policy_id(cfg)
    }

    fn load_for_path(path: PathBuf, cfg: &Config) -> (UploadIndex, bool) {
        let policy = Self::policy_id(cfg);
        let mut index = Self::load(path);
        let policy_changed = index.policy != policy;
        if policy_changed {
            index.entries.clear();
            index.policy = policy;
        }
        (index, policy_changed)
    }

    pub fn save(&self) -> std::io::Result<()> {
        let mut s = String::with_capacity(self.entries.len() * 80);
        if !self.policy.is_empty() { s.push_str(&format!("# encryption-policy:{}\n", self.policy)); }
        let mut keys: Vec<&String> = self.entries.keys().collect();
        keys.sort();
        for k in keys {
            let e = &self.entries[k];
            s.push_str(&format!("{}\t{}\t{}\t{}\n", esc(k), e.size, e.mtime_ns, esc(&e.etag)));
        }
        let parent = self.path.parent().filter(|path| !path.as_os_str().is_empty());
        if let Some(parent) = parent {
            std::fs::create_dir_all(parent)?;
        }
        paths::write_private(&self.path, s.as_bytes())?;
        #[cfg(unix)]
        if let Some(parent) = parent {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
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

enum ScanEvent {
    File(FileJob),
    Error(String),
    Tick,
}

fn scan_folder(
    folder: &Folder,
    cfg: &Config,
    resume_dir: Option<&Path>,
    cancel: &AtomicBool,
    on_event: &mut impl FnMut(ScanEvent),
) {
    let root = PathBuf::from(&folder.path);
    let mut skip_resume = None;
    if let Some(resume_dir) = resume_dir {
        if let Ok(resolved_root) = root.canonicalize() {
            if resolved_root.starts_with(resume_dir) {
                return;
            }
            skip_resume = resume_dir.strip_prefix(&resolved_root).ok().map(|path| root.join(path));
        }
    }
    let mut stack: Vec<(PathBuf, String)> = vec![(root, String::new())];
    let key_prefix = cfg.remote_root(folder);
    let skip_dev_artifacts = folder.skip_dev_artifacts.unwrap_or(cfg.skip_dev_artifacts);
    let mut last_tick = Instant::now();
    while let Some((dir, rel)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                on_event(ScanEvent::Error(format!("{}: {}", dir.display(), e)));
                continue;
            }
        };
        for ent in rd {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if last_tick.elapsed() >= Duration::from_millis(250) {
                on_event(ScanEvent::Tick);
                last_tick = Instant::now();
            }
            let ent = match ent {
                Ok(ent) => ent,
                Err(e) => {
                    on_event(ScanEvent::Error(format!("{}: {}", dir.display(), e)));
                    continue;
                }
            };
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if cfg.skip_hidden && name.starts_with('.') {
                continue;
            }
            let skip_dev_dir = skip_dev_artifacts && DEV_ARTIFACT_DIRS.contains(&name.as_ref());
            let rel_path = if rel.is_empty() { name.into_owned() } else { format!("{rel}/{name}") };
            if cfg.excludes.iter().chain(&folder.excludes).any(|p| glob::matches(p, &rel_path)) {
                continue;
            }
            let path = ent.path();
            let md = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    on_event(ScanEvent::Error(format!("{}: {}", path.display(), e)));
                    continue;
                }
            };
            if md.file_type().is_symlink() {
                continue;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if cfg.skip_hidden && md.file_attributes() & 0x2 != 0 {
                    continue;
                }
            }
            if md.is_dir() {
                if !skip_dev_dir && skip_resume.as_ref() != Some(&path) {
                    stack.push((path, rel_path));
                }
            } else if md.is_file() {
                on_event(ScanEvent::File(FileJob {
                    path,
                    key: format!("{key_prefix}{rel_path}"),
                    size: md.len(),
                    mtime_ns: mtime_ns(&md),
                }));
            }
        }
        if last_tick.elapsed() >= Duration::from_millis(250) {
            on_event(ScanEvent::Tick);
            last_tick = Instant::now();
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
                    return Err("Another backup or verification is already running.".into());
                }
                Err(e) => return Err(format!("cannot create lock file: {}", e)),
            }
        }
        Err("Another backup or verification is already running.".into())
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
    pub(crate) fn start(&self, trigger: &str) {
        *self.progress.lock().unwrap() = Progress {
            phase: Phase::Scanning,
            trigger: trigger.into(),
            started: now_secs(),
            message: "Scanning folders…".into(),
            ..Progress::default()
        };
    }
    pub(crate) fn finish(&self, phase: Phase, message: String) -> Progress {
        let mut p = self.progress.lock().unwrap();
        p.phase = phase;
        p.finished = now_secs();
        p.message = message;
        p.current.clear();
        p.clone()
    }
}

pub(crate) fn scan_backup(
    cfg: &Config,
    shared: &Shared,
    cancel: &AtomicBool,
    mut is_unchanged: impl FnMut(&FileJob) -> bool,
    mut on_upload: impl FnMut(FileJob),
) {
    let resume_dir = crate::remote::upload_resume_dir();
    let resume_dir = resume_dir.canonicalize().ok().or_else(|| {
        // The uploader may create the resume directory after scanning starts.
        let parent = resume_dir.parent()?.canonicalize().ok()?;
        Some(parent.join(resume_dir.file_name()?))
    });
    let mut found = 0;
    let mut skipped = 0;
    let mut bytes_skipped = 0;
    let publish = |found, skipped, bytes_skipped| {
        let mut p = shared.progress.lock().unwrap();
        p.files_found = found;
        p.files_skipped = skipped;
        p.bytes_skipped = bytes_skipped;
        if p.files_to_upload == 0 {
            p.message = format!("Scanning… {found} files");
        }
    };
    for f in cfg.folders.iter().filter(|f| f.enabled) {
        scan_folder(
            f,
            cfg,
            resume_dir.as_deref(),
            cancel,
            &mut |event| match event {
                ScanEvent::File(job) => {
                    found += 1;
                    if is_unchanged(&job) {
                        skipped += 1;
                        bytes_skipped += job.size;
                    } else {
                        {
                            let mut p = shared.progress.lock().unwrap();
                            p.files_to_upload += 1;
                            p.bytes_total += job.size;
                        }
                        on_upload(job);
                    }
                }
                ScanEvent::Error(e) => {
                    let mut p = shared.progress.lock().unwrap();
                    p.files_failed += 1;
                    p.error(e);
                }
                ScanEvent::Tick => publish(found, skipped, bytes_skipped),
            },
        );
        if cancel.load(Ordering::Relaxed) {
            break;
        }
    }
    publish(found, skipped, bytes_skipped);
}

pub(crate) fn is_unchanged(index: &UploadIndex, job: &FileJob) -> bool {
    index.entries.get(&job.key)
        .is_some_and(|entry| entry.size == job.size && entry.mtime_ns == job.mtime_ns)
}

/// Estimate backup work using the current local index, without creating a queue or writing state.
pub fn preview_backup(cfg: &Config, shared: &Shared, full: bool) -> Progress {
    let index = UploadIndex::for_preview(cfg);
    preview_with_index(cfg, shared, full, &index)
}

pub fn preview_with_index(cfg: &Config, shared: &Shared, full: bool, index: &UploadIndex) -> Progress {
    let trigger = if full { "Full backup preview" } else { "Incremental backup preview" };
    shared.start(trigger);
    if !cfg.folders.iter().any(|f| f.enabled) {
        return shared.finish(Phase::Failed, "No folders selected for backup.".into());
    }
    scan_backup(cfg, shared, &shared.cancel, |job| !full && is_unchanged(index, job), |_| {});
    if shared.cancel.load(Ordering::Relaxed) {
        return shared.finish(Phase::Cancelled, "Backup preview stopped.".into());
    }
    let p = shared.snapshot();
    if p.files_failed > 0 {
        shared.finish(Phase::FinishedWithErrors, format!("Preview found {} scan problem(s).", p.files_failed))
    } else {
        shared.finish(Phase::Finished, "Backup preview ready.".into())
    }
}

/// Run a complete backup. Blocks until finished. Progress is published in `shared`.
#[cfg(test)]
pub fn run_backup(cfg: &Config, storage: Arc<dyn Storage>, shared: Arc<Shared>, trigger: &str) -> Progress {
    run_backup_mode(cfg, storage, shared, trigger, false)
}
#[cfg(test)]
pub fn run_backup_full(cfg: &Config, storage: Arc<dyn Storage>, shared: Arc<Shared>, trigger: &str) -> Progress {
    run_backup_mode(cfg, storage, shared, trigger, true)
}
#[cfg(test)]
fn run_backup_mode(cfg: &Config, storage: Arc<dyn Storage>, shared: Arc<Shared>, trigger: &str, full: bool) -> Progress {
    shared.start(trigger);
    let lock = match RunLock::acquire() {
        Ok(l) => l,
        Err(e) => return shared.finish(Phase::Failed, e),
    };
    run_backup_locked(cfg, storage, shared, trigger, full, &lock)
}

pub(crate) fn run_backup_locked(
    cfg: &Config, storage: Arc<dyn Storage>, shared: Arc<Shared>, trigger: &str, full: bool, lock: &RunLock,
) -> Progress {
    shared.start(trigger);
    let finish = |phase: Phase, msg: String| -> Progress {
        let out = shared.finish(phase, msg);
        log_line(&format!(
            "backup {} ({}): uploaded {}, unchanged {}, failed {}, {} — {}",
            phase.as_str(), trigger, out.files_uploaded, out.files_skipped, out.files_failed,
            crate::timefmt::human_bytes(out.bytes_done), out.message
        ));
        append_history(&out);
        out
    };

    let folders = cfg.folders.iter().filter(|f| f.enabled).count();
    if folders == 0 {
        return finish(Phase::Failed, "No folders selected for backup.".into());
    }
    log_line(&format!("backup started ({}), {} folder(s)", trigger, folders));

    let (index, policy_changed) = UploadIndex::load_for_path(UploadIndex::path_for(cfg), cfg);
    let index = Mutex::new(index);
    let dirty = AtomicBool::new(false);
    let fatal = Mutex::new(None);
    lock.update(&shared.snapshot());
    std::thread::scope(|scope| {
        let (done, wait) = mpsc::channel::<()>();
        let (index, dirty, fatal) = (&index, &dirty, &fatal);
        let (shared, storage) = (shared.as_ref(), storage.as_ref());
        let work = scope.spawn(move || {
            let _done = done;
            let mut uploads = None;
            let mut workers = Vec::new();
            scan_backup(cfg, shared, &shared.cancel, |job| !full && is_unchanged(&index.lock().unwrap(), job), |job| {
                if uploads.is_none() {
                    // Persist invalidation before touching remote objects, even if interrupted.
                    if policy_changed {
                        if let Err(e) = index.lock().unwrap().save() {
                            *fatal.lock().unwrap() = Some(format!("Could not save upload index: {e}"));
                            shared.cancel.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                    let count = cfg.parallel_uploads.clamp(1, 16) as usize;
                    let (tx, rx) = mpsc::sync_channel(count * 4);
                    let rx = Arc::new(Mutex::new(rx));
                    for _ in 0..count {
                        let rx = rx.clone();
                        workers.push(scope.spawn(move || upload_worker(&rx, shared, storage, index, dirty, fatal)));
                    }
                    uploads = Some(tx);
                    shared.progress.lock().unwrap().message = "Scanning folders and uploading files…".into();
                }
                if uploads.as_ref().unwrap().send(job).is_err() {
                    shared.cancel.store(true, Ordering::Relaxed);
                }
            });
            if uploads.is_some() && !shared.cancel.load(Ordering::Relaxed) {
                let mut p = shared.progress.lock().unwrap();
                p.phase = Phase::Uploading;
                p.message = format!("Uploading {} files ({})", p.files_to_upload, crate::timefmt::human_bytes(p.bytes_total));
            }
            drop(uploads);
            for worker in workers {
                if worker.join().is_err() {
                    *fatal.lock().unwrap() = Some("An upload worker stopped unexpectedly.".into());
                }
            }
        });
        let mut last_save = Instant::now();
        while wait.recv_timeout(Duration::from_secs(2)) == Err(mpsc::RecvTimeoutError::Timeout) {
            lock.update(&shared.snapshot());
            if last_save.elapsed() >= Duration::from_secs(20) && dirty.swap(false, Ordering::Relaxed) {
                if index.lock().unwrap().save().is_err() {
                    dirty.store(true, Ordering::Relaxed);
                }
                last_save = Instant::now();
            }
        }
        if work.join().is_err() {
            *fatal.lock().unwrap() = Some("The backup scan stopped unexpectedly.".into());
        }
    });
    if let Err(e) = persist_uploads(&index, storage.as_ref(), dirty.load(Ordering::Relaxed)) {
        shared.progress.lock().unwrap().error(format!("Could not save upload index: {}", e));
    }
    if let Some(e) = fatal.lock().unwrap().take() {
        return finish(Phase::Failed, format!("Backup stopped: {}", e));
    }
    if shared.cancel.load(Ordering::SeqCst) {
        return finish(Phase::Cancelled, "Backup cancelled.".into());
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

fn persist_uploads(index: &Mutex<UploadIndex>, storage: &dyn Storage, dirty: bool) -> std::io::Result<()> {
    let committed = {
        let mut index = index.lock().unwrap();
        if dirty {
            index.save()?;
        }
        std::mem::take(&mut index.pending_receipts)
    };
    for key in committed {
        storage.index_committed(&key);
    }
    Ok(())
}

fn upload_worker(
    queue: &Mutex<mpsc::Receiver<FileJob>>,
    shared: &Shared,
    storage: &dyn Storage,
    index: &Mutex<UploadIndex>,
    dirty: &AtomicBool,
    fatal: &Mutex<Option<String>>,
) {
    let mut consecutive_failures = 0;
    loop {
        if shared.cancel.load(Ordering::Relaxed) {
            return;
        }
        let next = queue.lock().unwrap().recv();
        let Ok(job) = next else {
            return;
        };
        if shared.cancel.load(Ordering::Relaxed) {
            return;
        }
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
                let mut index = index.lock().unwrap();
                index.entries.insert(job.key.clone(), IndexEntry { size, mtime_ns: mt, etag });
                index.pending_receipts.push(job.key);
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

    #[test]
    fn verification_rejects_an_incomplete_index_row() {
        let root = tmpdir("verify-index");
        let index = root.join("index.tsv");
        std::fs::write(&index, "good\t2\t3\ttag\ndeleted\tbad\t42\ttag\n").unwrap();
        assert_eq!(UploadIndex::load(index.clone()).entries.len(), 1);
        assert!(UploadIndex::load_checked(index).err().unwrap().to_string().contains("line 2"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_excludes_private_resume_state_even_if_explicitly_selected() {
        let root = tmpdir("resume-filter");
        let resume = root.join(".upload-resume.tmp");
        std::fs::create_dir_all(resume.join("slot")).unwrap();
        std::fs::write(resume.join("slot/ciphertext"), b"private").unwrap();
        std::fs::write(root.join("file.txt"), b"public").unwrap();
        let mut cfg = Config::default();
        cfg.excludes.clear();
        cfg.add_folder(root.to_str().unwrap());
        cfg.add_folder(resume.join("slot").to_str().unwrap());
        let mut found = Vec::new();
        let real_resume = resume.canonicalize().unwrap();
        for folder in &cfg.folders {
            scan_folder(folder, &cfg, Some(&real_resume), &AtomicBool::new(false), &mut |event| {
                if let ScanEvent::File(file) = event {
                    found.push(file.path);
                }
            });
        }
        assert_eq!(found, [root.join("file.txt")]);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn folder_rules_filter_shared_scan_and_previews() {
        let root = tmpdir("folder-rules");
        let mut cfg = Config::default();
        cfg.device_name = "pc".into();
        cfg.skip_hidden = true;
        cfg.excludes.push("*.global".into());
        for folder in ["inherit", "include", "exclude", "paused"] {
            let path = root.join(folder);
            for rel in ["node_modules/module.js", "src/keep.txt", "src/file.local", "src/file.global", "src/.hidden"] {
                let file = path.join(rel);
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, b"123").unwrap();
            }
            cfg.add_folder(path.to_str().unwrap());
        }
        let mut json = cfg.to_json();
        let mut folders = json.arr("folders").to_vec();
        folders[1].set("skip_dev_artifacts", false);
        folders[1].set("excludes", Json::Arr(vec![Json::from("src/*.local")]));
        folders[2].set("skip_dev_artifacts", true);
        folders[3].set("enabled", false);
        json.set("folders", Json::Arr(folders));

        for global in [true, false] {
            json.set("skip_dev_artifacts", global);
            let cfg = Config::from_json(&json);
            let shared = Shared::new();
            let mut keys = Vec::new();
            scan_backup(&cfg, &shared, &shared.cancel, |_| false, |file| keys.push(file.key));
            keys.sort_unstable();
            let mut expected = vec![
                "pc/exclude/src/file.local", "pc/exclude/src/keep.txt",
                "pc/include/node_modules/module.js", "pc/include/src/keep.txt",
                "pc/inherit/src/file.local", "pc/inherit/src/keep.txt",
            ];
            if !global {
                expected.insert(4, "pc/inherit/node_modules/module.js");
            }
            assert_eq!(keys, expected);

            let index = UploadIndex::load(root.join("unused-index.tsv"));
            for full in [false, true] {
                let preview = preview_with_index(&cfg, &Shared::new(), full, &index);
                assert_eq!(preview.phase, Phase::Finished);
                assert_eq!(preview.files_to_upload, if global { 6 } else { 7 });
                assert_eq!(preview.bytes_total, if global { 18 } else { 21 });
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn project_artifact_filter_skips_subfolders_only_when_enabled() {
        let root = tmpdir("artifact-filter");
        for rel in [
            "app/node_modules/package/index.js",
            "app/build/app.js",
            "app/dist/app.js",
            "target/debug/stow",
            "app/.next/cache/page",
            "docs/build",
            "app/src/source.js",
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"data").unwrap();
        }
        let index = UploadIndex::load(root.join("unused-index.tsv"));
        let mut cfg = Config::default();
        cfg.add_folder(root.to_str().unwrap());
        let mut saved = cfg.to_json();
        let default = preview_with_index(&Config::from_json(&saved), &Shared::new(), true, &index);
        assert_eq!(default.files_to_upload, 7);

        saved.set("skip_dev_artifacts", true);
        let cfg = Config::from_json(&Config::from_json(&saved).to_json());
        let filtered = preview_with_index(&cfg, &Shared::new(), true, &index);
        assert_eq!(filtered.phase, Phase::Finished);
        assert_eq!(filtered.files_to_upload, 2);
        assert_eq!(filtered.bytes_total, 8);
        std::fs::remove_dir_all(root).unwrap();
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

    struct CreateDuringUpload {
        inner: LocalDirStorage,
        new_file: PathBuf,
        first: AtomicBool,
    }

    impl Storage for CreateDuringUpload {
        fn upload_file(&self, key: &str, path: &Path, progress: &mut dyn FnMut(u64), cancel: &AtomicBool) -> Result<String, String> {
            if self.first.swap(false, Ordering::Relaxed) {
                std::fs::write(&self.new_file, b"created during backup").unwrap();
            }
            self.inner.upload_file(key, path, progress, cancel)
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

        let index = UploadIndex::path_for(&cfg);
        let before_preview = std::fs::read(&index).unwrap();
        let lock = RunLock::acquire().unwrap();
        let p = preview_backup(&cfg, &Shared::new(), false);
        assert_eq!(p.phase, Phase::Finished);
        assert_eq!(p.files_found, 4);
        assert_eq!(p.files_to_upload, 1);
        assert_eq!(p.bytes_total, 3);
        assert_eq!(p.bytes_skipped, 300_012);
        let p = preview_backup(&cfg, &Shared::new(), true);
        assert_eq!(p.files_to_upload, 4);
        assert_eq!(p.bytes_total, 300_015);
        assert_eq!(p.bytes_skipped, 0);
        assert_eq!(std::fs::read(&index).unwrap(), before_preview);
        assert_eq!(load_history().len(), 1);
        drop(lock);

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

        let before = std::fs::metadata(&index).unwrap().modified().unwrap();
        let clean = run_backup(&cfg, storage.clone(), Shared::new(), "test");
        assert_eq!(clean.phase, Phase::Finished);
        assert_eq!(clean.files_skipped, 3);
        assert_eq!(std::fs::metadata(&index).unwrap().modified().unwrap(), before);

        let full = run_backup_full(&cfg, storage.clone(), shared.clone(), "test-full");
        assert_eq!(full.files_uploaded, 3);
        assert_eq!(full.files_skipped, 0);

        // A held lock blocks a concurrent run.
        let l = RunLock::acquire().unwrap();
        let p4 = run_backup(&cfg, storage.clone(), shared.clone(), "test");
        assert_eq!(p4.phase, Phase::Failed);
        drop(l);
        assert_eq!(load_history().len(), 5);

        // The first directory fills the small queue before the second directory is reached.
        let first = tmpdir("stream-first");
        let second = tmpdir("stream-second");
        for i in 0..20 {
            std::fs::write(first.join(format!("{i}.txt")), b"data").unwrap();
        }
        let mut streaming_cfg = Config::default();
        streaming_cfg.s3.bucket = "streaming-test".into();
        streaming_cfg.parallel_uploads = 1;
        streaming_cfg.add_folder(first.to_str().unwrap());
        streaming_cfg.add_folder(second.to_str().unwrap());
        let streaming = Arc::new(CreateDuringUpload {
            inner: LocalDirStorage(dst.clone()),
            new_file: second.join("new.txt"),
            first: AtomicBool::new(true),
        });
        let p = run_backup(&streaming_cfg, streaming, Shared::new(), "test-streaming");
        assert_eq!(p.phase, Phase::Finished);
        assert_eq!(p.files_uploaded, 21);
        let preview = preview_backup(&streaming_cfg, &Shared::new(), false);
        assert_eq!(preview.bytes_skipped, 101);
        assert_eq!(preview.bytes_total, 0);

        let stopped = Shared::new();
        stopped.cancel.store(true, Ordering::Relaxed);
        let cancelled = preview_backup(&streaming_cfg, &stopped, false);
        assert_eq!(cancelled.phase, Phase::Cancelled);
        assert_eq!(cancelled.files_found, 0);
        std::env::remove_var("BACKUP_TAKER_HOME");
    }

    #[test]
    fn encryption_policy_invalidates_index_on_every_transition() {
        let d = tmpdir("policy"); let path = d.join("index.tsv");
        let mut cfg = Config::default();
        let (mut first, policy_changed) = UploadIndex::load_for_path(path.clone(), &cfg);
        assert!(policy_changed);
        first.entries.insert("file".into(), IndexEntry { size: 5, mtime_ns: 1, etag: "e".into() });
        first.save().unwrap();
        let (loaded, policy_changed) = UploadIndex::load_for_path(path.clone(), &cfg);
        assert!(!policy_changed);
        assert_eq!(loaded.entries.len(), 1);
        cfg.s3.client_encryption = true; cfg.s3.recovery_key = "ab".repeat(32);
        let (mut second, policy_changed) = UploadIndex::load_for_path(path.clone(), &cfg);
        assert!(policy_changed);
        assert!(second.entries.is_empty());
        second.entries.insert("file".into(), IndexEntry { size: 5, mtime_ns: 1, etag: "encrypted".into() });
        second.save().unwrap();
        cfg.s3.client_encryption = false;
        assert!(UploadIndex::load_for_path(path, &cfg).0.entries.is_empty());
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
