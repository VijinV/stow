//! The desktop window: Overview, Folders, Storage (S3), Schedule and History pages.
use crate::config::{Config, ScheduleMode};
use crate::engine::{self, Phase, Progress, Shared, UploadIndex};
use crate::timefmt::{ago, format_local, human_bytes, human_duration, now_secs};
use bt_gui::*;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Folders,
    Storage,
    Encryption,
    Dashboard,
    Schedule,
    History,
    Browse,
    Verify,
}

/// Result slot for work done on a background thread.
pub(crate) type Slot<T> = Arc<Mutex<Option<T>>>;

pub(crate) fn spawn_job<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Slot<T> {
    let slot: Slot<T> = Arc::new(Mutex::new(None));
    let s2 = slot.clone();
    std::thread::spawn(move || {
        let r = f();
        *s2.lock().unwrap() = Some(r);
    });
    slot
}

pub(crate) fn take<T>(slot: &mut Option<Slot<T>>) -> Option<T> {
    let r = slot.as_ref()?.lock().unwrap().take();
    if r.is_some() {
        *slot = None;
    }
    r
}

struct FolderScan {
    path: String,
    shared: Arc<Shared>,
    result: Slot<(Progress, Arc<UploadIndex>)>,
}

struct FolderRulesDraft {
    path: String,
    excludes_text: String,
    dev_preset: usize,
}

const PROVIDERS: &[&str] = &[
    "Amazon S3",
    "Cloudflare R2",
    "Wasabi",
    "Backblaze B2",
    "DigitalOcean Spaces",
    "Other S3-compatible (MinIO, Ceph, …)",
];

const AWS_REGIONS: &[&str] = &[
    "Detect automatically",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-central-2",
    "eu-north-1",
    "eu-south-1",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-east-1",
    "me-south-1",
    "me-central-1",
    "il-central-1",
    "af-south-1",
    "sa-east-1",
];

const STORAGE_CLASSES: &[(&str, &str)] = &[
    ("", "Bucket default (Standard)"),
    ("STANDARD", "Standard"),
    ("INTELLIGENT_TIERING", "Intelligent-Tiering"),
    ("STANDARD_IA", "Standard-IA (infrequent access)"),
    ("ONEZONE_IA", "One Zone-IA"),
    ("GLACIER_IR", "Glacier Instant Retrieval"),
];

fn provider_of(endpoint: &str) -> usize {
    let e = endpoint.to_ascii_lowercase();
    if e.is_empty() || e.contains("amazonaws.com") {
        0
    } else if e.contains("r2.cloudflarestorage.com") {
        1
    } else if e.contains("wasabisys.com") {
        2
    } else if e.contains("backblazeb2.com") {
        3
    } else if e.contains("digitaloceanspaces.com") {
        4
    } else {
        5
    }
}

struct Draft {
    provider: usize,
    endpoint: String,
    region_idx: usize,
    region_text: String,
    bucket: String,
    prefix: String,
    access_key: String,
    secret_key: String,
    path_style: bool,
    storage_class: usize,
    ca_file: String,
    device_name: String,
    show_advanced: bool,
    client_encryption: bool,
    recovery_key: String,
    server_encryption: usize,
    kms_key_id: String,
    show_recovery_key: bool,
}

impl Draft {
    fn from(cfg: &Config) -> Draft {
        let s = &cfg.s3;
        let provider = provider_of(&s.endpoint);
        Draft {
            provider,
            endpoint: s.endpoint.clone(),
            region_idx: AWS_REGIONS.iter().position(|r| *r == s.region).unwrap_or(0),
            region_text: s.region.clone(),
            bucket: s.bucket.clone(),
            prefix: s.prefix.clone(),
            access_key: s.access_key.clone(),
            secret_key: s.secret_key.clone(),
            path_style: s.path_style,
            storage_class: STORAGE_CLASSES
                .iter()
                .position(|(k, _)| *k == s.storage_class)
                .unwrap_or(0),
            ca_file: s.ca_file.clone(),
            device_name: cfg.device_name.clone(),
            client_encryption: s.client_encryption,
            recovery_key: s.recovery_key.clone(),
            server_encryption: match s.server_encryption.as_str() {
                "AES256" => 1,
                "aws:kms" => 2,
                _ => 0,
            },
            kms_key_id: s.kms_key_id.clone(),
            show_recovery_key: false,
            show_advanced: s.path_style || !s.ca_file.is_empty() || !s.storage_class.is_empty(),
        }
    }

    fn apply_local_encryption(&self, cfg: &mut Config) {
        cfg.s3.client_encryption = self.client_encryption;
        cfg.s3.recovery_key = self.recovery_key.trim().to_string();
    }

    fn apply_to(&self, cfg: &mut Config) {
        self.apply_local_encryption(cfg);
        let s = &mut cfg.s3;
        s.endpoint = if self.provider == 0 {
            String::new()
        } else {
            self.endpoint.trim().to_string()
        };
        s.region = if self.provider == 0 {
            if self.region_idx == 0 {
                String::new()
            } else {
                AWS_REGIONS[self.region_idx].to_string()
            }
        } else {
            self.region_text.trim().to_string()
        };
        s.bucket = self.bucket.trim().to_string();
        s.prefix = self.prefix.trim().trim_matches('/').to_string();
        s.access_key = self.access_key.trim().to_string();
        s.secret_key = self.secret_key.trim().to_string();
        s.path_style = self.path_style;
        s.storage_class = if self.provider == 0 {
            STORAGE_CLASSES[self.storage_class].0.to_string()
        } else {
            String::new()
        };
        s.ca_file = self.ca_file.trim().to_string();
        s.server_encryption = ["", "AES256", "aws:kms"][self.server_encryption].into();
        s.kms_key_id = if self.server_encryption == 2 {
            self.kms_key_id.trim().to_string()
        } else {
            String::new()
        };
        let d = crate::config::sanitize_label(self.device_name.trim());
        if !self.device_name.trim().is_empty() {
            cfg.device_name = d;
        }
    }
}

struct App {
    cfg: Config,
    page: Page,
    draft: Draft,
    // backup
    shared: Arc<Shared>,
    backup_job: Option<Slot<Progress>>,
    external: Option<Progress>,
    last_external_check: Instant,
    speed: SpeedMeter,
    // storage page
    test_job: Option<Slot<Result<String, String>>>,
    test_result: Option<Result<String, String>>,
    buckets_job: Option<Slot<Result<Vec<String>, String>>>,
    buckets: Vec<String>,
    bucket_pick: usize,
    // folders
    browser: Option<FolderBrowser>,
    confirm_remove: Option<usize>,
    excludes_text: String,
    folder_rules: Option<FolderRulesDraft>,
    folder_scan: Option<FolderScan>,
    folder_sizes: HashMap<String, Progress>,
    folder_index: Option<Arc<UploadIndex>>,
    // schedule
    sched_mode: usize,
    sched_interval: usize,
    sched_time: String,
    sched_job: Option<Slot<Result<String, String>>>,
    sched_status: Option<Result<String, String>>,
    parallel: i64,
    // misc
    history: Vec<Progress>,
    history_loaded: Instant,
    confirm_quit: bool,
    quit_after_backup: bool,
    show_errors: bool,
    cloud: crate::browser_ui::BrowserView,
    verification: crate::verify_ui::VerifyView,
    dashboard: crate::managed_ui::View,
    full_backup: bool,
}

/// Smoothed upload speed for the progress display.
struct SpeedMeter {
    samples: Vec<(Instant, u64)>,
}

impl SpeedMeter {
    fn reset(&mut self) {
        self.samples.clear();
    }
    fn push(&mut self, bytes: u64) -> f64 {
        let now = Instant::now();
        if self
            .samples
            .last()
            .map(|(t, _)| now.duration_since(*t) > Duration::from_millis(400))
            .unwrap_or(true)
        {
            self.samples.push((now, bytes));
        }
        self.samples
            .retain(|(t, _)| now.duration_since(*t) < Duration::from_secs(8));
        match (self.samples.first(), self.samples.last()) {
            (Some((t0, b0)), Some((t1, b1))) if t1 > t0 => {
                (b1.saturating_sub(*b0)) as f64 / t1.duration_since(*t0).as_secs_f64()
            }
            _ => 0.0,
        }
    }
}

impl App {
    fn new() -> App {
        let cfg = Config::load();
        let draft = Draft::from(&cfg);
        let page = if cfg.folders.is_empty() && !cfg.s3.is_complete() {
            Page::Overview
        } else {
            Page::Overview
        };
        App {
            excludes_text: cfg.excludes.join(", "),
            sched_mode: match cfg.schedule {
                ScheduleMode::Off => 0,
                ScheduleMode::Interval => 1,
                ScheduleMode::Daily => 2,
            },
            sched_interval: crate::schedule::INTERVAL_CHOICES
                .iter()
                .position(|&h| h == cfg.interval_hours)
                .unwrap_or(7),
            sched_time: cfg.daily_time.clone(),
            parallel: cfg.parallel_uploads as i64,
            cfg,
            page,
            draft,
            shared: Shared::new(),
            backup_job: None,
            external: None,
            last_external_check: Instant::now() - Duration::from_secs(10),
            speed: SpeedMeter {
                samples: Vec::new(),
            },
            test_job: None,
            test_result: None,
            buckets_job: None,
            buckets: Vec::new(),
            bucket_pick: 0,
            browser: None,
            confirm_remove: None,
            folder_rules: None,
            folder_scan: None,
            folder_sizes: HashMap::new(),
            folder_index: None,
            sched_job: None,
            sched_status: None,
            history: engine::load_history(),
            history_loaded: Instant::now(),
            confirm_quit: false,
            quit_after_backup: false,
            show_errors: false,
            cloud: crate::browser_ui::BrowserView::new(),
            verification: crate::verify_ui::VerifyView::default(),
            dashboard: crate::managed_ui::View::default(),
            full_backup: false,
        }
    }

    fn save(&mut self, ui: &mut Ui) -> bool {
        match self.cfg.save() {
            Ok(()) => true,
            Err(e) => {
                ui.toast(Tone::Danger, &format!("Could not save settings: {}", e));
                false
            }
        }
    }

    fn save_folder_settings(&mut self, ui: &mut Ui, cfg: Config) -> bool {
        let previous = std::mem::replace(&mut self.cfg, cfg);
        if self.save(ui) {
            true
        } else {
            self.cfg = previous;
            false
        }
    }

    fn save_folder_rules(&mut self, ui: &mut Ui, i: usize, excludes: Vec<String>, skip_dev_artifacts: Option<bool>) -> bool {
        let mut cfg = self.cfg.clone();
        let folder = &mut cfg.folders[i];
        folder.excludes = excludes;
        folder.skip_dev_artifacts = skip_dev_artifacts;
        let path = folder.path.clone();
        if self.save_folder_settings(ui, cfg) {
            self.forget_folder_size(&path);
            true
        } else {
            false
        }
    }

    fn running(&self) -> bool {
        self.backup_job.is_some()
    }

    fn stop_before_quit(&mut self) {
        self.confirm_quit = false;
        self.quit_after_backup = true;
        self.shared.cancel.store(true, Ordering::SeqCst);
    }

    fn ready_to_quit(&self) -> bool {
        self.quit_after_backup && !self.running() && !self.verification.busy() && !self.cloud.busy()
    }

    fn refresh_folder_sizes(&mut self) {
        self.folder_sizes.clear();
        self.folder_index = None;
        if let Some(scan) = &self.folder_scan {
            scan.shared.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn forget_folder_size(&mut self, path: &str) {
        self.folder_sizes.remove(path);
        if let Some(scan) = self.folder_scan.as_ref().filter(|scan| scan.path == path) {
            scan.shared.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn poll_folder_scan(&mut self, ui: &mut Ui) {
        if let Some(scan) = &self.folder_scan {
            let result = scan.result.lock().unwrap().take();
            if let Some((progress, index)) = result {
                if !scan.shared.cancel.load(Ordering::Relaxed) {
                    self.folder_sizes.insert(scan.path.clone(), progress);
                    self.folder_index = Some(index);
                }
                self.folder_scan = None;
                ui.request_repaint();
            }
        }
        if self.folder_scan.is_none() && self.page == Page::Folders
            && !self.running() && !self.verification.busy() && self.external.is_none()
        {
            if let Some(folder) = self.cfg.folders.iter().rev()
                .find(|f| f.enabled && !self.folder_sizes.contains_key(&f.path))
            {
                let path = folder.path.clone();
                let shared = Shared::new();
                let worker = shared.clone();
                let Ok(mut cfg) = self.dashboard.effective(&self.cfg) else { return };
                cfg.folders.retain(|f| f.path == path);
                let cached = self.folder_index.take();
                let result = spawn_job(move || {
                    let index = cached.unwrap_or_else(|| Arc::new(UploadIndex::for_preview(&cfg)));
                    (engine::preview_with_index(&cfg, &worker, false, &index), index)
                });
                self.folder_scan = Some(FolderScan { path, shared, result });
            } else {
                self.folder_index = None;
            }
        }
        if self.folder_scan.is_some() {
            ui.request_repaint_after(Duration::from_millis(150));
        }
    }

    fn start_backup(&mut self, ui: &mut Ui) {
        if self.running() || self.quit_after_backup {
            return;
        }
        if !self.dashboard.selected() && !self.cfg.s3.is_complete() {
            ui.toast(
                Tone::Warning,
                "Pair with your dashboard before backing up.",
            );
            self.page = Page::Dashboard;
            return;
        }
        if !self.cfg.folders.iter().any(|f| f.enabled) {
            ui.toast(Tone::Warning, "Add at least one folder to back up.");
            self.page = Page::Folders;
            return;
        }
        if self.external.is_some() || self.verification.busy() {
            ui.toast(Tone::Info, "A backup or verification is already running.");
            return;
        }
        let cfg = self.cfg.clone();
        self.refresh_folder_sizes();
        self.shared = Shared::new();
        let shared = self.shared.clone();
        *shared.progress.lock().unwrap() = Progress {
            phase: Phase::Scanning,
            message: "Starting…".into(),
            started: now_secs(),
            ..Default::default()
        };
        self.speed.reset();
        self.show_errors = false;
        let full = self.full_backup;
        self.full_backup = false;
        self.backup_job = Some(spawn_job(move || {
            let trigger = if full { "manual full" } else { "manual" };
            crate::managed::backup(&cfg, shared, trigger, full)
        }));
    }

    fn poll(&mut self, ui: &mut Ui) {
        if self.dashboard.poll(ui, &self.cfg) {
            self.refresh_folder_sizes();
            self.cloud.invalidate();
        }
        if let Some(p) = take(&mut self.backup_job) {
            self.refresh_folder_sizes();
            self.cloud.invalidate();
            let tone = match p.phase {
                Phase::Finished => Tone::Success,
                Phase::Cancelled => Tone::Info,
                Phase::FinishedWithErrors => Tone::Warning,
                _ => Tone::Danger,
            };
            ui.toast_for(tone, &p.message, Duration::from_secs(6));
            self.history = engine::load_history();
        }
        if let Some(r) = take(&mut self.test_job) {
            if r.is_ok() {
                ui.toast(Tone::Success, "Connection works");
            }
            self.test_result = Some(r);
        }
        if let Some(r) = take(&mut self.buckets_job) {
            match r {
                Ok(b) if b.is_empty() => ui.toast(
                    Tone::Info,
                    "No buckets found for these keys. Create one in your provider's console.",
                ),
                Ok(b) => {
                    self.bucket_pick = b.iter().position(|x| *x == self.draft.bucket).unwrap_or(0);
                    self.buckets = b;
                }
                Err(e) => self.test_result = Some(Err(e)),
            }
        }
        if let Some(r) = take(&mut self.sched_job) {
            match &r {
                Ok(m) => ui.toast(Tone::Success, m),
                Err(e) => ui.toast(Tone::Danger, e),
            }
            self.sched_status = Some(r);
        }
        // A backup started by the OS scheduler (another process)?
        if self.verification.busy() {
            self.external = None;
        } else if !self.running() && self.last_external_check.elapsed() > Duration::from_secs(2) {
            self.last_external_check = Instant::now();
            let was = self.external.is_some();
            self.external = engine::RunLock::read_active()
                .filter(|p| p.phase.is_running() || p.phase == Phase::Idle);
            if was && self.external.is_none() {
                self.history = engine::load_history();
                self.refresh_folder_sizes();
            }
        }
        if self.history_loaded.elapsed() > Duration::from_secs(30) {
            self.history = engine::load_history();
            self.history_loaded = Instant::now();
        }
        if self.running()
            || self.test_job.is_some()
            || self.buckets_job.is_some()
            || self.sched_job.is_some()
        {
            ui.request_repaint_after(Duration::from_millis(150));
        } else {
            ui.request_repaint_after(Duration::from_secs(2));
        }
    }
}

pub fn run() -> std::io::Result<()> {
    let opts = WindowOptions {
        title: "Stow".into(),
        width: 1040,
        height: 700,
        min_width: 820,
        min_height: 560,
        app_id: "backup-taker".into(),
        icon: Some(app_icon(64)),
    };
    let mut app = App::new();
    run_ex(opts, Theme::light(), true, &mut app, &mut |ui, app| {
        frame(ui, app)
    })
}

/// The window icon, drawn procedurally (blue rounded square with a cloud + arrow).
fn app_icon(n: u32) -> (u32, u32, Vec<u32>) {
    let mut c = Canvas::new(n, n, 1.0);
    let f = n as f32;
    c.fill_rounded_rect(Rect::new(0.0, 0.0, f, f), f * 0.22, Color::hex(0x2563EB));
    bt_gui::icons::draw_icon(
        &mut c,
        Icon::Upload,
        f * 0.18,
        f * 0.18,
        f * 0.64,
        Color::WHITE,
    );
    let px = c.pixels.clone();
    (n, n, px)
}

fn frame(ui: &mut Ui, app: &mut App) {
    app.poll(ui);
    let (w, h) = ui.screen_size();

    // ---------------- sidebar
    let side = Rect::new(0.0, 0.0, 228.0, h);
    ui.canvas.fill_rect(side, ui.theme.sidebar);
    ui.canvas
        .fill_rect(Rect::new(side.right() - 1.0, 0.0, 1.0, h), ui.theme.border);
    ui.with_rect(side.shrink2(14.0, 18.0), |ui| {
        ui.horizontal(|ui| {
            let r = ui.allocate(Some(34.0), 34.0);
            let accent = ui.theme.accent;
            ui.canvas.fill_rounded_rect(r, 8.0, accent);
            ui.paint_text_centered(r, "S", 14.0, Color::WHITE, true);
            ui.subheading("Stow");
        });
        ui.space(6.0);
        ui.small("Your files, safely kept.");
        ui.space(12.0);
        ui.set_spacing(4.0);
        let managed = app.dashboard.selected();
        let storage = if !managed && app.cfg.s3.is_complete() {
            (Icon::Cloud, "Storage", Page::Storage)
        } else {
            (Icon::Key, "Encryption", Page::Encryption)
        };
        let items = [
            (Icon::Home, "Overview", Page::Overview),
            (Icon::Folder, "Folders", Page::Folders),
            (Icon::Cloud, "Dashboard", Page::Dashboard),
            storage,
            (Icon::Folder, "Browse backups", Page::Browse),
            (Icon::Check, "Verify", Page::Verify),
            (Icon::Clock, "Schedule", Page::Schedule),
            (Icon::Calendar, "History", Page::History),
        ];
        for (ic, name, pg) in items {
            if ui.nav_item(ic, name, app.page == pg).clicked {
                app.page = pg;
            }
        }
    });
    // sidebar footer: connection + schedule summary
    let foot = Rect::new(14.0, h - 74.0, side.w - 28.0, 60.0);
    ui.with_rect(foot, |ui| {
        ui.set_spacing(2.0);
        let (tone, text) = if app.dashboard.selected() {
            (Tone::Success, "Dashboard-managed".to_string())
        } else if app.cfg.s3.is_complete() {
            (Tone::Success, format!("Bucket: {}", app.cfg.s3.bucket))
        } else {
            (Tone::Warning, "Storage not connected".to_string())
        };
        ui.badge(&text, tone);
        ui.small(&crate::schedule::describe(&app.cfg));
    });

    // ---------------- content
    let content = Rect::new(side.right(), 0.0, w - side.right(), h);
    let backup_running = app.running() || app.external.is_some();
    let effective = if matches!(app.page, Page::Browse | Page::Verify) || app.cloud.busy() {
        app.dashboard.effective(&app.cfg)
    } else {
        Ok(app.cfg.clone())
    };
    ui.with_rect(content.shrink2(32.0, 26.0), |ui| {
        ui.scroll_area("page", None, |ui| match app.page {
            Page::Overview => overview_page(ui, app),
            Page::Folders => folders_page(ui, app),
            Page::Storage if !app.dashboard.selected() => storage_page(ui, app),
            Page::Storage | Page::Encryption => encryption_page(ui, app),
            Page::Dashboard => {
                if app.dashboard.show(ui, &app.cfg, backup_running || app.verification.busy() || app.cloud.busy()) {
                    app.refresh_folder_sizes();
                    app.cloud.invalidate();
                }
                if !app.dashboard.selected() && !app.cfg.s3.is_complete() {
                    ui.space(8.0);
                    if ui.link("Set up standalone storage").clicked {
                        app.page = Page::Storage;
                    }
                }
            }
            Page::Schedule => schedule_page(ui, app),
            Page::History => history_page(ui, app),
            Page::Browse => match &effective {
                Ok(cfg) => app.cloud.show(ui, cfg),
                Err(error) => ui.callout(Tone::Warning, error),
            },
            Page::Verify => match &effective {
                Ok(cfg) => app.verification.show(ui, cfg, backup_running),
                Err(error) => ui.callout(Tone::Warning, error),
            },
        });
    });

    app.poll_folder_scan(ui);
    app.verification.poll(ui);
    // ---------------- overlays
    app.cloud.poll(ui, effective.as_ref().unwrap_or(&app.cfg));
    folder_rules_dialog(ui, app);
    if let Some(i) = app.confirm_remove {
        let name = app
            .cfg
            .folders
            .get(i)
            .map(|f| f.path.clone())
            .unwrap_or_default();
        let r = ui.modal(
            "confirm-remove",
            "Stop backing up this folder?",
            460.0,
            |ui| {
                ui.label_wrapped(&format!(
                    "“{}” will no longer be backed up. Files already uploaded stay in your bucket.",
                    name
                ));
                ui.space(6.0);
                ui.right_to_left(|ui| {
                    if ui.danger_button("Remove").clicked {
                        if i < app.cfg.folders.len() {
                            let mut cfg = app.cfg.clone();
                            let removed = cfg.folders.remove(i);
                            if app.save_folder_settings(ui, cfg) {
                                app.forget_folder_size(&removed.path);
                                ui.toast(Tone::Success, "Folder removed");
                            }
                        }
                        app.confirm_remove = None;
                    }
                    if ui.button("Cancel").clicked {
                        app.confirm_remove = None;
                    }
                });
            },
        );
        if r.close_requested {
            app.confirm_remove = None;
        }
    }
    if let Some(b) = &mut app.browser {
        match b.show(ui) {
            FolderBrowserResult::Open => {}
            FolderBrowserResult::Cancelled => app.browser = None,
            FolderBrowserResult::Selected(p) => {
                app.browser = None;
                add_folder(ui, app, p);
            }
        }
    }
    if app.ready_to_quit() {
        ui.quit();
        return;
    }
    if ui.close_requested() && !app.quit_after_backup {
        if app.verification.busy() {
            app.page = Page::Verify;
            ui.toast(Tone::Warning, "Stop verification or wait for it to finish before closing.");
        } else if app.cloud.busy() {
            ui.toast(
                Tone::Warning,
                "Wait for the preview or restore to finish, or cancel the restore before closing.",
            );
        } else if app.running() {
            app.confirm_quit = true;
        } else {
            ui.quit();
        }
    }
    if app.confirm_quit {
        let r = ui.modal("confirm-quit", "A backup is running", 460.0, |ui| {
            ui.label_wrapped("Stow will stop the backup and save its progress before closing. The next backup reuses completed uploads and any resumable parts.");
            ui.space(6.0);
            ui.right_to_left(|ui| {
                if ui.danger_button("Stop and quit").clicked {
                    app.stop_before_quit();
                    app.page = Page::Overview;
                }
                if ui.button("Keep running").clicked {
                    app.confirm_quit = false;
                }
            });
        });
        if r.close_requested {
            app.confirm_quit = false;
        }
    }
}

fn add_folder(ui: &mut Ui, app: &mut App, p: std::path::PathBuf) {
    let s = p.to_string_lossy().to_string();
    if !p.is_dir() {
        ui.toast(Tone::Danger, "That is not a folder.");
        return;
    }
    let mut cfg = app.cfg.clone();
    if !cfg.add_folder(&s) {
        ui.toast(Tone::Info, "That folder is already in the list.");
    } else if app.save_folder_settings(ui, cfg) {
        ui.toast(Tone::Success, &format!("Added {}", s));
        if let Some(scan) = &app.folder_scan {
            scan.shared.cancel.store(true, Ordering::Relaxed);
        }
        app.poll_folder_scan(ui);
    }
}

fn page_header(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.set_spacing(2.0);
    ui.heading(title);
    ui.label_muted(subtitle);
    ui.set_spacing(ui.theme.spacing);
    ui.space(10.0);
}

// ---------------------------------------------------------------- Overview

fn overview_page(ui: &mut Ui, app: &mut App) {
    page_header(
        ui,
        "Overview",
        "Your folders are copied to your S3 bucket. Only new and changed files are uploaded.",
    );

    let managed = app.dashboard.selected();
    let standalone_configured = !managed && app.cfg.s3.is_complete();
    let configured = managed || standalone_configured;
    let has_folders = app.cfg.folders.iter().any(|f| f.enabled);
    let ever_ran = !app.history.is_empty();
    if !configured || !has_folders || !ever_ran {
        ui.card(|ui| {
            ui.subheading("Get started");
            ui.space(2.0);
            let steps: [(bool, &str, &str, Page); 3] = [
                (
                    has_folders,
                    "Choose folders to back up",
                    "Pick the folders that matter, e.g. Documents or Photos.",
                    Page::Folders,
                ),
                (
                    configured,
                    "Connect backup storage",
                    if managed { "The dashboard provides the destination." }
                    else if standalone_configured { "This device uses its saved storage settings." }
                    else { "Pair this installation with your dashboard." },
                    if standalone_configured { Page::Storage } else { Page::Dashboard },
                ),
                (
                    ever_ran,
                    "Run your first backup",
                    "After that, set a schedule so it happens automatically.",
                    Page::Schedule,
                ),
            ];
            for (i, (done, title, sub, pg)) in steps.iter().enumerate() {
                ui.with_id(i, |ui| {
                    let r = ui.row(i, 54.0, false, |ui| {
                        let c = if *done {
                            ui.theme.success
                        } else {
                            ui.theme.border_strong
                        };
                        ui.icon(
                            if *done {
                                Icon::Success
                            } else {
                                Icon::ChevronRight
                            },
                            22.0,
                            c,
                        );
                        ui.vertical(Some(ui.available_width() - 120.0), |ui| {
                            ui.set_spacing(0.0);
                            ui.text(title, TextStyle::body().bold());
                            ui.small(sub);
                        });
                        ui.right_to_left(|ui| {
                            if *done {
                                ui.badge("Done", Tone::Success);
                            } else {
                                ui.badge("To do", Tone::Neutral);
                            }
                        });
                    });
                    if r.clicked {
                        app.page = *pg;
                    }
                });
            }
        });
        ui.space(6.0);
    }

    // ---- status card
    let live: Option<Progress> = if app.running() {
        Some(app.shared.snapshot())
    } else {
        app.external.clone()
    };
    ui.card(|ui| match &live {
        Some(p) => {
            let external = !app.running();
            ui.horizontal(|ui| {
                ui.icon(Icon::Upload, 22.0, ui.theme.accent);
                ui.subheading(if p.trigger == crate::verify::TRIGGER {
                    "Verification in progress"
                } else if external {
                    "Scheduled backup in progress"
                } else {
                    "Backing up…"
                });
                ui.right_to_left(|ui| {
                    if !external {
                        let cancelling =
                            app.shared.cancel.load(std::sync::atomic::Ordering::Relaxed);
                        if ui
                            .button_ex(
                                if cancelling { "Stopping…" } else { "Stop" },
                                ButtonKind::Secondary,
                                Some(Icon::Stop),
                                !cancelling,
                            )
                            .clicked
                        {
                            app.shared
                                .cancel
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                });
            });
            ui.space(4.0);
            let frac = if p.phase == Phase::Scanning || p.bytes_total == 0 {
                None
            } else {
                Some((p.bytes_done as f64 / p.bytes_total as f64).clamp(0.0, 1.0) as f32)
            };
            ui.progress_bar(frac, 10.0);
            ui.label(&p.message);
            let speed = app.speed.push(p.bytes_done);
            ui.columns(4, |ui, c| match c {
                0 => stat(
                    ui,
                    "Files",
                    &format!("{} / {}", p.files_uploaded, p.files_to_upload),
                ),
                1 => stat(
                    ui,
                    "Data",
                    &format!(
                        "{} / {}",
                        human_bytes(p.bytes_done),
                        human_bytes(p.bytes_total)
                    ),
                ),
                2 => stat(
                    ui,
                    "Speed",
                    &if speed > 0.0 {
                        format!("{}/s", human_bytes(speed as u64))
                    } else {
                        "—".into()
                    },
                ),
                _ => {
                    let left = p.bytes_total.saturating_sub(p.bytes_done);
                    let eta = if speed > 1.0 && p.phase == Phase::Uploading {
                        human_duration((left as f64 / speed) as u64)
                    } else {
                        "—".into()
                    };
                    stat(ui, "Time left", &eta)
                }
            });
            if !p.current.is_empty() {
                ui.space(2.0);
                for f in p.current.iter().take(4) {
                    ui.small(&format!("↑ {}", f));
                }
            }
            if p.files_failed > 0 {
                ui.callout(
                    Tone::Warning,
                    &format!("{} scan or upload problem(s) so far.", p.files_failed),
                );
            }
        }
        None => {
            let last = app.history.first().cloned();
            ui.horizontal_sized(48.0, |ui| {
                let (icon, color, title) = match last.as_ref().map(|p| p.phase) {
                    None => (
                        Icon::Info,
                        ui.theme.text_muted,
                        "No backups yet".to_string(),
                    ),
                    Some(Phase::Finished) => (
                        Icon::Success,
                        ui.theme.success,
                        "Your files are backed up".to_string(),
                    ),
                    Some(Phase::FinishedWithErrors) => (
                        Icon::Warning,
                        ui.theme.warning,
                        "Last backup had problems".to_string(),
                    ),
                    Some(Phase::Cancelled) => (
                        Icon::Info,
                        ui.theme.text_muted,
                        "Last backup was stopped".to_string(),
                    ),
                    Some(_) => (
                        Icon::Error,
                        ui.theme.danger,
                        "Last backup failed".to_string(),
                    ),
                };
                ui.icon(icon, 30.0, color);
                ui.vertical(Some(ui.available_width() - 200.0), |ui| {
                    ui.set_spacing(0.0);
                    ui.subheading(&title);
                    match &last {
                        Some(p) => ui.label_muted(&format!(
                            "{} · {}",
                            ago(p.finished.max(p.started)),
                            p.message
                        )),
                        None => ui.label_muted("Press “Back up now” to make the first copy."),
                    };
                });
                ui.right_to_left(|ui| {
                    if ui
                        .button_ex(
                            if last.as_ref().is_some_and(|p| p.phase == Phase::Cancelled) && !app.full_backup {
                                "Resume backup"
                            } else {
                                "Back up now"
                            },
                            ButtonKind::Primary,
                            Some(Icon::Upload),
                            !app.quit_after_backup,
                        )
                        .clicked
                    {
                        app.start_backup(ui);
                    }
                });
            });
            if let Some(p) = &last {
                ui.separator();
                ui.columns(4, |ui, c| match c {
                    0 => stat(ui, "Uploaded", &p.files_uploaded.to_string()),
                    1 => stat(ui, "Unchanged", &p.files_skipped.to_string()),
                    2 => stat(ui, "Failed", &p.files_failed.to_string()),
                    _ => stat(ui, "Data backed up", &human_bytes(p.bytes_done)),
                });
                if !p.errors.is_empty() {
                    ui.space(2.0);
                    if ui
                        .link(if app.show_errors {
                            "Hide problems"
                        } else {
                            "Show problems"
                        })
                        .clicked
                    {
                        app.show_errors = !app.show_errors;
                    }
                    if app.show_errors {
                        for e in p.errors.iter().take(30) {
                            ui.text(
                                e,
                                TextStyle::body().size(12.0).color(ui.theme.danger).wrap(),
                            );
                        }
                    }
                }
            }
        }
    });
    ui.space(6.0);

    ui.card(|ui| {
        ui.subheading("Backup mode");
        ui.checkbox(
            &mut app.full_backup,
            "Upload all files on the next manual backup",
        );
        ui.small(if app.full_backup {
            "Full upload: re-upload every included file, even when unchanged."
        } else {
            "Incremental: upload new and changed files; skip unchanged files using the local index."
        });
        if ui.button("Browse backups / restore").clicked {
            app.page = Page::Browse;
        }
    });
    ui.space(6.0);

    // ---- summary cards
    ui.columns(3, |ui, c| {
        ui.card(|ui| match c {
            0 => {
                ui.small("FOLDERS");
                let n = app.cfg.folders.iter().filter(|f| f.enabled).count();
                ui.subheading(&format!("{} selected", n));
                if ui.link("Manage folders").clicked {
                    app.page = Page::Folders;
                }
            }
            1 => {
                ui.small("DESTINATION");
                let destination = if managed {
                    app.dashboard.effective(&app.cfg).map_or_else(
                        |_| "Dashboard-managed".to_string(),
                        |cfg| format!("s3://{}", cfg.s3.bucket),
                    )
                } else if standalone_configured {
                    format!("s3://{}", app.cfg.s3.bucket)
                } else {
                    "Not connected".to_string()
                };
                ui.subheading(&destination);
                let (label, page) = if standalone_configured {
                    ("Storage settings", Page::Storage)
                } else {
                    ("Dashboard settings", Page::Dashboard)
                };
                if ui.link(label).clicked {
                    app.page = page;
                }
            }
            _ => {
                ui.small("SCHEDULE");
                let s = match app.cfg.schedule {
                    ScheduleMode::Off => "Manual only".to_string(),
                    ScheduleMode::Interval => format!("Every {} h", app.cfg.interval_hours),
                    ScheduleMode::Daily => format!("Daily at {}", app.cfg.daily_time),
                };
                ui.subheading(&s);
                if ui.link("Change schedule").clicked {
                    app.page = Page::Schedule;
                }
            }
        });
    });
}

fn stat(ui: &mut Ui, label: &str, value: &str) {
    ui.set_spacing(0.0);
    ui.small(label);
    ui.text(value, TextStyle::body().size(16.0).bold());
}

// ---------------------------------------------------------------- Folders

fn folders_page(ui: &mut Ui, app: &mut App) {
    ui.horizontal_sized(48.0, |ui| {
        ui.vertical(Some(ui.available_width() - 180.0), |ui| {
            ui.set_spacing(2.0);
            ui.heading("Folders");
            ui.label_muted("Backup rules apply to each folder and its subfolders.");
        });
        ui.right_to_left(|ui| {
            if ui
                .button_ex("Add folder", ButtonKind::Primary, Some(Icon::Plus), true)
                .clicked
            {
                if native_folder_picker_available() {
                    if let Some(p) = pick_folder("Choose a folder to back up") {
                        add_folder(ui, app, p);
                    }
                } else {
                    app.browser = Some(FolderBrowser::new("Choose a folder to back up", None));
                }
            }
        });
    });
    ui.space(10.0);
    ui.card(|ui| {
        if !app.cfg.folders.is_empty() {
            ui.horizontal(|ui| {
                ui.small("Sizes reflect backup filters and the local upload index.");
                ui.right_to_left(|ui| {
                    if ui.button("Refresh sizes").clicked {
                        app.refresh_folder_sizes();
                    }
                });
            });
        }
        if app.cfg.folders.is_empty() {
            ui.horizontal_sized(60.0, |ui| {
                ui.icon(Icon::Folder, 28.0, ui.theme.text_faint);
                ui.label_muted("No folders yet. Click “Add folder” to choose one.");
            });
        }
        let mut remove = None;
        let mut toggled = Vec::new();
        let roots: Vec<String> = app
            .cfg
            .folders
            .iter()
            .map(|f| app.cfg.remote_root(f))
            .collect();
        let bucket = app.cfg.s3.bucket.clone();
        for (i, f) in app.cfg.folders.iter().enumerate() {
            ui.with_id(i, |ui| {
                ui.row(i, 80.0, false, |ui| {
                    ui.icon(
                        Icon::Folder,
                        24.0,
                        if f.enabled {
                            ui.theme.accent
                        } else {
                            ui.theme.text_faint
                        },
                    );
                    ui.vertical(Some(ui.available_width() - 230.0), |ui| {
                        ui.set_spacing(0.0);
                        ui.text(&f.path, TextStyle::body().bold());
                        let dest = if bucket.is_empty() {
                            roots[i].clone()
                        } else {
                            format!("s3://{}/{}", bucket, roots[i])
                        };
                        ui.small(&format!("→ {}", dest));
                        if !f.enabled {
                            ui.small("Paused");
                        } else if let Some(p) = app.folder_sizes.get(&f.path) {
                            ui.small(&format!(
                                "Size {} · Synced {} · Pending {}",
                                human_bytes(p.bytes_skipped + p.bytes_total),
                                human_bytes(p.bytes_skipped),
                                human_bytes(p.bytes_total),
                            ));
                            if p.files_failed > 0 {
                                let error = p.errors.first().map_or("Scan incomplete", String::as_str);
                                ui.text(error, TextStyle::body().size(12.0).color(ui.theme.danger));
                            }
                        } else if let Some(scan) = app.folder_scan.as_ref().filter(|scan| {
                            scan.path == f.path && !scan.shared.cancel.load(Ordering::Relaxed)
                        }) {
                            let found = scan.shared.progress.lock().unwrap().files_found;
                            ui.small(&format!("Scanning… {found} files"));
                        } else {
                            ui.small("Waiting to scan");
                        }
                    });
                    ui.right_to_left(|ui| {
                        let b = ui.icon_button(Icon::Trash);
                        ui.tooltip(&b, "Stop backing up this folder");
                        if b.clicked {
                            remove = Some(i);
                        }
                        let mut enabled = f.enabled;
                        if ui.toggle(&mut enabled, "").changed {
                            toggled.push((i, enabled));
                        }
                        if ui.button("Backup rules").clicked {
                            app.folder_rules = Some(FolderRulesDraft {
                                path: f.path.clone(),
                                excludes_text: f.excludes.join(", "),
                                dev_preset: match f.skip_dev_artifacts {
                                    None => 0,
                                    Some(true) => 1,
                                    Some(false) => 2,
                                },
                            });
                        }
                    });
                });
            });
        }
        if !toggled.is_empty() {
            let mut cfg = app.cfg.clone();
            for &(i, enabled) in &toggled {
                cfg.folders[i].enabled = enabled;
            }
            if app.save_folder_settings(ui, cfg) {
                for (i, _) in toggled {
                    let path = app.cfg.folders[i].path.clone();
                    app.forget_folder_size(&path);
                }
            }
        }
        if remove.is_some() {
            app.confirm_remove = remove;
        }
    });
    ui.space(8.0);
    ui.card(|ui| {
        ui.subheading("Global backup rules");
        let previous = (app.cfg.skip_hidden, app.cfg.skip_dev_artifacts);
        let (mut skip_hidden, mut skip_dev_artifacts) = previous;
        ui.checkbox(&mut skip_dev_artifacts, "Skip dependencies and build output");
        ui.small(&format!("Skips subfolders named {}.", crate::config::DEV_ARTIFACT_DIRS.join(", ")));
        ui.checkbox(&mut skip_hidden, "Skip hidden files and folders");
        if (skip_hidden, skip_dev_artifacts) != previous {
            let mut cfg = app.cfg.clone();
            cfg.skip_hidden = skip_hidden;
            cfg.skip_dev_artifacts = skip_dev_artifacts;
            if app.save_folder_settings(ui, cfg) {
                app.refresh_folder_sizes();
            }
        }
        ui.label_muted(
            "Custom exclusions use comma-separated names or patterns, such as *.tmp or cache/**.",
        );
        ui.text_input(
            "excludes",
            &mut app.excludes_text,
            &TextInputOptions {
                placeholder: ".DS_Store, *.tmp",
                ..Default::default()
            },
        );
        let new_ex = exclusion_patterns(&app.excludes_text, &app.cfg.excludes);
        let dirty = new_ex != app.cfg.excludes;
        ui.horizontal(|ui| {
            if ui
                .button_ex("Save", ButtonKind::Primary, None, dirty)
                .clicked
            {
                let mut cfg = app.cfg.clone();
                cfg.excludes = new_ex;
                if app.save_folder_settings(ui, cfg) {
                    app.refresh_folder_sizes();
                    ui.toast(Tone::Success, "Saved");
                }
            }
            if ui.button("Reset patterns to defaults").clicked {
                app.excludes_text = crate::config::DEFAULT_EXCLUDES.join(", ");
            }
        });
    });
}

fn exclusion_patterns(text: &str, saved: &[String]) -> Vec<String> {
    if text == saved.join(", ") {
        return saved.to_vec();
    }
    text.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
}

fn folder_rules_dialog(ui: &mut Ui, app: &mut App) {
    let Some(mut draft) = app.folder_rules.take() else { return };
    let Some(i) = app.cfg.folders.iter().position(|f| f.path == draft.path) else { return };
    let mut close = false;
    let response = ui.modal("folder-rules", "Backup rules", 500.0, |ui| {
        ui.label_wrapped(&draft.path);
        ui.label("Extra exclusions");
        ui.text_input(
            "folder-excludes",
            &mut draft.excludes_text,
            &TextInputOptions { placeholder: "*.bak, cache/**", ..Default::default() },
        );
        ui.label_wrapped("Separate names or patterns with commas. Global patterns and hidden-file rules still apply.");
        ui.label("Dependencies and build output");
        let inherit = if app.cfg.skip_dev_artifacts { "Use global (skip)" } else { "Use global (include)" };
        ui.segmented(&mut draft.dev_preset, &[inherit, "Skip", "Include"]);
        let skip_dev_artifacts = [None, Some(true), Some(false)][draft.dev_preset];
        let folder = &app.cfg.folders[i];
        let excludes = exclusion_patterns(&draft.excludes_text, &folder.excludes);
        let dirty = excludes != folder.excludes || skip_dev_artifacts != folder.skip_dev_artifacts;
        ui.right_to_left(|ui| {
            if ui.button_ex("Save rules", ButtonKind::Primary, None, dirty).clicked
                && app.save_folder_rules(ui, i, excludes, skip_dev_artifacts)
            {
                ui.toast(Tone::Success, "Backup rules saved");
                close = true;
            }
            if ui.button("Cancel").clicked {
                close = true;
            }
        });
    });
    if !close && !response.close_requested {
        app.folder_rules = Some(draft);
    }
}

// ---------------------------------------------------------------- Storage

fn encryption_page(ui: &mut Ui, app: &mut App) {
    page_header(ui, "Encryption", "Protect backup contents on this device before uploading.");
    let required = app.dashboard.encryption_required();
    ui.card(|ui| local_encryption_controls(ui, &mut app.draft, required));
    let mut candidate = app.cfg.clone();
    app.draft.apply_local_encryption(&mut candidate);
    if ui.button_ex("Save encryption settings", ButtonKind::Primary, Some(Icon::Check), candidate != app.cfg).clicked {
        if required || candidate.s3.client_encryption {
            if let Err(error) = crate::file_crypto::validate_key(&candidate.s3.recovery_key) {
                ui.toast(Tone::Danger, &error);
                return;
            }
        }
        let previous = std::mem::replace(&mut app.cfg, candidate);
        if app.save(ui) {
            app.refresh_folder_sizes();
            ui.toast(Tone::Success, "Encryption settings saved");
        } else {
            app.cfg = previous;
        }
    }
}

fn local_encryption_controls(ui: &mut Ui, d: &mut Draft, required: bool) {
    if required {
        ui.callout(Tone::Info, "Your dashboard requires files to be encrypted before upload.");
    } else {
        ui.checkbox(&mut d.client_encryption, "Encrypt file contents before uploading");
    }
    if required || d.client_encryption || !d.recovery_key.is_empty() {
        ui.field_label("Recovery key (64 hexadecimal characters)");
        ui.text_input("recovery-key", &mut d.recovery_key, &TextInputOptions { password: !d.show_recovery_key, placeholder: "Generate a key or paste your existing key", ..Default::default() });
        ui.checkbox(&mut d.show_recovery_key, "Show recovery key");
        ui.horizontal(|ui| {
            if ui.button_ex("Generate key", ButtonKind::Secondary, Some(Icon::Key), d.recovery_key.is_empty()).clicked {
                match crate::file_crypto::generate_key() { Ok(key) => d.recovery_key = key, Err(e) => ui.toast(Tone::Danger, &e) }
            }
            if ui.button_ex("Copy recovery key", ButtonKind::Secondary, None, !d.recovery_key.is_empty()).clicked {
                ui.copy_to_clipboard(&d.recovery_key); ui.toast(Tone::Info, "Recovery key copied. Save it somewhere safe outside this computer.");
            }
        });
        ui.callout(Tone::Warning, "Keep a separate copy of your recovery key. Losing it makes encrypted backups unrecoverable. File names remain visible. Keep older keys if you change keys; paste the matching key here before restoring older files.");
        ui.small("Recovery keys are saved with your settings for scheduled backups. Linux uses a private configuration file, without OS encryption.");
    }
    ui.small("Changing encryption settings re-uploads files on the next backup. Existing objects are updated only as uploads succeed.");
}

fn storage_page(ui: &mut Ui, app: &mut App) {
    page_header(ui, "Storage", "The S3 bucket your backups are stored in.");
    ui.callout(
        Tone::Info,
        "S3 has no one-click “Sign in” for desktop apps, so Stow uses an Access Key. Create one in the AWS console (IAM → Users → Security credentials → Create access key) for a user that can read and write your bucket.",
    );
    ui.space(4.0);
    let d = &mut app.draft;
    ui.card(|ui| {
        ui.field_label("Provider");
        let before = d.provider;
        ui.select("provider", &mut d.provider, PROVIDERS, Some(340.0));
        if d.provider != before {
            d.endpoint = match d.provider {
                1 => "https://<ACCOUNT_ID>.r2.cloudflarestorage.com".into(),
                2 => "https://s3.wasabisys.com".into(),
                3 => "https://s3.us-west-004.backblazeb2.com".into(),
                4 => "https://nyc3.digitaloceanspaces.com".into(),
                _ => String::new(),
            };
            d.region_text = match d.provider {
                1 => "auto".into(),
                2 => "us-east-1".into(),
                3 => "us-west-004".into(),
                4 => "us-east-1".into(),
                _ => String::new(),
            };
        }
        if d.provider != 0 {
            ui.field_label("Endpoint URL");
            ui.text_input("endpoint", &mut d.endpoint, &TextInputOptions { placeholder: "https://s3.example.com", icon: Some(Icon::Server), ..Default::default() });
        }
        ui.columns(2, |ui, col| {
            if col == 0 {
                ui.field_label("Access Key ID");
                ui.text_input("ak", &mut d.access_key, &TextInputOptions { placeholder: "AKIA…", icon: Some(Icon::Key), ..Default::default() });
                ui.field_label("Bucket name");
                ui.text_input("bucket", &mut d.bucket, &TextInputOptions { placeholder: "my-backups", ..Default::default() });
            } else {
                ui.field_label("Secret Access Key");
                ui.text_input("sk", &mut d.secret_key, &TextInputOptions { placeholder: "Paste your secret key", password: true, ..Default::default() });
                ui.field_label("Region");
                if d.provider == 0 {
                    ui.select("region", &mut d.region_idx, AWS_REGIONS, None);
                } else {
                    ui.text_input("region-text", &mut d.region_text, &TextInputOptions { placeholder: "auto / us-east-1", ..Default::default() });
                }
            }
        });
        if !app.buckets.is_empty() {
            ui.horizontal(|ui| {
                ui.label_muted("Your buckets:");
                let names: Vec<&str> = app.buckets.iter().map(|s| s.as_str()).collect();
                if ui.select("bucket-pick", &mut app.bucket_pick, &names, Some(300.0)).changed {
                    d.bucket = app.buckets[app.bucket_pick].clone();
                }
            });
        }
        ui.columns(2, |ui, col| {
            if col == 0 {
                ui.field_label("Folder inside the bucket (optional)");
                ui.text_input("prefix", &mut d.prefix, &TextInputOptions { placeholder: "backups", ..Default::default() });
            } else {
                ui.field_label("This computer's name");
                ui.text_input("device", &mut d.device_name, &TextInputOptions { placeholder: "my-laptop", ..Default::default() });
            }
        });
        let mut root = Vec::new();
        if !d.prefix.trim().trim_matches('/').is_empty() {
            root.push(d.prefix.trim().trim_matches('/').to_string());
        }
        root.push(crate::config::sanitize_label(if d.device_name.trim().is_empty() { "computer" } else { d.device_name.trim() }));
        ui.small(&format!("Files go to s3://{}/{}/<folder>/…", if d.bucket.trim().is_empty() { "<bucket>" } else { d.bucket.trim() }, root.join("/")));
        ui.space(2.0);
        ui.separator();
        ui.subheading("Encryption");
        ui.small("HTTPS encrypts transfers. Server-side encryption protects objects at the provider; client-side encryption protects contents before upload.");
        if d.endpoint.trim().starts_with("http://") { ui.callout(Tone::Warning, "This endpoint uses HTTP: transfers are not encrypted. Use HTTPS for remote storage."); }
        ui.field_label("S3-managed encryption for new uploads");
        ui.select("server-encryption", &mut d.server_encryption, &["Bucket default", "SSE-S3 (AES-256)", "SSE-KMS"], None);
        if d.server_encryption == 2 {
            ui.field_label("KMS key ID or ARN (optional: provider default when empty)");
            ui.text_input("kms-key", &mut d.kms_key_id, &TextInputOptions::default());
        }
        local_encryption_controls(ui, d, false);
        if ui.link(if d.show_advanced { "Hide advanced options" } else { "Advanced options" }).clicked {
            d.show_advanced = !d.show_advanced;
        }
        if d.show_advanced {
            ui.checkbox(&mut d.path_style, "Use path-style addresses (needed by some self-hosted servers)");
            if d.provider == 0 {
                ui.field_label("Storage class");
                let names: Vec<&str> = STORAGE_CLASSES.iter().map(|(_, n)| *n).collect();
                ui.select("sclass", &mut d.storage_class, &names, Some(340.0));
            }
            ui.field_label("Extra trusted CA certificate (PEM file, for self-hosted HTTPS)");
            ui.text_input("ca", &mut d.ca_file, &TextInputOptions { placeholder: "/path/to/ca.pem", ..Default::default() });
        }
    });
    ui.space(6.0);

    if let Some(r) = &app.test_result {
        match r {
            Ok(m) => ui.callout(Tone::Success, &format!("Connected. {}", m)),
            Err(e) => ui.callout(Tone::Danger, e),
        }
    }
    let busy = app.test_job.is_some() || app.buckets_job.is_some();
    let mut candidate = app.cfg.clone();
    app.draft.apply_to(&mut candidate);
    let dirty = candidate != app.cfg;
    ui.horizontal(|ui| {
        if ui
            .button_ex("Save", ButtonKind::Primary, Some(Icon::Check), dirty)
            .clicked
        {
            if let Err(e) = crate::remote::validate_encryption(&candidate.s3) {
                ui.toast(Tone::Danger, &e);
                return;
            }
            app.cfg = candidate.clone();
            app.refresh_folder_sizes();
            if app.save(ui) {
                ui.toast(Tone::Success, "Storage settings saved");
                let s3 = app.cfg.s3.clone();
                app.test_result = None;
                app.test_job = Some(spawn_job(move || crate::remote::test_connection(&s3)));
            }
        }
        if ui
            .button_ex(
                if app.test_job.is_some() {
                    "Testing…"
                } else {
                    "Test connection"
                },
                ButtonKind::Secondary,
                Some(Icon::Refresh),
                !busy,
            )
            .clicked
        {
            let s3 = candidate.s3.clone();
            app.test_result = None;
            app.test_job = Some(spawn_job(move || crate::remote::test_connection(&s3)));
        }
        if ui
            .button_ex(
                if app.buckets_job.is_some() {
                    "Loading…"
                } else {
                    "Find my buckets"
                },
                ButtonKind::Ghost,
                Some(Icon::Search),
                !busy,
            )
            .clicked
        {
            let s3 = candidate.s3.clone();
            app.buckets_job = Some(spawn_job(move || crate::remote::list_buckets(&s3)));
        }
        if busy {
            ui.progress_bar(None, 6.0);
        }
    });
    if dirty {
        ui.small("You have unsaved changes.");
    }
}

// ---------------------------------------------------------------- Schedule

fn schedule_page(ui: &mut Ui, app: &mut App) {
    page_header(
        ui,
        "Schedule",
        "Back up automatically. Scheduled backups run even when this window is closed.",
    );
    ui.card(|ui| {
        ui.field_label("Automatic backups");
        ui.segmented(
            &mut app.sched_mode,
            &["Off", "Every few hours", "Once a day"],
        );
        ui.space(4.0);
        match app.sched_mode {
            1 => {
                ui.field_label("Repeat every");
                let names: Vec<String> = crate::schedule::INTERVAL_CHOICES
                    .iter()
                    .map(|h| {
                        if *h == 1 {
                            "1 hour".to_string()
                        } else {
                            format!("{} hours", h)
                        }
                    })
                    .collect();
                let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                ui.select("interval", &mut app.sched_interval, &refs, Some(220.0));
            }
            2 => {
                ui.field_label("Time of day (24-hour, this computer's time zone)");
                ui.text_input(
                    "daily",
                    &mut app.sched_time,
                    &TextInputOptions {
                        placeholder: "02:00",
                        width: Some(140.0),
                        icon: Some(Icon::Clock),
                        ..Default::default()
                    },
                );
            }
            _ => {
                ui.label_muted("Backups only run when you press “Back up now”.");
            }
        }
        ui.space(4.0);
        ui.field_label("Files uploaded at the same time");
        ui.number_stepper("parallel", &mut app.parallel, 1, 16, 1, "");
        ui.small("Large-file parts share this upload connection limit.");
        ui.space(6.0);
        let busy = app.sched_job.is_some();
        if ui
            .button_ex(
                if busy { "Applying…" } else { "Apply" },
                ButtonKind::Primary,
                Some(Icon::Check),
                !busy,
            )
            .clicked
        {
            let mut cfg = app.cfg.clone();
            cfg.schedule = match app.sched_mode {
                1 => ScheduleMode::Interval,
                2 => ScheduleMode::Daily,
                _ => ScheduleMode::Off,
            };
            cfg.interval_hours = crate::schedule::INTERVAL_CHOICES[app
                .sched_interval
                .min(crate::schedule::INTERVAL_CHOICES.len() - 1)];
            cfg.daily_time = app.sched_time.trim().to_string();
            cfg.parallel_uploads = app.parallel.clamp(1, 16) as u32;
            if cfg.schedule == ScheduleMode::Daily && cfg.daily_minutes().is_none() {
                ui.toast(Tone::Danger, "Enter the time like 02:30");
            } else {
                let sched_changed = (cfg.schedule, cfg.interval_hours, &cfg.daily_time)
                    != (
                        app.cfg.schedule,
                        app.cfg.interval_hours,
                        &app.cfg.daily_time,
                    );
                app.cfg = cfg.clone();
                if app.save(ui) {
                    if sched_changed {
                        app.sched_job = Some(spawn_job(move || crate::schedule::apply(&cfg)));
                    } else {
                        ui.toast(Tone::Success, "Saved");
                    }
                }
            }
        }
        if let Some(Err(e)) = &app.sched_status {
            ui.callout(
                Tone::Danger,
                &format!(
                    "The schedule could not be registered with the system: {}",
                    e
                ),
            );
        }
    });
    ui.space(6.0);
    ui.card(|ui| {
        ui.subheading("How it works");
        ui.label_wrapped("Each backup scans your folders and uploads only files that are new or changed since the last backup. Deleting a file on this computer never deletes it from the bucket, so older backups stay safe. Turn on S3 Versioning on the bucket to keep every previous version of changed files too.");
        ui.space(2.0);
        if ui.link("Open the settings folder").clicked {
            let _ = crate::paths::ensure_app_dir();
            open_path(&crate::paths::app_dir());
        }
    });
}

// ---------------------------------------------------------------- History

fn history_page(ui: &mut Ui, app: &mut App) {
    ui.horizontal_sized(48.0, |ui| {
        ui.vertical(Some(ui.available_width() - 160.0), |ui| {
            ui.set_spacing(2.0);
            ui.heading("History");
            ui.label_muted("The most recent backups, newest first.");
        });
        ui.right_to_left(|ui| {
            if ui
                .button_ex("Refresh", ButtonKind::Secondary, Some(Icon::Refresh), true)
                .clicked
            {
                app.history = engine::load_history();
            }
        });
    });
    ui.space(10.0);
    ui.card(|ui| {
        if app.history.is_empty() {
            ui.label_muted("No backups yet.");
        }
        for (i, p) in app.history.iter().take(100).enumerate() {
            ui.with_id(i, |ui| {
                ui.row(i, 56.0, false, |ui| {
                    let (tone, label) = match p.phase {
                        Phase::Finished => (Tone::Success, "Completed"),
                        Phase::FinishedWithErrors => (Tone::Warning, "With problems"),
                        Phase::Cancelled => (Tone::Neutral, "Stopped"),
                        _ => (Tone::Danger, "Failed"),
                    };
                    ui.vertical(Some(170.0), |ui| {
                        ui.set_spacing(0.0);
                        ui.text(&format_local(p.started), TextStyle::body().bold());
                        let dur = (p.finished - p.started).max(0) as u64;
                        ui.small(&format!(
                            "{} · took {}",
                            if p.trigger.is_empty() {
                                "manual"
                            } else {
                                &p.trigger
                            },
                            human_duration(dur)
                        ));
                    });
                    ui.vertical(Some(ui.available_width() - 140.0), |ui| {
                        ui.set_spacing(0.0);
                        ui.label(&format!(
                            "{} uploaded · {} unchanged · {} failed · {}",
                            p.files_uploaded,
                            p.files_skipped,
                            p.files_failed,
                            human_bytes(p.bytes_done)
                        ));
                        ui.small(&p.message);
                    });
                    ui.right_to_left(|ui| {
                        ui.badge(label, tone);
                    });
                });
            });
        }
    });
}

#[cfg(test)]
mod folder_settings_tests {
    use super::*;

    #[test]
    fn failed_folder_settings_save_keeps_active_settings_and_estimates() {
        // BACKUP_TAKER_HOME is process-wide and other tests also use it.
        const CHILD: &str = "BT_TEST_FOLDER_SETTINGS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let dir = std::env::temp_dir().join(format!("bt-folder-settings-{}-{}", std::process::id(), now_secs()));
            std::fs::create_dir(&dir).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "app_ui::folder_settings_tests::failed_folder_settings_save_keeps_active_settings_and_estimates"])
                .env(CHILD, "1")
                .env("BACKUP_TAKER_HOME", &dir)
                .output().unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }

        let mut app = App::new();
        let mut ui = Ui::new(Theme::light());
        let dir = crate::paths::app_dir();
        let original = dir.join("existing");
        std::fs::create_dir(&original).unwrap();
        assert!(app.cfg.add_folder(original.to_str().unwrap()));
        let other = dir.join("other");
        assert!(app.cfg.add_folder(other.to_str().unwrap()));
        app.cfg.save().unwrap();
        let saved = app.cfg.clone();
        let path = saved.folders[0].path.clone();
        let other_path = saved.folders[1].path.clone();
        for folder in &saved.folders {
            app.folder_sizes.insert(folder.path.clone(), Progress::default());
        }
        let shared = Shared::new();
        let result = Arc::new(Mutex::new(None));
        app.folder_scan = Some(FolderScan {
            path: path.clone(),
            shared: shared.clone(),
            result: result.clone(),
        });

        // A directory in place of the temporary config file prevents an atomic save.
        let temp_config = dir.join("config.tmp");
        std::fs::create_dir(&temp_config).unwrap();
        add_folder(&mut ui, &mut app, dir);
        assert!(!app.save_folder_rules(&mut ui, 0, vec!["*.bak".into()], Some(false)));
        assert_eq!(app.cfg, saved);
        assert_eq!(Config::load(), saved);
        assert!(app.folder_sizes.contains_key(&path));
        assert!(!shared.cancel.load(Ordering::Relaxed));

        std::fs::remove_dir(temp_config).unwrap();
        assert!(app.save_folder_rules(&mut ui, 0, vec!["*.bak".into()], Some(false)));
        let reloaded = Config::load();
        assert_eq!(reloaded.folders[0].excludes, ["*.bak"]);
        assert_eq!(reloaded.folders[0].skip_dev_artifacts, Some(false));
        assert!(!app.folder_sizes.contains_key(&path));
        assert!(app.folder_sizes.contains_key(&other_path));
        assert!(shared.cancel.load(Ordering::Relaxed));
        *result.lock().unwrap() = Some((Progress::default(), Arc::new(UploadIndex::for_preview(&saved))));
        app.poll_folder_scan(&mut ui);
        assert!(!app.folder_sizes.contains_key(&path));
    }
}

#[cfg(test)]
mod encryption_ui_tests {
    use super::*;
    #[test]
    fn changing_from_kms_to_other_modes_can_be_saved() {
        let mut cfg = Config::default();
        cfg.s3.server_encryption = "aws:kms".into();
        cfg.s3.kms_key_id = "previous-kms-key".into();
        let mut draft = Draft::from(&cfg);
        for mode in [0, 1] {
            draft.server_encryption = mode;
            draft.apply_to(&mut cfg);
            assert!(crate::remote::validate_encryption(&cfg.s3).is_ok());
            assert!(cfg.s3.kms_key_id.is_empty());
        }
    }
}

#[cfg(test)]
#[test]
fn managed_encryption_save_preserves_saved_standalone_destination() {
    let mut cfg = Config::default();
    cfg.s3.bucket = "standalone-bucket".into();
    cfg.s3.access_key = "standalone-key".into();
    cfg.s3.server_encryption = "AES256".into();
    let mut draft = Draft::from(&cfg);
    draft.bucket = "unsaved-bucket".into();
    draft.access_key = "unsaved-key".into();
    draft.server_encryption = 2;
    draft.client_encryption = true;
    draft.recovery_key = "ab".repeat(32);
    draft.apply_local_encryption(&mut cfg);
    assert_eq!(cfg.s3.bucket, "standalone-bucket");
    assert_eq!(cfg.s3.access_key, "standalone-key");
    assert_eq!(cfg.s3.server_encryption, "AES256");
    assert!(cfg.s3.client_encryption);
    assert_eq!(cfg.s3.recovery_key, "ab".repeat(32));
}


#[cfg(test)]
#[test]
fn stop_and_quit_waits_for_backup_to_finish_saving() {
    let mut app = App::new();
    app.backup_job = Some(Arc::new(Mutex::new(None)));
    app.confirm_quit = true;
    app.stop_before_quit();
    assert!(app.shared.cancel.load(Ordering::SeqCst));
    assert!(!app.confirm_quit);
    assert!(!app.ready_to_quit());
    app.backup_job = None;
    assert!(app.ready_to_quit());
}
