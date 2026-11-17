//! S3 inventory, virtual folders, restore selection and preview controls.
use crate::{browse, config::Config, timefmt::human_bytes};
use bt_gui::*;
use bt_s3::ObjectInfo;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

type Job<T> = Arc<Mutex<Option<T>>>;
fn job<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Job<T> {
    let slot = Arc::new(Mutex::new(None));
    let out = slot.clone();
    std::thread::spawn(move || {
        *out.lock().unwrap() = Some(f());
    });
    slot
}
fn take<T>(slot: &mut Option<Job<T>>) -> Option<T> {
    let result = slot.as_ref()?.lock().unwrap().take();
    if result.is_some() {
        *slot = None;
    }
    result
}

pub struct BrowserView {
    objects: Vec<ObjectInfo>,
    destination: String,
    prefix: String,
    selected: Option<browse::BrowserEntry>,
    filter: String,
    list_job: Option<Job<Result<Vec<ObjectInfo>, String>>>,
    list_destination: String,
    loaded_at: Option<Instant>,
    error: Option<String>,
    restore_picker: Option<FolderBrowser>,
    restore_selection: Option<(Vec<ObjectInfo>, String)>,
    restore_job: Option<Job<Result<String, String>>>,
    restore_progress: Arc<Mutex<browse::RestoreProgress>>,
    restore_cancel: Arc<AtomicBool>,
    restore_message: Option<String>,
    preview_job: Option<Job<Result<String, String>>>,
    preview_message: Option<String>,
    preview_cancel: Arc<AtomicBool>,
}
impl BrowserView {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            destination: String::new(),
            prefix: String::new(),
            selected: None,
            filter: String::new(),
            list_job: None,
            list_destination: String::new(),
            loaded_at: None,
            error: None,
            restore_picker: None,
            restore_selection: None,
            restore_job: None,
            restore_progress: Arc::new(Mutex::new(Default::default())),
            restore_cancel: Arc::new(AtomicBool::new(false)),
            restore_message: None,
            preview_job: None,
            preview_message: None,
            preview_cancel: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn busy(&self) -> bool {
        self.restore_job.is_some() || self.preview_job.is_some()
    }
    pub fn invalidate(&mut self) {
        self.loaded_at = None;
    }
    fn refresh(&mut self, cfg: &Config) {
        if self.list_job.is_some() {
            return;
        }
        let s = cfg.s3.clone();
        self.list_destination = format!("{}|{}", s.endpoint, s.bucket);
        self.error = None;
        self.list_job = Some(job(move || browse::inventory(&s)));
    }
    pub fn poll(&mut self, ui: &mut Ui, cfg: &Config) {
        if let Some(result) = take(&mut self.list_job) {
            if self.destination == self.list_destination {
                match result {
                    Ok(objects) => {
                        self.objects = objects;
                        self.loaded_at = Some(Instant::now());
                        self.error = None;
                    }
                    Err(e) => {
                        self.error = Some(e);
                    }
                }
            }
        }
        if let Some(result) = take(&mut self.restore_job) {
            match result {
                Ok(message) => {
                    ui.toast(Tone::Success, &message);
                    self.restore_message = Some(message);
                }
                Err(e) => {
                    ui.toast(Tone::Danger, &e);
                    self.restore_message = Some(e);
                }
            }
        }
        if let Some(result) = take(&mut self.preview_job) {
            match result {
                Ok(message) => {
                    ui.toast(Tone::Info, &message);
                    self.preview_message = Some(message);
                }
                Err(e) => {
                    ui.toast(Tone::Danger, &e);
                    self.preview_message = Some(e);
                }
            }
        }
        if let Some(picker) = &mut self.restore_picker {
            match picker.show(ui) {
                FolderBrowserResult::Open => {}
                FolderBrowserResult::Cancelled => {
                    self.restore_picker = None;
                    self.restore_selection = None;
                }
                FolderBrowserResult::Selected(dest) => {
                    self.restore_picker = None;
                    if let Some((objects, prefix)) = self.restore_selection.take() {
                        self.start_restore(cfg, objects, prefix, dest);
                    }
                }
            }
        }
    }
    fn start_restore(
        &mut self,
        cfg: &Config,
        objects: Vec<ObjectInfo>,
        prefix: String,
        dest: PathBuf,
    ) {
        let settings = cfg.s3.clone();
        self.restore_progress = Arc::new(Mutex::new(Default::default()));
        self.restore_cancel = Arc::new(AtomicBool::new(false));
        self.restore_message = None;
        let progress = self.restore_progress.clone();
        let cancel = self.restore_cancel.clone();
        self.restore_job = Some(job(move || {
            browse::restore(&settings, objects, &prefix, &dest, progress, cancel)
        }));
    }
    fn select_restore(&mut self, objects: Vec<ObjectInfo>, prefix: String) {
        self.restore_selection = Some((objects, prefix));
        self.restore_picker = Some(FolderBrowser::new(
            "Choose restore destination (existing files are kept)",
            None,
        ));
    }
    pub fn show(&mut self, ui: &mut Ui, cfg: &Config) {
        ui.heading("Browse S3");
        ui.label_muted(
            "Browse backups, preview files and restore a file or folder to your computer.",
        );
        if !cfg.s3.is_complete() {
            ui.callout(
                Tone::Info,
                "Save your bucket and credentials in Storage first.",
            );
            return;
        }
        let destination = format!("{}|{}", cfg.s3.endpoint, cfg.s3.bucket);
        if self.destination != destination {
            self.destination = destination;
            self.objects.clear();
            self.loaded_at = None;
            self.prefix.clear();
            self.selected = None;
            self.error = None;
        }
        if self.loaded_at.is_none() && self.error.is_none() && self.list_job.is_none() {
            self.refresh(cfg);
        }
        ui.space(8.0);
        ui.card(|ui| {
            ui.horizontal(|ui| {
                ui.subheading(&format!("s3://{}", cfg.s3.bucket));
                if ui.button_ex(if self.list_job.is_some() { "Refreshing…" } else { "Refresh totals & files" }, ButtonKind::Secondary, Some(Icon::Refresh), self.list_job.is_none()).clicked { self.refresh(cfg); }
            });
            let bytes = self.objects.iter().fold(0u64, |sum, o| sum.saturating_add(o.size));
            ui.label(&format!("{} objects · {} stored", self.objects.len(), human_bytes(bytes)));
            ui.small(&self.loaded_at.map(|t| format!("Last refreshed {} seconds ago. Includes current objects across this bucket; excludes older versions and unfinished uploads.", t.elapsed().as_secs())).unwrap_or_else(|| "Loading bucket inventory…".into()));
            if self.list_job.is_some() { ui.progress_bar(None, 5.0); }
        });
        if let Some(e) = &self.error {
            ui.callout(Tone::Danger, e);
        }
        ui.horizontal(|ui| {
            if ui
                .button_ex(
                    "Up",
                    ButtonKind::Secondary,
                    Some(Icon::Folder),
                    !self.prefix.is_empty(),
                )
                .clicked
            {
                let trimmed = self.prefix.trim_end_matches('/');
                self.prefix = trimmed
                    .rsplit_once('/')
                    .map(|(p, _)| format!("{p}/"))
                    .unwrap_or_default();
                self.selected = None;
            }
            if ui.button("Bucket root").clicked {
                self.prefix.clear();
                self.selected = None;
            }
            ui.label(&format!("/{}", self.prefix));
        });
        ui.text_input(
            "s3-filter",
            &mut self.filter,
            &TextInputOptions {
                placeholder: "Filter names in this folder",
                ..Default::default()
            },
        );
        let entries = browse::entries(&self.objects, &self.prefix);
        ui.card(|ui| {
            if entries.is_empty() && self.list_job.is_none() {
                ui.label_muted("No files in this folder.");
            }
            ui.scroll_area("s3-entries", Some(240.0), |ui| {
                for entry in &entries {
                    if !entry
                        .name
                        .to_lowercase()
                        .contains(&self.filter.to_lowercase())
                    {
                        continue;
                    }
                    ui.with_id(&entry.key, |ui| {
                        let selected = self
                            .selected
                            .as_ref()
                            .map(|s| s.key == entry.key && s.is_folder == entry.is_folder)
                            .unwrap_or(false);
                        let response = ui.row(0, 42.0, selected, |ui| {
                            ui.icon(
                                if entry.is_folder {
                                    Icon::Folder
                                } else {
                                    Icon::File
                                },
                                18.0,
                                ui.theme.accent,
                            );
                            ui.label(&entry.name);
                            ui.right_to_left(|ui| {
                                ui.small(&human_bytes(entry.size));
                            });
                        });
                        if response.clicked {
                            self.selected = Some(entry.clone());
                        }
                        if response.double_clicked && entry.is_folder {
                            self.prefix = entry.key.clone();
                            self.selected = None;
                            self.filter.clear();
                        }
                    });
                }
            });
        });
        let selected = self.selected.clone();
        let busy = self.restore_job.is_some() || self.restore_picker.is_some();
        ui.horizontal(|ui| {
            if let Some(entry) = &selected {
                if entry.is_folder && ui.button("Open folder").clicked {
                    self.prefix = entry.key.clone();
                    self.selected = None;
                    self.filter.clear();
                }
                if ui
                    .button_ex(
                        if entry.is_folder {
                            "Restore folder…"
                        } else {
                            "Download / restore file…"
                        },
                        ButtonKind::Primary,
                        Some(Icon::Download),
                        !busy,
                    )
                    .clicked
                {
                    let (objects, prefix) = if entry.is_folder {
                        (
                            self.objects
                                .iter()
                                .filter(|o| o.key.starts_with(&entry.key))
                                .cloned()
                                .collect(),
                            entry.key.clone(),
                        )
                    } else {
                        (
                            self.objects
                                .iter()
                                .filter(|o| o.key == entry.key)
                                .cloned()
                                .collect(),
                            entry
                                .key
                                .rsplit_once('/')
                                .map(|(p, _)| format!("{p}/"))
                                .unwrap_or_default(),
                        )
                    };
                    self.select_restore(objects, prefix);
                }
                if !entry.is_folder
                    && ui
                        .button_ex(
                            "Preview",
                            ButtonKind::Secondary,
                            Some(Icon::Search),
                            self.preview_job.is_none(),
                        )
                        .clicked
                {
                    if let Some(object) = self.objects.iter().find(|o| o.key == entry.key).cloned()
                    {
                        let settings = cfg.s3.clone();
                        self.preview_message = None;
                        self.preview_cancel = Arc::new(AtomicBool::new(false));
                        let cancel = self.preview_cancel.clone();
                        self.preview_job = Some(job(move || {
                            crate::preview::open(&settings, &object, &cancel)
                        }));
                    }
                }
            }
            if ui
                .button_ex(
                    "Restore this folder…",
                    ButtonKind::Secondary,
                    None,
                    !busy && !self.objects.is_empty() && self.list_job.is_none(),
                )
                .clicked
            {
                let objects = self
                    .objects
                    .iter()
                    .filter(|o| o.key.starts_with(&self.prefix))
                    .cloned()
                    .collect();
                self.select_restore(objects, self.prefix.clone());
            }
        });
        ui.small("Double-click folders to open. Restore saves contents into your chosen destination and refuses to overwrite existing files.");
        if let Some(entry) = selected {
            ui.small(&format!(
                "Selected: {} · {}",
                entry.key, entry.last_modified
            ));
        }
        if self.preview_job.is_some() {
            ui.callout(
                Tone::Info,
                "Fetching preview from S3… Large or encrypted files may take a while.",
            );
            if ui.button("Cancel preview").clicked {
                self.preview_cancel.store(true, Ordering::SeqCst);
            }
        }
        if let Some(message) = &self.preview_message {
            ui.label_wrapped(message);
        }
        if self.restore_job.is_some() {
            let p = self.restore_progress.lock().unwrap().clone();
            ui.card(|ui| {
                ui.subheading("Restoring from S3…");
                ui.label(&format!(
                    "{} / {} files · {} / {}",
                    p.files_done,
                    p.files_total,
                    human_bytes(p.bytes_done),
                    human_bytes(p.bytes_total)
                ));
                ui.progress_bar(
                    if p.bytes_total == 0 {
                        None
                    } else {
                        Some((p.bytes_done as f64 / p.bytes_total as f64).clamp(0.0, 1.0) as f32)
                    },
                    8.0,
                );
                ui.small(&p.current);
                if ui.button("Cancel restore").clicked {
                    self.restore_cancel.store(true, Ordering::SeqCst);
                }
            });
        }
        if let Some(message) = &self.restore_message {
            ui.label_wrapped(message);
        }
    }
}
