//! In-app folder chooser (fallback when no native dialog is available).
use crate::icons::Icon;
use crate::ui::{ButtonKind, TextInputOptions, Tone, Ui};
use std::path::{Path, PathBuf};

pub enum FolderBrowserResult {
    /// Still open — call `show` again next frame.
    Open,
    Cancelled,
    Selected(PathBuf),
}

pub struct FolderBrowser {
    pub title: String,
    current: PathBuf,
    entries: Vec<(String, PathBuf)>,
    selected: Option<usize>,
    path_text: String,
    error: Option<String>,
    show_hidden: bool,
}

pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Root locations: drives on Windows, `/` elsewhere.
pub fn roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetLogicalDrives() -> u32;
        }
        let mask = unsafe { GetLogicalDrives() };
        (0..26).filter(|i| mask >> i & 1 == 1).map(|i| PathBuf::from(format!("{}:\\", (b'A' + i as u8) as char))).collect()
    }
    #[cfg(not(windows))]
    {
        let mut v = vec![PathBuf::from("/")];
        for m in ["/media", "/mnt", "/Volumes"] {
            if Path::new(m).is_dir() {
                v.push(PathBuf::from(m));
            }
        }
        v
    }
}

impl FolderBrowser {
    pub fn new(title: &str, start: Option<PathBuf>) -> FolderBrowser {
        let start = start.filter(|p| p.is_dir()).or_else(home_dir).unwrap_or_else(|| roots()[0].clone());
        let mut fb = FolderBrowser {
            title: title.to_string(),
            current: PathBuf::new(),
            entries: Vec::new(),
            selected: None,
            path_text: String::new(),
            error: None,
            show_hidden: false,
        };
        fb.navigate(start);
        fb
    }

    pub fn current(&self) -> &Path {
        &self.current
    }

    pub fn navigate(&mut self, dir: PathBuf) {
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                let mut v: Vec<(String, PathBuf)> = rd
                    .flatten()
                    .filter(|e| e.path().is_dir())
                    .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
                    .filter(|(n, _)| self.show_hidden || !n.starts_with('.'))
                    .collect();
                v.sort_by_key(|(n, _)| n.to_lowercase());
                self.entries = v;
                self.path_text = dir.display().to_string();
                self.current = dir;
                self.selected = None;
                self.error = None;
            }
            Err(e) => self.error = Some(format!("Can't open {}: {e}", dir.display())),
        }
    }

    /// Draw the browser as a modal dialog. Call every frame while open, after other widgets.
    pub fn show(&mut self, ui: &mut Ui) -> FolderBrowserResult {
        let mut result = FolderBrowserResult::Open;
        let title = self.title.clone();
        let mut nav: Option<PathBuf> = None;
        let resp = ui.modal("folder-browser", &title, 720.0, |ui| {
            ui.horizontal(|ui| {
                let parent = self.current.parent().map(|p| p.to_path_buf());
                if ui.button_ex("", ButtonKind::Secondary, Some(Icon::ArrowUp), parent.is_some()).clicked {
                    nav = parent;
                }
                let w = ui.available_width() - 70.0;
                let r = ui.text_input(
                    "fb-path",
                    &mut self.path_text,
                    &TextInputOptions { width: Some(w), icon: Some(Icon::Folder), ..Default::default() },
                );
                if ui.button("Go").clicked || r.submitted {
                    nav = Some(PathBuf::from(self.path_text.trim()));
                }
            });
            if let Some(e) = &self.error {
                ui.callout(Tone::Danger, e);
            }
            let places: Vec<(Icon, String, PathBuf)> = {
                let mut v = Vec::new();
                if let Some(h) = home_dir() {
                    v.push((Icon::Home, "Home".to_string(), h.clone()));
                    for (n, ic) in [("Desktop", Icon::Folder), ("Documents", Icon::File), ("Downloads", Icon::Download), ("Pictures", Icon::Folder)] {
                        let p = h.join(n);
                        if p.is_dir() {
                            v.push((ic, n.to_string(), p));
                        }
                    }
                }
                for r in roots() {
                    let name = r.display().to_string();
                    v.push((Icon::Drive, name, r));
                }
                v
            };
            ui.horizontal_sized(340.0, |ui| {
                ui.vertical(Some(170.0), |ui| {
                    ui.set_spacing(2.0);
                    ui.scroll_area("fb-places", Some(340.0), |ui| {
                        ui.set_spacing(2.0);
                        for (ic, name, p) in &places {
                            let sel = &self.current == p;
                            if ui.nav_item(*ic, name, sel).clicked {
                                nav = Some(p.clone());
                            }
                        }
                    });
                });
                ui.vertical(None, |ui| {
                    ui.scroll_area("fb-list", Some(340.0), |ui| {
                        ui.set_spacing(2.0);
                        if self.entries.is_empty() {
                            ui.space(12.0);
                            ui.label_muted("No sub-folders here.");
                        }
                        for i in 0..self.entries.len() {
                            let (name, path) = self.entries[i].clone();
                            let r = ui.list_item(Some(Icon::Folder), &name, None, self.selected == Some(i));
                            if r.double_clicked {
                                nav = Some(path);
                            } else if r.clicked {
                                self.selected = Some(i);
                            }
                        }
                    });
                });
            });
            ui.horizontal(|ui| {
                let mut h = self.show_hidden;
                if ui.checkbox(&mut h, "Show hidden folders").changed {
                    self.show_hidden = h;
                    nav = Some(self.current.clone());
                }
            });
            ui.separator();
            let target = self.selected.and_then(|i| self.entries.get(i)).map(|e| e.1.clone()).unwrap_or_else(|| self.current.clone());
            ui.horizontal(|ui| {
                let w = ui.available_width() - 250.0;
                ui.vertical(Some(w.max(50.0)), |ui| {
                    ui.small("Selected folder");
                    ui.label(&target.display().to_string());
                });
                ui.right_to_left(|ui| {
                    if ui.primary_button("Select folder").clicked {
                        result = FolderBrowserResult::Selected(target.clone());
                    }
                    if ui.button("Cancel").clicked {
                        result = FolderBrowserResult::Cancelled;
                    }
                });
            });
        });
        if resp.close_requested {
            result = FolderBrowserResult::Cancelled;
        }
        if let Some(p) = nav {
            self.navigate(p);
        }
        result
    }
}
