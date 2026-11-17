//! Widget gallery. Run: `cargo run -p bt-gui --example demo`
//! Offscreen snapshot: `cargo run -p bt-gui --example demo -- --snapshot out.ppm [page]`
use bt_gui::*;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Default)]
struct Demo {
    page: usize,
    folders: Vec<PathBuf>,
    selected_folder: Option<usize>,
    bucket: String,
    access_key: String,
    secret: String,
    region: usize,
    path_style: bool,
    auto_backup: bool,
    interval: i64,
    mode: usize,
    progress: f32,
    running: bool,
    show_modal: bool,
    browser: Option<FolderBrowser>,
    notes: String,
}

const REGIONS: &[&str] = &[
    "us-east-1 (N. Virginia)",
    "us-east-2 (Ohio)",
    "us-west-1 (N. California)",
    "us-west-2 (Oregon)",
    "eu-west-1 (Ireland)",
    "eu-central-1 (Frankfurt)",
    "ap-south-1 (Mumbai)",
    "ap-southeast-1 (Singapore)",
    "ap-southeast-2 (Sydney)",
    "ap-northeast-1 (Tokyo)",
    "sa-east-1 (São Paulo)",
    "ca-central-1 (Canada)",
];

fn frame(ui: &mut Ui, s: &mut Demo) {
    let (w, h) = ui.screen_size();
    // ----- sidebar
    let side = Rect::new(0.0, 0.0, 232.0, h);
    ui.canvas.fill_rect(side, ui.theme.sidebar);
    ui.canvas.fill_rect(Rect::new(side.right() - 1.0, 0.0, 1.0, h), ui.theme.border);
    ui.with_rect(side.shrink2(14.0, 18.0), |ui| {
        ui.horizontal(|ui| {
            let r = ui.allocate(Some(34.0), 34.0);
            ui.canvas.fill_rounded_rect(r, 8.0, ui.theme.accent);
            ui.paint_text_centered(r, "BT", 14.0, Color::WHITE, true);
            ui.subheading("Backup Taker");
        });
        ui.space(14.0);
        ui.set_spacing(4.0);
        let items = [(Icon::Folder, "Folders"), (Icon::Cloud, "Storage"), (Icon::Upload, "Backup"), (Icon::Gear, "Widgets")];
        for (i, (ic, name)) in items.iter().enumerate() {
            if ui.nav_item(*ic, name, s.page == i).clicked {
                s.page = i;
            }
        }
    });
    // ----- content
    let content = Rect::new(side.right(), 0.0, w - side.right(), h);
    ui.with_rect(content.shrink2(32.0, 28.0), |ui| match s.page {
        0 => folders_page(ui, s),
        1 => storage_page(ui, s),
        2 => backup_page(ui, s),
        _ => widgets_page(ui, s),
    });

    if s.show_modal {
        let r = ui.modal("confirm", "Remove folder?", 440.0, |ui| {
            ui.label_wrapped("The folder will no longer be backed up. Files already uploaded stay in your bucket.");
            ui.space(6.0);
            ui.right_to_left(|ui| {
                if ui.danger_button("Remove").clicked {
                    if let Some(i) = s.selected_folder.take() {
                        if i < s.folders.len() {
                            s.folders.remove(i);
                        }
                    }
                    s.show_modal = false;
                    ui.toast(Tone::Success, "Folder removed");
                }
                if ui.button("Cancel").clicked {
                    s.show_modal = false;
                }
            });
        });
        if r.close_requested {
            s.show_modal = false;
        }
    }
    if let Some(b) = &mut s.browser {
        match b.show(ui) {
            FolderBrowserResult::Open => {}
            FolderBrowserResult::Cancelled => s.browser = None,
            FolderBrowserResult::Selected(p) => {
                ui.toast(Tone::Success, &format!("Added {}", p.display()));
                s.folders.push(p);
                s.browser = None;
            }
        }
    }
    if s.running {
        s.progress += 0.004;
        if s.progress >= 1.0 {
            s.progress = 1.0;
            s.running = false;
            ui.toast(Tone::Success, "Backup finished: 1,284 files uploaded");
        }
        ui.request_repaint_after(Duration::from_millis(30));
    }
}

fn folders_page(ui: &mut Ui, s: &mut Demo) {
    ui.horizontal_sized(44.0, |ui| {
        ui.vertical(Some(ui.available_width() - 330.0), |ui| {
            ui.set_spacing(2.0);
            ui.heading("Backup folders");
            ui.label_muted("Choose the folders that should be copied to your bucket.");
        });
        ui.right_to_left(|ui| {
            if ui.button_ex("Add folder", ButtonKind::Primary, Some(Icon::Plus), true).clicked {
                if native_folder_picker_available() {
                    if let Some(p) = pick_folder("Choose a folder to back up") {
                        s.folders.push(p);
                    }
                } else {
                    s.browser = Some(FolderBrowser::new("Choose a folder to back up", None));
                }
            }
            if ui.button_ex("Browse in app", ButtonKind::Secondary, Some(Icon::Search), true).clicked {
                s.browser = Some(FolderBrowser::new("Choose a folder to back up", None));
            }
        });
    });
    ui.space(8.0);
    ui.card(|ui| {
        if s.folders.is_empty() {
            ui.label_muted("No folders yet. Click “Add folder” to pick one.");
        }
        let mut remove = None;
        ui.scroll_area("folders", Some(300.0), |ui| {
            ui.set_spacing(4.0);
            for (i, f) in s.folders.iter().enumerate() {
                let sel = s.selected_folder == Some(i);
                let r = ui.row(i, 56.0, sel, |ui| {
                    ui.icon(Icon::Folder, 22.0, ui.theme.accent);
                    ui.vertical(Some(ui.available_width() - 150.0), |ui| {
                        ui.set_spacing(0.0);
                        let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| f.display().to_string());
                        ui.text(&name, TextStyle::body().bold());
                        ui.small(&f.display().to_string());
                    });
                    ui.right_to_left(|ui| {
                        let b = ui.icon_button(Icon::Trash);
                        ui.tooltip(&b, "Remove from backup");
                        if b.clicked {
                            remove = Some(i);
                        }
                        ui.badge("Ready", Tone::Success);
                    });
                });
                if r.clicked {
                    s.selected_folder = Some(i);
                }
            }
        });
        if let Some(i) = remove {
            s.selected_folder = Some(i);
            s.show_modal = true;
        }
    });
}

fn storage_page(ui: &mut Ui, s: &mut Demo) {
    ui.heading("S3 storage");
    ui.label_muted("Connect the bucket your backups are stored in.");
    ui.space(8.0);
    ui.card(|ui| {
        ui.columns(2, |ui, col| {
            if col == 0 {
                ui.field_label("Access key ID");
                ui.text_input("ak", &mut s.access_key, &TextInputOptions { placeholder: "AKIA…", icon: Some(Icon::Key), ..Default::default() });
                ui.field_label("Bucket name");
                ui.text_input("bucket", &mut s.bucket, &TextInputOptions { placeholder: "my-backups", ..Default::default() });
            } else {
                ui.field_label("Secret access key");
                ui.text_input("sk", &mut s.secret, &TextInputOptions { placeholder: "••••••••", password: true, ..Default::default() });
                ui.field_label("Region");
                ui.select("region", &mut s.region, REGIONS, None);
            }
        });
        ui.space(4.0);
        ui.checkbox(&mut s.path_style, "Use path-style URLs (MinIO, Ceph, …)");
        ui.space(4.0);
        ui.horizontal(|ui| {
            if ui.primary_button("Save & test connection").clicked {
                if s.bucket.is_empty() {
                    ui.toast(Tone::Danger, "Bucket name is required");
                } else {
                    ui.toast(Tone::Success, &format!("Connected to {}", s.bucket));
                }
            }
            ui.button("Cancel");
        });
    });
}

fn backup_page(ui: &mut Ui, s: &mut Demo) {
    ui.horizontal_sized(44.0, |ui| {
        ui.heading("Backup");
        ui.badge(if s.running { "Running" } else { "Idle" }, if s.running { Tone::Info } else { Tone::Neutral });
    });
    ui.space(8.0);
    ui.card(|ui| {
        ui.horizontal(|ui| {
            ui.subheading(if s.running { "Uploading…" } else { "Last backup: today 14:02" });
        });
        ui.progress_bar(Some(s.progress), 10.0);
        ui.small(&format!("{:.0}% — 1.2 GB of 3.4 GB", s.progress * 100.0));
        ui.progress_bar(None, 6.0);
        ui.horizontal(|ui| {
            if s.running {
                if ui.button_ex("Stop", ButtonKind::Danger, Some(Icon::Stop), true).clicked {
                    s.running = false;
                    ui.toast(Tone::Warning, "Backup stopped");
                }
            } else if ui.button_ex("Back up now", ButtonKind::Primary, Some(Icon::Upload), true).clicked {
                s.running = true;
                if s.progress >= 1.0 {
                    s.progress = 0.0;
                }
            }
            ui.button_ex("Disabled", ButtonKind::Secondary, None, false);
        });
    });
    ui.space(6.0);
    ui.callout(Tone::Info, "Only new and changed files are uploaded. Deleted local files are kept in the bucket.");
    ui.callout(Tone::Warning, "Your secret key is stored on this computer. Use an IAM user that can only access the backup bucket.");
}

fn widgets_page(ui: &mut Ui, s: &mut Demo) {
    ui.heading("Widgets");
    ui.card(|ui| {
        ui.horizontal(|ui| {
            ui.toggle(&mut s.auto_backup, "Automatic backups");
            ui.number_stepper("interval", &mut s.interval, 1, 168, 1, " h");
        });
        ui.segmented(&mut s.mode, &["Hourly", "Daily", "Weekly"]);
        ui.horizontal(|ui| {
            ui.badge("Neutral", Tone::Neutral);
            ui.badge("Info", Tone::Info);
            ui.badge("Success", Tone::Success);
            ui.badge("Warning", Tone::Warning);
            ui.badge("Danger", Tone::Danger);
        });
        let icons = [
            Icon::Check, Icon::Close, Icon::Plus, Icon::Minus, Icon::ChevronDown, Icon::ChevronRight, Icon::Folder, Icon::File,
            Icon::Trash, Icon::Cloud, Icon::Upload, Icon::Download, Icon::Gear, Icon::Warning, Icon::Info, Icon::Error,
            Icon::Success, Icon::Refresh, Icon::Clock, Icon::Home, Icon::Drive, Icon::Play, Icon::Stop, Icon::Pause,
            Icon::Key, Icon::Search, Icon::Eye, Icon::Server, Icon::Calendar, Icon::Shield, Icon::Edit, Icon::Menu,
        ];
        for chunk in icons.chunks(16) {
            ui.horizontal_sized(24.0, |ui| {
                for ic in chunk {
                    ui.icon(*ic, 20.0, ui.theme.text_muted);
                }
            });
        }
        ui.field_label("Notes");
        ui.text_input("notes", &mut s.notes, &TextInputOptions { placeholder: "Type, select, copy & paste…", ..Default::default() });
        ui.label_wrapped("The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. Ünïcödé: café, naïve, 你好 (if the font has it).");
        ui.horizontal(|ui| {
            if ui.button("Toast").clicked {
                ui.toast(Tone::Info, "Hello from a toast notification!");
            }
            if ui.button("Error toast").clicked {
                ui.toast(Tone::Danger, "Access denied (403): check your secret key and bucket policy.");
            }
            if ui.link("Open runkiri.com").clicked {
                open_url("https://runkiri.com");
            }
        });
    });
}

fn main() {
    let mut s = Demo { interval: 24, progress: 0.35, ..Default::default() };
    s.folders = vec![
        PathBuf::from("/home/user/Documents"),
        PathBuf::from("/home/user/Pictures/Family photos"),
        PathBuf::from("/srv/projects/very/long/path/that/goes/on/and/on/to/test/ellipsis/handling/in/rows"),
    ];
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--snapshot") {
        let out = args.get(2).cloned().unwrap_or("snapshot.ppm".into());
        s.page = args.get(3).and_then(|p| p.parse().ok()).unwrap_or(0);
        let mut ui = Ui::new(Theme::light());
        for _ in 0..3 {
            ui.begin_frame_raw((1100, 720), 1.0, vec![], &mut || None);
            frame(&mut ui, &mut s);
            ui.end_frame_raw();
        }
        std::fs::write(&out, ui.canvas.to_ppm()).unwrap();
        println!("wrote {out} (font: {})", ui.fonts.regular.name);
        return;
    }
    let opts = WindowOptions {
        title: "Backup Taker — widget demo".into(),
        width: 1100,
        height: 720,
        min_width: 760,
        min_height: 520,
        app_id: "bt-gui-demo".into(),
        icon: None,
    };
    if let Err(e) = run(opts, Theme::light(), s, frame) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
