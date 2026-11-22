use crate::config::Config;
use crate::engine::Shared;
use crate::timefmt::format_local;
use crate::verify::{self, Report};
use bt_gui::{ButtonKind, Icon, TextStyle, Tone, Ui};
use std::collections::HashMap;
use std::sync::{atomic::Ordering, mpsc, Arc};
use std::time::{Duration, Instant};

struct Job {
    shared: Arc<Shared>,
    result: mpsc::Receiver<Result<verify::Summary, String>>,
}

#[derive(Default)]
pub struct VerifyView {
    job: Option<Job>,
    cached_cfg: Option<Config>,
    cached_at: Option<Instant>,
    reports: HashMap<String, Report>,
    expanded: Option<String>,
    outcome: Option<(Tone, String)>,
}

impl VerifyView {
    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn poll(&mut self, ui: &mut Ui) {
        let Some(job) = self.job.as_ref() else {
            return;
        };
        let result = match job.result.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("Verification stopped unexpectedly.".into())
            }
            Err(mpsc::TryRecvError::Empty) => {
                ui.request_repaint_after(Duration::from_millis(150));
                return;
            }
        };
        self.outcome = Some(match result {
            Ok(summary) if !summary.errors.is_empty() => (Tone::Danger, summary.errors.join("\n")),
            Ok(summary)
                if summary
                    .reports
                    .iter()
                    .any(|(_, report)| report.has_issues()) =>
            {
                (
                    Tone::Warning,
                    "Verification finished. Review the findings below.".into(),
                )
            }
            Ok(_) => (Tone::Success, "Verification finished.".into()),
            Err(e) if job.shared.cancel.load(Ordering::Relaxed) => (Tone::Info, e),
            Err(e) => (Tone::Danger, e),
        });
        self.job = None;
        self.cached_at = None;
        ui.request_repaint();
    }

    pub fn show(&mut self, ui: &mut Ui, cfg: &Config, backup_running: bool) {
        if self.cached_cfg.as_ref() != Some(cfg)
            || self
                .cached_at
                .is_none_or(|last| last.elapsed() >= Duration::from_secs(2))
        {
            self.reports = cfg
                .folders
                .iter()
                .filter(|folder| folder.enabled)
                .filter_map(|folder| {
                    verify::latest(cfg, folder).map(|report| (folder.path.clone(), report))
                })
                .collect();
            self.cached_cfg = Some(cfg.clone());
            self.cached_at = Some(Instant::now());
        }

        ui.heading("Verify backups");
        ui.label_muted("Compare Stow’s recorded uploads with the current objects in S3.");
        ui.space(8.0);
        let has_folders = cfg.folders.iter().any(|folder| folder.enabled);
        let configured = cfg.s3.is_complete();
        ui.card(|ui| {
            if let Some(job) = &self.job {
                ui.horizontal(|ui| {
                    let cancelling = job.shared.cancel.load(Ordering::Relaxed);
                    if ui.button_ex(
                        if cancelling { "Stopping…" } else { "Stop" },
                        ButtonKind::Secondary, Some(Icon::Stop), !cancelling,
                    ).clicked {
                        job.shared.cancel.store(true, Ordering::Relaxed);
                    }
                    let snapshot = job.shared.snapshot();
                    ui.label(if snapshot.message.is_empty() { "Preparing verification…" } else { &snapshot.message });
                });
                ui.progress_bar(None, 8.0);
            } else {
                if ui.button_ex(
                    "Verify now", ButtonKind::Primary, Some(Icon::Check),
                    configured && has_folders && !backup_running,
                ).clicked {
                    let cfg = cfg.clone();
                    let shared = Shared::new();
                    let worker = shared.clone();
                    let (sender, result) = mpsc::channel();
                    std::thread::spawn(move || {
                        let _ = sender.send(verify::run(&cfg, &worker));
                    });
                    self.outcome = None;
                    self.job = Some(Job { shared, result });
                    ui.request_repaint();
                }
                if !configured {
                    ui.small("Connect your bucket in Storage to verify uploads.");
                } else if !has_folders {
                    ui.small("Enable a folder in Folders to verify it.");
                } else if backup_running {
                    ui.small("Wait for the current operation to finish.");
                }
            }
            ui.small("Verification compares S3 object tags. A restore checks whether the files can be downloaded and opened.");
        });
        if let Some((tone, message)) = &self.outcome {
            ui.callout(*tone, message);
        }

        for folder in cfg.folders.iter().filter(|folder| folder.enabled) {
            ui.with_id(&folder.path, |ui| {
                ui.card(|ui| {
                    ui.subheading(&folder.label);
                    ui.small(&folder.path);
                    let Some(report) = self.reports.get(&folder.path) else {
                        ui.label_muted("No verification recorded.");
                        return;
                    };
                    ui.small(&format!("Last checked {}", format_local(report.checked_at)));
                    ui.label(&format!(
                        "{} matched · {} missing · {} changed in S3",
                        report.matched, report.missing, report.mismatched
                    ));
                    ui.label(&format!(
                        "{} pending local files · {} missing tags · {} scan problems",
                        report.pending, report.no_etag, report.scan_errors
                    ));

                    if !report.details.is_empty() {
                        let expanded = self.expanded.as_deref() == Some(folder.path.as_str());
                        if ui
                            .link(if expanded {
                                "Hide details"
                            } else {
                                "Show details"
                            })
                            .clicked
                        {
                            self.expanded = (!expanded).then(|| folder.path.clone());
                        }
                        if expanded {
                            for line in &report.details {
                                ui.text(line, TextStyle::body().size(12.0).wrap());
                            }
                            if report.missing
                                + report.mismatched
                                + report.no_etag
                                + report.pending
                                + report.scan_errors
                                > report.details.len() as u64
                            {
                                ui.small("Showing the first 40 findings.");
                            }
                        }
                    }
                })
            });
            ui.space(6.0);
        }
    }
}
