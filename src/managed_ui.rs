//! Desktop pairing and dashboard status.
use crate::{
    app_ui::{spawn_job, take, Slot},
    config::Config,
    managed::{self, Profile, Readiness},
};
use bt_gui::*;
use std::time::{Duration, Instant};

pub(crate) struct View {
    profile: Result<Option<Profile>, String>,
    origin: String,
    code: String,
    pair_job: Option<Slot<Result<Profile, String>>>,
    check_job: Option<Slot<Result<Readiness, String>>>,
    last_check: Option<Instant>,
    readiness: Option<Readiness>,
    message: Option<String>,
    confirm_disconnect: bool,
}

impl Default for View {
    fn default() -> Self {
        Self {
            profile: Profile::load(),
            origin: String::new(),
            code: String::new(),
            pair_job: None,
            check_job: None,
            last_check: None,
            readiness: None,
            message: None,
            confirm_disconnect: false,
        }
    }
}

impl View {
    pub(crate) fn selected(&self) -> bool {
        self.profile
            .as_ref()
            .map_or(true, |profile| profile.as_ref().is_some_and(|p| p.active))
    }

    pub(crate) fn encryption_required(&self) -> bool {
        self.selected()
            && self
                .readiness
                .as_ref()
                .and_then(|ready| ready.policy.as_ref())
                .is_some_and(|policy| policy.requires_encryption())
    }

    pub(crate) fn effective(&self, cfg: &Config) -> Result<Config, String> {
        if !self.selected() {
            return Ok(cfg.clone());
        }
        if let Err(error) = &self.profile {
            return Err(error.clone());
        }
        let policy = self
            .readiness
            .as_ref()
            .and_then(|ready| ready.policy.as_ref())
            .ok_or("The dashboard policy is unavailable. Check the Dashboard page.")?;
        policy.apply(cfg)
    }

    pub(crate) fn poll(&mut self, ui: &mut Ui, cfg: &Config) -> bool {
        let mut changed = false;
        if let Some(result) = take(&mut self.pair_job) {
            match result {
                Ok(profile) => {
                    self.profile = Ok(Some(profile));
                    self.last_check = None;
                    self.code.clear();
                    self.message = None;
                }
                Err(error) => self.message = Some(error),
            }
        }
        if let Some(result) = take(&mut self.check_job) {
            let old = self.revision();
            match result {
                Ok(mut readiness) => {
                    // Keep the scoped session caches when the policy revision
                    // is unchanged. A new revision receives a fresh scope.
                    if old.is_some() && old == readiness.policy.as_ref().map(|p| p.revision) {
                        readiness.policy = self
                            .readiness
                            .as_mut()
                            .and_then(|current| current.policy.take());
                    }
                    self.readiness = Some(readiness);
                    self.message = None;
                }
                Err(error) => {
                    self.readiness = None;
                    self.message = Some(error);
                }
            }
            changed |= old != self.revision();
        }
        if let Ok(Some(profile)) = &self.profile {
            if self.check_job.is_none()
                && self
                    .last_check
                    .is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
            {
                let profile = profile.clone();
                let cfg = cfg.clone();
                let applied = self.last_applied(&cfg);
                self.last_check = Some(Instant::now());
                self.check_job = Some(spawn_job(move || managed::refresh(&profile, &cfg, applied)));
            }
        }
        if self.pair_job.is_some() || self.check_job.is_some() {
            ui.request_repaint_after(Duration::from_millis(150));
        }
        changed
    }

    fn revision(&self) -> Option<u64> {
        self.readiness.as_ref()?.policy.as_ref().map(|p| p.revision)
    }

    fn last_applied(&self, cfg: &Config) -> Option<u64> {
        let revision = self.revision()?;
        let effective = self.effective(cfg).ok()?;
        (self.selected() && crate::remote::validate_encryption(&effective.s3).is_ok())
            .then_some(revision)
    }

    pub(crate) fn show(&mut self, ui: &mut Ui, cfg: &Config, operation_active: bool) -> bool {
        ui.heading("Dashboard");
        ui.label_muted("Pair this installation with your Stow dashboard for central backup settings and status.");
        ui.space(12.0);
        let mut changed = false;
        match &mut self.profile {
            Err(error) => {
                ui.callout(Tone::Danger, error);
                if ui
                    .button_ex(
                        "Clear local pairing",
                        ButtonKind::Secondary,
                        None,
                        !operation_active,
                    )
                    .clicked
                {
                    match Profile::disconnect() {
                        Ok(()) => {
                            self.profile = Ok(None);
                            changed = true;
                        }
                        Err(error) => self.message = Some(error),
                    }
                }
            }
            Ok(None) => {
                ui.card(|ui| {
                    ui.subheading("Pair a device");
                    ui.small("In the web dashboard, open Devices and choose Add device to generate a pairing code.");
                    ui.field_label("Dashboard address");
                    ui.text_input("dashboard-origin", &mut self.origin, &TextInputOptions {
                        placeholder: "https://dashboard.example.com", ..Default::default()
                    });
                    ui.field_label("Pairing code");
                    ui.text_input("dashboard-code", &mut self.code, &TextInputOptions {
                        placeholder: "Paste the pairing code", password: true, ..Default::default()
                    });
                    let enabled = !operation_active && self.pair_job.is_none()
                        && !self.origin.trim().is_empty() && !self.code.trim().is_empty();
                    if ui.button_ex(if self.pair_job.is_some() { "Connecting…" } else { "Connect device" },
                        ButtonKind::Primary, Some(Icon::Cloud), enabled).clicked
                    {
                        let origin = self.origin.clone();
                        let code = self.code.clone();
                        self.message = None;
                        self.pair_job = Some(spawn_job(move || Profile::pair(&origin, &code)));
                    }
                });
            }
            Ok(Some(profile)) => {
                ui.card(|ui| {
                    ui.subheading(&profile.name);
                    ui.label(&profile.origin);
                    ui.small(&format!("Device ID {}", profile.id));
                    ui.space(6.0);
                    ui.badge(if profile.active { "Managed backups" } else { "Standalone backups" },
                        if profile.active { Tone::Success } else { Tone::Neutral });
                    if self.readiness.as_ref().is_some_and(|ready| ready.paused) {
                        ui.callout(Tone::Warning, "The dashboard has paused this device’s backups.");
                    }
                    if let Some(ready) = &self.readiness {
                        if let Some(policy) = &ready.policy {
                            if let Ok(effective) = policy.apply(cfg) {
                                ui.small(&format!("Policy v{} · s3://{}/{}", policy.revision, effective.s3.bucket, effective.s3.prefix));
                            }
                        }
                        if let Some(error) = &ready.policy_error { ui.callout(Tone::Warning, error); }
                        if let Some(error) = &ready.reporting_error {
                            ui.callout(Tone::Warning, &format!("Some dashboard run reports are pending. {error}"));
                        }
                    }
                    ui.space(8.0);
                    if !profile.active {
                        ui.small("The first managed backup uploads the selected folders into the device’s assigned S3 prefix.");
                    }
                    ui.horizontal(|ui| {
                        let label = if profile.active { "Use standalone settings" } else { "Use dashboard for backups" };
                        if ui.button_ex(label, ButtonKind::Primary, None, !operation_active).clicked {
                            match profile.set_active(!profile.active) {
                                Ok(()) => { changed = true; self.last_check = None; }
                                Err(error) => self.message = Some(error),
                            }
                        }
                        if ui.button_ex("Refresh policy", ButtonKind::Secondary, Some(Icon::Refresh), self.check_job.is_none()).clicked {
                            self.last_check = None;
                        }
                        if ui.button_ex("Disconnect", ButtonKind::Secondary, None, !operation_active).clicked {
                            self.confirm_disconnect = true;
                        }
                    });
                });
                let mut confirmed = false;
                if self.confirm_disconnect {
                    let response = ui.modal("dashboard-disconnect", "Disconnect device?", 450.0, |ui| {
                        ui.label("This installation will return to standalone backups. You can revoke the device from the web dashboard.");
                        if ui.button("Disconnect and use standalone").clicked { confirmed = true; }
                        if ui.button("Cancel").clicked { self.confirm_disconnect = false; }
                    });
                    if response.close_requested || confirmed {
                        self.confirm_disconnect = false;
                    }
                }
                if confirmed {
                    match Profile::disconnect() {
                        Ok(()) => {
                            self.profile = Ok(None);
                            self.readiness = None;
                            self.check_job = None;
                            self.message = None;
                            changed = true;
                        }
                        Err(error) => self.message = Some(error),
                    }
                }
            }
        }
        if let Some(error) = &self.message {
            ui.callout(Tone::Danger, error);
        }
        changed
    }
}
