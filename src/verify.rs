//! Verify recorded uploads against the current objects in each configured S3 prefix.
use crate::config::{Config, Folder};
use crate::engine::{self, IndexEntry, Phase, RunLock, Shared, UploadIndex};
use crate::json::Json;
use crate::{paths, remote, timefmt};
use bt_s3::ObjectInfo;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

pub const TRIGGER: &str = "verification";
const MAX_DETAILS: usize = 40;

#[derive(Debug, Default)]
pub struct Report {
    pub checked_at: i64,
    pub matched: u64,
    pub missing: u64,
    pub mismatched: u64,
    pub no_etag: u64,
    pub pending: u64,
    pub scan_errors: u64,
    pub details: Vec<String>,
}

impl Report {
    pub fn has_issues(&self) -> bool {
        self.missing + self.mismatched + self.no_etag + self.pending + self.scan_errors > 0
    }

    fn note(&mut self, message: impl FnOnce() -> String) {
        if self.details.len() < MAX_DETAILS {
            self.details.push(message());
        }
    }

    fn check_object(&mut self, object: &ObjectInfo, entry: &IndexEntry) {
        if entry.etag.is_empty() || object.etag.is_empty() {
            self.no_etag += 1;
            self.note(|| format!("Missing ETag · {}", object.key));
        } else if object.etag != entry.etag {
            self.mismatched += 1;
            self.note(|| format!("Different S3 object · {}", object.key));
        } else {
            self.matched += 1;
        }
    }

    fn to_json(&self) -> Json {
        let mut j = Json::obj();
        j.set("version", 1u32);
        j.set("checked_at", self.checked_at as f64);
        j.set("matched", self.matched);
        j.set("missing", self.missing);
        j.set("mismatched", self.mismatched);
        j.set("no_etag", self.no_etag);
        j.set("pending", self.pending);
        j.set("scan_errors", self.scan_errors);
        j.set(
            "details",
            Json::Arr(
                self.details
                    .iter()
                    .map(|s| Json::from(s.as_str()))
                    .collect(),
            ),
        );
        j
    }

    fn from_json(j: &Json) -> Option<Self> {
        let count = |k| j.num_or(k, 0.0) as u64;
        let checked_at = j.num_or("checked_at", 0.0) as i64;
        if j.num_or("version", 0.0) != 1.0 || checked_at <= 0 {
            return None;
        }
        Some(Self {
            checked_at,
            matched: count("matched"),
            missing: count("missing"),
            mismatched: count("mismatched"),
            no_etag: count("no_etag"),
            pending: count("pending"),
            scan_errors: count("scan_errors"),
            details: j
                .arr("details")
                .iter()
                .take(MAX_DETAILS)
                .filter_map(|detail| detail.as_str().map(str::to_owned))
                .collect(),
        })
    }
}

#[derive(Default)]
pub struct Summary {
    pub reports: Vec<(String, Report)>,
    pub errors: Vec<String>,
}

fn hash(value: &Json) -> String {
    bt_tls::crypto::util::hex(&bt_tls::crypto::sha256::sha256(
        value.to_string_compact().as_bytes(),
    ))
}

fn report_path(cfg: &Config, folder: &Folder) -> PathBuf {
    let mut fields = vec![
        Json::from(cfg.s3.endpoint.trim()),
        Json::from(cfg.s3.bucket.trim()),
        Json::from(cfg.remote_root(folder).as_str()),
        Json::from(folder.path.as_str()),
    ];
    if let Some(target) = &cfg.s3.managed {
        fields.push(Json::from(target.scope()));
    }
    paths::app_dir().join(format!("verify-{}.json", hash(&Json::Arr(fields))))
}

fn rules_id(cfg: &Config, folder: &Folder) -> String {
    let mut rules = Json::obj();
    rules.set(
        "global",
        Json::Arr(
            cfg.excludes
                .iter()
                .map(|s| Json::from(s.as_str()))
                .collect(),
        ),
    );
    rules.set("hidden", cfg.skip_hidden);
    rules.set(
        "artifacts",
        folder.skip_dev_artifacts.unwrap_or(cfg.skip_dev_artifacts),
    );
    rules.set(
        "folder_rules",
        Json::Arr(
            folder
                .excludes
                .iter()
                .map(|s| Json::from(s.as_str()))
                .collect(),
        ),
    );
    rules.set("upload_policy", engine::UploadIndex::policy_id(cfg));
    hash(&rules)
}

pub fn latest(cfg: &Config, folder: &Folder) -> Option<Report> {
    let j = Json::parse(&std::fs::read_to_string(report_path(cfg, folder)).ok()?).ok()?;
    if j.str_or("rules", "") != rules_id(cfg, folder) {
        return None;
    }
    Report::from_json(&j)
}

fn save(cfg: &Config, folder: &Folder, report: &Report) -> Result<(), String> {
    let mut j = report.to_json();
    j.set("rules", rules_id(cfg, folder).as_str());
    paths::write_private(&report_path(cfg, folder), j.to_string_compact().as_bytes())
        .map_err(|e| format!("Could not save verification for {}: {e}", folder.label))
}

fn compare(
    mut expected: BTreeMap<&str, &IndexEntry>,
    mut fetch: impl FnMut(Option<&str>) -> Result<(Vec<ObjectInfo>, Option<String>), String>,
) -> Result<Report, String> {
    let mut report = Report::default();
    let mut token = None;
    let mut seen = HashSet::new();
    loop {
        let (objects, next) = fetch(token.as_deref())?;
        for object in objects {
            if let Some(entry) = expected.remove(object.key.as_str()) {
                report.check_object(&object, entry);
            }
        }
        let Some(next) = next else {
            break;
        };
        if expected.is_empty() {
            break;
        }
        if !seen.insert(next.clone()) {
            return Err("S3 returned a repeated continuation token.".into());
        }
        token = Some(next);
    }
    report.missing = expected.len() as u64;
    for key in expected.keys().take(MAX_DETAILS) {
        report.note(|| format!("Missing from S3 · {key}"));
    }
    Ok(report)
}

fn cancelled(shared: &Shared) -> Result<(), String> {
    if shared.cancel.load(Ordering::Relaxed) {
        return Err("Verification stopped.".into());
    }
    Ok(())
}

fn check(cfg: &Config, shared: &Shared) -> Result<Summary, String> {
    let client = match &cfg.s3.managed {
        Some(target) => remote::scoped_client(&cfg.s3, target.read_credentials("verify"))?,
        None => remote::client(&cfg.s3)?,
    };
    let index = UploadIndex::load_checked(UploadIndex::path_for(cfg))
        .map_err(|e| format!("Could not read the upload index: {e}"))?;
    let current_policy = index.matches_policy(cfg);
    let by_key: BTreeMap<_, _> = index
        .entries
        .iter()
        .map(|(key, entry)| (key.as_str(), entry))
        .collect();
    let mut scoped = cfg.clone();
    let mut summary = Summary::default();
    for folder in cfg.folders.iter().filter(|folder| folder.enabled) {
        cancelled(shared)?;
        let prefix = cfg.remote_root(folder);
        // Verify recorded objects even when the local file has since been deleted.
        let expected = by_key
            .range(prefix.as_str()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(&key, &entry)| (key, entry))
            .collect();
        shared.progress.lock().unwrap().message = format!("Checking S3 for {}…", folder.label);
        let result = compare(expected, |token| {
            cancelled(shared)?;
            client
                .list_objects_page_cancel(&prefix, 1000, token, &shared.cancel)
                .map_err(|e| e.to_string())
        });
        cancelled(shared)?;
        let mut report = match result {
            Ok(report) => report,
            Err(e) => {
                summary
                    .errors
                    .push(format!("Could not verify {}: {e}", folder.label));
                continue;
            }
        };
        scoped.folders.clear();
        scoped.folders.push(folder.clone());
        shared.progress.lock().unwrap().message =
            format!("Checking local files in {}…", folder.label);
        // Each folder has independent counts. Keep the run's public progress message intact.
        let local = Shared::new();
        engine::scan_backup(
            &scoped,
            &local,
            &shared.cancel,
            |job| current_policy && engine::is_unchanged(&index, job),
            |job| report.note(|| format!("Pending local file · {}", job.key)),
        );
        cancelled(shared)?;
        let scan = local.snapshot();
        report.pending = scan.files_to_upload;
        report.scan_errors = scan.files_failed;
        for error in scan.errors {
            report.note(|| format!("Local scan · {error}"));
        }
        report.checked_at = timefmt::now_secs();
        if let Err(e) = save(cfg, folder, &report) {
            summary.errors.push(e);
        }
        summary.reports.push((folder.path.clone(), report));
    }
    Ok(summary)
}

pub fn run(cfg: &Config, shared: &Shared) -> Result<Summary, String> {
    if !cfg.s3.is_complete() {
        return Err("Connect your S3 bucket before verifying backups.".into());
    }
    if !cfg.folders.iter().any(|folder| folder.enabled) {
        return Err("Select at least one folder to verify.".into());
    }
    let lock = RunLock::acquire()?;
    {
        let mut p = shared.progress.lock().unwrap();
        p.phase = Phase::Scanning;
        p.trigger = TRIGGER.into();
        p.started = timefmt::now_secs();
        p.message = "Preparing verification…".into();
    }
    lock.update(&shared.snapshot());
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = scope.spawn(move || {
            let _ = sender.send(check(cfg, shared));
        });
        let result = loop {
            match receiver.recv_timeout(Duration::from_secs(2)) {
                Ok(result) => break result,
                Err(mpsc::RecvTimeoutError::Timeout) => lock.update(&shared.snapshot()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err("Verification stopped unexpectedly.".into());
                }
            }
        };
        let _ = worker.join();
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_recorded_etags_and_reports_missing_objects() {
        let entry = |etag: &str| IndexEntry {
            size: 2,
            mtime_ns: 0,
            etag: etag.into(),
        };
        let (same, different, missing, legacy) =
            (entry("abc-3"), entry("123"), entry("abc"), entry(""));
        let expected = BTreeMap::from([
            ("x/same", &same),
            ("x/different", &different),
            ("x/missing", &missing),
            ("x/legacy", &legacy),
        ]);
        let remote = |key: &str, etag: &str| ObjectInfo {
            key: key.into(),
            etag: etag.into(),
            ..ObjectInfo::default()
        };
        let mut pages = 0;
        let report = compare(expected, |token| {
            pages += 1;
            Ok(match token {
                None => (
                    vec![remote("x/same", "abc-3"), remote("x/extra", "q")],
                    Some("next".into()),
                ),
                Some("next") => (
                    vec![remote("x/different", "456"), remote("x/legacy", "old")],
                    None,
                ),
                _ => panic!("unexpected continuation token"),
            })
        })
        .unwrap();
        assert_eq!(pages, 2);
        assert_eq!(
            (
                report.matched,
                report.mismatched,
                report.missing,
                report.no_etag
            ),
            (1, 1, 1, 1)
        );
        assert!(report
            .details
            .iter()
            .any(|line| line.ends_with("x/missing")));
        assert!(!report.details.iter().any(|line| line.ends_with("x/extra")));
    }

    #[test]
    fn failed_listing_does_not_report_objects_missing() {
        let entry = IndexEntry {
            size: 2,
            mtime_ns: 0,
            etag: "abc".into(),
        };
        let expected = BTreeMap::from([("x/file", &entry)]);
        let denied = compare(expected.clone(), |_| Err("AccessDenied".into())).unwrap_err();
        assert_eq!(denied, "AccessDenied");
        let repeated = compare(expected, |_| Ok((Vec::new(), Some("loop".into())))).unwrap_err();
        assert!(repeated.contains("repeated continuation token"));
    }
}
