//! Command-line mode (used by the OS scheduler, and handy for scripting/servers).
use crate::config::{Config, ScheduleMode};
use crate::engine::{self, Phase, Shared};
use crate::timefmt::{human_bytes, human_duration};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const HELP: &str = "Stow — Your files, safely kept.
Back up folders to Amazon S3 / S3-compatible storage

Usage:
  backup-taker                     Open the app
  backup-taker --backup-now [--full]
                                   Run a backup now; --full re-uploads all included files
  backup-taker --dry-run [--full]  Estimate files and data to upload using the local index
  backup-taker --verify           Compare recorded uploads with current objects in S3
  backup-taker --run-scheduled     Run a backup if a schedule is enabled (used by the OS scheduler)
  backup-taker --test-connection   Check the S3 settings
  backup-taker --list-buckets      List buckets visible to the configured keys
  backup-taker --status            Show settings, folders and the last runs
  backup-taker --add-folder PATH   Add a folder to back up
  backup-taker --remove-folder PATH
  backup-taker --set KEY=VALUE     Change a setting. Keys: endpoint region bucket prefix access_key
                                   secret_key path_style storage_class ca_file device_name
                                   parallel_uploads skip_hidden skip_dev_artifacts schedule(off|interval|daily)
                                   interval_hours daily_time
  backup-taker --version

Settings live in: ";

pub fn run(args: &[String]) -> i32 {
    let a = args[0].as_str();
    match a {
        "-h" | "--help" | "help" => {
            println!("{}{}", HELP, Config::path().display());
            0
        }
        "-V" | "--version" => {
            println!("backup-taker {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "--backup-now" | "--dry-run" => {
            let full = match &args[1..] {
                [] => false,
                [flag] if flag == "--full" => true,
                _ => {
                    eprintln!("Usage: backup-taker {} [--full]", a);
                    return 2;
                }
            };
            let cfg = Config::load();
            if a == "--dry-run" {
                preview(&cfg, full)
            } else {
                let trigger = if full { "manual full (command line)" } else { "manual (command line)" };
                backup(cfg, trigger, true, full)
            }
        }
        "--verify" if args.len() == 1 => verify(&Config::load()),
        "--run-scheduled" => {
            let cfg = Config::load();
            if cfg.schedule == ScheduleMode::Off {
                engine::log_line("scheduled run skipped: schedule is off");
                return 0;
            }
            backup(cfg, "scheduled", false, false)
        }
        "--test-connection" => match test_storage(&Config::load()) {
            Ok(s) => {
                println!("OK: {}", s);
                0
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                1
            }
        },
        "--list-buckets" => match crate::managed::effective_for_cli(&Config::load()).and_then(|cfg| {
            if cfg.s3.managed.is_some() { Ok(vec![cfg.s3.bucket]) }
            else { crate::remote::list_buckets(&cfg.s3) }
        }) {
            Ok(b) => {
                for x in b {
                    println!("{}", x);
                }
                0
            }
            Err(e) => {
                eprintln!("{}", e);
                1
            }
        },
        "--status" => {
            status();
            0
        }
        "--add-folder" | "--remove-folder" => {
            let Some(p) = args.get(1) else {
                eprintln!("{} needs a path", a);
                return 2;
            };
            let mut cfg = Config::load();
            if a == "--add-folder" {
                let path = std::path::Path::new(p);
                let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
                #[cfg(windows)]
                let abs = std::path::PathBuf::from(abs.to_string_lossy().trim_start_matches(r"\\?\").to_string());
                if !abs.is_dir() {
                    eprintln!("Not a folder: {}", p);
                    return 1;
                }
                if !cfg.add_folder(&abs.to_string_lossy()) {
                    println!("Already in the list.");
                }
            } else {
                let before = cfg.folders.len();
                cfg.folders.retain(|f| f.path != p.trim_end_matches(['/', '\\']));
                if cfg.folders.len() == before {
                    eprintln!("Not in the list: {}", p);
                    return 1;
                }
            }
            save(&cfg)
        }
        "--set" => {
            let mut cfg = Config::load();
            let old_sched = (cfg.schedule, cfg.interval_hours, cfg.daily_time.clone());
            for kv in &args[1..] {
                let Some((k, v)) = kv.split_once('=') else {
                    eprintln!("Expected KEY=VALUE, got {}", kv);
                    return 2;
                };
                let b = || matches!(v, "1" | "true" | "yes" | "on");
                match k {
                    "endpoint" => cfg.s3.endpoint = v.into(),
                    "region" => cfg.s3.region = v.into(),
                    "bucket" => cfg.s3.bucket = v.into(),
                    "prefix" => cfg.s3.prefix = v.trim_matches('/').into(),
                    "access_key" => cfg.s3.access_key = v.into(),
                    "secret_key" => cfg.s3.secret_key = v.into(),
                    "path_style" => cfg.s3.path_style = b(),
                    "storage_class" => cfg.s3.storage_class = v.into(),
                    "ca_file" => cfg.s3.ca_file = v.into(),
                    "device_name" => cfg.device_name = crate::config::sanitize_label(v),
                    "parallel_uploads" => cfg.parallel_uploads = v.parse().unwrap_or(4).clamp(1, 16),
                    "skip_hidden" => cfg.skip_hidden = b(),
                    "skip_dev_artifacts" => cfg.skip_dev_artifacts = b(),
                    "schedule" => {
                        cfg.schedule = match v {
                            "interval" => ScheduleMode::Interval,
                            "daily" => ScheduleMode::Daily,
                            _ => ScheduleMode::Off,
                        }
                    }
                    "interval_hours" => cfg.interval_hours = v.parse().unwrap_or(24),
                    "daily_time" => cfg.daily_time = v.into(),
                    _ => {
                        eprintln!("Unknown setting: {}", k);
                        return 2;
                    }
                }
            }
            let rc = save(&cfg);
            if rc == 0 && old_sched != (cfg.schedule, cfg.interval_hours, cfg.daily_time.clone()) {
                match crate::schedule::apply(&cfg) {
                    Ok(m) => println!("{}", m),
                    Err(e) => {
                        eprintln!("Schedule not applied: {}", e);
                        return 1;
                    }
                }
            }
            rc
        }
        _ => {
            eprintln!("Unknown option: {}\n\n{}{}", a, HELP, Config::path().display());
            2
        }
    }
}

fn save(cfg: &Config) -> i32 {
    match cfg.save() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Could not save settings: {}", e);
            1
        }
    }
}

fn test_storage(local: &Config) -> Result<String, String> {
    let cfg = crate::managed::effective_for_cli(local)?;
    if let Some(target) = &cfg.s3.managed {
        crate::remote::scoped_client(&cfg.s3, target.read_credentials("verify"))?
            .list_objects_page(&cfg.s3.prefix, 1, None)
            .map_err(|error| error.to_string())?;
        return Ok(format!("Managed destination s3://{}/{}", cfg.s3.bucket, cfg.s3.prefix));
    }
    crate::remote::test_connection(&cfg.s3)
}

fn status() {
    let cfg = Config::load();
    println!("Settings: {}", Config::path().display());
    let effective = match crate::managed::effective_for_cli(&cfg) {
        Ok(effective) if effective.s3.managed.is_some() => {
            println!("Storage:  dashboard-managed s3://{}/{}", effective.s3.bucket, effective.s3.prefix);
            Some(effective)
        }
        Ok(_) => {
            let ep = if cfg.s3.endpoint.is_empty() { "Amazon S3" } else { &cfg.s3.endpoint };
            println!("Storage:  {ep} bucket '{}' prefix '{}' (key {})", cfg.s3.bucket, cfg.s3.prefix,
                if cfg.s3.access_key.is_empty() { "not set" } else { &cfg.s3.access_key });
            Some(cfg.clone())
        }
        Err(error) => { println!("Storage:  dashboard-managed · {error}"); None }
    };
    println!("Device:   {}", cfg.device_name);
    println!("Schedule: {}", crate::schedule::describe(&cfg));
    println!("Folders:");
    for f in &cfg.folders {
        let prefix = effective.as_ref().map(|cfg| cfg.remote_root(f)).unwrap_or_else(|| "Unavailable".into());
        println!("  [{}] {}  ->  {}", if f.enabled { "x" } else { " " }, f.path, prefix);
    }
    if let Some(p) = engine::RunLock::read_active() {
        println!("Active operation: {}", p.message);
    }
    println!("Recent runs:");
    for h in engine::load_history().iter().take(5) {
        println!("  {}  {:<20} up {} / unchanged {} / failed {}  {}", crate::timefmt::format_local(h.started), h.phase.as_str(),
            h.files_uploaded, h.files_skipped, h.files_failed, human_bytes(h.bytes_done));
    }
}

fn preview(cfg: &Config, full: bool) -> i32 {
    let cfg = match crate::managed::effective_for_cli(cfg) {
        Ok(cfg) => cfg,
        Err(error) => { eprintln!("{error}"); return 1; }
    };
    let p = engine::preview_backup(&cfg, &Shared::new(), full);
    if matches!(p.phase, Phase::Finished | Phase::FinishedWithErrors) {
        println!("{} (local estimate): {} of {} files to upload ({}), {} unchanged.",
            p.trigger, p.files_to_upload, p.files_found, human_bytes(p.bytes_total), p.files_skipped);
    }
    if p.phase != Phase::Finished {
        eprintln!("{}", p.message);
    }
    for e in p.errors.iter().take(20) {
        eprintln!("  ! {}", e);
    }
    i32::from(p.phase != Phase::Finished)
}

fn verify(cfg: &Config) -> i32 {
    let cfg = match crate::managed::effective_for_cli(cfg) {
        Ok(cfg) => cfg,
        Err(error) => { eprintln!("{error}"); return 1; }
    };
    match crate::verify::run(&cfg, &Shared::new()) {
        Ok(summary) => {
            let mut issues = !summary.errors.is_empty();
            for error in summary.errors {
                eprintln!("{error}");
            }
            for (folder, report) in summary.reports {
                println!(
                    "{}: {} matched, {} missing, {} changed in S3, {} pending, {} missing tags, {} scan problems",
                    folder, report.matched, report.missing, report.mismatched, report.pending,
                    report.no_etag, report.scan_errors,
                );
                issues |= report.has_issues();
                for detail in report.details {
                    println!("  {detail}");
                }
            }
            i32::from(issues)
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn backup(cfg: Config, trigger: &str, verbose: bool, full: bool) -> i32 {
    let shared = Shared::new();
    let start = Instant::now();
    let s2 = shared.clone();
    let (done, wait_for_done) = mpsc::channel::<()>();
    let reporter = verbose.then(|| {
        std::thread::spawn(move || {
            while wait_for_done.recv_timeout(Duration::from_secs(1)) == Err(mpsc::RecvTimeoutError::Timeout) {
                let p = s2.snapshot();
                if p.phase.is_running() {
                    eprintln!("  {} — {}/{} files, {} / {}", p.message, p.files_uploaded, p.files_to_upload,
                        human_bytes(p.bytes_done), human_bytes(p.bytes_total));
                }
            }
        })
    });
    let p = crate::managed::backup(&cfg, shared, trigger, full);
    drop(done);
    if let Some(r) = reporter {
        let _ = r.join();
    }
    println!("{} ({}; uploaded {}, unchanged {}, failed {}, {} in {})", p.message, p.phase.as_str(), p.files_uploaded,
        p.files_skipped, p.files_failed, human_bytes(p.bytes_done), human_duration(start.elapsed().as_secs()));
    for e in p.errors.iter().take(20) {
        eprintln!("  ! {}", e);
    }
    match p.phase {
        Phase::Finished => 0,
        _ => 1,
    }
}
