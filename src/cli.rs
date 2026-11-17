//! Command-line mode (used by the OS scheduler, and handy for scripting/servers).
use crate::config::{Config, ScheduleMode};
use crate::engine::{self, Phase, Shared};
use crate::timefmt::{human_bytes, human_duration};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const HELP: &str = "Backup Taker — back up folders to Amazon S3 / S3-compatible storage

Usage:
  backup-taker                     Open the app
  backup-taker --backup-now        Run a backup now (prints progress)
  backup-taker --run-scheduled     Run a backup if a schedule is enabled (used by the OS scheduler)
  backup-taker --test-connection   Check the S3 settings
  backup-taker --list-buckets      List buckets visible to the configured keys
  backup-taker --status            Show settings, folders and the last runs
  backup-taker --add-folder PATH   Add a folder to back up
  backup-taker --remove-folder PATH
  backup-taker --set KEY=VALUE     Change a setting. Keys: endpoint region bucket prefix access_key
                                   secret_key path_style storage_class ca_file device_name
                                   parallel_uploads skip_hidden schedule(off|interval|daily)
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
        "--backup-now" => backup(Config::load(), "manual (command line)", true),
        "--run-scheduled" => {
            let cfg = Config::load();
            if cfg.schedule == ScheduleMode::Off {
                engine::log_line("scheduled run skipped: schedule is off");
                return 0;
            }
            backup(cfg, "scheduled", false)
        }
        "--test-connection" => match crate::remote::test_connection(&Config::load().s3) {
            Ok(s) => {
                println!("OK: {}", s);
                0
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                1
            }
        },
        "--list-buckets" => match crate::remote::list_buckets(&Config::load().s3) {
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

fn status() {
    let cfg = Config::load();
    println!("Settings: {}", Config::path().display());
    let ep = if cfg.s3.endpoint.is_empty() { "Amazon S3".to_string() } else { cfg.s3.endpoint.clone() };
    println!("Storage:  {} bucket '{}' prefix '{}' (key {})", ep, cfg.s3.bucket, cfg.s3.prefix,
        if cfg.s3.access_key.is_empty() { "not set".to_string() } else { cfg.s3.access_key.clone() });
    println!("Device:   {}", cfg.device_name);
    println!("Schedule: {}", crate::schedule::describe(&cfg));
    println!("Folders:");
    for f in &cfg.folders {
        println!("  [{}] {}  ->  {}", if f.enabled { "x" } else { " " }, f.path, cfg.remote_root(f));
    }
    if let Some(p) = engine::RunLock::read_active() {
        println!("A backup is running now: {}", p.message);
    }
    println!("Recent runs:");
    for h in engine::load_history().iter().take(5) {
        println!("  {}  {:<20} up {} / unchanged {} / failed {}  {}", crate::timefmt::format_local(h.started), h.phase.as_str(),
            h.files_uploaded, h.files_skipped, h.files_failed, human_bytes(h.bytes_done));
    }
}

fn backup(cfg: Config, trigger: &str, verbose: bool) -> i32 {
    if !cfg.s3.is_complete() {
        eprintln!("S3 is not configured yet. Open the app (or use --set) first.");
        engine::log_line("backup skipped: S3 settings incomplete");
        return 1;
    }
    let storage = match crate::remote::S3Storage::new(&cfg) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("{}", e);
            engine::log_line(&format!("backup could not start: {}", e));
            return 1;
        }
    };
    let shared = Shared::new();
    let start = Instant::now();
    let s2 = shared.clone();
    let reporter = verbose.then(|| {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(1000));
            let p = s2.snapshot();
            if !p.phase.is_running() {
                break;
            }
            eprintln!("  {} — {}/{} files, {} / {}", p.message, p.files_uploaded, p.files_to_upload,
                human_bytes(p.bytes_done), human_bytes(p.bytes_total));
        })
    });
    let p = engine::run_backup(&cfg, storage, shared, trigger);
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
