//! Registers automatic backups with the operating system's own scheduler, so they run even
//! when the app window is closed:
//! - Linux: a systemd user timer (falls back to the user's crontab)
//! - macOS: a LaunchAgent in ~/Library/LaunchAgents
//! - Windows: a Task Scheduler task (schtasks)
//! The scheduled command is `<this executable> --run-scheduled`.
use crate::config::{Config, ScheduleMode};
use std::process::Command;

pub const TASK_NAME: &str = "BackupTaker";
pub const INTERVAL_CHOICES: &[u32] = &[1, 2, 3, 4, 6, 8, 12, 24];

fn exe() -> Result<String, String> {
    let p = std::env::current_exe().map_err(|e| format!("cannot find own executable: {}", e))?;
    let p = p.canonicalize().unwrap_or(p);
    let s = p.to_string_lossy().to_string();
    #[cfg(windows)]
    let s = s.trim_start_matches(r"\\?\").to_string();
    Ok(s)
}

fn run(cmd: &mut Command) -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = cmd.output().map_err(|e| format!("{:?}: {}", cmd.get_program(), e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if msg.is_empty() {
            msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        Err(format!("{:?} failed: {}", cmd.get_program(), msg))
    }
}

pub fn describe(cfg: &Config) -> String {
    match cfg.schedule {
        ScheduleMode::Off => "Automatic backups are off.".into(),
        ScheduleMode::Interval if cfg.interval_hours == 1 => "Backs up every hour.".into(),
        ScheduleMode::Interval => format!("Backs up every {} hours.", cfg.interval_hours),
        ScheduleMode::Daily => format!("Backs up every day at {}.", cfg.daily_time.trim()),
    }
}

/// Normalised interval (must divide 24 so calendar-based schedulers can express it).
fn interval(cfg: &Config) -> u32 {
    let h = cfg.interval_hours.clamp(1, 24);
    *INTERVAL_CHOICES.iter().find(|&&c| c >= h).unwrap_or(&24)
}

/// Estimate the next configured wall-clock occurrence for dashboard status.
#[cfg(unix)]
pub(crate) fn next_expected(cfg: &Config, now: i64) -> Option<u64> {
    if cfg.schedule == ScheduleMode::Off { return None; }
    let daily = cfg.daily_minutes();
    let interval_minutes = i64::from(interval(cfg)) * 60;
    let first = now.div_euclid(60) + 1;
    (first..first + 27 * 60).find_map(|minute| {
        let utc = minute * 60;
        let local_minutes = (utc + crate::timefmt::local_offset_secs(utc)).div_euclid(60).rem_euclid(24 * 60);
        let matches = match cfg.schedule {
            ScheduleMode::Daily => daily.is_some_and(|m| i64::from(m) == local_minutes),
            ScheduleMode::Interval => local_minutes.rem_euclid(interval_minutes) == 0,
            ScheduleMode::Off => false,
        };
        matches.then_some(utc as u64)
    })
}

/// Install, update or remove the OS schedule to match `cfg`. Returns a human status message.
pub fn apply(cfg: &Config) -> Result<String, String> {
    if cfg.schedule == ScheduleMode::Daily && cfg.daily_minutes().is_none() {
        return Err("Daily time must look like 02:30 (24-hour clock).".into());
    }
    let r = os::apply(cfg);
    if r.is_ok() {
        crate::engine::log_line(&format!("schedule updated: {}", describe(cfg)));
    }
    r
}

#[cfg(all(unix, not(target_os = "macos")))]
mod os {
    use super::*;

    const CRON_TAG: &str = "# backup-taker-schedule";

    fn unit_dir() -> std::path::PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| crate::paths::home_dir().join(".config"));
        base.join("systemd").join("user")
    }

    fn on_calendar(cfg: &Config) -> String {
        match cfg.schedule {
            ScheduleMode::Daily => {
                let m = cfg.daily_minutes().unwrap_or(120);
                format!("*-*-* {:02}:{:02}:00", m / 60, m % 60)
            }
            _ => {
                let n = interval(cfg);
                if n >= 24 { "*-*-* 00:00:00".into() } else { format!("*-*-* 00/{}:00:00", n) }
            }
        }
    }

    fn cron_expr(cfg: &Config) -> String {
        match cfg.schedule {
            ScheduleMode::Daily => {
                let m = cfg.daily_minutes().unwrap_or(120);
                format!("{} {} * * *", m % 60, m / 60)
            }
            _ => {
                let n = interval(cfg);
                if n >= 24 { "0 0 * * *".into() } else { format!("0 */{} * * *", n) }
            }
        }
    }

    fn systemd_available() -> bool {
        Command::new("systemctl").args(["--user", "show-environment"]).output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn crontab_without_ours() -> String {
        let cur = Command::new("crontab").arg("-l").output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        cur.lines().filter(|l| !l.contains(CRON_TAG)).map(|l| format!("{}\n", l)).collect()
    }

    fn write_crontab(content: &str) -> Result<(), String> {
        use std::io::Write;
        let mut child = Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("crontab: {}", e))?;
        child.stdin.take().unwrap().write_all(content.as_bytes()).map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if out.status.success() { Ok(()) } else { Err(format!("crontab failed: {}", String::from_utf8_lossy(&out.stderr).trim())) }
    }

    pub fn apply(cfg: &Config) -> Result<String, String> {
        let dir = unit_dir();
        let svc = dir.join("backup-taker.service");
        let timer = dir.join("backup-taker.timer");
        let has_cron_entry = Command::new("crontab").arg("-l").output().map(|o| String::from_utf8_lossy(&o.stdout).contains(CRON_TAG)).unwrap_or(false);

        if cfg.schedule == ScheduleMode::Off {
            if timer.exists() {
                let _ = run(Command::new("systemctl").args(["--user", "disable", "--now", "backup-taker.timer"]));
                let _ = std::fs::remove_file(&timer);
                let _ = std::fs::remove_file(&svc);
                let _ = run(Command::new("systemctl").args(["--user", "daemon-reload"]));
            }
            if has_cron_entry {
                write_crontab(&crontab_without_ours())?;
            }
            return Ok(describe(cfg));
        }

        let exe = exe()?;
        if systemd_available() {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(
                &svc,
                format!(
                    "[Unit]\nDescription=Stow scheduled backup\n\n[Service]\nType=oneshot\nExecStart={} --run-scheduled\nNice=10\nIOSchedulingClass=idle\n",
                    quote(&exe)
                ),
            )
            .map_err(|e| e.to_string())?;
            std::fs::write(
                &timer,
                format!(
                    "[Unit]\nDescription=Stow schedule\n\n[Timer]\nOnCalendar={}\nPersistent=true\nRandomizedDelaySec=60\n\n[Install]\nWantedBy=timers.target\n",
                    on_calendar(cfg)
                ),
            )
            .map_err(|e| e.to_string())?;
            run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
            run(Command::new("systemctl").args(["--user", "enable", "--now", "backup-taker.timer"]))?;
            let _ = run(Command::new("systemctl").args(["--user", "restart", "backup-taker.timer"]));
            if has_cron_entry {
                let _ = write_crontab(&crontab_without_ours());
            }
            return Ok(format!("{} (systemd user timer)", describe(cfg)));
        }
        let mut tab = crontab_without_ours();
        tab.push_str(&format!("{} '{}' --run-scheduled {}\n", cron_expr(cfg), exe.replace('\'', "'\\''"), CRON_TAG));
        write_crontab(&tab)?;
        Ok(format!("{} (cron)", describe(cfg)))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn expressions() {
            let mut c = Config::default();
            c.schedule = ScheduleMode::Interval;
            c.interval_hours = 6;
            assert_eq!(on_calendar(&c), "*-*-* 00/6:00:00");
            assert_eq!(cron_expr(&c), "0 */6 * * *");
            c.interval_hours = 5; // rounds up to a divisor of 24
            assert_eq!(cron_expr(&c), "0 */6 * * *");
            c.schedule = ScheduleMode::Daily;
            c.daily_time = "3:07".into();
            assert_eq!(on_calendar(&c), "*-*-* 03:07:00");
            assert_eq!(cron_expr(&c), "7 3 * * *");
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    use super::*;
    const LABEL: &str = "com.backuptaker.scheduled";

    extern "C" {
        fn getuid() -> u32;
    }

    fn xml_esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    pub fn apply(cfg: &Config) -> Result<String, String> {
        let dir = crate::paths::home_dir().join("Library").join("LaunchAgents");
        let plist = dir.join(format!("{}.plist", LABEL));
        let domain = format!("gui/{}", unsafe { getuid() });
        if plist.exists() {
            let _ = run(Command::new("launchctl").args(["bootout", &domain, &plist.to_string_lossy()]));
        }
        if cfg.schedule == ScheduleMode::Off {
            let _ = std::fs::remove_file(&plist);
            return Ok(describe(cfg));
        }
        let times: Vec<(u32, u32)> = match cfg.schedule {
            ScheduleMode::Daily => {
                let m = cfg.daily_minutes().unwrap_or(120);
                vec![(m / 60, m % 60)]
            }
            _ => (0..24).step_by(interval(cfg) as usize).map(|h| (h, 0)).collect(),
        };
        let mut cal = String::new();
        for (h, m) in times {
            cal.push_str(&format!("    <dict><key>Hour</key><integer>{}</integer><key>Minute</key><integer>{}</integer></dict>\n", h, m));
        }
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{}</string>\n  <key>ProgramArguments</key>\n  <array><string>{}</string><string>--run-scheduled</string></array>\n  <key>StartCalendarInterval</key>\n  <array>\n{}  </array>\n  <key>ProcessType</key><string>Background</string>\n  <key>LowPriorityIO</key><true/>\n</dict>\n</plist>\n",
            LABEL,
            xml_esc(&exe()?),
            cal
        );
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::write(&plist, body).map_err(|e| e.to_string())?;
        run(Command::new("launchctl").args(["bootstrap", &domain, &plist.to_string_lossy()]))
            .or_else(|_| run(Command::new("launchctl").args(["load", "-w", &plist.to_string_lossy()])))?;
        Ok(format!("{} (launchd)", describe(cfg)))
    }
}

#[cfg(windows)]
mod os {
    use super::*;
    pub fn apply(cfg: &Config) -> Result<String, String> {
        if cfg.schedule == ScheduleMode::Off {
            let _ = run(Command::new("schtasks").args(["/Delete", "/TN", TASK_NAME, "/F"]));
            return Ok(describe(cfg));
        }
        let tr = format!("\"{}\" --run-scheduled", exe()?);
        let mut c = Command::new("schtasks");
        c.args(["/Create", "/F", "/TN", TASK_NAME, "/TR", &tr]);
        match cfg.schedule {
            ScheduleMode::Daily => {
                let m = cfg.daily_minutes().unwrap_or(120);
                let st = format!("{:02}:{:02}", m / 60, m % 60);
                c.args(["/SC", "DAILY", "/ST", &st]);
            }
            _ => {
                let n = interval(cfg);
                if n >= 24 {
                    c.args(["/SC", "DAILY", "/ST", "00:00"]);
                } else {
                    let mo = n.to_string();
                    c.args(["/SC", "HOURLY", "/MO", &mo, "/ST", "00:00"]);
                }
            }
        }
        run(&mut c)?;
        Ok(format!("{} (Task Scheduler)", describe(cfg)))
    }
}
