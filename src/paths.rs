//! Per-OS locations for configuration and state.
use std::path::PathBuf;

pub const APP_DIR_NAME: &str = "BackupTaker";

fn home() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(p) = std::env::var_os("USERPROFILE") {
            return PathBuf::from(p);
        }
    }
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

pub fn home_dir() -> PathBuf {
    home()
}

/// Directory holding config.json, the upload index and run history.
/// `BACKUP_TAKER_HOME` overrides it (used by tests and portable installs).
pub fn app_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("BACKUP_TAKER_HOME") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        if let Some(p) = std::env::var_os("APPDATA") {
            return PathBuf::from(p).join(APP_DIR_NAME);
        }
        home().join("AppData").join("Roaming").join(APP_DIR_NAME)
    }
    #[cfg(target_os = "macos")]
    {
        home().join("Library").join("Application Support").join(APP_DIR_NAME)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home().join(".config"));
        base.join("backup-taker")
    }
}

pub fn ensure_app_dir() -> std::io::Result<PathBuf> {
    let d = app_dir();
    std::fs::create_dir_all(&d)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    Ok(d)
}

/// Write a file atomically (temp file + rename), private to the user on Unix.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Device name used as a top-level folder in the bucket.
pub fn hostname() -> String {
    for k in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(v) = std::env::var(k) {
            if !v.trim().is_empty() {
                return v.trim().to_string();
            }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
            if !s.trim().is_empty() {
                return s.trim().to_string();
            }
        }
        if let Ok(o) = std::process::Command::new("hostname").output() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    "my-computer".to_string()
}
