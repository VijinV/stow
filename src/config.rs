//! Persistent app configuration (config.json in the app dir).
use crate::json::Json;
use crate::{paths, secret};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct S3Settings {
    /// Empty = Amazon S3. Otherwise e.g. "https://<account>.r2.cloudflarestorage.com" or "http://192.168.1.10:9000".
    pub endpoint: String,
    /// Empty = detect automatically.
    pub region: String,
    pub bucket: String,
    /// Optional key prefix inside the bucket, e.g. "backups".
    pub prefix: String,
    pub access_key: String,
    /// Plain-text secret (in memory only; stored protected on disk).
    pub secret_key: String,
    pub path_style: bool,
    /// "" (bucket default) / STANDARD / STANDARD_IA / INTELLIGENT_TIERING / GLACIER_IR / ...
    pub storage_class: String,
    /// Extra trusted CA certificate (PEM) for self-hosted endpoints.
    pub ca_file: String,
}

impl S3Settings {
    pub fn is_complete(&self) -> bool {
        !self.bucket.trim().is_empty() && !self.access_key.trim().is_empty() && !self.secret_key.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Folder {
    pub path: String,
    /// Folder name used in the bucket (unique among folders).
    pub label: String,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleMode {
    Off,
    /// Every N hours.
    Interval,
    /// Once a day at HH:MM local time.
    Daily,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub s3: S3Settings,
    pub folders: Vec<Folder>,
    pub excludes: Vec<String>,
    pub skip_hidden: bool,
    pub parallel_uploads: u32,
    pub device_name: String,
    pub schedule: ScheduleMode,
    pub interval_hours: u32,
    pub daily_time: String,
}

pub const DEFAULT_EXCLUDES: &[&str] = &[".DS_Store", "Thumbs.db", "desktop.ini", "~$*", "*.tmp", "*.swp", ".Trash*", "$RECYCLE.BIN"];

impl Default for Config {
    fn default() -> Self {
        Config {
            s3: S3Settings::default(),
            folders: Vec::new(),
            excludes: DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect(),
            skip_hidden: false,
            parallel_uploads: 4,
            device_name: sanitize_label(&paths::hostname()),
            schedule: ScheduleMode::Off,
            interval_hours: 24,
            daily_time: "02:00".into(),
        }
    }
}

/// Make a string safe to use as one S3 key segment.
pub fn sanitize_label(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ') { c } else { '_' })
        .collect();
    let t = t.trim().trim_matches('.').to_string();
    if t.is_empty() { "folder".into() } else { t }
}

impl Config {
    pub fn path() -> PathBuf {
        paths::app_dir().join("config.json")
    }

    pub fn load() -> Config {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => Json::parse(&s).map(|j| Self::from_json(&j)).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = paths::ensure_app_dir()?;
        paths::write_private(&dir.join("config.json"), self.to_json().to_string_pretty().as_bytes())
    }

    pub fn from_json(j: &Json) -> Config {
        let d = Config::default();
        let s3 = j.get("s3").cloned().unwrap_or_else(Json::obj);
        let s3 = S3Settings {
            endpoint: s3.str_or("endpoint", ""),
            region: s3.str_or("region", ""),
            bucket: s3.str_or("bucket", ""),
            prefix: s3.str_or("prefix", ""),
            access_key: s3.str_or("access_key", ""),
            secret_key: secret::unprotect(&s3.str_or("secret_key", "")),
            path_style: s3.bool_or("path_style", false),
            storage_class: s3.str_or("storage_class", ""),
            ca_file: s3.str_or("ca_file", ""),
        };
        let folders = j
            .arr("folders")
            .iter()
            .filter_map(|f| {
                let path = f.str_or("path", "");
                if path.is_empty() {
                    return None;
                }
                Some(Folder { label: f.str_or("label", &label_for(&path)), path, enabled: f.bool_or("enabled", true) })
            })
            .collect();
        let excludes = match j.get("excludes") {
            Some(Json::Arr(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            _ => d.excludes.clone(),
        };
        Config {
            s3,
            folders,
            excludes,
            skip_hidden: j.bool_or("skip_hidden", d.skip_hidden),
            parallel_uploads: (j.num_or("parallel_uploads", 4.0) as u32).clamp(1, 16),
            device_name: { let n = j.str_or("device_name", ""); if n.is_empty() { d.device_name } else { n } },
            schedule: match j.str_or("schedule", "off").as_str() {
                "interval" => ScheduleMode::Interval,
                "daily" => ScheduleMode::Daily,
                _ => ScheduleMode::Off,
            },
            interval_hours: (j.num_or("interval_hours", 24.0) as u32).clamp(1, 24 * 7),
            daily_time: j.str_or("daily_time", "02:00"),
        }
    }

    pub fn to_json(&self) -> Json {
        let mut s3 = Json::obj();
        s3.set("endpoint", self.s3.endpoint.trim());
        s3.set("region", self.s3.region.trim());
        s3.set("bucket", self.s3.bucket.trim());
        s3.set("prefix", self.s3.prefix.trim().trim_matches('/'));
        s3.set("access_key", self.s3.access_key.trim());
        s3.set("secret_key", secret::protect(&self.s3.secret_key, self.s3.access_key.trim()));
        s3.set("path_style", self.s3.path_style);
        s3.set("storage_class", self.s3.storage_class.as_str());
        s3.set("ca_file", self.s3.ca_file.as_str());
        let mut j = Json::obj();
        j.set("version", 1u32);
        j.set("s3", s3);
        j.set(
            "folders",
            Json::Arr(
                self.folders
                    .iter()
                    .map(|f| {
                        let mut o = Json::obj();
                        o.set("path", f.path.as_str());
                        o.set("label", f.label.as_str());
                        o.set("enabled", f.enabled);
                        o
                    })
                    .collect(),
            ),
        );
        j.set("excludes", Json::Arr(self.excludes.iter().map(|s| Json::from(s.as_str())).collect()));
        j.set("skip_hidden", self.skip_hidden);
        j.set("parallel_uploads", self.parallel_uploads);
        j.set("device_name", self.device_name.as_str());
        j.set(
            "schedule",
            match self.schedule {
                ScheduleMode::Off => "off",
                ScheduleMode::Interval => "interval",
                ScheduleMode::Daily => "daily",
            },
        );
        j.set("interval_hours", self.interval_hours);
        j.set("daily_time", self.daily_time.as_str());
        j
    }

    /// Add a folder, giving it a unique label. Returns false if it's already present.
    pub fn add_folder(&mut self, path: &str) -> bool {
        let norm = path.trim_end_matches(['/', '\\']);
        let norm = if norm.is_empty() { path } else { norm };
        if self.folders.iter().any(|f| same_path(&f.path, norm)) {
            return false;
        }
        let base = label_for(norm);
        let mut label = base.clone();
        let mut n = 2;
        while self.folders.iter().any(|f| f.label.eq_ignore_ascii_case(&label)) {
            label = format!("{} ({})", base, n);
            n += 1;
        }
        self.folders.push(Folder { path: norm.to_string(), label, enabled: true });
        true
    }

    /// Remote key prefix for one folder: "<prefix>/<device>/<label>/".
    pub fn remote_root(&self, f: &Folder) -> String {
        let mut parts = Vec::new();
        let p = self.s3.prefix.trim().trim_matches('/');
        if !p.is_empty() {
            parts.push(p.to_string());
        }
        parts.push(sanitize_label(&self.device_name));
        parts.push(f.label.clone());
        format!("{}/", parts.join("/"))
    }

    /// Parse "HH:MM" into minutes after midnight.
    pub fn daily_minutes(&self) -> Option<u32> {
        let (h, m) = self.daily_time.trim().split_once(':')?;
        let (h, m): (u32, u32) = (h.trim().parse().ok()?, m.trim().parse().ok()?);
        (h < 24 && m < 60).then_some(h * 60 + m)
    }
}

fn same_path(a: &str, b: &str) -> bool {
    if cfg!(windows) || cfg!(target_os = "macos") { a.eq_ignore_ascii_case(b) } else { a == b }
}

pub fn label_for(path: &str) -> String {
    let p = std::path::Path::new(path);
    let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if name.is_empty() {
        // a drive root like "C:\" or "/"
        let t: String = path.chars().filter(|c| c.is_alphanumeric()).collect();
        return if t.is_empty() { "root".into() } else { format!("drive-{}", t) };
    }
    sanitize_label(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_roundtrip_and_labels() {
        std::env::set_var("BACKUP_TAKER_PLAIN_SECRETS", "1");
        let mut c = Config::default();
        c.s3.bucket = "b".into();
        c.s3.access_key = "AK".into();
        c.s3.secret_key = "se/cr+et".into();
        c.s3.prefix = "/backups/".into();
        c.device_name = "laptop".into();
        assert!(c.add_folder("/home/u/Documents/"));
        assert!(!c.add_folder("/home/u/Documents"));
        assert!(c.add_folder("/mnt/x/Documents"));
        assert_eq!(c.folders[1].label, "Documents (2)");
        c.schedule = ScheduleMode::Daily;
        c.daily_time = "23:15".into();
        let back = Config::from_json(&Json::parse(&c.to_json().to_string_pretty()).unwrap());
        let mut expect = c.clone();
        expect.s3.prefix = "backups".into();
        assert_eq!(back, expect);
        assert_eq!(back.remote_root(&back.folders[0]), "backups/laptop/Documents/");
        assert_eq!(back.daily_minutes(), Some(23 * 60 + 15));
    }
}
