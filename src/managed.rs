//! Dashboard enrollment, runtime policy, and temporary AWS access.
use crate::{
    config::{Config, ScheduleMode},
    dashboard_api::{Api, Error},
    json::Json,
    paths, remote, secret,
};
use bt_s3::{CredentialProvider, RequestCredentials, S3Error, Url};
use std::{
    fmt, fs, io,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

#[path = "managed_run.rs"]
mod run;
pub(crate) use run::backup;

fn state_dir() -> PathBuf {
    remote::upload_resume_dir().join("dashboard")
}

fn store(path: &std::path::Path, value: &Json) -> Result<(), String> {
    paths::ensure_app_dir().map_err(|error| error.to_string())?;
    fs::create_dir_all(path.parent().ok_or("Invalid dashboard state directory.")?)
        .map_err(|e| e.to_string())?;
    paths::write_private(path, value.to_string_compact().as_bytes()).map_err(|e| e.to_string())
}

fn read(path: &std::path::Path) -> Result<Option<Json>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Json::parse(&text)
            .map(Some)
            .map_err(|_| "Could not read saved dashboard state.".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("Could not open dashboard state: {error}")),
    }
}

fn digest(text: &str) -> String {
    use bt_tls::crypto::{sha256::sha256, util::hex};
    hex(&sha256(text.as_bytes()))
}

fn valid_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

fn random_id() -> Result<String, String> {
    use bt_tls::crypto::{random, util::hex};
    let mut data = random::array::<16>().map_err(|_| "Could not generate a run ID.")?;
    data[6] = (data[6] & 0x0f) | 0x40;
    data[8] = (data[8] & 0x3f) | 0x80;
    let hex = hex(&data);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn object(fields: &[(&str, Json)]) -> Json {
    let mut result = Json::obj();
    for (key, value) in fields {
        result.set(key, value.clone());
    }
    result
}

fn string(value: &Json, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("The dashboard response is missing {key}."))
}

fn integer(value: &Json, key: &str) -> Result<u64, String> {
    match value.get(key) {
        Some(Json::Num(number))
            if *number >= 0.0 && *number <= 9_007_199_254_740_991.0 && number.fract() == 0.0 =>
        {
            Ok(*number as u64)
        }
        _ => Err(format!("The dashboard response has an invalid {key}.")),
    }
}

fn boolean(value: &Json, key: &str) -> Result<bool, String> {
    match value.get(key) {
        Some(Json::Bool(result)) => Ok(*result),
        _ => Err(format!("The dashboard response has an invalid {key}.")),
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Profile {
    pub origin: String,
    pub id: String,
    pub name: String,
    pub active: bool,
    token: String,
}

impl fmt::Debug for Profile {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("DashboardProfile")
            .field("origin", &self.origin)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Profile {
    pub fn validate_origin(input: &str) -> Result<String, String> {
        let input = input.trim().trim_end_matches('/');
        let (_, authority) = input
            .split_once("://")
            .ok_or("Enter an HTTPS dashboard address.")?;
        if authority.is_empty()
            || authority
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || b".-:[]".contains(&b)))
        {
            return Err(
                "Enter only the dashboard origin, such as https://dashboard.example.com.".into(),
            );
        }
        let url = Url::parse(input).map_err(|_| "Enter a valid dashboard address.")?;
        if url.port == 0
            || (!url.is_https() && !url.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
        {
            return Err("Use HTTPS for your dashboard. HTTP is available for loopback development addresses.".into());
        }
        Ok(format!("{}://{}", url.scheme, url.host_header()))
    }

    pub fn load() -> Result<Option<Self>, String> {
        let Some(value) = read(&state_dir().join("profile.json"))? else {
            return Ok(None);
        };
        let profile = Self {
            origin: Self::validate_origin(&string(&value, "origin")?)?,
            id: string(&value, "deviceId")?,
            name: string(&value, "name")?,
            active: boolean(&value, "active")?,
            token: secret::unprotect(&string(&value, "token")?),
        };
        if !valid_uuid(&profile.id)
            || profile.token.len() != 64
            || !profile.token.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Could not unlock the paired device. Disconnect it and pair again.".into());
        }
        Ok(Some(profile))
    }

    fn save(&self) -> Result<(), String> {
        store(
            &state_dir().join("profile.json"),
            &object(&[
                ("origin", Json::from(self.origin.as_str())),
                ("deviceId", Json::from(self.id.as_str())),
                ("name", Json::from(self.name.as_str())),
                ("active", Json::from(self.active)),
                (
                    "token",
                    Json::from(secret::protect(
                        &self.token,
                        &format!("dashboard-device-{}", self.identity()),
                    )),
                ),
            ]),
        )
    }

    pub fn set_active(&mut self, active: bool) -> Result<(), String> {
        let _lock = crate::engine::RunLock::acquire()?;
        let mut updated = Self::load()?
            .filter(|profile| profile.id == self.id && profile.origin == self.origin)
            .ok_or("The paired device changed. Reopen Stow and try again.")?;
        updated.active = active;
        updated.save()?;
        *self = updated;
        Ok(())
    }

    pub fn disconnect() -> Result<(), String> {
        let _lock = crate::engine::RunLock::acquire()?;
        let path = state_dir().join("profile.json");
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn pair(origin: &str, code: &str) -> Result<Self, String> {
        let _lock = crate::engine::RunLock::acquire()?;
        if Self::load()?.is_some() {
            return Err(
                "This installation is already paired. Disconnect it before pairing again.".into(),
            );
        }
        let origin = Self::validate_origin(origin)?;
        let code = code.trim();
        if code.len() != 64 || !code.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Paste the full pairing code from the dashboard.".into());
        }
        let pending = state_dir().join("pairing.json");
        let nonce = digest(&format!("{origin}\n{code}"));
        let previous = read(&pending)?
            .filter(|value| value.str_or("attempt", "") == nonce)
            .map(|value| secret::unprotect(&value.str_or("token", "")))
            .filter(|token| !token.is_empty());
        let token = match previous {
            Some(token) => token,
            None => {
                use bt_tls::crypto::{random, util::hex};
                let token =
                    hex(&random::array::<32>().map_err(|_| "Could not generate a device token.")?);
                store(
                    &pending,
                    &object(&[
                        ("attempt", Json::from(nonce.as_str())),
                        (
                            "token",
                            Json::from(secret::protect(
                                &token,
                                &format!("dashboard-pairing-{nonce}"),
                            )),
                        ),
                    ]),
                )?;
                token
            }
        };
        let api = Api::new(&origin).map_err(|e| e.message)?;
        let body = object(&[
            ("pairingCode", Json::from(code)),
            ("deviceToken", Json::from(token.as_str())),
        ]);
        let response = api
            .request("POST", "/enrollment/redeem", None, Some(&body))
            .map_err(|e| e.message)?;
        let id = string(&response, "deviceId")?;
        if !valid_uuid(&id) {
            return Err("The dashboard returned an invalid device ID.".into());
        }
        let profile = Self {
            origin,
            id,
            name: string(&response, "displayName")?,
            token,
            active: false,
        };
        profile.save()?;
        let _ = fs::remove_file(pending);
        Ok(profile)
    }

    fn identity(&self) -> String {
        digest(&format!("{}\n{}", self.origin, self.id))
    }

    fn api(&self) -> Result<Api, Error> {
        Api::new(&self.origin)
    }

    pub(crate) fn request(
        &self,
        api: &Api,
        method: &str,
        path: &str,
        body: Option<&Json>,
    ) -> Result<Json, Error> {
        api.request(method, path, Some(&self.token), body)
    }

    fn check_in(&self, api: &Api, cfg: &Config, revision: Option<u64>) -> Result<bool, Error> {
        let mut body = object(&[
            ("platform", Json::from(std::env::consts::OS)),
            ("appVersion", Json::from(env!("CARGO_PKG_VERSION"))),
            (
                "scheduleEnabled",
                Json::from(cfg.schedule != ScheduleMode::Off),
            ),
        ]);
        #[cfg(unix)]
        if let Some(due) = crate::schedule::next_expected(cfg, crate::timefmt::now_secs()) {
            body.set("nextDueAt", due);
        }
        if let Some(revision) = revision {
            body.set("appliedRevision", revision);
        }
        let response = self.request(api, "POST", "/device/check-in", Some(&body))?;
        match response.str_or("state", "").as_str() {
            "active" => Ok(false),
            "paused" => Ok(true),
            _ => Err(Error::local(
                "The dashboard returned an unknown device state.",
            )),
        }
    }

    #[cfg(test)]
    pub fn test(origin: &str, id: &str) -> Self {
        Self {
            origin: origin.into(),
            id: id.into(),
            name: "Test device".into(),
            active: true,
            token: "1".repeat(64),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Policy {
    pub revision: u64,
    target: Target,
    excludes: Vec<String>,
    skip_hidden: bool,
    skip_dev: bool,
    encryption_required: bool,
    parallelism: u32,
    storage_class: String,
    server_encryption: String,
    kms_key: String,
}

#[derive(Clone)]
pub(crate) struct Target(Arc<TargetData>);

struct TargetData {
    profile: Profile,
    generation: u64,
    bucket: String,
    region: String,
    prefix: String,
    scope: String,
    read: OnceLock<Arc<Sessions>>,
    verify: OnceLock<Arc<Sessions>>,
}

impl fmt::Debug for Target {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ManagedTarget")
            .field("scope", &self.scope())
            .finish()
    }
}

impl PartialEq for Target {
    fn eq(&self, other: &Self) -> bool {
        self.scope() == other.scope()
    }
}

impl Target {
    pub fn scope(&self) -> &str {
        &self.0.scope
    }

    pub fn read_credentials(&self, purpose: &'static str) -> Arc<dyn CredentialProvider> {
        let slot = if purpose == "verify" {
            &self.0.verify
        } else {
            &self.0.read
        };
        slot.get_or_init(|| Arc::new(Sessions::new(self, purpose, None)))
            .clone()
    }
}

impl Policy {
    pub(crate) fn requires_encryption(&self) -> bool {
        self.encryption_required
    }

    pub(crate) fn parse(raw: &Json, profile: &Profile) -> Result<Self, String> {
        if integer(raw, "schemaVersion")? != 1 {
            return Err("Update Stow to use this dashboard policy.".into());
        }
        let revision = integer(raw, "revision")?;
        let generation = integer(raw, "destinationRevisionId")?;
        let bucket = string(raw, "bucket")?;
        let region = string(raw, "region")?;
        let prefix = string(raw, "prefix")?;
        let expected = format!("devices/{}/", profile.id);
        let base = prefix
            .strip_suffix(&expected)
            .ok_or("The policy prefix does not match this device.")?;
        let dns = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if revision == 0
            || generation == 0
            || !(3..=63).contains(&bucket.len())
            || !bucket.bytes().all(dns)
            || bucket.starts_with('-')
            || bucket.ends_with('-')
            || region.is_empty()
            || region.len() > 32
            || !region.bytes().all(dns)
            || !region.contains('-')
            || base.len() > 97
            || (!base.is_empty()
                && (!base.ends_with('/')
                    || base.trim_end_matches('/').split('/').any(|part| {
                        part.is_empty()
                            || matches!(part, "." | "..")
                            || !part
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    })))
        {
            return Err("The dashboard returned an invalid S3 destination.".into());
        }
        let rules = raw
            .get("rules")
            .ok_or("The dashboard policy is missing its backup rules.")?;
        let excludes = match rules.get("excludes") {
            Some(Json::Arr(items)) if items.len() <= 100 => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .filter(|s| {
                            !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
                        })
                        .map(str::to_owned)
                        .ok_or("The dashboard returned an invalid exclusion.")
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("The dashboard returned invalid exclusions.".into()),
        };
        let parallelism = integer(rules, "maxParallelUploads")?;
        if !(1..=16).contains(&parallelism) {
            return Err("The dashboard returned an invalid upload limit.".into());
        }
        let storage_class = string(rules, "storageClass")?;
        let server_encryption = string(rules, "serverEncryption")?;
        let kms_key = string(rules, "kmsKeyArn")?;
        if !matches!(
            storage_class.as_str(),
            "" | "STANDARD" | "STANDARD_IA" | "INTELLIGENT_TIERING"
        ) || !matches!(server_encryption.as_str(), "" | "AES256" | "aws:kms")
            || (server_encryption == "aws:kms" && kms_key.is_empty())
            || kms_key.chars().any(char::is_control)
        {
            return Err(
                "The dashboard returned unsupported storage or encryption settings.".into(),
            );
        }
        let scope = digest(&format!(
            "{}\n{generation}\n{bucket}\n{region}\n{prefix}",
            profile.identity()
        ));
        Ok(Self {
            revision,
            target: Target(Arc::new(TargetData {
                profile: profile.clone(),
                generation,
                bucket,
                region,
                prefix,
                scope,
                read: OnceLock::new(),
                verify: OnceLock::new(),
            })),
            excludes,
            skip_hidden: boolean(rules, "skipHidden")?,
            skip_dev: boolean(rules, "skipDevArtifacts")?,
            encryption_required: boolean(rules, "requireClientEncryption")?,
            parallelism: parallelism as u32,
            storage_class,
            server_encryption,
            kms_key,
        })
    }

    pub fn apply(&self, local: &Config) -> Result<Config, String> {
        let mut effective = local.clone();
        let mut labels = std::collections::HashSet::new();
        for folder in &mut effective.folders {
            if folder.enabled
                && (folder.label.trim().is_empty()
                    || matches!(folder.label.as_str(), "." | "..")
                    || folder.label.contains(['/', '\\'])
                    || folder.label.chars().any(char::is_control)
                    || !labels.insert(folder.label.to_lowercase()))
            {
                return Err("Give each enabled folder a unique, valid backup label.".into());
            }
            if self.skip_dev {
                folder.skip_dev_artifacts = Some(true);
            }
        }
        effective.excludes.extend(self.excludes.iter().cloned());
        effective.skip_hidden |= self.skip_hidden;
        effective.skip_dev_artifacts |= self.skip_dev;
        effective.parallel_uploads = effective.parallel_uploads.min(self.parallelism);
        let storage = &mut effective.s3;
        storage.endpoint.clear();
        storage.ca_file.clear();
        storage.access_key.clear();
        storage.secret_key.clear();
        storage.bucket = self.target.0.bucket.clone();
        storage.region = self.target.0.region.clone();
        storage.prefix = self.target.0.prefix.clone();
        storage.storage_class = self.storage_class.clone();
        storage.server_encryption = self.server_encryption.clone();
        // Bucket default uses its own encryption header settings; AWS access
        // still receives KMS permissions from the dashboard if configured.
        storage.kms_key_id = if self.server_encryption == "aws:kms" {
            self.kms_key.clone()
        } else {
            String::new()
        };
        storage.path_style = false;
        storage.client_encryption |= self.encryption_required;
        storage.managed = Some(self.target.clone());
        Ok(effective)
    }
}

pub(crate) struct Readiness {
    pub paused: bool,
    pub policy: Option<Policy>,
    pub policy_error: Option<String>,
    pub reporting_error: Option<String>,
}

pub(crate) fn refresh(
    profile: &Profile,
    cfg: &Config,
    applied: Option<u64>,
) -> Result<Readiness, String> {
    let api = profile.api().map_err(|e| e.message)?;
    let paused = profile
        .check_in(&api, cfg, applied)
        .map_err(|e| e.message)?;
    let reporting_error = run::flush_pending(profile, &api).err();
    let policy = profile
        .request(&api, "GET", "/device/policy", None)
        .map_err(|e| e.message)
        .and_then(|value| Policy::parse(&value, profile));
    let (policy, policy_error) = match policy {
        Ok(policy) => (Some(policy), None),
        Err(error) => (None, Some(error)),
    };
    Ok(Readiness {
        paused,
        policy,
        policy_error,
        reporting_error,
    })
}

pub(crate) fn effective_for_cli(cfg: &Config) -> Result<Config, String> {
    let Some(profile) = Profile::load()?.filter(|p| p.active) else {
        return Ok(cfg.clone());
    };
    let api = profile.api().map_err(|e| e.message)?;
    let value = profile
        .request(&api, "GET", "/device/policy", None)
        .map_err(|e| e.message)?;
    Policy::parse(&value, &profile)?.apply(cfg)
}

struct Sessions {
    profile: Profile,
    generation: u64,
    bucket: String,
    region: String,
    prefix: String,
    purpose: &'static str,
    run_id: Option<String>,
    state: Mutex<SessionState>,
    stopped: AtomicBool,
}

#[derive(Default)]
struct SessionState {
    current: Option<(RequestCredentials, Instant)>,
    retry_at: Option<Instant>,
    denied: bool,
}

impl Sessions {
    fn new(target: &Target, purpose: &'static str, run_id: Option<String>) -> Self {
        let target = &target.0;
        Self {
            profile: target.profile.clone(),
            generation: target.generation,
            bucket: target.bucket.clone(),
            region: target.region.clone(),
            prefix: target.prefix.clone(),
            purpose,
            run_id,
            state: Mutex::new(SessionState::default()),
            stopped: AtomicBool::new(false),
        }
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Ok(mut state) = self.state.try_lock() {
            state.current = None;
        }
    }

    fn issue(&self) -> Result<(RequestCredentials, Instant), Error> {
        let api = self.profile.api()?;
        let mut body = object(&[("purpose", Json::from(self.purpose))]);
        if let Some(id) = &self.run_id {
            body.set("runId", id.as_str());
        }
        let requested = Instant::now();
        let value = self
            .profile
            .request(&api, "POST", "/device/storage-sessions", Some(&body))?;
        if integer(&value, "destinationRevisionId") != Ok(self.generation)
            || string(&value, "prefix").as_deref() != Ok(self.prefix.as_str())
            || string(&value, "bucket").as_deref() != Ok(self.bucket.as_str())
            || string(&value, "region").as_deref() != Ok(self.region.as_str())
        {
            return Err(Error::local("Dashboard storage access no longer matches the selected destination. Refresh and retry."));
        }
        let ttl = integer(&value, "expiresAt")
            .and_then(|expires| {
                let server = integer(&value, "serverTime")?;
                Ok(expires.saturating_sub(server))
            })
            .map_err(Error::local)?;
        let expiry = requested + Duration::from_secs(ttl.min(900));
        if expiry <= Instant::now() {
            return Err(Error::local(
                "The dashboard returned expired storage access.",
            ));
        }
        let field = |name| {
            string(&value, name).map_err(Error::local).and_then(|text| {
                if text.is_empty()
                    || text.len() > 8192
                    || !text.bytes().all(|b| b.is_ascii_graphic())
                {
                    Err(Error::local(
                        "The dashboard returned invalid AWS session credentials.",
                    ))
                } else {
                    Ok(text)
                }
            })
        };
        Ok((
            RequestCredentials {
                access_key: field("accessKeyId")?,
                secret_key: field("secretAccessKey")?,
                session_token: field("sessionToken")?,
            },
            expiry,
        ))
    }
}

impl CredentialProvider for Sessions {
    fn credentials(&self, rejected: Option<&str>) -> Result<RequestCredentials, S3Error> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| S3Error::new(0, "DashboardAccess", "Could not read dashboard access."))?;
        if state.denied || self.stopped.load(Ordering::Relaxed) {
            state.current = None;
            return Err(S3Error::new(
                403,
                "DashboardAccess",
                "Device storage access was denied.",
            ));
        }
        let now = Instant::now();
        if let Some((current, _)) = state.current.as_ref().filter(|(current, expires)| {
            Some(current.access_key.as_str()) != rejected
                && *expires > now
                && (*expires > now + Duration::from_secs(120)
                    || state.retry_at.is_some_and(|retry| retry > now))
        }) {
            return Ok(current.clone());
        }
        if state.retry_at.is_some_and(|retry| retry > now) {
            return Err(S3Error::new(
                0,
                "DashboardAccess",
                "Temporary storage access is unavailable. Try again shortly.",
            ));
        }
        let issued = self.issue();
        if self.stopped.load(Ordering::Relaxed) {
            state.current = None;
            return Err(S3Error::new(
                403,
                "DashboardAccess",
                "Device storage access was stopped.",
            ));
        }
        match issued {
            Ok((current, expires)) => {
                state.current = Some((current.clone(), expires));
                state.retry_at = None;
                Ok(current)
            }
            Err(error) if error.authorization_failed() => {
                state.denied = true;
                state.current = None;
                Err(S3Error::new(error.status, "DashboardAccess", error.message))
            }
            Err(error) => {
                state.retry_at = Some(Instant::now() + Duration::from_secs(5));
                if let Some((current, _)) = state.current.as_ref().filter(|(current, expires)| {
                    Some(current.access_key.as_str()) != rejected && *expires > Instant::now()
                }) {
                    return Ok(current.clone());
                }
                Err(S3Error::new(error.status, "DashboardAccess", error.message))
            }
        }
    }
}
