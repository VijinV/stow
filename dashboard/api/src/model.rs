use crate::{ApiError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyInput {
    pub bucket: String,
    pub region: String,
    pub base_prefix: String,
    pub role_arn: String,
    pub rules: Rules,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rules {
    pub excludes: Vec<String>,
    pub skip_hidden: bool,
    pub skip_dev_artifacts: bool,
    pub require_client_encryption: bool,
    pub max_parallel_uploads: u8,
    pub storage_class: String,
    pub server_encryption: String,
    #[serde(default)]
    pub kms_key_arn: String,
}

pub struct Policy {
    pub revision: i64,
    pub destination_revision: i64,
    pub settings: PolicyInput,
}

fn lower_dns(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl PolicyInput {
    pub fn validate(&self) -> Result<()> {
        if !(3..=63).contains(&self.bucket.len())
            || !lower_dns(&self.bucket)
            || self.bucket.starts_with('-')
            || self.bucket.ends_with('-')
        {
            return Err(ApiError::bad(
                "Use a valid Amazon S3 bucket name without dots.",
            ));
        }
        if self.region.len() > 32
            || !self.region.starts_with(|c: char| c.is_ascii_lowercase())
            || !lower_dns(&self.region)
            || !self.region.contains('-')
        {
            return Err(ApiError::bad("Enter an AWS region such as us-east-1."));
        }
        if self.base_prefix.len() > 96
            || (!self.base_prefix.is_empty()
                && self.base_prefix.split('/').any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || !part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                }))
        {
            return Err(ApiError::bad(
                "Use only letters, numbers, dots, hyphens, and underscores in prefix segments.",
            ));
        }
        let mut parts = self.base_prefix.split('/').peekable();
        while let Some(part) = parts.next() {
            if part == "devices" && parts.peek().is_some_and(|id| Uuid::parse_str(id).is_ok()) {
                return Err(ApiError::bad(
                    "The base prefix cannot enter a reserved device namespace.",
                ));
            }
        }
        let role = self
            .role_arn
            .strip_prefix("arn:aws:iam::")
            .and_then(|arn| arn.split_once(":role/"));
        if self.role_arn.len() > 256
            || !role.is_some_and(|(account, path)| {
                account.len() == 12
                    && account.bytes().all(|b| b.is_ascii_digit())
                    && !path.is_empty()
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/+=,.@_-".contains(&b))
            })
        {
            return Err(ApiError::bad("Enter a valid AWS IAM role ARN."));
        }
        if self.rules.excludes.len() > 100
            || self.rules.excludes.iter().any(|rule| {
                rule.is_empty() || rule.len() > 256 || rule.chars().any(char::is_control)
            })
            || !(1..=16).contains(&self.rules.max_parallel_uploads)
        {
            return Err(ApiError::bad(
                "Use up to 100 non-empty patterns and a parallel upload limit from 1 to 16.",
            ));
        }
        if !matches!(
            self.rules.storage_class.as_str(),
            "" | "STANDARD" | "STANDARD_IA" | "INTELLIGENT_TIERING"
        ) || !matches!(
            self.rules.server_encryption.as_str(),
            "" | "AES256" | "aws:kms"
        ) {
            return Err(ApiError::bad(
                "Choose a supported storage class and encryption mode.",
            ));
        }
        let kms = &self.rules.kms_key_arn;
        let valid_kms = kms
            .strip_prefix(&format!("arn:aws:kms:{}:", self.region))
            .and_then(|arn| arn.split_once(":key/"))
            .is_some_and(|(account, id)| {
                account.len() == 12
                    && account.bytes().all(|b| b.is_ascii_digit())
                    && (Uuid::parse_str(id).is_ok()
                        || id.strip_prefix("mrk-").is_some_and(|key| {
                            key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
                        }))
            });
        match self.rules.server_encryption.as_str() {
            "aws:kms" if kms.is_empty() => {
                return Err(ApiError::bad("SSE-KMS requires a KMS key ARN."))
            }
            "AES256" if !kms.is_empty() => {
                return Err(ApiError::bad("SSE-S3 does not use a KMS key."))
            }
            _ if !kms.is_empty() && !valid_kms => {
                return Err(ApiError::bad(
                    "Enter a KMS key ARN in the destination region.",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

impl Policy {
    pub fn prefix(&self, device: Uuid) -> String {
        let base = &self.settings.base_prefix;
        if base.is_empty() {
            format!("devices/{device}/")
        } else {
            format!("{base}/devices/{device}/")
        }
    }

    pub fn device_view(&self, device: Uuid) -> Value {
        json!({"schemaVersion": 1, "revision": self.revision, "destinationRevisionId": self.destination_revision,
            "bucket": self.settings.bucket, "region": self.settings.region, "prefix": self.prefix(device),
            "rules": self.settings.rules})
    }
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Pending,
    Active,
    Paused,
    Revoked,
}

impl DeviceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub sequence: u32,
    pub phase: Phase,
    pub files_uploaded: String,
    pub files_failed: String,
    pub files_skipped: String,
    pub bytes_done: String,
    #[serde(default)]
    pub error_code: Option<ErrorCode>,
    #[serde(default)]
    pub replayed: bool,
}

impl Snapshot {
    pub fn validate(&self) -> Result<()> {
        let counters = [
            &self.files_uploaded,
            &self.files_failed,
            &self.files_skipped,
            &self.bytes_done,
        ];
        if self.sequence == 0
            || counters
                .iter()
                .any(|s| s.parse::<u64>().map_or(true, |n| n.to_string() != **s))
        {
            return Err(ApiError::bad(
                "Use a positive sequence and unsigned decimal string counters.",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    StorageAccessDenied,
    PolicyUnavailable,
    LocalReadFailed,
    RecoveryKeyRequired,
    DashboardUnavailable,
    StorageUnavailable,
    Unknown,
}

#[derive(Deserialize, Serialize, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Scanning,
    Uploading,
    Finished,
    FinishedWithErrors,
    Failed,
    Cancelled,
}

impl Phase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Finished | Self::FinishedWithErrors | Self::Failed | Self::Cancelled
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scanning => "scanning",
            Self::Uploading => "uploading",
            Self::Finished => "finished",
            Self::FinishedWithErrors => "finished_with_errors",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Manual,
    Scheduled,
}
impl Trigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Scheduled => "scheduled",
        }
    }
}
