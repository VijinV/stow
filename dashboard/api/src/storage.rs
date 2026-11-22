#[cfg(feature = "aws")]
use crate::now;
use crate::{
    audit,
    devices::authenticate,
    model::{Policy, PolicyInput},
    policy, ApiError, AppState, Result,
};
use axum::{extract::State, http::HeaderMap, Json};
use rusqlite::TransactionBehavior;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
#[cfg(feature = "aws")]
use {axum::http::StatusCode, rusqlite::Connection};

pub async fn admin_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    state.admin(&headers)?;
    state
        .db(|conn| {
            Ok(Json(
                policy(conn, None)?.map(admin_view).unwrap_or(Value::Null),
            ))
        })
        .await
}

pub async fn save_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PolicyInput>,
) -> Result<Json<Value>> {
    state.admin(&headers)?;
    input.validate()?;
    state
        .db(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let previous = policy(&tx, None)?;
            let revision = previous.as_ref().map_or(1, |p| p.revision + 1);
            let destination_revision = previous
                .as_ref()
                .filter(|p| {
                    let old = &p.settings;
                    old.bucket == input.bucket
                        && old.region == input.region
                        && old.base_prefix == input.base_prefix
                        && old.role_arn == input.role_arn
                })
                .map_or(revision, |p| p.destination_revision);
            tx.execute(
                "INSERT INTO policies VALUES (?1,?2,?3)",
                (
                    revision,
                    destination_revision,
                    serde_json::to_string(&input)?,
                ),
            )?;
            audit(&tx, "policy_published", &revision.to_string())?;
            tx.commit()?;
            Ok(Json(admin_view(Policy {
                revision,
                destination_revision,
                settings: input,
            })))
        })
        .await
}

fn admin_view(p: Policy) -> Value {
    json!({"revision":p.revision,"destinationRevisionId":p.destination_revision,"settings":p.settings})
}

pub async fn device_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let token = state.device_token(&headers)?;
    state
        .db(move |conn| {
            let (device, _) = authenticate(conn, &token)?;
            let current = policy(conn, None)?
                .ok_or_else(|| ApiError::unavailable("The administrator has not configured S3."))?;
            Ok(Json(current.device_view(device)))
        })
        .await
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Purpose {
    Backup,
    Verify,
    Browse,
    Restore,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRequest {
    purpose: Purpose,
    run_id: Option<Uuid>,
}

pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SessionRequest>,
) -> Result<Json<Value>> {
    let token = state.device_token(&headers)?;
    let backup = matches!(input.purpose, Purpose::Backup);
    if backup != input.run_id.is_some() {
        return Err(ApiError::bad("Only backup sessions require a run ID."));
    }
    #[cfg(not(feature = "aws"))]
    {
        state
            .db(move |conn| authenticate(conn, &token).map(|_| ()))
            .await?;
        Err(ApiError::unavailable("AWS session issuance is disabled."))
    }
    #[cfg(feature = "aws")]
    {
        let (device, target) = state
            .db(move |conn| {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let (device, target) = authorized_target(&tx, &token, input)?;
                let timestamp = now();
                let updated = tx.execute(
                    "UPDATE devices SET last_session_at=?1 WHERE id=?2 AND
                (last_session_at IS NULL OR last_session_at <= ?3)",
                    (timestamp, device.to_string(), timestamp - 5),
                )?;
                if updated == 0 {
                    return Err(ApiError(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Wait five seconds before requesting another storage session.",
                    ));
                }
                tx.commit()?;
                Ok((device, target))
            })
            .await?;
        let sts = state
            .sts
            .as_ref()
            .ok_or_else(|| ApiError::unavailable("AWS session issuance is disabled."))?;
        let scope = session_policy(&target, device, input.purpose).to_string();
        if scope.len() > 2048 {
            return Err(ApiError::bad(
                "The S3 session policy exceeds the AWS size limit.",
            ));
        }
        let reply = sts.assume_role()
            .role_arn(&target.settings.role_arn)
            .role_session_name(format!("stow-{}", device.simple()))
            .duration_seconds(900)
            .set_external_id(state.external_id.clone())
            .policy(scope)
            .send().await.map_err(|_| ApiError::unavailable("AWS could not issue a scoped session. Check the configured role and trust policy."))?;
        let credentials = reply
            .credentials()
            .ok_or_else(|| ApiError::unavailable("AWS returned no session credentials."))?;
        let expires = credentials.expiration().secs();
        let prefix = target.prefix(device);
        let revision = target.destination_revision;
        let response = json!({"accessKeyId":credentials.access_key_id(),"secretAccessKey":credentials.secret_access_key(),
            "sessionToken":credentials.session_token(),"expiresAt":expires,"serverTime":now(),"destinationRevisionId":revision,
            "bucket":target.settings.bucket,"region":target.settings.region,"prefix":prefix});
        state.db(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (_, latest) = authorized_target(&tx,&token,input)?;
            if latest.revision != target.revision { return Err(ApiError(StatusCode::CONFLICT, "Policy changed during authorization. Request a new session.")); }
            if let Some(run) = input.run_id {
                tx.execute("UPDATE runs SET aws_expires_at=MAX(aws_expires_at,?1),last_lease_at=?2 WHERE device_id=?3 AND id=?4",
                    (expires,now(),device.to_string(),run.to_string()))?;
            }
            tx.commit()?;
            Ok(Json(response))
        }).await
    }
}

#[cfg(feature = "aws")]
fn authorized_target(
    conn: &Connection,
    token: &[u8; 32],
    input: SessionRequest,
) -> Result<(Uuid, Policy)> {
    let (device, device_state) = authenticate(conn, token)?;
    let revision = if let Some(run) = input.run_id {
        if device_state != "active" {
            return Err(ApiError::denied());
        }
        Some(crate::runs::active_revision(conn, device, run)?)
    } else {
        None
    };
    let target = policy(conn, revision)?
        .ok_or_else(|| ApiError::unavailable("The administrator has not configured S3."))?;
    Ok((device, target))
}

#[cfg(feature = "aws")]
fn session_policy(policy: &Policy, device: Uuid, purpose: Purpose) -> Value {
    let bucket = format!("arn:aws:s3:::{}", policy.settings.bucket);
    let prefix = policy.prefix(device);
    let subtree = format!("{prefix}*");
    let object = format!("{bucket}/{subtree}");
    let list_actions = match purpose {
        Purpose::Browse | Purpose::Restore => vec!["s3:ListBucket", "s3:ListBucketVersions"],
        Purpose::Backup | Purpose::Verify => vec!["s3:ListBucket"],
    };
    let object_actions = match purpose {
        Purpose::Backup => vec![
            "s3:PutObject",
            "s3:AbortMultipartUpload",
            "s3:ListMultipartUploadParts",
            "s3:GetObject",
        ],
        Purpose::Browse | Purpose::Restore => vec!["s3:GetObject", "s3:GetObjectVersion"],
        Purpose::Verify => vec![],
    };
    let mut statements = vec![
        json!({"Effect":"Allow","Action":list_actions,"Resource":bucket,
        "Condition":{"StringLike":{"s3:prefix":subtree}}}),
    ];
    if !object_actions.is_empty() {
        statements.push(json!({"Effect":"Allow","Action":object_actions,"Resource":object}));
    }
    let key = &policy.settings.rules.kms_key_arn;
    if !key.is_empty()
        && matches!(
            purpose,
            Purpose::Backup | Purpose::Restore | Purpose::Browse
        )
    {
        let actions = if matches!(purpose, Purpose::Backup) {
            vec!["kms:GenerateDataKey", "kms:Decrypt"]
        } else {
            vec!["kms:Decrypt"]
        };
        statements.push(json!({"Effect":"Allow","Action":actions,"Resource":key,
            "Condition":{"StringEquals":{"kms:ViaService":format!("s3.{}.amazonaws.com",policy.settings.region)},
            "StringLike":{"kms:EncryptionContext:aws:s3:arn":[object,bucket]}}}));
    }
    json!({"Version":"2012-10-17","Statement":statements})
}
