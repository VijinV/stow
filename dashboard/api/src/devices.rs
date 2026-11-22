use crate::model::DeviceState;
use crate::{audit, digest, now, policy, unauthorized, ApiError, AppState, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Enrollment {
    display_name: String,
}

pub async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Enrollment>,
) -> Result<(StatusCode, Json<Value>)> {
    state.admin(&headers)?;
    let name = input.display_name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
        return Err(ApiError::bad("Enter a device name of up to 80 characters."));
    }
    let code = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let id = Uuid::new_v4();
    let expires = now() + 600;
    state
        .db(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO devices(id,name,state,created_at) VALUES(?1,?2,'pending',?3)",
                (id.to_string(), &name, now()),
            )?;
            tx.execute(
                "INSERT INTO enrollments VALUES(?1,?2,?3)",
                (digest(&code).as_slice(), id.to_string(), expires),
            )?;
            audit(&tx, "enrollment_created", &id.to_string())?;
            tx.commit()?;
            Ok((
                StatusCode::CREATED,
                Json(json!({"deviceId":id,"pairingCode":code,"expiresAt":expires})),
            ))
        })
        .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Redeem {
    pairing_code: String,
    device_token: String,
}

pub async fn redeem(
    State(state): State<AppState>,
    Json(input): Json<Redeem>,
) -> Result<Json<Value>> {
    if input.pairing_code.len() != 64
        || !input
            .pairing_code
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !(32..=256).contains(&input.device_token.len())
        || !input
            .device_token
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(ApiError::denied());
    }
    let code = digest(&input.pairing_code);
    let token = digest(&input.device_token);
    if token == state.administrator {
        return Err(ApiError::denied());
    }
    state.db(move |conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (id, name, state, digest) = tx.query_row(
            "SELECT d.id,d.name,d.state,d.token_hash FROM enrollments e JOIN devices d ON d.id=e.device_id WHERE e.code_hash=?1 AND e.expires_at>?2",
            (code.as_slice(), now()), |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<Vec<u8>>>(3)?)),
        ).optional()?.ok_or_else(ApiError::denied)?;
        if state == "revoked" { return Err(ApiError::denied()); }
        if let Some(previous) = digest {
            if previous != token { return Err(ApiError::denied()); }
        } else {
            let reused = tx.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE token_hash=?1)", [token.as_slice()], |row| row.get::<_, bool>(0))?;
            if reused { return Err(ApiError::denied()); }
            tx.execute("UPDATE devices SET state='active', token_hash=?1, last_seen=?2 WHERE id=?3", (token.as_slice(), now(), &id))?;
            audit(&tx, "enrollment_redeemed", &id)?;
        }
        tx.commit()?;
        Ok(Json(json!({"deviceId":id,"displayName":name})))
    }).await
}

pub fn authenticate(conn: &Connection, token: &[u8; 32]) -> Result<(Uuid, String)> {
    let (device, status) = conn
        .query_row(
            "SELECT id,state FROM devices WHERE token_hash=?1",
            [token.as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(unauthorized)?;
    if status == "revoked" {
        return Err(ApiError::denied());
    }
    Ok((
        Uuid::parse_str(&device).map_err(|_| ApiError::internal())?,
        status,
    ))
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>> {
    state.admin(&headers)?;
    state.db(|conn| {
        let mut query = conn.prepare(
            "SELECT d.id,d.name,d.state,d.last_seen,d.applied_revision,d.platform,d.app_version,d.next_due_at,d.schedule_enabled,
            r.phase,r.last_progress_at,r.started_at,
            (SELECT finished_at FROM runs WHERE device_id=d.id AND phase='finished' ORDER BY serial DESC LIMIT 1)
            FROM devices d LEFT JOIN runs r ON r.serial=(SELECT serial FROM runs WHERE device_id=d.id ORDER BY serial DESC LIMIT 1)
            ORDER BY lower(d.name),d.id"
        )?;
        let rows = query.query_map([], |row| {
            let phase: Option<String> = row.get(9)?;
            let live: Option<i64> = row.get(10)?;
            let started: Option<i64> = row.get(11)?;
            let delayed = matches!(phase.as_deref(), Some("scanning" | "uploading" | "starting"))
                && live.or(started).is_some_and(|stamp| now() - stamp > 120);
            Ok(json!({"deviceId":row.get::<_,String>(0)?,"displayName":row.get::<_,String>(1)?,"state":row.get::<_,String>(2)?,
                "lastSeenAt":row.get::<_,Option<i64>>(3)?,"appliedRevision":row.get::<_,Option<i64>>(4)?,
                "platform":row.get::<_,Option<String>>(5)?,"appVersion":row.get::<_,Option<String>>(6)?,
                "nextDueAt":row.get::<_,Option<i64>>(7)?,"scheduleEnabled":row.get::<_,Option<bool>>(8)?,
                "lastRunPhase":phase,"updatesDelayed":delayed,"lastSuccessAt":row.get::<_,Option<i64>>(12)?}))
        })?;
        Ok(Json(json!(rows.collect::<rusqlite::Result<Vec<_>>>()?)))
    }).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateChange {
    state: DeviceState,
}

pub async fn set_state(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<StateChange>,
) -> Result<Json<Value>> {
    state.admin(&headers)?;
    if input.state == DeviceState::Pending {
        return Err(ApiError::bad("Invalid device state."));
    }
    state
        .db(move |conn| {
            let id = id.to_string();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let previous = tx
                .query_row("SELECT state FROM devices WHERE id=?1", [&id], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .ok_or_else(ApiError::missing)?;
            if (previous == "revoked" || previous == "pending")
                && input.state != DeviceState::Revoked
            {
                return Err(ApiError(
                    StatusCode::CONFLICT,
                    "Only a paired device can be paused or resumed.",
                ));
            }
            tx.execute(
                "UPDATE devices SET state=?1 WHERE id=?2",
                (input.state.as_str(), &id),
            )?;
            if previous != input.state.as_str() {
                audit(&tx, "device_state_changed", &id)?;
            }
            tx.commit()?;
            Ok(Json(json!({"state":input.state})))
        })
        .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckIn {
    app_version: String,
    platform: String,
    applied_revision: Option<i64>,
    schedule_enabled: bool,
    next_due_at: Option<i64>,
}

pub async fn check_in(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CheckIn>,
) -> Result<Json<Value>> {
    let token = state.device_token(&headers)?;
    if [&input.app_version, &input.platform]
        .iter()
        .any(|s| s.is_empty() || s.len() > 48 || s.chars().any(char::is_control))
        || input
            .next_due_at
            .is_some_and(|date| !input.schedule_enabled || !(0..=253402300799).contains(&date))
        || input.applied_revision.is_some_and(|revision| revision < 1)
    {
        return Err(ApiError::bad("Invalid device check-in."));
    }
    state.db(move |conn| {
        let (id, status) = authenticate(conn, &token)?;
        let current = policy(conn,None)?.map(|p| p.revision);
        if input.applied_revision > current { return Err(ApiError::bad("Unknown policy revision.")); }
        conn.execute("UPDATE devices SET last_seen=?1,applied_revision=?2,app_version=?3,platform=?4,schedule_enabled=?5,next_due_at=?6 WHERE id=?7",
            (now(),input.applied_revision,input.app_version,input.platform,input.schedule_enabled,input.next_due_at,id.to_string()))?;
        Ok(Json(json!({"state":status,"revision":current})))
    }).await
}
