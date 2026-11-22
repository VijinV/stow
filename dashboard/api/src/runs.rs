use crate::model::{Snapshot, Trigger};
use crate::{devices::authenticate, now, policy, ApiError, AppState, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
#[cfg(feature = "aws")]
use rusqlite::Connection;
use rusqlite::{OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub const LEASE_SECONDS: i64 = 300;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunStart {
    run_id: Uuid,
    trigger: Trigger,
}

pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RunStart>,
) -> Result<Json<Value>> {
    let token = state.device_token(&headers)?;
    state.db(move |conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (device, status) = authenticate(&tx, &token)?;
        let timestamp = now();
        let id = input.run_id.to_string();
        let device_id = device.to_string();
        let record = tx.query_row(
            "SELECT revision,phase,block_reason,started_at,
                serial=(SELECT MAX(serial) FROM runs WHERE device_id=?1 AND block_reason IS NULL),
                (last_lease_at>?3 OR aws_expires_at>?4)
                FROM runs WHERE device_id=?1 AND id=?2",
            (&device_id, &id, timestamp-LEASE_SECONDS, timestamp),
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<bool>>(4)?.unwrap_or(false), row.get::<_, bool>(5)?)),
        ).optional()?;
        if let Some((rev, phase, reason, started_at, latest, leased)) = record {
            let previous = match rev { Some(rev) => policy(&tx, Some(rev))?, None => None };
            let decision = if reason.is_some() { "blocked" } else if latest && leased && is_running(&phase) && status == "active" { "accepted" } else { "closed" };
            return Ok(Json(json!({"runId":input.run_id,"decision":decision,"phase":phase,"reason":reason,"startedAt":started_at,
                "policy":previous.map(|p| p.device_view(device))})));
        }

        let current = policy(&tx, None)?;
        let reason = if status == "paused" { Some("device_paused") }
            else if current.is_none() { Some("policy_unavailable") }
            else { None };
        if reason.is_none() {
            let active = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE device_id=?1 AND phase IN ('starting','scanning','uploading')
                 AND serial=(SELECT MAX(serial) FROM runs WHERE device_id=?1 AND block_reason IS NULL)
                 AND (last_lease_at>?2 OR aws_expires_at>?3))",
                (&device_id,timestamp-LEASE_SECONDS,timestamp), |row| row.get::<_,bool>(0),
            )?;
            if active {
                return Err(ApiError(StatusCode::CONFLICT, "A backup is already in progress for this device."));
            }
        }
        let phase = if reason.is_some() { "blocked" } else { "starting" };
        tx.execute(
            "INSERT INTO runs(id,device_id,trigger,revision,phase,block_reason,started_at,last_lease_at,finished_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?7,?8)",
            (&id,&device_id,input.trigger.as_str(),current.as_ref().map(|p| p.revision),phase,reason,timestamp,reason.map(|_| timestamp)),
        )?;
        tx.execute("UPDATE devices SET last_seen=?1 WHERE id=?2", (timestamp, &device_id))?;
        tx.commit()?;
        Ok(Json(json!({"runId":input.run_id,"phase":phase,"decision":if reason.is_some() {"blocked"} else {"accepted"},
            "reason":reason,"startedAt":timestamp,"policy":current.map(|p| p.device_view(device))})))
    }).await
}

pub fn is_running(phase: &str) -> bool {
    matches!(phase, "starting" | "scanning" | "uploading")
}

pub async fn snapshot(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<Snapshot>,
) -> Result<Json<Value>> {
    let token = state.device_token(&headers)?;
    input.validate()?;
    state
        .db(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (device, _) = authenticate(&tx, &token)?;
            let device = device.to_string();
            let id = id.to_string();
            let timestamp = now();
            let (phase, sequence, latest, leased) = tx
                .query_row(
                    "SELECT phase,sequence,serial=(SELECT MAX(serial) FROM runs WHERE device_id=?1 AND block_reason IS NULL),
                    (last_lease_at>?3 OR aws_expires_at>?4) FROM runs WHERE device_id=?1 AND id=?2",
                    (&device, &id, timestamp-LEASE_SECONDS, timestamp),
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?, row.get::<_, Option<bool>>(2)?.unwrap_or(false), row.get::<_, bool>(3)?)),
                )
                .optional()?
                .ok_or_else(ApiError::missing)?;
            let terminal = input.phase.terminal();
            if !is_running(&phase) || input.sequence <= sequence || (!terminal && !(latest && leased)) {
                return Ok(Json(json!({"acceptedSequence":sequence})));
            }
            let live = (latest && leased && !input.replayed).then_some(timestamp);
            let finished_at = terminal.then_some(timestamp);
            tx.execute(
                "UPDATE runs SET phase=?1,sequence=?2,snapshot=?3,finished_at=?4,
            last_progress_at=COALESCE(?5,last_progress_at),last_lease_at=COALESCE(?5,last_lease_at)
            WHERE device_id=?6 AND id=?7",
                (
                    input.phase.as_str(),
                    input.sequence,
                    serde_json::to_string(&input)?,
                    finished_at,
                    live,
                    &device,
                    &id,
                ),
            )?;
            if let Some(live) = live {
                tx.execute(
                    "UPDATE devices SET last_seen=?1 WHERE id=?2",
                    (live, &device),
                )?;
            }
            tx.commit()?;
            Ok(Json(json!({"acceptedSequence":input.sequence})))
        })
        .await
}

pub async fn history(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    state.admin(&headers)?;
    state.db(move |conn| {
        let id = id.to_string();
        let exists = conn.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1)", [&id], |row| row.get::<_,bool>(0))?;
        if !exists { return Err(ApiError::missing()); }
        let mut statement = conn.prepare(
            "SELECT id,trigger,revision,started_at,finished_at,phase,block_reason,sequence,snapshot
             FROM runs WHERE device_id=?1 ORDER BY serial DESC LIMIT 100",
        )?;
        let rows = statement.query_map([&id], |row| {
            Ok((json!({"runId":row.get::<_,String>(0)?,"trigger":row.get::<_,String>(1)?,"revision":row.get::<_,Option<i64>>(2)?,
                "startedAt":row.get::<_,i64>(3)?,"finishedAt":row.get::<_,Option<i64>>(4)?,"phase":row.get::<_,String>(5)?,
                "reason":row.get::<_,Option<String>>(6)?,"sequence":row.get::<_,u32>(7)?}),row.get::<_,Option<String>>(8)?))
        })?;
        let mut history = Vec::new();
        for row in rows {
            let (mut item, snapshot) = row?;
            if let Some(snapshot) = snapshot {
                let mut snapshot = serde_json::from_str::<Value>(&snapshot)?;
                for key in ["filesUploaded","filesFailed","filesSkipped","bytesDone","errorCode"] {
                    item[key] = snapshot[key].take();
                }
            }
            history.push(item);
        }
        Ok(Json(json!(history)))
    }).await
}

#[cfg(feature = "aws")]
pub fn active_revision(conn: &Connection, device: Uuid, run: Uuid) -> Result<i64> {
    conn.query_row(
        "SELECT revision FROM runs r WHERE device_id=?1 AND id=?2 AND phase IN ('starting','scanning','uploading')
         AND (last_lease_at>?3 OR aws_expires_at>?4) AND NOT EXISTS (SELECT 1 FROM runs newer WHERE newer.device_id=r.device_id
             AND newer.serial>r.serial AND newer.block_reason IS NULL)",
        (device.to_string(), run.to_string(), now()-LEASE_SECONDS, now()),
        |row| row.get(0),
    ).optional()?.ok_or_else(ApiError::denied)
}
