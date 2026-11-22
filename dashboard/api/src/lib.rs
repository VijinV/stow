mod devices;
mod model;
mod runs;
mod storage;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post, put},
    Json, Router,
};
use model::Policy;
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct AppState {
    database: Arc<Mutex<Connection>>,
    administrator: [u8; 32],
    #[cfg(feature = "aws")]
    sts: Option<aws_sdk_sts::Client>,
    #[cfg(feature = "aws")]
    external_id: Option<String>,
}

#[derive(Debug)]
struct ApiError(StatusCode, &'static str);
type Result<T> = std::result::Result<T, ApiError>;

impl ApiError {
    fn bad(message: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, message)
    }
    fn denied() -> Self {
        Self(StatusCode::FORBIDDEN, "Access denied.")
    }
    fn missing() -> Self {
        Self(StatusCode::NOT_FOUND, "Record not found.")
    }
    fn unavailable(message: &'static str) -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, message)
    }
    fn internal() -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Dashboard storage error.",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.0, Json(json!({"error":self.1}))).into_response();
        if self.0 == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        }
        response
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        Self::internal()
    }
}
impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self::internal()
    }
}

impl AppState {
    pub fn open(
        path: impl AsRef<Path>,
        administrator: &str,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        if administrator.len() < 32 || !administrator.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(
                "STOW_ADMIN_TOKEN must contain at least 32 visible ASCII characters".into(),
            );
        }
        let database = Connection::open(path)?;
        database.busy_timeout(Duration::from_secs(5))?;
        database.execute_batch(include_str!("schema.sql"))?;
        Ok(Self {
            database: Arc::new(Mutex::new(database)),
            administrator: digest(administrator),
            #[cfg(feature = "aws")]
            sts: None,
            #[cfg(feature = "aws")]
            external_id: None,
        })
    }

    #[cfg(feature = "aws")]
    pub fn with_aws(mut self, sts: aws_sdk_sts::Client, external_id: Option<String>) -> Self {
        self.sts = Some(sts);
        self.external_id = external_id;
        self
    }

    async fn db<T: Send + 'static>(
        &self,
        action: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let database = self.database.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = database.lock().map_err(|_| ApiError::internal())?;
            action(&mut connection)
        })
        .await
        .map_err(|_| ApiError::internal())?
    }

    fn admin(&self, headers: &HeaderMap) -> Result<()> {
        if bool::from(self.administrator.ct_eq(&digest(bearer(headers)?))) {
            Ok(())
        } else {
            Err(unauthorized())
        }
    }

    fn device_token(&self, headers: &HeaderMap) -> Result<[u8; 32]> {
        let token = digest(bearer(headers)?);
        if bool::from(self.administrator.ct_eq(&token)) {
            return Err(unauthorized());
        }
        Ok(token)
    }
}

pub fn app(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/admin/enrollments", post(devices::enroll))
        .route("/admin/devices", get(devices::list))
        .route("/admin/devices/{id}", patch(devices::set_state))
        .route("/admin/devices/{id}/runs", get(runs::history))
        .route(
            "/admin/policy",
            get(storage::admin_policy).put(storage::save_policy),
        )
        .route("/enrollment/redeem", post(devices::redeem))
        .route("/device/check-in", post(devices::check_in))
        .route("/device/policy", get(storage::device_policy))
        .route("/device/runs", post(runs::start))
        .route("/device/runs/{id}/snapshot", put(runs::snapshot))
        .route("/device/storage-sessions", post(storage::session))
        .fallback(|| async { ApiError::missing() })
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(middleware::from_fn(no_cache))
        .with_state(state);
    Router::new().nest("/api/v1", api)
}

async fn no_cache(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn unauthorized() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "A valid access token is required.",
    )
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| {
            (32..=256).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or_else(unauthorized)
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn policy(connection: &Connection, revision: Option<i64>) -> Result<Option<Policy>> {
    let data = connection.query_row(
        "SELECT revision, destination_revision, settings FROM policies WHERE (?1 IS NULL OR revision=?1) ORDER BY revision DESC LIMIT 1",
        [revision],
        |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, String>(2)?)),
    ).optional()?;
    data.map(|(revision, destination_revision, settings)| {
        Ok(Policy {
            revision,
            destination_revision,
            settings: serde_json::from_str(&settings)?,
        })
    })
    .transpose()
}

fn audit(connection: &Connection, action: &str, subject: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO audit_events(action, subject, occurred_at) VALUES (?1,?2,?3)",
        (action, subject, now()),
    )?;
    Ok(())
}
