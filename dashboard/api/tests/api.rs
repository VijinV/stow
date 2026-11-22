use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use serde_json::{json, Value};
use stow_dashboard::{app, AppState};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN: &str = "test-admin-key-long-enough-0000000000";
const TOKEN: &str = "test-device-key-long-enough-11111111";
const OTHER: &str = "test-device-key-long-enough-22222222";
const ROOT: &str = "/api/v1";

async fn call(router: &Router, method: &str, path: &str, token: &str, body: Value) -> (u16, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("{ROOT}{path}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let code = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (code, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn pair(router: &Router, name: &str, token: &str) -> (String, String) {
    let (status, enrollment) = call(
        router,
        "POST",
        "/admin/enrollments",
        ADMIN,
        json!({"displayName":name}),
    )
    .await;
    assert_eq!(status, 201);
    let code = enrollment["pairingCode"].as_str().unwrap();
    let (status, device) = call(
        router,
        "POST",
        "/enrollment/redeem",
        "",
        json!({"pairingCode":code,"deviceToken":token}),
    )
    .await;
    assert_eq!(status, 200);
    (
        device["deviceId"].as_str().unwrap().to_owned(),
        code.to_owned(),
    )
}

fn policy(bucket: &str, excludes: Vec<&str>) -> Value {
    json!({"bucket":bucket,"region":"us-east-1","basePrefix":"backups","roleArn":"arn:aws:iam::123456789012:role/StowBackup","rules":{"excludes":excludes,"skipHidden":true,"skipDevArtifacts":true,"requireClientEncryption":false,"maxParallelUploads":4,"storageClass":"STANDARD","serverEncryption":"AES256"}})
}

#[tokio::test]
async fn pairing_retries_only_for_same_token_and_scopes_devices_by_id() {
    let router = app(AppState::open(":memory:", ADMIN).unwrap());
    assert_eq!(
        call(
            &router,
            "PUT",
            "/admin/policy",
            ADMIN,
            policy("stow-backups", vec![])
        )
        .await
        .0,
        200
    );
    let (id, code) = pair(&router, "Work laptop", TOKEN).await;
    let (_, replay) = call(
        &router,
        "POST",
        "/enrollment/redeem",
        "",
        json!({"pairingCode":code,"deviceToken":TOKEN}),
    )
    .await;
    assert_eq!(replay["deviceId"], id);
    assert_eq!(
        call(
            &router,
            "POST",
            "/enrollment/redeem",
            "",
            json!({"pairingCode":code,"deviceToken":OTHER})
        )
        .await
        .0,
        403
    );
    let (other, _) = pair(&router, "Work laptop", OTHER).await;
    assert_ne!(id, other);
    assert_eq!(
        call(&router, "GET", "/admin/devices", TOKEN, Value::Null)
            .await
            .0,
        401
    );
    let (_, config) = call(&router, "GET", "/device/policy", TOKEN, Value::Null).await;
    assert_eq!(config["prefix"], format!("backups/devices/{id}/"));
    assert!(config.get("roleArn").is_none());
}

#[tokio::test]
async fn runs_pin_policy_and_terminal_snapshots_survive_replays() {
    let router = app(AppState::open(":memory:", ADMIN).unwrap());
    call(
        &router,
        "PUT",
        "/admin/policy",
        ADMIN,
        policy("stow-backups", vec!["*.tmp"]),
    )
    .await;
    let (id, _) = pair(&router, "Laptop", TOKEN).await;
    pair(&router, "Desktop", OTHER).await;
    let run = Uuid::new_v4();
    let payload = json!({"runId":run,"trigger":"scheduled"});
    let (status, started) = call(&router, "POST", "/device/runs", TOKEN, payload.clone()).await;
    assert_eq!(status, 200);
    call(
        &router,
        "PUT",
        "/admin/policy",
        ADMIN,
        policy("stow-next", vec![]),
    )
    .await;
    let (_, replay) = call(&router, "POST", "/device/runs", TOKEN, payload).await;
    assert_eq!(started["policy"], replay["policy"]);
    let path = format!("/device/runs/{run}/snapshot");
    let snapshot = json!({"sequence":2,"phase":"finished","filesUploaded":"2","filesFailed":"0","filesSkipped":"0","bytesDone":"9007199254740993"});
    assert_eq!(
        call(&router, "PUT", &path, OTHER, snapshot.clone()).await.0,
        404
    );
    assert_eq!(
        call(&router, "PUT", &path, TOKEN, snapshot.clone()).await.0,
        200
    );
    assert_eq!(call(&router, "PUT", &path, TOKEN, snapshot).await.0, 200);
    let (_, stale) = call(&router,"PUT",&path,TOKEN,json!({"sequence":1,"phase":"uploading","filesUploaded":"0","filesFailed":"0","filesSkipped":"0","bytesDone":"0"})).await;
    assert_eq!(stale["acceptedSequence"], 2);
    let (_, history) = call(
        &router,
        "GET",
        &format!("/admin/devices/{id}/runs"),
        ADMIN,
        Value::Null,
    )
    .await;
    assert_eq!(history[0]["phase"], "finished");
    assert_eq!(history[0]["bytesDone"], "9007199254740993");
}

#[tokio::test]
async fn pause_blocks_backups_and_revocation_blocks_device_authentication() {
    let router = app(AppState::open(":memory:", ADMIN).unwrap());
    call(
        &router,
        "PUT",
        "/admin/policy",
        ADMIN,
        policy("stow-backups", vec![]),
    )
    .await;
    let (id, _) = pair(&router, "Laptop", TOKEN).await;
    let path = format!("/admin/devices/{id}");
    assert_eq!(
        call(&router, "PATCH", &path, ADMIN, json!({"state":"paused"}))
            .await
            .0,
        200
    );
    let (_, run) = call(
        &router,
        "POST",
        "/device/runs",
        TOKEN,
        json!({"runId":Uuid::new_v4(),"trigger":"manual"}),
    )
    .await;
    assert_eq!(run["decision"], "blocked");
    assert_eq!(
        call(&router, "PATCH", &path, ADMIN, json!({"state":"revoked"}))
            .await
            .0,
        200
    );
    assert_eq!(
        call(&router, "GET", "/device/policy", TOKEN, Value::Null)
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn rejects_upload_bodies_and_unsafe_prefixes() {
    let router = app(AppState::open(":memory:", ADMIN).unwrap());
    let mut unsafe_policy = policy("stow-backups", vec![]);
    unsafe_policy["basePrefix"] = json!("backups/*");
    assert_eq!(
        call(&router, "PUT", "/admin/policy", ADMIN, unsafe_policy)
            .await
            .0,
        400
    );
    let oversized = json!({"displayName": "a".repeat(33 * 1024)});
    assert_eq!(
        call(&router, "POST", "/admin/enrollments", ADMIN, oversized)
            .await
            .0,
        413
    );
    let unknown = json!({"displayName":"Laptop","fileContents":"unused"});
    assert_eq!(
        call(&router, "POST", "/admin/enrollments", ADMIN, unknown)
            .await
            .0,
        422
    );
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn sts_receives_device_scoped_policy_and_returns_credentials_to_owning_run() {
    use axum::{
        extract::{Form, State},
        http::header::CONTENT_TYPE,
        routing::post,
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    let form_capture = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let mock = Router::new().route("/", post(
        |State(capture): State<Arc<Mutex<HashMap<String, String>>>>, Form(data): Form<HashMap<String, String>>| async move {
            *capture.lock().unwrap() = data;
            ([(CONTENT_TYPE, "text/xml")], "<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult><Credentials><AccessKeyId>example-access</AccessKeyId><SecretAccessKey>example-secret</SecretAccessKey><SessionToken>example-session</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult><ResponseMetadata><RequestId>test</RequestId></ResponseMetadata></AssumeRoleResponse>")
        },
    )).with_state(form_capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let config = aws_sdk_sts::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_sts::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_sts::config::Credentials::new(
            "example", "example", None, None, "test",
        ))
        .endpoint_url(endpoint)
        .build();
    let sts = aws_sdk_sts::Client::from_conf(config);
    let router = app(AppState::open(":memory:", ADMIN)
        .unwrap()
        .with_aws(sts, Some("test-trust".into())));
    assert_eq!(
        call(
            &router,
            "PUT",
            "/admin/policy",
            ADMIN,
            policy("stow-backups", vec![])
        )
        .await
        .0,
        200
    );
    let (id, _) = pair(&router, "Laptop", TOKEN).await;
    pair(&router, "Second laptop", OTHER).await;
    let run = Uuid::new_v4();
    assert_eq!(
        call(
            &router,
            "POST",
            "/device/runs",
            TOKEN,
            json!({"runId":run,"trigger":"manual"})
        )
        .await
        .0,
        200
    );
    let input = json!({"purpose":"backup","runId":run});
    assert_eq!(
        call(
            &router,
            "POST",
            "/device/storage-sessions",
            OTHER,
            input.clone()
        )
        .await
        .0,
        403
    );
    assert!(form_capture.lock().unwrap().is_empty());
    let (status, session) = call(
        &router,
        "POST",
        "/device/storage-sessions",
        TOKEN,
        input.clone(),
    )
    .await;
    assert_eq!(status, 200, "{session}");
    assert_eq!(session["sessionToken"], "example-session");
    assert_eq!(session["prefix"], format!("backups/devices/{id}/"));
    {
        let form = form_capture.lock().unwrap();
        assert_eq!(form["Action"], "AssumeRole");
        assert_eq!(form["DurationSeconds"], "900");
        assert_eq!(form["ExternalId"], "test-trust");
        let policy: Value = serde_json::from_str(&form["Policy"]).unwrap();
        let statements = &policy["Statement"];
        let prefix = format!("backups/devices/{id}/*");
        assert_eq!(
            statements[0]["Condition"]["StringLike"]["s3:prefix"],
            prefix
        );
        assert_eq!(
            statements[1]["Resource"],
            format!("arn:aws:s3:::stow-backups/{prefix}")
        );
        assert!(!form["Policy"].contains("s3:DeleteObject"));
    }
    assert_eq!(
        call(
            &router,
            "PATCH",
            &format!("/admin/devices/{id}"),
            ADMIN,
            json!({"state":"paused"})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(&router, "POST", "/device/storage-sessions", TOKEN, input)
            .await
            .0,
        403
    );
    server.abort();
}

#[tokio::test]
async fn paired_device_and_policy_survive_a_server_restart() {
    let directory = std::env::temp_dir().join(format!("stow-dashboard-test-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let db = directory.join("stow.sqlite3");
    let router = app(AppState::open(&db, ADMIN).unwrap());
    call(
        &router,
        "PUT",
        "/admin/policy",
        ADMIN,
        policy("stow-backups", vec!["*.tmp"]),
    )
    .await;
    let (id, _) = pair(&router, "Work laptop", TOKEN).await;
    drop(router);
    let reopened = app(AppState::open(&db, ADMIN).unwrap());
    let (status, config) = call(&reopened, "GET", "/device/policy", TOKEN, Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(config["prefix"], format!("backups/devices/{id}/"));
    assert_eq!(config["rules"]["excludes"], json!(["*.tmp"]));
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn destination_cannot_nest_inside_any_device_namespace() {
    let router = app(AppState::open(":memory:", ADMIN).unwrap());
    assert_eq!(
        call(
            &router,
            "PUT",
            "/admin/policy",
            ADMIN,
            policy("stow-backups", vec![])
        )
        .await
        .0,
        200
    );
    let (id, _) = pair(&router, "Laptop", TOKEN).await;
    let mut nested = policy("stow-backups", vec![]);
    nested["basePrefix"] = json!(format!("backups/devices/{id}/archive"));
    assert_eq!(
        call(&router, "PUT", "/admin/policy", ADMIN, nested).await.0,
        400
    );
}

#[tokio::test]
async fn bucket_default_accepts_a_scoped_kms_key() {
    let router = app(AppState::open(":memory:", ADMIN).unwrap());
    let mut config = policy("stow-backups", vec![]);
    config["rules"]["serverEncryption"] = json!("");
    config["rules"]["kmsKeyArn"] =
        json!("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012");
    assert_eq!(
        call(&router, "PUT", "/admin/policy", ADMIN, config).await.0,
        200
    );
}

#[tokio::test]
async fn expired_runs_cannot_renew_via_progress_but_can_report_completion() {
    let directory = std::env::temp_dir().join(format!("stow-dashboard-test-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let db = directory.join("stow.sqlite3");
    let router = app(AppState::open(&db, ADMIN).unwrap());
    call(
        &router,
        "PUT",
        "/admin/policy",
        ADMIN,
        policy("stow-backups", vec![]),
    )
    .await;
    pair(&router, "Laptop", TOKEN).await;
    let id = Uuid::new_v4();
    let start = json!({"runId":id,"trigger":"scheduled"});
    assert_eq!(
        call(&router, "POST", "/device/runs", TOKEN, start.clone())
            .await
            .0,
        200
    );
    {
        let db = rusqlite::Connection::open(&db).unwrap();
        db.execute(
            "UPDATE runs SET last_lease_at=0,aws_expires_at=0 WHERE id=?1",
            [id.to_string()],
        )
        .unwrap();
    }
    let (_, replay) = call(&router, "POST", "/device/runs", TOKEN, start).await;
    assert_eq!(replay["decision"], "closed");
    let mut snapshot = json!({"sequence":1,"phase":"uploading","filesUploaded":"0","filesFailed":"0","filesSkipped":"0","bytesDone":"0"});
    let path = format!("/device/runs/{id}/snapshot");
    let (_, ignored) = call(&router, "PUT", &path, TOKEN, snapshot.clone()).await;
    assert_eq!(ignored["acceptedSequence"], 0);
    assert_eq!(
        call(
            &router,
            "POST",
            "/device/runs",
            TOKEN,
            json!({"runId":Uuid::new_v4(),"trigger":"scheduled"})
        )
        .await
        .0,
        200
    );
    snapshot["phase"] = json!("finished");
    let (_, accepted) = call(&router, "PUT", &path, TOKEN, snapshot).await;
    assert_eq!(accepted["acceptedSequence"], 1);
    drop(router);
    std::fs::remove_dir_all(directory).unwrap();
}
