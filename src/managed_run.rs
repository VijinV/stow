use super::{
    integer, object, random_id, read, state_dir, store, valid_uuid, Api, Policy, Profile, Sessions,
};
use crate::{
    config::Config,
    dashboard_api::Error,
    engine::{self, Phase, Progress, RunLock, Shared},
    json::Json,
    remote,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, mpsc, Arc},
    time::Duration,
};

fn outbox(profile: &Profile) -> PathBuf {
    state_dir().join("runs").join(profile.identity())
}

fn start_body(id: &str, trigger: &str) -> Json {
    object(&[("runId", Json::from(id)), ("trigger", Json::from(trigger))])
}

fn snapshot(sequence: u32, progress: &Progress, code: Option<&str>, replayed: bool) -> Json {
    let mut value = object(&[
        ("sequence", Json::from(sequence)),
        ("phase", Json::from(progress.phase.as_str())),
        (
            "filesUploaded",
            Json::from(progress.files_uploaded.to_string()),
        ),
        ("filesFailed", Json::from(progress.files_failed.to_string())),
        (
            "filesSkipped",
            Json::from(progress.files_skipped.to_string()),
        ),
        ("bytesDone", Json::from(progress.bytes_done.to_string())),
        ("replayed", Json::from(replayed)),
    ]);
    if let Some(code) = code {
        value.set("errorCode", code);
    }
    value
}

fn update(profile: &Profile, api: &Api, run: &str, data: &Json) -> Result<(), Error> {
    let reply = profile.request(
        api,
        "PUT",
        &format!("/device/runs/{run}/snapshot"),
        Some(data),
    )?;
    if integer(&reply, "acceptedSequence").map_err(Error::local)?
        >= integer(data, "sequence").map_err(Error::local)?
    {
        Ok(())
    } else {
        Err(Error::local(
            "The dashboard did not acknowledge the run status.",
        ))
    }
}

fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn stored_paths(profile: &Profile) -> Result<Vec<PathBuf>, String> {
    let mut entries = match fs::read_dir(outbox(profile)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    }
    .filter_map(Result::ok)
    .map(|entry| entry.path())
    .filter(|path| {
        path.extension().is_some_and(|ext| ext == "json")
            && path
                .file_stem()
                .and_then(|name| name.to_str())
                .is_some_and(valid_uuid)
    })
    .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

/// Retry finished reports from check-in without touching run-start receipts
/// that might belong to an active GUI or scheduled process.
pub(super) fn flush_pending(profile: &Profile, api: &Api) -> Result<(), String> {
    let mut error = None;
    for path in stored_paths(profile)?.into_iter().take(32) {
        let Some(record) = read(&path)? else {
            continue;
        };
        let Some(terminal) = record.get("terminal") else {
            continue;
        };
        let run = path.file_stem().and_then(|run| run.to_str()).unwrap();
        let mut terminal = terminal.clone();
        terminal.set("replayed", true);
        match update(profile, api, run, &terminal)
            .map_err(|e| e.message)
            .and_then(|_| remove(&path))
        {
            Ok(()) => {}
            Err(message) => {
                error = Some(message);
                break;
            }
        }
    }
    error.map_or(Ok(()), Err)
}

fn recover_start_receipts(profile: &Profile, api: &Api) -> Result<(), String> {
    for path in stored_paths(profile)? {
        let Some(record) = read(&path)? else {
            continue;
        };
        if record.get("terminal").is_some() {
            continue;
        }
        let id = path.file_stem().and_then(|run| run.to_str()).unwrap();
        let trigger = record.str_or("trigger", "manual");
        let response =
            match profile.request(api, "POST", "/device/runs", Some(&start_body(id, &trigger))) {
                Ok(response) => response,
                // An abandoned request that never started does not need a row.
                Err(error) if error.status == 409 => {
                    remove(&path)?;
                    continue;
                }
                Err(error) => return Err(error.message),
            };
        if matches!(
            response.str_or("phase", "").as_str(),
            "starting" | "scanning" | "uploading"
        ) {
            let stopped = Progress {
                phase: Phase::Cancelled,
                ..Progress::default()
            };
            let terminal = snapshot(u32::MAX, &stopped, None, true);
            store(&path, &object(&[("terminal", terminal.clone())]))?;
            update(profile, api, id, &terminal).map_err(|e| e.message)?;
        }
        remove(&path)?;
    }
    Ok(())
}

pub(crate) fn backup(cfg: &Config, shared: Arc<Shared>, trigger: &str, full: bool) -> Progress {
    backup_with_client(cfg, shared, trigger, full, |cfg, provider| {
        remote::scoped_client(&cfg.s3, provider)
    })
}

fn backup_with_client(
    cfg: &Config,
    shared: Arc<Shared>,
    trigger: &str,
    full: bool,
    connect: impl FnOnce(&Config, Arc<dyn bt_s3::CredentialProvider>) -> Result<bt_s3::S3Client, String>,
) -> Progress {
    let fail = |message| {
        shared.start(trigger);
        let result = shared.finish(Phase::Failed, message);
        engine::log_line(&format!(
            "backup {}: {}",
            result.phase.as_str(),
            result.message
        ));
        result
    };
    let lock = match RunLock::acquire() {
        Ok(lock) => lock,
        Err(error) => return fail(error),
    };
    let profile = match Profile::load() {
        Ok(profile) => profile.filter(|p| p.active),
        Err(error) => return fail(error),
    };
    let Some(profile) = profile else {
        let storage = match remote::S3Storage::new(cfg) {
            Ok(storage) => Arc::new(storage),
            Err(error) => return fail(error),
        };
        return engine::run_backup_locked(cfg, storage, shared.clone(), trigger, full, &lock);
    };
    let fail = |message| {
        let result = fail(message);
        engine::append_history(&result);
        result
    };
    let api = match profile.api() {
        Ok(api) => api,
        Err(error) => return fail(error.message),
    };
    if trigger == "scheduled" {
        if let Err(error) = profile.check_in(&api, cfg, None) {
            if error.authorization_failed() {
                return fail(error.message);
            }
        }
    }
    let _ = flush_pending(&profile, &api);
    if let Err(error) = recover_start_receipts(&profile, &api) {
        return fail(error);
    }
    let remote_trigger = if trigger == "scheduled" {
        "scheduled"
    } else {
        "manual"
    };
    let run = match random_id() {
        Ok(run) => run,
        Err(error) => return fail(error),
    };
    let receipt = outbox(&profile).join(format!("{run}.json"));
    if let Err(error) = store(
        &receipt,
        &object(&[("trigger", Json::from(remote_trigger))]),
    ) {
        return fail(format!("Could not save managed run state: {error}"));
    }
    let start = start_body(&run, remote_trigger);
    let started = match profile.request(&api, "POST", "/device/runs", Some(&start)) {
        Ok(started) => started,
        Err(error) => {
            if error.status != 0 && error.status < 500 {
                let _ = remove(&receipt);
            }
            return fail(error.message);
        }
    };
    if started.str_or("decision", "") != "accepted" {
        let _ = remove(&receipt);
        return fail(match started.str_or("reason", "").as_str() {
            "device_paused" => "Backups are paused on the dashboard.".into(),
            "policy_unavailable" => {
                "Configure the S3 destination in the dashboard before backing up.".into()
            }
            _ => "The dashboard did not accept the backup.".into(),
        });
    }

    let mut reason = None;
    let result = match prepare(cfg, &profile, &started, &run, connect) {
        Ok(prepared) => match profile.check_in(&api, cfg, Some(prepared.revision)) {
            Ok(true) => {
                reason = Some("storage_access_denied");
                fail("Backups are paused on the dashboard.".into())
            }
            Err(error) if error.authorization_failed() => {
                reason = Some("storage_access_denied");
                fail(error.message)
            }
            _ => execute(
                cfg,
                &profile,
                &run,
                prepared,
                shared.clone(),
                trigger,
                full,
                &lock,
            ),
        },
        Err((message, code)) => {
            reason = Some(code);
            fail(message)
        }
    };
    if reason.is_none() && matches!(result.phase, Phase::Failed | Phase::FinishedWithErrors) {
        reason = Some(
            if result
                .errors
                .iter()
                .any(|msg| msg.contains("DashboardAccess") || msg.contains("AccessDenied"))
            {
                "storage_access_denied"
            } else {
                "unknown"
            },
        );
    }
    let terminal = snapshot(u32::MAX, &result, reason, false);
    let reported = store(&receipt, &object(&[("terminal", terminal.clone())]));
    let (message, reported) = match reported {
        Ok(()) => (
            "Dashboard status will be retried.",
            update(&profile, &api, &run, &terminal)
                .map_err(|e| e.message)
                .and_then(|_| remove(&receipt)),
        ),
        Err(error) => ("Could not save dashboard status for retry.", Err(error)),
    };
    if reported.is_err() {
        let mut progress = shared.progress.lock().unwrap();
        progress.message.push(' ');
        progress.message.push_str(message);
        return progress.clone();
    }
    result
}

struct Prepared {
    effective: Config,
    revision: u64,
    storage: remote::S3Storage,
    sessions: Arc<Sessions>,
}

fn execute(
    local: &Config,
    profile: &Profile,
    run: &str,
    prepared: Prepared,
    shared: Arc<Shared>,
    trigger: &str,
    full: bool,
    lock: &RunLock,
) -> Progress {
    let Prepared {
        effective,
        revision,
        storage,
        sessions,
    } = prepared;
    std::thread::scope(|scope| {
        let (done, receiver) = mpsc::channel::<()>();
        let shared_for_status = shared.clone();
        let reporter = scope.spawn(move || {
            let api = match profile.api() {
                Ok(api) => api,
                Err(_) => return,
            };
            let mut sequence = 1;
            while receiver.recv_timeout(Duration::from_secs(15))
                == Err(mpsc::RecvTimeoutError::Timeout)
            {
                let progress = shared_for_status.snapshot();
                if !progress.phase.is_running() {
                    break;
                }
                let denied = update(
                    profile,
                    &api,
                    run,
                    &snapshot(sequence, &progress, None, false),
                )
                .is_err_and(|error| error.authorization_failed());
                let stop = denied
                    || match profile.check_in(&api, local, Some(revision)) {
                        Ok(paused) => paused,
                        Err(error) => error.authorization_failed(),
                    };
                if stop {
                    shared_for_status.cancel.store(true, Ordering::Relaxed);
                    sessions.stop();
                    break;
                }
                sequence = sequence.saturating_add(1);
            }
        });
        let result =
            engine::run_backup_locked(&effective, Arc::new(storage), shared, trigger, full, lock);
        drop(done);
        let _ = reporter.join();
        result
    })
}

fn prepare(
    cfg: &Config,
    profile: &Profile,
    started: &Json,
    run: &str,
    connect: impl FnOnce(&Config, Arc<dyn bt_s3::CredentialProvider>) -> Result<bt_s3::S3Client, String>,
) -> Result<Prepared, (String, &'static str)> {
    let policy = started
        .get("policy")
        .ok_or_else(|| "The dashboard did not supply a backup policy.".to_string())
        .and_then(|raw| Policy::parse(raw, profile))
        .map_err(|error| (error, "policy_unavailable"))?;
    let effective = policy
        .apply(cfg)
        .map_err(|error| (error, "policy_unavailable"))?;
    if effective.s3.client_encryption
        && crate::file_crypto::validate_key(&effective.s3.recovery_key).is_err()
    {
        return Err((
            "Add and save a client encryption recovery key in Encryption before backing up.".into(),
            "recovery_key_required",
        ));
    }
    let sessions = Arc::new(Sessions::new(
        &policy.target,
        "backup",
        Some(run.to_owned()),
    ));
    let client =
        connect(&effective, sessions.clone()).map_err(|error| (error, "storage_unavailable"))?;
    let storage = remote::S3Storage::from_client(&effective, client)
        .map_err(|error| (error, "storage_unavailable"))?;
    Ok(Prepared {
        effective,
        revision: policy.revision,
        storage,
        sessions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed;
    use bt_s3::{NoTls, S3Client};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        process::Command,
        sync::atomic::{AtomicBool, AtomicU32},
    };

    const DEVICE: &str = "48cde4f8-bdf8-4ac0-98ed-b32abb66cc79";

    struct Request {
        method: String,
        path: String,
        headers: Vec<String>,
        body: Vec<u8>,
    }

    struct Server {
        url: String,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Server {
        fn spawn(
            mut handler: impl FnMut(Request) -> (u16, String, &'static str) + Send + 'static,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let finished = stop.clone();
            let thread = std::thread::spawn(move || {
                while !finished.load(Ordering::Relaxed) {
                    let (mut socket, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("{error}"),
                    };
                    socket
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut reader = BufReader::new(&mut socket);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let mut first = line.split_whitespace();
                    let method = first.next().unwrap().to_string();
                    let path = first.next().unwrap().to_string();
                    let mut headers = Vec::new();
                    let len = loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        if line.trim().is_empty() {
                            break headers
                                .iter()
                                .find_map(|line: &String| {
                                    line.strip_prefix("content-length: ")
                                        .and_then(|value| value.parse::<usize>().ok())
                                })
                                .unwrap_or(0);
                        }
                        headers.push(line.trim().to_ascii_lowercase());
                    };
                    let mut body = vec![0; len];
                    reader.read_exact(&mut body).unwrap();
                    let (status, response, extra) = handler(Request {
                        method,
                        path,
                        headers,
                        body,
                    });
                    write!(socket, "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{response}", response.len()).unwrap();
                }
            });
            Self {
                url,
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
        }
    }

    #[test]
    fn managed_backup_uploads_directly_refreshes_expiry_and_replays_status() {
        const CHILD: &str = "STOW_MANAGED_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let root =
                std::env::temp_dir().join(format!("stow-managed-test-{}", random_id().unwrap()));
            fs::create_dir(&root).unwrap();
            let result = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "managed::run::tests::managed_backup_uploads_directly_refreshes_expiry_and_replays_status", "--nocapture"])
                .env(CHILD, "1")
                .env("BACKUP_TAKER_HOME", root.join("state"))
                .env("BACKUP_TAKER_PLAIN_SECRETS", "1")
                .output().unwrap();
            fs::remove_dir_all(root).unwrap();
            assert!(
                result.status.success(),
                "{}
{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr),
            );
            return;
        }

        let root = crate::paths::app_dir();
        let source = root.parent().unwrap().join("source");
        fs::create_dir(&source).unwrap();
        let contents = b"this payload goes straight to object storage";
        fs::write(source.join("one.txt"), contents).unwrap();
        fs::write(source.join("excluded.tmp"), b"excluded by dashboard rule").unwrap();

        let direct_requests = Arc::new(AtomicU32::new(0));
        let transfers = direct_requests.clone();
        let s3 = Server::spawn(move |request| {
            let attempt = transfers.fetch_add(1, Ordering::Relaxed);
            assert_eq!(request.method, "PUT");
            assert_eq!(
                request.path,
                format!("/stow-test/backups/devices/{DEVICE}/source/one.txt")
            );
            assert_eq!(request.body, contents);
            assert!(request
                .headers
                .contains(&format!("x-amz-security-token: session-{}", attempt + 1)));
            if attempt == 0 {
                return (403, "<Error><Code>ExpiredToken</Code></Error>".into(), "");
            }
            (200, String::new(), "ETag: \"stored\"\r\n")
        });

        let sessions = Arc::new(AtomicU32::new(0));
        let reports = Arc::new(AtomicU32::new(0));
        let (issued, received) = (sessions.clone(), reports.clone());
        let abandoned = random_id().unwrap();
        let prior = abandoned.clone();
        let recovery = Arc::new(AtomicBool::new(false));
        let recovered = recovery.clone();
        let deny_preflight = Arc::new(AtomicBool::new(false));
        let denied = deny_preflight.clone();
        let checks = Arc::new(AtomicU32::new(0));
        let checked = checks.clone();
        let policy = format!(
            r#"{{"schemaVersion":1,"revision":1,"destinationRevisionId":1,"bucket":"stow-test","region":"us-east-1","prefix":"backups/devices/{DEVICE}/","rules":{{"excludes":["*.tmp"],"skipHidden":true,"skipDevArtifacts":true,"requireClientEncryption":false,"maxParallelUploads":2,"storageClass":"STANDARD","serverEncryption":"","kmsKeyArn":""}}}}"#
        );
        let mut policy = Json::parse(&policy).unwrap();
        let mut rules = policy.get("rules").unwrap().clone();
        let mut patterns = vec![Json::from("*.tmp")];
        patterns
            .extend((0..99).map(|_| Json::from(format!("{}{}", "\"".repeat(68), "a".repeat(188)))));
        rules.set("excludes", patterns);
        policy.set("rules", rules);
        let policy = policy.to_string_compact();
        let dashboard = Server::spawn(move |request| {
            assert!(!request
                .body
                .windows(contents.len())
                .any(|chunk| chunk == contents));
            assert!(!String::from_utf8_lossy(&request.body).contains("one.txt"));
            let body = Json::parse(&String::from_utf8_lossy(&request.body)).unwrap_or(Json::Null);
            let (status, reply) = match request.path.as_str() {
                "/api/v1/enrollment/redeem" => (
                    200,
                    format!(r#"{{"deviceId":"{DEVICE}","displayName":"Fixture"}}"#),
                ),
                "/api/v1/device/check-in" => {
                    assert!(body.bool_or("scheduleEnabled", false));
                    #[cfg(unix)]
                    assert!(body.num_or("nextDueAt", 0.0) > crate::timefmt::now_secs() as f64);
                    checked.fetch_add(1, Ordering::Relaxed);
                    if denied.load(Ordering::Relaxed) && body.get("appliedRevision").is_some() {
                        (403, "{}".into())
                    } else {
                        (200, r#"{"state":"active"}"#.into())
                    }
                }
                "/api/v1/device/policy" => (200, policy.clone()),
                "/api/v1/device/runs" => {
                    assert_eq!(body.str_or("trigger", ""), "scheduled");
                    assert!(checked.load(Ordering::Relaxed) > 0);
                    (
                        200,
                        format!(
                            r#"{{"decision":"accepted","phase":"starting","policy":{policy}}}"#
                        ),
                    )
                }
                "/api/v1/device/storage-sessions" => {
                    assert_eq!(body.str_or("purpose", ""), "backup");
                    assert!(valid_uuid(&body.str_or("runId", "")));
                    let number = issued.fetch_add(1, Ordering::Relaxed) + 1;
                    (
                        200,
                        format!(
                            r#"{{"destinationRevisionId":1,"bucket":"stow-test","region":"us-east-1","prefix":"backups/devices/{DEVICE}/","serverTime":1000,"expiresAt":1900,"accessKeyId":"access-{number}","secretAccessKey":"test-secret","sessionToken":"session-{number}"}}"#
                        ),
                    )
                }
                path if path.ends_with("/snapshot") => {
                    if path.contains(&prior) {
                        assert_eq!(body.str_or("phase", ""), "cancelled");
                        recovered.store(true, Ordering::Relaxed);
                        return (200, r#"{"acceptedSequence":4294967295}"#.into(), "");
                    }
                    if denied.load(Ordering::Relaxed) {
                        assert_eq!(body.str_or("phase", ""), "failed");
                        assert_eq!(body.str_or("errorCode", ""), "storage_access_denied");
                        return (200, r#"{"acceptedSequence":4294967295}"#.into(), "");
                    }
                    assert_eq!(body.str_or("phase", ""), "finished");
                    assert_eq!(body.str_or("filesUploaded", ""), "1");
                    assert_eq!(body.str_or("bytesDone", ""), contents.len().to_string());
                    if received.fetch_add(1, Ordering::Relaxed) == 0 {
                        assert!(!body.bool_or("replayed", false));
                        (503, "{}".into())
                    } else {
                        assert!(body.bool_or("replayed", false));
                        (200, r#"{"acceptedSequence":4294967295}"#.into())
                    }
                }
                path => panic!("Unexpected dashboard request {path}"),
            };
            (status, reply, "")
        });

        let mut profile = Profile::pair(&dashboard.url, &"a".repeat(64)).unwrap();
        assert!(!profile.active);
        {
            let lock = RunLock::acquire().unwrap();
            assert!(profile.set_active(true).is_err());
            assert!(!Profile::load().unwrap().unwrap().active);
            drop(lock);
        }
        profile.set_active(true).unwrap();
        let mut cfg = Config {
            schedule: crate::config::ScheduleMode::Interval,
            ..Config::default()
        };
        cfg.add_folder(source.to_str().unwrap());
        store(
            &outbox(&profile).join(format!("{abandoned}.json")),
            &object(&[("trigger", Json::from("scheduled"))]),
        )
        .unwrap();
        let result =
            backup_with_client(&cfg, Shared::new(), "scheduled", false, |cfg, provider| {
                let mut settings = remote::s3_config(&cfg.s3);
                settings.endpoint = s3.url.clone();
                Ok(S3Client::new(settings, Arc::new(NoTls)).with_credentials(provider))
            });
        assert_eq!(result.phase, Phase::Finished, "{:?}", result.errors);
        assert!(recovery.load(Ordering::Relaxed));
        assert_eq!(direct_requests.load(Ordering::Relaxed), 2);
        assert_eq!(sessions.load(Ordering::Relaxed), 2);
        assert!(result.message.contains("will be retried"));
        assert_eq!(stored_paths(&profile).unwrap().len(), 1);
        assert!(managed::refresh(&profile, &cfg, Some(1))
            .unwrap()
            .reporting_error
            .is_none());
        assert_eq!(reports.load(Ordering::Relaxed), 2);
        assert!(stored_paths(&profile).unwrap().is_empty());
        deny_preflight.store(true, Ordering::Relaxed);
        let denied_result =
            backup_with_client(&cfg, Shared::new(), "scheduled", true, |cfg, provider| {
                let mut settings = remote::s3_config(&cfg.s3);
                settings.endpoint = s3.url.clone();
                Ok(S3Client::new(settings, Arc::new(NoTls)).with_credentials(provider))
            });
        assert_eq!(denied_result.phase, Phase::Failed);
        assert_eq!(direct_requests.load(Ordering::Relaxed), 2);
        assert_eq!(sessions.load(Ordering::Relaxed), 2);
    }
}
