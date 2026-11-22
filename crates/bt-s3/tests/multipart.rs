use bt_s3::{NoTls, S3Client, S3Config, UploadBudget, UploadOptions};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PART: u64 = 5 << 20;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let random = bt_tls::crypto::random::array::<16>().unwrap();
        let path = std::env::temp_dir().join(bt_tls::crypto::util::hex(&random));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn client(listener: &TcpListener) -> S3Client {
    let cfg = S3Config {
        endpoint: format!("http://{}", listener.local_addr().unwrap()),
        bucket: "bucket".into(),
        ..Default::default()
    };
    S3Client::new(cfg, Arc::new(NoTls))
}

fn request(listener: &TcpListener) -> (TcpStream, String, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("timed out accepting S3 request: {e}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(&mut stream);
    let mut head = String::new();
    let mut len = 0;
    loop {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = value.trim().parse::<usize>().unwrap();
        }
        head.push_str(&line);
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).unwrap();
    (stream, head, body)
}

fn respond(mut stream: TcpStream, status: &str, headers: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
    .unwrap();
}

#[test]
fn multipart_puts_overlap_and_complete_in_part_order() {
    let dir = TempDir::new();
    let path = dir.0.join("source");
    File::create(&path).unwrap().set_len(2 * PART).unwrap();
    let opts = UploadOptions {
        part_size: PART,
        multipart_threshold: PART,
        multipart_parallelism: 2,
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = client(&listener);
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploads="));
            respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>id</UploadId></InitiateMultipartUploadResult>");
            let (first, head, _) = request(&listener);
            let first_is_one = head.starts_with("PUT /bucket/file?partNumber=1&uploadId=id");
            // Hold the first response until both part requests are in flight.
            let (second, head, _) = request(&listener);
            assert_eq!(first_is_one, head.starts_with("PUT /bucket/file?partNumber=2&uploadId=id"));
            let (one, two) = if first_is_one { (first, second) } else { (second, first) };
            respond(two, "200 OK", "ETag: \"two\"\r\n", "");
            respond(one, "200 OK", "ETag: \"one\"\r\n", "");
            let (stream, head, body) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploadId=id"));
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("<PartNumber>1</PartNumber><ETag>&quot;one&quot;</ETag></Part><Part><PartNumber>2</PartNumber><ETag>&quot;two&quot;</ETag>"));
            respond(stream, "200 OK", "", "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>");
        });
        let cancel = AtomicBool::new(false);
        let mut sent = 0;
        let uploaded = client.upload_file("file", &path, &opts, &mut |n| sent += n, &cancel);
        server.join().unwrap();
        assert_eq!(uploaded.unwrap(), "done");
        assert_eq!(sent, 2 * PART);
    });
}

#[test]
fn restart_reconciles_checkpoint_against_all_server_part_pages() {
    let dir = TempDir::new();
    let path = dir.0.join("source");
    File::create(&path).unwrap().set_len(3 * PART).unwrap();
    let checkpoint = dir.0.join("checkpoint");
    let opts = UploadOptions {
        part_size: PART,
        multipart_threshold: PART,
        multipart_checkpoint: Some(checkpoint.clone()),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let first_client = client(&listener);
    let second_client = client(&listener);
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploads="));
            respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>open+id</UploadId></InitiateMultipartUploadResult>");
            for part in [1, 2] {
                let (stream, head, body) = request(&listener);
                assert!(head.starts_with(&format!("PUT /bucket/file?partNumber={part}&uploadId=open%2Bid")));
                assert_eq!(body.len() as u64, PART);
                respond(stream, "200 OK", &format!("ETag: \"part{part}\"\r\n"), "");
            }
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("PUT /bucket/file?partNumber=3&uploadId=open%2Bid"));
            respond(stream, "400 Bad Request", "", "<Error><Code>InvalidRequest</Code></Error>");

            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("GET /bucket/file?uploadId=open%2Bid"), "{head}");
            respond(stream, "200 OK", "", &format!("<ListPartsResult><IsTruncated>true</IsTruncated><NextPartNumberMarker>1</NextPartNumberMarker><Part><PartNumber>1</PartNumber><ETag>&quot;part1&quot;</ETag><Size>{PART}</Size></Part></ListPartsResult>"));
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("GET /bucket/file?part-number-marker=1&uploadId=open%2Bid"), "{head}");
            respond(stream, "200 OK", "", &format!("<ListPartsResult><IsTruncated>false</IsTruncated><Part><PartNumber>2</PartNumber><ETag>&quot;other&quot;</ETag><Size>{PART}</Size></Part><Part><PartNumber>3</PartNumber><ETag>&quot;unknown&quot;</ETag><Size>{PART}</Size></Part></ListPartsResult>"));
            for (attempt, part) in [2, 2, 3].into_iter().enumerate() {
                let (stream, head, body) = request(&listener);
                assert!(head.starts_with(&format!("PUT /bucket/file?partNumber={part}&uploadId=open%2Bid")), "{head}");
                assert_eq!(body.len() as u64, PART);
                if attempt == 0 {
                    respond(stream, "503 Service Unavailable", "", "<Error><Code>SlowDown</Code></Error>");
                } else {
                    respond(stream, "200 OK", &format!("ETag: \"new{part}\"\r\n"), "");
                }
            }
            let (stream, head, body) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploadId=open%2Bid"));
            let body = String::from_utf8(body).unwrap();
            for (part, etag) in [(1, "part1"), (2, "new2"), (3, "new3")] {
                assert!(body.contains(&format!("<PartNumber>{part}</PartNumber><ETag>&quot;{etag}&quot;</ETag>")), "{body}");
            }
            respond(stream, "200 OK", "", "<CompleteMultipartUploadResult><ETag>resumed</ETag></CompleteMultipartUploadResult>");
        });
        let cancel = AtomicBool::new(false);
        assert!(first_client
            .upload_file("file", &path, &opts, &mut |_| {}, &cancel)
            .is_err());
        assert!(checkpoint.exists());
        let mut journal = fs::OpenOptions::new()
            .append(true)
            .open(&checkpoint)
            .unwrap();
        journal.write_all(b"3 123").unwrap();
        drop(journal);
        let mut sent = 0;
        let resumed = second_client.upload_file("file", &path, &opts, &mut |n| sent += n, &cancel);
        server.join().unwrap();
        assert_eq!(resumed.unwrap(), "resumed");
        assert_eq!(sent, 3 * PART);
        assert!(!checkpoint.exists());
    });
}

#[test]
fn cancelled_upload_restarts_if_server_expired_its_id() {
    restart_upload(Restart::Expired);
}

#[test]
fn cancelled_upload_never_reuses_parts_after_a_same_size_source_edit() {
    restart_upload(Restart::Changed);
}

#[test]
fn cancelled_upload_restarts_when_list_parts_and_abort_are_denied() {
    restart_upload(Restart::DeniedListAndAbort);
}

#[test]
fn changed_source_restarts_when_abort_is_denied() {
    restart_upload(Restart::ChangedWithDeniedAbort);
}

enum Restart {
    Expired,
    Changed,
    DeniedListAndAbort,
    ChangedWithDeniedAbort,
}

fn restart_upload(restart: Restart) {
    let source_changed = matches!(restart, Restart::Changed | Restart::ChangedWithDeniedAbort);
    let dir = TempDir::new();
    let path = dir.0.join("source");
    File::create(&path).unwrap().set_len(2 * PART).unwrap();
    let checkpoint = dir.0.join("checkpoint");
    let opts = UploadOptions {
        part_size: PART,
        multipart_threshold: PART,
        multipart_checkpoint: Some(checkpoint.clone()),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let first_client = client(&listener);
    let second_client = client(&listener);
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploads="));
            respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>expired</UploadId></InitiateMultipartUploadResult>");
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("PUT /bucket/file?partNumber=1&uploadId=expired"));
            respond(stream, "200 OK", "ETag: old\r\n", "");

            let (stream, head, _) = request(&listener);
            match restart {
                Restart::Changed => {
                    assert!(head.starts_with("DELETE /bucket/file?uploadId=expired"), "{head}");
                    respond(stream, "204 No Content", "", "");
                }
                Restart::Expired => {
                    assert!(head.starts_with("GET /bucket/file?uploadId=expired"), "{head}");
                    respond(stream, "404 Not Found", "", "<Error><Code>NoSuchUpload</Code></Error>");
                }
                Restart::DeniedListAndAbort => {
                    assert!(head.starts_with("GET /bucket/file?uploadId=expired"), "{head}");
                    respond(stream, "403 Forbidden", "", "<Error><Code>AccessDenied</Code></Error>");
                    let (stream, head, _) = request(&listener);
                    assert!(head.starts_with("DELETE /bucket/file?uploadId=expired"), "{head}");
                    respond(stream, "403 Forbidden", "", "<Error><Code>AccessDenied</Code></Error>");
                }
                Restart::ChangedWithDeniedAbort => {
                    assert!(head.starts_with("DELETE /bucket/file?uploadId=expired"), "{head}");
                    respond(stream, "403 Forbidden", "", "<Error><Code>AccessDenied</Code></Error>");
                }
            }
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploads="));
            respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>new</UploadId></InitiateMultipartUploadResult>");
            for part in [1, 2] {
                let (stream, head, body) = request(&listener);
                assert!(head.starts_with(&format!("PUT /bucket/file?partNumber={part}&uploadId=new")), "{head}");
                if part == 1 && source_changed {
                    assert_eq!(body[0], 42);
                }
                respond(stream, "200 OK", &format!("ETag: new{part}\r\n"), "");
            }
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploadId=new"));
            respond(stream, "200 OK", "", "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>");
        });
        let cancel = AtomicBool::new(false);
        let cancelled = first_client.upload_file(
            "file",
            &path,
            &opts,
            &mut |n| {
                assert_eq!(n, PART);
                cancel.store(true, Ordering::Relaxed);
            },
            &cancel,
        );
        assert!(cancelled.unwrap_err().is_cancelled());
        assert!(checkpoint.exists());
        if source_changed {
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .write_all(&[42])
                .unwrap();
        }
        cancel.store(false, Ordering::Relaxed);
        let mut sent = 0;
        let resumed = second_client.upload_file("file", &path, &opts, &mut |n| sent += n, &cancel);
        assert_eq!(resumed.unwrap(), "done");
        server.join().unwrap();
        assert_eq!(sent, 2 * PART);
        assert!(!checkpoint.exists());
    });
}

#[test]
fn restart_recovers_a_committed_object_after_losing_completion_reply() {
    restart_after_lost_completion(CompletionObject::Matching, false);
}

#[test]
fn restart_reports_conflict_without_writing_after_losing_completion_reply() {
    restart_after_lost_completion(CompletionObject::Conflicting, false);
}

#[test]
fn changed_source_preserves_conflict_after_losing_completion_reply() {
    restart_after_lost_completion(CompletionObject::ConflictingAfterSourceChange, false);
}

#[test]
fn restart_recovers_a_committed_object_when_list_parts_is_denied() {
    restart_after_lost_completion(CompletionObject::MatchingWithDeniedList, false);
}

#[test]
fn restart_uploads_again_if_lost_completion_left_no_object() {
    restart_after_lost_completion(CompletionObject::Missing, false);
}

#[test]
fn recovered_completion_keeps_checkpoint_when_requested() {
    restart_after_lost_completion(CompletionObject::Matching, true);
}

#[derive(Clone, Copy)]
enum CompletionObject {
    Matching,
    MatchingWithDeniedList,
    Missing,
    Conflicting,
    ConflictingAfterSourceChange,
}

fn restart_after_lost_completion(object: CompletionObject, retain_completed_checkpoint: bool) {
    let source_changed = matches!(object, CompletionObject::ConflictingAfterSourceChange);
    let dir = TempDir::new();
    let path = dir.0.join("source");
    File::create(&path).unwrap().set_len(PART).unwrap();
    let checkpoint = dir.0.join("checkpoint");
    let opts = UploadOptions {
        part_size: PART,
        multipart_threshold: PART,
        multipart_checkpoint: Some(checkpoint.clone()),
        retain_completed_checkpoint,
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let first_client = client(&listener);
    let second_client = client(&listener);
    let cancel = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    thread::scope(|scope| {
        let interrupted = &cancel;
        let finished = &finished;
        let server = scope.spawn(move || {
            let (stream, head, _) = request(&listener);
            let token = head.lines().find_map(|line| line.strip_prefix("x-amz-meta-bt-multipart-token: ")).unwrap();
            respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>id</UploadId></InitiateMultipartUploadResult>");
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("PUT /bucket/file?partNumber=1&uploadId=id"));
            respond(stream, "200 OK", "ETag: part\r\n", "");
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploadId=id"));
            interrupted.store(true, Ordering::Relaxed);
            drop(stream);

            let (stream, head, _) = request(&listener);
            let method = if source_changed { "DELETE" } else { "GET" };
            assert!(head.starts_with(&format!("{method} /bucket/file?uploadId=id")), "{head}");
            if matches!(object, CompletionObject::MatchingWithDeniedList) {
                respond(stream, "403 Forbidden", "", "<Error><Code>AccessDenied</Code></Error>");
            } else {
                respond(stream, "404 Not Found", "", "<Error><Code>NoSuchUpload</Code></Error>");
            }
            let (mut stream, head, _) = request(&listener);
            assert!(head.starts_with("HEAD /bucket/file HTTP/1.1"), "{head}");
            match object {
                CompletionObject::Matching | CompletionObject::MatchingWithDeniedList => {
                    write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {PART}\r\nETag: \"done\"\r\nx-amz-meta-bt-multipart-token: {token}\r\n\r\n").unwrap();
                }
                CompletionObject::Missing => {
                    respond(stream, "404 Not Found", "", "");
                    let (stream, head, _) = request(&listener);
                    assert!(head.starts_with("POST /bucket/file?uploads="));
                    respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>new</UploadId></InitiateMultipartUploadResult>");
                    let (stream, head, _) = request(&listener);
                    assert!(head.starts_with("PUT /bucket/file?partNumber=1&uploadId=new"));
                    respond(stream, "200 OK", "ETag: part\r\n", "");
                    let (stream, head, _) = request(&listener);
                    assert!(head.starts_with("POST /bucket/file?uploadId=new"));
                    respond(stream, "200 OK", "", "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>");
                }
                CompletionObject::Conflicting | CompletionObject::ConflictingAfterSourceChange => {
                    write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {PART}\r\nETag: \"newer\"\r\nx-amz-meta-bt-multipart-token: newer\r\n\r\n").unwrap();
                    drop(stream);
                    loop {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                respond(stream, "400 Bad Request", "", "<Error><Code>UnexpectedWrite</Code></Error>");
                                return false;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                if finished.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(e) => panic!("failed to check for a subsequent request: {e}"),
                        }
                    }
                }
            }
            true
        });
        assert!(first_client
            .upload_file("file", &path, &opts, &mut |_| {}, &cancel)
            .unwrap_err()
            .is_cancelled());
        let saved = fs::read(&checkpoint).unwrap();
        if source_changed {
            fs::write(&path, b"replacement now below the multipart threshold").unwrap();
        }
        cancel.store(false, Ordering::Relaxed);
        let mut sent = 0;
        let resumed = second_client.upload_file("file", &path, &opts, &mut |n| sent += n, &cancel);
        finished.store(true, Ordering::Relaxed);
        assert!(
            server.join().unwrap(),
            "sent a request after detecting conflict"
        );
        match object {
            CompletionObject::Conflicting | CompletionObject::ConflictingAfterSourceChange => {
                assert_eq!(resumed.unwrap_err().code, "MultipartCompletionConflict");
                assert_eq!(sent, 0);
                assert_eq!(fs::read(&checkpoint).unwrap(), saved);
            }
            CompletionObject::Matching
            | CompletionObject::MatchingWithDeniedList
            | CompletionObject::Missing => {
                assert_eq!(resumed.unwrap(), "done");
                assert_eq!(sent, PART);
                if retain_completed_checkpoint {
                    assert_eq!(fs::read(&checkpoint).unwrap(), saved);
                } else {
                    assert!(!checkpoint.exists());
                }
            }
        }
    });
}

#[test]
fn successful_completion_keeps_checkpoint_when_requested() {
    let dir = TempDir::new();
    let path = dir.0.join("source");
    File::create(&path).unwrap().set_len(PART).unwrap();
    let checkpoint = dir.0.join("checkpoint");
    let opts = UploadOptions {
        part_size: PART,
        multipart_threshold: PART,
        multipart_checkpoint: Some(checkpoint.clone()),
        retain_completed_checkpoint: true,
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = client(&listener);
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploads="));
            respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>id</UploadId></InitiateMultipartUploadResult>");
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("PUT /bucket/file?partNumber=1&uploadId=id"));
            respond(stream, "200 OK", "ETag: part\r\n", "");
            let (stream, head, _) = request(&listener);
            assert!(head.starts_with("POST /bucket/file?uploadId=id"));
            respond(stream, "200 OK", "", "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>");
        });
        let cancel = AtomicBool::new(false);
        let uploaded = client.upload_file("file", &path, &opts, &mut |_| {}, &cancel);
        server.join().unwrap();
        assert_eq!(uploaded.unwrap(), "done");
        assert!(fs::read_to_string(checkpoint)
            .unwrap()
            .ends_with("complete\n"));
    });
}

#[test]
fn concurrent_files_share_the_part_request_budget() {
    let dir = TempDir::new();
    let path = dir.0.join("source");
    File::create(&path).unwrap().set_len(2 * PART).unwrap();
    let opts = UploadOptions {
        part_size: PART,
        multipart_threshold: PART,
        multipart_parallelism: 2,
        upload_budget: Some(Arc::new(UploadBudget::new(2))),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let clients = [client(&listener), client(&listener)];
    let cancel = AtomicBool::new(false);
    thread::scope(|scope| {
        let server = scope.spawn(move || {
            let (first, head, _) = request(&listener);
            assert!(head.starts_with("POST ") && head.contains("?uploads="));
            let (second, head, _) = request(&listener);
            assert!(head.starts_with("POST ") && head.contains("?uploads="));
            for stream in [first, second] {
                respond(stream, "200 OK", "", "<InitiateMultipartUploadResult><UploadId>id</UploadId></InitiateMultipartUploadResult>");
            }
            let (first, head, _) = request(&listener);
            assert!(head.starts_with("PUT "));
            let (second, head, _) = request(&listener);
            assert!(head.starts_with("PUT "));
            // Four workers can start here. Only the two holding permits may
            // make requests while their responses remain pending.
            thread::sleep(Duration::from_millis(200));
            assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
            for stream in [first, second] {
                respond(stream, "200 OK", "ETag: part\r\n", "");
            }
            let mut parts = 2;
            let mut completed = 0;
            while completed < 2 {
                let (stream, head, _) = request(&listener);
                if head.starts_with("PUT ") {
                    parts += 1;
                    respond(stream, "200 OK", "ETag: part\r\n", "");
                } else {
                    assert!(head.starts_with("POST ") && head.contains("?uploadId="));
                    completed += 1;
                    respond(stream, "200 OK", "", "<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>");
                }
            }
            assert_eq!(parts, 4);
        });
        let uploads = ["one", "two"]
            .into_iter()
            .zip(&clients)
            .map(|(key, client)| {
                let (path, opts, cancel) = (&path, &opts, &cancel);
                scope.spawn(move || client.upload_file(key, path, opts, &mut |_| {}, cancel))
            })
            .collect::<Vec<_>>();
        server.join().unwrap();
        for upload in uploads {
            assert_eq!(upload.join().unwrap().unwrap(), "done");
        }
    });
}
