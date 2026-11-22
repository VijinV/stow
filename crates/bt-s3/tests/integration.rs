//! Integration tests against real S3-compatible servers.
//!
//! Run with: `cargo test -p bt-s3 -- --ignored`
//! Endpoints come from `BT_S3_ENDPOINTS` (comma-separated), default
//! `http://127.0.0.1:9000,http://127.0.0.1:8333` (RustFS, SeaweedFS), with
//! credentials `BT_S3_KEY` / `BT_S3_SECRET` (default testkey/testsecret123).
use bt_s3::{NoTls, S3Client, S3Config, UploadOptions};
use bt_tls::crypto::sha256::Sha256;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

fn endpoints() -> Vec<String> {
    std::env::var("BT_S3_ENDPOINTS")
        .unwrap_or_else(|_| "http://127.0.0.1:9000,http://127.0.0.1:8333".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn cfg(endpoint: &str, bucket: &str) -> S3Config {
    S3Config {
        endpoint: endpoint.into(),
        region: String::new(),
        bucket: bucket.into(),
        access_key: std::env::var("BT_S3_KEY").unwrap_or_else(|_| "testkey".into()),
        secret_key: std::env::var("BT_S3_SECRET").unwrap_or_else(|_| "testsecret123".into()),
        session_token: None,
        path_style: false,
    }
}

fn unique(name: &str) -> String {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() % 1_000_000_000;
    format!("bt-{}-{}", name, n)
}

fn bucket(endpoint: &str, name: &str) -> S3Client {
    let c = S3Client::new(cfg(endpoint, &unique(name)), Arc::new(NoTls));
    c.create_bucket().unwrap_or_else(|e| panic!("create bucket on {}: {}", endpoint, e));
    c
}

fn tmpdir() -> PathBuf {
    let d = std::env::temp_dir().join(unique("tmp"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn file_sha(p: &std::path::Path) -> [u8; 32] {
    let data = std::fs::read(p).unwrap();
    let mut h = Sha256::new();
    h.update(&data);
    h.finalize()
}

/// Deterministic pseudo-random file of `size` bytes.
fn make_file(p: &std::path::Path, size: u64) {
    let mut f = std::io::BufWriter::new(std::fs::File::create(p).unwrap());
    let mut x: u64 = 0x9E3779B97F4A7C15 ^ size;
    let mut buf = vec![0u8; 1 << 20];
    let mut left = size;
    while left > 0 {
        for chunk in buf.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let b = x.to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        let n = left.min(buf.len() as u64) as usize;
        f.write_all(&buf[..n]).unwrap();
        left -= n as u64;
    }
}

fn cleanup(c: &S3Client) {
    if let Ok(objs) = c.list_objects("") {
        for o in objs {
            let _ = c.delete_object(&o.key);
        }
    }
    let _ = c.delete_bucket();
}

#[test]
#[ignore]
fn check_access_variants() {
    for ep in endpoints() {
        let c = bucket(&ep, "access");
        let msg = c.check_access().unwrap();
        assert!(msg.contains("Connected"), "{}", msg);
        assert!(c.list_buckets().unwrap().contains(&c.config().bucket));

        let mut bad = c.config().clone();
        bad.secret_key = "wrong-secret".into();
        let e = S3Client::new(bad, Arc::new(NoTls)).check_access().unwrap_err();
        assert_eq!(e.status, 403, "{}: {}", ep, e);
        assert!(e.code == "SignatureDoesNotMatch" || e.code == "AccessDenied", "{}: {}", ep, e);

        let mut bad = c.config().clone();
        bad.access_key = "nosuchkey".into();
        let e = S3Client::new(bad, Arc::new(NoTls)).check_access().unwrap_err();
        assert_eq!(e.status, 403, "{}: {}", ep, e);
        println!("{} bad key -> {}", ep, e);

        let mut bad = c.config().clone();
        bad.bucket = "bt-does-not-exist-7f3a".into();
        let e = S3Client::new(bad, Arc::new(NoTls)).check_access().unwrap_err();
        assert_eq!((e.status, e.code.as_str()), (404, "NoSuchBucket"), "{}: {}", ep, e);

        let e = S3Client::new(cfg("http://127.0.0.1:1", "x"), Arc::new(NoTls)).check_access().unwrap_err();
        assert_eq!(e.status, 0);
        cleanup(&c);
    }
}

#[test]
#[ignore]
fn small_empty_and_unicode_keys() {
    for ep in endpoints() {
        let c = bucket(&ep, "small");
        let d = tmpdir();
        let keys = [
            "plain.txt",
            "dir with space/file name (1).txt",
            "plus+sign&amp=x?.txt",
            "unicode/café-日本語-😀.bin",
            "deep/a/b/c/d/~tilde_.dat",
            "percent%20literal.txt",
        ];
        for (i, k) in keys.iter().enumerate() {
            let p = d.join(format!("f{}", i));
            make_file(&p, (i as u64) * 1000 + 1);
            let cancel = AtomicBool::new(false);
            let mut prog = 0;
            c.upload_file(k, &p, &UploadOptions::default(), &mut |n| prog += n, &cancel).unwrap_or_else(|e| panic!("{} {}: {}", ep, k, e));
            assert_eq!(prog, (i as u64) * 1000 + 1);
            let h = c.head_object(k).unwrap().unwrap_or_else(|| panic!("{} head {}", ep, k));
            assert_eq!(h.size, (i as u64) * 1000 + 1);
            let back = d.join(format!("back{}", i));
            c.get_object_to_file(k, &back, &mut |_| {}, &cancel).unwrap();
            assert_eq!(file_sha(&p), file_sha(&back));
        }
        let listed: Vec<String> = c.list_objects("").unwrap().into_iter().map(|o| o.key).collect();
        for k in keys {
            assert!(listed.contains(&k.to_string()), "{}: {} missing from {:?}", ep, k, listed);
        }
        // empty file
        let p = d.join("empty");
        std::fs::File::create(&p).unwrap();
        c.upload_file("empty.txt", &p, &UploadOptions::default(), &mut |_| {}, &AtomicBool::new(false)).unwrap();
        assert_eq!(c.head_object("empty.txt").unwrap().unwrap().size, 0);
        assert_eq!(c.get_object_bytes("empty.txt").unwrap().len(), 0);
        // bytes + delete + missing head
        c.put_object_bytes("mem.txt", b"hello", Some("text/plain")).unwrap();
        assert_eq!(c.get_object_bytes("mem.txt").unwrap(), b"hello");
        c.delete_object("mem.txt").unwrap();
        assert!(c.head_object("mem.txt").unwrap().is_none());
        let e = c.get_object_to_file("nope", &d.join("nope"), &mut |_| {}, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(e.status, 404);
        assert!(!d.join("nope").exists() && !d.join("nope.btpart").exists());
        cleanup(&c);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
#[ignore]
fn multipart_100mb_roundtrip() {
    for ep in endpoints() {
        let c = bucket(&ep, "big");
        let d = tmpdir();
        let p = d.join("big.bin");
        let size = 100 * 1024 * 1024 + 12345;
        make_file(&p, size);
        let opts = UploadOptions { part_size: 8 * 1024 * 1024, multipart_threshold: 16 * 1024 * 1024, ..Default::default() };
        let mut prog = 0u64;
        let t = std::time::Instant::now();
        let etag = c.upload_file("big/big.bin", &p, &opts, &mut |n| prog += n, &AtomicBool::new(false)).unwrap();
        println!("{}: 100MB multipart in {:?}, etag {}", ep, t.elapsed(), etag);
        assert_eq!(prog, size);
        assert!(etag.ends_with("-13"), "expected 13 parts, etag {}", etag);
        assert_eq!(c.head_object("big/big.bin").unwrap().unwrap().size, size);
        let back = d.join("back.bin");
        let mut dl = 0u64;
        c.get_object_to_file("big/big.bin", &back, &mut |n| dl += n, &AtomicBool::new(false)).unwrap();
        assert_eq!(dl, size);
        assert_eq!(file_sha(&p), file_sha(&back));
        assert!(c.list_multipart_uploads("").unwrap().is_empty());
        cleanup(&c);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
#[ignore]
fn pagination() {
    for ep in endpoints() {
        let c = Arc::new(bucket(&ep, "page"));
        // 1005 keys written by 8 threads (exercises the pool too)
        let n = 1005;
        let hs: Vec<_> = (0..8)
            .map(|t| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for i in (t..n).step_by(8) {
                        c.put_object_bytes(&format!("p/{:05}", i), b"x", None).unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        // manual small pages
        let mut token = None;
        let mut got = Vec::new();
        let mut pages = 0;
        loop {
            let (items, next) = c.list_objects_page("p/", 100, token.as_deref()).unwrap();
            pages += 1;
            got.extend(items.into_iter().map(|o| o.key));
            match next {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        assert_eq!(pages, 11);
        assert_eq!(got.len(), n);
        let all = c.list_objects("p/").unwrap();
        assert_eq!(all.len(), n, "{}", ep);
        let mut keys: Vec<_> = all.iter().map(|o| o.key.clone()).collect();
        keys.dedup();
        assert_eq!(keys.len(), n);
        assert!(c.list_objects("zzz/").unwrap().is_empty());
        cleanup(&c);
    }
}

#[test]
#[ignore]
fn cancel_mid_upload() {
    for ep in endpoints() {
        let c = bucket(&ep, "cancel");
        let d = tmpdir();
        for (name, size) in [("single", 20u64 << 20), ("multi", 60u64 << 20)] {
            let p = d.join(name);
            make_file(&p, size);
            let cancel = AtomicBool::new(false);
            let mut sent = 0u64;
            let opts = UploadOptions { part_size: 5 << 20, multipart_threshold: 32 << 20, ..Default::default() };
            let r = c.upload_file(name, &p, &opts, &mut |n| {
                sent += n;
                if sent > size / 3 {
                    cancel.store(true, Ordering::Relaxed);
                }
            }, &cancel);
            let e = r.unwrap_err();
            assert!(e.is_cancelled(), "{}: {}", ep, e);
            assert!(c.head_object(name).unwrap().is_none(), "{}: {} should not exist", ep, name);
        }
        assert!(c.list_multipart_uploads("").unwrap().is_empty(), "{}: multipart not aborted", ep);
        cleanup(&c);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
#[ignore]
fn resumable_parallel_multipart_roundtrip() {
    for ep in endpoints() {
        let c = bucket(&ep, "resume");
        let d = tmpdir();
        let source = d.join("source");
        let size = (20 << 20) + 1234;
        make_file(&source, size);
        let checkpoint = d.join("multipart");
        let opts = UploadOptions {
            part_size: 5 << 20,
            multipart_threshold: 5 << 20,
            multipart_parallelism: 3,
            multipart_checkpoint: Some(checkpoint.clone()),
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let r = c.upload_file("object", &source, &opts, &mut |_| {
            cancel.store(true, Ordering::Relaxed);
        }, &cancel);
        assert!(r.unwrap_err().is_cancelled(), "{ep}");
        assert!(checkpoint.is_file());
        assert_eq!(c.list_multipart_uploads("").unwrap().len(), 1, "{ep}");
        assert!(c.head_object("object").unwrap().is_none());

        let restarted = S3Client::new(c.config().clone(), Arc::new(NoTls));
        let mut sent = 0;
        restarted.upload_file("object", &source, &opts, &mut |n| sent += n, &AtomicBool::new(false)).unwrap();
        assert_eq!(sent, size);
        assert!(!checkpoint.exists());
        assert!(restarted.list_multipart_uploads("").unwrap().is_empty());
        let downloaded = d.join("downloaded");
        restarted.get_object_to_file("object", &downloaded, &mut |_| {}, &AtomicBool::new(false)).unwrap();
        assert_eq!(file_sha(&source), file_sha(&downloaded), "{ep}");
        println!("{ep}: cancelled, resumed and verified {size} bytes");
        cleanup(&restarted);
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
#[ignore]
fn parallel_uploads() {
    for ep in endpoints() {
        let c = Arc::new(bucket(&ep, "par"));
        let d = tmpdir();
        let total = Arc::new(AtomicU64::new(0));
        let hs: Vec<_> = (0..4)
            .map(|t| {
                let c = c.clone();
                let d = d.clone();
                let total = total.clone();
                std::thread::spawn(move || {
                    for i in 0..5 {
                        let p = d.join(format!("t{}-{}", t, i));
                        let size = if i == 4 { 40 << 20 } else { 300_000 + i * 7 };
                        make_file(&p, size);
                        let opts = UploadOptions { multipart_threshold: 32 << 20, part_size: 8 << 20, ..Default::default() };
                        c.upload_file(&format!("par/{}", p.file_name().unwrap().to_str().unwrap()), &p, &opts, &mut |n| {
                            total.fetch_add(n, Ordering::Relaxed);
                        }, &AtomicBool::new(false))
                        .unwrap();
                        let h = c.head_object(&format!("par/t{}-{}", t, i)).unwrap().unwrap();
                        assert_eq!(h.size, size);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(c.list_objects("par/").unwrap().len(), 20);
        assert_eq!(total.load(Ordering::Relaxed), 4 * ((40 << 20) + 300_000 * 4 + 7 * 6));
        cleanup(&c);
        let _ = std::fs::remove_dir_all(&d);
    }
}
