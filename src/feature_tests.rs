//! Opt-in integration checks against disposable local S3-compatible buckets.
use crate::{
    browse,
    config::Config,
    engine::{self, Phase, Shared},
    remote,
};
use std::fs;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[test]
#[ignore = "requires local S3 servers; run with --ignored --test-threads=1"]
fn encrypted_backup_browse_restore_end_to_end() {
    for endpoint in std::env::var("BT_S3_ENDPOINTS")
        .unwrap_or_else(|_| "http://127.0.0.1:9000,http://127.0.0.1:8333".into())
        .split(',')
    {
        let id = crate::file_crypto::generate_key().unwrap();
        let root = std::env::temp_dir().join(format!("bt-features-{}", &id[..12]));
        fs::create_dir_all(root.join("source/sub")).unwrap();
        fs::create_dir_all(root.join("restored")).unwrap();
        std::env::set_var("BACKUP_TAKER_HOME", root.join("config"));
        fs::write(root.join("source/note.txt"), b"restore this exact content").unwrap();
        fs::write(root.join("source/sub/empty.txt"), b"").unwrap();
        // Above multipart threshold, and includes non-ASCII key encoding.
        let big = vec![0x6bu8; 33 * 1024 * 1024];
        fs::write(root.join("source/sub/vidéo.bin"), &big).unwrap();
        let mut cfg = Config::default();
        cfg.device_name = "test-device".into();
        cfg.s3.endpoint = endpoint.into();
        cfg.s3.bucket = format!("bt-features-{}", &id[..12]);
        cfg.s3.access_key = std::env::var("BT_S3_KEY").unwrap_or_else(|_| "testkey".into());
        cfg.s3.secret_key =
            std::env::var("BT_S3_SECRET").unwrap_or_else(|_| "testsecret123".into());
        cfg.s3.client_encryption = true;
        cfg.s3.recovery_key = crate::file_crypto::generate_key().unwrap();
        cfg.add_folder(root.join("source").to_str().unwrap());
        let client = remote::client(&cfg.s3).unwrap();
        client.create_bucket().unwrap();
        let backup = |cfg: &Config, full: bool| {
            let storage = Arc::new(remote::S3Storage::new(cfg).unwrap());
            if full {
                engine::run_backup_full(cfg, storage, Shared::new(), "test-full")
            } else {
                engine::run_backup(cfg, storage, Shared::new(), "test")
            }
        };
        let p = backup(&cfg, false);
        assert_eq!(p.phase, Phase::Finished, "{:?}", p.errors);
        assert_eq!(p.files_uploaded, 3);
        let p = backup(&cfg, false);
        assert_eq!(p.files_uploaded, 0);
        assert_eq!(p.files_skipped, 3);
        let p = backup(&cfg, true);
        assert_eq!(p.files_uploaded, 3);
        let objects = browse::inventory(&cfg.s3).unwrap();
        assert_eq!(objects.len(), 3);
        assert!(objects.iter().map(|o| o.size).sum::<u64>() > big.len() as u64);
        let prefix = cfg.remote_root(&cfg.folders[0]);
        let entries = browse::entries(&objects, &prefix);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_folder);
        let note_key = format!("{prefix}note.txt");
        let wire = client.get_object_bytes(&note_key).unwrap();
        assert!(!wire.windows(25).any(|w| w == b"restore this exact content"));
        fs::remove_dir_all(root.join("source")).unwrap();
        let status = Arc::new(Mutex::new(Default::default()));
        browse::restore(
            &cfg.s3,
            objects.clone(),
            &prefix,
            &root.join("restored"),
            status.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(
            fs::read(root.join("restored/note.txt")).unwrap(),
            b"restore this exact content"
        );
        assert_eq!(fs::read(root.join("restored/sub/empty.txt")).unwrap(), b"");
        assert_eq!(fs::read(root.join("restored/sub/vidéo.bin")).unwrap(), big);
        assert_eq!(status.lock().unwrap().files_done, 3);
        assert!(browse::restore(
            &cfg.s3,
            objects.clone(),
            &prefix,
            &root.join("restored"),
            Arc::new(Mutex::new(Default::default())),
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
        let mut wrong = cfg.s3.clone();
        wrong.recovery_key = crate::file_crypto::generate_key().unwrap();
        fs::create_dir_all(root.join("wrong")).unwrap();
        assert!(browse::restore(
            &wrong,
            objects.clone(),
            &prefix,
            &root.join("wrong"),
            Arc::new(Mutex::new(Default::default())),
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
        assert!(!root.join("wrong/note.txt").exists());
        for o in objects {
            client.delete_object(&o.key).unwrap();
        }
        client.delete_bucket().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    std::env::remove_var("BACKUP_TAKER_HOME");
}

#[test]
#[ignore = "creates a local GUI demonstration bucket; opt-in only"]
fn prepare_gui_demo() {
    let id = crate::file_crypto::generate_key().unwrap();
    let root = std::env::temp_dir().join(format!("bt-gui-demo-{}", &id[..12]));
    fs::create_dir_all(root.join("Example files/Photos")).unwrap();
    fs::write(
        root.join("Example files/Photos/backup-logo.png"),
        include_bytes!("../assets/icon-256.png"),
    )
    .unwrap();
    fs::write(root.join("Example files/Read me.txt"), b"This preview was fetched from S3 and decrypted locally.\nRestore this folder using Browse S3.\n").unwrap();
    if let Ok(video) = fs::read("/tmp/bt-test-flower.mp4") {
        fs::create_dir_all(root.join("Example files/Videos")).unwrap();
        fs::write(root.join("Example files/Videos/flower.mp4"), video).unwrap();
    }
    std::env::set_var("BACKUP_TAKER_HOME", root.join("config"));
    let mut cfg = Config::default();
    cfg.device_name = "Demo computer".into();
    cfg.s3.endpoint = "http://127.0.0.1:9000".into();
    cfg.s3.bucket = format!("bt-gui-demo-{}", &id[..12]);
    cfg.s3.access_key = "testkey".into();
    cfg.s3.secret_key = "testsecret123".into();
    cfg.s3.client_encryption = true;
    cfg.s3.recovery_key = crate::file_crypto::generate_key().unwrap();
    cfg.add_folder(root.join("Example files").to_str().unwrap());
    cfg.save().unwrap();
    remote::client(&cfg.s3).unwrap().create_bucket().unwrap();
    let p = engine::run_backup(
        &cfg,
        Arc::new(remote::S3Storage::new(&cfg).unwrap()),
        Shared::new(),
        "GUI demo",
    );
    assert_eq!(p.phase, Phase::Finished, "{:?}", p.errors);
    fs::write(
        "/tmp/backup-taker-run/demo-home",
        root.join("config").to_str().unwrap(),
    )
    .unwrap();
    std::env::remove_var("BACKUP_TAKER_HOME");
}
