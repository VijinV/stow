use crate::{
    config::Config,
    json::Json,
    managed::{Policy, Profile},
};

const DEVICE: &str = "48cde4f8-bdf8-4ac0-98ed-b32abb66cc79";

#[test]
fn managed_origin_requires_https_except_literal_loopback() {
    assert!(Profile::validate_origin("http://127.0.0.1:8787").is_ok());
    assert!(Profile::validate_origin("http://[::1]:8787").is_ok());
    assert!(Profile::validate_origin("https://dashboard.example.com").is_ok());
    for bad in [
        "http://dashboard.example.com",
        "https://host/path",
        "https://u@host",
        "https://host/#token",
        "https://host?",
    ] {
        assert!(Profile::validate_origin(bad).is_err(), "{bad}");
    }
}

#[test]
fn managed_policy_applies_required_rules_and_exact_prefix() {
    let profile = Profile::test("http://127.0.0.1:8787", DEVICE);
    let raw = Json::parse(&format!(r#"{{"schemaVersion":1,"revision":1,"destinationRevisionId":1,"bucket":"stow-test","region":"us-east-1","prefix":"base/devices/{DEVICE}/","rules":{{"excludes":["*.xyz"],"skipHidden":true,"skipDevArtifacts":true,"requireClientEncryption":false,"maxParallelUploads":2,"storageClass":"STANDARD","serverEncryption":"","kmsKeyArn":""}}}}"#)).unwrap();
    let mut standalone = Config::default();
    standalone.add_folder("/tmp/docs");
    standalone.folders[0].skip_dev_artifacts = Some(false);
    let effective = Policy::parse(&raw, &profile)
        .unwrap()
        .apply(&standalone)
        .unwrap();
    assert_eq!(
        effective.remote_root(&effective.folders[0]),
        format!("base/devices/{DEVICE}/docs/")
    );
    assert!(effective.excludes.iter().any(|rule| rule == "*.xyz"));
    assert_eq!(effective.folders[0].skip_dev_artifacts, Some(true));
    assert!(effective.skip_hidden);
    assert_eq!(effective.parallel_uploads, 2);
    assert_ne!(
        crate::engine::UploadIndex::path_for(&standalone),
        crate::engine::UploadIndex::path_for(&effective)
    );
    assert!(standalone.s3.managed.is_none());
    let mut bad = raw;
    bad.set("prefix", "base/devices/a-different-device/");
    assert!(Policy::parse(&bad, &profile).is_err());
}
