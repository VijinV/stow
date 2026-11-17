# Backup Taker

A Rust desktop app for backing up folders to Amazon S3 and S3-compatible storage. No third-party Rust crates: the GUI, HTTP/S3 client, TLS implementation and file encryption are implemented in this repository.

## Using the app

1. Open **Folders** and select the directories to back up; set exclusion patterns if needed.
2. In **Storage**, configure the bucket, region/endpoint and access credentials. Test the connection and save.
3. Optionally choose **SSE-S3** or **SSE-KMS** for encryption at the storage provider. Your provider must support that mode and your credentials must have the necessary permissions. Bucket default leaves the decision to the bucket.
4. For encryption before upload, enable **Encrypt file contents before uploading**, generate a recovery key, copy it to a separate safe location, then save. Both encryption layers may be used together. Contents use authenticated ChaCha20-Poly1305 encryption; object names and approximate sizes remain visible.
5. Click **Back up now** in Overview. The first run uploads all included files. Later runs compare size and modification time with a local index and upload new/changed files in full. Select **Upload all files on the next manual backup** to bypass the index. Encryption policy changes also invalidate the index.
6. Use **Browse S3** to navigate bucket folders. **Refresh totals & files** fetches current object counts and bytes for the entire bucket, including other devices/prefixes. These totals exclude old versions and unfinished multipart uploads. They are refreshed snapshots, not continuous monitoring.
7. Select a file or folder and choose **Download / restore file** or **Restore folder**. Pick a destination directory; folder contents are restored into it. Existing files are never overwritten. Local deletion does not delete S3 copies. Stop/Cancel interrupts transfers and encryption/decryption.
8. **Preview** fetches a supported image, video, audio, PDF or text object from S3 and decrypts it locally when necessary. The browser opens a private loopback preview. The full file downloads before preview opens; seeking works after download. Browser codec support varies. Text is limited to 2 MiB; HTML, SVG, executables and office documents are not rendered. Restore unsupported formats to open with a suitable app.
9. **History** records backup run counts, bytes and failures. **Schedule** installs an operating-system schedule for unattended backups.

## Encryption and recovery

- Remote transfers should use HTTPS. Custom HTTP endpoints show a warning and transfer data without TLS.
- Recovery keys contain 256 random bits (64 hexadecimal characters). Keep a separate copy: lost keys cannot be recovered from S3. Losing local configuration without saving the key makes encrypted backups unrecoverable.
- The app retains one recovery key in its settings. If you change keys, retain every old key: unchanged/deleted objects can still require earlier keys. Paste the matching key in Storage and save before restoring or previewing them. Do not run a backup with a historical key unless you intend to re-encrypt current files with it.
- Changing encryption settings affects subsequent successful uploads; it does not change old object versions or deleted local files still in S3. Enable bucket versioning separately if you need historical revisions.
- Windows uses DPAPI and macOS uses Keychain when available; failures fall back to a private plaintext configuration. Linux stores secrets/recovery keys in a user-only configuration file, without OS encryption.
- Preview caches are private to the user and expire after 15 minutes or a normal app exit. A crash or forced termination can leave temporary cache files. Local disk encryption is advisable when handling sensitive content.
- This project's custom TLS/crypto code has automated tests but has not had an independent security audit.

## Build and test

```sh
cargo test --workspace --locked
cargo build --release --locked
./target/release/backup-taker
```

Local S3 integration tests require disposable servers. Defaults are localhost ports 9000 and 8333 with test-only credentials. Override `BT_S3_ENDPOINTS`, `BT_S3_KEY` and `BT_S3_SECRET` as needed.

```sh
cargo test --bin backup-taker feature_tests::encrypted_backup_browse_restore_end_to_end -- --ignored --test-threads=1
cargo test -p bt-s3 --test integration -- --ignored --test-threads=1
```

Linux packages: `bash packaging/linux/build-deb.sh`. macOS app/DMG: `bash packaging/macos/build-app.sh` on macOS. Windows installer: use the existing Inno Setup configuration in `packaging/windows/installer.iss`. CI builds platform packages on native runners.

Restore on Linux uses directory descriptors to resist symlink swaps. Other platforms reject existing symlinks but do not provide the same guarantee against concurrent malicious filesystem changes. Restores require a filesystem supporting hard links for atomic no-overwrite publication.
