# Stow

**Your files, safely kept.**

A Rust desktop app for backing up folders to Amazon S3 and S3-compatible storage. No third-party Rust crates: the GUI, HTTP/S3 client, TLS implementation and file encryption are implemented in this repository.

## Using the app

1. Open **Folders** and select the directories to back up. Stow scans newly added folders in the background and shows their included size, synced size, and pending size. These figures follow the exclusion settings and use the local upload index to estimate what is synced. Use **Refresh sizes** after changing local files.
2. For standalone backups, open **Dashboard → Set up standalone storage**, then configure the bucket, region/endpoint and access credentials. Test the connection and save.
3. Optionally choose **SSE-S3** or **SSE-KMS** for encryption at the storage provider. Your provider must support that mode and your credentials must have the necessary permissions. Bucket default leaves the decision to the bucket.
4. For encryption before upload, enable **Encrypt file contents before uploading**, generate a recovery key, copy it to a separate safe location, then save. Both encryption layers may be used together. Contents use authenticated ChaCha20-Poly1305 encryption; object names and approximate sizes remain visible.
5. Click **Back up now** in Overview. Stow scans the current files and starts uploading as it finds files that need to be backed up. The first run uploads all included files. Later runs compare size and modification time with the local index. Select **Upload all files on the next manual backup** to bypass the index. Encryption policy changes also invalidate the index.
6. Use **Browse backups** to navigate bucket folders. **Refresh totals & files** fetches current object counts and bytes for the entire bucket, including other devices/prefixes. These totals exclude old versions and unfinished multipart uploads. They are refreshed snapshots, not continuous monitoring.
7. Select a file or folder and choose **Download / restore file** or **Restore folder**. Pick a destination directory; folder contents are restored into it. Existing files are never overwritten. Local deletion does not delete S3 copies. Stop/Cancel interrupts transfers and encryption/decryption.
8. **Preview** fetches a supported image, video, audio, PDF or text object from S3 and decrypts it locally when necessary. The browser opens a private loopback preview. The full file downloads before preview opens; seeking works after download. Browser codec support varies. Text is limited to 2 MiB; HTML, SVG, executables and office documents are not rendered. Restore unsupported formats to open with a suitable app.
9. **History** records backup run counts, bytes and failures. **Schedule** installs an operating-system schedule for unattended backups.

Run `backup-taker --dry-run` to estimate the pending upload from the command line. Add `--full` to estimate a full upload, or run `backup-taker --backup-now --full` to perform one.

### Connect to a Stow dashboard

1. Configure Amazon S3 and generate a pairing code in the [web dashboard](dashboard/README.md).
2. Open **Dashboard** in Stow, enter the website address and pairing code, and choose **Connect device**.
3. Review the assigned bucket and prefix, then choose **Use dashboard for backups**. Stow fetches the current rules before each run. Manual and scheduled backups use the device’s temporary credentials to upload directly to S3. The dashboard shows run progress and results.
4. Use **Folders** and **Schedule** for local choices. If the dashboard requires encryption, save your recovery key in **Encryption**. You can return to standalone settings from **Dashboard**.

### Upload speed and resume

In **Schedule**, use **Files uploaded at the same time** to set the shared concurrency limit for file uploads and multipart requests. Stow can send up to four parts of one large file at once within that limit. After a stop, disconnect, or restart, run the backup again to resume an unchanged multipart upload. Completed parts count toward transfer progress. Smaller files that use a single request restart from the beginning.

Resuming an incomplete upload requires permission to list its parts. Stow may temporarily retain a local encrypted copy of a large file while the transfer is incomplete. An incomplete-upload lifecycle rule on the bucket can clean up parts from uploads that are never resumed.

### Verification and earlier versions

- Choose **Verify → Verify now** or run `backup-taker --verify`. Stow records when each folder was checked, compares recorded upload ETags with the current objects in S3, and shows missing, changed, and pending files. The check reads object listings. To test whether a file can be decrypted and opened, restore a copy.
- In **Browse S3**, select a file and choose **File versions…**. Use **Browse versions…** to find older versions of deleted files by key prefix. Select a version and choose **Restore version…**. Your storage provider needs to support version listings and version downloads, and the credentials need access to both. Configure bucket versioning with your provider.

### Folder rules

Under **Folders → Global backup rules**, turn on **Skip dependencies and build output** to exclude subfolders named `node_modules`, `build`, `dist`, `target`, and `.next`. For CLI setup, use `backup-taker --set skip_dev_artifacts=true`.

Choose **Backup rules** next to a folder to add its own exclusion patterns or override the global dependency and build-output setting. Global filename patterns and hidden-file settings still apply. Folder rules are used by manual and scheduled backups, previews, and size estimates.

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
