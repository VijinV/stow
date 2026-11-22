# Stow

Stow backs up folders directly to Amazon S3 and S3-compatible storage from Windows, macOS, and Linux. Run it as a standalone desktop app or pair it with a self-hosted dashboard that manages backup policies and shows run status.

[Download Stow](https://github.com/VijinV/stow/releases/latest) · [User guide](docs/usage.md) · [Dashboard setup](dashboard/README.md) · [Changelog](CHANGELOG.md)

## Install

Download the package for your platform from [GitHub Releases](https://github.com/VijinV/stow/releases/latest).

- **Windows x64** — Run the setup installer or open the portable executable. SHA-256 checksums are provided for both.
- **macOS** — Open the universal DMG and drag **Stow** to Applications.
- **Linux amd64** — Install the Debian package or extract and run the tarball. The desktop app uses X11.

## Start a backup

1. Open **Folders** and select the directories you want to back up.
2. Choose how Stow gets its storage settings:
   - **Standalone** — Open **Dashboard → Set up standalone storage**. Enter your bucket, endpoint or region, and access credentials, then test and save the connection.
   - **Dashboard-managed** — [Run the dashboard](dashboard/README.md) and configure its AWS destination. Create a device pairing code in the web dashboard. In Stow, open **Dashboard**, enter the dashboard address and code, and choose **Use dashboard for backups** after pairing.
3. In **Overview**, choose **Back up now**. Use **Schedule** to run future backups automatically.

The dashboard gives paired devices backup rules and temporary AWS credentials scoped to their own S3 prefix. Devices send file contents directly to S3 and report run status to the dashboard.

## Backup and restore

- Incremental backups use a local upload index. Large, unchanged files can resume a multipart upload after a stop or restart.
- **Browse backups** can preview supported files and restore files or folders without overwriting existing local files. S3 versioning provides access to earlier object versions.
- **Verify** compares recorded uploads with the current S3 objects. Restore a sample file to check that it can be opened and, if applicable, decrypted.
- **Encryption** can protect file contents before upload. Keep a separate copy of the recovery key to restore encrypted backups.

See the [user guide](docs/usage.md) for exclusions, encryption and recovery, verification, and command-line usage.

## Build from source

The desktop app is written in Rust. The optional dashboard uses Rust/Axum, SQLite, and React/Vite.

```sh
cargo test --workspace --locked
cargo build --release --locked
```

The desktop binary is `target/release/backup-taker` (`backup-taker.exe` on Windows). See the [contributing guide](CONTRIBUTING.md) for prerequisites, dashboard tests, and native packaging. You can build the [dashboard container](dashboard/README.md#run-with-docker) from the public source.

## Project

- [Report a bug or request a feature](https://github.com/VijinV/stow/issues/new/choose)
- [Contribute to Stow](CONTRIBUTING.md)
- [Report a security vulnerability privately](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

Stow is released under the [MIT License](LICENSE).
