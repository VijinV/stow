# Changelog

## Unreleased

- Added the project’s MIT license file, contributor and security guides, code of conduct, and issue templates.
- Reorganized the README and expanded the self-hosted dashboard instructions.

## [0.3.0](https://github.com/VijinV/stow/releases/tag/v0.3.0) · 2026-11-22

- Added a self-hosted dashboard for device pairing, backup policies, and run history. Paired devices upload directly to S3 with short-lived credentials.
- Added multipart upload resume, backup verification, and browsing and restoring earlier S3 object versions.
- Added per-folder exclusions and backup controls. Stopping a backup interrupts stalled transfers, and **Stop and quit** waits for progress to save.
- Published the Docker dashboard image for Linux amd64.

## [0.2.1](https://github.com/VijinV/stow/releases/tag/v0.2.1) · 2026-11-18

- Released desktop packages for Linux, macOS, and Windows.
- Included standalone S3 backups, encryption, browsing, restore, and file previews.
- Published SHA-256 checksums for the Windows installer and portable executable.
