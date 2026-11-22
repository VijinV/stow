# Security policy

## Report a vulnerability

Use GitHub’s [private vulnerability reporting form](https://github.com/VijinV/stow/security/advisories/new) for suspected vulnerabilities in the desktop app, dashboard, or bundled crates. For other problems, use the [issue tracker](https://github.com/VijinV/stow/issues/new/choose).

Include the affected version, operating system, which component is affected, and the conditions needed to reproduce the issue. Describe the impact and share a minimal reproduction with synthetic data where possible. Remove credentials, pairing codes, recovery keys, and personal backup contents from the report and its attachments.

## Supported versions

Security fixes target the [latest stable release](https://github.com/VijinV/stow/releases/latest) and the default branch. Stow’s custom TLS and file encryption have automated tests. They have not had an independent security audit.

## Deployment and recovery

Keep dashboard administrator tokens, device tokens, and S3 credentials private. Remote dashboards require HTTPS for pairing. Keep a separate copy of each client-side recovery key, and periodically test restoring a file. The [dashboard guide](dashboard/README.md) describes AWS role scoping and the checks to run before deploying against live backups.
