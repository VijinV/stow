# S3 browsing, restore, preview and encryption implementation plan

Goal: Extend the existing Rust-only desktop app with both client-side and S3-managed encryption, browsing, safe restore, live storage totals, and media previews. User explicitly authorized implementation and selected both encryption types.

Design: Retain existing custom Rust GUI/S3/TLS crates. Add authenticated streaming file encryption using the existing ChaCha20-Poly1305 primitive and a generated 256-bit recovery key. File names remain visible. Preserve compatibility with plaintext objects. Changing encryption settings changes the upload-index namespace. Add SSE-S3/SSE-KMS headers to normal and multipart uploads. Recover into a destination selected by the user, refusing overwrites and unsafe object paths. Browser displays a refreshed bucket inventory with total bytes and objects, virtual folders and selection actions. Stream ordinary media through signed expiring S3 URLs in a browser preview, with local decrypted preview for client-encrypted files. No credentials embedded in HTML. Preserve incremental behavior and add explicit full upload.

Approaches considered: S3 encryption alone would omit requested client encryption; client encryption alone would omit S3 controls. Both independently selectable is the selected approach. Native decoding of all video/image/document formats conflicts with the dependency-free Rust constraint, so use the OS browser's existing media support, with a local Rust preview service where needed.

Tasks:
- [x] Encryption implementation and tests: config, file envelope, S3 upload headers and engine integration.
- [x] Browse/restore backend and tests: safe paths, inventory, atomic no-overwrite restore, progress/cancel.
- [x] Preview backend and tests: authenticated media delivery, HTML escaping, supported type handling.
- [x] Desktop controls: browse page, encryption/recovery controls, restore picker, status and totals, full-upload action.
- [x] Verify workspace tests, end-to-end local S3 cases, build release, launch new binary and document limitations.

Validation: wrong-key/tamper/truncation rejection, multi-chunk/empty encryption round trips; traversal and overwrite refusal; listing pagination; encrypted upload/restore byte identity; preview request access control and ranges; existing tests; desktop interaction and release build. Real AWS and Windows/macOS execution remain pending suitable environments/credentials.

Verification: 104 workspace tests passed; six existing S3 integration tests passed against both local servers; encrypted backup/browse/restore integration passed against both servers including multipart data. Linux deb/tar and Windows GNU portable EXE built. Both macOS target checks passed. Desktop browsing, encrypted PNG/MP4 preview and restore picker exercised. Review findings fixed and independently rechecked. No third-party Rust crates added. Full-file preview cache is the implemented alternative to direct presigned streaming.
