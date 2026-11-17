#!/usr/bin/env bash
# Builds dist/backup-taker_<version>_<arch>.deb and a portable .tar.gz (with install.sh).
# Usage: packaging/linux/build-deb.sh [target-triple]
set -euo pipefail
cd "$(dirname "$0")/../.."
TARGET="${1:-x86_64-unknown-linux-gnu}"
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
case "$TARGET" in
  x86_64-*) ARCH=amd64 ;;
  aarch64-*) ARCH=arm64 ;;
  *) echo "unsupported target $TARGET" >&2; exit 1 ;;
esac
cargo build --release --locked --target "$TARGET"
BIN="target/$TARGET/release/backup-taker"
mkdir -p dist
ROOT="$(mktemp -d)/backup-taker_${VERSION}_${ARCH}"
install -Dm755 "$BIN" "$ROOT/usr/bin/backup-taker"
install -Dm644 packaging/linux/backup-taker.desktop "$ROOT/usr/share/applications/backup-taker.desktop"
install -Dm644 assets/icon-256.png "$ROOT/usr/share/icons/hicolor/256x256/apps/backup-taker.png"
install -Dm644 assets/icon-512.png "$ROOT/usr/share/icons/hicolor/512x512/apps/backup-taker.png"
install -Dm644 assets/icon.svg "$ROOT/usr/share/icons/hicolor/scalable/apps/backup-taker.svg"
mkdir -p "$ROOT/DEBIAN"
SIZE_KB="$(du -sk "$ROOT/usr" | cut -f1)"
cat > "$ROOT/DEBIAN/control" <<CTL
Package: backup-taker
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Installed-Size: $SIZE_KB
Maintainer: Stow <noreply@backuptaker.invalid>
Description: Back up folders to Amazon S3 or S3-compatible storage
 Desktop app that backs up the folders you choose to an S3 bucket,
 incrementally, with optional automatic schedules.
CTL
cat > "$ROOT/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
exit 0
PI
chmod 755 "$ROOT/DEBIAN/postinst"
dpkg-deb --root-owner-group --build "$ROOT" "dist/backup-taker_${VERSION}_${ARCH}.deb"

# Portable tarball for non-Debian distros.
TAR="$(mktemp -d)/backup-taker-${VERSION}-linux-${ARCH}"
mkdir -p "$TAR"
cp "$BIN" "$TAR/backup-taker"
cp packaging/linux/backup-taker.desktop assets/icon-256.png "$TAR/"
cp packaging/linux/install.sh "$TAR/install.sh"
chmod 755 "$TAR/install.sh" "$TAR/backup-taker"
tar -C "$(dirname "$TAR")" -czf "dist/backup-taker-${VERSION}-linux-${ARCH}.tar.gz" "$(basename "$TAR")"
ls -la dist
