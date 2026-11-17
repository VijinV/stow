#!/usr/bin/env bash
# macOS only. Builds a universal (arm64 + x86_64) "Backup Taker.app" and a .dmg in dist/.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --locked --target aarch64-apple-darwin
cargo build --release --locked --target x86_64-apple-darwin
APP="dist/Backup Taker.app"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/backup-taker" \
  target/aarch64-apple-darwin/release/backup-taker target/x86_64-apple-darwin/release/backup-taker
sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
ICONSET="$(mktemp -d)/AppIcon.iconset"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s assets/icon-512.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); sips -z $d $d assets/icon-512.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
codesign --force --deep -s - "$APP"   # ad-hoc signature (use a Developer ID to distribute widely)
STAGE="$(mktemp -d)"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Backup Taker" -srcfolder "$STAGE" -ov -format UDZO "dist/BackupTaker-${VERSION}-macos-universal.dmg"
ls -la dist
