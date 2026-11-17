#!/usr/bin/env bash
# Per-user install for the portable tarball: ~/.local/bin + menu entry. Run from the unpacked folder.
set -euo pipefail
cd "$(dirname "$0")"
BIN="$HOME/.local/bin"; APPS="$HOME/.local/share/applications"; ICONS="$HOME/.local/share/icons/hicolor/256x256/apps"
mkdir -p "$BIN" "$APPS" "$ICONS"
install -m755 backup-taker "$BIN/backup-taker"
install -m644 icon-256.png "$ICONS/backup-taker.png"
sed "s|^Exec=.*|Exec=$BIN/backup-taker|" backup-taker.desktop > "$APPS/backup-taker.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APPS" || true
echo "Installed. Open 'Stow' from your applications menu, or run $BIN/backup-taker"
