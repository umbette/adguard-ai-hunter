#!/usr/bin/env bash
set -euo pipefail

# Converts the Chromium MV3 Sentinel Shield extension into an iOS + macOS Safari Web Extension project.
# Requires macOS with Xcode command-line tools (`xcrun safari-web-extension-converter`).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_DIR="$ROOT_DIR/extension"
OUT_DIR="${1:-$ROOT_DIR/build/safari-extension}"

if ! command -v xcrun >/dev/null 2>&1; then
  echo "Error: xcrun is only available on macOS with Xcode installed."
  echo "Run this script on macOS to generate the iOS/macOS Safari Web Extension Xcode project from: $EXT_DIR"
  exit 1
fi

mkdir -p "$(dirname "$OUT_DIR")"
xcrun safari-web-extension-converter "$EXT_DIR" \
  --project-location "$OUT_DIR" \
  --app-name "Sentinel Shield" \
  --bundle-identifier "com.umbette.sentinelshield" \
  --force

echo "✅ Safari Web Extension Xcode project generated at: $OUT_DIR"
echo "   Open it in Xcode and deploy directly to macOS Safari or iPhone/iPad Safari."
