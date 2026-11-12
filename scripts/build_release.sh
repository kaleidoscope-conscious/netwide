#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT_DIR="$(dirname "$ROOT_DIR")"
DIST_DIR="$ROOT_DIR/dist"
VERSION="4.5.0"

echo "======================================================================"
echo "  NetPulse v${VERSION} — Commercial Release Pipeline"
echo "======================================================================"

echo "[1/5] Running static analysis (pyflakes)..."
python3 -m pyflakes "$ROOT_DIR"/*.py "$ROOT_DIR"/tests/*.py "$ROOT_DIR"/scripts/*.py

echo "[2/5] Running unit & integration test suite (pytest)..."
PYTHONPATH="$PARENT_DIR" python3 -m pytest -q "$ROOT_DIR/tests"

echo "[3/5] Building & cryptographically signing Android 15 APK & Google Play AAB..."
bash "$ROOT_DIR/android/build_apk.sh"

echo "[4/5] Packaging commercial distribution bundle into $DIST_DIR..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

cp "$ROOT_DIR/static/NetPulse-Mobile.apk" "$DIST_DIR/NetPulse-Mobile-v${VERSION}.apk"
cp "$ROOT_DIR/static/NetPulse-Mobile-PlayStore.aab" "$DIST_DIR/NetPulse-Mobile-PlayStore-v${VERSION}.aab"

TAR_NAME="NetPulse-v${VERSION}-Production.tar.gz"
tar -czf "$DIST_DIR/$TAR_NAME" \
    --exclude="dist" \
    --exclude="__pycache__" \
    --exclude=".pytest_cache" \
    --exclude="android/build" \
    --exclude="netpulse_intel.db*" \
    -C "$PARENT_DIR" "$(basename "$ROOT_DIR")"

echo "[5/5] Generating SHA-256 cryptographic release manifest..."
(
  cd "$DIST_DIR"
  sha256sum "$TAR_NAME" "NetPulse-Mobile-v${VERSION}.apk" "NetPulse-Mobile-PlayStore-v${VERSION}.aab" > SHA256SUMS.txt
  cat SHA256SUMS.txt
)

echo "======================================================================"
echo "  SUCCESS: Production artifacts ready in $DIST_DIR"
echo "======================================================================"
