#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$APP_DIR")"
PYTHON_BIN="$(command -v python3)"

echo "======================================================================"
echo "  NetPulse v4.5.0 — Production Installer"
echo "======================================================================"

# 1. Create a virtualenv and install runtime dependencies
#    (install.sh previously started the service WITHOUT installing Python deps —
#    guaranteed crash on any clean machine).
VENV_DIR="$APP_DIR/.venv"
RUNTIME_DEPS=( "fastapi>=0.110.0" "uvicorn[standard]>=0.29.0" "pydantic>=2.6.0" "rich>=13.7.0" "qrcode>=7.4.2" "cryptography>=42.0.0" "PyQt6>=6.6.0" "PyQt6-WebEngine>=6.6.0" )
if "$PYTHON_BIN" -m venv "$VENV_DIR" 2>/dev/null; then
    echo "[*] Installing runtime dependencies into $VENV_DIR ..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet "${RUNTIME_DEPS[@]}"
    VENV_PY="$VENV_DIR/bin/python"
else
    echo "[!] python3-venv unavailable — falling back to user-site pip install"
    "$PYTHON_BIN" -m pip install --user --quiet "${RUNTIME_DEPS[@]}"
    VENV_PY="$PYTHON_BIN"
fi

# 2. Install systemd user service
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

cat > "$SYSTEMD_USER_DIR/netpulse-guardian.service" <<EOF
[Unit]
Description=NetPulse Sovereign Network & RF Intelligence Daemon
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PYTHONPATH=$PARENT_DIR
Environment=PYTHONUNBUFFERED=1
ExecStart=$VENV_PY -m netpulse serve --host 0.0.0.0 --port 8765
Restart=always
RestartSec=4

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now netpulse-guardian.service

# 3. Install Desktop Launcher (.desktop)
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"

cat > "$APPS_DIR/netpulse.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetPulse Workbench
GenericName=Sovereign Network & RF Intelligence Suite
Comment=Deep LAN Fingerprinting, 802.11 TSF De-Cloaking, Wire DPI & Endpoint Control
Exec=env PYTHONPATH=$PARENT_DIR $VENV_PY -m netpulse desktop
Icon=$APP_DIR/static/netpulse-icon.svg
Terminal=false
Categories=Network;Security;System;Monitor;
StartupNotify=true
EOF

chmod +x "$APPS_DIR/netpulse.desktop"

echo "[✓] systemd service 'netpulse-guardian.service' enabled & running on :8765"
echo "[✓] Desktop launcher installed to $APPS_DIR/netpulse.desktop"
echo "[✓] Admin Master Token saved to ~/.config/netpulse/admin.token (0600)"
echo "----------------------------------------------------------------------"
echo "  Workbench URL:  http://127.0.0.1:8765"
echo "  Storefront URL: http://127.0.0.1:8765/pricing"
echo "  Mobile App URL: http://127.0.0.1:8765/mobile"
echo "  Health Check:   http://127.0.0.1:8765/api/health"
echo "======================================================================"
