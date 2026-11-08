#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$APP_DIR")"
PYTHON_BIN="$(command -v python3)"

echo "======================================================================"
echo "  NetPulse // OmniSight v4.5.0 — Production Installer"
echo "======================================================================"

# 1. Install systemd user service
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

cat > "$SYSTEMD_USER_DIR/netpulse-guardian.service" <<EOF
[Unit]
Description=NetPulse // OmniSight Sovereign Network & RF Intelligence Daemon
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=PYTHONPATH=$PARENT_DIR
ExecStart=$PYTHON_BIN -m netpulse serve --host 0.0.0.0 --port 8765
Restart=always
RestartSec=4

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now netpulse-guardian.service

# 2. Install Desktop Launcher (.desktop)
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"

cat > "$APPS_DIR/netpulse.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetPulse Workbench
GenericName=Sovereign Network & RF Intelligence Suite
Comment=Deep LAN Fingerprinting, 802.11 TSF De-Cloaking, Wire DPI & Endpoint Control
Exec=env PYTHONPATH=$PARENT_DIR $PYTHON_BIN -m netpulse desktop
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
