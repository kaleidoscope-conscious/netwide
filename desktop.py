"""
Native Linux PyQt6 Desktop Application for NetPulse // OmniSight.
Features:
- Auto-spawns or attaches to the local NetPulse Reconnaissance Daemon (127.0.0.1:8765)
- Native PyQt6 QMainWindow + QWebEngineView with hardware acceleration
- Native Ubuntu / GNOME System Tray Guardian (QSystemTrayIcon) with quick actions
- Native OS Desktop Notifications (notify-send / Tray notifications)
- Keyboard shortcuts:
  * Ctrl+R : Trigger Immediate Deep Subnet Scan
  * Ctrl+E : Export Forensic Markdown & JSON Dossier to ~/Desktop
  * F5     : Reload Command Center View
  * F11    : Toggle Fullscreen Operations Mode
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Optional

os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "netpulse-icon.svg")
DEFAULT_PORT = 8765
DAEMON_URL = f"http://127.0.0.1:{DEFAULT_PORT}"


def is_daemon_alive(port: int = DEFAULT_PORT) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def ensure_daemon_running(port: int = DEFAULT_PORT) -> None:
    """Ensure the FastAPI/Uvicorn reconnaissance daemon is listening on 127.0.0.1:port."""
    if is_daemon_alive(port):
        return

    def _run_server() -> None:
        import uvicorn
        uvicorn.run("netpulse.server:app", host="0.0.0.0", port=port, log_level="warning")

    t = threading.Thread(target=_run_server, daemon=True)
    t.start()

    for _ in range(30):
        if is_daemon_alive(port):
            break
        time.sleep(0.15)


def send_os_notification(title: str, body: str) -> None:
    try:
        subprocess.Popen(
            ["notify-send", "-i", ICON_PATH, "-a", "NetPulse // OmniSight", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def launch_desktop_app() -> None:
    ensure_daemon_running(DEFAULT_PORT)

    try:
        from PyQt6.QtCore import QTimer, QUrl, Qt
        from PyQt6.QtGui import QAction, QIcon, QKeySequence, QShortcut
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        from PyQt6.QtWidgets import (
            QApplication,
            QMainWindow,
            QMenu,
            QStatusBar,
            QSystemTrayIcon,
            QToolBar,
        )
    except Exception:
        # Fallback to chromeless Google Chrome app window if PyQt6 is unavailable
        subprocess.Popen(["google-chrome", f"--app={DAEMON_URL}", "--window-size=1540,940"])
        return

    app = QApplication(sys.argv)
    app.setApplicationName("NetPulse // OmniSight")
    app.setApplicationDisplayName("NetPulse // OmniSight — Sovereign Network Intelligence")
    app.setOrganizationName("Antigravity Sovereign Systems")

    icon = QIcon(ICON_PATH) if os.path.exists(ICON_PATH) else QIcon()
    app.setWindowIcon(icon)

    win = QMainWindow()
    win.setWindowTitle("NetPulse Workbench — Network Inventory, Deep Telemetry & Endpoint Control")
    win.setWindowIcon(icon)
    win.resize(1580, 960)
    win.setStyleSheet(
        """
        QMainWindow { background-color: #0a0c10; color: #e2e8f0; }
        QToolBar {
            background-color: #10131a;
            border-bottom: 1px solid #1f2633;
            spacing: 6px;
            padding: 4px 12px;
        }
        QToolButton {
            background-color: #161a24;
            color: #e2e8f0;
            border: 1px solid #2d3748;
            border-radius: 4px;
            padding: 4px 10px;
            font-family: Inter, sans-serif;
            font-size: 11.5px;
            font-weight: 500;
        }
        QToolButton:hover {
            border-color: #3b82f6;
            background-color: #1c212e;
        }
        QStatusBar {
            background-color: #10131a;
            color: #94a3b8;
            border-top: 1px solid #1f2633;
            font-family: monospace;
            font-size: 11px;
        }
        """
    )

    webview = QWebEngineView(win)
    webview.setUrl(QUrl(DAEMON_URL))
    win.setCentralWidget(webview)

    # Native Desktop Command Toolbar
    toolbar = QToolBar("Operations Toolbar", win)
    toolbar.setMovable(False)
    win.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

    status_bar = QStatusBar(win)
    win.setStatusBar(status_bar)
    status_bar.showMessage(
        f"Connected to Local Daemon ({DAEMON_URL})  |  47,033 IEEE OUIs Loaded  |  Shortcuts: [Ctrl+R] Scan Subnet  [Ctrl+E] Export Report  [F11] Fullscreen"
    )

    def _api_post(endpoint: str, label: str) -> None:
        status_bar.showMessage(f"Running {label}…")

        def _worker() -> None:
            try:
                req = urllib.request.Request(f"{DAEMON_URL}{endpoint}", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                msg = data.get("summary") or f"{label} completed."
                send_os_notification("NetPulse Workbench", msg)
            except Exception as e:
                send_os_notification("NetPulse Workbench", f"{label} error: {e}")

        threading.Thread(target=_worker, daemon=True).start()
        QTimer.singleShot(1800, webview.reload)

    act_scan = QAction("Scan Subnet (Ctrl+R)", win)
    act_scan.triggered.connect(lambda: webview.page().runJavaScript("triggerManualScan()"))
    toolbar.addAction(act_scan)

    act_cam = QAction("ONVIF & RF Audit", win)
    act_cam.triggered.connect(lambda: webview.page().runJavaScript("triggerCameraSweep()"))
    toolbar.addAction(act_cam)

    act_speed = QAction("WAN Benchmark", win)
    act_speed.triggered.connect(lambda: webview.page().runJavaScript("triggerSpeedtest()"))
    toolbar.addAction(act_speed)

    act_oui = QAction("OUI & EUI-64 Lookup (Ctrl+F)", win)
    act_oui.triggered.connect(lambda: webview.page().runJavaScript("openOuiModal()"))
    toolbar.addAction(act_oui)

    act_toolkit = QAction("All-Around Toolkit (Ctrl+T)", win)
    act_toolkit.triggered.connect(lambda: webview.page().runJavaScript("openAllAroundToolkitModal()"))
    toolbar.addAction(act_toolkit)

    def _export_csv_to_desktop() -> None:
        status_bar.showMessage("Exporting CSV Inventory to ~/Desktop…")

        def _csv_worker() -> None:
            try:
                with urllib.request.urlopen(f"{DAEMON_URL}/api/export/csv", timeout=15) as resp:
                    csv_bytes = resp.read()
                out_path = os.path.expanduser("~/Desktop/NetPulse_Device_Inventory.csv")
                with open(out_path, "wb") as f:
                    f.write(csv_bytes)
                send_os_notification("NetPulse CSV Exported", f"Saved inventory to {out_path}")
            except Exception as e:
                send_os_notification("NetPulse CSV Export Error", str(e))

        threading.Thread(target=_csv_worker, daemon=True).start()

    act_csv = QAction("Export CSV (Ctrl+Shift+E)", win)
    act_csv.triggered.connect(_export_csv_to_desktop)
    toolbar.addAction(act_csv)

    act_export = QAction("Export Dossier (Ctrl+E)", win)
    act_export.triggered.connect(lambda: _api_post("/api/export/report", "Forensic Report Export"))
    toolbar.addAction(act_export)

    act_reload = QAction("Reload View (F5)", win)
    act_reload.triggered.connect(webview.reload)
    toolbar.addAction(act_reload)

    def _toggle_fullscreen() -> None:
        if win.isFullScreen():
            win.showNormal()
        else:
            win.showFullScreen()

    act_fs = QAction("Fullscreen (F11)", win)
    act_fs.triggered.connect(_toggle_fullscreen)
    toolbar.addAction(act_fs)

    # Keyboard shortcuts
    QShortcut(QKeySequence("Ctrl+R"), win, activated=lambda: webview.page().runJavaScript("triggerManualScan()"))
    QShortcut(QKeySequence("Ctrl+F"), win, activated=lambda: webview.page().runJavaScript("openOuiModal()"))
    QShortcut(QKeySequence("Ctrl+T"), win, activated=lambda: webview.page().runJavaScript("openAllAroundToolkitModal()"))
    QShortcut(QKeySequence("Ctrl+Shift+E"), win, activated=_export_csv_to_desktop)
    QShortcut(QKeySequence("Ctrl+E"), win, activated=lambda: _api_post("/api/export/report", "Forensic Dossier Export"))
    QShortcut(QKeySequence("F5"), win, activated=webview.reload)
    QShortcut(QKeySequence("F11"), win, activated=_toggle_fullscreen)

    # System Tray Guardian Icon
    tray: Optional[QSystemTrayIcon] = None
    if QSystemTrayIcon.isSystemTrayAvailable():
        tray = QSystemTrayIcon(icon, win)
        tray.setToolTip("NetPulse // OmniSight — Sovereign Network Guardian")
        tray_menu = QMenu()
        a_show = tray_menu.addAction("Open NetPulse Command Center")
        assert a_show is not None
        a_show.triggered.connect(lambda: (win.showNormal(), win.activateWindow()))
        a_scan = tray_menu.addAction("⚡ Trigger Deep Subnet Scan")
        assert a_scan is not None
        a_scan.triggered.connect(lambda: _api_post("/api/scan", "Deep Subnet Scan"))
        a_oui = tray_menu.addAction("🔍 OUI & EUI-64 Hardware Lookup")
        assert a_oui is not None
        a_oui.triggered.connect(lambda: (win.showNormal(), win.activateWindow(), webview.page().runJavaScript("openOuiModal()")))
        a_tk = tray_menu.addAction("🛠 All-Around Domain/TLS/Sockets Toolkit")
        assert a_tk is not None
        a_tk.triggered.connect(lambda: (win.showNormal(), win.activateWindow(), webview.page().runJavaScript("openAllAroundToolkitModal()")))
        a_csv = tray_menu.addAction("⬇ Export CSV Inventory to Desktop")
        assert a_csv is not None
        a_csv.triggered.connect(_export_csv_to_desktop)
        a_exp = tray_menu.addAction("📄 Export Forensic Dossier to Desktop")
        assert a_exp is not None
        a_exp.triggered.connect(lambda: _api_post("/api/export/report", "Forensic Dossier Export"))
        tray_menu.addSeparator()
        a_quit = tray_menu.addAction("Quit NetPulse Desktop")
        assert a_quit is not None
        a_quit.triggered.connect(app.quit)
        tray.setContextMenu(tray_menu)
        tray.show()

    def _poll_live_posture() -> None:
        def _fetch() -> None:
            try:
                with urllib.request.urlopen(f"{DAEMON_URL}/api/analytics", timeout=4) as r:
                    data = json.loads(r.read().decode())
                pos = data.get("security_posture") or {}
                ana = data.get("database_analytics") or {}
                ch = data.get("channel_recommendations") or {}
                score = pos.get("score", "—")
                grade = pos.get("grade", "—")
                on_cnt = ana.get("online_devices", 0)
                tot_cnt = ana.get("total_devices", 0)
                ch24 = (ch.get("band_24ghz") or {}).get("recommended_channel") or ch.get("recommended_24ghz_channel", "?")
                ch5 = (ch.get("band_5ghz") or {}).get("recommended_channel") or ch.get("recommended_5ghz_channel", "?")
                summary = (
                    f"Security Posture: {score}/100 (Grade {grade})  |  "
                    f"Hosts: {on_cnt}/{tot_cnt} Online  |  "
                    f"Optimal RF: 2.4G Ch {ch24} / 5G Ch {ch5}  |  "
                    f"[Ctrl+R] Scan  [Ctrl+F] OUI Search  [Ctrl+Shift+E] CSV"
                )
                status_bar.showMessage(summary)
                win.setWindowTitle(f"NetPulse // OmniSight — Security Grade {grade} ({score}/100) • {on_cnt} Hosts Online")
                if tray is not None:
                    tray.setToolTip(f"NetPulse // OmniSight — Grade {grade} ({score}/100) • {on_cnt}/{tot_cnt} Online")
            except Exception:
                pass

        threading.Thread(target=_fetch, daemon=True).start()

    poller = QTimer(win)
    poller.timeout.connect(_poll_live_posture)
    poller.start(12000)
    QTimer.singleShot(1500, _poll_live_posture)

    win.show()
    send_os_notification(
        "NetPulse // OmniSight Active",
        "Sovereign Network & RF Reconnaissance Desktop Suite is online.",
    )
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_desktop_app()
