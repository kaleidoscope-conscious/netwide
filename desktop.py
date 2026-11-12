"""
Native Linux PyQt6 Desktop Application for NetPulse.
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
import logging
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
        uvicorn.run("netpulse.server:app", host="127.0.0.1", port=port, log_level="warning")

    t = threading.Thread(target=_run_server, daemon=True)
    t.start()

    for _ in range(30):
        if is_daemon_alive(port):
            break
        time.sleep(0.15)


def send_os_notification(title: str, body: str) -> None:
    try:
        subprocess.Popen(
            ["notify-send", "-i", ICON_PATH, "-a", "NetPulse", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def launch_desktop_app() -> None:
    ensure_daemon_running(DEFAULT_PORT)

    try:
        from PyQt6.QtCore import QObject, QTimer, QUrl, Qt, pyqtSignal
        from PyQt6.QtGui import QAction, QDesktopServices, QIcon, QKeySequence, QShortcut
        from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest, QWebEnginePage
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
    app.setApplicationName("NetPulse")
    app.setApplicationDisplayName("NetPulse — Sovereign Network Intelligence")
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

    status_bar = QStatusBar(win)
    win.setStatusBar(status_bar)
    status_bar.showMessage(
        f"Connected to Local Daemon ({DAEMON_URL})  |  47,035 IEEE OUIs Loaded  |  Shortcuts: [Ctrl+R] Scan Subnet  [Ctrl+E] Export Report  [F11] Fullscreen"
    )

    webview = QWebEngineView(win)

    class _PopupBridgePage(QWebEnginePage):
        """Captures target='_blank' / window.open URLs and routes local paths in-app or external URLs to OS browser."""

        def __init__(self, parent_view: QWebEngineView) -> None:
            super().__init__(parent_view.page().profile(), parent_view)
            self._parent_view = parent_view
            self.urlChanged.connect(self._on_popup_url)

        def _on_popup_url(self, url: QUrl) -> None:
            url_str = url.toString()
            if not url_str or url_str == "about:blank":
                return
            host = url.host().lower()
            if host in ("127.0.0.1", "localhost") or url_str.startswith(DAEMON_URL):
                status_bar.showMessage(f"Navigating to {url_str}…")
                self._parent_view.setUrl(url)
            else:
                status_bar.showMessage(f"Opening external link in system browser: {url_str}")
                if not QDesktopServices.openUrl(url):
                    subprocess.Popen(["xdg-open", url_str], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                send_os_notification("NetPulse External Link", f"Opened {url_str} in browser")
            self.deleteLater()

    class NetPulseWebEnginePage(QWebEnginePage):
        def __init__(self, view: QWebEngineView) -> None:
            super().__init__(view)
            self._view = view
            self._popups: list[_PopupBridgePage] = []

        def createWindow(self, _type: QWebEnginePage.WebWindowType) -> QWebEnginePage:
            popup = _PopupBridgePage(self._view)
            self._popups.append(popup)
            return popup

    custom_page = NetPulseWebEnginePage(webview)
    webview.setPage(custom_page)

    def _on_download_requested(download: QWebEngineDownloadRequest) -> None:
        suggested = download.downloadFileName() or "NetPulse_Download.bin"
        desktop_dir = os.path.expanduser("~/Desktop")
        target_dir = desktop_dir if os.path.isdir(desktop_dir) else os.path.expanduser("~")
        download.setDownloadDirectory(target_dir)
        download.setDownloadFileName(suggested)
        download.accept()
        save_path = os.path.join(target_dir, suggested)
        status_bar.showMessage(f"Downloading {suggested} -> {save_path}…")
        send_os_notification("NetPulse File Saved", f"Downloaded {suggested} to {save_path}")

    webview.page().profile().downloadRequested.connect(_on_download_requested)
    webview.setUrl(QUrl(DAEMON_URL))
    win.setCentralWidget(webview)

    # Native Desktop Command Toolbar
    toolbar = QToolBar("Operations Toolbar", win)
    toolbar.setMovable(False)
    win.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)

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

    def _ensure_on_workbench_then(js_code: str) -> None:
        cur_path = webview.url().path()
        if cur_path not in ("", "/", "/index.html"):
            webview.setUrl(QUrl(f"{DAEMON_URL}/?desktop=1"))
            QTimer.singleShot(450, lambda: webview.page().runJavaScript(js_code))
        else:
            webview.page().runJavaScript(js_code)

    act_home = QAction("🏠 Workbench", win)
    act_home.triggered.connect(lambda: webview.setUrl(QUrl(f"{DAEMON_URL}/?desktop=1")))
    toolbar.addAction(act_home)

    act_scan = QAction("Scan Subnet (Ctrl+R)", win)
    act_scan.triggered.connect(lambda: _ensure_on_workbench_then("triggerManualScan()"))
    toolbar.addAction(act_scan)

    act_cam = QAction("ONVIF & RF Audit", win)
    act_cam.triggered.connect(lambda: _ensure_on_workbench_then("triggerCameraSweep()"))
    toolbar.addAction(act_cam)

    act_speed = QAction("WAN Benchmark", win)
    act_speed.triggered.connect(lambda: _ensure_on_workbench_then("triggerSpeedtest()"))
    toolbar.addAction(act_speed)

    act_oui = QAction("OUI & EUI-64 Lookup (Ctrl+F)", win)
    act_oui.triggered.connect(lambda: _ensure_on_workbench_then("openOuiModal()"))
    toolbar.addAction(act_oui)

    act_toolkit = QAction("All-Around Toolkit (Ctrl+T)", win)
    act_toolkit.triggered.connect(lambda: _ensure_on_workbench_then("openAllAroundToolkitModal()"))
    toolbar.addAction(act_toolkit)

    act_pricing = QAction("💎 Storefront", win)
    act_pricing.triggered.connect(lambda: webview.setUrl(QUrl(f"{DAEMON_URL}/pricing")))
    toolbar.addAction(act_pricing)

    act_launch = QAction("🚀 Launch Hub", win)
    act_launch.triggered.connect(lambda: webview.setUrl(QUrl(f"{DAEMON_URL}/launch")))
    toolbar.addAction(act_launch)

    act_business = QAction("📊 Business", win)
    act_business.triggered.connect(lambda: webview.setUrl(QUrl(f"{DAEMON_URL}/admin")))
    toolbar.addAction(act_business)

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
        tray.setToolTip("NetPulse — Sovereign Network Guardian")
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

    class _PostureBridge(QObject):
        posture_ready = pyqtSignal(str, str, str)

    posture_bridge = _PostureBridge(win)

    def _apply_posture(summary: str, title: str, tooltip: str) -> None:
        status_bar.showMessage(summary)
        win.setWindowTitle(title)
        if tray is not None:
            tray.setToolTip(tooltip)

    posture_bridge.posture_ready.connect(_apply_posture)

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
                title = f"NetPulse — Security Grade {grade} ({score}/100) • {on_cnt} Hosts Online"
                tooltip = f"NetPulse — Grade {grade} ({score}/100) • {on_cnt}/{tot_cnt} Online"
                posture_bridge.posture_ready.emit(summary, title, tooltip)
            except Exception as exc:
                logging.getLogger(__name__).debug("posture poll failed: %s", exc)

        threading.Thread(target=_fetch, daemon=True).start()

    poller = QTimer(win)
    poller.timeout.connect(_poll_live_posture)
    poller.start(12000)
    QTimer.singleShot(1500, _poll_live_posture)

    win.show()
    send_os_notification(
        "NetPulse Active",
        "Sovereign Network & RF Reconnaissance Desktop Suite is online.",
    )
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_desktop_app()
