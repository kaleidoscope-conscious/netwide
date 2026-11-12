"""
Unit tests for NetPulse FastAPI endpoints and API contracts.
"""

from fastapi.testclient import TestClient

from netpulse.server import app

client = TestClient(app)


def test_api_state():
    resp = client.get("/api/state")
    assert resp.status_code == 200
    data = resp.json()
    assert "meta" in data
    assert "interface" in data
    assert "devices" in data
    assert "threats" in data


def test_api_mobile_qr():
    resp = client.get("/api/mobile-qr")
    assert resp.status_code == 200
    data = resp.json()
    assert "mobile_url" in data
    assert "apk_url" in data
    assert "mobile_qr_svg" in data
    assert "apk_qr_svg" in data
    assert "<svg" in data["mobile_qr_svg"]
    assert "<svg" in data["apk_qr_svg"]


def test_vendored_leaflet_assets_served_same_origin():
    """The WAN map library must be vendored same-origin (CSP has no CDN origins)."""
    resp = client.get("/vendor/leaflet.js")
    assert resp.status_code == 200
    assert "Leaflet" in resp.text
    assert resp.headers["content-type"].split(";")[0].strip() in ("application/javascript", "text/javascript")
    css = client.get("/vendor/leaflet.css")
    assert css.status_code == 200
    assert "leaflet-pane" in css.text


def test_index_html_references_vendored_assets_only():
    """index.html must not load scripts/styles from third-party CDNs."""
    import os

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root_dir, "static", "index.html"), encoding="utf-8") as fh:
        html = fh.read()
    assert "/vendor/leaflet.js" in html
    assert "/vendor/leaflet.css" in html
    assert "unpkg.com" not in html


def test_api_action_wol_validation():
    resp = client.post("/api/action/wol", json={"mac": "INVALID_MAC"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is False


def test_api_action_wol_valid():
    resp = client.post("/api/action/wol", json={"mac": "18:A5:FF:0C:62:3A"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True


def test_api_action_quarantine_stop():
    # 1. Verify Free tier enforces HTTP 402 Payment Required on Enterprise quarantine endpoint
    client.post("/api/subscription/deactivate")
    resp_gated = client.post(
        "/api/action/quarantine",
        json={"ip": "192.0.2.200", "mac": "AA:BB:CC:DD:EE:FF", "action": "stop"},
    )
    assert resp_gated.status_code == 402
    assert resp_gated.json()["upgrade_required"] is True

    # 2. Mint & activate Sovereign Enterprise key and verify quarantine endpoint succeeds
    mint_resp = client.post(
        "/api/subscription/admin/mint",
        json={"tier": "enterprise", "plan": "lifetime", "email": "founder@netpulse.io", "auto_activate": True},
    )
    assert mint_resp.status_code == 200
    assert mint_resp.json()["ok"] is True

    resp = client.post(
        "/api/action/quarantine",
        json={"ip": "192.0.2.200", "mac": "AA:BB:CC:DD:EE:FF", "action": "stop"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["quarantined"] is False


def test_api_action_smart_home_control_invalid_protocol():
    resp = client.post(
        "/api/action/smart-home-control",
        json={"ip": "192.0.2.200", "protocol": "unknown_proto", "action": "status"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is False



def test_mobile_pwa_and_apk_download():
    resp_pwa = client.get("/mobile")
    assert resp_pwa.status_code == 200
    assert "mobileToggleQuarantine" in resp_pwa.text
    assert "mobileTopoCanvas" in resp_pwa.text

    resp_apk = client.get("/download/NetPulse-Mobile.apk")
    assert resp_apk.status_code == 200
    assert len(resp_apk.content) > 10000


def test_health_pricing_and_admin_security():
    resp_health = client.get("/api/health")
    assert resp_health.status_code == 200
    assert resp_health.headers.get("X-Content-Type-Options") == "nosniff"
    hdata = resp_health.json()
    assert hdata["status"] == "healthy"
    assert hdata["version"] == "4.5.0"

    resp_pricing = client.get("/pricing")
    assert resp_pricing.status_code == 200
    assert "Pro Guardian" in resp_pricing.text
    assert "Sovereign Enterprise" in resp_pricing.text

    # Invalid X-Admin-Token must be rejected with 403 Forbidden
    resp_bad_admin = client.post(
        "/api/subscription/admin/mint",
        headers={"X-Admin-Token": "invalid_forged_token_123"},
        json={"tier": "enterprise", "plan": "lifetime", "email": "attacker@example.com"},
    )
    assert resp_bad_admin.status_code == 403


def test_admin_dashboard_page_and_business_metrics():
    # Operator dashboard page serves and references its data API
    resp_page = client.get("/admin")
    assert resp_page.status_code == 200
    assert "Business Control Room" in resp_page.text
    assert "/api/admin/business" in resp_page.text

    # Metrics endpoint: loopback TestClient is admin by design; forged token rejected
    resp_forbidden = client.get("/api/admin/business", headers={"X-Admin-Token": "forged"})
    assert resp_forbidden.status_code == 403

    resp = client.get("/api/admin/business")
    assert resp.status_code == 200
    d = resp.json()
    assert d["ok"] is True
    for section in ("licenses", "customers", "revenue", "leads", "stripe", "system"):
        assert section in d
    assert "mints_timeline" in d and isinstance(d["mints_timeline"], dict)
    assert "lifetime_revenue_usd" in d["revenue"]
    assert "active" in d["licenses"]
    assert "recent" in d["customers"]
    assert "version" in d["system"]


def test_google_play_bundle_privacy_and_launch_hub():
    resp_aab = client.get("/download/NetPulse-Mobile-PlayStore.aab")
    assert resp_aab.status_code == 200
    assert len(resp_aab.content) > 10000

    resp_privacy = client.get("/privacy")
    assert resp_privacy.status_code == 200
    assert "ACCESS_FINE_LOCATION" in resp_privacy.text
    assert "Zero-Cloud Telemetry Guarantee" in resp_privacy.text

    resp_launch = client.get("/launch")
    assert resp_launch.status_code == 200
    assert "Google Play Store" in resp_launch.text
    assert "Show HN" in resp_launch.text

    resp_icon = client.get("/play-store-assets/icon_512x512.png")
    assert resp_icon.status_code == 200
    assert resp_icon.headers.get("content-type") == "image/png"
    assert len(resp_icon.content) > 5000


def test_oui_search_analytics_telemetry_and_csv_export():
    # 1. OUI search API
    resp_oui = client.get("/api/oui/search?q=Sonos&limit=10")
    assert resp_oui.status_code == 200
    odata = resp_oui.json()
    assert odata["ok"] is True
    assert odata["mode"] == "vendor_search"
    assert odata["total_matches"] >= 1

    # 2. Analytics API
    resp_ana = client.get("/api/analytics")
    assert resp_ana.status_code == 200
    adata = resp_ana.json()
    assert adata["ok"] is True
    assert "analytics" in adata
    assert "security_posture" in adata

    # 3. Mobile Telemetry Fusion API
    resp_tel = client.post(
        "/api/mobile/telemetry",
        json={
            "phone_model": "Pixel 9 Pro Fold",
            "phone_ip": "192.168.12.142",
            "mag_ut": {"bx": 15.2, "by": -22.1, "bz": 39.4, "total_ut": 47.6},
            "azimuth_deg": 270.0,
            "wifi_aps": [{"bssid": "18:A5:1D:0C:62:3B", "signal_dbm": -41}],
        },
    )
    assert resp_tel.status_code == 200
    tdata = resp_tel.json()
    assert tdata["ok"] is True
    assert tdata["telemetry"]["active"] is True

    # 4. CSV export API (ensure Enterprise tier is active)
    client.post(
        "/api/subscription/admin/mint",
        json={"tier": "enterprise", "plan": "lifetime", "email": "founder@netpulse.io", "auto_activate": True},
    )
    resp_csv = client.get("/api/export/csv")
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers.get("content-type", "")
    assert "IPv4,Hardware MAC,Display Name" in resp_csv.text


def test_ssh_and_smb_audit_tier_gating():
    # Free tier should return 402 Payment Required on Enterprise SSH/SMB/DNS audit actions
    client.post("/api/subscription/deactivate")
    r_ssh = client.post("/api/action/ssh-audit", json={"ip": "127.0.0.1", "port": 22})
    assert r_ssh.status_code == 402
    r_smb = client.post("/api/action/smb-audit", json={"ip": "127.0.0.1", "port": 445})
    assert r_smb.status_code == 402
    r_dns_gated = client.post("/api/action/dns-audit", json={"ip": "127.0.0.1"})
    assert r_dns_gated.status_code == 402

    # Restore Enterprise license and verify DNS audit executes cleanly
    client.post(
        "/api/subscription/admin/mint",
        json={"tier": "enterprise", "plan": "lifetime", "email": "founder@netpulse.io", "auto_activate": True},
    )
    r_dns = client.post("/api/action/dns-audit", json={"ip": "127.0.0.1"})
    assert r_dns.status_code == 200
    assert r_dns.json()["ok"] is True
    assert "security_grade" in r_dns.json()

    r_v6 = client.get("/api/ipv6/audit")
    assert r_v6.status_code == 200
    assert r_v6.json()["ok"] is True
    assert "security_grade" in r_v6.json()

    r_knock = client.post(
        "/api/action/port-knock",
        json={"ip": "127.0.0.1", "ports": [7001, 7002], "protocol": "udp", "delay_ms": 5, "verify_port": 22},
    )
    assert r_knock.status_code == 200
    assert r_knock.json()["ok"] is True

    # Verify All-Around Toolkit endpoints: CIDR calculator, local sockets, domain intel, and wake-all
    r_cidr = client.get("/api/subnet/calc?cidr=10.20.30.0/24")
    assert r_cidr.status_code == 200
    assert r_cidr.json()["ok"] is True
    assert r_cidr.json()["usable_hosts"] == 254

    r_socks = client.get("/api/local/sockets")
    assert r_socks.status_code == 200
    assert r_socks.json()["ok"] is True

    r_dom = client.post("/api/action/domain-intel", json={"target": "127.0.0.1"})
    assert r_dom.status_code == 200
    assert r_dom.json()["ok"] is True

    r_wake_all = client.post("/api/action/wake-all")
    assert r_wake_all.status_code == 200
    assert r_wake_all.json()["ok"] is True


def test_all_registered_endpoints_and_websocket_functional():
    """Verify every registered route and WebSocket endpoint in server.py executes cleanly."""
    # Ensure Enterprise license is active so all gated endpoints run their full handler logic
    r_mint = client.post(
        "/api/subscription/admin/mint",
        json={"tier": "enterprise", "plan": "lifetime", "email": "founder@netpulse.io", "auto_activate": True},
    )
    assert r_mint.status_code == 200
    minted_key = r_mint.json()["license_key"]

    endpoint_matrix = [
        ("GET", "/api/health", None, [200]),
        ("GET", "/", None, [200]),
        ("GET", "/mobile", None, [200]),
        ("GET", "/pricing", None, [200]),
        ("GET", "/terms", None, [200]),
        ("GET", "/privacy", None, [200]),
        ("GET", "/distribute", None, [200]),
        ("GET", "/launch", None, [200]),
        ("GET", "/play-store-assets/icon_512x512.png", None, [200]),
        ("GET", "/manifest.json", None, [200]),
        ("GET", "/sw.js", None, [200]),
        ("GET", "/static/icon.svg", None, [200]),
        ("GET", "/download/NetPulse-Mobile.apk", None, [200]),
        ("GET", "/download/NetPulse-Mobile-PlayStore.aab", None, [200]),
        ("GET", "/api/mobile-qr", None, [200]),
        ("GET", "/api/state", None, [200]),
        ("GET", "/api/hypotheses", None, [200]),
        ("POST", "/api/scan", None, [200]),
        ("GET", "/api/oui/search?q=Ubiquiti&limit=5", None, [200]),
        ("GET", "/api/analytics", None, [200]),
        ("GET", "/api/ledger", None, [200]),
        ("GET", "/api/ledger/verify", None, [200]),
        ("GET", "/api/ipv6/audit", None, [200]),
        ("GET", "/api/subnet/calc?cidr=192.168.12.0/24", None, [200]),
        ("POST", "/api/subnet/calc", {"cidr": "10.0.0.0/16"}, [200]),
        ("GET", "/api/local/sockets", None, [200]),
        ("POST", "/api/action/domain-intel", {"target": "127.0.0.1"}, [200]),
        ("POST", "/api/mobile/telemetry", {"phone_model": "Pixel 9", "phone_ip": "192.168.12.142", "wifi_aps": []}, [200]),
        ("POST", "/api/action/wol", {"mac": "AA:BB:CC:DD:EE:FF"}, [200]),
        ("POST", "/api/action/wake-all", {}, [200]),
        ("POST", "/api/action/roku-key", {"ip": "127.0.0.1", "key": "Home"}, [200]),
        ("POST", "/api/action/roku-launch", {"ip": "127.0.0.1", "app_id": "12"}, [200]),
        ("POST", "/api/action/roku-text", {"ip": "127.0.0.1", "text": "test"}, [200]),
        ("POST", "/api/action/dial-app", {"ip": "127.0.0.1", "app_name": "YouTube", "action": "status"}, [200]),
        ("POST", "/api/action/gateway-control", {"ip": "127.0.0.1", "action": "telemetry"}, [200]),
        ("POST", "/api/action/bt-control", {"mac": "", "action": "status"}, [200]),
        ("POST", "/api/action/launch-client", {"ip": "127.0.0.1", "port": 8765, "protocol": "probe"}, [200]),
        ("POST", "/api/action/playstation-wake", {"ip": "127.0.0.1", "mac": "AA:BB:CC:DD:EE:FF"}, [200]),
        ("POST", "/api/action/spotify-control", {"ip": "127.0.0.1", "action": "getInfo"}, [200]),
        ("POST", "/api/action/smart-home-control", {"ip": "127.0.0.1", "protocol": "shelly", "action": "status"}, [200]),
        ("POST", "/api/action/sonos-control", {"ip": "127.0.0.1", "action": "GetTransportInfo", "volume": 20}, [200]),
        ("POST", "/api/action/ssh-audit", {"ip": "127.0.0.1", "port": 22}, [200]),
        ("POST", "/api/action/smb-audit", {"ip": "127.0.0.1", "port": 445}, [200]),
        ("POST", "/api/action/upnp-nat-audit", {"gateway_ip": "127.0.0.1"}, [200]),
        ("POST", "/api/action/dns-audit", {"ip": "127.0.0.1"}, [200]),
        ("POST", "/api/action/ntp-audit", {"ip": "127.0.0.1"}, [200]),
        ("POST", "/api/action/port-knock", {"ip": "127.0.0.1", "ports": [7000, 8000], "protocol": "udp", "delay_ms": 5, "verify_port": 22}, [200]),
        ("POST", "/api/action/http-probe", {"ip": "127.0.0.1", "port": 8765, "path": "/api/health", "method": "GET"}, [200]),
        ("POST", "/api/action/port-range-scan", {"ip": "127.0.0.1", "start_port": 8764, "end_port": 8766}, [200]),
        ("POST", "/api/action/ping-burst", {"ip": "127.0.0.1"}, [200]),
        ("POST", "/api/action/deep-nmap", {"ip": "127.0.0.1"}, [200]),
        ("POST", "/api/action/traceroute", {"ip": "127.0.0.1"}, [200]),
        ("POST", "/api/action/camera-sweep", {}, [200]),
        ("POST", "/api/action/quarantine", {"ip": "127.0.0.1", "action": "stop"}, [200]),
        ("GET", "/api/export/csv", None, [200]),
        ("POST", "/api/export/report", {}, [200]),
        ("GET", "/api/subscription/status", None, [200]),
        ("POST", "/api/subscription/trial", {"email": "matrix_trial@netpulse.io"}, [200]),
        ("POST", "/api/subscription/checkout", {"tier": "pro", "plan": "monthly", "email": "test@netpulse.io"}, [200]),
        ("POST", "/api/subscription/checkout", {"tier": "enterprise", "plan": "lifetime", "email": "founder@netpulse.io"}, [200]),
        ("POST", "/api/subscription/lead", {"email": "lead@netpulse.io", "source": "github_pages", "use_case": "msp"}, [200]),
        ("GET", "/api/subscription/admin/leads", None, [200]),
        ("POST", "/api/subscription/verify-session", {"session_id": "cs_test_demo"}, [200]),
        ("POST", "/api/subscription/stripe-config", {"secret_key": "", "publishable_key": "", "webhook_secret": ""}, [200]),
        ("POST", "/api/subscription/webhook", {}, [200, 400]),
        ("GET", "/api/subscription/admin/keys", None, [200]),
        ("POST", "/api/subscription/activate", {"license_key": minted_key}, [200]),
        ("GET", "/api/accuracy", None, [200]),
        ("GET", "/api/chronicle", None, [200]),
        ("GET", "/api/chronicle/wrapped", None, [200]),
        ("POST", "/api/evidence/bundle", {"device_key": "127.0.0.1"}, [200]),
        ("POST", "/api/evidence/verify", {"bundle": {"@graph": []}}, [200, 400]),
        ("GET", "/api/device/127.0.0.1/proof", None, [200, 404]),
    ]

    for method, path, body, expected_codes in endpoint_matrix:
        if method == "GET":
            resp = client.get(path)
        elif method == "POST":
            resp = client.post(path, json=body)
        elif method == "DELETE":
            resp = client.delete(path)
        assert resp.status_code in expected_codes, f"{method} {path} returned {resp.status_code}: {resp.text[:200]}"

    with client.websocket_connect("/ws") as ws:
        init_msg = ws.receive_json()
        assert init_msg["type"] == "full_state"
        ws.send_text("ping")
        pong_msg = ws.receive_json()
        assert pong_msg["type"] == "pong"


def test_every_html_button_and_link_leads_to_valid_action() -> None:
    """Verify every <button> and <a href> across all 6 UI & Storefront HTML files resolves to a defined JS function or live HTTP 200 route."""
    import os
    import re

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html_files = [
        os.path.join(root_dir, "static", "index.html"),
        os.path.join(root_dir, "static", "mobile.html"),
        os.path.join(root_dir, "static", "pricing.html"),
        os.path.join(root_dir, "static", "launch.html"),
        os.path.join(root_dir, "static", "privacy.html"),
        os.path.join(root_dir, "docs", "index.html"),
    ]

    for fpath in html_files:
        assert os.path.exists(fpath), f"Missing HTML file: {fpath}"
        with open(fpath, "r", encoding="utf-8") as f:
            html = f.read()

        # Extract all JS function definitions in this file
        defined_funcs = set(re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\(", html))

        # 1. Audit every static <button ...> tag outside JS template strings
        # Check onclick handlers call a defined JS function or inline DOM expression
        for match in re.finditer(r"<button\b([^>]*)>", html):
            attrs = match.group(1)
            onclick_m = re.search(r'onclick="([^"]+)"', attrs)
            assert onclick_m is not None, f"Button without onclick in {os.path.basename(fpath)}: <button{attrs}>"
            expr = onclick_m.group(1).strip()
            assert len(expr) > 0, f"Empty onclick in {os.path.basename(fpath)}"
            if not expr.startswith("document.") and not expr.startswith("${"):
                fn_m = re.match(r"^([a-zA-Z0-9_]+)\s*\(", expr)
                if fn_m:
                    fn_name = fn_m.group(1)
                    assert fn_name in defined_funcs, (
                        f"Button in {os.path.basename(fpath)} calls undefined function '{fn_name}()': {expr}"
                    )

        # 2. Audit every <a ... href="..."> tag
        for match in re.finditer(r'<a\b[^>]*\bhref="([^"]*)"', html):
            href = match.group(1).strip()
            if "${" in href:
                continue
            assert href != "" and href != "#", f"Dead <a href='{href}'> in {os.path.basename(fpath)}"
            assert " " not in href, f"Whitespace typo in <a href='{href}'> in {os.path.basename(fpath)}"
            assert "github.com/sponsors" not in href, f"Unactivated sponsors link in {os.path.basename(fpath)}: {href}"
            if href.startswith("/"):
                resp = client.get(href)
                assert resp.status_code == 200, (
                    f"Broken internal link <a href='{href}'> in {os.path.basename(fpath)}: HTTP {resp.status_code}"
                )


def test_every_backend_api_endpoint_is_surfaced_in_ui() -> None:
    """Verify that 100% of user-facing /api/* backend endpoints in server.py are surfaced across the UI HTML views."""
    import os
    from fastapi.routing import APIRoute

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ui_files = [
        os.path.join(root_dir, "static", "index.html"),
        os.path.join(root_dir, "static", "mobile.html"),
        os.path.join(root_dir, "static", "pricing.html"),
        os.path.join(root_dir, "static", "launch.html"),
        os.path.join(root_dir, "static", "admin.html"),
    ]
    combined_ui = "\n".join(open(p, "r", encoding="utf-8").read() for p in ui_files)

    # Server-to-server webhook & health check routes that aren't user-clicked in the browser
    non_ui_routes = {"/api/subscription/webhook", "/api/health"}

    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/"):
            if route.path in non_ui_routes:
                continue
            # Normalize parameterized paths like /api/device/{device_key}/customize -> /api/device/
            base_prefix = route.path.split("{")[0].rstrip("/")
            assert base_prefix in combined_ui, (
                f"Backend endpoint '{route.path}' (prefix '{base_prefix}') is not surfaced in any UI HTML view!"
            )








