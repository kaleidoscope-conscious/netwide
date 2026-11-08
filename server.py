"""
FastAPI + WebSocket Real-Time Command Center Server for NetPulse (OmniSight).
Provides:
- Continuous background Multi-Vector LAN Scanner + Passive Wire Sniffer (tshark)
- Live WebSocket telemetry broadcast (/ws)
- Hardware Device Image Proxy (/api/device-image/{ip})
- Active Control Endpoints:
  * Wake-on-LAN Magic Packet Transmitter (/api/action/wol)
  * Roku TV / Stick Live Remote Control & Find-Remote Beeper (/api/action/roku-key)
  * Deep Nmap Service & Version Probe (/api/action/deep-nmap)
  * High-Precision Ping Burst & Jitter Analyzer (/api/action/ping-burst)
  * MTR / Multi-Hop Path Traceroute (/api/action/traceroute)
  * Multi-Stream WAN Throughput & Bufferbloat Speedtest (/api/action/speedtest)
"""

from __future__ import annotations

import asyncio
import csv
import io
import os
import subprocess
import time
import urllib.request
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from netpulse.billing import subscription_engine
from netpulse.database import net_db
from netpulse.fingerprint import (
    audit_network_threats,
    compute_network_security_posture,
    run_full_network_scan,
)
from netpulse.oui import oui_db
from netpulse.probers import (
    NetworkInterfaceInfo,
    PassiveWireSniffer,
    audit_ipv6_posture,
    audit_local_workstation_sockets,
    calculate_subnet_cidr,
    control_bluetooth_device,
    control_dial_app,
    control_smart_home_device,
    control_sonos_speaker,
    control_spotify_zeroconf,
    control_tmobile_gateway,
    detect_active_interface,
    launch_local_client,
    measure_single_host_latency,
    probe_dns_security_posture,
    probe_domain_and_wan_target,
    probe_http_endpoint_custom,
    probe_ntp_server,
    probe_onvif_ws_discovery,
    probe_smb2_negotiate,
    probe_ssh_kex_and_hostkeys,
    probe_upnp_igd_nat_mappings,
    quarantine_engine,
    scan_custom_port_range,
    send_playstation_wakeup,
    send_port_knock_sequence,
    send_roku_keypress,
    send_roku_text,
    send_wake_on_lan,
)
from netpulse.wireless import (
    build_area_scan_report,
    fetch_wan_intelligence,
    mobile_telemetry_hub,
    run_wan_speedtest,
    scan_bluetooth_radar,
    wireless_engine,
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class CustomizeDeviceRequest(BaseModel):
    custom_name: Optional[str] = None
    trust_state: Optional[str] = None
    notes: Optional[str] = None


class WoLRequest(BaseModel):
    mac: str
    ip: Optional[str] = None


class RokuKeyRequest(BaseModel):
    ip: str
    key: str


class RokuTextRequest(BaseModel):
    ip: str
    text: str


class RokuLaunchRequest(BaseModel):
    ip: str
    app_id: str = "12"


class DomainIntelRequest(BaseModel):
    target: str


class SubnetCalcRequest(BaseModel):
    cidr: str = "192.168.12.0/24"


class DialAppRequest(BaseModel):
    ip: str
    app_name: str
    action: str = "launch"
    payload: str = ""


class GatewayControlRequest(BaseModel):
    ip: str = "192.168.12.1"
    action: str = "telemetry"
    username: str = "admin"
    password: str = ""


class BluetoothControlRequest(BaseModel):
    mac: str = ""
    action: str = "info"


class LaunchClientRequest(BaseModel):
    ip: str
    port: int = 80
    protocol: str = "http"
    username: str = ""


class PlayStationWakeRequest(BaseModel):
    ip: str
    mac: str = ""
    host_id: str = ""


class SpotifyControlRequest(BaseModel):
    ip: str
    endpoint_url: str = ""
    action: str = "getInfo"


class HttpProbeRequest(BaseModel):
    ip: str
    port: int = 80
    path: str = "/"
    method: str = "GET"


class PortRangeScanRequest(BaseModel):
    ip: str
    start_port: int = 1
    end_port: int = 10000


class TargetIPRequest(BaseModel):
    ip: str


class QuarantineRequest(BaseModel):
    ip: str
    mac: str = ""
    action: str = "engage"  # engage | release


class SmartHomeControlRequest(BaseModel):
    ip: str
    protocol: str = "shelly"  # kasa | shelly | google_cast
    action: str = "status"    # on | off | toggle | reboot | status


class SonosControlRequest(BaseModel):
    ip: str
    action: str = "GetTransportInfo"  # Play | Pause | Stop | Next | Previous | SetVolume | GetTransportInfo
    volume: int = 25


class SshAuditRequest(BaseModel):
    ip: str
    port: int = 22


class SmbAuditRequest(BaseModel):
    ip: str
    port: int = 445


class UpnpNatAuditRequest(BaseModel):
    gateway_ip: str = ""
    upnp_location: str = ""


class DnsAuditRequest(BaseModel):
    ip: str = ""


class NtpAuditRequest(BaseModel):
    ip: str = ""


class PortKnockRequest(BaseModel):
    ip: str
    ports: List[int] = [7000, 8000, 9000]
    protocol: str = "tcp"
    delay_ms: int = 75
    verify_port: int = 22


class MobileTelemetryRequest(BaseModel):
    handset_id: str = "android-handset"
    phone_model: str = ""
    phone_ip: str = ""
    wifi_aps: List[Dict[str, Any]] = []
    mag_ut: Any = 0.0
    azimuth_deg: float = 0.0


class ActivateLicenseRequest(BaseModel):
    license_key: str


class CheckoutSessionRequest(BaseModel):
    tier: str = "pro"          # pro | enterprise
    plan: str = "monthly"      # monthly | annual
    email: str = ""
    origin_url: str = "http://127.0.0.1:8765"


class VerifyStripeSessionRequest(BaseModel):
    session_id: str


class StripeConfigRequest(BaseModel):
    secret_key: str = ""
    publishable_key: str = ""
    webhook_secret: str = ""
    admin_token: str = ""


class StartTrialRequest(BaseModel):
    email: str = "trial@netpulse.io"


class MintLicenseRequest(BaseModel):
    tier: str = "enterprise"
    plan: str = "lifetime"
    email: str = "founder@netpulse.local"
    days: Optional[int] = None
    max_nodes: Optional[int] = None
    auto_activate: bool = True
    admin_token: str = ""


class RevokeLicenseRequest(BaseModel):
    jti: str
    admin_token: str = ""


class CaptureLeadRequest(BaseModel):
    email: str
    source: str = "pricing_storefront"
    use_case: str = "prosumer"


def _require_admin(request: Request, body_token: str = "") -> Optional[JSONResponse]:
    hdr_tok = (
        request.headers.get("x-admin-token")
        or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        or body_token
    )
    if hdr_tok:
        if subscription_engine.verify_admin_token(hdr_tok):
            return None
        return JSONResponse(
            {"ok": False, "error": "Invalid Sovereign Admin Master Token."},
            status_code=403,
        )
    client_host = request.client.host if request.client else ""
    if client_host in ("127.0.0.1", "::1", "localhost", "testclient"):
        return None
    return JSONResponse(
        {
            "ok": False,
            "error": "Sovereign Admin Master Token required (pass X-Admin-Token header or run on local loopback).",
        },
        status_code=403,
    )


def _require_tier(feature_key: str) -> Optional[JSONResponse]:
    allowed, err_payload = subscription_engine.check_feature_access(feature_key)
    if not allowed and err_payload is not None:
        return JSONResponse(err_payload, status_code=402)
    return None



class EngineState:
    def __init__(self) -> None:
        self.net_info: NetworkInterfaceInfo = detect_active_interface()
        self.devices: List[Dict[str, Any]] = []
        self.wifi_spectrum: Dict[str, Any] = {}
        self.bluetooth_radar: Dict[str, Any] = {}
        self.wan_intel: Dict[str, Any] = {}
        self.last_speedtest: Optional[Dict[str, Any]] = None
        self.scan_in_progress: bool = False
        self.scan_count: int = 0
        self.last_scan_duration_sec: float = 0.0
        self.last_scan_time: str = "Never"
        self.sniffer: PassiveWireSniffer = PassiveWireSniffer(interface=self.net_info.interface)
        self.ws_clients: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def to_snapshot(self) -> Dict[str, Any]:
        for d in self.devices:
            dip = d.get("ip", "")
            d["is_quarantined"] = quarantine_engine.is_quarantined(dip)
            ht = self.sniffer.host_traffic.get(dip)
            if ht:
                bw = self.sniffer.get_host_bandwidth(dip)
                ht["rate_kbps"] = bw["rate_kbps"]
                ht["pps"] = bw["pps"]
                d["rate_kbps"] = bw["rate_kbps"]
                d["pps"] = bw["pps"]
                d["wire_traffic"] = ht
                specs = d.setdefault("hardware_specs", {})
                pkts = ht.get("packets", 0)
                b_cnt = ht.get("bytes", 0)
                protos = ", ".join(ht.get("protocols", []))
                specs["Observed Wire Traffic (DPI)"] = (
                    f"{pkts} frames ({b_cnt:,} bytes) • {bw['rate_kbps']} KB/s (Peak {ht.get('peak_kbps', 0.0)} KB/s) • Protocols: {protos or 'L2'}"
                )
                doms = ht.get("domains", [])
                if doms:
                    specs["Observed DNS / mDNS / TLS Domains"] = ", ".join(doms[:8])
                ja3s = ht.get("ja3_hashes", [])
                if ja3s:
                    specs["TLS ClientHello JA3 Fingerprint"] = ", ".join(ja3s[:3])
                if ht.get("dhcp_opt55"):
                    specs["DHCP Option 55 (PRL Fingerprint)"] = ht["dhcp_opt55"]
                if ht.get("dhcp_vendor_class"):
                    specs["DHCP Option 60 (Vendor Class)"] = ht["dhcp_vendor_class"]
                if ht.get("tcp_syn_signature"):
                    specs["Passive p0f TCP SYN Signature"] = ht["tcp_syn_signature"]
            else:
                d["rate_kbps"] = 0.0
                d["pps"] = 0.0
        online_devs = [d for d in self.devices if d.get("is_online")]
        gateway_dev = next((d for d in self.devices if d.get("is_gateway")), None)
        if gateway_dev and gateway_dev.get("is_online") and gateway_dev.get("mac") and not quarantine_engine.locked_gateway_mac:
            quarantine_engine.lock_gateway_mac(gateway_dev.get("ip", ""), gateway_dev.get("mac", ""))
        gw_5g = gateway_dev.get("gateway_5g_info", {}) if gateway_dev else {}
        threats = audit_network_threats(self.devices, self.wifi_spectrum, self.net_info.ssid)
        security_posture = compute_network_security_posture(self.devices, threats, self.wifi_spectrum)
        triangulation = mobile_telemetry_hub.triangulate_aps(self.wifi_spectrum.get("access_points", []))
        top_talkers = sorted(
            self.sniffer.host_traffic.values(),
            key=lambda x: x.get("packets", 0),
            reverse=True,
        )[:15]

        area_scan = build_area_scan_report(
            self.wifi_spectrum,
            self.devices,
            self.bluetooth_radar,
            self.net_info,
            gw_5g,
            self.wan_intel,
        )

        return {
            "meta": {
                "version": "4.5.0",
                "oui_database_size": oui_db.loaded_count,
                "scan_in_progress": self.scan_in_progress,
                "scan_count": self.scan_count,
                "last_scan_duration_sec": self.last_scan_duration_sec,
                "last_scan_time": self.last_scan_time,
                "total_devices": len(self.devices),
                "online_devices": len(online_devs),
                "offline_devices": len(self.devices) - len(online_devs),
                "high_risk_devices": len(threats),
                "security_score": security_posture["score"],
                "security_grade": security_posture["grade"],
            },
            "interface": {
                "interface": self.net_info.interface,
                "ip": self.net_info.ip,
                "cidr": self.net_info.cidr,
                "netmask": self.net_info.netmask,
                "gateway_ip": self.net_info.gateway_ip,
                "mac": self.net_info.mac,
                "ipv6_addresses": self.net_info.ipv6_addresses,
                "ssid": self.net_info.ssid,
                "freq_mhz": self.net_info.freq_mhz,
                "channel": self.net_info.channel,
                "txpower_dbm": self.net_info.txpower_dbm,
            },
            "gateway_5g": gw_5g,
            "devices": self.devices,
            "threats": threats,
            "security_posture": security_posture,
            "top_talkers": top_talkers,
            "wifi": self.wifi_spectrum,
            "area_scan": area_scan,
            "bluetooth": self.bluetooth_radar,
            "wan": self.wan_intel,
            "speedtest": self.last_speedtest,
            "mobile_telemetry": mobile_telemetry_hub.get_status(),
            "triangulation": triangulation,
            "events": net_db.get_recent_events(80),
            "wire_packets": list(self.sniffer.packets)[:80],
            "arp_anomalies": list(self.sniffer.arp_anomalies)[:25],
            "subscription": subscription_engine.get_subscription_status(),
        }


state = EngineState()


async def broadcast_ws(payload: Dict[str, Any]) -> None:
    if not state.ws_clients:
        return
    dead: List[WebSocket] = []
    for ws in list(state.ws_clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        state.ws_clients.discard(ws)


def _execute_blocking_scan() -> None:
    if state.scan_in_progress:
        return
    state.scan_in_progress = True
    t0 = time.perf_counter()
    try:
        state.net_info = detect_active_interface()
        active_profiles = run_full_network_scan(
            state.net_info,
            passive_hosts=dict(state.sniffer.passive_hosts),
            dhcp_hostnames=dict(state.sniffer.dhcp_hostnames),
        )
        state.devices = net_db.sync_scan_results(active_profiles)
        state.wifi_spectrum = wireless_engine.scan_wifi_spectrum(trigger_rescan=False, lan_devices=state.devices)
        state.bluetooth_radar = scan_bluetooth_radar()
        if not state.wan_intel or state.scan_count % 5 == 0:
            state.wan_intel = fetch_wan_intelligence(state.net_info.gateway_ip)
        state.scan_count += 1
        state.last_scan_duration_sec = round(time.perf_counter() - t0, 2)
        state.last_scan_time = time.strftime("%H:%M:%S")
    finally:
        state.scan_in_progress = False


async def trigger_scan_and_broadcast() -> Dict[str, Any]:
    await broadcast_ws({"type": "scan_status", "scan_in_progress": True})
    await asyncio.to_thread(_execute_blocking_scan)
    snap = state.to_snapshot()
    await broadcast_ws({"type": "full_state", "data": snap})
    return snap


async def periodic_scanner_task() -> None:
    # Initial immediate scan on startup
    await trigger_scan_and_broadcast()
    while True:
        await asyncio.sleep(22)
        if not state.scan_in_progress:
            await trigger_scan_and_broadcast()


def _on_wire_packet(pkt: Dict[str, Any]) -> None:
    if state._loop and state.ws_clients:
        asyncio.run_coroutine_threadsafe(
            broadcast_ws({"type": "wire_packet", "packet": pkt}),
            state._loop,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    state._loop = asyncio.get_running_loop()
    state.devices = net_db.get_all_devices()
    state.sniffer.start(on_packet=_on_wire_packet)
    task = asyncio.create_task(periodic_scanner_task())
    yield
    task.cancel()
    state.sniffer.stop()


app = FastAPI(
    title="NetPulse (OmniSight) — Sovereign Network Intelligence",
    version="4.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/api/health")
async def api_health() -> JSONResponse:
    sub = subscription_engine.get_subscription_status()
    return JSONResponse({
        "status": "healthy",
        "version": "4.5.0",
        "oui_database_size": oui_db.loaded_count,
        "sniffer_active": state.sniffer.running,
        "scan_count": state.scan_count,
        "subscription_tier": sub["tier"],
    })


def _generate_qr_svg(url_str: str) -> str:
    """Generate a high-contrast scannable SVG QR code for mobile pairing."""
    try:
        import qrcode
        qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
        qr.add_data(url_str)
        qr.make(fit=True)
        matrix = qr.get_matrix()
        n = len(matrix)
        rects = []
        for r, row in enumerate(matrix):
            for c, val in enumerate(row):
                if val:
                    rects.append(f'<rect x="{c}" y="{r}" width="1" height="1" fill="#090d14"/>')
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" '
            f'shape-rendering="crispEdges" style="width:100%;height:100%;background:#ffffff;border-radius:10px;padding:6px;">'
            f'<rect width="{n}" height="{n}" fill="#ffffff"/>'
            + "".join(rects)
            + "</svg>"
        )
    except Exception:
        return ""


@app.get("/")
async def serve_index(request: Request, desktop: int = 0) -> FileResponse:
    ua = (request.headers.get("user-agent") or "").lower()
    if not desktop and any(k in ua for k in ("android", "iphone", "ipad", "ipod", "mobile")):
        return FileResponse(os.path.join(STATIC_DIR, "mobile.html"))
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/mobile")
async def serve_mobile() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "mobile.html"))


@app.get("/pricing")
async def serve_pricing() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "pricing.html"))


@app.get("/privacy")
@app.get("/terms")
async def serve_privacy() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "privacy.html"))


@app.get("/launch")
@app.get("/distribute")
async def serve_launch() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "launch.html"))


@app.get("/play-store-assets/{filename}")
async def serve_play_store_asset(filename: str) -> FileResponse:
    safe_name = os.path.basename(filename)
    asset_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "play_store_assets")
    asset_path = os.path.join(asset_dir, safe_name)
    if not os.path.exists(asset_path):
        raise HTTPException(status_code=404, detail=f"Play Store asset {safe_name} not found")
    return FileResponse(asset_path, media_type="image/png", filename=safe_name)


@app.get("/manifest.json")
async def serve_manifest() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "manifest.json"), media_type="application/manifest+json")


@app.get("/sw.js")
async def serve_sw() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "sw.js"), media_type="application/javascript")


@app.get("/static/icon.svg")
async def serve_icon_svg() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "icon.svg"), media_type="image/svg+xml")


@app.get("/download/NetPulse-Mobile.apk")
async def download_mobile_apk() -> FileResponse:
    apk_path = os.path.join(STATIC_DIR, "NetPulse-Mobile.apk")
    if not os.path.exists(apk_path):
        raise HTTPException(status_code=404, detail="NetPulse-Mobile.apk not found")
    return FileResponse(
        apk_path,
        media_type="application/vnd.android.package-archive",
        filename="NetPulse-Mobile.apk",
    )


@app.get("/download/NetPulse-Mobile-PlayStore.aab")
async def download_mobile_aab() -> FileResponse:
    aab_path = os.path.join(STATIC_DIR, "NetPulse-Mobile-PlayStore.aab")
    if not os.path.exists(aab_path):
        raise HTTPException(status_code=404, detail="NetPulse-Mobile-PlayStore.aab not found")
    return FileResponse(
        aab_path,
        media_type="application/octet-stream",
        filename="NetPulse-Mobile-PlayStore.aab",
    )


@app.get("/api/mobile-qr")
async def get_mobile_qr() -> JSONResponse:
    host_ip = state.net_info.ip if (state.net_info and state.net_info.ip and state.net_info.ip != "127.0.0.1") else "192.168.12.225"
    mobile_url = f"http://{host_ip}:8765/mobile"
    apk_url = f"http://{host_ip}:8765/download/NetPulse-Mobile.apk"
    aab_url = f"http://{host_ip}:8765/download/NetPulse-Mobile-PlayStore.aab"
    apk_path = os.path.join(STATIC_DIR, "NetPulse-Mobile.apk")
    apk_size_kb = round(os.path.getsize(apk_path) / 1024, 1) if os.path.exists(apk_path) else 0
    return JSONResponse({
        "host_ip": host_ip,
        "port": 8765,
        "ssid": state.net_info.ssid if state.net_info else "Jude'sRoom",
        "mobile_url": mobile_url,
        "apk_url": apk_url,
        "aab_url": aab_url,
        "apk_desktop_path": os.path.expanduser("~/Desktop/NetPulse-Mobile.apk"),
        "aab_desktop_path": os.path.expanduser("~/Desktop/NetPulse-Mobile-PlayStore.aab"),
        "apk_size_kb": apk_size_kb,
        "mobile_qr_svg": _generate_qr_svg(mobile_url),
        "apk_qr_svg": _generate_qr_svg(apk_url),
    })


@app.get("/api/state")
async def get_state() -> JSONResponse:
    return JSONResponse(state.to_snapshot())


@app.post("/api/scan")
async def manual_scan() -> JSONResponse:
    snap = await trigger_scan_and_broadcast()
    return JSONResponse(snap)


@app.get("/api/device-image/{ip}")
async def proxy_device_image(ip: str) -> Response:
    """Fetch and proxy actual hardware PNG icon directly from Roku / UPnP device on the LAN."""
    candidate_urls = [f"http://{ip}:8060/device-image.png"]
    dev = next((d for d in state.devices if d.get("ip") == ip), None)
    if dev:
        upnp_icon = dev.get("upnp_info", {}).get("icon_url")
        if upnp_icon and upnp_icon not in candidate_urls:
            candidate_urls.insert(0, upnp_icon)

    def _fetch() -> Optional[bytes]:
        for url in candidate_urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/2.0"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    return resp.read(524288)
            except Exception:
                continue
        return None

    img_bytes = await asyncio.to_thread(_fetch)
    if not img_bytes:
        raise HTTPException(status_code=404, detail="Device hardware image unavailable")
    return Response(content=img_bytes, media_type="image/png")


@app.post("/api/device/{device_key}/customize")
async def customize_device(device_key: str, req: CustomizeDeviceRequest) -> JSONResponse:
    updated = await asyncio.to_thread(
        net_db.update_device_customization,
        device_key,
        req.custom_name,
        req.trust_state,
        req.notes,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Device {device_key} not found")
    state.devices = await asyncio.to_thread(net_db.get_all_devices)
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse({"status": "ok", "device": updated})


@app.delete("/api/device/{device_key}")
async def delete_device_endpoint(device_key: str) -> JSONResponse:
    deleted = await asyncio.to_thread(net_db.delete_device, device_key)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Device {device_key} not found")
    state.devices = await asyncio.to_thread(net_db.get_all_devices)
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse({"ok": True, "deleted": device_key})


@app.get("/api/oui/search")
async def search_oui_database(q: str = "", limit: int = 40) -> JSONResponse:
    res = await asyncio.to_thread(oui_db.search, q, limit)
    return JSONResponse(res)


@app.get("/api/analytics")
async def get_network_analytics_endpoint() -> JSONResponse:
    db_stats = await asyncio.to_thread(net_db.get_network_analytics)
    ipv6_pos = await asyncio.to_thread(audit_ipv6_posture, state.net_info.interface)
    threats = audit_network_threats(state.devices, state.wifi_spectrum, state.net_info.ssid)
    posture = compute_network_security_posture(state.devices, threats, state.wifi_spectrum)
    triangulation = mobile_telemetry_hub.triangulate_aps(state.wifi_spectrum.get("access_points", []))
    return JSONResponse({
        "ok": True,
        "security_posture": posture,
        "ipv6_posture": ipv6_pos,
        "database_analytics": db_stats,
        "analytics": db_stats,
        "channel_recommendations": state.wifi_spectrum.get("channel_recommendations", {}),
        "mobile_telemetry": mobile_telemetry_hub.get_status(),
        "triangulation": triangulation,
        "arp_anomalies": list(state.sniffer.arp_anomalies)[:25],
    })


@app.get("/api/ipv6/audit")
async def get_ipv6_audit_endpoint() -> JSONResponse:
    res = await asyncio.to_thread(audit_ipv6_posture, state.net_info.interface)
    res["ok"] = True
    return JSONResponse(res)


@app.get("/api/subnet/calc")
async def get_subnet_calc_endpoint(cidr: str = "") -> JSONResponse:
    target_cidr = cidr.strip() or (state.net_info.subnet_cidr if state.net_info else "192.168.12.0/24") or "192.168.12.0/24"
    res = await asyncio.to_thread(calculate_subnet_cidr, target_cidr)
    return JSONResponse(res)


@app.post("/api/subnet/calc")
async def post_subnet_calc_endpoint(req: SubnetCalcRequest) -> JSONResponse:
    target_cidr = req.cidr.strip() or (state.net_info.subnet_cidr if state.net_info else "192.168.12.0/24") or "192.168.12.0/24"
    res = await asyncio.to_thread(calculate_subnet_cidr, target_cidr)
    return JSONResponse(res)


@app.get("/api/local/sockets")
async def get_local_sockets_endpoint() -> JSONResponse:
    res = await asyncio.to_thread(audit_local_workstation_sockets)
    return JSONResponse(res)


@app.post("/api/action/domain-intel")
async def action_domain_intel(req: DomainIntelRequest) -> JSONResponse:
    res = await asyncio.to_thread(probe_domain_and_wan_target, req.target)
    return JSONResponse(res)


@app.post("/api/mobile/telemetry")
async def ingest_mobile_telemetry(req: MobileTelemetryRequest) -> JSONResponse:
    status = await asyncio.to_thread(
        mobile_telemetry_hub.ingest,
        {
            "handset_model": req.phone_model or req.handset_id,
            "handset_ip": req.phone_ip,
            "wifi_aps": req.wifi_aps,
            "mag_ut": req.mag_ut,
            "azimuth_deg": req.azimuth_deg,
        },
    )
    triangulated = await asyncio.to_thread(
        mobile_telemetry_hub.triangulate_aps,
        state.wifi_spectrum.get("access_points", []),
    )
    return JSONResponse({
        "ok": True,
        "telemetry": status,
        "triangulation": triangulated,
    })


@app.post("/api/action/wol")
async def action_wake_on_lan(req: WoLRequest) -> JSONResponse:
    ok, msg = await asyncio.to_thread(send_wake_on_lan, req.mac)
    return JSONResponse({"ok": ok, "message": msg})


@app.post("/api/action/wake-all")
async def action_wake_all_lan() -> JSONResponse:
    """Send IEEE 802.3 Wake-on-LAN Magic Packets to all discovered non-gateway LAN hosts."""
    results: List[Dict[str, Any]] = []
    seen_macs: Set[str] = set()
    for d in state.devices:
        if d.get("is_gateway") or d.get("is_local"):
            continue
        mac = (d.get("mac") or "").strip().upper()
        if not mac or len(mac) < 17 or mac.startswith("00:00:00") or mac in seen_macs:
            continue
        seen_macs.add(mac)
        ok, msg = await asyncio.to_thread(send_wake_on_lan, mac)
        results.append({
            "ip": d.get("ip", ""),
            "mac": mac,
            "hostname": d.get("custom_name") or d.get("hostname") or d.get("ip", ""),
            "ok": ok,
            "message": msg,
        })
    return JSONResponse({
        "ok": True,
        "woken_count": sum(1 for r in results if r["ok"]),
        "total_targets": len(results),
        "results": results,
    })


@app.post("/api/action/roku-key")
async def action_roku_key(req: RokuKeyRequest) -> JSONResponse:
    gate = _require_tier("roku_control")
    if gate:
        return gate
    ok, msg = await asyncio.to_thread(send_roku_keypress, req.ip, req.key)
    return JSONResponse({"ok": ok, "message": msg})


@app.post("/api/action/roku-launch")
async def action_roku_launch(req: RokuLaunchRequest) -> JSONResponse:
    gate = _require_tier("roku_control")
    if gate:
        return gate

    def _launch() -> Dict[str, Any]:
        clean_app = "".join(ch for ch in str(req.app_id) if ch.isalnum() or ch in ("_", "-"))
        url = f"http://{req.ip}:8060/launch/{clean_app}"
        try:
            r = urllib.request.Request(url, data=b"", method="POST")
            with urllib.request.urlopen(r, timeout=2.5) as resp:
                return {"ok": resp.status in (200, 204), "status": resp.status, "message": f"Launched Roku channel {clean_app} on {req.ip}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "message": f"Roku launch failed on {req.ip}: {exc}"}

    res = await asyncio.to_thread(_launch)
    return JSONResponse(res)


@app.post("/api/action/roku-text")
async def action_roku_text(req: RokuTextRequest) -> JSONResponse:
    gate = _require_tier("roku_control")
    if gate:
        return gate
    res = await asyncio.to_thread(send_roku_text, req.ip, req.text)
    return JSONResponse(res)


@app.post("/api/action/dial-app")
async def action_dial_app(req: DialAppRequest) -> JSONResponse:
    gate = _require_tier("dial_control")
    if gate:
        return gate
    ok, msg = await asyncio.to_thread(control_dial_app, req.ip, req.app_name, req.action, 8060, req.payload)
    return JSONResponse({"ok": ok, "message": msg})


@app.post("/api/action/gateway-control")
async def action_gateway_control(req: GatewayControlRequest) -> JSONResponse:
    gate = _require_tier("gateway_control")
    if gate:
        return gate
    res = await asyncio.to_thread(control_tmobile_gateway, req.ip, req.action, req.username, req.password)
    return JSONResponse(res)


@app.post("/api/action/bt-control")
async def action_bt_control(req: BluetoothControlRequest) -> JSONResponse:
    gate = _require_tier("bt_control")
    if gate:
        return gate
    res = await asyncio.to_thread(control_bluetooth_device, req.mac, req.action)
    return JSONResponse(res)


@app.post("/api/action/launch-client")
async def action_launch_client(req: LaunchClientRequest) -> JSONResponse:
    gate = _require_tier("launch_client")
    if gate:
        return gate
    res = await asyncio.to_thread(launch_local_client, req.ip, req.port, req.protocol, req.username)
    return JSONResponse(res)


@app.post("/api/action/playstation-wake")
async def action_playstation_wake(req: PlayStationWakeRequest) -> JSONResponse:
    gate = _require_tier("playstation_wake")
    if gate:
        return gate
    res = await asyncio.to_thread(send_playstation_wakeup, req.ip, req.mac, req.host_id)
    return JSONResponse(res)


@app.post("/api/action/spotify-control")
async def action_spotify_control(req: SpotifyControlRequest) -> JSONResponse:
    gate = _require_tier("spotify_control")
    if gate:
        return gate
    res = await asyncio.to_thread(control_spotify_zeroconf, req.ip, req.endpoint_url, req.action)
    return JSONResponse(res)


@app.post("/api/action/smart-home-control")
async def action_smart_home_control(req: SmartHomeControlRequest) -> JSONResponse:
    gate = _require_tier("smart_home_control")
    if gate:
        return gate
    res = await asyncio.to_thread(control_smart_home_device, req.ip, req.protocol, req.action)
    return JSONResponse(res)


@app.post("/api/action/sonos-control")
async def action_sonos_control(req: SonosControlRequest) -> JSONResponse:
    gate = _require_tier("sonos_control")
    if gate:
        return gate
    res = await asyncio.to_thread(control_sonos_speaker, req.ip, req.action, req.volume)
    return JSONResponse(res)


@app.post("/api/action/ssh-audit")
async def action_ssh_audit(req: SshAuditRequest) -> JSONResponse:
    gate = _require_tier("ssh_audit")
    if gate:
        return gate
    res = await asyncio.to_thread(probe_ssh_kex_and_hostkeys, req.ip, req.port)
    if not res:
        return JSONResponse({"ok": False, "ip": req.ip, "port": req.port, "error": f"No SSHv2 KEXINIT response on {req.ip}:{req.port}"})
    res["ok"] = True
    return JSONResponse(res)


@app.post("/api/action/smb-audit")
async def action_smb_audit(req: SmbAuditRequest) -> JSONResponse:
    gate = _require_tier("smb_audit")
    if gate:
        return gate
    res = await asyncio.to_thread(probe_smb2_negotiate, req.ip, req.port)
    if not res:
        return JSONResponse({"ok": False, "ip": req.ip, "port": req.port, "error": f"No SMB2/3 Negotiate response on {req.ip}:{req.port}"})
    res["ok"] = True
    return JSONResponse(res)


@app.post("/api/action/upnp-nat-audit")
async def action_upnp_nat_audit(req: UpnpNatAuditRequest) -> JSONResponse:
    gate = _require_tier("upnp_nat_audit")
    if gate:
        return gate
    gw_ip = req.gateway_ip or state.net_info.gateway_ip
    gw_dev = next((d for d in state.devices if d.get("ip") == gw_ip or d.get("is_gateway")), None)
    upnp_loc = req.upnp_location or ((gw_dev or {}).get("upnp_info", {}).get("location", ""))
    res = await asyncio.to_thread(probe_upnp_igd_nat_mappings, gw_ip, upnp_loc)
    return JSONResponse(res)


@app.post("/api/action/dns-audit")
async def action_dns_audit(req: DnsAuditRequest) -> JSONResponse:
    gate = _require_tier("dns_audit")
    if gate:
        return gate
    target_ip = req.ip or state.net_info.gateway_ip or "1.1.1.1"
    res = await asyncio.to_thread(probe_dns_security_posture, target_ip)
    res["ok"] = True
    return JSONResponse(res)


@app.post("/api/action/ntp-audit")
async def action_ntp_audit(req: NtpAuditRequest) -> JSONResponse:
    gate = _require_tier("ntp_audit")
    if gate:
        return gate
    target_ip = req.ip or state.net_info.gateway_ip or "162.159.200.1"
    res = await asyncio.to_thread(probe_ntp_server, target_ip)
    res["ok"] = True
    return JSONResponse(res)


@app.post("/api/action/port-knock")
async def action_port_knock(req: PortKnockRequest) -> JSONResponse:
    gate = _require_tier("port_knock")
    if gate:
        return gate
    res = await asyncio.to_thread(
        send_port_knock_sequence,
        req.ip,
        req.ports,
        req.protocol,
        req.delay_ms,
        req.verify_port,
    )
    return JSONResponse(res)


@app.post("/api/action/quarantine")
async def action_quarantine(req: QuarantineRequest) -> JSONResponse:
    gate = _require_tier("quarantine")
    if gate:
        return gate
    dkey = req.mac.upper().strip() if req.mac else f"IP:{req.ip}"
    if req.action.lower() in ("release", "stop"):
        released = quarantine_engine.release(req.ip)
        net_db.update_device_customization(dkey, trust_state="watchlist")
        state.devices = net_db.get_all_devices()
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
        return JSONResponse({"ok": True, "ip": req.ip, "quarantined": False, "released": released})
    entry = quarantine_engine.engage(req.ip, req.mac, reason="Guardian Shield Active Quarantine")
    net_db.update_device_customization(dkey, trust_state="intruder")
    state.devices = net_db.get_all_devices()
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse({"ok": True, "ip": req.ip, "quarantined": True, "entry": entry})


@app.post("/api/action/http-probe")
async def action_http_probe(req: HttpProbeRequest) -> JSONResponse:
    gate = _require_tier("http_probe")
    if gate:
        return gate
    res = await asyncio.to_thread(probe_http_endpoint_custom, req.ip, req.port, req.path, req.method)
    return JSONResponse(res)


@app.post("/api/action/port-range-scan")
async def action_port_range_scan(req: PortRangeScanRequest) -> JSONResponse:
    gate = _require_tier("port_range_scan")
    if gate:
        return gate
    res = await asyncio.to_thread(scan_custom_port_range, req.ip, req.start_port, req.end_port)
    return JSONResponse(res)


@app.post("/api/action/ping-burst")
async def action_ping_burst(req: TargetIPRequest) -> JSONResponse:
    """Execute a 5-sample high-precision latency & jitter test against a target IP."""
    def _run_burst() -> Dict[str, Any]:
        is_local = req.ip == state.net_info.ip
        samples: List[Dict[str, Any]] = []
        rtts: List[float] = []
        for seq in range(1, 6):
            rtt, method, ttl = measure_single_host_latency(req.ip, is_local=is_local)
            samples.append({"seq": seq, "rtt_ms": rtt, "method": method, "ttl": ttl})
            if rtt is not None:
                rtts.append(rtt)
            time.sleep(0.1)
        return {
            "ip": req.ip,
            "samples": samples,
            "min_ms": round(min(rtts), 2) if rtts else None,
            "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
            "max_ms": round(max(rtts), 2) if rtts else None,
            "jitter_ms": round(max(rtts) - min(rtts), 2) if len(rtts) >= 2 else 0.0,
            "packet_loss_pct": round(((5 - len(rtts)) / 5.0) * 100.0, 1),
        }

    res = await asyncio.to_thread(_run_burst)
    return JSONResponse(res)


@app.post("/api/action/deep-nmap")
async def action_deep_nmap(req: TargetIPRequest) -> JSONResponse:
    """Execute an on-demand Nmap Service Version (-sV --version-light) scan against a target IP."""
    gate = _require_tier("deep_nmap")
    if gate:
        return gate
    def _run_nmap() -> Dict[str, Any]:
        try:
            proc = subprocess.run(
                ["nmap", "-sT", "-sV", "--version-light", "-F", "-T4", req.ip],
                capture_output=True,
                text=True,
                timeout=25.0,
            )
            return {"ok": proc.returncode == 0, "ip": req.ip, "output": proc.stdout or proc.stderr}
        except Exception as e:
            return {"ok": False, "ip": req.ip, "output": str(e)}

    res = await asyncio.to_thread(_run_nmap)
    return JSONResponse(res)


@app.post("/api/action/traceroute")
async def action_traceroute(req: TargetIPRequest) -> JSONResponse:
    """Execute an MTR multi-hop network path report to any LAN or WAN target."""
    gate = _require_tier("traceroute")
    if gate:
        return gate
    def _run_mtr() -> Dict[str, Any]:
        try:
            proc = subprocess.run(
                ["mtr", "-r", "-c", "3", "-n", req.ip],
                capture_output=True,
                text=True,
                timeout=18.0,
            )
            return {"ok": proc.returncode == 0, "ip": req.ip, "output": proc.stdout or proc.stderr}
        except Exception as e:
            return {"ok": False, "ip": req.ip, "output": str(e)}

    res = await asyncio.to_thread(_run_mtr)
    return JSONResponse(res)


@app.post("/api/action/speedtest")
async def action_speedtest() -> JSONResponse:
    res = await asyncio.to_thread(run_wan_speedtest)
    state.last_speedtest = res
    await broadcast_ws({"type": "speedtest_result", "data": res})
    return JSONResponse(res)


@app.post("/api/action/area-scan")
async def action_area_scan() -> JSONResponse:
    """
    Execute a Deep & Wide Multi-Ring Area Scan:
    - Triggers active 802.11 2.4/5 GHz scan + kernel nl80211 Beacon IE dump (64-bit TSF, QBSS, WPS, DS channel)
    - Correlates every BSSID against LAN ARP/MAC tables and 64-bit hardware TSF clocks
    - Scans local virtual/container bridges and wide-area 5G NR cellular perimeter
    """
    gate = _require_tier("area_scan")
    if gate:
        return gate
    def _do_area_scan() -> Dict[str, Any]:
        state.wifi_spectrum = wireless_engine.scan_wifi_spectrum(trigger_rescan=True, lan_devices=state.devices)
        state.bluetooth_radar = scan_bluetooth_radar()
        gateway_dev = next((d for d in state.devices if d.get("is_gateway")), None)
        gw_5g = gateway_dev.get("gateway_5g_info", {}) if gateway_dev else {}
        return build_area_scan_report(
            state.wifi_spectrum,
            state.devices,
            state.bluetooth_radar,
            state.net_info,
            gw_5g,
            state.wan_intel,
        )

    area_res = await asyncio.to_thread(_do_area_scan)
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(area_res)


@app.post("/api/action/camera-sweep")
async def action_camera_sweep() -> JSONResponse:
    """
    Execute an active Counter-Surveillance & RF Attribution Audit:
    1. ONVIF WS-Discovery SOAP Multicast Probe (UDP 239.255.255.250:3702)
    2. LAN RTSP (TCP 554 / 8554) & Camera OUI Inspection
    3. 5-Vector Physical Silicon & 64-Bit TSF Attribution (separating verified LAN/Gateway Virtual APs from unattributed transmitters)
    """
    gate = _require_tier("camera_sweep")
    if gate:
        return gate
    def _sweep() -> Dict[str, Any]:
        onvif_devs = probe_onvif_ws_discovery(timeout=1.4)
        wifi = wireless_engine.scan_wifi_spectrum(trigger_rescan=False, lan_devices=state.devices)
        state.wifi_spectrum = wifi
        verified_vaps: List[Dict[str, Any]] = []
        suspect_rf: List[Dict[str, Any]] = []
        cam_keywords = ("xinyang", "hisilicon", "espressif", "beken", "tuya", "shenzhen", "camera", "ipc", "wifi-")

        for ap in wifi.get("access_points", []):
            hay = f"{ap.get('ssid', '')} {ap.get('vendor', '')}".lower()
            is_open_strong = "open" in ap.get("security", "").lower() and ap.get("signal_pct", 0) >= 50
            has_cam_oui = any(k in hay for k in cam_keywords)
            verdict = str(ap.get("attribution_verdict", "UNVERIFIED_EXTERNAL"))

            entry = {
                "ssid": ap.get("ssid"),
                "bssid": ap.get("bssid"),
                "channel": ap.get("channel"),
                "freq_mhz": ap.get("freq_mhz"),
                "band": ap.get("band"),
                "signal_pct": ap.get("signal_pct"),
                "signal_dbm": ap.get("signal_dbm"),
                "est_distance_m": ap.get("est_distance_m"),
                "distance_range_m": ap.get("distance_range_m"),
                "rssi_stddev_db": ap.get("rssi_stddev_db"),
                "tsf_human": ap.get("tsf_human"),
                "qbss_stations": ap.get("qbss_stations"),
                "qbss_utilization_pct": ap.get("qbss_utilization_pct"),
                "wps_identity": ap.get("wps_identity"),
                "security": ap.get("security"),
                "vendor": ap.get("vendor"),
                "attribution_verdict": verdict,
                "attribution_confidence": ap.get("attribution_confidence"),
                "de_cloaked_parent": ap.get("de_cloaked_parent", ""),
                "attribution_proof": ap.get("attribution_proof", ""),
                "linked_lan_ip": ap.get("linked_lan_ip", ""),
            }

            if verdict.startswith("VERIFIED_") and not has_cam_oui and not is_open_strong:
                if ap.get("is_hidden") or ap.get("de_cloaked_parent"):
                    verified_vaps.append(entry)
            elif has_cam_oui or is_open_strong or ap.get("is_hidden"):
                entry["reason"] = (
                    "Unencrypted Close-Range RF Hotspot"
                    if is_open_strong
                    else ("Embedded Camera / IoT Radio OUI" if has_cam_oui else "Unattributed Hidden BSSID Transmitter")
                )
                suspect_rf.append(entry)

        rtsp_hosts = [
            {"ip": d["ip"], "name": d["display_name"], "ports": d["open_ports"]}
            for d in state.devices
            if any(p in d.get("open_ports", []) for p in (554, 8554))
        ]
        gateway_dev = next((d for d in state.devices if d.get("is_gateway")), None)
        gw_5g = gateway_dev.get("gateway_5g_info", {}) if gateway_dev else {}
        area = build_area_scan_report(
            wifi,
            state.devices,
            state.bluetooth_radar,
            state.net_info,
            gw_5g,
            state.wan_intel,
        )
        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "onvif_devices": onvif_devs,
            "rtsp_lan_hosts": rtsp_hosts,
            "verified_lan_and_router_vaps": verified_vaps,
            "suspect_rf_transmitters": suspect_rf,
            "anomaly_resolutions": area.get("anomaly_resolutions", []),
            "rf_multipath_fluctuations": wifi.get("rf_alerts", []),
        }

    res = await asyncio.to_thread(_sweep)
    return JSONResponse(res)


def _build_inventory_csv_text(devices: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "IPv4",
        "Hardware MAC",
        "Display Name",
        "Custom Label",
        "Manufacturer (OUI)",
        "Brand",
        "Model",
        "Category",
        "OS Family",
        "Firmware Version",
        "Power State",
        "Online",
        "RTT (ms)",
        "Confidence (%)",
        "Risk Score",
        "Trust State",
        "Open TCP Ports",
    ])
    for d in devices:
        writer.writerow([
            d.get("ip", ""),
            d.get("mac", ""),
            d.get("display_name", ""),
            d.get("custom_name", ""),
            d.get("vendor", ""),
            d.get("brand", ""),
            d.get("model", ""),
            d.get("category", ""),
            d.get("os_family", ""),
            d.get("firmware_version", ""),
            d.get("power_state", ""),
            "YES" if d.get("is_online") else "NO",
            d.get("rtt_ms") if d.get("rtt_ms") is not None else "",
            d.get("confidence_score", ""),
            d.get("risk_score", 0),
            d.get("trust_state", "known"),
            ";".join(str(p) for p in (d.get("open_ports") or [])),
        ])
    return buf.getvalue()


@app.get("/api/export/csv")
async def export_inventory_csv() -> Response:
    csv_text = await asyncio.to_thread(_build_inventory_csv_text, state.devices)
    return Response(
        content=csv_text.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="NetPulse_Inventory.csv"'},
    )


@app.post("/api/export/report")
async def export_forensic_report() -> JSONResponse:
    """Export a comprehensive Forensic Network & RF Intelligence Dossier to ~/Desktop."""
    gate = _require_tier("forensic_export")
    if gate:
        return gate
    def _export() -> Dict[str, Any]:
        snap = state.to_snapshot()
        desktop_dir = os.path.expanduser("~/Desktop")
        os.makedirs(desktop_dir, exist_ok=True)
        json_path = os.path.join(desktop_dir, "NetPulse_Forensic_Report.json")
        md_path = os.path.join(desktop_dir, "NetPulse_Forensic_Report.md")
        csv_path = os.path.join(desktop_dir, "NetPulse_Inventory.csv")

        with open(json_path, "w", encoding="utf-8") as jf:
            import json as _json
            _json.dump(snap, jf, indent=2)

        with open(csv_path, "w", encoding="utf-8") as cf:
            cf.write(_build_inventory_csv_text(snap["devices"]))

        posture = snap.get("security_posture") or {}
        lines = [
            "# NETPULSE WORKBENCH — Forensic Network, 802.11 TSF Attribution & Area Intelligence Report",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Interface:** `{snap['interface']['interface']}` (`{snap['interface']['ip']}` on `{snap['interface']['cidr']}`)  ",
            f"**Connected SSID:** `{snap['interface']['ssid']}` (Channel {snap['interface']['channel']}, {snap['interface']['freq_mhz']} MHz)  ",
            f"**WAN Egress:** `{snap['wan'].get('public_ip', 'N/A')}` — {snap['wan'].get('isp', '')} ({snap['wan'].get('city', '')}, {snap['wan'].get('region', '')})  ",
            f"**Subnet Security Posture:** **{posture.get('score', 100)}/100 (Grade {posture.get('grade', 'A+')})**  ",
            "",
            "---",
            "## 1. Universal Hidden De-Cloaker Ledger (100% Unmasked Hidden BSSIDs, Privacy MACs & Stealth Hosts)",
            "| Domain | Identifier | Cloaking Mechanism | Unmasked Real Identity & Role | Parent Router / Subnet | Signal / RTT | 10-Stage Silicon & TSF Proof |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for h in (snap.get("area_scan") or {}).get("hidden_entities", []):
            lines.append(
                f"| **{h['domain']}** | `{h['identifier']}` | {h['cloaked_as']} | "
                f"**{h['unmasked_identity']}** ({h['role_classification']}) | {h['parent_or_ip']} | "
                f"{h['channel_or_subnet']} • {h['signal_or_rtt']} | {h['silicon_proof']} |"
            )

        lines.extend([
            "",
            "---",
            "## 2. Complete 802.11 Spectrum & Technical Anomaly Attribution Ledger",
            "| BSSID | Broadcast / Unmasked SSID | Band / Ch (Freq) | 64-Bit TSF Clock | QBSS Load | Signal & Multipath Band | Verdict & Cryptographic / Silicon Proof |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for ar in (snap.get("area_scan") or {}).get("anomaly_resolutions", []):
            qbss = f"{ar.get('qbss_stations')} sta / {ar.get('qbss_utilization_pct')}%" if ar.get("qbss_stations") is not None else "—"
            lines.append(
                f"| `{ar['bssid']}` | **{ar['ssid']}** | {ar['band']} Ch {ar['channel']} ({ar.get('freq_mhz') or '?'} MHz) | "
                f"`{ar.get('tsf_clock') or '—'}` | {qbss} | {ar.get('signal_dbm')} dBm (`{ar.get('distance_range_m')}`) | "
                f"**{ar.get('verdict')}** ({ar.get('confidence')}%): {ar.get('technical_proof')} |"
            )

        lines.extend([
            "",
            "---",
            f"## 3. Deep-Fingerprinted LAN Endpoints ({len(snap['devices'])} Total)",
            "| IPv4 | Hardware MAC | Identity & Model | Category | OS / Firmware | State / Active App | RTT | Conf |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for d in snap["devices"]:
            lines.append(
                f"| `{d['ip']}` | `{d['mac']}` | **{d.get('custom_name') or d.get('display_name')}** ({d.get('vendor')}) | "
                f"{d.get('category')} | {d.get('os_family')} {d.get('firmware_version') or ''} | "
                f"`{d.get('power_state')}` | {d.get('rtt_ms')} ms | {d.get('confidence_score')}% |"
            )

        lines.extend([
            "",
            "---",
            f"## 4. Complete 802.11 Spectrum & Physical Radio Clusters ({snap['wifi'].get('total_aps', 0)} BSSIDs)",
            "| SSID / Attribution | BSSID | Band / Ch | 64-Bit TSF Uptime | Signal / Multipath Range | Security | Vendor / WPS |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for ap in snap["wifi"].get("access_points", []):
            s_label = ap["ssid"]
            if ap.get("de_cloaked_parent"):
                s_label += f" *({ap['de_cloaked_parent']})*"
            wps_str = ap.get("wps_identity") or ap.get("vendor")
            lines.append(
                f"| **{s_label}** | `{ap['bssid']}` | {ap['band']} (Ch {ap['channel']}) | `{ap.get('tsf_human') or '—'}` | "
                f"{ap['signal_pct']}% ({ap['signal_dbm']} dBm • `{ap.get('distance_range_m', '?')}`) | {ap['security']} | {wps_str} |"
            )

        md_text = "\n".join(lines) + "\n"
        with open(md_path, "w", encoding="utf-8") as mf:
            mf.write(md_text)

        return {
            "ok": True,
            "markdown_path": md_path,
            "json_path": json_path,
            "csv_path": csv_path,
            "summary": f"Exported Forensic Dossier ({len(snap['devices'])} LAN hosts, {snap['wifi'].get('total_aps', 0)} BSSIDs) to {md_path}",
        }

    res = await asyncio.to_thread(_export)
    return JSONResponse(res)


# ==================== SUBSCRIPTION, STRIPE BILLING & CRYPTOGRAPHIC LICENSING ====================


@app.get("/api/subscription/status")
async def get_subscription_status() -> JSONResponse:
    status = await asyncio.to_thread(subscription_engine.get_subscription_status)
    return JSONResponse(status)


@app.post("/api/subscription/activate")
async def activate_license_endpoint(req: ActivateLicenseRequest) -> JSONResponse:
    res = await asyncio.to_thread(subscription_engine.activate_license_key, req.license_key)
    if res.get("ok"):
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/deactivate")
async def deactivate_license_endpoint() -> JSONResponse:
    res = await asyncio.to_thread(subscription_engine.deactivate_license)
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/trial")
async def start_free_trial_endpoint(req: StartTrialRequest) -> JSONResponse:
    res = await asyncio.to_thread(subscription_engine.start_free_trial, req.email)
    if res.get("ok"):
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/checkout")
async def create_stripe_checkout_endpoint(req: CheckoutSessionRequest) -> JSONResponse:
    res = await asyncio.to_thread(
        subscription_engine.create_stripe_checkout_session,
        req.tier,
        req.plan,
        req.email,
        req.origin_url,
    )
    return JSONResponse(res)


@app.post("/api/subscription/verify-session")
async def verify_stripe_session_endpoint(req: VerifyStripeSessionRequest) -> JSONResponse:
    res = await asyncio.to_thread(subscription_engine.verify_stripe_session_and_activate, req.session_id)
    if res.get("ok"):
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/stripe-config")
async def configure_stripe_endpoint(request: Request, req: StripeConfigRequest) -> JSONResponse:
    adm_err = _require_admin(request, req.admin_token)
    if adm_err:
        return adm_err
    res = await asyncio.to_thread(
        subscription_engine.configure_stripe_keys,
        req.secret_key,
        req.publishable_key,
        req.webhook_secret,
    )
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/webhook")
async def stripe_webhook_endpoint(request: Request) -> JSONResponse:
    raw_body = await request.body()
    sig = request.headers.get("stripe-signature", "")
    res = await asyncio.to_thread(subscription_engine.handle_stripe_webhook, raw_body, sig)
    if res.get("ok") and res.get("minted"):
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/admin/mint")
async def admin_mint_license_endpoint(request: Request, req: MintLicenseRequest) -> JSONResponse:
    adm_err = _require_admin(request, req.admin_token)
    if adm_err:
        return adm_err
    minted = await asyncio.to_thread(
        subscription_engine.mint_license_key,
        req.tier,
        req.plan,
        req.email,
        req.days,
        req.max_nodes,
    )
    if req.auto_activate and minted.get("license_key"):
        await asyncio.to_thread(subscription_engine.activate_license_key, minted["license_key"])
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    minted["subscription"] = await asyncio.to_thread(subscription_engine.get_subscription_status)
    return JSONResponse(minted)


@app.get("/api/subscription/admin/keys")
async def admin_list_licenses_endpoint(request: Request) -> JSONResponse:
    adm_err = _require_admin(request)
    if adm_err:
        return adm_err
    keys = await asyncio.to_thread(subscription_engine.list_minted_licenses)
    return JSONResponse({"ok": True, "keys": keys})


@app.post("/api/subscription/admin/revoke")
async def admin_revoke_license_endpoint(request: Request, req: RevokeLicenseRequest) -> JSONResponse:
    adm_err = _require_admin(request, req.admin_token)
    if adm_err:
        return adm_err
    res = await asyncio.to_thread(subscription_engine.revoke_license, req.jti)
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.post("/api/subscription/lead")
async def capture_marketing_lead_endpoint(req: CaptureLeadRequest) -> JSONResponse:
    res = await asyncio.to_thread(
        subscription_engine.capture_lead_and_issue_trial,
        req.email,
        req.source,
        req.use_case,
    )
    if res.get("ok"):
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.get("/api/subscription/admin/leads")
async def admin_list_leads_endpoint(request: Request) -> JSONResponse:
    adm_err = _require_admin(request)
    if adm_err:
        return adm_err
    leads = await asyncio.to_thread(subscription_engine.list_marketing_leads)
    return JSONResponse({"ok": True, "leads": leads})


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    state.ws_clients.add(ws)
    try:
        await ws.send_json({"type": "full_state", "data": state.to_snapshot()})
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        state.ws_clients.discard(ws)
    except Exception:
        state.ws_clients.discard(ws)
