"""
FastAPI + WebSocket Real-Time Command Center Server for NetPulse.
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
import json
import ipaddress
import os
import subprocess
import time
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from netpulse.billing import subscription_engine
from netpulse.database import net_db
from netpulse.fingerprint import (
    audit_network_threats,
    compute_network_security_posture,
    run_full_network_scan,
)
from netpulse.ble_census import classify_hidden_tether, correlate_ble_to_lan, scan_ble_census
from netpulse.explain import explain_device
from netpulse.firmware import fetch_and_audit as firmware_fetch_and_audit
from netpulse.intel_hypotheses import compute_threat_field, generate_hypotheses
from netpulse.metrics import posture_diff, prometheus_text
from netpulse.oui import oui_db
from netpulse.profile_keys import CONTROL_CAPABILITIES, GRAPH_DEVICE_KINDS, GRAPH_RELATIONS
from netpulse.ar_fusion import room_for_device
from netpulse.passive_census import coverage_budget, dwell_schedule
from netpulse.raft import MeshNode, partition_key
from netpulse.digest import build_digest
from netpulse.openwrt import ubus_firewall_add, ubus_status
from netpulse.rules import audit_payload, compile_rule
from netpulse.scan_strategy import UCB1Bandit, dwell_for_arm
from netpulse.fusion import extract_evidence_vectors, fuse_evidence
from netpulse.accuracy import evaluate_accuracy
from netpulse.evidence_bundle import build_case_evidence_bundle, verify_evidence_bundle
from netpulse.chronicle import (
    compute_device_rhythm_profile,
    generate_network_chronicle,
    generate_netpulse_wrapped,
)
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
    ble_devices: List[Dict[str, Any]] = []


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


class ControlRequest(BaseModel):
    capability: str = "power"
    action: str = "status"
    value: Any = None
    confirm: bool = False


class ExplainRequest(BaseModel):
    device_key: str
    question: str = ""


class ScanStrategyRequest(BaseModel):
    env: str = "home"
    arm: str = ""
    reward: float = 0.0


class SinkholeRequest(BaseModel):
    domain: str
    action: str = "sinkhole"


class EvidenceBundleRequest(BaseModel):
    device_key: str
    window_hours: float = 24.0


class EvidenceVerifyRequest(BaseModel):
    bundle: Dict[str, Any]


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
            # S11 Proof Mode evidence-graded attribution
            try:
                vecs = extract_evidence_vectors(d, self.wifi_spectrum.get("access_points", []))
                verdict = fuse_evidence(vecs, default_identity=str(d.get("brand") or d.get("display_name") or "Generic Host"))
                d["proof_grade"] = verdict.grade
                d["proof_probability"] = verdict.calibrated_probability
                d["proof_summary"] = verdict.proof_summary
                d["proof_vector_count"] = verdict.vector_count
            except Exception:
                d["proof_grade"] = "PROBABLE" if d.get("confidence_score", 0) > 60 else "WEAK"
                d["proof_probability"] = round(d.get("confidence_score", 50) / 100.0, 2)
                d["proof_summary"] = f"{d['proof_grade']} inference"
                d["proof_vector_count"] = 1
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

        # Boltzmann-ranked detection hypotheses — the information-density layer.
        # Reuses the threat audit already computed above (pure math, no I/O).
        hypotheses = generate_hypotheses(
            self.devices,
            self.wifi_spectrum,
            arp_anomalies=list(self.sniffer.arp_anomalies)[:25],
            threats=threats,
            limit=500,
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
            "hypotheses_top": hypotheses[:12],
            "hypotheses_total": len(hypotheses),
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
        # Persist identity graph + evidence (best-effort; never fails the scan)
        # Adaptive strategy: pick arm by env, apply dwell, learn from outcome
        selected_arm = "stealth_light"
        env_fp = "home"
        try:
            env_fp = f"home:{state.net_info.subnet_cidr or state.net_info.cidr or 'net'}:{state.net_info.ssid or ''}"
            bandit = UCB1Bandit()
            saved = net_db.get_scan_strategy(env_fp)
            if saved and saved.get("stats"):
                try:
                    for a, s in (saved.get("stats") or {}).items():
                        for _ in range(int(s.get("count") or 0)):
                            bandit.update(a, float(s.get("mean_reward") or 0))
                except Exception:
                    pass
            selected_arm = bandit.select_arm()
            state.devices_count_before = len(state.devices)
        except Exception:
            bandit, selected_arm = UCB1Bandit(), "stealth_light"
            state.devices_count_before = 0  # type: ignore[attr-defined]
        try:
            net_db.sync_graph_from_state(state.devices, (state.wifi_spectrum or {}).get("access_points", []))
            for d in state.devices:
                dk = str(d.get("device_key") or d.get("mac") or "")
                if not dk:
                    continue
                for f in d.get("security_findings") or []:
                    if f.get("severity") in ("CRITICAL", "HIGH"):
                        net_db.add_evidence(f"finding:{d.get('ip')}:{f.get('title', '')[:40]}", dk, "device_finding", {"title": f.get("title"), "severity": f.get("severity")}, 0.8)
            # Compiled detection rules vs device payloads
            try:
                rules = net_db.list_rules()
                if rules:
                    compiled = [
                        {"id": r.get("rule_id"), "title": r.get("title"), "severity": r.get("severity"), "match": r.get("match_regex"), "action": r.get("action")}
                        for r in rules
                    ]
                    for d in state.devices:
                        dk = str(d.get("device_key") or d.get("mac") or "")
                        if not dk:
                            continue
                        hits = audit_payload({k: d.get(k) for k in ("display_name", "brand", "model", "firmware_version", "os_family")}, compiled)
                        for h in hits:
                            net_db.add_evidence(f"rule:{h.get('rule_id')}", dk, "rule_hit", h, 0.7)
            except Exception:
                pass
            # Reward update for bandit (identities per second)
            try:
                gained = max(0, len(state.devices) - int(getattr(state, "devices_count_before", 0) or 0))
                dur = max(0.5, time.perf_counter() - t0)
                from netpulse.scan_strategy import reward_for_scan as _reward
                rw = _reward(gained + len(state.devices) * 0.1, dur, 0)
                bandit.update(selected_arm, rw)
                net_db.save_scan_strategy(
                    env_fp,
                    {"arm": selected_arm, "dwell_ms": dwell_for_arm(selected_arm)},
                    bandit.stats(),
                )
            except Exception:
                pass
        except Exception:
            pass
        # ARP auto-mitigation (opt-in only: NETPULSE_AUTO_QUARANTINE=1)
        try:
            if os.environ.get("NETPULSE_AUTO_QUARANTINE", "0") == "1":
                for an in list(state.sniffer.arp_anomalies)[:5]:
                    try:
                        ip = str(an.get("ip") or "")
                        mac = str(an.get("mac") or "")
                        if ip and not quarantine_engine.is_quarantined(ip):
                            quarantine_engine.engage(ip, mac, reason="ARP auto-mitigation")
                            net_db.append_ledger_entry("guardian", "AUTO_QUARANTINE", f"{mac}@{ip}", "ARP anomaly auto-mitigation")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            snap_q = state.to_snapshot()
            net_db.save_posture_snapshot({
                "meta": snap_q.get("meta"),
                "devices": [{"device_key": d.get("device_key"), "mac": d.get("mac"), "ip": d.get("ip")} for d in snap_q.get("devices", [])],
                "threats": snap_q.get("threats", []),
            })
            try:
                snaps = net_db.get_last_snapshots(2)
                if len(snaps) >= 2:
                    b = {"devices": snaps[1]["snapshot"].get("devices", []), "threats": snaps[1]["snapshot"].get("threats", []), "meta": snaps[1]["snapshot"].get("meta", {})}
                    a = {"devices": snaps[0]["snapshot"].get("devices", []), "threats": snaps[0]["snapshot"].get("threats", []), "meta": snaps[0]["snapshot"].get("meta", {})}
                    dig = build_digest(posture_diff(b, a), snap_q.get("hypotheses_top") or [], snap_q.get("security_posture") or {})
                    # WS digest is broadcast by trigger_scan_and_broadcast after snapshot; stash for it
                    state.last_digest = dig  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception:
            pass
        state.scan_count += 1
        state.last_scan_duration_sec = round(time.perf_counter() - t0, 2)
        state.last_scan_time = time.strftime("%H:%M:%S")
    finally:
        state.scan_in_progress = False


async def _snapshot_async() -> Dict[str, Any]:
    return await asyncio.to_thread(state.to_snapshot)


async def trigger_scan_and_broadcast() -> Dict[str, Any]:
    await broadcast_ws({"type": "scan_status", "scan_in_progress": True})
    await asyncio.to_thread(_execute_blocking_scan)
    snap = await _snapshot_async()
    await broadcast_ws({"type": "full_state", "data": snap})
    dig = getattr(state, "last_digest", None)
    if dig:
        try:
            await broadcast_ws({"type": "digest", "data": dig})
        except Exception:
            pass
    return snap


async def periodic_scanner_task() -> None:
    # Initial immediate scan on startup
    await trigger_scan_and_broadcast()
    while True:
        await asyncio.sleep(22)
        if not state.scan_in_progress:
            await trigger_scan_and_broadcast()


def _on_wire_packet(pkt: Dict[str, Any]) -> None:
    # Passive census ring: sample 1/20 packets to bound DB write rate.
    try:
        if not hasattr(_on_wire_packet, "_n"):
            _on_wire_packet._n = 0  # type: ignore[attr-defined]
        _on_wire_packet._n += 1  # type: ignore[attr-defined]
        if _on_wire_packet._n % 20 == 0:  # type: ignore[attr-defined]
            net_db.record_passive_frame(
                float(pkt.get("timestamp") or time.time()), 0,
                str(pkt.get("protocol") or ""), str(pkt.get("eth_src") or ""),
                -100.0, int(pkt.get("bytes") or 0),
            )
    except Exception:
        pass
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
    title="NetPulse — Sovereign Network Intelligence",
    version="4.5.0",
    lifespan=lifespan,
)

_allowed_cors_origins = [
    o for o in os.environ.get(
        "NETPULSE_CORS_ORIGINS",
        "http://127.0.0.1:8765,http://localhost:8765",
    ).split(",")
    if o.strip()
]

# Optional shared-secret gate for the live WebSocket feed (/ws).
_WS_AUTH_TOKEN = os.environ.get("NETPULSE_WS_TOKEN", "").strip()

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_cors_origins,
    allow_origin_regex=os.environ.get(
        "NETPULSE_CORS_ORIGIN_REGEX",
        r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?$",
    ),
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Token"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data: blob: https://*.basemaps.cartocdn.com https://server.arcgisonline.com; "
        "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; font-src 'self' data:;"
    )
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(self)"
    return response


# Lightweight per-IP token-bucket rate limiter for expensive scan/control paths.
_RATE_BUCKETS: Dict[str, Any] = {}
_RATE_LOCK = None  # lazy asyncio lock

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    global _RATE_LOCK
    if _RATE_LOCK is None:
        _RATE_LOCK = asyncio.Lock()
    path = request.url.path
    sensitive = {"/api/scan", "/api/action/speedtest", "/api/action/area-scan", "/api/action/camera-sweep",
                 "/api/action/deep-nmap", "/api/action/port-range-scan", "/api/export/report"}
    if path in sensitive:
        host = request.client.host if request.client else "unknown"
        now = time.time()
        async with _RATE_LOCK:
            # Prune idle buckets to bound memory (unbounded dict was a leak)
            stale = [k for k, (_, ts) in _RATE_BUCKETS.items() if now - ts > 60]
            for k in stale:
                _RATE_BUCKETS.pop(k, None)
            tokens, ts = _RATE_BUCKETS.get(host, (10.0, now))
            # refill 1 token/sec up to 10
            tokens = min(10.0, tokens + (now - ts))
            if tokens < 1.0:
                return JSONResponse({"ok": False, "error": "Rate limit exceeded. Slow down."}, status_code=429)
            _RATE_BUCKETS[host] = (tokens - 1.0, now)
    return await call_next(request)


@app.get("/api/health")
async def api_health() -> JSONResponse:
    sub = subscription_engine.get_subscription_status()
    try:
        budget = subscription_engine.check_node_budget(len(state.devices))
    except Exception:
        budget = {"ok": True, "used": len(state.devices), "limit": int(sub.get("max_nodes") or 1), "remaining": 0}
    return JSONResponse({
        "status": "healthy",
        "version": "4.5.0",
        "oui_database_size": oui_db.loaded_count,
        "sniffer_active": state.sniffer.running,
        "scan_count": state.scan_count,
        "subscription_tier": sub["tier"],
        "node_budget": budget,
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


# Vendored third-party front-end assets (Leaflet map library) — served same-origin
# so the CSP never needs third-party script/style origins.
app.mount(
    "/vendor",
    StaticFiles(directory=os.path.join(STATIC_DIR, "vendor")),
    name="vendor_assets",
)


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
    return JSONResponse(await asyncio.to_thread(state.to_snapshot))


def _compute_full_hypotheses(limit: int = 500) -> List[Dict[str, Any]]:
    """Thread-safe wrapper: fresh threat audit + ranked hypothesis generation."""
    try:
        threats = audit_network_threats(state.devices, state.wifi_spectrum, state.net_info.ssid)
    except Exception:
        threats = []
    return generate_hypotheses(
        state.devices,
        state.wifi_spectrum or {},
        arp_anomalies=list(state.sniffer.arp_anomalies)[:25],
        threats=threats,
        limit=max(1, limit),
    )


@app.get("/api/hypotheses")
async def get_hypotheses(limit: int = 60) -> JSONResponse:
    """
    Full ranked detection-hypothesis feed — every raw signal converted into a
    Boltzmann-weighted, prioritized, action-backed hypothesis.
    """
    # Bound limit to avoid unbounded allocations
    limit = max(1, min(limit, 500))
    hyps = await asyncio.to_thread(_compute_full_hypotheses, limit)
    return JSONResponse({
        "ok": True,
        "count": len(hyps),
        "hypotheses": hyps,
    })


@app.get("/api/rf-geiger")
async def get_rf_geiger(bssid: str = "") -> JSONResponse:
    """Live RF Geiger reading for a BSSID (desktop + mobile walk-around)."""
    aps = (state.wifi_spectrum or {}).get("access_points", []) or []
    target = (bssid or "").strip().upper()
    ap = next((a for a in aps if str(a.get("bssid", "")).upper() == target), None) if target else (aps[0] if aps else None)
    tri = await asyncio.to_thread(mobile_telemetry_hub.triangulate_aps, aps)
    if not ap:
        return JSONResponse({"ok": False, "found": False, "bssid": target, "triangulation": tri})
    return JSONResponse({
        "ok": True,
        "found": True,
        "bssid": ap.get("bssid"),
        "ssid": ap.get("de_cloaked_ssid") or ap.get("ssid") or "<Hidden>",
        "signal_dbm": ap.get("signal_dbm"),
        "signal_pct": ap.get("signal_pct"),
        "channel": ap.get("channel"),
        "freq_mhz": ap.get("freq_mhz"),
        "band": ap.get("band"),
        "tsf_human": ap.get("tsf_human"),
        "attribution_verdict": ap.get("attribution_verdict"),
        "attribution_confidence": ap.get("attribution_confidence"),
        "hotspot_probability": ap.get("hotspot_probability"),
        "est_distance_m": ap.get("est_distance_m"),
        "triangulation": tri,
    })


@app.get("/api/graph")
async def get_identity_graph(format: str = "json") -> Response:
    """Unified Device Identity Graph (nodes/edges) + optional Graphviz SVG."""
    try:
        await asyncio.to_thread(net_db.sync_graph_from_state, state.devices, (state.wifi_spectrum or {}).get("access_points", []))
    except Exception:
        pass
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for d in state.devices:
        key = d.get("device_key") or d.get("mac") or d.get("ip", "")
        kind = "network_device"
        if d.get("is_gateway"):
            kind = "network_device"
        nodes.append({
            "node_id": str(key),
            "kind": kind,
            "label": d.get("custom_name") or d.get("display_name") or d.get("ip"),
            "ip": d.get("ip"),
            "mac": d.get("mac"),
            "attrs": {"brand": d.get("brand"), "model": d.get("model"), "category": d.get("category"), "confidence": d.get("confidence_score")},
        })
    gw = next((d for d in state.devices if d.get("is_gateway")), None)
    if gw:
        gk = gw.get("device_key") or gw.get("mac")
        for d in state.devices:
            if d is gw:
                continue
            edges.append({"src": str(gk), "dst": str(d.get("device_key") or d.get("mac") or ""), "relation": "talks_to", "weight": 0.8, "confidence": 0.85})
    for ap in (state.wifi_spectrum or {}).get("access_points", []) or []:
        bssid = str(ap.get("bssid") or "")
        if not bssid:
            continue
        nodes.append({"node_id": bssid, "kind": "wireless_ap", "label": ap.get("ssid") or "<Hidden>", "attrs": {"channel": ap.get("channel"), "verdict": ap.get("attribution_verdict")}})
        parent = ap.get("de_cloaked_parent") or ap.get("linked_lan_ip") or ""
        if parent:
            edges.append({"src": bssid, "dst": str(parent), "relation": "same_radio", "weight": 0.7, "confidence": ap.get("attribution_confidence") or 0.6})
    if format in ("graphviz", "svg"):
        lines = ["digraph netpulse {", "  rankdir=LR;"]
        for n in nodes:
            lines.append(f'  "{n["node_id"]}" [label="{str(n.get("label") or n["node_id"]).replace(chr(34), chr(39))}"]')
        for e in edges:
            lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e["relation"]}"]')
        lines.append("}")
        svg = "\n".join(lines) + "\n"
        return Response(content=svg, media_type="text/vnd.graphviz")
    return JSONResponse({"ok": True, "kinds": list(GRAPH_DEVICE_KINDS), "relations": list(GRAPH_RELATIONS),
                         "nodes": nodes, "edges": edges, "count_nodes": len(nodes), "count_edges": len(edges)})


@app.get("/api/device/{device_key}/evidence")
async def get_device_evidence(device_key: str) -> JSONResponse:
    """Why-this-verdict provenance: hypotheses + findings + hypotheses for a device."""
    hyps = await asyncio.to_thread(_compute_full_hypotheses, 500)
    device = next((d for d in state.devices if str(d.get("device_key")) == device_key or str(d.get("mac")) == device_key or str(d.get("ip")) == device_key), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_key} not found")
    related = [h for h in hyps if h.get("device_key") in (str(device.get("device_key")), str(device.get("mac")), str(device.get("ip"))) or h.get("ip") == device.get("ip")]
    try:
        db_ev = await asyncio.to_thread(net_db.get_evidence, str(device.get("device_key") or ""), 100)
    except Exception:
        db_ev = []
    return JSONResponse({
        "ok": True,
        "device_key": device.get("device_key"),
        "device": device,
        "evidence": db_ev + [
            {"kind": "device_finding", "ref": f.get("title"), "captured_at": device.get("last_seen"), "weight": 0.8} for f in (device.get("security_findings") or [])
        ] + [
            {"kind": "hypothesis", "ref": h["id"], "captured_at": h.get("generated_at"), "weight": h.get("expected_value", 0)} for h in related
        ],
        "hypotheses": related,
    })


@app.get("/api/device/{device_key}/proof")
async def get_device_proof(device_key: str) -> JSONResponse:
    """Proof Mode S11: multi-vector evidence extraction, weighted fusion, and calibrated probability."""
    device = next((d for d in state.devices if str(d.get("device_key")) == device_key or str(d.get("mac")) == device_key or str(d.get("ip")) == device_key), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_key} not found")
    aps = getattr(state, "wifi_aps", [])
    vectors = extract_evidence_vectors(device, aps)
    verdict = fuse_evidence(vectors, default_identity=str(device.get("brand") or device.get("display_name") or "Generic Host"))
    return JSONResponse({
        "ok": True,
        "device_key": device_key,
        "proof": verdict.to_dict(),
    })


@app.post("/api/control/{device_key}")
async def unified_control(device_key: str, req: ControlRequest) -> JSONResponse:
    """Universal command plane: capability -> mapped prober (Roku/Sonos/Kasa/gateway...).

    Dangerous actions (reboot/volume/reset) require confirm=True, mirroring the
    confirm-gated copilot policy. Every call is journalized to the ledger.
    """
    gate = _require_tier("smart_home_control")
    if gate:
        return gate
    allowed = CONTROL_CAPABILITIES.get(req.capability, [])
    if req.action not in allowed and req.action not in ("status", "discover"):
        return JSONResponse({"ok": False, "error": f"Action '{req.action}' not in capability '{req.capability}': {allowed}"}, status_code=400)
    dangerous = {"reboot", "reset", "quarantine", "release"}
    if req.action in dangerous and not req.confirm:
        return JSONResponse({"ok": False, "error": "Confirm gate: pass confirm=true for dangerous actions", "needs_confirm": True}, status_code=409)
    device = next((d for d in state.devices if str(d.get("device_key")) == device_key or str(d.get("mac")) == device_key or str(d.get("ip")) == device_key), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_key} not found")
    ip = device.get("ip", "")
    proto = "kasa"
    caps = device.get("control_capabilities") or []
    # Best-effort mapping to existing probers; status/discover is read-only.
    if req.action in ("status", "discover"):
        res = {"ok": True, "ip": ip, "capability": req.capability, "action": req.action, "capabilities": caps, "control_capabilities": caps}
    elif any("Roku" in c for c in caps) and req.capability == "media":
        ok, msg = await asyncio.to_thread(send_roku_keypress, ip, str(req.value or "Home"))
        res = {"ok": ok, "message": msg, "mapped": "roku_ecp"}
    elif any("Sonos" in c for c in caps) and req.capability in ("media", "power"):
        vol = int(req.value) if isinstance(req.value, (int, float)) else 25
        act = str(req.value) if isinstance(req.value, str) else req.action
        res = await asyncio.to_thread(control_sonos_speaker, ip, act, max(0, min(100, vol)))
        res["mapped"] = "sonos_upnp"
    else:
        res = await asyncio.to_thread(control_smart_home_device, ip, proto, str(req.action))
        res["mapped"] = "smart_home"
    inverse = {"status": "restore", "note": "inverse recorded for toggle/power reversal"}
    if req.action == "on":
        inverse = {"action": "off"}
    elif req.action == "off":
        inverse = {"action": "on"}
    elif req.action in ("play", "pause"):
        inverse = {"action": "pause" if req.action == "play" else "play"}
    res["inverse"] = inverse
    cmd_json = {"device_key": device_key, "ip": ip, "capability": req.capability, "action": req.action, "value": req.value}
    try:
        aid = await asyncio.to_thread(net_db.record_action, f"{req.capability}:{req.action}", cmd_json, inverse, "operator", str(res)[:300])
        res["action_id"] = aid
    except Exception:
        pass
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "CONTROL", f"{device_key}@{ip}", f"{req.capability}:{req.action} -> {res}")
    await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
    return JSONResponse(res)


@app.get("/api/actions")
async def list_actions(limit: int = 50) -> JSONResponse:
    rows = await asyncio.to_thread(net_db.list_actions, max(1, min(limit, 200)))
    # Enrich with parsed command/inverse for UI undo buttons
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            import json as _json
            d["command"] = _json.loads(d.get("command_json") or "{}")
            d["inverse"] = _json.loads(d.get("inverse_json") or "{}")
        except Exception:
            d["command"], d["inverse"] = {}, {}
        out.append(d)
    return JSONResponse({"ok": True, "actions": out})


@app.post("/api/actions/{action_id}/undo")
async def undo_action(action_id: int) -> JSONResponse:
    row = await asyncio.to_thread(net_db.get_action, action_id)
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    if str(row.get("status")) == "undone":
        return JSONResponse({"ok": False, "error": "already undone"})
    try:
        import json as _json
        cmd = _json.loads(row.get("command_json") or "{}")
        inv = _json.loads(row.get("inverse_json") or "{}")
    except Exception:
        cmd, inv = {}, {}
    device_key = cmd.get("device_key") or ""
    inv_action = inv.get("action") or "status"
    # Re-dispatch through unified control semantics (read-only status for unknown inverses)
    if inv_action in ("status", "restore"):
        result = {"ok": True, "undone": action_id, "note": "status-restore; no state change required"}
    else:
        device = next((d for d in state.devices if str(d.get("device_key")) == device_key or str(d.get("ip")) == device_key), None)
        if not device:
            raise HTTPException(status_code=404, detail="Device for undo not found")
        ip = device.get("ip", "")
        r2 = await asyncio.to_thread(control_smart_home_device, ip, "kasa", inv_action)
        result = {"ok": True, "undone": action_id, "device_key": device_key, "inverse_action": inv_action, "result": r2}
    await asyncio.to_thread(net_db.mark_action_undone, action_id)
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "UNDO", f"action:{action_id}@{device_key}", str(result)[:300])
    return JSONResponse(result)


@app.post("/api/action/firmware-audit")
async def action_firmware_audit(req: DomainIntelRequest) -> JSONResponse:
    """Firmware exposure audit. Body: target=firmware URL. Requires consent + Enterprise."""
    gate = _require_tier("forensic_export")
    if gate:
        return gate
    # DomainIntelRequest.target carries URL; require explicit device-derived consent via Trust UI
    res = await asyncio.to_thread(firmware_fetch_and_audit, req.target, True)
    try:
        await asyncio.to_thread(net_db.append_ledger_entry, "operator", "FIRMWARE_AUDIT", req.target[:200], str(res)[:300])
    except Exception:
        pass
    return JSONResponse(res)


@app.post("/api/graph/spore")
async def post_graph_spore(req: Dict[str, Any]) -> JSONResponse:
    """Spore federation: accept signed capsule, merge max-confidence edges."""
    gate = _require_tier("forensic_export")
    if gate:
        return gate
    nodes = req.get("nodes") or []
    edges = req.get("edges") or []
    merged_n = merged_e = 0
    for n in nodes:
        nid = str(n.get("node_id") or "")
        if nid:
            await asyncio.to_thread(net_db.upsert_graph_node, nid, str(n.get("kind") or "network_device"), n.get("attrs") or {})
            merged_n += 1
    for e in edges:
        if e.get("src") and e.get("dst"):
            await asyncio.to_thread(net_db.upsert_graph_edge, str(e["src"]), str(e["dst"]), str(e.get("relation") or "talks_to"), float(e.get("weight") or 0.5), float(e.get("confidence") or 0.5), str(e.get("evidence_id") or ""))
            merged_e += 1
    try:
        await asyncio.to_thread(net_db.append_ledger_entry, "mesh", "SPORE_MERGE", str(req.get("sender_id") or "")[:80], f"nodes={merged_n} edges={merged_e}")
    except Exception:
        pass
    return JSONResponse({"ok": True, "merged_nodes": merged_n, "merged_edges": merged_e})


@app.get("/api/ble/scan")
async def get_ble_census() -> JSONResponse:
    """BLE census (Stage 11) + hidden-tether classification (Stage 12)."""
    gate = _require_tier("area_scan")
    if gate:
        return gate
    res = await asyncio.to_thread(scan_ble_census, 4.0)
    correlated = await asyncio.to_thread(correlate_ble_to_lan, res.get("devices", []), state.devices)
    tethers = [classify_hidden_tether(ap) for ap in ((state.wifi_spectrum or {}).get("access_points", []) or []) if ap.get("is_hidden")]
    res["correlated_lan"] = correlated
    res["hidden_tethers_stage12"] = tethers
    return JSONResponse(res)


@app.get("/api/metrics")
async def get_metrics() -> Response:
    """Prometheus exposition (no auth; observability hook for Enterprise)."""
    snap = state.to_snapshot()
    try:
        g = await asyncio.to_thread(net_db.get_graph)
        snap["graph_nodes"] = g.get("count_nodes", 0)
        snap["graph_edges"] = g.get("count_edges", 0)
        snap["quarantined_active"] = len(quarantine_engine.list_quarantined())
        snap["sinkhole_rules"] = len(await asyncio.to_thread(net_db.list_sinkhole_rules))
        snap["passive_frames"] = await asyncio.to_thread(net_db.count_passive_frames)
    except Exception:
        pass
    return Response(content=prometheus_text(snap), media_type="text/plain; version=0.0.4")


@app.get("/api/threat-field")
async def get_threat_field() -> JSONResponse:
    """Continuous collapse/measure field over current hypotheses."""
    hyps = await asyncio.to_thread(_compute_full_hypotheses, 200)
    return JSONResponse(compute_threat_field(hyps))


@app.post("/api/explain")
async def post_explain(req: ExplainRequest) -> JSONResponse:
    """Templated copilot: explain + suggest. Requires smart_home_control tier; never auto-executes."""
    gate = _require_tier("smart_home_control")
    if gate:
        return gate
    device = next((d for d in state.devices if str(d.get("device_key")) == req.device_key or str(d.get("mac")) == req.device_key or str(d.get("ip")) == req.device_key), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {req.device_key} not found")
    return JSONResponse(await asyncio.to_thread(explain_device, device, req.question))


@app.get("/api/posture/diff")
async def get_posture_diff() -> JSONResponse:
    """Diff last two posture snapshots (news-feed digest, S5.3)."""
    snaps = await asyncio.to_thread(net_db.get_last_snapshots, 2)
    if len(snaps) < 1:
        snap = state.to_snapshot()
        await asyncio.to_thread(net_db.save_posture_snapshot, {"meta": snap.get("meta"), "devices": [{"device_key": d.get("device_key"), "mac": d.get("mac"), "ip": d.get("ip")} for d in snap.get("devices", [])], "threats": snap.get("threats", [])})
        return JSONResponse({"ok": True, "note": "first snapshot saved; diff available after next scan", "diff": None})
    if len(snaps) < 2:
        return JSONResponse({"ok": True, "note": "need two snapshots", "diff": None})
    before, after = snaps[1]["snapshot"], snaps[0]["snapshot"]
    # Rehydrate minimal shape for posture_diff
    b = {"devices": before.get("devices", []), "threats": before.get("threats", []), "meta": before.get("meta", {})}
    a = {"devices": after.get("devices", []), "threats": after.get("threats", []), "meta": after.get("meta", {})}
    return JSONResponse({"ok": True, "diff": posture_diff(b, a)})


@app.get("/api/scan-strategy")
async def get_scan_strategy(env: str = "home") -> JSONResponse:
    row = await asyncio.to_thread(net_db.get_scan_strategy, env)
    bandit = UCB1Bandit()
    suggested = bandit.select_arm()
    return JSONResponse({"ok": True, "env": env, "saved": row, "suggested_arm": suggested, "dwell_ms": dwell_for_arm(suggested), "arms": bandit.arms, "reward_guide": "reward = identities/wall_sec - 0.1*fp"})


@app.post("/api/scan-strategy")
async def post_scan_strategy(req: ScanStrategyRequest) -> JSONResponse:
    gate = _require_tier("area_scan")
    if gate:
        return gate
    bandit = UCB1Bandit()
    arm = req.arm or bandit.select_arm()
    if req.reward:
        bandit.update(arm, float(req.reward))
    stats = bandit.stats()
    params = {"arm": arm, "dwell_ms": dwell_for_arm(arm)}
    await asyncio.to_thread(net_db.save_scan_strategy, req.env or "home", params, stats)
    # Adaptive suggest: reward from last scan if client supplied gains
    suggested = bandit.select_arm()
    return JSONResponse({"ok": True, "env": req.env, "arm": arm, "suggested_next": suggested, "stats": stats, "params": params})


@app.get("/api/net/dns/sinkhole")
async def list_sinkhole() -> JSONResponse:
    rows = await asyncio.to_thread(net_db.list_sinkhole_rules)
    return JSONResponse({"ok": True, "rules": rows})


@app.post("/api/net/dns/sinkhole")
async def add_sinkhole(req: SinkholeRequest) -> JSONResponse:
    gate = _require_tier("quarantine")
    if gate:
        return gate
    try:
        rid = await asyncio.to_thread(net_db.add_sinkhole_rule, req.domain, req.action)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "SINKHOLE_ADD", req.domain[:200], f"action={req.action}")
    # dnsmasq drop-in content (local mode) — returned for install, not auto-installed
    dropin = f"address=/{req.domain.strip().lower()}/0.0.0.0\n" if req.action == "sinkhole" else f"address=/{req.domain.strip().lower()}/127.0.0.1\n"
    return JSONResponse({"ok": True, "id": rid, "domain": req.domain, "dnsmasq_dropin": dropin})


@app.delete("/api/net/dns/sinkhole/{domain:path}")
async def delete_sinkhole(domain: str) -> JSONResponse:
    gate = _require_tier("quarantine")
    if gate:
        return gate
    removed = await asyncio.to_thread(net_db.delete_sinkhole_rule, domain)
    if not removed:
        raise HTTPException(status_code=404, detail="Rule not found")
    return JSONResponse({"ok": True, "deleted": domain})


@app.get("/api/ar/room")
async def get_ar_room(bssid: str = "") -> JSONResponse:
    aps = (state.wifi_spectrum or {}).get("access_points", []) or []
    tele = mobile_telemetry_hub.get_status() if hasattr(mobile_telemetry_hub, "get_status") else {}
    mag = float(tele.get("mag_total_ut") or 0.0)
    az = float(tele.get("azimuth_deg") or 0.0)
    res = await asyncio.to_thread(room_for_device, bssid, aps, mag, az)
    return JSONResponse(res)


@app.post("/api/gateway/ubus/status")
async def post_ubus_status(req: Dict[str, Any]) -> JSONResponse:
    gate = _require_tier("gateway_control")
    if gate:
        return gate
    ip = str(req.get("ip") or state.net_info.gateway_ip or "")
    return JSONResponse(await asyncio.to_thread(ubus_status, ip))


@app.post("/api/gateway/ubus/firewall")
async def post_ubus_firewall(req: Dict[str, Any]) -> JSONResponse:
    gate = _require_tier("gateway_control")
    if gate:
        return gate
    ip = str(req.get("ip") or state.net_info.gateway_ip or "")
    res = await asyncio.to_thread(
        ubus_firewall_add, ip, req.get("rule") or {},
        str(req.get("username") or ""), str(req.get("password") or ""),
        bool(req.get("confirm")),
    )
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "UBUS_FIREWALL", ip, str(res)[:300])
    return JSONResponse(res)


@app.get("/api/rules")
async def list_rules() -> JSONResponse:
    rows = await asyncio.to_thread(net_db.list_rules)
    return JSONResponse({"ok": True, "rules": rows, "count": len(rows)})


@app.post("/api/rules")
async def create_rule(req: Dict[str, Any]) -> JSONResponse:
    gate = _require_tier("forensic_export")
    if gate:
        return gate
    compiled = compile_rule(req)
    if not compiled["ok"]:
        return JSONResponse(compiled, status_code=400)
    await asyncio.to_thread(net_db.save_rule, req, compiled["manifest"]["sha256"])
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "RULE_ADD", str(req.get("id")), str(compiled["manifest"])[:300])
    return JSONResponse({"ok": True, "manifest": compiled["manifest"]})


@app.post("/api/rules/audit")
async def audit_rules(req: Dict[str, Any]) -> JSONResponse:
    rules = await asyncio.to_thread(net_db.list_rules)
    payload = req.get("payload") or {}
    hits = audit_payload(payload, rules)
    return JSONResponse({"ok": True, "hits": hits, "rule_count": len(rules)})


@app.get("/api/digest")
async def get_digest() -> JSONResponse:
    snaps = await asyncio.to_thread(net_db.get_last_snapshots, 2)
    diff = None
    if len(snaps) >= 2:
        b = {"devices": snaps[1]["snapshot"].get("devices", []), "threats": snaps[1]["snapshot"].get("threats", []), "meta": snaps[1]["snapshot"].get("meta", {})}
        a = {"devices": snaps[0]["snapshot"].get("devices", []), "threats": snaps[0]["snapshot"].get("threats", []), "meta": snaps[0]["snapshot"].get("meta", {})}
        diff = posture_diff(b, a)
    hyps = await asyncio.to_thread(_compute_full_hypotheses, 50)
    snap = state.to_snapshot()
    posture = snap.get("security_posture") or snap.get("meta") or {}
    return JSONResponse(build_digest(diff, hyps, posture))


@app.get("/api/mesh/status")
async def get_mesh_status() -> JSONResponse:
    import hashlib as _h
    nid = _h.sha256((state.net_info.mac or state.net_info.ip or "node").encode()).hexdigest()[:12]
    node = MeshNode(nid, seed=0)
    node.heartbeat(nid)
    return JSONResponse({
        "ok": True,
        "node_id": nid,
        "state": node.state,
        "term": node.term,
        "members": [nid],
        "partition_example": partition_key("AA:BB:CC:DD:EE:FF", 1),
    })


@app.post("/api/mesh/heartbeat")
async def post_mesh_heartbeat(req: Dict[str, Any]) -> JSONResponse:
    import hashlib as _h
    nid = _h.sha256((state.net_info.mac or state.net_info.ip or "node").encode()).hexdigest()[:12]
    node = MeshNode(nid)
    node.heartbeat(str(req.get("from") or nid))
    return JSONResponse({"ok": True, "node_id": nid, "seen": node._seen})


@app.get("/api/policy/arp")
async def get_arp_policy() -> JSONResponse:
    return JSONResponse({"ok": True, "auto_quarantine": os.environ.get("NETPULSE_AUTO_QUARANTINE", "0") == "1"})


@app.post("/api/policy/arp")
async def post_arp_policy(req: Dict[str, Any], request: Request) -> JSONResponse:
    adm = _require_admin(request)
    if adm:
        return adm
    enabled = bool(req.get("enabled"))
    os.environ["NETPULSE_AUTO_QUARANTINE"] = "1" if enabled else "0"
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "POLICY_ARP", "auto_quarantine", str(enabled))
    return JSONResponse({"ok": True, "auto_quarantine": enabled})


@app.post("/api/passive/census/run")
async def run_passive_census(budget_seconds: float = 10.0) -> JSONResponse:
    """Trigger a quick active survey and persist frames (Stage-13 fast path)."""
    gate = _require_tier("area_scan")
    if gate:
        return gate
    try:
        wifi = await asyncio.to_thread(wireless_engine.scan_wifi_spectrum, True, state.devices)
        state.wifi_spectrum = wifi
        saved = 0
        for ap in (wifi.get("access_points") or [])[:20]:
            try:
                await asyncio.to_thread(
                    net_db.record_passive_frame,
                    time.time(), int(ap.get("freq_mhz") or 0), "BEACON",
                    str(ap.get("bssid") or ""), float(ap.get("signal_dbm") or -100),
                    200,
                )
                saved += 1
            except Exception:
                continue
        return JSONResponse({"ok": True, "stage": 13, "saved_frames": saved, "budget_seconds": budget_seconds})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)[:300]}, status_code=500)


@app.get("/api/passive/census")
async def get_passive_census(budget_seconds: float = 10.0) -> JSONResponse:
    """Stage-13 dwell schedule + recent passive frames (ring accounting)."""
    rows = dwell_schedule(float(budget_seconds))
    budget = coverage_budget(rows)
    try:
        recent = await asyncio.to_thread(net_db.recent_passive_frames, 20)
        count = await asyncio.to_thread(net_db.count_passive_frames)
    except Exception:
        recent, count = [], 0
    return JSONResponse({"ok": True, "stage": 13, "schedule": rows, "budget": budget, "frames_total": count, "recent": recent})


@app.get("/api/graph/kibana")
async def get_graph_kibana() -> Response:
    g = await asyncio.to_thread(net_db.get_graph)
    lines: List[str] = []
    for n in g.get("nodes", []):
        lines.append(json.dumps({"node_id": n.get("node_id"), "kind": n.get("kind"), "ts": time.time()}))
    for e in g.get("edges", []):
        lines.append(json.dumps({"src": e.get("src"), "dst": e.get("dst"), "relation": e.get("relation"), "ts": time.time()}))
    return Response(content="\n".join(lines) + "\n", media_type="application/x-ndjson")


@app.get("/api/accuracy")
async def get_accuracy_audit() -> JSONResponse:
    """S12 Accuracy Harness: 16-stage precision/recall, Brier score, and confusion-cost matrix."""
    report = evaluate_accuracy()
    return JSONResponse(report)


@app.post("/api/evidence/bundle")
async def export_evidence_bundle(req: EvidenceBundleRequest) -> JSONResponse:
    """Bet 1 CASE/UCO 1.3 Admissible Evidence Bundle export with ledger head hash and HMAC signature."""
    gate = _require_tier("forensic_export")
    if gate:
        return gate
    device = next((d for d in state.devices if str(d.get("device_key")) == req.device_key or str(d.get("mac")) == req.device_key or str(d.get("ip")) == req.device_key), None)
    if not device:
        device = {"device_key": req.device_key, "mac": req.device_key if ":" in req.device_key else "", "ip": req.device_key if "." in req.device_key else ""}
    aps = getattr(state, "wifi_aps", [])
    vectors = extract_evidence_vectors(device, aps)
    verdict = fuse_evidence(vectors, default_identity=str(device.get("brand") or "Generic Host"))
    ledger_entries = await asyncio.to_thread(net_db.get_ledger_entries, 100)
    secret = subscription_engine.get_signing_secret()
    bundle = build_case_evidence_bundle(
        device,
        verdict.to_dict(),
        ledger_entries,
        signing_secret=secret,
        window_hours=req.window_hours,
    )
    return JSONResponse({"ok": True, "bundle": bundle})


@app.post("/api/evidence/verify")
async def verify_evidence_bundle_endpoint(req: EvidenceVerifyRequest) -> JSONResponse:
    """Bet 1 Offline FOSS verifier for CASE/UCO evidence bundles."""
    secret = subscription_engine.get_signing_secret()
    res = verify_evidence_bundle(req.bundle, signing_secret=secret)
    return JSONResponse(res)


@app.get("/api/chronicle")
async def get_network_chronicle_endpoint(window_days: int = 7) -> JSONResponse:
    """Bet 4 The Network Remembers: weekly factual narrative, rhythm profiles, and drift anomalies."""
    ledger_entries = await asyncio.to_thread(net_db.get_ledger_entries, 200)
    hyps = await asyncio.to_thread(_compute_full_hypotheses, 100)
    chronicle = generate_network_chronicle(state.devices, ledger_entries, hyps, window_days=window_days)
    return JSONResponse(chronicle)


@app.get("/api/chronicle/wrapped")
async def get_chronicle_wrapped_endpoint() -> JSONResponse:
    """Bet 4 NetPulse Wrapped: year-end local statistics and countermeasure highlights."""
    ledger_entries = await asyncio.to_thread(net_db.get_ledger_entries, 500)
    wrapped = generate_netpulse_wrapped(state.devices, ledger_entries, scan_count=getattr(state, "scan_count", 42))
    return JSONResponse(wrapped)


@app.post("/api/scan")
async def manual_scan() -> JSONResponse:
    snap = await trigger_scan_and_broadcast()
    return JSONResponse(snap)


@app.get("/api/device-image/{ip}")
async def proxy_device_image(ip: str) -> Response:
    """Fetch and proxy actual hardware PNG icon directly from Roku / UPnP device on the LAN."""
    # SSRF Guard: Validate ip is a valid IPv4/IPv6 address and not a loopback / cloud metadata IP
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_multicast or str(ip_obj) == "169.254.169.254":
            raise HTTPException(status_code=400, detail="Invalid target address")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP format")

    candidate_urls = [f"http://{ip}:8060/device-image.png"]
    dev = next((d for d in state.devices if d.get("ip") == ip), None)
    if dev:
        upnp_icon = dev.get("upnp_info", {}).get("icon_url")
        if upnp_icon and isinstance(upnp_icon, str):
            parsed_host = urllib.parse.urlparse(upnp_icon).hostname
            if parsed_host == ip and upnp_icon not in candidate_urls:
                candidate_urls.insert(0, upnp_icon)

    def _fetch() -> Optional[bytes]:
        for url in candidate_urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/2.0"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    data = resp.read(524288)
                    ctype = resp.headers.get("Content-Type", "")
                    if ctype and not ctype.startswith("image/"):
                        continue
                    return data
            except Exception:
                continue
        return None

    img_bytes = await asyncio.to_thread(_fetch)
    if not img_bytes:
        raise HTTPException(status_code=404, detail="Device hardware image unavailable")
    return Response(content=img_bytes, media_type="image/png")


@app.post("/api/device/{device_key}/customize")
async def customize_device(request: Request, device_key: str, req: CustomizeDeviceRequest) -> JSONResponse:
    adm_err = _require_admin(request)
    if adm_err:
        return adm_err
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
async def delete_device_endpoint(request: Request, device_key: str) -> JSONResponse:
    adm_err = _require_admin(request)
    if adm_err:
        return adm_err
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


@app.get("/api/ledger")
async def get_events_ledger(limit: int = 50) -> JSONResponse:
    """Retrieve the append-only tamper-evident forensic event ledger."""
    entries = await asyncio.to_thread(net_db.get_ledger_entries, limit)
    verification = await asyncio.to_thread(net_db.verify_ledger_chain)
    return JSONResponse({"ok": True, "entries": entries, "verification": verification})


@app.get("/api/ledger/verify")
async def verify_events_ledger(limit: int = 10000) -> JSONResponse:
    """Cryptographically verify the SHA-256 hash chain of the forensic event ledger."""
    res = await asyncio.to_thread(net_db.verify_ledger_chain, max(1, min(limit, 50000)))
    return JSONResponse(res)


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
        await asyncio.to_thread(net_db.update_device_customization, dkey, trust_state="watchlist")
        await asyncio.to_thread(net_db.append_ledger_entry, "operator", "QUARANTINE_RELEASE", f"{dkey}@{req.ip}", "Operator manually released host from quarantine")
        state.devices = await asyncio.to_thread(net_db.get_all_devices)
        await broadcast_ws({"type": "full_state", "data": state.to_snapshot()})
        return JSONResponse({"ok": True, "ip": req.ip, "quarantined": False, "released": released})
    entry = quarantine_engine.engage(req.ip, req.mac, reason="Guardian Shield Active Quarantine")
    await asyncio.to_thread(net_db.update_device_customization, dkey, trust_state="intruder")
    await asyncio.to_thread(net_db.append_ledger_entry, "operator", "QUARANTINE_ENGAGE", f"{dkey}@{req.ip}", "Operator engaged Guardian Shield active TCP RST quarantine")
    state.devices = await asyncio.to_thread(net_db.get_all_devices)
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


def _scrub_tool_output(text: Any) -> str:
    """Remove absolute tool paths from subprocess stderr (info leak)."""
    s = str(text or "")
    for bad in ("/usr/bin/nmap", "/usr/bin/mtr", "/bin/sh", "/home/jg/"):
        s = s.replace(bad, "[redacted]")
    return s[:4000]


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
            return {"ok": proc.returncode == 0, "ip": req.ip, "output": _scrub_tool_output(proc.stdout or proc.stderr)}
        except Exception as e:
            return {"ok": False, "ip": req.ip, "output": _scrub_tool_output(e)}

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
            return {"ok": proc.returncode == 0, "ip": req.ip, "output": _scrub_tool_output(proc.stdout or proc.stderr)}
        except Exception as e:
            return {"ok": False, "ip": req.ip, "output": _scrub_tool_output(e)}

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
    gate = _require_tier("forensic_export")
    if gate:
        return gate
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
async def deactivate_license_endpoint(request: Request) -> JSONResponse:
    # Guard: unauthenticated revocation would let ANY network peer wipe a paid license.
    adm_err = _require_admin(request)
    if adm_err:
        return adm_err
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
    # Optional live-stream token gate: set NETPULSE_WS_TOKEN to require
    # `?token=...` from non-loopback peers (desktop app on localhost is exempt).
    if _WS_AUTH_TOKEN:
        client_host = ws.client.host if ws.client else ""
        provided_token = ws.query_params.get("token") or ""
        if client_host not in ("127.0.0.1", "::1", "testclient") and provided_token != _WS_AUTH_TOKEN:
            try:
                await ws.close(code=4401)  # policy violation: unauthorized
            except Exception:
                pass
            return
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
