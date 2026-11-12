"""Tenfold improvements: BLE, profile keys, threat propagation, new API surface."""
import sys
sys.path.insert(0, "/home/jg")

from netpulse.ble_census import (
    classify_hidden_tether,
    correlate_ble_to_lan,
    parse_apple_continuity,
)
from netpulse.intel_hypotheses import FINDING_PLAYBOOK, _hyp_id, generate_hypotheses
from netpulse.fingerprint import audit_network_threats
from netpulse.profile_keys import CONTROL_CAPABILITIES, normalize_extended_iot, normalize_mdns_entry
from netpulse.proc import stop_process_gracefully

def test_apple_continuity_iphone():
    payload = bytes.fromhex("4c00012a")
    out = parse_apple_continuity(payload)
    assert out.get("apple") is True
    assert out.get("continuity_type") == "iPhone"
    assert out.get("airdrop_capable") is True

def test_apple_non_apple():
    assert parse_apple_continuity(b"\x00\x11\x22\x33") == {}

def test_tether_classifier():
    ap = {"bssid": "02:11:22:33:44:55", "rate_mbps": 65, "signal_dbm": -50, "security": "OPEN"}
    out = classify_hidden_tether(ap)
    assert out["stage"] == 12
    assert out["hotspot_probability"] >= 0.55

def test_ble_correlate():
    ble = [{"addr": "AA:BB:CC:DD:EE:FF", "rssi": -60, "vendor": "Apple",
            "ble_identity": {"continuity_type": "iPhone"}}]
    lan = [{"device_key": "K1", "mac": "00:1A:2B:11:22:33", "ip": "192.168.12.5", "brand": "Apple Inc."}]
    out = correlate_ble_to_lan(ble, lan)
    assert len(out) == 1
    assert out[0]["stage"] == 11
    assert 0 < out[0]["confidence"] <= 1

def test_mdns_normalize():
    e = {"service": "_googlecast._tcp.local.", "instance": "Living Room"}
    out = normalize_mdns_entry(e)
    assert out["service_type"] == "_googlecast._tcp.local."
    assert out["instance_name"] == "Living Room"

def test_extended_iot_normalize():
    ext = {"sonos": {"roomName": "Kitchen", "modelName": "Move"}}
    out = normalize_extended_iot(ext)
    assert out["sonos"]["room_name"] == "Kitchen"
    assert out["sonos"]["model"] == "Move"

def test_control_capabilities_present():
    assert "power" in CONTROL_CAPABILITIES
    assert "on" in CONTROL_CAPABILITIES["power"]

def test_hyp_id_unique_per_title():
    a = _hyp_id("device_finding", "K1", "Telnet exposed")
    b = _hyp_id("device_finding", "K1", "Deprecated TLS")
    assert a != b
    assert a.startswith("hyp_")

def test_playbook_matches_real_titles():
    # Direct playbook scan mirrors generate_hypotheses loop
    def find(title):
        low = title.lower()
        for pb in FINDING_PLAYBOOK:
            if str(pb["k"]).lower() in low:
                return pb["k"]
        return None
    assert find("Cleartext Telnet Service Exposed (TCP 23)") == "telnet"
    assert find("Deprecated TLS Protocol Version on TCP :443") == "deprecated tls"
    assert find("Unauthenticated Docker Engine API Exposed (TCP 2375)") in ("unauthenticated docker", "docker")

def test_threat_propagation_keeps_identity():
    devices = [{
        "device_key": "A1", "mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.12.5",
        "is_online": True, "is_gateway": False,
        "security_findings": [{"severity": "CRITICAL", "title": "Cleartext Telnet", "description": "d"}],
    }]
    threats = audit_network_threats(devices, {"access_points": []}, "")
    lan = [t for t in threats if t["category"] == "LAN_VULNERABILITY"]
    assert lan, "expected LAN_VULNERABILITY threat"
    assert lan[0].get("device_key") == "A1"
    assert lan[0].get("ip") == "192.168.12.5"

def test_hypotheses_no_collapse_distinct_threats():
    devices = [{
        "device_key": "A1", "mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.12.5",
        "custom_name": "Test", "risk_score": 90,
        "security_findings": [
            {"severity": "CRITICAL", "title": "Cleartext Telnet Service Exposed", "description": "x"},
            {"severity": "HIGH", "title": "Deprecated TLS Protocol Version", "description": "y"},
        ],
    }]
    hyps = generate_hypotheses(devices, {"access_points": []}, [], [], 10)
    ids = [h["id"] for h in hyps]
    assert len(ids) == len(set(ids)), "hyp IDs must be unique per title"
    assert len(hyps) >= 2

def test_proc_stop_gracefully_no_crash():
    import subprocess
    p = subprocess.Popen(["sleep", "0.05"])
    stop_process_gracefully(p)
    assert p.poll() is not None

def test_new_api_surface():
    from netpulse.server import app
    from fastapi.testclient import TestClient
    c = TestClient(app)
    assert c.get("/api/rf-geiger?bssid=00:11:22:33:44:55").status_code == 200
    g = c.get("/api/graph")
    assert g.status_code == 200 and g.json()["ok"] is True
    assert c.get("/api/ble/scan").status_code in (200, 402)  # 402 on free tier is correct gating
    assert c.get("/api/device/nope/evidence").status_code in (200, 404)  # 404 if empty DB
    bad = c.post("/api/control/x", json={"capability": "power", "action": "invalid_action"})
    assert bad.status_code in (400, 402, 404)
