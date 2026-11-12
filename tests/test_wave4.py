"""Wave 4: AR, ubus, rule compiler, digest, kibana."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from netwide.ar_fusion import fuse_rssi_mag, room_for_device
from netwide.rules import audit_payload, compile_rule, validate_rule
from netwide.digest import build_digest

def test_fuse_same_room():
    out = fuse_rssi_mag(-50, 30.0, 90.0)
    assert out["stage"] == 15
    assert "Same Room" in out["room_estimate"]
    assert out["heading_hint"] == "E"

def test_room_for_device():
    aps = [{"bssid": "AA:BB:CC:DD:EE:01", "ssid": "Net", "signal_dbm": -55}]
    out = room_for_device("AA:BB:CC:DD:EE:01", aps, 0.0, 0.0)
    assert out["found"] is True

def test_rule_compile_and_validate():
    good = {"id": "r1", "title": "Telnet", "severity": "HIGH", "category": "net", "match": "telnet", "action": "disable"}
    assert validate_rule(good)["ok"] is True
    c = compile_rule(good)
    assert c["ok"] is True
    assert len(c["manifest"]["sha256"]) == 64
    bad = compile_rule({"id": "x", "title": "t", "severity": "HIGH", "category": "c", "match": "[", "action": "a"})
    assert bad["ok"] is False

def test_audit_payload():
    rules = [{"id": "r1", "title": "Telnet", "severity": "HIGH", "match": "telnet", "action": "disable"}]
    hits = audit_payload({"a": "Cleartext Telnet exposed"}, rules)
    assert len(hits) == 1

def test_digest():
    d = build_digest({"changed_devices_new": ["B"], "posture_delta": 2}, [{"severity": "HIGH", "title": "T", "expected_value": 0.9}], {"score": 92})
    assert "Posture 92/100" in d["text"]

def test_wave4_api():
    from fastapi.testclient import TestClient
    from netwide.server import app
    c = TestClient(app)
    assert c.get("/api/ar/room?bssid=AA%3ABB%3ACC%3ADD%3AEE%3A01").status_code == 200
    assert c.get("/api/digest").status_code == 200
    assert c.get("/api/rules").status_code == 200
    assert c.get("/api/graph/kibana").status_code == 200
    assert c.post("/api/rules/audit", json={"payload": {"x": "telnet"}}).status_code == 200
    st = c.post("/api/gateway/ubus/status", json={"ip": "192.168.12.1"})
    assert st.status_code in (200, 402)
