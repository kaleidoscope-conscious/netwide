"""Wave 3: adaptive strategy, copilot, metrics, threat-field, sinkhole, posture diff."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from netwide.scan_strategy import UCB1Bandit, dwell_for_arm, reward_for_scan
from netwide.explain import explain_device
from netwide.metrics import posture_diff, prometheus_text
from netwide.intel_hypotheses import compute_threat_field

def test_ucb1_explores_then_exploits():
    b = UCB1Bandit(arms=["a", "b"])
    assert b.select_arm() == "a"
    b.update("a", 1.0)
    assert b.select_arm() == "b"  # unexplored first
    b.update("b", 0.0)
    assert b.total == 2
    assert b.stats()["a"]["count"] == 1

def test_dwell_and_reward():
    assert dwell_for_arm("mesh_sweep") == 150
    assert reward_for_scan(10, 2.0, 0) == 5.0
    assert reward_for_scan(0, 0, 0) == 0.0

def test_explain_device():
    dev = {
        "device_key": "K1", "ip": "192.168.12.5",
        "security_findings": [{"title": "Cleartext Telnet Service Exposed (TCP 23)", "description": "d", "remediation": "r"}],
    }
    out = explain_device(dev, "why?")
    assert out["ok"] is True
    assert out["confirm_required"] is True
    assert out["auto_executed"] is False
    assert len(out["suggested_commands"]) >= 1

def test_prometheus_text():
    snap = {"meta": {"total_devices": 3, "online_devices": 2, "security_score": 90, "high_risk_devices": 1, "scan_count": 7},
            "devices": [{}, {}, {}], "threats": [{"severity": "HIGH"}], "hypotheses_top": [], "hypotheses_total": 4}
    txt = prometheus_text(snap)
    assert "netwide_devices_total 3" in txt
    assert "netwide_scan_total 7" in txt

def test_posture_diff():
    before = {"devices": [{"device_key": "A"}], "threats": [{"category": "X", "title": "t1"}], "meta": {"security_score": 80, "scan_count": 1}}
    after = {"devices": [{"device_key": "A"}, {"device_key": "B"}], "threats": [], "meta": {"security_score": 85, "scan_count": 2}}
    d = posture_diff(before, after)
    assert d["changed_devices_new"] == ["B"]
    assert d["posture_delta"] == 5

def test_threat_field():
    hyps = [
        {"device_key": "K1", "severity": "CRITICAL", "expected_value": 0.9},
        {"device_key": "K1", "severity": "HIGH", "expected_value": 0.5},
        {"device_key": "K2", "severity": "LOW", "expected_value": 0.1},
    ]
    f = compute_threat_field(hyps)
    assert f["coherence"] > 0
    assert f["devices_in_field"] == 2
    assert f["field"][0]["device_key"] == "K1"

def test_wave3_api():
    from fastapi.testclient import TestClient
    from netwide.server import app
    c = TestClient(app)
    assert c.get("/api/metrics").status_code == 200
    assert c.get("/api/threat-field").status_code == 200
    assert c.get("/api/threat-field").json()["ok"] is True
    assert c.get("/api/scan-strategy").status_code == 200
    assert c.get("/api/posture/diff").status_code == 200
    assert c.get("/api/net/dns/sinkhole").status_code == 200
    ex = c.post("/api/explain", json={"device_key": "x", "question": "hi"})
    assert ex.status_code in (200, 402, 404)
    sh = c.post("/api/net/dns/sinkhole", json={"domain": "bad.example", "action": "sinkhole"})
    assert sh.status_code in (200, 402)
