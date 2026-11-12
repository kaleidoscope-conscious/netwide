"""Wave 5: metrics extensions, adaptive wiring helpers, digest."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from netwide.metrics import prometheus_text

def test_metrics_extensions():
    snap = {"meta": {"total_devices": 1, "online_devices": 1, "security_score": 90, "high_risk_devices": 0, "scan_count": 3},
            "devices": [{}], "threats": [], "hypotheses_top": [], "hypotheses_total": 0,
            "graph_nodes": 5, "graph_edges": 4, "quarantined_active": 1, "sinkhole_rules": 2, "passive_frames": 99}
    txt = prometheus_text(snap)
    assert "netwide_graph_nodes 5" in txt
    assert "netwide_quarantined_active 1" in txt
    assert "netwide_sinkhole_rules 2" in txt

def test_scan_strategy_persistence():
    from netwide.database import NetworkDatabase
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        path = tf.name
    try:
        db = NetworkDatabase(path)
        db.save_scan_strategy("home:test", {"arm": "iot_focus"}, {"iot_focus": {"count": 1.0, "mean_reward": 2.0}})
        row = db.get_scan_strategy("home:test")
        assert row is not None and row["params"]["arm"] == "iot_focus"
        assert db.add_sinkhole_rule("evil.example", "sinkhole") > 0
        assert len(db.list_sinkhole_rules()) >= 1
        assert db.delete_sinkhole_rule("evil.example") is True
        sid = db.save_posture_snapshot({"meta": {"security_score": 90}})
        assert sid > 0
        assert len(db.get_last_snapshots(2)) >= 1
    finally:
        os.unlink(path)

def test_wave5_api():
    from fastapi.testclient import TestClient
    from netwide.server import app
    c = TestClient(app)
    m = c.get("/api/metrics")
    assert m.status_code == 200 and "netwide_graph_nodes" in m.text
    assert c.get("/api/scan-strategy?env=home").status_code == 200
    assert c.get("/api/digest").status_code == 200
    assert c.get("/api/rules").status_code == 200
