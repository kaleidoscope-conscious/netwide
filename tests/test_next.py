"""Next tenfold: persistence, undo, firmware, spore, quarantine firewall stub."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from netpulse.firmware import analyze_firmware, is_rfc1918_target, shannon_entropy

def test_firmware_analyze_elf():
    blob = b"\x7fELF" + b"A" * 200 + b"Linux version 5.10.0" + b"v1.2.3" + b"B" * 100
    out = analyze_firmware(blob)
    assert out["ok"] is True
    assert "ELF" in out["signatures"]
    assert "Linux kernel" in out["signatures"]
    assert out["sha256"]
    assert out["bytes"] == len(blob)

def test_firmware_entropy():
    assert shannon_entropy(b"A" * 10000) == 0.0
    import os
    assert shannon_entropy(os.urandom(8192)) > 7.0

def test_firmware_ssrf_guard():
    assert is_rfc1918_target("http://192.168.1.1/fw.bin") is True
    assert is_rfc1918_target("http://8.8.8.8/fw.bin") is False
    assert is_rfc1918_target("https://example.com/fw.bin") is False

def test_db_graph_and_evidence():
    from netpulse.database import NetworkDatabase
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        path = tf.name
    try:
        db = NetworkDatabase(path)
        db.sync_graph_from_state(
            [{"device_key": "K1", "mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.12.5", "is_gateway": True, "brand": "Test"}],
            [{"bssid": "AA:BB:CC:DD:EE:02", "ssid": "Net", "channel": 6}],
        )
        g = db.get_graph()
        assert g["count_nodes"] >= 2
        eid = db.add_evidence("claim:1", "K1", "device_finding", {"title": "Telnet"}, 0.9)
        assert eid > 0
        assert len(db.get_evidence("K1")) >= 1
        aid = db.record_action("power:on", {"device_key": "K1"}, {"action": "off"}, "operator", "ok")
        assert aid > 0
        assert db.get_action(aid) is not None
        assert db.mark_action_undone(aid) is True
        db.record_passive_frame(123456.0, 2437, "BEACON", "AA:BB:CC:DD:EE:02", -70.0, 200)
    finally:
        os.unlink(path)

def test_quarantine_firewall_graceful():
    from netpulse.probers import quarantine_engine
    fw = quarantine_engine._set_firewall_drop("192.168.99.99", True)
    assert "backend" in fw
    assert "actions" in fw
    # release on non-quarantined must not raise
    assert quarantine_engine.release("192.168.99.99") in (True, False)

def test_new_endpoints_next():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    assert c.get("/api/actions").status_code == 200
    assert c.get("/api/actions").json()["ok"] is True
    assert c.post("/api/graph/spore", json={"nodes": [], "edges": []}).status_code in (200, 402)
    fw = c.post("/api/action/firmware-audit", json={"target": "http://8.8.8.8/fw.bin"})
    assert fw.status_code in (200, 402)
    if fw.status_code == 200:
        assert fw.json()["ok"] is False  # SSRF guard, not crash
    assert c.post("/api/actions/999999/undo").status_code == 404
