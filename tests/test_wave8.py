"""Wave 8: passive census, CLI defaults, prune, demo."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

def test_passive_schedule_budget():
    from netpulse.passive_census import coverage_budget, dwell_schedule
    rows = dwell_schedule(10.0)
    assert coverage_budget(rows)["channels"] == len(rows)

def test_db_passive_helpers():
    from netpulse.database import NetworkDatabase
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
        path = tf.name
    try:
        db = NetworkDatabase(path)
        db.record_passive_frame(1.0, 2437, "BEACON", "AA:BB:CC:DD:EE:01", -70.0, 200)
        assert db.count_passive_frames() >= 1
        assert len(db.recent_passive_frames(5)) >= 1
    finally:
        os.unlink(path)

def test_health_and_verify_limit():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    assert c.get("/api/passive/census").status_code == 200
    assert c.get("/api/ledger/verify?limit=100").status_code == 200
    h = c.get("/api/health").json()
    assert "node_budget" in h

def test_demo_exists():
    assert open(str(pathlib.Path(__file__).resolve().parents[1] / "runbook/DEMO.md"), encoding="utf-8").read().__len__() > 200

def test_cli_serve_default_loopback():
    import pathlib
    txt = pathlib.Path(str(pathlib.Path(__file__).resolve().parents[1] / "cli.py")).read_text(encoding="utf-8")
    assert "127.0.0.1" in txt and "NETPULSE_HOST" in txt
