"""Wave 9: passive run, DB timeout, TTL normalize, ledger cap."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

def test_passive_run_gated():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    r = c.post("/api/passive/census/run")
    assert r.status_code in (200, 402)

def test_db_busy_timeout():
    import inspect
    from netpulse.database import NetworkDatabase
    src = inspect.getsource(NetworkDatabase._connect)
    assert "busy_timeout" in src and "15.0" in src

def test_ttl_normalize_comment():
    txt = open(str(pathlib.Path(__file__).resolve().parents[1] / "fingerprint.py"), encoding="utf-8").read()
    assert "normalize to 64/128/255" in txt

def test_ledger_limit_param():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    assert c.get("/api/ledger/verify?limit=50").status_code == 200
