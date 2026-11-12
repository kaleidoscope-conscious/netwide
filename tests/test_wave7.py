"""Wave 7: passive census, CLI hardening, README."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from netwide.passive_census import coverage_budget, dwell_schedule

def test_dwell_schedule():
    rows = dwell_schedule(10.0)
    assert len(rows) >= 7  # 3 + 4 + 2
    assert all(r["dwell_ms"] > 0 for r in rows)
    b = coverage_budget(rows)
    assert b["total_dwell_s"] > 0

def test_passive_api_and_cli():
    from fastapi.testclient import TestClient
    from netwide.server import app
    c = TestClient(app)
    r = c.get("/api/passive/census")
    assert r.status_code == 200
    d = r.json()
    assert d["stage"] == 13 and "schedule" in d

def test_cli_no_args_exit2():
    from netwide.cli import main
    import pytest
    with pytest.raises(SystemExit) as e:
        main([])
    assert e.value.code == 2

def test_readme_new_sections():
    txt = open(str(pathlib.Path(__file__).resolve().parents[1] / "README.md"), encoding="utf-8").read()
    for needle in ["/api/graph", "/api/ble/scan", "/api/control", "/api/metrics", "/api/explain", "Threat Field", "Simple"]:
        assert needle in txt
