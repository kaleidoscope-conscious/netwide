"""Wave 11: scrub, onboarding, mobile verdict."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

def test_scrub_tool_output():
    from netpulse.server import _scrub_tool_output
    assert "/usr/bin/nmap" not in _scrub_tool_output("/usr/bin/nmap -sV 1.2.3.4")
    assert "[redacted]" in _scrub_tool_output("/home/jg/secret")

def test_onboarding_and_mobile():
    html = open(str(pathlib.Path(__file__).resolve().parents[1] / "static/index.html"), encoding="utf-8").read()
    assert "Press Scan to begin" in html and "verdictBar" in html
    m = open(str(pathlib.Path(__file__).resolve().parents[1] / "static/mobile.html"), encoding="utf-8").read()
    assert "mobileVerdictScore" in m

def test_passive_and_mesh_still():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    assert c.get("/api/passive/census").status_code == 200
    assert c.get("/api/mesh/status").status_code == 200
