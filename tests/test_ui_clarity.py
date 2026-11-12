"""UI clarity: plain-English labels, attention card, Why/Evidence wiring."""
import pathlib

def _html(name: str) -> str:
    return (pathlib.Path(__file__).resolve().parents[1] / "static" / name).read_text(encoding="utf-8")

def test_desktop_plain_tabs():
    html = _html("index.html")
    assert 'data-tab="inventory"' in html
    # Plain labels present, jargon labels gone as primary text
    assert "Devices" in html and "Wi-Fi Finder" in html and "Map" in html
    assert "LAN Inventory &amp; Control" not in html.split('class="nav-tabs"')[1][:2000]
    assert "Start here:" in html
    assert "What needs attention?" in html
    assert "refreshAttention" in html
    assert "explainDevice" in html and "showEvidence" in html
    # Header grouped under More (details keeps buttons searchable)
    assert "<details>" in html and "More ▾" in html

def test_mobile_plain_nav():
    html = _html("mobile.html")
    assert "Hidden Wi-Fi" in html and "Find signal" in html and "Devices" in html
    assert "Tap <strong>Scan</strong>" in html

def test_attention_uses_new_apis():
    html = _html("index.html")
    for p in ["/api/digest", "/api/hypotheses", "/api/explain", "/api/device/"]:
        assert p in html, p

def test_verdict_and_simple_mode():
    html = _html("index.html")
    assert "verdictBar" in html and "verdictScore" in html
    assert "toggleSimpleMode" in html and "Simple view" in html
    assert "Status" in html and "Fix now" in html and "Check" in html
    # Inspector accordions (details) instead of wall of panels
    assert "<details" in html and "Activity &amp; traffic" in html
    assert "Why this verdict?" in html
