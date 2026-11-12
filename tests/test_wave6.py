"""Wave 6: security hardening (device gates, trial RLock, max_nodes, webhook prune)."""
import sys
sys.path.insert(0, "/home/jg")

def test_device_mutation_loopback_ok():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    # TestClient host is testclient (loopback bypass) -> admin gate passes, device not found => 404 not 403
    r = c.post("/api/device/nope/customize", json={"custom_name": "x"})
    assert r.status_code in (200, 404)
    assert r.status_code != 403
    d = c.delete("/api/device/nope")
    assert d.status_code in (200, 404)
    assert d.status_code != 403

def test_max_nodes_helpers():
    from netpulse.billing import subscription_engine
    b = subscription_engine.check_node_budget(0)
    assert "limit" in b and "used" in b
    assert subscription_engine.get_max_nodes() >= 1

def test_health_has_budget():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    h = c.get("/api/health")
    assert h.status_code == 200
    assert "node_budget" in h.json()

def test_prune_safe():
    from netpulse.billing import subscription_engine
    n = subscription_engine.prune_webhook_idempotency(90)
    assert isinstance(n, int) and n >= 0

def test_benchmark_importable():
    import pathlib
    p = pathlib.Path("/home/jg/netpulse/scripts/benchmark_vs_fing.py")
    assert p.exists()
