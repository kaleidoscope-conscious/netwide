"""Wave 10: raft election, ARP policy, offloaded snapshot."""
import sys
sys.path.insert(0, "/home/jg")

from netpulse.raft import MeshNode, partition_key

def test_raft_majority():
    m = MeshNode("n1")
    m.start_election(["n1", "n2", "n3"])
    r = m.tally({"n1": "n1", "n2": "n1", "n3": "n2"}, ["n1", "n2", "n3"])
    assert r["leader"] == "n1" and r["majority"] == 2
    assert m.state == "leader"

def test_partition_deterministic():
    assert partition_key("AA:BB:CC:DD:EE:FF", 3) == partition_key("AA:BB:CC:DD:EE:FF", 3)

def test_mesh_policy_api():
    from fastapi.testclient import TestClient
    from netpulse.server import app
    c = TestClient(app)
    assert c.get("/api/mesh/status").status_code == 200
    assert c.post("/api/mesh/heartbeat", json={"from": "n2"}).status_code == 200
    assert c.get("/api/policy/arp").status_code == 200
    # POST as testclient (loopback bypass) should work
    assert c.post("/api/policy/arp", json={"enabled": False}).status_code == 200
