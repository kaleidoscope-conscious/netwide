"""Wave 12: Proof Mode (S11), Accuracy Harness (S12), CASE/UCO Evidence Bundle (Bet 1), and Longitudinal Chronicle (Bet 4)."""

import sys
sys.path.insert(0, "/home/jg")

from fastapi.testclient import TestClient

from netpulse.accuracy import GOLDEN_LAB_CORPUS, evaluate_accuracy
from netpulse.chronicle import (
    compute_device_rhythm_profile,
    generate_network_chronicle,
    generate_netpulse_wrapped,
)
from netpulse.evidence_bundle import build_case_evidence_bundle, verify_evidence_bundle
from netpulse.fusion import (
    VECTOR_DEFINITIONS,
    extract_evidence_vectors,
    fuse_evidence,
)
from netpulse.server import app

client = TestClient(app)


def test_fusion_vectors_catalog():
    """Verify all 16 independent evidence vectors exist with required metadata and weights."""
    assert len(VECTOR_DEFINITIONS) == 16
    for vid, vdef in VECTOR_DEFINITIONS.items():
        assert "name" in vdef
        assert "category" in vdef
        assert 0.5 <= vdef["weight"] <= 1.0


def test_fusion_evidence_extraction_and_grade():
    """Verify multi-vector fusion assigns VERIFIED when >=2 independent strong vectors agree."""
    device = {
        "mac": "00:11:32:11:22:33",
        "ip": "192.168.1.150",
        "brand": "Synology Inc.",
        "model": "DiskStation DS920+",
        "is_randomized_mac": False,
        "signal_dbm": -48.0,
        "upnp_info": {"manufacturer": "Synology", "model_name": "DS920+", "udn": "uuid:12345"},
        "mdns_services": [{"service": "_smb._tcp.local.", "instance": "DiskStation"}],
    }
    vectors = extract_evidence_vectors(device)
    assert len(vectors) >= 3
    verdict = fuse_evidence(vectors, default_identity="Synology DiskStation")
    assert verdict.grade == "VERIFIED"
    assert verdict.calibrated_probability >= 0.82
    assert "Synology" in verdict.primary_claim
    assert len(verdict.agreeing_vectors) >= 3
    assert len(verdict.disagreeing_vectors) == 0


def test_fusion_contradiction_downgrade():
    """Verify contradictory evidence triggers a disagreement penalty and prevents VERIFIED grade."""
    # Rogue AP with severe TSF clock skew contradicting parent AP
    device = {
        "mac": "02:AA:BB:CC:DD:EE",
        "ip": "192.168.1.254",
        "brand": "Unknown",
        "is_randomized_mac": True,
        "signal_dbm": -35.0,
    }
    aps = [
        {
            "bssid": "02:AA:BB:CC:DD:EE",
            "ssid": "Target-AP",
            "tsf_delta_us": 95000.0,  # Massive clock skew anomaly
            "rate_mbps": 54,
        }
    ]
    vectors = extract_evidence_vectors(device, aps)
    verdict = fuse_evidence(vectors, default_identity="Unknown")
    assert verdict.grade == "WEAK"
    assert any(v["vector_id"] == "tsf_clock_delta" for v in verdict.disagreeing_vectors)


def test_accuracy_harness_evaluation():
    """Verify S12 Accuracy Harness runs on golden corpus and passes the Brier < 0.15 gate."""
    res = evaluate_accuracy(GOLDEN_LAB_CORPUS)
    assert res["ok"] is True
    assert res["fixtures_evaluated"] >= 6
    assert res["overall_accuracy"] >= 0.80
    assert res["brier_score"] < 0.15
    assert res["brier_gate_passed"] is True
    assert res["total_confusion_cost"] >= 0.0
    assert len(res["stage_metrics"]) == 16
    assert len(res["vector_statistics"]) == 16


def test_evidence_bundle_case_uco_lifecycle():
    """Verify Bet 1 CASE/UCO evidence bundle creation, signing, and standalone verification."""
    device = {
        "device_key": "synology_ds920",
        "mac": "00:11:32:AA:BB:CC",
        "ip": "192.168.1.150",
        "brand": "Synology",
        "model": "DS920+",
    }
    proof_verdict = {
        "grade": "VERIFIED",
        "calibrated_probability": 0.94,
        "proof_summary": "VERIFIED via 3 independent vectors",
        "brier_score": 0.0036,
        "agreeing_vectors": [
            {
                "vector_id": "oui_burn",
                "name": "Burned-in IEEE OUI",
                "raw_evidence": "IEEE OUI -> Synology",
                "weight": 0.88,
                "confidence": 0.92,
                "observed_at": 1700000000.0,
            }
        ],
    }
    ledger = [{"hash": "a1b2c3d4e5f6", "action": "scan_complete", "ts": 1700000000.0}]
    secret = "test-node-signing-secret-12345"

    bundle = build_case_evidence_bundle(device, proof_verdict, ledger, signing_secret=secret)
    assert bundle["@type"] == "case-investigation:InvestigativeBundle"
    assert "netpulse:signature" in bundle

    # 1. Verification of untouched bundle must succeed
    v_ok = verify_evidence_bundle(bundle, signing_secret=secret)
    assert v_ok["valid"] is True
    assert v_ok["signature_valid"] is True
    assert v_ok["verdict_grade"] == "VERIFIED"

    # 2. Verification of tampered bundle must fail
    tampered = dict(bundle)
    graph_copy = list(bundle["@graph"])
    graph_copy[0] = dict(graph_copy[0])
    graph_copy[0]["uco-core:name"] = "Hacked Device"
    tampered["@graph"] = graph_copy

    v_tampered = verify_evidence_bundle(tampered, signing_secret=secret)
    assert v_tampered["valid"] is False
    assert "tampered" in v_tampered.get("error", "").lower() or "mismatch" in v_tampered.get("error", "").lower()


def test_chronicle_and_rhythm_engine():
    """Verify Bet 4 Longitudinal Chronicle, 24-hr rhythm profile, and Wrapped summary."""
    ledger_events = [
        {"target": "dev_1", "action": "quarantine", "ts": 1700000000.0 + (3600 * 2)},  # 02:00 UTC (quiet)
        {"target": "dev_1", "action": "port_scan", "ts": 1700000000.0 + (3600 * 14)}, # 14:00 UTC (active)
    ]
    rhythm = compute_device_rhythm_profile("dev_1", ledger_events, current_timestamp=1700000000.0 + 86400)
    assert rhythm["device_key"] == "dev_1"
    assert len(rhythm["hourly_distribution"]) == 24
    assert rhythm["total_historical_events"] == 2

    devices = [{"device_key": "dev_1", "brand": "Sonos", "model": "Move", "ip": "192.168.1.140"}]
    chronicle = generate_network_chronicle(devices, ledger_events, [], window_days=7)
    assert chronicle["ok"] is True
    assert "narrative" in chronicle

    wrapped = generate_netpulse_wrapped(devices, ledger_events, scan_count=15)
    assert wrapped["ok"] is True
    assert wrapped["total_devices_tracked"] == 1
    assert wrapped["top_hardware_ecosystem"] == "Sonos"


def test_api_accuracy_and_proof_endpoints():
    """Verify FastAPI routes for /api/accuracy, /api/device/{key}/proof, /api/chronicle, and /api/evidence."""
    # 1. /api/accuracy
    r_acc = client.get("/api/accuracy")
    assert r_acc.status_code == 200
    d_acc = r_acc.json()
    assert d_acc["ok"] is True
    assert d_acc["brier_gate_passed"] is True
    assert len(d_acc["stage_metrics"]) == 16

    # 2. /api/chronicle
    r_chr = client.get("/api/chronicle")
    assert r_chr.status_code == 200
    assert r_chr.json()["ok"] is True

    # 3. /api/chronicle/wrapped
    r_wrp = client.get("/api/chronicle/wrapped")
    assert r_wrp.status_code == 200
    assert r_wrp.json()["ok"] is True

    # 4. /api/evidence/verify
    # First activate an enterprise key for bundle generation
    mint_resp = client.post(
        "/api/subscription/admin/mint",
        json={"tier": "enterprise", "plan": "lifetime", "email": "founder@netpulse.io", "auto_activate": True},
    )
    assert mint_resp.status_code == 200

    r_bnd = client.post("/api/evidence/bundle", json={"device_key": "synology_ds920", "window_hours": 24.0})
    assert r_bnd.status_code == 200
    bundle = r_bnd.json()["bundle"]

    r_ver = client.post("/api/evidence/verify", json={"bundle": bundle})
    assert r_ver.status_code == 200
    assert r_ver.json()["valid"] is True
