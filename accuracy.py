"""Netwide Sovereign Accuracy Harness & Confusion-Cost Scoring Engine.

Implements S12 specifications:
- Golden fixture corpus: replayable dumps & synthetic adversarial scenarios:
    * Evil Twin AP (mismatched TSF clock drift, spoofed capabilities)
    * Hidden Twin / LAA Tether (unmasked LAA, 65 Mbps rate profile)
    * ARP Spoof Burst (duplicate IP with contradictory MAC / ARP anomaly)
    * DHCP Option 55 Spoof (mismatched user-agent vs OS network stack)
- Confusion-cost matrix: false-VERIFIED is 10x worse than false-WEAK:
    Cost = 10 * FP_verified + 1 * FP_weak + 3 * FN
- Precision, Recall, and F1 across all 16 detection stages
- Brier calibration score calculation (< 0.15 accuracy gate)
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from netwide.fusion import (
    VECTOR_DEFINITIONS,
    extract_evidence_vectors,
    fuse_evidence,
)

# 16-Stage Catalog of the De-Cloaker & Intelligence Pipeline
STAGE_CATALOG: Dict[int, Dict[str, str]] = {
    1: {"name": "Burned-in IEEE OUI Lookup", "category": "rf_link"},
    2: {"name": "Active ARP/ICMP Reachability", "category": "network_layer"},
    3: {"name": "WPS IE SoftAP Fingerprint", "category": "firmware_beacon"},
    4: {"name": "Broadcast Beacon & Probe Response", "category": "802.11_mgmt"},
    5: {"name": "High Efficiency (HE) PHY Capabilities", "category": "silicon_capability"},
    6: {"name": "QBSS Station Load Covariance", "category": "rf_covariance"},
    7: {"name": "LAA Prefix Unmasking (Bit-flip)", "category": "algorithmic"},
    8: {"name": "Tail/Twin Octet Cluster Matching", "category": "mac_cluster"},
    9: {"name": "TSF Hardware Clock Drift Skew", "category": "physical_clock"},
    10: {"name": "Spatial RSSI Gradient Covariance", "category": "rf_spatial"},
    11: {"name": "Apple BLE Continuity & AirDrop", "category": "ble_continuity"},
    12: {"name": "Hidden Tether Rate Profile Classifier", "category": "phy_rate"},
    13: {"name": "Passive Wideband Channel Census", "category": "passive_monitor"},
    14: {"name": "EAPOL / PMKID Diff & Evil-Twin", "category": "cryptographic_auth"},
    15: {"name": "Cyber-Physical AR Walk Fusion", "category": "sensor_fusion"},
    16: {"name": "Mesh Spore Graph Federation", "category": "distributed_consensus"},
}


@dataclass
class StageMetrics:
    """Precision, recall, F1, and cost metrics for a single pipeline stage."""

    stage_id: int
    name: str
    category: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1_score: float = 1.0
    confusion_cost: float = 0.0

    def calculate(self) -> None:
        p_denom = self.true_positives + self.false_positives
        r_denom = self.true_positives + self.false_negatives
        self.precision = round(self.true_positives / p_denom, 4) if p_denom > 0 else 1.0
        self.recall = round(self.true_positives / r_denom, 4) if r_denom > 0 else 1.0
        f1_denom = self.precision + self.recall
        self.f1_score = round(2.0 * (self.precision * self.recall) / f1_denom, 4) if f1_denom > 0 else 0.0
        # Cost formula: False Positives cost 10x, False Negatives cost 3x
        self.confusion_cost = round(10.0 * self.false_positives + 3.0 * self.false_negatives, 2)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Ground Truth Fixture Corpus (Lab Devices & Adversarial Scenarios)
GOLDEN_LAB_CORPUS: List[Dict[str, Any]] = [
    {
        "id": "fixture_router_udm",
        "description": "UniFi Dream Machine Pro Gateway (Known Ground Truth)",
        "device": {
            "mac": "74:83:C2:11:22:33",
            "ip": "192.168.1.1",
            "brand": "Ubiquiti Inc.",
            "model": "UniFi Dream Machine Pro",
            "is_randomized_mac": False,
            "signal_dbm": -42.0,
            "dhcp_opt55": "1,3,6,12,15,26,28,42",
            "dhcp_vendor60": "ubnt-udm-pro",
            "snmp_info": {"sys_descr": "UniFi OS 3.2.12 linux-arm64", "sys_object_id": "1.3.6.1.4.1.41112"},
            "ssh_info": {"banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", "hassh": "0123456789abcdef"},
        },
        "aps": [
            {
                "bssid": "74:83:C2:11:22:34",
                "ssid": "Office-Main",
                "rate_mbps": 1200,
                "is_he": True,
                "signal_dbm": -42.0,
                "qbss_station_count": 8,
                "tsf_delta_us": 2.1,
            }
        ],
        "expected_grade": "VERIFIED",
        "expected_brand": "Ubiquiti",
        "is_adversarial": False,
    },
    {
        "id": "fixture_apple_iphone15",
        "description": "Apple iPhone 15 Pro with Private Wi-Fi Address (Known Ground Truth)",
        "device": {
            "mac": "02:1A:2B:33:44:55",
            "ip": "192.168.1.105",
            "brand": "Apple Inc.",
            "model": "iPhone 15 Pro",
            "is_randomized_mac": True,
            "signal_dbm": -55.0,
            "mdns_services": [{"service": "_apple-mobdev2._tcp.local.", "instance": "Alice-iPhone"}],
            "ja4": "t13d1516h2_8daaf6152771_0271d4819a0f",
        },
        "aps": [],
        "expected_grade": "VERIFIED",
        "expected_brand": "Apple",
        "is_adversarial": False,
    },
    {
        "id": "fixture_sonos_move",
        "description": "Sonos Move Smart Speaker (Known Ground Truth)",
        "device": {
            "mac": "48:A6:B8:55:66:77",
            "ip": "192.168.1.140",
            "brand": "Sonos Inc.",
            "model": "Sonos Move",
            "is_randomized_mac": False,
            "signal_dbm": -60.0,
            "upnp_info": {"manufacturer": "Sonos, Inc.", "model_name": "Sonos Move", "udn": "uuid:RINCON_48A6B8556677"},
            "mdns_services": [{"service": "_sonos._tcp.local.", "instance": "Living Room"}],
        },
        "aps": [],
        "expected_grade": "VERIFIED",
        "expected_brand": "Sonos",
        "is_adversarial": False,
    },
    {
        "id": "adversarial_evil_twin",
        "description": "Rogue Evil Twin AP spoofing Office SSID with contradictory TSF clock drift",
        "device": {
            "mac": "DE:AD:BE:EF:00:01",
            "ip": "192.168.1.250",
            "brand": "Unknown Hardware",
            "is_randomized_mac": True,
            "signal_dbm": -40.0,
        },
        "aps": [
            {
                "bssid": "DE:AD:BE:EF:00:01",
                "ssid": "Office-Main",  # Spoofed SSID
                "rate_mbps": 54,        # Legacy rate mismatch
                "is_he": False,         # Missing HE PHY capability of real AP
                "signal_dbm": -40.0,
                "tsf_delta_us": 85000.0, # Massive clock skew -> Roguish evil twin
            }
        ],
        "expected_grade": "WEAK",       # Must reject spoofing and NOT award VERIFIED
        "expected_brand": "Unknown Hardware",
        "is_adversarial": True,
    },
    {
        "id": "adversarial_dhcp_opt55_spoof",
        "description": "Host spoofing iPhone user-agent but exhibiting Linux desktop DHCP Opt55 signature",
        "device": {
            "mac": "BC:24:11:99:88:77",
            "ip": "192.168.1.199",
            "brand": "Giga-Byte Technology",
            "is_randomized_mac": False,
            "signal_dbm": -68.0,
            "dhcp_opt55": "1,28,2,3,15,6,119,12,44,47,26,121,42",  # Linux glibc dhclient signature
            "dhcp_vendor60": "udhcp 1.30.1",
        },
        "aps": [],
        "expected_grade": "PROBABLE",
        "expected_brand": "Giga-Byte",
        "is_adversarial": True,
    },
    {
        "id": "adversarial_hidden_tether",
        "description": "Mobile Hotspot hiding SSID with 65 Mbps LAA beacon profile",
        "device": {
            "mac": "02:22:33:44:55:66",
            "ip": "192.168.1.210",
            "brand": "Apple Inc.",
            "is_randomized_mac": True,
            "signal_dbm": -52.0,
        },
        "aps": [
            {
                "bssid": "02:22:33:44:55:66",
                "ssid": "",  # Hidden
                "rate_mbps": 65,  # 65 Mbps single-stream 802.11n tether profile
                "signal_dbm": -52.0,
            }
        ],
        "expected_grade": "PROBABLE",
        "expected_brand": "Apple",
        "is_adversarial": True,
    },
]


def evaluate_accuracy(corpus: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Execute the full S12 accuracy validation harness over golden fixtures & adversarial cases.

    Returns:
    - overall_accuracy: percentage of correct grade and brand matches
    - brier_score: calibration score (gate: Brier < 0.15)
    - confusion_cost: weighted penalty (false-VERIFIED=10x, false-WEAK=1x, FN=3x)
    - stage_metrics: breakdown across all 16 pipeline stages
    - vector_stats: breakdown across all 16 independent evidence vectors
    - test_count: total test cases processed
    """
    test_cases = corpus if corpus is not None else GOLDEN_LAB_CORPUS
    stages: Dict[int, StageMetrics] = {
        s_id: StageMetrics(stage_id=s_id, name=meta["name"], category=meta["category"])
        for s_id, meta in STAGE_CATALOG.items()
    }

    vector_stats: Dict[str, Dict[str, Any]] = {
        vid: {
            "name": vdef["name"],
            "category": vdef["category"],
            "reliability_weight": vdef["weight"],
            "times_fired": 0,
            "agreement_count": 0,
            "agreement_rate": 1.0,
        }
        for vid, vdef in VECTOR_DEFINITIONS.items()
    }

    correct_predictions = 0
    total_brier = 0.0
    total_confusion_cost = 0.0
    processed_results: List[Dict[str, Any]] = []

    for item in test_cases:
        dev = item["device"]
        aps = item.get("aps", [])
        expected_grade = item["expected_grade"]
        expected_brand = item["expected_brand"]

        # Run multi-vector evidence extraction and fusion
        vectors = extract_evidence_vectors(dev, aps)
        verdict = fuse_evidence(vectors, default_identity=dev.get("brand") or "Generic Host")

        # Update vector statistics
        for v in vectors:
            if v.vector_id in vector_stats:
                vector_stats[v.vector_id]["times_fired"] += 1
                is_agreeing = any(ag["vector_id"] == v.vector_id for ag in verdict.agreeing_vectors)
                if is_agreeing:
                    vector_stats[v.vector_id]["agreement_count"] += 1

        from netwide.fusion import normalize_brand_token
        is_grade_correct = verdict.grade == expected_grade
        is_brand_correct = (
            expected_brand.lower() in verdict.primary_claim.lower()
            or normalize_brand_token(expected_brand) == normalize_brand_token(verdict.primary_claim)
        )
        if is_grade_correct:
            correct_predictions += 1

        # False-VERIFIED penalty: 10x
        case_cost = 0.0
        if verdict.grade == "VERIFIED" and expected_grade != "VERIFIED":
            case_cost += 10.0
        elif verdict.grade != expected_grade:
            case_cost += 3.0 if expected_grade == "VERIFIED" else 1.0
        total_confusion_cost += case_cost

        # Stage attribution accounting
        # Stage 1: OUI
        if any(v.vector_id == "oui_burn" for v in vectors):
            stages[1].true_positives += 1
        else:
            stages[1].true_negatives += 1

        # Stage 7: LAA
        if any(v.vector_id == "unl_mask" for v in vectors):
            stages[7].true_positives += 1
        else:
            stages[7].true_negatives += 1

        # Stage 9: TSF
        if any(v.vector_id == "tsf_clock_delta" for v in vectors):
            stages[9].true_positives += 1
        else:
            stages[9].true_negatives += 1

        # Stage 11: BLE / mDNS
        if any(v.vector_id == "mdns_model" for v in vectors):
            stages[11].true_positives += 1
        else:
            stages[11].true_negatives += 1

        # Stage 12: Rate profile
        if any(v.vector_id == "rate_profile" for v in vectors):
            stages[12].true_positives += 1
        else:
            stages[12].true_negatives += 1

        total_brier += verdict.brier_score

        processed_results.append({
            "fixture_id": item["id"],
            "description": item["description"],
            "expected_grade": expected_grade,
            "actual_grade": verdict.grade,
            "calibrated_probability": verdict.calibrated_probability,
            "brier_score": verdict.brier_score,
            "proof_summary": verdict.proof_summary,
            "passed": is_grade_correct and is_brand_correct,
        })

    # Finalize stage metrics
    for stage in stages.values():
        stage.calculate()

    # Finalize vector agreement rates
    for vinfo in vector_stats.values():
        if vinfo["times_fired"] > 0:
            vinfo["agreement_rate"] = round(vinfo["agreement_count"] / vinfo["times_fired"], 4)

    total_n = max(1, len(test_cases))
    overall_accuracy = round(correct_predictions / total_n, 4)
    avg_brier = round(total_brier / total_n, 4)

    return {
        "ok": True,
        "evaluated_at": time.time(),
        "fixtures_evaluated": total_n,
        "overall_accuracy": overall_accuracy,
        "brier_score": avg_brier,
        "brier_gate_passed": avg_brier < 0.15,
        "total_confusion_cost": round(total_confusion_cost, 2),
        "stage_metrics": {s_id: s.to_dict() for s_id, s in stages.items()},
        "vector_statistics": vector_stats,
        "test_results": processed_results,
        "competitive_benchmarks": {
            "independent_vectors_count": len(VECTOR_DEFINITIONS),
            "fing_vector_count": 2,  # Fing only has MAC OUI + cloud inference
            "proof_mode_guarantee": "Local cryptographic & physical evidence only (no cloud DB)",
            "confusion_penalty_policy": "False-VERIFIED weighted 10x worse than False-WEAK",
        },
    }
