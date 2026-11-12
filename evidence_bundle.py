"""NetPulse Sovereign Admissible Evidence — CASE / UCO Forensic Bundle Engine.

Implements Bet 1 specifications:
- Cyber-investigation Analysis Standard Expression (CASE / UCO 1.3 - caseontology.org)
- Expresses LAN devices as UCO ObservableObjects with MACAddressFacet and IPAddressFacet
- Expresses scans and network audits as InvestigativeActions
- Expresses Proof Mode verdicts and hypotheses as CASE Inferences bound to supporting evidence vectors
- Anchored to tamper-evident events_ledger SHA-256 head hash and cryptographically signed
- Includes offline standalone validator (no external API or cloud dependencies)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

CASE_CONTEXT = [
    "https://ontology.caseontology.org/case/1.3.0/context.jsonld",
    {
        "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
        "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
        "uco-action": "https://ontology.unifiedcyberontology.org/uco/action/",
        "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
        "case-investigation": "https://ontology.caseontology.org/case/investigation/",
        "netpulse": "https://netpulse.io/schema/proof/v1#",
    },
]


def build_case_evidence_bundle(
    device: Dict[str, Any],
    proof_verdict: Dict[str, Any],
    ledger_entries: List[Dict[str, Any]],
    signing_secret: str,
    investigator_id: str = "NetPulse Sovereign Investigator",
    window_hours: float = 24.0,
) -> Dict[str, Any]:
    """Generate an internationally standard CASE/UCO JSON-LD evidence bundle."""
    now_ts = time.time()
    created_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))
    device_key = str(device.get("device_key") or device.get("mac") or device.get("ip") or "unknown")
    mac = str(device.get("mac") or "").upper()
    ip = str(device.get("ip") or "")
    brand = str(device.get("brand") or "Generic Host")
    model = str(device.get("model") or device.get("display_name") or "")

    bundle_id = f"netpulse:bundle:{hashlib.sha256(f'{device_key}:{now_ts}'.encode()).hexdigest()[:16]}"
    investigation_id = f"netpulse:investigation:{device_key}"
    device_obj_id = f"netpulse:observable:device:{device_key}"

    # 1. Build UCO Observable Device Object with Facets
    facets: List[Dict[str, Any]] = []
    if mac:
        facets.append({
            "@type": "uco-observable:MACAddressFacet",
            "uco-observable:macAddress": mac,
            "uco-observable:isRandomized": bool(device.get("is_randomized_mac")),
        })
    if ip:
        facets.append({
            "@type": "uco-observable:IPAddressFacet",
            "uco-observable:ipAddress": ip,
            "uco-observable:ipAddressType": "IPv4" if ":" not in ip else "IPv6",
        })
    if brand or model:
        facets.append({
            "@type": "uco-observable:DeviceFacet",
            "uco-observable:manufacturer": brand,
            "uco-observable:model": model,
            "uco-observable:serialNumber": str(device.get("serial_number") or ""),
        })

    uco_device_object = {
        "@id": device_obj_id,
        "@type": "uco-observable:ObservableObject",
        "uco-core:name": f"{brand} {model}".strip() or "Network Device",
        "uco-core:hasFacet": facets,
    }

    # 2. Build Supporting Evidence Vectors as CASE Evidence Objects
    evidence_items: List[Dict[str, Any]] = []
    agreeing = proof_verdict.get("agreeing_vectors") or []
    for idx, vec in enumerate(agreeing):
        vec_id = f"netpulse:evidence:{device_key}:{vec.get('vector_id')}:{idx}"
        evidence_items.append({
            "@id": vec_id,
            "@type": "case-investigation:Evidence",
            "uco-core:name": vec.get("name"),
            "netpulse:vectorType": vec.get("vector_id"),
            "netpulse:rawSignal": vec.get("raw_evidence"),
            "netpulse:weight": vec.get("weight"),
            "netpulse:confidence": vec.get("confidence"),
            "netpulse:observedAt": vec.get("observed_at"),
        })

    # 3. Build CASE Inference (Attribution Verdict & Proof Mode Grade)
    inference_id = f"netpulse:inference:{device_key}:{now_ts}"
    case_inference = {
        "@id": inference_id,
        "@type": "case-investigation:Inference",
        "uco-core:name": "Device Identity & Proof Mode Attribution",
        "case-investigation:evidence": [item["@id"] for item in evidence_items],
        "case-investigation:subject": device_obj_id,
        "netpulse:verdictGrade": proof_verdict.get("grade", "WEAK"),
        "netpulse:calibratedProbability": proof_verdict.get("calibrated_probability", 0.0),
        "netpulse:proofSummary": proof_verdict.get("proof_summary", ""),
        "netpulse:brierScore": proof_verdict.get("brier_score", 0.0),
    }

    # 4. Chain of Custody from Events Ledger
    ledger_hashes: List[str] = []
    for entry in ledger_entries:
        h = entry.get("hash")
        if h:
            ledger_hashes.append(str(h))

    head_hash = ledger_hashes[-1] if ledger_hashes else hashlib.sha256(b"netpulse-genesis").hexdigest()

    chain_of_custody = {
        "@type": "case-investigation:ChainOfCustody",
        "uco-core:name": "NetPulse Tamper-Evident SHA-256 Event Ledger",
        "netpulse:ledgerHeadHash": head_hash,
        "netpulse:ledgerEntriesCount": len(ledger_entries),
        "netpulse:verificationWindowHours": window_hours,
    }

    # 5. Assemble JSON-LD Graph Bundle
    bundle = {
        "@context": CASE_CONTEXT,
        "@id": bundle_id,
        "@type": "case-investigation:InvestigativeBundle",
        "uco-core:name": f"Admissible Evidence Bundle for {device_key}",
        "uco-core:createdTime": created_iso,
        "uco-core:createdBy": investigator_id,
        "@graph": [
            uco_device_object,
            *evidence_items,
            case_inference,
            {
                "@id": investigation_id,
                "@type": "case-investigation:InvestigativeAction",
                "uco-core:name": "Sovereign Multi-Vector Network Intelligence Scan",
                "uco-action:actionStatus": "Success",
                "case-investigation:chainOfCustody": chain_of_custody,
            },
        ],
    }

    # 6. Cryptographic Manifest Signature
    canonical_bytes = json.dumps(bundle, sort_keys=True).encode("utf-8")
    sig = hmac.new(signing_secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    bundle["netpulse:signature"] = {
        "algorithm": "HMAC-SHA256",
        "manifest_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "signature_hex": sig,
    }

    return bundle


def verify_evidence_bundle(bundle: Dict[str, Any], signing_secret: Optional[str] = None) -> Dict[str, Any]:
    """Offline standalone verification of a CASE/UCO evidence bundle."""
    sig_block = bundle.get("netpulse:signature")
    if not sig_block or not isinstance(sig_block, dict):
        return {"valid": False, "error": "Missing netpulse:signature block"}

    sig_hex = sig_block.get("signature_hex")
    manifest_hash = sig_block.get("manifest_sha256")

    # Reconstruct un-signed bundle payload
    bundle_copy = {k: v for k, v in bundle.items() if k != "netpulse:signature"}
    canonical_bytes = json.dumps(bundle_copy, sort_keys=True).encode("utf-8")
    calculated_manifest = hashlib.sha256(canonical_bytes).hexdigest()

    if calculated_manifest != manifest_hash:
        return {
            "valid": False,
            "error": "Manifest hash mismatch (tampered content)",
            "expected_manifest": manifest_hash,
            "calculated_manifest": calculated_manifest,
        }

    signature_valid: Optional[bool] = None
    if signing_secret:
        expected_sig = hmac.new(signing_secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
        signature_valid = hmac.compare_digest(expected_sig, sig_hex or "")
        if not signature_valid:
            return {"valid": False, "error": "Cryptographic signature verification failed"}

    # Validate CASE/UCO Graph Structure
    graph = bundle.get("@graph", [])
    has_observable = any(n.get("@type") == "uco-observable:ObservableObject" for n in graph)
    has_inference = any(n.get("@type") == "case-investigation:Inference" for n in graph)
    evidence_count = sum(1 for n in graph if n.get("@type") == "case-investigation:Evidence")

    inference = next((n for n in graph if n.get("@type") == "case-investigation:Inference"), {})
    verdict_grade = inference.get("netpulse:verdictGrade", "UNKNOWN")
    calibrated_p = inference.get("netpulse:calibratedProbability", 0.0)

    return {
        "valid": True,
        "signature_valid": signature_valid,
        "bundle_id": bundle.get("@id"),
        "created_time": bundle.get("uco-core:createdTime"),
        "has_observable_device": has_observable,
        "has_case_inference": has_inference,
        "evidence_vector_count": evidence_count,
        "verdict_grade": verdict_grade,
        "calibrated_probability": calibrated_p,
        "manifest_sha256": calculated_manifest,
    }
