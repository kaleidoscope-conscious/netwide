"""Detection-rule compiler (JSON DSL -> audit manifest).

Enterprise add-on shape: declare a rule in JSON, compile to a
vuln-regex audit + SHA-256 manifest for provenance. No code exec.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List

DSL_FIELDS = ("id", "title", "severity", "category", "match", "action")

def validate_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    for f in DSL_FIELDS:
        if f not in rule:
            return {"ok": False, "error": f"missing field: {f}"}
    if str(rule["severity"]).upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return {"ok": False, "error": "severity must be CRITICAL/HIGH/MEDIUM/LOW/INFO"}
    try:
        re.compile(str(rule["match"]))
    except re.error as e:
        return {"ok": False, "error": f"bad regex: {e}"}
    return {"ok": True}

def compile_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    v = validate_rule(rule)
    if not v["ok"]:
        return {"ok": False, "error": v["error"]}
    canonical = json.dumps(rule, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "rule_id": str(rule["id"]),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "regex": str(rule["match"]),
        "severity": str(rule["severity"]).upper(),
        "action": str(rule["action"]),
    }
    # Compile to a python matcher (pure, no exec of user code)
    try:
        pattern = re.compile(str(rule["match"]), re.IGNORECASE)
        def _matcher(text: str) -> bool:
            return bool(pattern.search(text or ""))
        manifest["test_match"] = _matcher("test " + str(rule["title"]) + " sample")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "manifest": manifest}

def audit_payload(payload: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    try:
        text = json.dumps(payload).lower()
    except Exception:
        text = str(payload).lower()
    for r in rules:
        try:
            if re.search(str(r.get("match") or ""), text, re.IGNORECASE):
                hits.append({"rule_id": r.get("id"), "title": r.get("title"), "severity": r.get("severity")})
        except re.error:
            continue
    return hits
