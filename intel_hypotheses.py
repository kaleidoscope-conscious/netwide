"""
Detection Hypothesis Generator — the "information density" differentiator.

Converts raw probe/auditor/threat findings into prioritized, actionable
hypotheses with a suggested remedy per hypothesis.

Two-axis Boltzmann algebra (adapted from the quantum binding-hypothesis
prototype, corrected for threat semantics):

    probability = exp(-E_uncertainty / kT)     # kT = 0.592 normalized scale
        E_uncertainty is the "maturation energy" of the signal:
        directly observed facts (live ARP flips, probe VERIFIED results) have
        near-zero uncertainty energy -> probability near 1. Speculative /
        unattributed signals carry high uncertainty energy -> low probability.

    severity  = f(E_severity)                  # CRITICAL / HIGH / MEDIUM / LOW
    impact    = composite(severity_energy, exposure, proximity)  # 0..1
    expected_value = probability * impact      # ranking key

This avoids the classic inversion bug where a fully-observed CRITICAL event
would score BELOW a weak-but-easy MEDIUM signal.

Output shape per hypothesis:
    {id, category, signal_kind, severity, title, device_key, ip, device_name,
     probability, impact, confidence, suggested_action, evidence,
     expected_value, generated_at}
"""

from __future__ import annotations

import hashlib
import math
import time
from typing import Any, Dict, List

K_BOLTZ = 0.592  # normalized kT (uncertainty/maturity energy scale)


def _gaussian(x: float, mu: float, sigma: float) -> float:
    """Gaussian prior factor in [0, 1]."""
    return math.exp(-((x - mu) ** 2) / (2.0 * (sigma ** 2 + 1e-9)))


def _probability_from_uncertainty(uncertainty: float) -> float:
    return round(math.exp(-max(0.0, uncertainty) / K_BOLTZ), 4)


def _severity_from_energy(energy: float) -> str:
    if energy >= 0.75:
        return "CRITICAL"
    if energy >= 0.5:
        return "HIGH"
    if energy >= 0.3:
        return "MEDIUM"
    return "LOW"


def _hyp_id(signal_kind: str, device_key: str, title: str = "") -> str:
    digest = hashlib.sha256(f"{signal_kind}:{device_key}:{title}".encode("utf-8")).hexdigest()[:12]
    return f"hyp_{digest}"


def _mk(
    signal: str,
    severity_energy: float,
    title: str,
    action: str,
    device_key: str = "",
    ip: str = "",
    device_name: str = "",
    impact: float = 0.0,
    uncertainty: float = 0.30,
    confidence: float = 0.6,
    evidence: str = "",
) -> Dict[str, Any]:
    impact = impact if impact > 0 else min(1.0, 0.35 + 0.55 * severity_energy)
    probability = _probability_from_uncertainty(uncertainty)
    return {
        "id": _hyp_id(signal, device_key or ip, title),
        "category": "threat",
        "signal_kind": signal,
        "severity": _severity_from_energy(severity_energy),
        "title": title,
        "device_key": device_key,
        "ip": ip,
        "device_name": device_name,
        "probability": probability,
        "impact": round(impact, 3),
        "confidence": round(confidence, 3),
        "expected_value": round(probability * impact, 4),
        "suggested_action": action,
        "evidence": (evidence or title)[:400],
        "generated_at": time.time(),
    }


# Finding-title keyword -> (severity_energy, suggested-action playbook).
# Finding texts come from live probes, so their uncertainty is low by default.
# Matched against actual synthesized titles in fingerprint.py (e.g. "Cleartext
# Telnet Service Exposed", "Deprecated TLS Protocol Version", "Unencrypted
# HTTP Gateway Management") plus legacy IoT keywords.
FINDING_PLAYBOOK: List[Dict[str, Any]] = [
    {"k": "anonymous", "t": "mqtt", "energy": 0.80,
     "action": "Isolate this broker behind a VLAN and enable broker authentication (MQTT 3.x ships with NO authentication by default)."},
    {"k": "unauthenticated docker", "energy": 0.90,
     "action": "Bind the Docker Engine API to 127.0.0.1 or enable TLS — an open :2375 is effectively remote root."},
    {"k": "docker", "energy": 0.90,
     "action": "Bind the Docker Engine API to 127.0.0.1 or enable TLS — an open :2375 is effectively remote root."},
    {"k": "telnet", "energy": 0.95,
     "action": "Disable Telnet immediately and migrate to SSH key auth — cleartext credentials are captured by any LAN observer."},
    {"k": "adb", "energy": 0.92,
     "action": "Disable Wireless Debugging / ADB over TCP; exposed ADB gives LAN shell execution."},
    {"k": "deprecated tls", "energy": 0.65,
     "action": "Disable TLS 1.0/1.1 and enforce TLS 1.2+ with AEAD suites on this service."},
    {"k": "smb", "energy": 0.50,
     "action": "Enable mandatory SMB packet signing (GPO / smb.conf 'server signing = mandatory')."},
    {"k": "ssh", "energy": 0.45,
     "action": "Upgrade OpenSSH and disable obsolete KEX/cipher suites; prefer Ed25519 host keys."},
    {"k": "mqtt", "energy": 0.72,
     "action": "Enable broker authentication; anonymous CONNECT acceptance is directly exploitable."},
    {"k": "dns", "energy": 0.40,
     "action": "Enable DNSSEC validation and DNS-over-TLS on the upstream resolver."},
    {"k": "unencrypted", "energy": 0.55,
     "action": "Gate this endpoint behind TLS/VLAN and strong auth — unencrypted LAN admin is sniffable capture."},
    {"k": "roku", "energy": 0.35,
     "action": "Disable Roku ECP network access if not needed (Settings → Network)."},
    {"k": "randomized", "energy": 0.35,
     "action": "Verify this randomized-MAC device is an authorized household/guest device."},
    {"k": "duplicate", "energy": 0.85,
     "action": "Validate gateway MAC manually and quarantine the anomalous host via Guardian Shield if confirmed."},
    {"k": "evil twin", "energy": 0.85,
     "action": "Confirm your SSID security; disable WPS and enforce WPA3."},
    {"k": "ntp", "energy": 0.60,
     "action": "Restrict Mode-6/7 control queries and disable monlist; rate-limit NTP at the gateway."},
    {"k": "kasa", "energy": 0.62,
     "action": "Update device firmware — the legacy Kasa XOR autokey is reversible by any LAN observer."},
    {"k": "sonos", "energy": 0.30,
     "action": "Restrict UPnP AVTransport control to the intended subnets."},
    {"k": "hue", "energy": 0.28,
     "action": "Regenerate the Hue Bridge API key (press-ink bridge cycle)."},
    {"k": "upnp", "energy": 0.55,
     "action": "Disable UPnP IGD port-forwarding on the gateway or scope it to trusted hosts."},
    {"k": "camera", "energy": 0.68,
     "action": "Counter-surveillance sweep hit — physically inspect the flagged device."},
]

DEFAULT_ENERGY = 0.45
# Probe-produced device findings are measurements, not guesses.
FINDING_UNCERTAINTY = 0.15


def _severity_energy_from_finding(sev: str) -> float:
    return {"CRITICAL": 0.85, "HIGH": 0.55, "MEDIUM": 0.35, "LOW": 0.2}.get((sev or "").upper(), DEFAULT_ENERGY)


def generate_hypotheses(
    devices: List[Dict[str, Any]],
    wifi_spectrum: Dict[str, Any],
    arp_anomalies: List[Dict[str, Any]] = None,
    threats: List[Dict[str, str]] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """
    Build the focused, ranked hypothesis list.

    Sources:
      devices       — device inventory rows (with security_findings,
                      risk_score, custom_name / display_name)
      wifi_spectrum — spectrum dict with access_points (hidden APs, verdicts,
                      security, signal, hotspot_probability from Stage 12)
      arp_anomalies — live sniffer anomaly entries
      threats       — output of fingerprint.audit_network_threats
    """
    arp_anomalies = arp_anomalies or []
    threats = threats or []
    hyps: List[Dict[str, Any]] = []

    # 1) Per-device security findings (probe-verified measurements)
    for d in devices:
        dkey = d.get("device_key") or d.get("mac") or f"IP:{d.get('ip', '')}"
        ip = d.get("ip", "")
        dname = d.get("custom_name") or d.get("display_name") or ip
        risk = min(1.0, float(d.get("risk_score") or 0) / 100.0)
        for f in d.get("security_findings", []) or []:
            title = str(f.get("title", "") or "")
            sev = str(f.get("severity", "") or "")
            low = title.lower()
            sev_energy = _severity_energy_from_finding(sev)
            # Uncertainty modulated by host risk context: risky hosts make
            # real exploitation more plausible (Boltzmann prior shift).
            uncertainty = max(0.05, FINDING_UNCERTAINTY - 0.10 * risk)
            action = "Review device endpoint exposure and apply vendor hardening guidance."
            for pb in FINDING_PLAYBOOK:
                if str(pb["k"]).lower() in low:
                    sev_energy = float(pb["energy"])
                    action = str(pb["action"])
                    break
            impact = min(1.0, 0.35 + 0.45 * sev_energy + 0.20 * risk)
            confidence = min(1.0, 0.55 + 0.25 * risk + (0.20 if sev == "CRITICAL" else 0.0))
            hyps.append(_mk(
                "device_finding", sev_energy, f"{dname} — {title}" if dname else title, action,
                device_key=dkey, ip=ip, device_name=dname,
                impact=impact, uncertainty=uncertainty, confidence=confidence,
                evidence=str(f.get("description", ""))[:400] or title,
            ))

    # 2) RF spectrum signals — hidden APs, tether classifiers, open APs
    aps = (wifi_spectrum or {}).get("access_points", []) or []
    for ap in aps:
        bssid = ap.get("bssid", "")
        ssid = ap.get("ssid", "<Hidden>")
        dbm = float(ap.get("signal_dbm") or -90.0)
        verdict = str(ap.get("attribution_verdict") or "")
        proximity = _gaussian(dbm, -55.0, 20.0)  # -55 dBm ≈ same room

        if ap.get("is_hidden"):
            hot_prob = float(ap.get("hotspot_probability") or 0.0)
            if verdict.startswith("VERIFIED_"):
                # De-cloaker directly attributed this BSSID — strong signal
                hyps.append(_mk(
                    "hidden_tether", 0.30,
                    f"Decloaked hidden AP {bssid} attributed: {verdict}",
                    "Verify the attributed owner/device class matches expectations; unexpected cloaks are moving-device indicators.",
                    device_key=bssid, ip="RF",
                    impact=0.35, uncertainty=0.18, confidence=0.9,
                    evidence=f"{ssid} | {verdict} | evidence: {ap.get('attribution_evidence')}",
                ))
            elif hot_prob >= 0.55:
                # Stage-12 tether classifier fired — moderate probability,
                # rising with hotspot_probability (Boltzmann prior shift)
                hyps.append(_mk(
                    "hidden_tether", 0.35,
                    f"Probable personal hotspot / tether transmitter {bssid} (p={hot_prob:.2f})",
                    ap.get("tether_role_hint")
                    or "Correlate with nearby mobile devices; a hotspot moves with its owner.",
                    device_key=bssid, ip="RF",
                    impact=0.30 + 0.40 * hot_prob * proximity,
                    uncertainty=max(0.10, 0.55 - 0.50 * hot_prob),
                    confidence=hot_prob,
                    evidence=f"{ssid} | {ap.get('tether_role_hint', '')} | vendor={ap.get('vendor')}",
                ))
            else:
                hyps.append(_mk(
                    "hidden_unattributed", 0.45,
                    f"Hidden SSID transmitter with no attribution: {bssid} (Ch {ap.get('channel')}, {dbm:.0f} dBm)",
                    "Run the 10-Stage De-Cloaker walk-around (Stage-10 RSSI covariance needs dwell time) or enable passive census.",
                    device_key=bssid, ip="RF",
                    impact=0.30 + 0.45 * proximity,
                    uncertainty=0.62, confidence=proximity,
                    evidence=f"security={ap.get('security')} vendor={ap.get('vendor')} signal={dbm} dBm",
                ))

        if "OPEN" in str(ap.get("security", "")).upper():
            # Measured beacon (real) — proximity scales impact, not probability
            hyps.append(_mk(
                "open_ap", 0.42,
                f"Open (unencrypted) AP '{ssid}' ({bssid}) on Ch {ap.get('channel')}",
                "Confirm whether this is your guest SSID; otherwise move the network to WPA2/WPA3 and disable WPS push-button.",
                device_key=bssid, ip="RF",
                impact=0.35 + 0.50 * proximity,
                uncertainty=0.25, confidence=max(0.5, proximity),
                evidence=f"vendor={ap.get('vendor')} signal={dbm} dBm",
            ))

    # 3) Live sniffer anomalies (L2 measurements — near-certain)
    for an in arp_anomalies:
        kind = str(an.get("kind", an.get("type", "arp")))
        hyps.append(_mk(
            f"arp_{kind}", 0.85,
            str(an.get("title") or "ARP anomaly observed on the wire"),
            "Validate the gateway MAC manually and quarantine the anomalous host via Guardian Shield if confirmed.",
            device_key=str(an.get("mac", "")), ip=str(an.get("ip", "")),
            impact=0.92, uncertainty=0.05, confidence=0.85,
            evidence=str(an.get("details", ""))[:400],
        ))

    # 4) Threat-audit correlations (live table + RF cross-checks)
    for t in threats:
        cat = str(t.get("category", ""))
        sev = str(t.get("severity", "HIGH"))
        hyps.append(_mk(
            f"audit_{cat.lower()}", _severity_energy_from_finding(sev),
            str(t.get("title", "")),
            "Investigate per the NetPulse threat playbook; Guardian Shield quarantine is one click away.",
            device_key=str(t.get("device_key", "")), ip=str(t.get("ip", "")),
            uncertainty=0.15, confidence=0.75,
            evidence=str(t.get("details", ""))[:400],
        ))

    # Rank by expected value = probability * impact (ties -> confidence)
    hyps.sort(key=lambda h: (h["expected_value"], h["confidence"]), reverse=True)
    # Deduplicate by id (first occurrence keeps the higher rank)
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for h in hyps:
        if h["id"] in seen:
            continue
        seen.add(h["id"])
        out.append(h)
    return out[:limit]


def compute_threat_field(hypotheses: List[Dict[str, Any]], top_n: int = 12) -> Dict[str, Any]:
    """Continuous collapse/measure: per-device field + global coherence.

    Field per device = max expected_value among its hypotheses.
    Coherence = fraction of devices whose top hypothesis is CRITICAL/HIGH.
    """
    by_device: Dict[str, float] = {}
    for h in hypotheses or []:
        k = str(h.get("device_key") or h.get("ip") or "unknown")
        ev = float(h.get("expected_value") or 0)
        if k not in by_device or ev > by_device[k]:
            by_device[k] = ev
    ranked = sorted(by_device.items(), key=lambda kv: kv[1], reverse=True)
    high = sum(1 for h in (hypotheses or []) if str(h.get("severity")).upper() in ("CRITICAL", "HIGH"))
    coherence = round(high / max(1, len(hypotheses or [])), 3)
    field = [
        {"device_key": k, "field_strength": round(v, 4)}
        for k, v in ranked[:top_n]
    ]
    return {
        "ok": True,
        "coherence": coherence,
        "devices_in_field": len(by_device),
        "field": field,
        "top": (hypotheses or [])[:top_n],
    }
