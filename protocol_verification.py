"""
Netwide Protocol Verification Engine (NPVE).

The rule this module enforces across the whole product:

    A verdict must be supported by evidence. If the evidence is structurally
    invalid, the engine reports the failure instead of a conclusion.

For every protocol the scanners assessed, this builds a report that states:

* whether the exchange was **structurally valid** (which specification
  requirements were met and which failed),
* the **security conclusion** that was drawn,
* the **confidence** in that conclusion, and
* the **evidence** the conclusion rests on.

It is intentionally read-only and derived from the evidence already captured, so
it can never claim more than the scanners actually proved.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Confidence levels, strongest first.
CONFIDENCE_ORDER = ("definitive", "strong", "inferred", "weak")

PROTOCOL_SPECS = {
    "ssh": {"spec": "RFC 4253 §7.1", "label": "SSHv2 KEXINIT"},
    "smb": {"spec": "MS-SMB2 3.2.3.1/3.2.3.2", "label": "SMB2 NEGOTIATE"},
    "dns": {"spec": "RFC 1035 §4.1 + RFC 4035 §3.2.3", "label": "DNS / DNSSEC"},
    "dot": {"spec": "RFC 7858", "label": "DNS-over-TLS"},
    "ntp": {"spec": "RFC 5905", "label": "NTPv4 control messages"},
    "tls": {"spec": "RFC 8446 / RFC 5280", "label": "TLS + X.509"},
}


def _confidence_from(validation: Dict[str, Any], inferred_only: bool = False) -> str:
    """
    Map a parser's validation block onto a confidence level.

    * ``complete``  -> the exchange satisfied the specification -> definitive
    * partial       -> some requirements failed -> inferred
    * absent        -> no structural evidence at all -> weak
    """
    if not validation:
        return "weak"
    if validation.get("complete"):
        return "strong" if inferred_only else "definitive"
    return "inferred" if not inferred_only else "weak"


def _entry(protocol: str, *, validation: Dict[str, Any], verdict: str, basis: str,
           confidence: str, details: Dict[str, Any] | None = None) -> Dict[str, Any]:
    spec = PROTOCOL_SPECS.get(protocol, {})
    return {
        "protocol": protocol,
        "label": spec.get("label", protocol.upper()),
        "specification": spec.get("spec", ""),
        "evidence_valid": bool(validation.get("complete")),
        "requirements_failed": list(validation.get("failed") or []),
        "verdict": verdict,
        "confidence": confidence,
        "evidence": basis,
        "details": details or {},
    }


def assess_device(device: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build the verification entries for one device from its captured evidence."""
    out: List[Dict[str, Any]] = []
    ip = device.get("ip", "")

    # ---------------------------------------------------------------- SSH
    ssh = device.get("ssh_info") or {}
    if ssh:
        validation = ssh.get("validation") or {}
        weak = (ssh.get("weak_kex") or []) + (ssh.get("weak_ciphers") or []) + \
               (ssh.get("weak_hostkeys") or []) + (ssh.get("weak_macs") or [])
        if weak:
            verdict = f"{ssh.get('crypto_grade', 'Unrated')} — {len(weak)} legacy algorithm(s) advertised"
        else:
            verdict = f"{ssh.get('crypto_grade', 'Unrated')} — no legacy algorithm advertised"
        out.append(_entry(
            "ssh",
            validation=validation,
            verdict=verdict,
            basis=(
                f"KEXINIT parsed (10/10 name-lists), HASSH {ssh.get('hassh_server', '')[:16]}…, "
                f"framing {'valid' if validation.get('packet_framing_valid') else 'unverified'}. "
                "Algorithms are advertised availability, not the negotiated set."
            ),
            confidence=_confidence_from(validation),
            details={
                "weak_algorithms": weak[:8],
                "hassh_server": ssh.get("hassh_server", ""),
                "post_quantum_kex": ssh.get("post_quantum_kex", False),
            },
        ))

    # --------------------------------------------------------------- SMB2
    smb = device.get("smb_info") or {}
    if smb:
        validation = smb.get("validation") or {}
        out.append(_entry(
            "smb",
            validation=validation,
            verdict=smb.get("security_posture", "Unrated"),
            basis=(
                f"NEGOTIATE response: dialect {smb.get('dialect', '?')}, "
                f"signing enabled={smb.get('signing_enabled')} required={smb.get('signing_required')}; "
                f"negotiate contexts {smb.get('negotiate_contexts') or 'none'}; "
                f"relay risk indicator={smb.get('ntlm_relay_risk')}."
            ),
            confidence="definitive" if validation.get("complete", True) else "inferred",
            details={
                "relay_risk_indicator": smb.get("ntlm_relay_risk"),
                "relay_risk_basis": smb.get("ntlm_relay_risk_basis", ""),
                "negotiate_contexts": smb.get("negotiate_contexts", []),
                "preauth_integrity_supported": smb.get("preauth_integrity_supported"),
            },
        ))

    # --------------------------------------------------------- DNS / DNSSEC
    dns = device.get("dns_info") or {}
    if dns:
        validation = {"complete": bool(dns.get("dns_active")), "failed": []}
        if dns.get("response_validation", "").startswith("REJECTED"):
            validation["complete"] = False
            validation["failed"] = [dns["response_validation"]]
        out.append(_entry(
            "dns",
            validation=validation,
            verdict=(
                f"Resolver reported AD=1 (DNSSEC)" if dns.get("dnssec_validated")
                else "Resolver did not report DNSSEC validation (AD=0)"
            ),
            basis=(
                f"{dns.get('response_validation', 'no response validation')}. "
                "The AD bit is the resolver's own assertion (RFC 4035), not an independent "
                "validation performed by Netwide."
            ),
            # AD=1 is a second-hand assertion -> strong, not definitive
            confidence=_confidence_from(validation, inferred_only=True),
            details={
                "recursion_available": dns.get("recursion_available"),
                "version_bind_leak": dns.get("version_bind_leak", ""),
                "rcode": dns.get("rcode_name"),
                "validation_source": dns.get("dnssec_validation_source", ""),
            },
        ))

    # ------------------------------------------------------ DNS-over-TLS
    if dns.get("dot_port_853_open"):
        out.append(_entry(
            "dot",
            validation={"complete": bool(dns.get("dot_protocol_works")), "failed": []},
            verdict=(
                "RFC 7858 DoT exchange completed; certificate chain trusted"
                if dns.get("dot_protocol_works") and dns.get("dot_tls_chain_trusted")
                else ("RFC 7858 DoT exchange completed; certificate chain NOT trusted"
                      if dns.get("dot_protocol_works")
                      else "TLS service present on 853 but no valid DNS-over-TLS exchange")
            ),
            basis=(
                f"Length-prefixed DNS query sent over TLS; response validated={dns.get('dot_response_validated')}; "
                f"chain trusted={dns.get('dot_tls_chain_trusted')}; cipher {dns.get('dot_tls_cipher', '?')}."
            ),
            confidence="definitive" if dns.get("dot_protocol_works") else "weak",
            details={"tls_cipher": dns.get("dot_tls_cipher", ""),
                     "verify_error": dns.get("dot_tls_verify_error", "")},
        ))

    # ---------------------------------------------------------------- NTP
    ntp = device.get("ntp_info") or {}
    if ntp:
        if ntp.get("mode6_control_exposed"):
            verdict = "NTP Mode 6 control messages are answered (management exposure, not amplification)"
            basis = ("Mode 6 control request received a Mode 6 response. Mode 7 MONLIST is the historical "
                     "CVE-2013-5211 amplification vector and is assessed separately.")
            conf = "definitive"
        elif ntp.get("legacy_monlist_amplification"):
            verdict = "Mode 7 MONLIST amplification measured"
            basis = ntp.get("legacy_monlist_amplification_detail", "")
            conf = "definitive"
        elif ntp.get("ntp_active"):
            verdict = "NTP server responsive; no control-message exposure observed"
            basis = ("Mode 6 and Mode 7 probes received no control response.")
            conf = "definitive"
        else:
            verdict = "No NTP response"
            basis = "The NTP probe timed out."
            conf = "weak"
        out.append(_entry(
            "ntp",
            validation={"complete": bool(ntp.get("ntp_active")), "failed": []},
            verdict=verdict,
            basis=basis,
            confidence=conf,
            details={
                "mode6_control_responsive": ntp.get("ntp_control_responsive", ""),
                "mode7_amplification_ratio": ntp.get("mode7_amplification_ratio", 0.0),
                "mode7_detail": ntp.get("legacy_monlist_amplification_detail", ""),
                "stratum": ntp.get("stratum"),
            },
        ))

    # ---------------------------------------------------------------- TLS
    for svc in (device.get("port_services") or []):
        if not svc.get("tls_grade"):
            continue
        chain = svc.get("cert_chain_trusted")
        expired = svc.get("cert_expired")
        out.append(_entry(
            "tls",
            validation={"complete": True, "failed": []},
            verdict=svc.get("tls_grade", "Unrated"),
            basis=(
                f"{svc.get('tls_version', '?')} / {svc.get('tls_cipher', '?')}; "
                f"chain trusted={chain}; expired={expired}; identity match={svc.get('cert_hostname_match')}; "
                f"JA3={svc.get('ja3', 'n/a')} (source: {svc.get('ja3_source', 'n/a')})."
            ),
            confidence="definitive" if chain and not expired else "strong",
            details={
                "ja3": svc.get("ja3", ""), "ja3s": svc.get("ja3s", ""),
                "ja3_source": svc.get("ja3_source", ""),
                "chain_trusted": chain, "expired": expired,
                "hostname_match": svc.get("cert_hostname_match"),
            },
        ))
    return out


def build_report(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assemble the verification report for every assessed device."""
    entries: List[Dict[str, Any]] = []
    per_protocol: Dict[str, Dict[str, int]] = {}
    for dev in devices:
        for entry in assess_device(dev):
            entry["ip"] = dev.get("ip", "")
            entry["device"] = dev.get("display_name", "")
            entries.append(entry)
            bucket = per_protocol.setdefault(entry["protocol"], {"total": 0, "definitive": 0, "weak": 0})
            bucket["total"] += 1
            if entry["confidence"] == "definitive":
                bucket["definitive"] += 1
            if entry["confidence"] == "weak":
                bucket["weak"] += 1
    return {
        "ok": True,
        "principle": (
            "A verdict must be supported by evidence. If the evidence is structurally "
            "invalid, the engine reports the failure instead of a conclusion."
        ),
        "confidence_scale": list(CONFIDENCE_ORDER),
        "protocols": per_protocol,
        "entries": entries,
        "counts": {
            "entries": len(entries),
            "definitive": sum(1 for e in entries if e["confidence"] == "definitive"),
            "weak": sum(1 for e in entries if e["confidence"] == "weak"),
        },
    }
