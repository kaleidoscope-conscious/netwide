"""LLM-assisted remediation (tempered, confirm-gated, no auto-exec).

Local template engine — no external LLM call, no tokens burned. Every
suggestion requires explicit confirm to run. This is the safe 80%.
"""
from __future__ import annotations

from typing import Any, Dict

TEMPLATES = [
    ("telnet", "Telnet sends credentials in cleartext on TCP {port}. Any LAN observer can capture them. Switch to SSH key auth and close {port}.", "Disable Telnet; enable sshd with PasswordAuthentication no + PubkeyAuthentication yes."),
    ("adb", "ADB over TCP {port} grants LAN shell execution. Disable Wireless Debugging in Developer Options.", "Turn off Developer Options → Wireless Debugging, then re-scan."),
    ("docker", "Docker Engine on :2375 lets any LAN client escape to root via the daemon API. Bind to unix socket or require mTLS on :2376.", "Bind dockerd to unix:///var/run/docker.sock; block 2375 at the gateway."),
    ("mqtt", "Anonymous MQTT allows subscribing to '#' and injecting actuator commands without credentials.", "Set allow_anonymous false; enforce username/password + TLS per device."),
    ("smb", "SMB signing not required enables NTLM relay via Responder on the LAN.", "Enable 'server signing = mandatory' / GPO 'Digitally sign communications (always)'."),
    ("tls", "Deprecated TLS is negotiable — attackers can downgrade to weak ciphers. Enforce TLS 1.2+ with AEAD.", "Disable TLS 1.0/1.1 in the service config; restart and re-audit."),
    ("randomized", "This MAC has the LAA bit set (per-SSID randomization). It may be a phone's private MAC — verify household membership.", "Confirm owner; if expected, mark trusted to clear the identity penalty."),
    ("evil twin", "An open AP is broadcasting your SSID. It may harvest handshakes.", "Verify channel/BSSID in person; enforce WPA3-SAE; disable WPS."),
    ("duplicate", "One MAC on two IPs signals possible ARP poisoning / MITM.", "Check gateway ARP table; quarantine the second claimant via Guardian Shield."),
]

def search_template(haystack: str) -> Dict[str, str] | None:
    low = (haystack or "").lower()
    for key, explain, suggest in TEMPLATES:
        if key in low:
            return {"key": key, "explain": explain, "suggest": suggest}
    return None

def explain_device(device: Dict[str, Any], question: str = "") -> Dict[str, Any]:
    findings = device.get("security_findings") or []
    lines, suggestions = [], []
    for f in findings:
        title = str(f.get("title") or "")
        desc = str(f.get("description") or "")
        t = search_template(title + " " + desc)
        if t:
            lines.append(f"{title}: {t['explain'].format(port='')}")
            suggestions.append(t["suggest"])
        else:
            lines.append(f"{title}: {desc[:200]}")
            suggestions.append(str(f.get("remediation") or "Review vendor hardening guidance."))
    summary = " ".join(lines) or "No active findings for this device. Consider marking it trusted if expected."
    return {
        "ok": True,
        "device_key": device.get("device_key"),
        "ip": device.get("ip"),
        "question": question,
        "explanation": summary,
        "suggested_commands": suggestions,
        "confirm_required": True,
        "auto_executed": False,
        "note": "Suggestions require explicit operator confirm via POST /api/control or /api/action/quarantine. Nothing was executed.",
    }
