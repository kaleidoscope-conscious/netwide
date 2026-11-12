"""Firmware exposure pillar (Enterprise differentiator).

Discovery is intentionally conservative:
- Only device-reported URLs (UPnP desc / vendor HTTP on RFC1918 LAN hosts)
- 30 MB cap, 5s timeout, consent-gated by caller (tier + explicit action)
- Read-only analysis: entropy, strings, version extraction, CVE hints by
  exact version string. Never auto-flashes, never auto-verifies CVEs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import urllib.request
from typing import Any, Dict, List

_MAX_FIRMWARE_BYTES = 30 * 1024 * 1024
_KNOWN_VERSION_RE = re.compile(r"(?:v|ver\.?|firmware|fw)\s*v?([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE)
# Tiny offline CVE hint pack — exact version strings only. Extend via add-on packs.
_OFFLINE_CVE_HINTS: Dict[str, List[str]] = {
    "1.0.0": ["CVE-2021-0000 (example pack — replace with licensed feed)"],
    "6.5.2": ["Check Ubiquiti 6.5 advisory before exposing controller"],
    "7.5.0": ["Check RouterOS 7.5 changelog for WAN auth fixes"],
    "3.10.1": ["Check TP-Link KRACK/wpa2 patch level"],
    "5.3.9": ["Check D-Link/TP-Link era firmware advisories"],
}

def is_rfc1918_target(url: str) -> bool:
    try:
        host = re.sub(r"^https?://", "", str(url).strip()).split("/", 1)[0].split(":", 1)[0]
        return ipaddress.ip_address(host).is_private  # RFC1918 + loopback family
    except Exception:
        return False

def extract_version(blob: bytes, limit: int = 2_000_000) -> str:
    head = blob[:limit]
    txt = head.decode("utf-8", errors="ignore")
    m = _KNOWN_VERSION_RE.search(txt)
    return m.group(1) if m else ""

def shannon_entropy(blob: bytes, sample: int = 65536) -> float:
    if not blob:
        return 0.0
    data = blob[:sample]
    if len(data) == 0:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    ent = 0.0
    n = len(data)
    for c in hist:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)

def extract_strings(blob: bytes, min_len: int = 6, limit: int = 200) -> List[str]:
    out: List[str] = []
    cur: List[int] = []
    for b in blob[:2_000_000]:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="ignore"))
                if len(out) >= limit:
                    break
            cur = []
    if len(cur) >= min_len and len(out) < limit:
        out.append(bytes(cur).decode("ascii", errors="ignore"))
    return out

def has_binwalk_signatures(blob: bytes) -> List[str]:
    sigs: List[str] = []
    if blob[:4] == b"\x7fELF":
        sigs.append("ELF")
    if blob[:4] == b"\x1f\x8b\x08\x00":
        sigs.append("gzip")
    if b"HSQS" in blob[:65536]:
        sigs.append("SquashFS")
    if b"U-Boot" in blob[:65536] or b"UBOOT" in blob[:65536]:
        sigs.append("U-Boot")
    if b"Linux version" in blob[:65536]:
        sigs.append("Linux kernel")
    return sigs

def analyze_firmware(blob: bytes) -> Dict[str, Any]:
    if not blob:
        return {"ok": False, "error": "empty blob"}
    sigs = has_binwalk_signatures(blob)
    ent = shannon_entropy(blob)
    version = extract_version(blob)
    strings = extract_strings(blob)
    cves = list(_OFFLINE_CVE_HINTS.get(version, []))
    return {
        "ok": True,
        "sha256": hashlib.sha256(blob).hexdigest(),
        "bytes": len(blob),
        "signatures": sigs,
        "entropy": ent,
        "version_guess": version,
        "cve_hints": cves,
        "strings_sample": strings[:40],
        "cve_disclaimer": "Hints by exact version only; verify against vendor + licensed CVE feed before acting.",
    }

def fetch_and_audit(url: str, consent: bool = False) -> Dict[str, Any]:
    if not consent:
        return {"ok": False, "error": "consent=true required (explicit operator confirmation)."}
    if not is_rfc1918_target(url):
        return {"ok": False, "error": "SSRF guard: firmware URL must be RFC1918 LAN host only."}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetPulse/4.5-FirmwareAudit"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            blob = resp.read(_MAX_FIRMWARE_BYTES + 1)
        if len(blob) > _MAX_FIRMWARE_BYTES:
            return {"ok": False, "error": "firmware exceeds 30MB cap"}
        return analyze_firmware(blob)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}
