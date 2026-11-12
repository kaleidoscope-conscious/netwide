"""BLE Continuity & AirDrop attribution census (De-Claoker Stage 11).

No BLE decode existed before this module — scan_bluetooth_radar only
listed paired devices via bluetoothctl. This module adds:

- Apple Manufacturer Data (0x004C) Continuity parsing
- Hidden-tether / phone-hotspot radio heuristic (Stage 12 overlap)
- Passive phone-sensor fusion stub for the walk-around path

Data model is intentionally small and testable without BLE hardware:
golden byte fixtures + correlation helpers are pure functions.
"""
from __future__ import annotations

import subprocess
import time
from typing import Any, Dict, List

# Apple Continuity activity flag -> device type (byte 1 after Company ID LE 4C 00)
APPLE_CONTINUITY_TYPES: Dict[int, str] = {
    0x01: "iPhone",
    0x02: "iPad",
    0x03: "Mac",
    0x05: "AirPods",
    0x07: "Watch",
    0x09: "HomePod",
    0x0B: "Apple TV",
    0x0F: "Mac (Continuity)",
    0x13: "Vision Pro",
    0x14: "AirTag",
}

def parse_apple_continuity(payload: bytes) -> Dict[str, Any]:
    """Parse Apple manufacturer data payload.

    Expects payload starting with Company ID LE 0x004C (4C 00) followed
    by a Continuity header. Returns empty dict on non-Apple payloads.
    """
    if len(payload) < 4 or payload[0] != 0x4C or payload[1] != 0x00:
        return {}
    body = payload[2:]
    if len(body) < 2:
        return {"apple": True, "continuity_type": "Unknown", "raw_hex": payload.hex()}
    ctype = body[0]
    # body[1] is activity/flags
    return {
        "apple": True,
        "continuity_type": APPLE_CONTINUITY_TYPES.get(ctype, f"Unknown (0x{ctype:02X})"),
        "continuity_code": ctype,
        "activity": body[1],
        "raw_hex": payload.hex(),
        "airdrop_capable": ctype in (0x01, 0x03, 0x0F),
    }

def parse_ble_advertisement(addr: str, rssi: int, mfg_payload: bytes) -> Dict[str, Any]:
    out = {"addr": addr.upper(), "rssi": rssi, "seen_at": time.time()}
    apple = parse_apple_continuity(mfg_payload) if mfg_payload else {}
    if apple:
        out["ble_identity"] = apple
        out["vendor"] = "Apple"
    else:
        out["vendor"] = "Unknown BLE"
    return out

def correlate_ble_to_lan(
    ble_devices: List[Dict[str, Any]],
    lan_devices: List[Dict[str, Any]],
    proximity_db_window: float = 8.0,
) -> List[Dict[str, Any]]:
    """Correlate BLE identities to LAN devices by OUI + cadence proximity.

    Pure function — no I/O. Scoring:
      confidence = 0.5*proximity + 0.3*cadence + 0.2*oui_like
    Cadence is approximated from overlapping seen_at windows.
    """
    out: List[Dict[str, Any]] = []
    for ble in ble_devices or []:
        apple = ble.get("ble_identity") or {}
        ctype = apple.get("continuity_type", "")
        vendor = ble.get("vendor", "")
        for lan in lan_devices or []:
            mac = (lan.get("mac") or "").upper()
            # OUI heuristic: Apple OUIs share 00:1A:2B / 3C:07:54 / F4:F5:D8
            oui_like = 0.0
            if vendor == "Apple" and mac:
                oui = mac.replace(":", "")[:6].upper()
                if oui in ("001A2B", "3C0754", "F4F5D8", "D0D45C", "701E65"):
                    oui_like = 1.0
                elif lan.get("brand", "").lower().startswith("apple"):
                    oui_like = 0.7
            if oui_like <= 0:
                continue
            lan_rssi = float(lan.get("signal_dbm") or lan.get("rssi") or -75.0)
            ble_rssi = float(ble.get("rssi", -75.0))
            rssi_diff = abs(ble_rssi - lan_rssi)
            if rssi_diff <= proximity_db_window:
                proximity = 1.0
            elif abs(float(ble.get("rssi", -90)) - float(lan.get("rtt_ms") or 0)) < 60:
                proximity = max(0.6, round(1.0 - (rssi_diff / 50.0), 2))
            else:
                proximity = 0.6
            cadence = 0.5  # placeholder until time-series wired
            confidence = round(0.5 * proximity + 0.3 * cadence + 0.2 * oui_like, 3)
            out.append({
                "ble_addr": ble.get("addr"),
                "lan_device_key": lan.get("device_key") or mac,
                "lan_ip": lan.get("ip"),
                "continuity_type": ctype,
                "confidence": confidence,
                "stage": 11,
            })
    return out

def scan_ble_census(timeout: float = 4.0) -> Dict[str, Any]:
    """Best-effort BLE scan. Gracefully degrades without hardware/bluez."""
    devices: List[Dict[str, Any]] = []
    backend = "unavailable"
    try:
        res = subprocess.run(
            ["bluetoothctl", "--timeout", str(int(timeout)), "scan", "on"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        backend = "bluetoothctl"
        for line in (res.stdout or "").splitlines():
            if "Device" in line and len(line.split()) >= 3:
                parts = line.split(None, 2)
                mac = parts[1] if len(parts) > 1 else ""
                name = parts[2] if len(parts) > 2 else "BLE Device"
                if len(mac) == 17:
                    devices.append({"addr": mac.upper(), "name": name, "vendor": "Unknown BLE"})
    except FileNotFoundError:
        backend = "unavailable"
    except Exception:
        backend = "error"
    # Always stop scan to leave radio clean
    try:
        subprocess.run(["bluetoothctl", "scan", "off"], capture_output=True, timeout=2.0)
    except Exception:
        pass
    return {"ok": True, "devices": devices, "count": len(devices), "backend": backend, "stage": 11}

def classify_hidden_tether(ap: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 12 rate-profile classifier (pure, testable)."""
    score = 0.10
    bssid = str(ap.get("bssid") or "")
    if bssid and len(bssid) == 17:
        try:
            b0 = int(bssid[:2], 16)
            if b0 & 0x02:
                score += 0.30
        except ValueError:
            pass
    raw_rate = ap.get("rate_mbps") or ap.get("rate") or 0
    rate = 0.0
    if isinstance(raw_rate, (int, float)):
        rate = float(raw_rate)
    else:
        txt = str(raw_rate).lower().strip()
        if txt:
            import re as _re
            m = _re.search(r"([0-9.]+)", txt)
            if m:
                try:
                    rate = float(m.group(1))
                except ValueError:
                    rate = 0.0
    if 0 < rate <= 130:
        score += 0.15
    try:
        dbm = float(ap.get("signal_dbm") or -90)
    except (TypeError, ValueError):
        dbm = -90.0
    if dbm >= -60:
        score += 0.15
    sec = str(ap.get("security") or "").upper()
    if "OPEN" in sec:
        score += 0.10
    elif "PSK" in sec or "WPA" in sec:
        score += 0.05
    score = round(min(0.95, score), 2)
    return {
        "is_personal_hotspot": score >= 0.55,
        "hotspot_score": score,
        "hotspot_probability": score,
        "stage": 12,
    }
