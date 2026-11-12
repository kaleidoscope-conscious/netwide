"""Cyber-physical AR fusion helpers (room attribution, no hardware required).

Fuses handset RSSI + magnetometer + azimuth into a room-level estimate.
Pure functions — camera optical flow is supplied by the native APK via
/mobile/telemetry -> ar_fusion_frame when present.
"""
from __future__ import annotations

from typing import Any, Dict

def fuse_rssi_mag(rssi_dbm: float, mag_ut: float, azimuth_deg: float, all_aps: list | None = None) -> Dict[str, Any]:
    """Estimate room + confidence from a single reading.

    Heuristic: -55 dBm ≈ same-room, -70 ≈ same-floor, else adjacent/fringe.
    Magnetic anomaly |mag|>70 uT suggests near large metal (kitchen/office).
    Azimuth is echoed for HUD heading.
    """
    try:
        r = float(rssi_dbm)
    except Exception:
        r = -90.0
    try:
        mag = float(mag_ut or 0.0)
    except Exception:
        mag = 0.0
    try:
        az = float(azimuth_deg or 0.0) % 360.0
    except Exception:
        az = 0.0
    if r >= -56:
        room, conf = "Same Room (likely)", 0.87
    elif r >= -70:
        room, conf = "Same Floor", 0.68
    elif r >= -82:
        room, conf = "Adjacent Unit", 0.52
    else:
        room, conf = "Fringe / Far", 0.34
    if abs(mag) > 70:
        room += " • metal anomaly"
        conf = round(min(0.95, conf + 0.05), 2)
    # Closest AP among provided list boosts confidence
    closest_dbm = r
    if all_aps:
        try:
            best = max(float(a.get("signal_dbm") or -100) for a in all_aps)
            if best >= r:
                closest_dbm = best
        except Exception:
            pass
    return {
        "room_estimate": room,
        "anchor_confidence": conf,
        "rssi_dbm": round(r, 1),
        "closest_rssi_dbm": round(closest_dbm, 1),
        "mag_ut": round(mag, 1),
        "azimuth_deg": round(az, 1),
        "heading_hint": _heading_hint(az),
        "stage": 15,
    }

def _heading_hint(az: float) -> str:
    dirs = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
    return dirs[int((az + 22.5) // 45) % 8]

def room_for_device(bssid: str, aps: list | None, mag_ut: float = 0.0, azimuth_deg: float = 0.0) -> Dict[str, Any]:
    target = (bssid or "").upper()
    ap = next((a for a in (aps or []) if str(a.get("bssid") or "").upper() == target), None)
    if not ap:
        return {"bssid": target, "found": False}
    fused = fuse_rssi_mag(float(ap.get("signal_dbm") or -90), mag_ut, azimuth_deg, aps)
    return {"bssid": target, "found": True, "ssid": ap.get("de_cloaked_ssid") or ap.get("ssid") or "<Hidden>", **fused}
