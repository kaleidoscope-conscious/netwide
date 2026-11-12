"""Passive-only wideband census (Stage 13 dwell schedule).

Active probing misses stealthy APs that never answer. This module is the
pure planning + accounting layer: dwell schedule per band, budget math,
and recent-frame summary helpers. Actual capture is the existing
PassiveWireSniffer (tshark) sampled into passive_frames.
"""
from __future__ import annotations

from typing import Any, Dict, List

BANDS: Dict[str, Dict[str, Any]] = {
    "2.4G": {"channels": [1, 6, 11], "dwell_ms": 100, "note": "1/6/11 non-overlapping"},
    "5G": {"channels": [36, 44, 149, 161], "dwell_ms": 100, "note": "UHNI subset"},
    "6G": {"channels": [5, 21], "dwell_ms": 80, "note": "Wi-Fi 6E/7 (where allowed)"},
}

def dwell_schedule(budget_seconds: float = 10.0, include_6g: bool = True) -> List[Dict[str, Any]]:
    bands = {k: v for k, v in BANDS.items() if k != "6G" or include_6g}
    total_channels = sum(len(v["channels"]) for v in bands.values())
    dwell_ms = max(40, min(200, int(budget_seconds * 1000 / max(1, total_channels))))
    rows: List[Dict[str, Any]] = []
    for band, cfg in bands.items():
        for ch in cfg["channels"]:
            rows.append({"band": band, "channel": ch, "dwell_ms": dwell_ms, "dwell_s": round(dwell_ms / 1000, 3)})
    return rows

def coverage_budget(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_s = round(sum(r.get("dwell_s", 0) for r in rows), 2)
    return {"channels": len(rows), "total_dwell_s": total_s, "bands": BANDS}
