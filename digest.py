"""Daily/weekly posture diff digest (news-feed angle)."""
from __future__ import annotations

from typing import Any, Dict

def build_digest(diff: Dict[str, Any] | None, hypotheses: list | None, posture: Dict[str, Any] | None) -> Dict[str, Any]:
    diff = diff or {}
    posture = posture or {}
    hyps = hypotheses or []
    top = hyps[:5]
    lines = [
        f"Posture {posture.get('score', '?')}/100 (was delta {diff.get('posture_delta', 0):+d})",
        f"New devices: {len(diff.get('changed_devices_new', []))}  Gone: {len(diff.get('changed_devices_gone', []))}",
        f"New threats: {len(diff.get('new_threats', []))}  Resolved: {len(diff.get('resolved_threats', []))}",
        f"Scans delta: {diff.get('scan_count_delta', 0)}",
    ]
    for h in top:
        lines.append(f"- [{h.get('severity')}] {h.get('title')} (EV {h.get('expected_value')})")
    return {
        "ok": True,
        "summary_lines": lines,
        "text": "\n".join(lines),
        "top_hypotheses": top,
        "diff": diff,
        "posture": posture,
    }
