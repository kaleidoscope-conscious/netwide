"""Prometheus exposition + posture diff helpers (pure, testable)."""
from __future__ import annotations

from typing import Any, Dict, List

def prometheus_text(state_snapshot: Dict[str, Any]) -> str:
    meta = state_snapshot.get("meta") or {}
    devices = state_snapshot.get("devices") or []
    threats = state_snapshot.get("threats") or []
    hyps = state_snapshot.get("hypotheses_top") or []
    lines: List[str] = []
    lines.append("# HELP netpulse_devices_total Total discovered LAN devices")
    lines.append("# TYPE netpulse_devices_total gauge")
    lines.append(f"netpulse_devices_total {meta.get('total_devices', len(devices))}")
    lines.append("# HELP netpulse_devices_online Online devices")
    lines.append("# TYPE netpulse_devices_online gauge")
    lines.append(f"netpulse_devices_online {meta.get('online_devices', 0)}")
    lines.append("# HELP netpulse_security_score Security posture 0-100")
    lines.append("# TYPE netpulse_security_score gauge")
    lines.append(f"netpulse_security_score {meta.get('security_score', 0)}")
    lines.append("# HELP netpulse_threats_total Active threats")
    lines.append("# TYPE netpulse_threats_total gauge")
    lines.append(f"netpulse_threats_total {len(threats)}")
    lines.append("# HELP netpulse_hypotheses_top Highest expected-value hypotheses")
    lines.append("# TYPE netpulse_hypotheses_top gauge")
    lines.append(f"netpulse_hypotheses_top {state_snapshot.get('hypotheses_total', len(hyps))}")
    lines.append("# HELP netpulse_high_risk_devices Devices with CRITICAL/HIGH findings")
    lines.append("# TYPE netpulse_high_risk_devices gauge")
    lines.append(f"netpulse_high_risk_devices {meta.get('high_risk_devices', 0)}")
    lines.append("# HELP netpulse_scan_total Lifetime scans")
    lines.append("# TYPE netpulse_scan_total counter")
    lines.append(f"netpulse_scan_total {meta.get('scan_count', 0)}")
    # Wave-5 extensions (defensive .get — absent on old snapshots)
    lines.append("# HELP netpulse_graph_nodes Identity graph nodes")
    lines.append("# TYPE netpulse_graph_nodes gauge")
    lines.append(f"netpulse_graph_nodes {state_snapshot.get('graph_nodes', 0)}")
    lines.append("# HELP netpulse_graph_edges Identity graph edges")
    lines.append("# TYPE netpulse_graph_edges gauge")
    lines.append(f"netpulse_graph_edges {state_snapshot.get('graph_edges', 0)}")
    lines.append("# HELP netpulse_quarantined_active Actively quarantined hosts")
    lines.append("# TYPE netpulse_quarantined_active gauge")
    lines.append(f"netpulse_quarantined_active {state_snapshot.get('quarantined_active', 0)}")
    lines.append("# HELP netpulse_sinkhole_rules Enabled DNS sinkhole rules")
    lines.append("# TYPE netpulse_sinkhole_rules gauge")
    lines.append(f"netpulse_sinkhole_rules {state_snapshot.get('sinkhole_rules', 0)}")
    lines.append("# HELP netpulse_passive_frames Passive census frames (ring size)")
    lines.append("# TYPE netpulse_passive_frames gauge")
    lines.append(f"netpulse_passive_frames {state_snapshot.get('passive_frames', 0)}")
    return "\n".join(lines) + "\n"

def posture_diff(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    b_devices = {str(d.get("device_key") or d.get("mac") or d.get("ip")) for d in (before.get("devices") or [])}
    a_devices = {str(d.get("device_key") or d.get("mac") or d.get("ip")) for d in (after.get("devices") or [])}
    b_threats = {(t.get("category") or "") + ":" + (t.get("title") or "")[:80] for t in (before.get("threats") or [])}
    a_threats = {(t.get("category") or "") + ":" + (t.get("title") or "")[:80] for t in (after.get("threats") or [])}
    return {
        "changed_devices_new": sorted(a_devices - b_devices),
        "changed_devices_gone": sorted(b_devices - a_devices),
        "new_threats": sorted(a_threats - b_threats),
        "resolved_threats": sorted(b_threats - a_threats),
        "posture_delta": int((after.get("meta") or {}).get("security_score", 0)) - int((before.get("meta") or {}).get("security_score", 0)),
        "scan_count_delta": int((after.get("meta") or {}).get("scan_count", 0)) - int((before.get("meta") or {}).get("scan_count", 0)),
    }
