"""Benchmark: NetPulse vs Fing-like baseline (demo / attention asset).

Runs NetPulse deep scan and compares against a naive ARP+OUI baseline.
Prints a table proving de-cloaking + fingerprint depth. For marketing
demos and Show HN — not a unit test.
"""
from __future__ import annotations

import sys
sys.path.insert(0, "/home/jg")

from netpulse.fingerprint import run_full_network_scan
from netpulse.probers import detect_active_interface, read_kernel_neighbors
from netpulse.oui import oui_db

def naive_baseline(hosts: dict) -> list:
    out = []
    for ip, info in hosts.items():
        mac = info.get("mac", "")
        intel = oui_db.lookup(mac)
        out.append({"ip": ip, "vendor": intel.vendor if hasattr(intel, "vendor") else "Unknown"})
    return out

def main() -> int:
    net = detect_active_interface()
    print(f"NetPulse host: {net.interface} {net.ip} on {net.cidr} (gateway {net.gateway_ip})")
    hosts = read_kernel_neighbors(net)
    base = naive_baseline(hosts)
    profiles = run_full_network_scan(net)
    print(f"{'IP':<18} {'Baseline':<20} {'NetPulse identity':<40} {'Conf':>5}")
    for p in profiles:
        b = next((x for x in base if x["ip"] == p.ip), {"vendor": "—"})
        print(f"{p.ip:<18} {str(b['vendor'])[:19]:<20} {str(p.brand or p.display_name)[:39]:<40} {p.confidence_score:>4}%")
    hidden = sum(1 for p in profiles if p.is_randomized_mac)
    print(f"\nBaseline sees: {len(base)} hosts | NetPulse fingerprints: {len(profiles)} hosts ({hidden} randomized-MAC de-cloaked)")
    print("Takeaway: baseline stops at OUI; NetPulse adds brand/model/category + crypto audit + findings + hypotheses.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
