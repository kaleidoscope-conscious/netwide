# NetPulse // OmniSight — 30-Second Demo Script

**Story:** *Apple randomizes your MAC to hide you. NetPulse sees through it — and shows you the packet that proves it.*

Audience: Hacker News `Show HN`, r/Privacy, YouTube (NetworkChuck-style), TikTok/Reels.

## 0:00–0:05 — Hook
Walk into a room with phone in Geiger mode. `netpulse serve` on Pi/laptop, `/mobile` on phone. Say:
> "Your phone randomizes its MAC per Wi-Fi — so tools like Fing go blind. Ours doesn't."

## 0:05–0:15 — De-cloak
Scan. Show Hidden Wi-Fi tab: a hidden AP decloaked as `Personal iPhone hotspot (p=0.91)` via Stage-11 BLE + Stage-12 rate profile + Stage-10 TSF Pearson `r>=0.85`. Tap Evidence → packet/TSF rows.

## 0:15–0:22 — Verdict
Hero bar: `92/100 All good` or `58/100 Fix now — Anonymous MQTT`. Tap `Why?` → plain-English + confirm-gated fix. Nothing auto-executes.

## 0:22–0:30 — Control + proof
Open device → Control → quarantine. Show Undo (`/api/actions` → undo) + ledger `CHAIN_INTEGRITY_VERIFIED`. Close:
> "Local-only. No cloud. Every verdict has proof."

## Checklist
- `python -m netpulse scan` (CLI) vs `scripts/benchmark_vs_fing.py` (baseline vs deep)
- `netpulse graph` / `ble` / `passive` / `metrics` / `digest` for advanced cuts
- Endpoints for b-roll: `/api/rf-geiger?bssid=`, `/api/graph`, `/api/threat-field`, `/api/passive/census`

## Anti-demo (don't show)
- 7 expert tabs, TSF/QBSS/HASSH jargon, ports tables — that's Expert view, not the hook.
