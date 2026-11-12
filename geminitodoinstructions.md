# geminitodoinstructions — Netwide: Making It Truly Groundbreaking

*Netwide v4.5.0 — Sovereign Network Intelligence, 10-Stage 802.11 TSF De-Cloaking, Cryptographic Protocol Auditing, Wire DPI & Active Countermeasures*

> Not another scanner. A local-first atlas that proves what everything on your network *is*, *where it is*, *what it can do to you*, and *how to undo it* — with evidence.

---

## 1. TL;DR — The Bet

Fing, Lansweeper, and WiFi analyzers list `IP -> MAC -> vendor`. Netwide wins by fusing **identity + proof + physics + action** into verdicts:

1. **Identity Graph** across 802.11 / BLE / Wired / Cloud with provenance
2. **Threat Field** — Boltzmann-ranked hypotheses, not raw findings
3. **Cyber-Physical walk** — AR + RF to room-level attribution
4. **Forensic trust + Control** — hash-chained ledger, UNDO, firmware CVE, mesh federation

If those four ship, no consumer competitor can copy it in 3 months.

---

## 2. Where We Already Are (Moat Seeds)

| Area | Status in Code |
|------|----------------|
| 47K OUI + LAA/EUI-64 de-masking | Done (`oui.py`) |
| SSH HASSH, SMB2/3 NTLM-relay, DNSSEC/DoT, NTP CVE-2013-5211 | Done (`probers.py`) |
| 10-Stage De-Cloaker, TSF, QBSS, WPS, MLO, RSSI covariance, channel optimizer | Done, but blind — see P0 (`wireless.py`) |
| Mobile Geiger Finder + dual-node triangulation | Done (`wireless.py`, `server.py` `/api/mobile/telemetry`) |
| DPI: JA3, DHCP PRL, p0f, DNS/mDNS/TLS, ARP anomalies | Done (`probers.py:PassiveWireSniffer`) |
| Control: Roku, Cast, Sonos, Hue, Kasa, Shelly, MQTT, Docker, TMO 5G, quarantine | Done (tier-gated in `server.py`) |
| Boltzmann Hypothesis Engine | MVP done (`intel_hypotheses.py`, `GET /api/hypotheses`) |
| Hash-chained ledger, quarantine ledger entries | Done (`database.py:events_ledger`, `GET /api/ledger`) |
| Billing: 3-tier, NP1 licenses, Stripe, trials | Done, with flaws (`billing.py`) |
| CLI `scan/watch/wifi`, Desktop PyQt6, Mobile `mobile.html` + APK | Done (`cli.py`, `desktop.py`, `static/`) |

We are not starting from zero. We are starting from a broad surface with broken load-bearing parsers.

---

## 3. The 5 Pillars — What Actually Makes It Groundbreaking

### Pillar 1: Identity Graph + Provenance (Differentiator #1)

**Problem:** Every competitor shows a flat list. Confidence scores are numbers without traceable evidence.

**Build:**

- **Unified graph:** `graph_nodes(node_id, kind, attrs_json)` where kind = `network_device | cellular_modem | bt_device | zigbee_node | matter_node`; `graph_edges(src, dst, relation, weight, confidence, evidence_id)` where relation = `same_radio | talks_to | masquerades_as | controls | observed_by`. PageRank centrality to find hubs. `GET /api/graph?format=json|graphviz` (SVG via graphviz).
- **BLE Census — Stage 11:** New `ble_census.py`. Parse Apple Manufacturer `0x004C` (0x01 iPhone, 0x07 Watch, 0x0F Mac, 0x05 AirPods/AirTag), AWDL/AirDrop beacons. Correlate to LAN via RSSI proximity + 10-min cadence correlation + OUI. Emission: `DeviceProfile.ble_identity`. Score: `0.5*proximity + 0.3*cadence + 0.2*OUI_like`.
- **Hidden-tether classifier — Stage 12:** `classify_hidden_tether(ap)` → `{is_personal_hotspot, hotspot_score 0..1}` from 65/130/260 Mbit/s rate profile + LAA `first_octet & 0x02`. UI badge: phone-tether icon.
- **Passive wideband census — Stage 13:** Monitor-mode dwell cyclist, 0.1s/channel + DFS when allowed, management frames only. Ring table `passive_frames(timestamp, freq, frame_type, bssid, rssi, len, raw_hash)` capped 500k rows. This sees stealthy APs active probing never will. Biggest coverage win.
- **Evidence layer:** `evidence(claim_id, device_key, kind, ref_json, captured_at, sha256, confidence_influence)`. `GET /api/device/{key}/evidence`. Every claim (identity, botnet, de-cloak) links to ≥1 row. Hover any badge = why-this-verdict.

**Why it wins:** Fing has no BLE, no RF covariance, no provenance. This turns Netwide from labeler into auditor.

### Pillar 2: Intelligence Loop — Threat Field + Adaptive Scanning

**Problem:** Raw findings with no prioritization. Every scan runs 3,500 lines brute-force regardless of network persona.

**Build:**

- **Threat-Field engine (S2.1 → S2.2):** Existing `generate_hypotheses()` does `probability = exp(-E_uncertainty/kT)`, `impact = 0.35+0.45*severity_energy+0.20*risk`, rank by `probability*impact`. Add single asyncio loop every 5s: pull new evidence → collapse per-device field → rank → `/ws` broadcast + store. New table `hypotheses`. UI: Hypotheses tab sorted by expected value.
- **Adaptive scan tuner (S2.3):** UCB1 bandit over `{channel_dwell_ms, probe_order[], thread_pool, timeout_ms, prober_enablement[], passive_duty}` keyed by `{tv, mobile, IoT, gateway, mesh, WAN}`. Reward = Δ confirmed identity confidence / wall-second, minus FP penalty. Surrogate L-BFGS-B for continuous knobs when >25 samples. Persist `scan_strategy(env_fingerprint, params_json, ucb1_stats)`. Flag `--adaptive on|off` (default ON Pro+).
- **AI copilot, confirm-gated:** `POST /api/explain {device_key, question}` → tempered English + suggested command. Requires `/permissions/confirm` to run. Tenacity retry + asyncio timeout + JSON validate. Token budget per user. Never auto-execute. Tier: Pro+.

**Why it wins:** Cheaper + smarter sweeps, plain-language answers, no auto-execution risk.

### Pillar 3: Cyber-Physical Walk (Signature Demo)

**Problem:** RF locates to ~meters. Nobody in consumer does room-level.

**Build:**

- **AR fusion (S1.15 / S6.1):** Extend `/api/mobile/telemetry` with `ar_fusion_frame{motion_vector, landmark_id, anchor_confidence}` from phone camera optical flow. Server keeps `room_estimate{room_label, anchor_confidence, seen_at}`. HUD: "you are heading toward the decoy AP". Desktop map tab shows physical heatmaps. Privacy opt-in only.
- **One-tap sweep (S6.3):** Walk room, sweep all: BLE + passive RF + AR fused in 60s. Use RSSI/magnetometer/azimuth already in `mobile_telemetry_hub`.
- **Counter-surveillance (already at `server.py` camera-sweep):** ONVIF WS-discovery + RTSP scan + camera-OUI + TSF attribution. Keep as hero feature for Enterprise.

**Why it wins:** Physical attribution is the founder demo moment.

### Pillar 4: Forensic Trust + Real Control

**Problem:** "Forensic dossier export" is marketing until it's chain-of-custody, undoable, and enforceable.

**Build:**

- **Firmware exposure pillar (S4):** Parse UPnP `descDeviceURL` / vendor HTTP for firmware URLs → fetch RFC1918-only, SSRF-whitelist, 30MB cap, consent prompt → binwalk/LIEF/entropy/strings → exact-version CVE hints → per-device `firmware{hash, version, cvelist[], entropy_findings}`. Endpoint `POST /api/action/firmware-audit`. Enterprise tier. Read-only, journalized.
- **Action journal with UNDO (S3.2):** `actions(id, initiated_by, kind, command_json, inverse_json, status, started_at, completed_at, result)`. One-click undo, auto-undo on failure.
- **Ledger hardening (S3.1):** Already `events_ledger` immutable via triggers. Add `/api/ledger/verify` recompute, snapshot retention (fix `server.py` export writes to `~/Desktop` with no retention).
- **Operator modes:** ARP-spoof vigilance → warn WS → quarantine (existing engine) → optional gateway rebind. Rogue-DHCP/captive-portal detection (fix `wireless.py:2887` first). DNS sinkhole (`/api/net/dns/sinkhole`, dnsmasq / OpenWrt / per-device proxy). OpenWrt `ubus` enforcement: firewall CRUD, MAC allowlist, shaping — with allowlist of supported builds. Fallback to warning-only elsewhere.
- **Mesh federation (S1.16 + S3.7):** Signed spore capsule `{version, sender_id, snap_ts, nodes[], edges[], signature}` via `POST /api/graph/spore`. Merge: latest `snap_ts` wins per key, edges take-max confidence. Raft-style leader election on UDP 8766: partition by `hash(device_key)%quorum`. One planetary atlas across subnets/VLANs. Enterprise tier (up to 25 nodes).

**Why it wins:** Local-first, offline, sovereign, exportable to Prometheus (`/api/metrics`) + Kibana ndjson + Graphviz SVG.

### Pillar 5: Information Density is the Product

- **Enriched profile fields:** JA4+/QUIC, DNS query mix, cloud beacons `{domain, ASN, country, cadence}`, BLE identity, Thread/Matter/Zigbee role, hotspot probability, firmware exposure, risk pipeline from hypotheses. Per-device ribbon of badges, hover = provenance.
- **Daily/weekly posture diff digest:** Diff `EngineState` snapshots → WS/email `{changed_devices, new_threats, resolved_threats, posture_delta, top_hypotheses}`. Drives retention ("news feed" angle).
- **Detection-rule compiler (P3):** Netwide DSL (JSON) → compiled probers with vuln-regex audit + SHA-256 manifest → shipped as Enterprise add-ons. Dockerized tests.

---

## 4. P0 Killers — Fix Before Anything Else (from `worktodo.txt`)

These block every later layer. Intelligence starves on broken parsers.

1. **De-cloaker blind:** `parse_iw_scan_dump() wireless.py:58-64` splits on `^BSS ` then `split("(")[0]` → `"BSS 00:11..."` fails len check → empty AP list. Fix: `re.match(r"BSS\s+([0-9A-Fa-f:]{17})")`. Golden fixture of real `iw dev scan dump`.
2. **Stage-3 verdict precedence:** `wireless.py:736-737` `(A+B) if C else D` → verdict becomes `")"` when no parent. Use explicit branch. Test `startswith(("VERIFIED_","IDENTIFIED_"))` for `server.py:1117`.
3. **Stage-7/8 MAC:** `bssid[3:8]` is char slice, not octet. Build from `bssid.split(":")`. Same for `[ :5]`, `[12:]` — normalize once to octet tuples + `same_unmasked_oui()` helper.
4. **MQTT CONNACK:** `probers.py:2241` reads `resp[3]`, should be `resp[2]` (byte0=0x20 type, byte1=flags, byte2=RC). Test vectors: `20 02 00` anon-allowed, `20 02 05` denied. 5.0 adds property-length after RC — don't misread.
5. **Key drift probers↔fingerprint:** `ollama_ai→ollama`, Sonos camelCase→snake_case, Hue keys, `anonymous_allowed→auth_status`, `security_mode` never populated. Fix: new `netwide/profile_keys.py` typed dict shared by both. Unit test shape.
6. **nmcli SIGNAL scale:** `wireless.py:265` treats dBm as 0-100%. Add `signal_to_dbm(raw)`: if ≤-30 treat as dBm, 0-100 → `(pct/2)-100`, else reject.
7. **Hardening:** `_require_tier("forensic_export")` on `GET /api/export/csv`, admin auth on `/api/subscription/deactivate`, CORS allowlist (already patched to env regex — keep), move sync DB to `asyncio.to_thread`, close SQLite conns in `billing.py`, full HMAC tag (not 18-byte truncate), fail-closed webhook, reject `no_payment_required`, enforce `trial_claimed` in lead path + `max_nodes`, rate limiting, TrustedHost, HSTS/CSP, request size cap.
8. **Subprocess + except policy:** `netwide/proc.py` `run_with_timeout(cmd, 5.0)` wrapper everywhere; `PassiveWireSniffer.stop()` terminate→wait(2)→kill→reap. Blanket `except: pass` only in cosmetic paths; decision loops log + surface `probe_status`.

**Effort: S (days). Do not skip.**

---

## 5. Roadmap

| Phase | What | Effort | Depends On |
|-------|------|--------|------------|
| **P0** | S0.1–S0.10 parser + hardening fixes | S (days) | — |
| **P1** | Hypotheses UI + evidence + BLE Stage 11 + passive Stage 13 + tether Stage 12 + ledger verify + profile enrichment + posture digest | M (1-2 wks) | P0 |
| **P2** | Bandit tuner + firmware pillar + spore mesh + copilot + ARP/DHCP defense + identity graph + Prometheus | M-L (3-4 wks) | P1 |
| **P3** | AR walk + OpenWrt ubus fleet + detection-rule compiler + Kibana export | L | P2 |

### Demo That Proves Groundbreaking

Walk a room with phone. HUD shows 3 hidden APs decloaked as `T-Mobile VAP` vs `Personal iPhone hotspot (p=0.91)` vs `Unattributed (Ch6, -52dBm, room: Office, anchor 0.87)`. Tap one → packet + TSF + BLE evidence chain. Tap fix → quarantine + UNDO + ledger hash. That's not a scanner. That's an atlas with chain-of-custody.

### Metrics to Track

- Identity resolution rate (devices correctly attributed / total)
- Provenance coverage (% claims with ≥1 evidence row)
- Scan cost: median scan seconds vs baseline brute-force
- MTTR: observed → hypothesis → action → UNDO availability
- Coverage: passive-only APs found that active missed

### Security / Legal Notes

- **PMKID/Evil-twin (Stage 14):** capture hash only, explicit opt-in + legal note, Enterprise tier, never default-on. Banner: "Only scan networks you own or have permission to test."
- **SSRF safety:** deep-nmap, http-probe, gateway creds, SSDP Location fetch — RFC1918-only, allowlist + content-type checks.
- **Billing:** fail-closed, no default secret, full tag, proper revocation (`customer.subscription.deleted`).

### Positioning vs Competitors

|  | Fing | Wireshark | Lansweeper | Netwide |
|---|---|---|---|---|
| Consumer simple | ✓ | ✗ | ✗ | ✓ |
| Forensic deep | ✗ | ✓ | ~ | ✓ |
| RF + BLE + Physical | ✗ | ✗ | ✗ | ✓ |
| Local-first / Sovereign | cloud | local | cloud | local SQLite |
| Action + Undo + Ledger | ✗ | ✗ | ~ | ✓ |

> **Rule:** Don't add more probers until P0 is green. Add proof, physics, and undo to every verdict. Information density per device is the moat.

---

## 6. Next Actions for Agent / Implementer

1. Fix S0.1–S0.8 with golden fixtures + `profile_keys.py` + `proc.py`.
2. Ship `GET /api/hypotheses` UI + `GET /api/device/{key}/evidence` + ledger verify button.
3. Add `ble_census.py` (Stage 11) + `classify_hidden_tether` (Stage 12) + passive ring buffer (Stage 13).
4. Add `graph_nodes/edges` + `GET /api/graph` + digest generator.
5. Prototype AR fusion frame + spore capsule sync on two nodes.

*Generated from codebase review (`server.py`, `wireless.py`, `probers.py`, `fingerprint.py`, `database.py`, `intel_hypotheses.py`) + `worktodo.txt` §1–§3.*
