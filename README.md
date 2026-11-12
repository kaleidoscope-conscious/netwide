# NetPulse v4.5.0

[![Release v4.5.0](https://img.shields.io/badge/release-v4.5.0-10b981?style=for-the-badge)](https://github.com/kaleidoscopeAI/netpulse/releases/tag/v4.5.0)
[![Android 15 APK](https://img.shields.io/badge/Android_15_(API_35)-Download_APK-0284c7?style=for-the-badge&logo=android)](https://github.com/kaleidoscopeAI/netpulse/releases/download/v4.5.0/NetPulse-Mobile-v4.5.0.apk)
[![Storefront & Pricing](https://img.shields.io/badge/Storefront-Founder's_Lifetime_%24149-7c3aed?style=for-the-badge)](https://kaleidoscopeai.github.io/netpulse/)
[![Tests](https://img.shields.io/badge/pytest-132%2F132_passing-34d399?style=for-the-badge)](https://github.com/kaleidoscopeAI/netpulse/actions)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor_♥-GitHub-db61fc?style=for-the-badge&logo=githubsponsors)](https://github.com/sponsors/kaleidoscopeAI)
[![Donate via PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/jgraham1000)

**Sovereign Network Intelligence, 10-Stage 802.11 TSF De-Cloaking, Cryptographic Protocol Auditing, Domain/WAN OSINT, Wire DPI, Autonomous Countermeasures & Commercial Subscription Suite**

- **Live Storefront & Documentation**: [https://kaleidoscopeai.github.io/netpulse/](https://kaleidoscopeai.github.io/netpulse/)
- **Signed Android 15 APK (v2+v3)**: [Download `NetPulse-Mobile-v4.5.0.apk`](https://github.com/kaleidoscopeAI/netpulse/releases/download/v4.5.0/NetPulse-Mobile-v4.5.0.apk)
- **Google Play Store Bundle (`.aab`)**: [Download `NetPulse-Mobile-PlayStore-v4.5.0.aab`](https://github.com/kaleidoscopeAI/netpulse/releases/download/v4.5.0/NetPulse-Mobile-PlayStore-v4.5.0.aab)

### ❤ Support NetPulse

Development is sovereign-funded by the community:

- **[Become a GitHub Sponsor](https://github.com/sponsors/kaleidoscopeAI)** — monthly/one-time, powered by GitHub
- **[Donate via PayPal](https://paypal.me/jgraham1000)** — one-time tip, any amount

![NetPulse Banner](play_store_assets/feature_graphic_1024x500.png)

---

## Quick Start (1-Line Install)

```bash
git clone https://github.com/kaleidoscopeAI/netpulse.git && cd netpulse && ./install.sh
```

Or launch directly with Python / Docker:
```bash
# Launch Sovereign Web Command Center + WebSocket Daemon (http://127.0.0.1:8765)
python3 -m netpulse serve --host 0.0.0.0 --port 8765

# Launch Native PyQt6 Desktop Command Center + System Tray Guardian
python3 -m netpulse desktop

# Or via Docker Compose (host networking)
docker compose up -d
```

---

## 1. Key Capabilities

### Deep LAN Fingerprinting, Binary Protocol & Cryptographic Intelligence
- **47,035+ IEEE OUI Hardware Database + LAA Virtual BSSID & IPv6 EUI-64 De-Masking**: Unmasks randomized LAA MAC addresses via SLAAC EUI-64 `FF:FE` bit-inversion, unmasks virtual mesh BSSIDs (`first_octet & 0xFD`) to their parent IEEE OUI, and provides instant full-text vendor/HQ/MAC/EUI-64 search (`/api/oui/search`, `netpulse oui <query>`).
- **Cryptographic & Transport Security Auditors**:
  - **SSHv2 Binary `KEXINIT` & HASSH Fingerprinting (`:22`)**: RFC 4253 binary parser extracting all 10 algorithm lists, computing the **Salesforce HASSH Server MD5 fingerprint**, detecting Post-Quantum Hybrid KEX (`sntrup761x25519-sha512`, `mlkem768x25519`), and grading cipher/KEX posture (`A+` to `C`).
  - **SMB2/SMB3 Binary `NEGOTIATE` Dialect & NTLM-Relay Auditor (`:445`)**: Pure-binary NetBIOS + `\xfeSMB` handshake inspector extracting negotiated dialect (`SMB 2.0.2`–`3.1.1`), Server GUID, capabilities (`ENCRYPTION`, `MULTI_CHANNEL`), and SMB Packet Signing enforcement (`ntlm_relay_vulnerable`).
  - **RFC 4035 DNSSEC & DoT (`:853`) Resolver Security Auditor (`:53/:853`)**: Audits recursive resolution (`RA`), DNSSEC Authenticated Data (`AD=1`) signature verification, Chaos `TXT version.bind` software leakage, and RFC 7858 DNS-over-TLS (`:853`) encryption.
  - **RFC 5905 NTPv4 Stratum, Reference Clock & CVE-2013-5211 Mode-6 Auditor (`:123`)**: Binary NTPv4 client + Mode-6 Control amplification inspector.
  - **Domain, DNS, SPF/DMARC & Live TLS `:443` X.509 OSINT Engine**: Inspects `A`/`AAAA`/`MX`/`NS`/`TXT`/`SPF`/`_dmarc`, X.509 certificate chains, and HTTP/3 (`Alt-Svc: h3`) security posture (`/api/action/domain-intel`, `netpulse domain <target>`).
  - **Local Workstation Socket & Process Inspector (`ss -tulnp`)**: Audits local listening daemons, PIDs, LAN-exposed vs. loopback bindings, and `/proc/net/dev` traffic counters (`/api/local/sockets`, `netpulse sockets`).
  - **UPnP IGD External NAT Port-Forwarding Auditor**: Queries gateway `WANIPConnection:1` SOAP `GetExternalIPAddress` and `GetGenericPortMappingEntry` to enumerate active WAN-to-LAN port forwards.
- **Multi-Protocol Active Probers & Controllers**:
  - **Smart TVs, Audio & Media**: Roku ECP (`:8060`), DIAL v2.1, Google Cast / Chromecast Eureka (`:8008`), Samsung Tizen (`:8001`), Apple AirPlay (`:7000`), **Sonos ZonePlayer UPnP SOAP AVTransport & Volume Controller (`:1400`)**, **Plex Media Server (`:32400/identity`)**, Spotify Connect ZeroConf.
  - **Smart Home, AI & Enterprise Infra**: Apple HomeKit (`_hap._tcp`), CSA Matter / Thread (`_matter._tcp`, `_meshcop._udp`), **Philips Hue Bridge (`:80/api/config`)**, TP-Link Kasa TCP `9999` Autokey XOR cipher, Shelly Gen1/2/3 HTTP relays, **OASIS MQTT v3.1.1 Anonymous Broker Auditor (`:1883`)**, **Ollama Local LLM AI Server (`:11434/api/tags`)**, **Unauthenticated Docker Engine API Detector (`:2375/version`)**, and ASN.1 BER SNMPv2c (`UDP 161`).
  - **Game Consoles & Gateways**: Sony PlayStation 4 / 5 DDP (`UDP 987 / 9302`) and T-Mobile 5G NR Gateway (`TMO-G4AR` `/TMI/v1/gateway` cellular telemetry).

### 10-Stage Universal Hidden Entity De-Cloaker, RF Channel Optimizer & Dual-Node Geiger Finder
- **10-Stage Universal De-Cloaker**: Correlates hidden 802.11 BSSIDs against visible parent routers using **64-bit microsecond hardware TSF clocks** (`nl80211`), 5-byte silicon MAC masks, QBSS load elements, 802.11k Reduced Neighbor Reports / MLO, and **Stage 10 Temporal Multipath RSSI Co-Variance (`Pearson r >= 0.85`)**.
- **Spectral Overlap Channel Optimizer**: Computes adjacent-channel interference scores across 2.4 GHz (Channels 1–11) and 5 GHz (Channels 36–165) to recommend optimal non-overlapping channels.
- **Mobile Walk-Around RF Geiger Counter & Dual-Node Triangulation (`/api/mobile/telemetry`)**: Fuses live Android handset Wi-Fi RSSI (with 802.11ax/be channel width & Wi-Fi 7/6/5 standard detection), 3-axis hardware Magnetometer (`µT`), and Compass Azimuth (`°`) with the stationary `wlo1` node, plus standalone on-phone 28-port TCP banner auditing and SSDP multicast discovery.

### Why-this-verdict, Identity Graph & Threat Field (new)
- **Provenance**: every identity + threat links to packets/evidence (`/api/device/{key}/evidence`, `Evidence` / `Why?` in UI). No black-box scores.
- **Identity Graph**: `graph_nodes / graph_edges` (`/api/graph`, `/api/graph/spore`, Kibana NDJSON) — `same_radio / talks_to / controls / observed_by` with confidence.
- **Threat Field**: Boltzmann hypotheses continuously collapsed (`/api/hypotheses`, `/api/threat-field`) — `EV = probability × impact`, coherence metric per device.
- **BLE Continuity Stage 11 + Tether Stage 12 + Passive Stage 13**: Apple `0x004C` decode, hotspot rate-profile, dwell-cycle census table `passive_frames` (`/api/ble/scan`, `/api/passive/census`).
- **Firmware exposure**: consent-gated, RFC1918-only, SSRF-safe (`/api/action/firmware-audit`) — binwalk sigs, entropy, version, CVE hints.
- **Adaptive scans**: UCB1 bandit learns which probers matter per network (`/api/scan-strategy`, `netpulse scan-strategy home`).
- **Copilot**: `POST /api/explain` — plain-English + suggested fix, `confirm_required=True, auto_executed=False`.
- **Control plane + UNDO**: `POST /api/control/{key}` maps `power/media/lighting/network` to Roku/Sonos/Kasa/gateway; every action journalized with inverse (`/api/actions`, `POST /api/actions/{id}/undo`).
- **Enforcement**: Guardian Shield quarantine attempts `iptables/nft` L3 DROP (RST fallback) + OpenWrt `ubus` (`/api/gateway/ubus/*`) + DNS sinkhole (`/api/net/dns/sinkhole`, dnsmasq drop-in preview).
- **Observability**: Prometheus (`/api/metrics`), daily digest + WS (`/api/posture/diff`, `/api/digest`), AR room estimate (`/api/ar/room`), detection-rule compiler (`/api/rules` + SHA-256 manifest).
- **Simple / Expert UI**: verdict bar answers "Am I safe?" + top fix; per-device `OK / Check / Fix now` badges; accordions instead of 10 stacked panels.

---

## 2. Commercial 3-Tier Subscription & Founder's Lifetime Licensing

| Tier | Pricing | Included Capabilities |
| :--- | :--- | :--- |
| **Community Edition (`free`)** | **$0 / forever** | ARP/IPv6 discovery, 47K+ IEEE OUI lookup, latency sparklines, Ping Burst, Wake-on-LAN, CIDR Calculator |
| **Pro Guardian (`pro`)** | **$9.99/mo**, **$99/yr**, or **$69 Lifetime** *(+ 7-Day Free Trial)* | 10-Stage Hidden De-Cloaker, Walk-Around RF Geiger Finder, 24h Presence Heatmap, Smart Home/TV/Sonos/Console Controls, 4-Ring Area Scan (up to 3 nodes) |
| **Sovereign Enterprise (`enterprise`)** | **$29.99/mo**, **$299/yr**, or **$149 Founder's Lifetime** | Guardian Shield Host Quarantine, SSH HASSH / SMB2 / DNSSEC / NTP Auditors, Wire DPI/JA3/p0f, Counter-Surveillance Camera Sweep, 5G Gateway Control, Nmap `-sV`, MTR Trace, Forensic Dossier Export (up to 25 nodes) |

---

## 3. CLI Reference (`python3 -m netpulse`)

```bash
python3 -m netpulse scan                  # Deep multi-vector subnet scan & Rich device matrix
python3 -m netpulse watch                 # Live auto-refreshing Terminal TUI Network Guardian
python3 -m netpulse wifi                  # 2.4/5 GHz RF Spectrum, 10-Stage De-Cloaker & Channel Optimizer
python3 -m netpulse audit                 # 5-Pillar Subnet Security & Cryptographic Posture Audit
python3 -m netpulse domain cloudflare.com # DNS (A/AAAA/MX/NS/SPF/DMARC), TLS :443 X.509 & HTTP/3 Recon
python3 -m netpulse sockets               # Audit local workstation listening ports, PIDs & RX/TX counters
python3 -m netpulse cidr 192.168.12.0/24  # IPv4 / IPv6 Subnet & CIDR Calculator
python3 -m netpulse oui Sonos             # Search 47,035+ IEEE OUI prefixes or unmask IPv6 EUI-64
python3 -m netpulse speedtest             # Multi-stream WAN download/upload & Bufferbloat benchmark
python3 -m netpulse graph                 # Unified Device Identity Graph
python3 -m netpulse ble                   # BLE Continuity census (Stage 11)
python3 -m netpulse passive               # Passive census dwell schedule + frames
python3 -m netpulse metrics               # Prometheus exposition
python3 -m netpulse threat                # Threat Field (collapse)
python3 -m netpulse digest                # Daily posture digest
python3 -m netpulse explain <key>         # Copilot: why this verdict?
python3 -m netpulse control <key> power status # Universal control
python3 -m netpulse scan-strategy home    # Adaptive bandit state
python3 -m netpulse sinkhole bad.example  # DNS sinkhole add
python3 -m netpulse rules                 # Detection rules list/compile
python3 -m netpulse ar <bssid>            # AR room estimate
python3 -m netpulse license status        # View or mint cryptographic NP1-* licenses
```
