# Security Policy

Netwide is a network-security tool that inspects your LAN, parses untrusted protocol
handshakes, and can take enforcement actions (ARP quarantine, `iptables`/`nft` rules,
DNS sinkhole). It is designed to be safe to run on your own network, but bugs happen.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 4.6.x | ✅ |
| 4.5.x | ✅ (security fixes only) |
| < 4.5 | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security bugs.**

Report privately via GitHub's security advisory form:
**Security → Report a vulnerability** on this repository
(or `https://github.com/kaleidoscope-conscious/netwide/security/advisories/new`).

Please include:

- Affected version and platform (Linux / Docker / Android)
- What you ran (scan mode, passive census, BLE census, control plane…)
- Steps to reproduce, ideally with the raw evidence bundle
  (`POST /api/evidence/bundle`) attached
- The impact you observed

### What to expect

| Stage | Target |
| :--- | :--- |
| Acknowledgement | ≤ 72 hours |
| Triage + severity | ≤ 7 days |
| Fix released | ≤ 30 days for critical/high (fast-track for active exploitation) |
| Disclosure | 90 days after the fix ships, or sooner if a user is at risk |

You are welcome to publish your finding once a fix is released. Credit is given unless you
prefer otherwise.

## Scope notes

- **In scope**: the daemon API, the CLI, the desktop app, protocol parsers, the control plane,
  the licence/authority code, the evidence bundle, and the Docker image.
- **Out of scope**: attacks on networks you do not own or administer; social engineering;
  physical access to the host; vulnerabilities in third-party dependencies (report those
  upstream — but tell us, and we will help coordinate the update).
- Netwide performs active probing on the network it is running on. **Only use it on networks
  you are authorised to test.**

## Hardening your own deployment

- The daemon binds `127.0.0.1` by default. It listens on `0.0.0.0` only when explicitly asked
  (`--host 0.0.0.0`) — understand the exposure before you do.
- Operator surfaces (`/admin`, `/watchtower`) and all privileged licensing actions require the
  Sovereign Admin Master Token.
- Set `NETWIDE_WS_TOKEN` to require a token for WebSocket clients connecting from non-loopback.
- `NETWIDE_LICENSE_PRIVATE_KEY` is only needed on the machine that *issues* licences; never
  ship it, and back it up (`netwide authority show`).
