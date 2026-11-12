"""
NetPulse Sovereign Subscription, Stripe Billing & Cryptographic License Engine.

Provides:
1. Cryptographic License Key Minting & Verification (NP1-<B64URL_PAYLOAD>-<HMAC_SHA256_SIG>)
2. 3-Tier Feature Entitlement Matrix (Community Free, Pro Guardian $9.99/mo, Sovereign Enterprise $29.99/mo)
3. Direct Stripe REST API Integration (Checkout Sessions, Billing Portal, HMAC-SHA256 Webhook Verification)
4. SQLite Persistence for Active Node Subscription, Minted Keys Ledger & Revocation List
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from netpulse import license_authority
from contextlib import closing
from typing import Any, Dict, List, Optional, Tuple

DB_DEFAULT_PATH = os.environ.get("NETPULSE_DB_PATH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "netpulse_intel.db")

TIER_RANK: Dict[str, int] = {
    "free": 0,
    "pro": 1,
    "enterprise": 2,
}

TIER_CATALOG: Dict[str, Dict[str, Any]] = {
    "free": {
        "id": "free",
        "name": "Community Edition",
        "badge": "FREE TIER",
        "price_monthly_usd": 0.0,
        "price_annual_usd": 0.0,
        "tagline": "Essential LAN discovery, OUI hardware lookup, Ping Burst & Wake-on-LAN.",
        "max_nodes": 1,
        "features": [
            "Real-time ARP / IPv6 Neighbor Discovery",
            "47,000+ IEEE OUI Hardware Vendor Lookup",
            "ICMP / TCP Latency Sparklines & Ping Burst",
            "IEEE 802 Wake-on-LAN Magic Packet Transmitter",
            "Basic 802.11 Wi-Fi Access Point List",
        ],
    },
    "pro": {
        "id": "pro",
        "name": "Pro Guardian",
        "badge": "PRO GUARDIAN",
        "price_monthly_usd": 9.99,
        "price_annual_usd": 99.00,
        "price_lifetime_usd": 69.00,
        "tagline": "Full 10-stage Hidden Entity De-Cloaker, Walk-Around RF Geiger Counter & Smart Home/TV Control.",
        "max_nodes": 3,
        "features": [
            "Everything in Community Edition",
            "10-Stage Universal Hidden BSSID & Privacy MAC De-Cloaker (802.11k + Temporal RSSI Pearson)",
            "Walk-Around RF Geiger Finder & Dual-Node Handset/Desktop RF Triangulation",
            "24-Hour Host Presence & Availability Heatmap Timeline",
            "Roku ECP, DIAL, PlayStation DDP, Spotify, Sonos UPnP & Smart IoT Relays (Kasa / Shelly / Cast)",
            "4-Ring Deep & Wide Area Scan + Physical Radio Silicon Clustering & Channel Optimizer",
        ],
    },
    "enterprise": {
        "id": "enterprise",
        "name": "Sovereign Enterprise",
        "badge": "SOVEREIGN ENTERPRISE",
        "price_monthly_usd": 29.99,
        "price_annual_usd": 299.00,
        "price_lifetime_usd": 149.00,
        "tagline": "Autonomous Host Quarantine, Wire DPI/JA3, SSH HASSH / SMB2 Audit, Counter-Surveillance & Exports.",
        "max_nodes": 25,
        "features": [
            "Everything in Pro Guardian",
            "Guardian Shield Active Host Quarantine, TCP RST Teardown & Gateway Anti-ARP-Spoofing Lock",
            "Live Wire DPI: Rolling KB/s Bandwidth, DNS/TLS SNI Timeline, TLS JA3 & p0f SYN Signatures",
            "SSHv2 Binary KEXINIT / HASSH Server Audit & SMB2/3 NTLM-Relay Signing Inspector",
            "Counter-Surveillance ONVIF / RTSP / Hidden Camera RF Sweep & UPnP IGD NAT Port-Forward Audit",
            "T-Mobile 5G NR Cellular Gateway Telemetry & Reboot Control",
            "Deep Nmap (-sV), MTR Multi-Hop Traceroute & Custom Port-Range Prober",
            "One-Click Forensic Intelligence Dossier Export (Markdown + JSON + CSV)",
        ],
    },
}

FEATURE_REQUIREMENTS: Dict[str, Tuple[str, str]] = {
    # Pro Guardian features
    "area_scan": ("pro", "4-Ring Deep & Wide Area Scan & De-Cloaker"),
    "roku_control": ("pro", "Smart TV & Roku ECP Remote Control"),
    "dial_control": ("pro", "DIAL v2.1 Smart TV App Launcher"),
    "playstation_wake": ("pro", "Sony PlayStation DDP Wakeup Controller"),
    "spotify_control": ("pro", "Spotify Connect ZeroConf Controller"),
    "sonos_control": ("pro", "Sonos UPnP AVTransport & Volume Controller"),
    "smart_home_control": ("pro", "Smart Home Relay Control (Kasa / Shelly / Google Cast)"),
    "bt_control": ("pro", "Bluetooth HCI Active Device Control"),
    "launch_client": ("pro", "Native Protocol Session Launcher"),
    # Sovereign Enterprise features
    "quarantine": ("enterprise", "Guardian Shield Active Host Quarantine & Teardown"),
    "camera_sweep": ("enterprise", "Counter-Surveillance Camera & RF Attribution Sweep"),
    "gateway_control": ("enterprise", "5G NR Cellular Gateway Control"),
    "ssh_audit": ("enterprise", "SSHv2 Binary KEXINIT & HASSH Cryptographic Audit"),
    "smb_audit": ("enterprise", "SMB2/3 Dialect & NTLM-Relay Signing Audit"),
    "dns_audit": ("enterprise", "RFC 4035 DNSSEC & DoT (:853) Resolver Security Audit"),
    "ntp_audit": ("enterprise", "RFC 5905 NTPv4 Stratum, Reference Clock & Mode-6 Audit"),
    "port_knock": ("enterprise", "Deterministic Multi-Port TCP/UDP Port-Knocking Engine"),
    "upnp_nat_audit": ("enterprise", "UPnP IGD External NAT Port-Forwarding Audit"),
    "deep_nmap": ("enterprise", "Deep Nmap Service & Version Probe (-sV)"),
    "traceroute": ("enterprise", "MTR Multi-Hop Path Traceroute"),
    "port_range_scan": ("enterprise", "Concurrent TCP Port-Range Prober"),
    "http_probe": ("enterprise", "Custom HTTP / REST Payload Prober"),
    "forensic_export": ("enterprise", "Forensic Intelligence Dossier Export (MD + JSON + CSV)"),
}


def _b64url_encode(data: bytes) -> str:
    return base64.b64encode(data, altchars=b"._").decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode((s + pad).encode("ascii"), altchars=b"._")


class SubscriptionManager:
    """
    Manages cryptographic license keys, tier entitlements, SQLite subscription state,
    and Stripe Checkout / Customer Portal / Webhook lifecycle.
    """

    def __init__(self, db_path: str = DB_DEFAULT_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn
    def _init_tables(self) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS subscription_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS minted_licenses (
                    jti TEXT PRIMARY KEY,
                    license_key TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    plan TEXT NOT NULL,
                    email TEXT NOT NULL,
                    max_nodes INTEGER DEFAULT 3,
                    issued_at REAL NOT NULL,
                    expires_at REAL DEFAULT 0,
                    stripe_session_id TEXT DEFAULT '',
                    stripe_customer_id TEXT DEFAULT '',
                    revoked INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS marketing_leads (
                    email TEXT PRIMARY KEY,
                    source TEXT DEFAULT 'pricing_page',
                    use_case TEXT DEFAULT 'prosumer',
                    trial_jti TEXT DEFAULT '',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            # Ensure signing secret exists
            row = conn.execute(
                "SELECT value FROM subscription_config WHERE key = 'signing_secret'"
            ).fetchone()
            if not row:
                env_secret = os.environ.get("NETPULSE_LICENSE_SECRET", "").strip()
                secret_val = env_secret if env_secret else secrets.token_hex(32)
                conn.execute(
                    "INSERT INTO subscription_config (key, value) VALUES ('signing_secret', ?)",
                    (secret_val,),
                )

            # Ensure admin master token exists
            admin_row = conn.execute(
                "SELECT value FROM subscription_config WHERE key = 'admin_token'"
            ).fetchone()
            if not admin_row:
                env_admin = os.environ.get("NETPULSE_ADMIN_TOKEN", "").strip()
                admin_val = env_admin if env_admin else f"np_adm_{secrets.token_hex(16)}"
                conn.execute(
                    "INSERT INTO subscription_config (key, value) VALUES ('admin_token', ?)",
                    (admin_val,),
                )
            else:
                admin_val = str(admin_row["value"])
            conn.commit()

            # Persist admin token to ~/.config/netpulse/admin.token (0600) for local CLI/operator convenience
            try:
                cfg_dir = os.path.expanduser("~/.config/netpulse")
                os.makedirs(cfg_dir, exist_ok=True)
                tok_file = os.path.join(cfg_dir, "admin.token")
                with open(tok_file, "w", encoding="utf-8") as tf:
                    tf.write(admin_val + "\n")
                os.chmod(tok_file, 0o600)
            except Exception:
                pass

    def _get_config(self, key: str, default: str = "") -> str:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT value FROM subscription_config WHERE key = ?", (key,)
            ).fetchone()
            return str(row["value"]) if row else default

    def _set_config(self, key: str, value: str) -> None:
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO subscription_config (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            conn.commit()

    def _signing_secret(self) -> bytes:
        env_secret = os.environ.get("NETPULSE_LICENSE_SECRET", "").strip()
        if env_secret:
            return env_secret.encode("utf-8")
        stored = self._get_config("signing_secret", "")
        if stored:
            return stored.encode("utf-8")
        # No env secret and no persisted secret: generate a strong random secret and
        # persist it immediately. Never fall back to a publicly-known constant —
        # that would make every NP1 key forgeable.
        generated = secrets.token_hex(32)
        self._set_config("signing_secret", generated)
        return generated.encode("utf-8")

    def get_signing_secret(self) -> str:
        """Return the persistent node HMAC signing secret for cryptographic bundle verification."""
        return self._signing_secret().decode("utf-8", errors="replace")

    def get_admin_token(self) -> str:
        env_admin = os.environ.get("NETPULSE_ADMIN_TOKEN", "").strip()
        if env_admin:
            return env_admin
        return self._get_config("admin_token", "")

    def verify_admin_token(self, candidate: str) -> bool:
        expected = self.get_admin_token()
        if not expected or not candidate:
            return False
        return hmac.compare_digest(expected.strip(), candidate.strip())

    def start_free_trial(self, email: str = "trial@netpulse.io") -> Dict[str, Any]:
        """
        Issue a one-time 7-day Pro Guardian evaluation license key for this node.
        Check-and-claim is serialized on RLock (no TOCTOU between concurrent POSTs).
        """
        with self._lock:
            already_claimed = self._get_config("trial_claimed", "")
            if already_claimed:
                return {
                    "ok": False,
                    "error": "The 7-day Pro Guardian free trial has already been used on this node. Please subscribe or activate a full license key.",
                }
            minted = self.mint_license_key(tier="pro", plan="trial", email=email, days=7)
            self._set_config("trial_claimed", str(int(time.time())))
            act = self.activate_license_key(minted["license_key"])
            act["trial_license"] = minted
            return act

    # ==================== CRYPTOGRAPHIC LICENSE MINTING & VERIFICATION ====================

    def mint_license_key(
        self,
        tier: str = "enterprise",
        plan: str = "annual",
        email: str = "operator@netpulse.local",
        days: Optional[int] = None,
        max_nodes: Optional[int] = None,
        stripe_session_id: str = "",
        stripe_customer_id: str = "",
    ) -> Dict[str, Any]:
        """
        Mint a cryptographically signed NetPulse license key:
        Format: NP1-<TIER_UPPER>-<B64URL_PAYLOAD>-<HMAC_SHA256_SIG_24>
        """
        tier_clean = tier.lower().strip()
        if tier_clean not in TIER_CATALOG or tier_clean == "free":
            tier_clean = "pro"
        plan_clean = plan.lower().strip()

        now = int(time.time())
        if days is not None:
            exp = 0 if days <= 0 else now + int(days * 86400)
        else:
            if plan_clean == "lifetime":
                exp = 0
            elif plan_clean == "annual":
                exp = now + 365 * 86400
            elif plan_clean == "trial":
                exp = now + 7 * 86400
            else:
                exp = now + 31 * 86400

        nodes = max_nodes or TIER_CATALOG[tier_clean]["max_nodes"]
        jti = f"np_{secrets.token_hex(6)}"

        payload = {
            "v": 1,
            "jti": jti,
            "tier": tier_clean,
            "plan": plan_clean,
            "email": email.strip() or "operator@netpulse.local",
            "nodes": nodes,
            "iat": now,
            "exp": exp,
        }
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = _b64url_encode(payload_bytes)

        # Preferred: asymmetric Ed25519 signature — verifiable on ANY NetPulse node
        # because only the public key ships with the product.
        sig_b64 = ""
        try:
            sig_b64 = license_authority.sign_payload(payload_b64) or ""
        except Exception:
            sig_b64 = ""
        if sig_b64:
            payload["sk"] = "ed25519"
            payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            payload_b64 = _b64url_encode(payload_bytes)
            sig_b64 = license_authority.sign_payload(payload_b64) or ""
        if not sig_b64:
            # Legacy node-local HMAC fallback (trial keys minted on a customer node).
            sig_full = hmac.new(self._signing_secret(), payload_b64.encode("ascii"), hashlib.sha256).digest()
            # Full 256-bit HMAC-SHA256 tag (upgraded from the legacy 144-bit truncated tag).
            # verify_license_key() accepts both the full tag and the legacy truncated one.
            sig_b64 = _b64url_encode(sig_full)

        license_key = f"NP1-{tier_clean.upper()}-{payload_b64}-{sig_b64}"

        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO minted_licenses (
                    jti, license_key, tier, plan, email, max_nodes,
                    issued_at, expires_at, stripe_session_id, stripe_customer_id, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    jti,
                    license_key,
                    tier_clean,
                    plan_clean,
                    payload["email"],
                    nodes,
                    float(now),
                    float(exp),
                    stripe_session_id,
                    stripe_customer_id,
                ),
            )
            conn.commit()

        return {
            "ok": True,
            "jti": jti,
            "license_key": license_key,
            "tier": tier_clean,
            "tier_name": TIER_CATALOG[tier_clean]["name"],
            "plan": plan_clean,
            "email": payload["email"],
            "max_nodes": nodes,
            "issued_at": now,
            "expires_at": exp,
            "expires_human": "Lifetime (Never Expires)"
            if exp == 0
            else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp)),
        }

    def verify_license_key(self, license_key: str) -> Dict[str, Any]:
        """
        Verify a cryptographic NP1-* license key in constant time and check expiration/revocation.
        """
        clean_key = (license_key or "").strip()
        parts = clean_key.split("-")
        if len(parts) != 4 or parts[0] != "NP1":
            return {"valid": False, "error": "Malformed license key format (expected NP1-<TIER>-<PAYLOAD>-<SIG>)."}

        _, tier_prefix, payload_b64, sig_b64 = parts

        # Decode the payload first so we know which signature scheme to use.
        try:
            payload_probe = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except Exception:
            return {"valid": False, "error": "Corrupted license payload encoding."}

        scheme = str(payload_probe.get("sk") or "hmac")
        signature_ok = False
        if scheme == "ed25519":
            # Operator-signed license: verifies on any node (public key ships with the app).
            try:
                signature_ok = license_authority.verify_payload(payload_b64, sig_b64)
            except Exception:
                signature_ok = False
            if not signature_ok:
                return {
                    "valid": False,
                    "error": "Cryptographic signature verification failed (invalid Ed25519 signature).",
                }
        else:
            expected_sig = hmac.new(self._signing_secret(), payload_b64.encode("ascii"), hashlib.sha256).digest()
            # Accept both the current full 256-bit tag and the legacy 144-bit truncated tag
            # so pre-upgrade minted keys remain valid.
            expected_sig_full = _b64url_encode(expected_sig)
            expected_sig_trunc = _b64url_encode(expected_sig[:18])
            signature_ok = (
                hmac.compare_digest(sig_b64, expected_sig_full)
                or hmac.compare_digest(sig_b64, expected_sig_trunc)
            )
            if not signature_ok:
                return {"valid": False, "error": "Cryptographic signature verification failed (invalid HMAC-SHA256 tag)."}

        try:
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        except Exception:
            return {"valid": False, "error": "Corrupted license payload encoding."}

        tier = str(payload.get("tier", "")).lower()
        if tier not in TIER_CATALOG or tier.upper() != tier_prefix.upper():
            return {"valid": False, "error": "License tier mismatch."}

        exp = int(payload.get("exp") or 0)
        now = int(time.time())
        if exp > 0 and now > exp:
            return {
                "valid": False,
                "expired": True,
                "error": f"License expired on {time.strftime('%Y-%m-%d', time.localtime(exp))}.",
            }

        jti = str(payload.get("jti", ""))
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT revoked FROM minted_licenses WHERE jti = ?", (jti,)
            ).fetchone()
            if row and int(row["revoked"] or 0) == 1:
                return {"valid": False, "revoked": True, "error": f"License {jti} has been revoked."}

        return {
            "valid": True,
            "jti": jti,
            "tier": tier,
            "tier_name": TIER_CATALOG[tier]["name"],
            "plan": str(payload.get("plan", "monthly")),
            "email": str(payload.get("email", "operator@netpulse.local")),
            "max_nodes": int(payload.get("nodes", TIER_CATALOG[tier]["max_nodes"])),
            "issued_at": int(payload.get("iat", now)),
            "expires_at": exp,
            "expires_human": "Lifetime (Never Expires)"
            if exp == 0
            else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp)),
            "license_key": clean_key,
        }

    # ==================== NODE ACTIVATION & ENTITLEMENT CHECKING ====================

    def activate_license_key(self, license_key: str) -> Dict[str, Any]:
        ver = self.verify_license_key(license_key)
        if not ver.get("valid"):
            return {"ok": False, "error": ver.get("error", "Invalid license key")}

        self._set_config("active_license_key", license_key.strip())
        self._set_config("activated_at", str(int(time.time())))
        return {
            "ok": True,
            "message": f"Activated {ver['tier_name']} ({ver['plan'].upper()}) for {ver['email']}",
            "subscription": self.get_subscription_status(),
        }

    def deactivate_license(self) -> Dict[str, Any]:
        self._set_config("active_license_key", "")
        return {
            "ok": True,
            "message": "Reverted node to Community Edition (Free Tier).",
            "subscription": self.get_subscription_status(),
        }

    def revoke_license(self, jti: str) -> Dict[str, Any]:
        target = (jti or "").strip()
        # Accept a full NP1-* license key (admins commonly paste the whole key)
        # in addition to a bare JTI ledger id.
        if target.startswith("NP1-"):
            parts = target.split("-")
            if len(parts) != 4:
                return {"ok": False, "error": "Malformed license key cannot be parsed for revocation."}
            try:
                payload = json.loads(_b64url_decode(parts[2]).decode("utf-8"))
                target = str(payload.get("jti", "")).strip() or target
            except Exception:
                pass
        with self._lock, closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "UPDATE minted_licenses SET revoked = 1 WHERE jti = ?", (target,)
            )
            conn.commit()
            if cur.rowcount == 0:
                return {"ok": False, "error": f"License ID '{jti}' not found."}
        active_key = self._get_config("active_license_key", "")
        if active_key:
            ver = self.verify_license_key(active_key)
            if not ver.get("valid"):
                self._set_config("active_license_key", "")
        return {"ok": True, "jti": jti, "revoked": True}

    def list_minted_licenses(self) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM minted_licenses ORDER BY issued_at DESC LIMIT 100"
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                exp = int(d.get("expires_at") or 0)
                d["expires_human"] = (
                    "Lifetime"
                    if exp == 0
                    else time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
                )
                out.append(d)
            return out

    # Unit prices mirroring TIER_CATALOG (pro 9.99/99/69 · enterprise 29.99/299/149).
    _PRICE_TABLE = {
        ("pro", "monthly"): 9.99,
        ("pro", "annual"): 99.00,
        ("pro", "lifetime"): 69.00,
        ("enterprise", "monthly"): 29.99,
        ("enterprise", "annual"): 299.00,
        ("enterprise", "lifetime"): 149.00,
    }

    def business_metrics(self) -> Dict[str, Any]:
        """Aggregated commercial + usage metrics for the operator dashboard."""
        with closing(self._connect()) as conn:
            lic_rows = [dict(r) for r in conn.execute(
                "SELECT license_key, tier, plan, email, issued_at, expires_at,"
                " stripe_session_id, revoked FROM minted_licenses ORDER BY issued_at DESC"
            ).fetchall()]
            leads = [dict(r) for r in conn.execute(
                "SELECT email, source, use_case, trial_jti, created_at FROM marketing_leads"
                " ORDER BY created_at DESC LIMIT 100"
            ).fetchall()]
            ledger_events = conn.execute("SELECT COUNT(*) FROM events_ledger").fetchone()[0]
            webhook_keys = conn.execute(
                "SELECT COUNT(*) FROM subscription_config WHERE key LIKE 'webhook_processed_%'"
            ).fetchone()[0]

        active = [r for r in lic_rows if not r.get("revoked")]
        revoked = [r for r in lic_rows if r.get("revoked")]

        def _price(r: Dict[str, Any]) -> float:
            return self._PRICE_TABLE.get((r.get("tier"), r.get("plan")), 0.0)

        lifetime_revenue = sum(_price(r) for r in active if r.get("plan") in ("lifetime",))
        mrr_estimate = sum(
            _price(r) / (12.0 if r.get("plan") == "annual" else 1.0)
            for r in active if r.get("plan") in ("monthly", "annual")
        )

        by_tier: Dict[str, int] = {}
        by_plan: Dict[str, int] = {}
        for r in active:
            by_tier[r.get("tier") or "?"] = by_tier.get(r.get("tier") or "?", 0) + 1
            by_plan[r.get("plan") or "?"] = by_plan.get(r.get("plan") or "?", 0) + 1

        distinct_emails = {r.get("email") for r in lic_rows if r.get("email")}
        paid_emails = {r.get("email") for r in active if r.get("email")}

        # Last-30-day mint timeline
        import collections
        today = time.localtime()
        tl = collections.OrderedDict()
        for i in range(29, -1, -1):
            day = time.strftime("%Y-%m-%d", time.localtime(time.mktime(today) - i * 86400))
            tl[day] = 0
        for r in lic_rows:
            day = time.strftime("%Y-%m-%d", time.localtime(r.get("issued_at") or 0))
            if day in tl:
                tl[day] += 1

        recent = [
            {
                "issued_human": time.strftime("%Y-%m-%d %H:%M", time.localtime(r.get("issued_at") or 0)),
                "email": r.get("email"),
                "tier": r.get("tier"),
                "plan": r.get("plan"),
                "source": "stripe" if r.get("stripe_session_id") else "manual",
                "revoked": bool(r.get("revoked")),
            }
            for r in lic_rows[:25]
        ]

        return {
            "licenses": {
                "total": len(lic_rows),
                "active": len(active),
                "revoked": len(revoked),
                "by_tier": by_tier,
                "by_plan": by_plan,
            },
            "customers": {
                "distinct_emails": len(distinct_emails),
                "paid_emails": len(paid_emails),
                "recent": recent,
            },
            "revenue": {
                "lifetime_revenue_usd": round(lifetime_revenue, 2),
                "mrr_estimate_usd": round(mrr_estimate, 2),
                "arr_estimate_usd": round(mrr_estimate * 12.0, 2),
            },
            "leads": {
                "total": len(leads),
                "trials_claimed": sum(1 for l in leads if l.get("trial_jti")),
                "recent": [
                    {
                        "email": l.get("email"),
                        "source": l.get("source"),
                        "use_case": l.get("use_case"),
                        "human": time.strftime("%Y-%m-%d", time.localtime(l.get("created_at") or 0)),
                    }
                    for l in leads[:10]
                ],
            },
            "stripe": {
                "configured": bool(
                    os.environ.get("STRIPE_SECRET_KEY") or self._get_config("stripe_secret_key", "")
                ),
                "webhook_events_processed": webhook_keys,
            },
            "ledger_events": ledger_events,
            "mints_timeline": tl,
        }

    def get_subscription_status(self) -> Dict[str, Any]:
        active_key = self._get_config("active_license_key", "")
        stripe_sk = os.environ.get("STRIPE_SECRET_KEY") or self._get_config("stripe_secret_key", "")
        stripe_pk = os.environ.get("STRIPE_PUBLISHABLE_KEY") or self._get_config("stripe_publishable_key", "")
        trial_avail = not bool(self._get_config("trial_claimed", ""))

        if active_key:
            ver = self.verify_license_key(active_key)
            if ver.get("valid"):
                tier = ver["tier"]
                masked_key = active_key[:14] + "••••" + active_key[-8:]
                return {
                    "tier": tier,
                    "tier_rank": TIER_RANK.get(tier, 0),
                    "tier_name": ver["tier_name"],
                    "badge": TIER_CATALOG[tier]["badge"],
                    "plan": ver["plan"],
                    "email": ver["email"],
                    "jti": ver["jti"],
                    "max_nodes": ver["max_nodes"],
                    "expires_at": ver["expires_at"],
                    "expires_human": ver["expires_human"],
                    "license_key_masked": masked_key,
                    "is_paid": True,
                    "trial_available": trial_avail,
                    "stripe_configured": bool(stripe_sk),
                    "stripe_publishable_key": stripe_pk,
                    "entitlements": self._build_entitlement_map(tier),
                    "catalog": TIER_CATALOG,
                }

        return {
            "tier": "free",
            "tier_rank": 0,
            "tier_name": TIER_CATALOG["free"]["name"],
            "badge": TIER_CATALOG["free"]["badge"],
            "plan": "free",
            "email": "Community User",
            "jti": "",
            "max_nodes": 1,
            "expires_at": 0,
            "expires_human": "Always Free",
            "license_key_masked": "None (Community Tier)",
            "is_paid": False,
            "trial_available": trial_avail,
            "stripe_configured": bool(stripe_sk),
            "stripe_publishable_key": stripe_pk,
            "entitlements": self._build_entitlement_map("free"),
            "catalog": TIER_CATALOG,
        }

    def get_max_nodes(self) -> int:
        return int(self.get_subscription_status().get("max_nodes") or 1)

    def check_node_budget(self, current_nodes: int) -> Dict[str, Any]:
        limit = self.get_max_nodes()
        used = int(current_nodes or 0)
        return {
            "ok": used <= limit,
            "used": used,
            "limit": limit,
            "remaining": max(0, limit - used),
            "note": "Nodes beyond budget are inventoried read-only; upgrade to control them." if used > limit else "within budget",
        }

    def prune_webhook_idempotency(self, days: int = 90) -> int:
        cutoff = int(time.time() - days * 86400)
        pruned = 0
        try:
            with self._lock, closing(self._connect()) as conn, conn:
                cur = conn.execute(
                    "DELETE FROM subscription_config WHERE key LIKE 'webhook_processed_%' AND CAST(value AS INTEGER) < ?",
                    (cutoff,),
                )
                pruned = int(cur.rowcount or 0)
        except Exception:
            pruned = 0
        return pruned

    def _build_entitlement_map(self, current_tier: str) -> Dict[str, bool]:
        cur_rank = TIER_RANK.get(current_tier, 0)
        return {
            feat: cur_rank >= TIER_RANK.get(req_tier, 1)
            for feat, (req_tier, _) in FEATURE_REQUIREMENTS.items()
        }

    def check_feature_access(self, feature_key: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if the active node subscription permits `feature_key`.
        Returns (True, None) if permitted, or (False, error_payload_dict) if gated.
        """
        req = FEATURE_REQUIREMENTS.get(feature_key)
        if not req:
            return False, {
                "ok": False,
                "upgrade_required": True,
                "feature_key": feature_key,
                "feature_name": feature_key,
                "error": f"Feature '{feature_key}' is unrecognized or unentitled.",
            }
        req_tier, feature_label = req
        status = self.get_subscription_status()
        cur_tier = status["tier"]
        if TIER_RANK.get(cur_tier, 0) >= TIER_RANK.get(req_tier, 1):
            return True, None

        target_info = TIER_CATALOG[req_tier]
        return False, {
            "ok": False,
            "upgrade_required": True,
            "feature_key": feature_key,
            "feature_name": feature_label,
            "current_tier": cur_tier,
            "current_tier_name": status["tier_name"],
            "required_tier": req_tier,
            "required_tier_name": target_info["name"],
            "price_monthly_usd": target_info["price_monthly_usd"],
            "message": (
                f"'{feature_label}' requires {target_info['name']} "
                f"(${target_info['price_monthly_usd']:.2f}/mo) or higher."
            ),
        }

    # ==================== STRIPE CHECKOUT, BILLING PORTAL & WEBHOOKS ====================

    def configure_stripe_keys(
        self,
        secret_key: str,
        publishable_key: str = "",
        webhook_secret: str = "",
    ) -> Dict[str, Any]:
        if secret_key.strip():
            self._set_config("stripe_secret_key", secret_key.strip())
        if publishable_key.strip():
            self._set_config("stripe_publishable_key", publishable_key.strip())
        if webhook_secret.strip():
            self._set_config("stripe_webhook_secret", webhook_secret.strip())
        return {
            "ok": True,
            "stripe_configured": bool(secret_key.strip() or self._get_config("stripe_secret_key")),
            "message": "Saved Stripe billing configuration.",
        }

    def create_stripe_checkout_session(
        self,
        tier: str,
        plan: str,
        email: str,
        origin_url: str = "http://127.0.0.1:8765",
    ) -> Dict[str, Any]:
        """
        Create a live Stripe Checkout Session via `POST https://api.stripe.com/v1/checkout/sessions`
        using inline `price_data` so no pre-created Stripe Product IDs are required.
        """
        tier_clean = tier.lower().strip()
        if tier_clean not in ("pro", "enterprise"):
            return {"ok": False, "error": f"Invalid subscription tier '{tier}'."}

        raw_plan = plan.lower().strip()
        if raw_plan == "lifetime":
            plan_clean = "lifetime"
        elif raw_plan == "annual":
            plan_clean = "annual"
        else:
            plan_clean = "monthly"

        cat = TIER_CATALOG[tier_clean]
        if plan_clean == "lifetime":
            amount_usd = cat.get("price_lifetime_usd", 149.00 if tier_clean == "enterprise" else 69.00)
        elif plan_clean == "annual":
            amount_usd = cat["price_annual_usd"]
        else:
            amount_usd = cat["price_monthly_usd"]
        unit_amount_cents = int(round(amount_usd * 100))
        interval = "year" if plan_clean == "annual" else "month"

        stripe_sk = os.environ.get("STRIPE_SECRET_KEY") or self._get_config("stripe_secret_key", "")
        if not stripe_sk:
            return {
                "ok": False,
                "stripe_not_configured": True,
                "tier": tier_clean,
                "plan": plan_clean,
                "price_usd": amount_usd,
                "error": (
                    "Stripe API Secret Key (sk_live_... or sk_test_...) is not configured yet. "
                    "Add your Stripe Secret Key in the Billing Settings tab or mint/activate a signed NP1 license key directly."
                ),
            }

        form_params: Dict[str, str] = {
            "mode": "payment" if plan_clean == "lifetime" else "subscription",
            "success_url": f"{origin_url}/?stripe_session_id={{CHECKOUT_SESSION_ID}}&tier={tier_clean}&plan={plan_clean}",
            "cancel_url": f"{origin_url}/?stripe_canceled=1",
            "line_items[0][quantity]": "1",
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": str(unit_amount_cents),
            "line_items[0][price_data][product_data][name]": f"NetPulse {cat['name']} ({plan_clean.capitalize()})",
            "line_items[0][price_data][product_data][description]": cat["tagline"],
            "metadata[netpulse_tier]": tier_clean,
            "metadata[netpulse_plan]": plan_clean,
            "metadata[subscriber_email]": email.strip() or "subscriber@netpulse.io",
        }
        if plan_clean != "lifetime":
            form_params["line_items[0][price_data][recurring][interval]"] = interval
        if email and "@" in email:
            form_params["customer_email"] = email.strip()

        encoded = urllib.parse.urlencode(form_params).encode("utf-8")
        req = urllib.request.Request(
            "https://api.stripe.com/v1/checkout/sessions",
            data=encoded,
            headers={
                "Authorization": f"Bearer {stripe_sk}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "ok": True,
                    "session_id": data.get("id", ""),
                    "checkout_url": data.get("url", ""),
                    "tier": tier_clean,
                    "plan": plan_clean,
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            try:
                err_json = json.loads(err_body)
                msg = err_json.get("error", {}).get("message", err_body)
            except Exception:
                msg = err_body
            return {"ok": False, "error": f"Stripe API error: {msg}"}
        except Exception as e:
            return {"ok": False, "error": f"Stripe connection error: {e}"}

    def verify_stripe_session_and_activate(self, session_id: str) -> Dict[str, Any]:
        """
        Verify a completed Stripe Checkout Session (`GET /v1/checkout/sessions/{id}`)
        and automatically mint + activate the corresponding NetPulse license key.
        """
        stripe_sk = os.environ.get("STRIPE_SECRET_KEY") or self._get_config("stripe_secret_key", "")
        if not stripe_sk:
            return {"ok": False, "error": "Stripe Secret Key not configured."}

        req = urllib.request.Request(
            f"https://api.stripe.com/v1/checkout/sessions/{urllib.parse.quote(session_id.strip())}",
            headers={"Authorization": f"Bearer {stripe_sk}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"ok": False, "error": f"Failed to verify Stripe session: {e}"}

        payment_status = data.get("payment_status")
        status = data.get("status")
        if payment_status == "no_payment_required":
            return {"ok": False, "error": "Refusing to mint a paid license for a free (no_payment_required) checkout session."}
        if payment_status != "paid":
            return {"ok": False, "error": f"Checkout session not paid yet (status={status}, payment={payment_status})."}

        meta = data.get("metadata") or {}
        tier = meta.get("netpulse_tier", "pro")
        plan = meta.get("netpulse_plan", "monthly")
        email = (
            (data.get("customer_details") or {}).get("email")
            or data.get("customer_email")
            or meta.get("subscriber_email")
            or "subscriber@netpulse.io"
        )
        cust_id = str(data.get("customer") or "")
        minted = self.mint_license_key(
            tier=tier,
            plan=plan,
            email=email,
            stripe_session_id=session_id,
            stripe_customer_id=cust_id,
        )
        act = self.activate_license_key(minted["license_key"])
        act["minted_license"] = minted
        return act

    def sync_paid_sessions(self, limit: int = 25) -> Dict[str, Any]:
        """
        Pull recent Checkout Sessions from Stripe and mint licenses for any paid
        session we have not issued yet. This covers purchases made through the
        hosted Stripe Payment Links (web-first checkout) where no webhook
        endpoint is reachable.
        """
        stripe_sk = os.environ.get("STRIPE_SECRET_KEY") or self._get_config("stripe_secret_key", "")
        if not stripe_sk:
            return {"ok": False, "error": "Stripe Secret Key not configured.", "minted": 0}
        url = (
            "https://api.stripe.com/v1/checkout/sessions?limit=%d"
            "&expand[]=data.payment_intent" % max(1, min(int(limit), 100))
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {stripe_sk}"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return {"ok": False, "error": f"Stripe session sync failed: {e}", "minted": 0}

        minted_count = 0
        issued: List[str] = []
        for sess in payload.get("data", []) or []:
            if sess.get("payment_status") != "paid":
                continue
            session_id = str(sess.get("id") or "")
            if not session_id:
                continue
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT license_key FROM minted_licenses WHERE stripe_session_id = ?",
                    (session_id,),
                ).fetchone()
            if row:
                continue
            meta = sess.get("metadata") or {}
            tier = str(meta.get("netpulse_tier") or "pro").lower()
            plan = str(meta.get("netpulse_plan") or "monthly").lower()
            if tier not in ("pro", "enterprise"):
                tier = "pro"
            if plan not in ("monthly", "annual", "lifetime"):
                plan = "monthly"
            email = (
                (sess.get("customer_details") or {}).get("email")
                or sess.get("customer_email")
                or meta.get("subscriber_email")
                or "subscriber@netpulse.io"
            )
            minted = self.mint_license_key(
                tier=tier,
                plan=plan,
                email=email,
                stripe_session_id=session_id,
                stripe_customer_id=str(sess.get("customer") or ""),
            )
            if minted.get("license_key"):
                minted_count += 1
                issued.append(session_id)

        return {"ok": True, "minted": minted_count, "sessions": issued}

    def handle_stripe_webhook(self, raw_body: bytes, sig_header: str) -> Dict[str, Any]:
        """
        Verify Stripe-Signature (`t=...,v1=...`) using HMAC-SHA256 and process
        `checkout.session.completed` and `customer.subscription.deleted` events.

        Hardening:
        - Fail-closed: unsigned/unverifiable payloads are rejected unless the
          NETPULSE_WEBHOOK_ALLOW_UNSIGNED=1 escape hatch is set (local dev only).
        - 5-minute timestamp tolerance window (anti-replay), matching Stripe docs.
        - Idempotent: repeated deliveries of the same event id / session id
          short-circuit instead of minting duplicate licenses.
        - `customer.subscription.deleted` revokes all licenses minted for the
          cancelled subscription/customer and downgrades the node if it was active.
        """
        wh_secret = os.environ.get("STRIPE_WEBHOOK_SECRET") or self._get_config("stripe_webhook_secret", "")
        if wh_secret and sig_header:
            parts = dict(
                item.split("=", 1) for item in sig_header.split(",") if "=" in item
            )
            t_val = parts.get("t", "")
            v1_val = parts.get("v1", "")
            try:
                ts = int(t_val)
                if abs(time.time() - ts) > 300:
                    return {"ok": False, "error": "Stripe webhook timestamp outside tolerance window (possible replay)."}
            except ValueError:
                return {"ok": False, "error": "Malformed Stripe webhook timestamp."}
            signed_payload = f"{t_val}.".encode("utf-8") + raw_body
            expected = hmac.new(wh_secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(v1_val, expected):
                return {"ok": False, "error": "Invalid Stripe webhook signature."}
        elif not (os.environ.get("NETPULSE_WEBHOOK_ALLOW_UNSIGNED", "").strip().lower() in ("1", "true", "yes")):
            return {
                "ok": False,
                "error": "Stripe webhook signature required: no webhook secret configured. "
                         "Set STRIPE_WEBHOOK_SECRET (or the stripe_webhook_secret config) to enable webhook processing. "
                         "Set NETPULSE_WEBHOOK_ALLOW_UNSIGNED=1 only for local testing.",
            }

        try:
            event = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return {"ok": False, "error": "Invalid JSON webhook payload."}

        ev_type = event.get("type", "")
        ev_id = str(event.get("id", ""))
        obj = (event.get("data") or {}).get("object") or {}

        # Idempotency: skip events we already processed (Stripe retries deliveries).
        if ev_id and self._get_config(f"webhook_processed_{ev_id}", ""):
            return {"ok": True, "event": ev_type, "duplicate": True}

        if ev_type == "checkout.session.completed":
            session_id = str(obj.get("id", ""))
            # Duplicate-delivery guard: never re-mint for the same checkout session.
            existing_key = ""
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT license_key FROM minted_licenses WHERE stripe_session_id = ? LIMIT 1",
                    (session_id,),
                ).fetchone()
                if row:
                    existing_key = str(row["license_key"])
            if existing_key:
                act = self.activate_license_key(existing_key)
                if ev_id:
                    self._set_config(f"webhook_processed_{ev_id}", str(int(time.time())))
                return {"ok": True, "event": ev_type, "duplicate_session": True, "activated": act}

            payment_status = str(obj.get("payment_status") or "").strip()
            if payment_status != "paid":
                return {
                    "ok": False,
                    "error": f"Refusing to mint: payment_status must be 'paid' (got '{payment_status}').",
                }

            meta = obj.get("metadata") or {}
            tier = meta.get("netpulse_tier", "pro")
            plan = meta.get("netpulse_plan", "monthly")
            email = (
                (obj.get("customer_details") or {}).get("email")
                or obj.get("customer_email")
                or meta.get("subscriber_email")
                or "subscriber@netpulse.io"
            )
            minted = self.mint_license_key(
                tier=tier,
                plan=plan,
                email=email,
                stripe_session_id=session_id,
                stripe_customer_id=str(obj.get("customer", "")),
            )
            self.activate_license_key(minted["license_key"])
            if ev_id:
                self._set_config(f"webhook_processed_{ev_id}", str(int(time.time())))
            return {"ok": True, "event": ev_type, "minted": minted}

        if ev_type == "customer.subscription.deleted":
            cust_id = str(obj.get("customer", "") or "")
            sub_session = str(obj.get("id", "") or "")
            revoked_jtis: List[str] = []
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    """
                    SELECT jti FROM minted_licenses
                    WHERE (stripe_customer_id != '' AND stripe_customer_id = ?)
                       OR (stripe_session_id != '' AND stripe_session_id = ?)
                    """,
                    (cust_id, sub_session),
                ).fetchall()
                revoked_jtis = [str(r["jti"]) for r in rows]
                for jti in revoked_jtis:
                    conn.execute("UPDATE minted_licenses SET revoked = 1 WHERE jti = ?", (jti,))
                conn.commit()
            # If any revoked key was the active one, drop it (verifier now flags revoked).
            active_key = self._get_config("active_license_key", "")
            if active_key:
                ver = self.verify_license_key(active_key)
                if not ver.get("valid"):
                    self._set_config("active_license_key", "")
            if ev_id:
                self._set_config(f"webhook_processed_{ev_id}", str(int(time.time())))
            return {"ok": True, "event": ev_type, "revoked_jtis": revoked_jtis}

        if ev_id:
            self._set_config(f"webhook_processed_{ev_id}", str(int(time.time())))
        return {"ok": True, "event": ev_type, "ignored": True}

    def capture_lead_and_issue_trial(
        self,
        email: str,
        source: str = "pricing_storefront",
        use_case: str = "prosumer",
    ) -> Dict[str, Any]:
        """Record a marketing lead in SQLite and automatically issue a 7-day Pro Guardian trial key.

        Trial is enforced ONCE per node (same gate as start_free_trial) to prevent
        unlimited trial minting via repeated lead submissions.
        """
        clean_email = (email or "").strip().lower()
        if not clean_email or "@" not in clean_email:
            return {"ok": False, "error": "Please provide a valid email address."}
        already_claimed = self._get_config("trial_claimed", "")
        if already_claimed:
            # Still record the lead, but no longer mint another free trial.
            now = time.time()
            with self._lock, closing(self._connect()) as conn, conn:
                conn.execute(
                    """
                    INSERT INTO marketing_leads (email, source, use_case, trial_jti, created_at, updated_at)
                    VALUES (?, ?, ?, '', ?, ?)
                    ON CONFLICT(email) DO UPDATE SET
                        source = excluded.source,
                        use_case = excluded.use_case,
                        updated_at = excluded.updated_at
                    """,
                    (clean_email, source.strip() or "web", use_case.strip() or "general", now, now),
                )
            return {
                "ok": False,
                "already_claimed": True,
                "error": "The 7-day Pro Guardian free trial has already been used on this node.",
                "message": "Lead captured — the one-time trial was already claimed on this node.",
            }
        now = time.time()
        minted = self.mint_license_key(tier="pro", plan="trial", email=clean_email, days=7, max_nodes=3)
        with self._lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT INTO marketing_leads (email, source, use_case, trial_jti, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    source = excluded.source,
                    use_case = excluded.use_case,
                    trial_jti = excluded.trial_jti,
                    updated_at = excluded.updated_at
                """,
                (clean_email, source.strip() or "web", use_case.strip() or "general", minted["jti"], now, now),
            )
            conn.commit()
        self._set_config("trial_claimed", str(int(time.time())))
        self.activate_license_key(minted["license_key"])
        return {
            "ok": True,
            "email": clean_email,
            "source": source,
            "use_case": use_case,
            "trial_license": minted,
            "message": f"7-Day Pro Guardian Trial key minted and activated for {clean_email}!",
        }

    def list_marketing_leads(self) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM marketing_leads ORDER BY updated_at DESC LIMIT 250"
            ).fetchall()
            return [dict(r) for r in rows]


subscription_engine = SubscriptionManager()
