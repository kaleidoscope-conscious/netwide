"""
SQLite Persistence Engine for Sovereign Network Intelligence.
Stores:
- Known device inventory, first_seen / last_seen timestamps, and user trust/label customizations
- Time-series RTT latency sparklines per device
- Chronological Network Security & Presence Event Log (joins, leaves, IP shifts, app/power state shifts, vulnerabilities)
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from netwide.fingerprint import DeviceProfile

_db_dir = os.path.dirname(os.path.abspath(__file__))
_db_new = os.path.join(_db_dir, "netwide_intel.db")
_db_legacy = os.path.join(_db_dir, "netpulse_intel.db")
DB_PATH = (
    os.environ.get("NETWIDE_DB_PATH")
    or os.environ.get("NETPULSE_DB_PATH")
    or (_db_legacy if os.path.exists(_db_legacy) and not os.path.exists(_db_new) else _db_new)
)


class NetworkDatabase:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 15000;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_key TEXT PRIMARY KEY,
                    mac TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    display_name TEXT,
                    custom_name TEXT DEFAULT '',
                    brand TEXT,
                    model TEXT,
                    category TEXT,
                    icon_type TEXT,
                    os_family TEXT,
                    firmware_version TEXT,
                    serial_number TEXT,
                    vendor TEXT,
                    power_state TEXT,
                    trust_state TEXT DEFAULT 'known',
                    notes TEXT DEFAULT '',
                    first_seen REAL,
                    last_seen REAL,
                    total_scans_seen INTEGER DEFAULT 1,
                    is_online INTEGER DEFAULT 1,
                    risk_score INTEGER DEFAULT 0,
                    confidence_score INTEGER DEFAULT 50,
                    raw_json TEXT
                );

                CREATE TABLE IF NOT EXISTS latency_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_key TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    rtt_ms REAL,
                    power_state TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_latency_dev ON latency_history(device_key, timestamp DESC);

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    time_str TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    device_key TEXT,
                    ip TEXT,
                    device_name TEXT,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);

                CREATE TABLE IF NOT EXISTS events_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    time_str TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    details TEXT NOT NULL,
                    hash_version INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_ledger_ts ON events_ledger(timestamp DESC);

                CREATE TRIGGER IF NOT EXISTS trg_ledger_no_update
                BEFORE UPDATE ON events_ledger
                BEGIN
                    SELECT RAISE(FAIL, 'events_ledger is an immutable append-only ledger');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_ledger_no_delete
                BEFORE DELETE ON events_ledger
                BEGIN
                    SELECT RAISE(FAIL, 'events_ledger is an immutable append-only ledger');
                END;

                CREATE TABLE IF NOT EXISTS graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    attrs_json TEXT DEFAULT '{}',
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graph_edges (
                    src TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    weight REAL DEFAULT 0.5,
                    confidence REAL DEFAULT 0.5,
                    evidence_id TEXT DEFAULT '',
                    PRIMARY KEY (src, dst, relation)
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    claim_id TEXT NOT NULL,
                    device_key TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    ref_json TEXT DEFAULT '{}',
                    captured_at REAL NOT NULL,
                    sha256 TEXT DEFAULT '',
                    confidence_influence REAL DEFAULT 0.0
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_dev ON evidence(device_key, captured_at DESC);

                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    initiated_by TEXT DEFAULT 'operator',
                    kind TEXT NOT NULL,
                    command_json TEXT DEFAULT '{}',
                    inverse_json TEXT DEFAULT '{}',
                    status TEXT DEFAULT 'completed',
                    started_at REAL NOT NULL,
                    completed_at REAL,
                    result TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS passive_frames (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    freq INTEGER DEFAULT 0,
                    frame_type TEXT DEFAULT '',
                    bssid TEXT DEFAULT '',
                    rssi REAL DEFAULT -100,
                    len INTEGER DEFAULT 0,
                    raw_hash TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_passive_ts ON passive_frames(ts DESC);

                CREATE TABLE IF NOT EXISTS scan_strategy (
                    env_fingerprint TEXT PRIMARY KEY,
                    params_json TEXT DEFAULT '{}',
                    ucb1_stats TEXT DEFAULT '{}',
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sinkhole_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    action TEXT NOT NULL DEFAULT 'sinkhole',
                    created_by TEXT DEFAULT 'operator',
                    created_at REAL NOT NULL,
                    enabled INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS posture_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    taken_at REAL NOT NULL,
                    snapshot_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_posture_ts ON posture_snapshots(taken_at DESC);

                CREATE TABLE IF NOT EXISTS detection_rules (
                    rule_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    match_regex TEXT NOT NULL,
                    action TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )
            # v2 ledger: canonical, length-prefixed serialization. Pre-existing rows
            # keep hash_version=1 (legacy colon format) and remain verifiable.
            try:
                conn.execute("ALTER TABLE events_ledger ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column already present

    @staticmethod
    def _key_for(mac: str, ip: str) -> str:
        clean_mac = mac.upper().strip()
        if clean_mac and clean_mac != "00:00:00:00:00:00":
            return clean_mac
        return f"IP:{ip}"

    @staticmethod
    def _ledger_content_v1(prev_hash: str, ts: float, actor: str, action: str,
                           target: str, details: str) -> str:
        """Legacy (v1) ledger serialization: colon-joined, ambiguous across field boundaries."""
        return f"{prev_hash}:{ts:.6f}:{actor}:{action}:{target}:{details}"

    @staticmethod
    def _ledger_content_v2(prev_hash: str, ts: float, actor: str, action: str,
                           target: str, details: str) -> bytes:
        """
        Canonical (v2) ledger serialization: each field is length-prefixed, so no two
        different field splits can ever serialize to the same bytes.
        """
        out = bytearray()
        for field in (prev_hash, f"{ts:.6f}", actor, action, target, details):
            raw = field.encode("utf-8")
            out += len(raw).to_bytes(4, "big") + raw
        return bytes(out)

    @classmethod
    def _ledger_hash(cls, version: int, prev_hash: str, ts: float, actor: str,
                     action: str, target: str, details: str) -> str:
        if int(version or 1) >= 2:
            return hashlib.sha256(cls._ledger_content_v2(prev_hash, ts, actor, action, target, details)).hexdigest()
        return hashlib.sha256(cls._ledger_content_v1(prev_hash, ts, actor, action, target, details).encode("utf-8")).hexdigest()

    def log_event(
        self,
        conn: sqlite3.Connection,
        event_type: str,
        severity: str,
        device_key: str,
        ip: str,
        device_name: str,
        details: str,
    ) -> None:
        now = time.time()
        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        conn.execute(
            """
            INSERT INTO events (timestamp, time_str, event_type, severity, device_key, ip, device_name, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now, t_str, event_type, severity, device_key, ip, device_name, details),
        )
        self.append_ledger_entry(
            actor="netwide_guardian",
            action=event_type,
            target=f"{device_key}@{ip}",
            details=f"[{severity}] {details}",
            conn=conn,
        )

    def append_ledger_entry(
        self,
        actor: str,
        action: str,
        target: str,
        details: str,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

        def _do_insert(c: sqlite3.Connection) -> Dict[str, Any]:
            last_row = c.execute("SELECT hash FROM events_ledger ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = str(last_row["hash"]) if last_row else "0" * 64
            entry_hash = self._ledger_hash(2, prev_hash, now, actor, action, target, details)
            cur = c.execute(
                """
                INSERT INTO events_ledger (prev_hash, hash, timestamp, time_str, actor, action, target, details, hash_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 2)
                """,
                (prev_hash, entry_hash, now, t_str, actor, action, target, details),
            )
            return {
                "id": cur.lastrowid,
                "prev_hash": prev_hash,
                "hash": entry_hash,
                "timestamp": now,
                "time_str": t_str,
                "actor": actor,
                "action": action,
                "target": target,
                "details": details,
            }

        if conn is not None:
            return _do_insert(conn)
        with self._lock, self._connect() as c:
            res = _do_insert(c)
            c.commit()
            return res

    def get_ledger_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events_ledger ORDER BY id DESC LIMIT ?", (max(1, min(1000, limit)),)
            ).fetchall()
            return [dict(r) for r in rows]

    get_events_ledger = get_ledger_entries

    def verify_ledger_chain(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Verify the whole hash chain by default.

        `limit` is retained for backwards compatibility but now defaults to None
        (meaning "verify everything"). A truncated verification can no longer be
        mistaken for a full one: the result reports `complete`, the number of rows
        verified, the total row count, and the true head hash read independently
        from the ledger (not from the last row we happened to fetch).
        """
        with self._lock, self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events_ledger").fetchone()[0]
            head_row = conn.execute("SELECT hash FROM events_ledger ORDER BY id DESC LIMIT 1").fetchone()
            true_head = str(head_row["hash"]) if head_row else "0" * 64

            if limit is None:
                rows = conn.execute("SELECT * FROM events_ledger ORDER BY id ASC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events_ledger ORDER BY id ASC LIMIT ?", (max(1, int(limit)),)
                ).fetchall()

            if not rows:
                return {
                    "valid": True,
                    "count": 0,
                    "total_count": int(total),
                    "complete": int(total) == 0,
                    "status": "GENESIS_EMPTY",
                    "genesis_hash": "0" * 64,
                    "head_hash": true_head,
                    "hash_version": 2,
                }

            expected_prev = "0" * 64
            for r in rows:
                if r["prev_hash"] != expected_prev:
                    return {
                        "valid": False,
                        "broken_at_id": r["id"],
                        "expected_prev": expected_prev,
                        "actual_prev": r["prev_hash"],
                        "count": len(rows),
                        "total_count": int(total),
                        "complete": False,
                        "head_hash": true_head,
                    }
                version = int(r["hash_version"] if "hash_version" in r.keys() else 1)
                expected_hash = self._ledger_hash(
                    version, r["prev_hash"], r["timestamp"], r["actor"], r["action"], r["target"], r["details"]
                )
                if r["hash"] != expected_hash:
                    return {
                        "valid": False,
                        "broken_at_id": r["id"],
                        "expected_hash": expected_hash,
                        "actual_hash": r["hash"],
                        "count": len(rows),
                        "total_count": int(total),
                        "complete": False,
                        "head_hash": true_head,
                    }
                expected_prev = r["hash"]

            complete = len(rows) == int(total)
            versions = sorted({int(r["hash_version"] if "hash_version" in r.keys() else 1) for r in rows})
            return {
                "valid": True,
                "count": len(rows),
                "total_count": int(total),
                "complete": complete,
                "status": "CHAIN_INTEGRITY_VERIFIED" if complete else "CHAIN_PARTIAL_VERIFIED",
                "genesis_hash": rows[0]["hash"],
                "head_hash": true_head,
                "verified_head_hash": rows[-1]["hash"],
                "head_verified": rows[-1]["hash"] == true_head,
                "hash_version": max(versions),
                "hash_versions_present": versions,
            }

    def upsert_graph_node(self, node_id: str, kind: str, attrs: Dict[str, Any] | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO graph_nodes(node_id, kind, attrs_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET kind=excluded.kind, attrs_json=excluded.attrs_json, updated_at=excluded.updated_at",
                (node_id, kind, json.dumps(attrs or {}, sort_keys=True), time.time()),
            )
            conn.commit()

    def upsert_graph_edge(self, src: str, dst: str, relation: str, weight: float = 0.5, confidence: float = 0.5, evidence_id: str = "") -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO graph_edges(src, dst, relation, weight, confidence, evidence_id) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(src, dst, relation) DO UPDATE SET weight=excluded.weight, confidence=excluded.confidence, evidence_id=excluded.evidence_id",
                (src, dst, relation, float(weight), float(confidence), evidence_id),
            )
            conn.commit()

    def get_graph(self) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            nodes = [dict(r) for r in conn.execute("SELECT * FROM graph_nodes").fetchall()]
            for n in nodes:
                try:
                    n["attrs"] = json.loads(n.pop("attrs_json") or "{}")
                except Exception:
                    n["attrs"] = {}
            edges = [dict(r) for r in conn.execute("SELECT * FROM graph_edges").fetchall()]
            return {"nodes": nodes, "edges": edges, "count_nodes": len(nodes), "count_edges": len(edges)}

    def add_evidence(self, claim_id: str, device_key: str, kind: str, ref: Dict[str, Any], confidence: float = 0.0) -> int:
        ref_json = json.dumps(ref or {}, sort_keys=True)
        sha = hashlib.sha256(ref_json.encode("utf-8")).hexdigest()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO evidence(claim_id, device_key, kind, ref_json, captured_at, sha256, confidence_influence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (claim_id, device_key, kind, ref_json, time.time(), sha, float(confidence)),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def get_evidence(self, device_key: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE device_key = ? ORDER BY captured_at DESC LIMIT ?",
                (device_key, max(1, limit)),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                try:
                    d["ref"] = json.loads(d.pop("ref_json") or "{}")
                except Exception:
                    d["ref"] = {}
                out.append(d)
            return out

    def record_action(self, kind: str, command: Dict[str, Any], inverse: Dict[str, Any] | None = None, initiated_by: str = "operator", result: str = "") -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO actions(initiated_by, kind, command_json, inverse_json, status, started_at, completed_at, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (initiated_by, kind, json.dumps(command or {}), json.dumps(inverse or {}), "completed", time.time(), time.time(), result),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def list_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (max(1, limit),)).fetchall()
            return [dict(r) for r in rows]

    def save_scan_strategy(self, env_fingerprint: str, params: Dict[str, Any], stats: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_strategy(env_fingerprint, params_json, ucb1_stats, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(env_fingerprint) DO UPDATE SET params_json=excluded.params_json, ucb1_stats=excluded.ucb1_stats, updated_at=excluded.updated_at",
                (env_fingerprint, json.dumps(params, sort_keys=True), json.dumps(stats, sort_keys=True), time.time()),
            )
            conn.commit()

    def get_scan_strategy(self, env_fingerprint: str) -> Dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scan_strategy WHERE env_fingerprint = ?", (env_fingerprint,)).fetchone()
            if not row:
                return None
            d = dict(row)
            try:
                d["params"] = json.loads(d.pop("params_json") or "{}")
                d["stats"] = json.loads(d.pop("ucb1_stats") or "{}")
            except Exception:
                d["params"], d["stats"] = {}, {}
            return d

    def add_sinkhole_rule(self, domain: str, action: str = "sinkhole", created_by: str = "operator") -> int:
        clean = str(domain or "").strip().lower()
        if not clean:
            raise ValueError("domain required")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sinkhole_rules(domain, action, created_by, created_at, enabled) VALUES (?, ?, ?, ?, 1)",
                (clean, action, created_by, time.time()),
            )
            conn.commit()
            row = conn.execute("SELECT id FROM sinkhole_rules WHERE domain = ?", (clean,)).fetchone()
            return int(row["id"]) if row else 0

    def list_sinkhole_rules(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM sinkhole_rules ORDER BY domain ASC").fetchall()
            return [dict(r) for r in rows]

    def delete_sinkhole_rule(self, domain: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM sinkhole_rules WHERE domain = ?", (str(domain or "").strip().lower(),))
            conn.commit()
            return cur.rowcount > 0

    def save_rule(self, rule: Dict[str, Any], sha256: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO detection_rules(rule_id, title, severity, category, match_regex, action, sha256, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (str(rule.get("id")), str(rule.get("title")), str(rule.get("severity")).upper(), str(rule.get("category")), str(rule.get("match")), str(rule.get("action")), str(sha256), time.time()),
            )
            conn.commit()

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM detection_rules ORDER BY rule_id ASC").fetchall()
            return [dict(r) for r in rows]

    def save_posture_snapshot(self, snapshot: Dict[str, Any]) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO posture_snapshots(taken_at, snapshot_json) VALUES (?, ?)",
                (time.time(), json.dumps(snapshot)),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def count_passive_frames(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM passive_frames").fetchone()
            return int(row["n"] if row else 0)

    def recent_passive_frames(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM passive_frames ORDER BY id DESC LIMIT ?", (max(1, limit),)).fetchall()
            return [dict(r) for r in rows]

    def get_last_snapshots(self, limit: int = 2) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM posture_snapshots ORDER BY id DESC LIMIT ?", (max(1, limit),)).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                try:
                    out.append({"id": r["id"], "taken_at": r["taken_at"], "snapshot": json.loads(r["snapshot_json"] or "{}")})
                except Exception:
                    out.append({"id": r["id"], "taken_at": r["taken_at"], "snapshot": {}})
            return out

    def get_action(self, action_id: int) -> Dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
            return dict(row) if row else None

    def mark_action_undone(self, action_id: int) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE actions SET status = 'undone' WHERE id = ?", (action_id,))
            conn.commit()
            return cur.rowcount > 0

    def record_passive_frame(self, ts: float, freq: int, frame_type: str, bssid: str, rssi: float, length: int) -> None:
        raw = f"{ts}:{bssid}:{frame_type}:{length}"
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO passive_frames(ts, freq, frame_type, bssid, rssi, len, raw_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (float(ts), int(freq or 0), str(frame_type or ""), str(bssid or "").upper(), float(rssi or -100), int(length or 0), h),
            )
            # Cap ring at 500k rows to bound growth
            conn.execute("DELETE FROM passive_frames WHERE id NOT IN (SELECT id FROM passive_frames ORDER BY id DESC LIMIT 500000)")
            conn.commit()

    def sync_graph_from_state(self, devices: List[Dict[str, Any]], aps: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        nodes = edges = 0
        aps = aps or []
        with self._lock, self._connect() as conn:
            for d in devices or []:
                key = str(d.get("device_key") or d.get("mac") or d.get("ip") or "")
                if not key:
                    continue
                kind = "network_device"
                attrs = {"brand": d.get("brand"), "model": d.get("model"), "category": d.get("category")}
                conn.execute(
                    "INSERT INTO graph_nodes(node_id, kind, attrs_json, updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET kind=excluded.kind, attrs_json=excluded.attrs_json, updated_at=excluded.updated_at",
                    (key, kind, json.dumps(attrs, sort_keys=True), time.time()),
                )
                nodes += 1
            gw = next((d for d in (devices or []) if d.get("is_gateway")), None)
            if gw:
                gk = str(gw.get("device_key") or gw.get("mac") or "")
                for d in devices or []:
                    if d is gw:
                        continue
                    dk = str(d.get("device_key") or d.get("mac") or "")
                    if not dk:
                        continue
                    conn.execute(
                        "INSERT INTO graph_edges(src, dst, relation, weight, confidence, evidence_id) VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(src, dst, relation) DO UPDATE SET weight=excluded.weight, confidence=excluded.confidence",
                        (gk, dk, "talks_to", 0.8, 0.85, ""),
                    )
                    edges += 1
            for a in aps:
                bssid = str(a.get("bssid") or "")
                if not bssid:
                    continue
                conn.execute(
                    "INSERT INTO graph_nodes(node_id, kind, attrs_json, updated_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(node_id) DO UPDATE SET attrs_json=excluded.attrs_json, updated_at=excluded.updated_at",
                    (bssid, "wireless_ap", json.dumps({"channel": a.get("channel"), "verdict": a.get("attribution_verdict")}, sort_keys=True), time.time()),
                )
                nodes += 1
                parent = str(a.get("de_cloaked_parent") or a.get("linked_lan_ip") or "")
                if parent:
                    conn.execute(
                        "INSERT INTO graph_edges(src, dst, relation, weight, confidence, evidence_id) VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(src, dst, relation) DO UPDATE SET weight=excluded.weight, confidence=excluded.confidence",
                        (bssid, parent, "same_radio", 0.7, float(a.get("attribution_confidence") or 0.6), str(a.get("attribution_proof") or "")[:64]),
                    )
                    edges += 1
            conn.commit()
        return {"ok": True, "nodes": nodes, "edges": edges}

    def sync_scan_results(self, active_profiles: List[DeviceProfile]) -> List[Dict[str, Any]]:
        """
        Persist newly scanned profiles, detect state transitions (new device, offline->online,
        IP change, power/app change, critical security findings), and enrich profiles with
        historical first_seen, user customizations, and latency sparklines.
        """
        now = time.time()
        seen_keys = set()

        with self._lock, self._connect() as conn:
            existing_rows = {
                row["device_key"]: dict(row)
                for row in conn.execute("SELECT * FROM devices").fetchall()
            }

            for prof in active_profiles:
                dkey = self._key_for(prof.mac, prof.ip)
                seen_keys.add(dkey)
                prev = existing_rows.get(dkey)

                if prev is None:
                    # Brand-new device discovered
                    prof.first_seen = now
                    prof.last_seen = now
                    self.log_event(
                        conn,
                        "DEVICE_DISCOVERED",
                        "WARNING" if prof.is_randomized_mac else "INFO",
                        dkey,
                        prof.ip,
                        prof.display_name,
                        f"Discovered {prof.category} ({prof.vendor}) at {prof.ip} [{prof.mac}] with {prof.confidence_score}% confidence.",
                    )
                    for finding in prof.security_findings:
                        if finding.get("severity") in ("CRITICAL", "HIGH"):
                            self.log_event(
                                conn,
                                "SECURITY_ALERT",
                                finding["severity"],
                                dkey,
                                prof.ip,
                                prof.display_name,
                                f"{finding['title']}: {finding['description']}",
                            )
                else:
                    prof.first_seen = prev["first_seen"] or now
                    prof.last_seen = now
                    prof.custom_name = prev.get("custom_name") or ""
                    prof.trust_state = prev.get("trust_state") or "known"
                    prof.notes = prev.get("notes") or ""

                    if not prev.get("is_online"):
                        self.log_event(
                            conn,
                            "DEVICE_ONLINE",
                            "INFO",
                            dkey,
                            prof.ip,
                            prof.custom_name or prof.display_name,
                            f"Device rejoined network at {prof.ip} ({prof.power_state}).",
                        )
                    if prev.get("ip") and prev["ip"] != prof.ip:
                        self.log_event(
                            conn,
                            "IP_CHANGED",
                            "WARNING",
                            dkey,
                            prof.ip,
                            prof.custom_name or prof.display_name,
                            f"DHCP address changed from {prev['ip']} -> {prof.ip}.",
                        )
                    if prev.get("power_state") and prev["power_state"] != prof.power_state:
                        # Log meaningful power/app transitions (skip minor DTIM ms fluctuations)
                        if not (prev["power_state"].startswith("POWERSAVE") and prof.power_state.startswith("POWERSAVE")):
                            self.log_event(
                                conn,
                                "STATE_CHANGE",
                                "INFO",
                                dkey,
                                prof.ip,
                                prof.custom_name or prof.display_name,
                                f"State transitioned: '{prev['power_state']}' -> '{prof.power_state}'.",
                            )
                    # Port-Change & Service-Diff Alerting
                    try:
                        prev_raw = json.loads(prev["raw_json"]) if prev.get("raw_json") else {}
                        prev_ports = set(prev_raw.get("open_ports") or [])
                        curr_ports = set(prof.open_ports or [])
                        newly_opened = sorted(curr_ports - prev_ports)
                        if newly_opened and prev_ports:
                            sev = "CRITICAL" if any(p in (23, 5555, 5900, 445, 3389, 2375) for p in newly_opened) else "WARNING"
                            self.log_event(
                                conn,
                                "PORT_OPENED",
                                sev,
                                dkey,
                                prof.ip,
                                prof.custom_name or prof.display_name,
                                f"New TCP service port(s) opened: {newly_opened} (previously {sorted(prev_ports)}).",
                            )
                        newly_closed = sorted(prev_ports - curr_ports)
                        if newly_closed and curr_ports:
                            self.log_event(
                                conn,
                                "PORT_CLOSED",
                                "INFO",
                                dkey,
                                prof.ip,
                                prof.custom_name or prof.display_name,
                                f"TCP service port(s) closed: {newly_closed} (remaining {sorted(curr_ports)}).",
                            )
                    except Exception:
                        pass

                # Upsert device record
                raw_dict = prof.to_dict()
                conn.execute(
                    """
                    INSERT INTO devices (
                        device_key, mac, ip, display_name, custom_name, brand, model, category,
                        icon_type, os_family, firmware_version, serial_number, vendor, power_state,
                        trust_state, notes, first_seen, last_seen, total_scans_seen, is_online,
                        risk_score, confidence_score, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?)
                    ON CONFLICT(device_key) DO UPDATE SET
                        ip = excluded.ip,
                        display_name = CASE
                            WHEN excluded.confidence_score >= devices.confidence_score OR devices.display_name = '' OR devices.display_name = devices.ip OR devices.display_name LIKE '%(%.'
                            THEN excluded.display_name ELSE devices.display_name END,
                        brand = CASE
                            WHEN excluded.confidence_score >= devices.confidence_score OR devices.brand = '' OR devices.brand LIKE '%Unknown%'
                            THEN excluded.brand ELSE devices.brand END,
                        model = CASE
                            WHEN excluded.confidence_score >= devices.confidence_score OR devices.model = '' OR devices.model LIKE '%Generic%' OR devices.model LIKE '%Network Device%'
                            THEN excluded.model ELSE devices.model END,
                        category = CASE
                            WHEN excluded.confidence_score >= devices.confidence_score OR devices.category = '' OR devices.category = 'Network Endpoint'
                            THEN excluded.category ELSE devices.category END,
                        icon_type = CASE
                            WHEN excluded.confidence_score >= devices.confidence_score OR devices.icon_type = 'device'
                            THEN excluded.icon_type ELSE devices.icon_type END,
                        os_family = CASE
                            WHEN excluded.os_family != 'Unknown OS' THEN excluded.os_family ELSE devices.os_family END,
                        firmware_version = CASE WHEN excluded.firmware_version != '' THEN excluded.firmware_version ELSE devices.firmware_version END,
                        serial_number = CASE WHEN excluded.serial_number != '' THEN excluded.serial_number ELSE devices.serial_number END,
                        vendor = CASE WHEN excluded.vendor != 'Unknown Vendor' THEN excluded.vendor ELSE devices.vendor END,
                        power_state = excluded.power_state,
                        last_seen = excluded.last_seen,
                        total_scans_seen = devices.total_scans_seen + 1,
                        is_online = 1,
                        risk_score = excluded.risk_score,
                        confidence_score = MAX(devices.confidence_score, excluded.confidence_score),
                        raw_json = CASE
                            WHEN excluded.confidence_score >= devices.confidence_score THEN excluded.raw_json
                            ELSE devices.raw_json END
                    """,
                    (
                        dkey,
                        prof.mac,
                        prof.ip,
                        prof.display_name,
                        prof.custom_name,
                        prof.brand,
                        prof.model,
                        prof.category,
                        prof.icon_type,
                        prof.os_family,
                        prof.firmware_version,
                        prof.serial_number,
                        prof.vendor,
                        prof.power_state,
                        prof.trust_state,
                        prof.notes,
                        prof.first_seen,
                        prof.last_seen,
                        prof.risk_score,
                        prof.confidence_score,
                        json.dumps(raw_dict),
                    ),
                )

                # Record latency sample
                if prof.rtt_ms is not None:
                    conn.execute(
                        """
                        INSERT INTO latency_history (device_key, ip, timestamp, rtt_ms, power_state)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (dkey, prof.ip, now, prof.rtt_ms, prof.power_state),
                    )

            # Check for previously online devices that went offline (grace window: 120 seconds)
            for dkey, prev in existing_rows.items():
                if dkey not in seen_keys and prev.get("is_online") == 1:
                    if now - (prev.get("last_seen") or 0) > 90:
                        conn.execute("UPDATE devices SET is_online = 0, power_state = 'OFFLINE' WHERE device_key = ?", (dkey,))
                        self.log_event(
                            conn,
                            "DEVICE_OFFLINE",
                            "WARNING",
                            dkey,
                            prev.get("ip", ""),
                            prev.get("custom_name") or prev.get("display_name", dkey),
                            f"Device went offline (last seen at {prev.get('ip')}).",
                        )

            conn.commit()
            return self._fetch_all_enriched(conn)

    def _fetch_all_enriched(self, conn: sqlite3.Connection) -> List[Dict[str, Any]]:
        now_ts = time.time()
        cutoff_24h = now_ts - 86400.0
        # Pre-aggregate 24-hour hourly presence buckets across all devices in one query
        bucket_rows = conn.execute(
            """
            SELECT device_key,
                   CAST((timestamp - ?) / 3600 AS INTEGER) AS hr_idx,
                   COUNT(*) AS samples,
                   AVG(rtt_ms) AS avg_rtt
            FROM latency_history
            WHERE timestamp >= ?
            GROUP BY device_key, hr_idx
            """,
            (cutoff_24h, cutoff_24h),
        ).fetchall()
        dev_hourly: Dict[str, Dict[int, Dict[str, Any]]] = {}
        for br in bucket_rows:
            idx = max(0, min(23, int(br["hr_idx"] or 0)))
            dev_hourly.setdefault(br["device_key"], {})[idx] = {
                "samples": int(br["samples"] or 0),
                "avg_rtt_ms": round(float(br["avg_rtt"]), 2) if br["avg_rtt"] is not None else None,
            }

        rows = conn.execute("SELECT * FROM devices ORDER BY is_online DESC, ip ASC").fetchall()
        enriched: List[Dict[str, Any]] = []
        for row in rows:
            dkey = row["device_key"]
            try:
                data = json.loads(row["raw_json"]) if row["raw_json"] else dict(row)
            except Exception:
                data = dict(row)

            data["device_key"] = dkey
            data["ip"] = row["ip"]
            data["mac"] = row["mac"]
            data["display_name"] = row["display_name"]
            data["brand"] = row["brand"]
            data["model"] = row["model"]
            data["category"] = row["category"]
            data["icon_type"] = row["icon_type"]
            data["os_family"] = row["os_family"]
            data["firmware_version"] = row["firmware_version"]
            data["serial_number"] = row["serial_number"]
            data["vendor"] = row["vendor"]
            data["confidence_score"] = row["confidence_score"]
            data["risk_score"] = row["risk_score"]
            data["is_online"] = bool(row["is_online"])
            data["custom_name"] = row["custom_name"] or ""
            data["trust_state"] = row["trust_state"] or "known"
            data["notes"] = row["notes"] or ""
            data["first_seen"] = row["first_seen"]
            data["last_seen"] = row["last_seen"]
            data["total_scans_seen"] = row["total_scans_seen"]
            if not data["is_online"]:
                data["power_state"] = "OFFLINE"

            if not data.get("hardware_specs"):
                data["hardware_specs"] = {
                    "IPv4 Address": data.get("ip", ""),
                    "Primary MAC (L2)": data.get("mac", ""),
                    "NIC Manufacturer (OUI)": f"{data.get('vendor', 'Unknown')} ({data.get('oui_prefix', '')})",
                    "IEEE Registry Class": data.get("registry_type", "IEEE MA-L (24-bit)"),
                    "IEEE 802 MAC Type": "Locally Administered (U/L=1 Randomized)" if data.get("is_randomized_mac") else "Universally Administered Burned-In (U/L=0)",
                    "Power / Radio State": data.get("power_state", "OFFLINE"),
                    "Neighbor Cache State": data.get("neigh_state", "OFFLINE"),
                }
            if not data.get("control_capabilities"):
                data["control_capabilities"] = [
                    "IEEE 802 Wake-on-LAN (Magic Packet)",
                    "ICMP / TCP Latency & Jitter Burst",
                    "MTR Multi-Hop Path Trace",
                    "Deep Nmap Service & Version Scan",
                    "Custom Port Range & HTTP Probe",
                ]

            # Attach last 25 latency samples for sparklines
            lat_rows = conn.execute(
                "SELECT timestamp, rtt_ms FROM latency_history WHERE device_key = ? ORDER BY timestamp DESC LIMIT 25",
                (dkey,),
            ).fetchall()
            sparkline = [round(r["rtt_ms"], 2) for r in reversed(lat_rows) if r["rtt_ms"] is not None]
            data["latency_sparkline"] = sparkline
            if sparkline:
                data["avg_rtt_ms"] = round(sum(sparkline) / len(sparkline), 2)
                data["min_rtt_ms"] = round(min(sparkline), 2)
                data["max_rtt_ms"] = round(max(sparkline), 2)
                data["jitter_ms"] = round(max(sparkline) - min(sparkline), 2)
            else:
                data["avg_rtt_ms"] = data.get("rtt_ms")
                data["min_rtt_ms"] = data.get("rtt_ms")
                data["max_rtt_ms"] = data.get("rtt_ms")
                data["jitter_ms"] = 0.0

            # Build 24-hour presence & availability heatmap timeline
            hr_map = dev_hourly.get(dkey, {})
            timeline_24h: List[Dict[str, Any]] = []
            active_hrs = 0
            for h_i in range(24):
                slot_ts = cutoff_24h + h_i * 3600.0
                hr_label = time.strftime("%H:00", time.localtime(slot_ts))
                b_info = hr_map.get(h_i)
                if b_info and b_info["samples"] > 0:
                    active_hrs += 1
                    timeline_24h.append({
                        "hour": hr_label,
                        "status": "ONLINE",
                        "samples": b_info["samples"],
                        "avg_rtt_ms": b_info["avg_rtt_ms"],
                    })
                elif h_i == 23 and data["is_online"]:
                    active_hrs += 1
                    timeline_24h.append({
                        "hour": hr_label,
                        "status": "ONLINE",
                        "samples": 1,
                        "avg_rtt_ms": data.get("rtt_ms"),
                    })
                else:
                    timeline_24h.append({
                        "hour": hr_label,
                        "status": "OFFLINE",
                        "samples": 0,
                        "avg_rtt_ms": None,
                    })
            data["presence_24h"] = timeline_24h
            data["uptime_24h_pct"] = round((active_hrs / 24.0) * 100.0, 1)

            enriched.append(data)

        # Sort Online Gateway first, then online devices by numeric IP, then offline
        def _sort_key(d: Dict[str, Any]) -> Any:
            parts = [int(x) if x.isdigit() else 0 for x in d.get("ip", "0.0.0.0").split(".")]
            is_on = bool(d.get("is_online"))
            is_gw = bool(d.get("is_gateway"))
            if is_gw and is_on:
                tier = 0
            elif is_on:
                tier = 1
            elif is_gw:
                tier = 2
            else:
                tier = 3
            return (tier, parts)

        enriched.sort(key=_sort_key)
        return enriched

    def get_all_devices(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            return self._fetch_all_enriched(conn)

    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def update_device_customization(
        self,
        device_key: str,
        custom_name: Optional[str] = None,
        trust_state: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_key = ? OR ip = ?",
                (device_key, device_key),
            ).fetchone()
            if not row:
                return None
            actual_key = str(row["device_key"])
            new_name = custom_name if custom_name is not None else row["custom_name"]
            new_trust = trust_state if trust_state is not None else row["trust_state"]
            new_notes = notes if notes is not None else row["notes"]
            conn.execute(
                "UPDATE devices SET custom_name = ?, trust_state = ?, notes = ? WHERE device_key = ?",
                (new_name, new_trust, new_notes, actual_key),
            )
            self.log_event(
                conn,
                "DEVICE_UPDATED",
                "INFO",
                actual_key,
                row["ip"],
                new_name or row["display_name"],
                f"Updated metadata: Label='{new_name}', Trust='{new_trust}'.",
            )
            conn.commit()
            all_devs = self._fetch_all_enriched(conn)
            return next((d for d in all_devs if d["device_key"] == actual_key), None)

    def delete_device(self, device_key: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_key = ? OR ip = ?",
                (device_key, device_key),
            ).fetchone()
            if not row:
                return False
            actual_key = str(row["device_key"])
            conn.execute("DELETE FROM latency_history WHERE device_key = ?", (actual_key,))
            conn.execute("DELETE FROM devices WHERE device_key = ?", (actual_key,))
            self.log_event(
                conn,
                "DEVICE_REMOVED",
                "INFO",
                actual_key,
                row["ip"],
                row["custom_name"] or row["display_name"] or actual_key,
                f"Removed device {actual_key} ({row['ip']}) from persistent inventory.",
            )
            conn.commit()
            return True

    def get_network_analytics(self) -> Dict[str, Any]:
        """
        Compute 24-hour SQLite telemetry analytics across all devices, RTT samples, and security events.
        """
        cutoff_24h = time.time() - 86400.0
        with self._lock, self._connect() as conn:
            dev_rows = conn.execute("SELECT * FROM devices").fetchall()
            lat_row = conn.execute(
                """
                SELECT COUNT(*) AS samples,
                       AVG(rtt_ms) AS avg_rtt,
                       MIN(rtt_ms) AS min_rtt,
                       MAX(rtt_ms) AS max_rtt
                FROM latency_history
                WHERE timestamp >= ? AND rtt_ms IS NOT NULL
                """,
                (cutoff_24h,),
            ).fetchone()
            ev_rows = conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM events WHERE timestamp >= ? GROUP BY severity",
                (cutoff_24h,),
            ).fetchall()

        cat_dist: Dict[str, int] = {}
        vendor_dist: Dict[str, int] = {}
        trust_dist: Dict[str, int] = {}
        online_cnt = 0
        rand_cnt = 0
        high_risk_cnt = 0
        top_risk: List[Dict[str, Any]] = []

        for r in dev_rows:
            cat = r["category"] or "Network Endpoint"
            cat_dist[cat] = cat_dist.get(cat, 0) + 1
            vnd = r["brand"] or r["vendor"] or "Unknown"
            vendor_dist[vnd] = vendor_dist.get(vnd, 0) + 1
            tr = r["trust_state"] or "known"
            trust_dist[tr] = trust_dist.get(tr, 0) + 1
            if r["is_online"]:
                online_cnt += 1
            try:
                raw = json.loads(r["raw_json"]) if r["raw_json"] else {}
                if raw.get("is_randomized_mac"):
                    rand_cnt += 1
            except Exception:
                pass
            rscore = int(r["risk_score"] or 0)
            if rscore >= 25:
                high_risk_cnt += 1
            top_risk.append({
                "device_key": r["device_key"],
                "ip": r["ip"],
                "name": r["custom_name"] or r["display_name"] or r["ip"],
                "risk_score": rscore,
                "is_online": bool(r["is_online"]),
            })

        top_risk.sort(key=lambda x: (-x["risk_score"], x["ip"]))
        sev_counts = {r["severity"]: int(r["cnt"]) for r in ev_rows}

        return {
            "total_devices": len(dev_rows),
            "online_devices": online_cnt,
            "offline_devices": max(0, len(dev_rows) - online_cnt),
            "randomized_mac_devices": rand_cnt,
            "high_risk_devices": high_risk_cnt,
            "subnet_rtt_24h": {
                "samples": int(lat_row["samples"] or 0) if lat_row else 0,
                "avg_rtt_ms": round(float(lat_row["avg_rtt"]), 2) if lat_row and lat_row["avg_rtt"] is not None else None,
                "min_rtt_ms": round(float(lat_row["min_rtt"]), 2) if lat_row and lat_row["min_rtt"] is not None else None,
                "max_rtt_ms": round(float(lat_row["max_rtt"]), 2) if lat_row and lat_row["max_rtt"] is not None else None,
            },
            "category_distribution": cat_dist,
            "category_breakdown": cat_dist,
            "vendor_breakdown": vendor_dist,
            "trust_distribution": trust_dist,
            "event_severity_24h": sev_counts,
            "top_risk_hosts": top_risk[:6],
        }


net_db = NetworkDatabase()
