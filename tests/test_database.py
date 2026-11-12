"""
Unit tests for Netwide SQLite persistence engine and event logging.
"""

import os
import tempfile
import time

from netwide.database import NetworkDatabase
from netwide.fingerprint import DeviceProfile


def test_database_init_wal():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = NetworkDatabase(db_path)
        with db._connect() as conn:
            mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            assert mode.upper() == "WAL"


def test_sync_scan_results_preserves_high_confidence():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = NetworkDatabase(db_path)

        # 1. High confidence scan
        p1 = DeviceProfile(
            ip="192.168.1.1",
            mac="18:A5:FF:0C:62:3A",
            display_name="T-Mobile 5G Gateway (TMO-G4AR)",
            brand="Arcadyan",
            model="TMO-G4AR",
            category="5G NR Cellular Gateway / Router",
            icon_type="router",
            confidence_score=100,
            is_gateway=True,
            first_seen=time.time(),
            last_seen=time.time(),
        )
        db.sync_scan_results([p1])
        devs = db.get_all_devices()
        assert len(devs) == 1
        assert devs[0]["display_name"] == "T-Mobile 5G Gateway (TMO-G4AR)"
        assert devs[0]["category"] == "5G NR Cellular Gateway / Router"

        # 2. Lower confidence scan (e.g. transient timeout fallback)
        p2 = DeviceProfile(
            ip="192.168.1.1",
            mac="18:A5:FF:0C:62:3A",
            display_name="Arcadyan Technology Corporation (192.168.1.1)",
            brand="Arcadyan Technology Corporation",
            model="Arcadyan Technology Corporation Network Device",
            category="Network Endpoint",
            icon_type="device",
            confidence_score=50,
            is_gateway=True,
            first_seen=time.time(),
            last_seen=time.time(),
        )
        db.sync_scan_results([p2])
        devs2 = db.get_all_devices()
        assert len(devs2) == 1
        # High confidence display_name and category must NOT be overwritten!
        assert devs2[0]["display_name"] == "T-Mobile 5G Gateway (TMO-G4AR)"
        assert devs2[0]["category"] == "5G NR Cellular Gateway / Router"
        assert devs2[0]["icon_type"] == "router"
        assert devs2[0]["confidence_score"] == 100


def test_update_device_customization():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = NetworkDatabase(db_path)

        p = DeviceProfile(
            ip="192.168.1.50",
            mac="AA:BB:CC:DD:EE:FF",
            display_name="Generic Host",
            confidence_score=60,
        )
        db.sync_scan_results([p])

        updated = db.update_device_customization(
            device_key="AA:BB:CC:DD:EE:FF",
            custom_name="Master Bedroom TV",
            trust_state="trusted",
            notes="Mounted on north wall",
        )
        assert updated is not None
        assert updated["custom_name"] == "Master Bedroom TV"
        assert updated["trust_state"] == "trusted"
        assert updated["notes"] == "Mounted on north wall"

        events = db.get_recent_events(10)
        assert any(e["event_type"] == "DEVICE_UPDATED" for e in events)


def test_port_opened_event_and_24h_presence():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = NetworkDatabase(db_path)

        p1 = DeviceProfile(
            ip="192.168.1.99",
            mac="11:22:33:44:55:66",
            display_name="Core Workstation",
            open_ports=[22, 80],
            port_services={22: "SSH", 80: "HTTP"},
            rtt_ms=2.4,
        )
        db.sync_scan_results([p1])

        # Second scan opens port 445 (SMB) and 3389 (RDP)
        p2 = DeviceProfile(
            ip="192.168.1.99",
            mac="11:22:33:44:55:66",
            display_name="Core Workstation",
            open_ports=[22, 80, 445, 3389],
            port_services={22: "SSH", 80: "HTTP", 445: "SMB", 3389: "RDP"},
            rtt_ms=3.1,
        )
        db.sync_scan_results([p2])

        events = db.get_recent_events(10)
        port_events = [e for e in events if e["event_type"] == "PORT_OPENED"]
        assert len(port_events) == 1
        assert "445" in port_events[0]["details"]
        assert "3389" in port_events[0]["details"]

        devs = db.get_all_devices()
        assert len(devs) == 1
        assert "presence_24h" in devs[0]
        assert len(devs[0]["presence_24h"]) == 24
        assert devs[0]["presence_24h"][-1]["status"] == "ONLINE"
        assert devs[0]["uptime_24h_pct"] > 0

        # Third scan closes port 3389
        p3 = DeviceProfile(
            ip="192.168.1.99",
            mac="11:22:33:44:55:66",
            display_name="Core Workstation",
            open_ports=[22, 80, 445],
            port_services={22: "SSH", 80: "HTTP", 445: "SMB"},
            rtt_ms=2.8,
        )
        db.sync_scan_results([p3])
        events2 = db.get_recent_events(15)
        closed_events = [e for e in events2 if e["event_type"] == "PORT_CLOSED"]
        assert len(closed_events) == 1
        assert "3389" in closed_events[0]["details"]


def test_network_analytics_and_delete_device():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = NetworkDatabase(db_path)

        p = DeviceProfile(
            ip="192.168.1.77",
            mac="CC:DD:EE:11:22:33",
            display_name="Sonos Era 300",
            brand="Sonos, Inc.",
            category="Smart Speaker / Media",
            open_ports=[1400],
            rtt_ms=4.2,
        )
        db.sync_scan_results([p])

        analytics = db.get_network_analytics()
        assert analytics["total_devices"] == 1
        assert analytics["online_devices"] == 1
        assert "Smart Speaker / Media" in analytics["category_breakdown"]
        assert "Sonos, Inc." in analytics["vendor_breakdown"]

        deleted = db.delete_device("CC:DD:EE:11:22:33")
        assert deleted is True
        assert len(db.get_all_devices()) == 0


def test_tamper_evident_events_ledger():
    import sqlite3
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ledger.db")
        db = NetworkDatabase(db_path)

        # 1. Empty ledger verification
        assert db.verify_ledger_chain()["valid"] is True
        assert db.verify_ledger_chain()["count"] == 0

        # 2. Append entries
        e1 = db.append_ledger_entry("operator", "QUARANTINE_ENGAGE", "192.168.1.50", "Isolating rogue device")
        e2 = db.append_ledger_entry("netwide_guardian", "SECURITY_ALERT", "192.168.1.50", "ARP spoofing attempt detected")
        e3 = db.append_ledger_entry("operator", "QUARANTINE_RELEASE", "192.168.1.50", "Released host")

        assert e2["prev_hash"] == e1["hash"]
        assert e3["prev_hash"] == e2["hash"]

        ver = db.verify_ledger_chain()
        assert ver["valid"] is True
        assert ver["count"] == 3
        assert ver["genesis_hash"] == e1["hash"]
        assert ver["head_hash"] == e3["hash"]

        entries = db.get_ledger_entries(10)
        assert len(entries) == 3

        # 3. Test append-only trigger immutability (UPDATE and DELETE prohibited)
        with db._connect() as conn:
            import pytest
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute("UPDATE events_ledger SET details = 'tampered' WHERE id = 1")

            with pytest.raises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM events_ledger WHERE id = 1")


