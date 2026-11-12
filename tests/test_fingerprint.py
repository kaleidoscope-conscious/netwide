"""
Unit tests for Netwide device fingerprinting and threat analysis.
"""

from netwide.fingerprint import (
    audit_network_threats,
    compute_network_security_posture,
    synthesize_device_profile,
)
from netwide.wireless import MobileFieldTelemetryHub, WirelessSpectrumEngine


def test_gateway_classification_with_tmobile():
    base_host = {
        "mac": "18:A5:FF:0C:62:3A",
        "is_local": False,
        "is_gateway": True,
        "neigh_state": "REACHABLE",
    }
    # Mocking forbidden in prod, but pure data payload passing to synthesize_device_profile
    prof = synthesize_device_profile(
        ip="192.168.1.1",
        base_host=base_host,
        mdns_list=[],
        upnp_data={},
    )
    assert prof.is_gateway
    assert prof.category == "Network Gateway / Router"
    assert prof.icon_type == "router"
    assert prof.confidence_score >= 85


def test_local_host_classification():
    base_host = {
        "mac": "00:42:38:AB:02:8E",
        "is_local": True,
        "is_gateway": False,
        "neigh_state": "LOCAL_HOST",
    }
    prof = synthesize_device_profile(
        ip="192.168.1.225",
        base_host=base_host,
        mdns_list=[],
        upnp_data={},
    )
    assert prof.is_local
    assert prof.category == "Workstation / Scanner Host"
    assert prof.icon_type == "laptop"
    assert prof.confidence_score == 100


def test_audit_network_threats_rogue_ap():
    devices = []
    wifi_spectrum = {
        "access_points": [
            {
                "ssid": "Home-Network",
                "bssid": "00:11:22:33:44:55",
                "security": "WPA2-PSK",
                "signal_dbm": -50,
                "vendor": "Netgear",
                "is_hidden": False,
            },
            {
                "ssid": "Home-Network",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "security": "OPEN",  # Rogue AP with no encryption!
                "signal_dbm": -45,
                "vendor": "Unknown",
                "is_hidden": False,
            },
        ]
    }
    threats = audit_network_threats(devices, wifi_spectrum, connected_ssid="Home-Network")
    assert any("Evil Twin" in t.get("title", "") or "Unencrypted" in t.get("title", "") for t in threats)


def test_compute_network_security_posture():
    devices = [
        {"ip": "192.168.12.1", "trust_state": "trusted", "is_gateway": True, "open_ports": [80, 443]},
        {"ip": "192.168.12.50", "trust_state": "known", "is_gateway": False, "open_ports": [22]},
    ]
    threats = [
        {"severity": "MEDIUM", "category": "Cryptographic Posture", "title": "Self-Signed TLS"},
    ]
    wifi_spectrum = {
        "access_points": [
            {"ssid": "TMOBILE-623B", "bssid": "18:A5:1D:0C:62:3B", "security": "WPA2 WPA3", "is_hidden": False}
        ]
    }
    posture = compute_network_security_posture(devices, threats, wifi_spectrum)
    assert 0 <= posture["score"] <= 100
    assert posture["grade"] in ("A+", "A", "B", "C", "D", "F")
    assert "pillars" in posture
    assert len(posture["pillars"]) == 5


def test_wireless_channel_recommendations_and_triangulation():
    aps = [
        {"bssid": "18:A5:1D:0C:62:3B", "ssid": "TMOBILE-623B", "band": "2.4 GHz", "channel": 6, "freq_mhz": 2437, "signal_dbm": -48},
        {"bssid": "18:A5:1D:0C:62:3C", "ssid": "TMOBILE-623B", "band": "5 GHz", "channel": 36, "freq_mhz": 5180, "signal_dbm": -52},
    ]
    rec = WirelessSpectrumEngine.compute_channel_recommendations(aps)
    assert rec["best_24ghz_channel"] in (1, 6, 11)
    assert rec["best_5ghz_channel"] in (36, 40, 44, 48, 149, 153, 157, 161, 165)

    hub = MobileFieldTelemetryHub()
    status = hub.ingest({
        "handset_ip": "192.168.12.142",
        "handset_model": "Pixel 9 Pro",
        "mag_total_ut": 49.5,
        "azimuth_deg": 182.0,
        "wifi_aps": [{"bssid": "18:A5:1D:0C:62:3B", "signal_dbm": -38}],
    })
    assert status["active"] is True
    assert status["tracked_bssids"] == 1

    tri = hub.triangulate_aps(aps)
    assert len(tri) == 1
    assert tri[0]["bssid"] == "18:A5:1D:0C:62:3B"
    assert tri[0]["closer_receiver"] == "Mobile Handset"

