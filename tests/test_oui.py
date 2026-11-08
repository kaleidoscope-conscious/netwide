"""
Unit tests for NetPulse OUI & IEEE 802 MAC address intelligence engine.
"""

from netpulse.oui import oui_db, unmask_eui64_ipv6_mac


def test_oui_db_loaded():
    assert oui_db.loaded_count > 1000, f"Expected loaded OUI count > 1000, got {oui_db.loaded_count}"


def test_oui_lookup_arcadyan_modern():
    res = oui_db.lookup("18:A5:FF:0C:62:3A")
    assert "Arcadyan" in res.vendor
    assert not res.is_locally_administered
    assert not res.is_multicast
    assert res.oui_prefix == "18:A5:FF"


def test_oui_lookup_sony_playstation():
    res = oui_db.lookup("04:F7:78:26:37:24")
    assert "Sony" in res.vendor
    assert not res.is_locally_administered


def test_oui_lookup_randomized_mac():
    # Bit 1 of first byte set = Locally Administered (randomized)
    # 5E = 0101 1110 (bit 1 is 1)
    res = oui_db.lookup("5E:0F:09:46:F4:98")
    assert res.is_locally_administered
    assert res.randomization_profile is not None


def test_oui_lookup_multicast():
    # Bit 0 of first byte set = Multicast (e.g. 01:00:5E:...)
    res = oui_db.lookup("01:00:5E:00:00:01")
    assert res.is_multicast


def test_oui_lookup_invalid():
    res = oui_db.lookup("INVALID_MAC")
    assert res.registry_type == "Invalid"
    assert res.vendor == "Unknown Hardware"


def test_unmask_eui64_ipv6_mac():
    # MAC 00:42:38:AB:02:8E -> EUI-64 is fe80::0242:38ff:feab:028e
    unmasked = unmask_eui64_ipv6_mac(["fe80::0242:38ff:feab:028e%wlo1"])
    assert unmasked is not None
    mac, intel = unmasked
    assert mac == "00:42:38:AB:02:8E"
    assert "Intel" in intel.vendor


def test_laa_virtual_bssid_unmasking():
    # 1A:A5:FF is locally administered bit of 18:A5:FF (Arcadyan)
    res = oui_db.lookup("1A:A5:FF:0C:62:3A")
    assert res.is_locally_administered
    assert res.unmasked_parent_oui == "18:A5:FF"
    assert res.unmasked_parent_vendor is not None
    assert "Arcadyan" in res.unmasked_parent_vendor


def test_oui_search_modes():
    # 1. EUI-64 IPv6 search mode
    s_eui = oui_db.search("fe80::0242:38ff:feab:028e")
    assert s_eui["mode"] == "ipv6_eui64_unmask"
    assert s_eui["total_matches"] == 1
    assert s_eui["results"][0]["unmasked_mac"] == "00:42:38:AB:02:8E"

    # 2. MAC lookup mode
    s_mac = oui_db.search("18:A5:FF:0C:62:3A")
    assert s_mac["mode"] == "mac_lookup"
    assert s_mac["total_matches"] == 1
    assert "Arcadyan" in s_mac["results"][0]["vendor"]

    # 3. Vendor full-text search mode
    s_vendor = oui_db.search("Sonos")
    assert s_vendor["mode"] == "vendor_search"
    assert s_vendor["total_matches"] >= 1
    assert any("Sonos" in r["vendor"] for r in s_vendor["results"])


