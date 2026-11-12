"""
Unit tests for wireless spectrum, BSSID de-cloaker heuristics, and iw parser.
"""

from unittest.mock import patch
from netwide.wireless import (
    wireless_engine,
    _freq_to_channel,
    parse_signal_value,
    parse_iw_scan_dump,
)


def test_freq_to_channel():
    assert _freq_to_channel(2412) == 1
    assert _freq_to_channel(2437) == 6
    assert _freq_to_channel(2462) == 11
    assert _freq_to_channel(5180) == 36
    assert _freq_to_channel(5240) == 48
    assert _freq_to_channel(5745) == 149
    assert _freq_to_channel(9999) == 0


def test_parse_signal_value():
    pct, dbm = parse_signal_value("-45 dBm")
    assert dbm == -45.0
    assert 90 <= pct <= 100

    pct2, dbm2 = parse_signal_value("75%")
    assert pct2 == 75
    assert dbm2 < 0.0


def test_rssi_pearson_correlation():
    # Identical synchronized trend -> Pearson ~ 1.0
    r_perf = wireless_engine._compute_rssi_pearson([-60, -62, -64, -63], [-61, -63, -65, -64])
    assert r_perf is not None
    assert r_perf > 0.95

    # Insufficient samples (< 3)
    assert wireless_engine._compute_rssi_pearson([-60, -62], [-61, -63]) is None


def test_parse_iw_scan_dump_parsing():
    mock_iw_output = """BSS 22:ef:bd:5b:09:a8(on wlo1) -- associated
\tTSF: 123456789 usec (0d, 00:02:03)
\tsignal: -48.0 dBm
\tfreq: 2417
\tSSID: TestNetwork
BSS 00:11:22:33:44:55(on wlo1)
\tTSF: 987654321 usec (0d, 00:16:27)
\tsignal: -72.0 dBm
\tfreq: 5200
"""
    with patch("subprocess.check_output", return_value=mock_iw_output):
        res = parse_iw_scan_dump("wlo1")
        assert "22:EF:BD:5B:09:A8" in res
        entry1 = res["22:EF:BD:5B:09:A8"]
        assert entry1["signal_dbm"] == -48.0
        assert entry1["ssid"] == "TestNetwork"
        assert entry1["tsf_usec"] == 123456789

        assert "00:11:22:33:44:55" in res
        entry2 = res["00:11:22:33:44:55"]
        assert entry2["signal_dbm"] == -72.0
