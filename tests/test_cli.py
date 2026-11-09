"""
Tests for NetPulse Rich Terminal CLI commands and exit codes.
"""

import pytest
from netpulse.cli import main, cmd_cidr, cmd_oui


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "4.5.0" in captured.out or "4.5.0" in captured.err


def test_cli_cidr_valid(capsys):
    # Valid CIDR should not raise SystemExit
    cmd_cidr("192.168.1.0/24")
    captured = capsys.readouterr()
    assert "192.168.1.0/24" in captured.out


def test_cli_cidr_invalid(capsys):
    with pytest.raises(SystemExit) as exc:
        cmd_cidr("999.999.999.999/99")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Invalid CIDR" in captured.out


def test_cli_oui_search(capsys):
    cmd_oui("Ubiquiti")
    captured = capsys.readouterr()
    assert "Ubiquiti" in captured.out


def test_cli_license_status():
    # Should run cleanly without exception
    main(["license", "status"])


def test_cli_license_activate_invalid():
    with pytest.raises(SystemExit) as exc:
        main(["license", "activate", "--key", "INVALID-KEY-123"])
    assert exc.value.code == 1
