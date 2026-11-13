"""
Tests for Netwide Rich Terminal CLI commands and exit codes.
"""

import pytest
from netwide.cli import main, cmd_cidr, cmd_oui


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "4.9.0" in captured.out or "4.9.0" in captured.err


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


def test_authority_backup_creates_a_protected_copy():
    """`netwide authority backup` must copy the private key and keep it owner-only."""
    import os as _os
    import stat as _stat
    import tempfile as _tempfile
    from netwide import license_authority as _authority

    key_dir = _tempfile.mkdtemp()
    key_path = _os.path.join(key_dir, "authority_ed25519.key")
    pub, priv = _authority.generate_keypair()
    with open(key_path, "w", encoding="utf-8") as fh:
        fh.write(priv)
    old_path = _os.environ.get("NETWIDE_LICENSE_KEY_PATH")
    _os.environ["NETWIDE_LICENSE_KEY_PATH"] = key_path
    try:
        from netwide.cli import main
        import io as _io
        import contextlib as _ctx
        buf = _io.StringIO()
        with _ctx.redirect_stdout(buf):
            try:
                main(["authority", "backup"])
            except SystemExit:
                pass
        backups = _os.listdir(_os.path.join(key_dir, "backups"))
        assert backups, "expected a backup file to be written"
        mode = _stat.S_IMODE(_os.stat(_os.path.join(key_dir, "backups", backups[0])).st_mode)
        assert mode & 0o077 == 0, "backup must not be group/world readable"
        assert _os.path.getsize(_os.path.join(key_dir, "backups", backups[0])) == len(priv)
    finally:
        if old_path is None:
            _os.environ.pop("NETWIDE_LICENSE_KEY_PATH", None)
        else:
            _os.environ["NETWIDE_LICENSE_KEY_PATH"] = old_path
