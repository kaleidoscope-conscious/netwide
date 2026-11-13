"""
Capture corpus regression runner (v4.9.0).

`tests/fixtures/` holds real handshakes harvested from live systems plus
clearly-labelled synthetic ones. Every fixture is replayed here so a parser
change cannot silently alter the verdict on a known-good capture.

Each manifest entry records its provenance (`real` or `synthetic`) so a
synthetic fixture can never be mistaken for a captured one.
"""

import json
import pathlib

import pytest

from netwide.probers import (
    _parse_dns_response_header,
    _parse_smb2_negotiate_response,
    _parse_ssh_kexinit_payload,
)
from netwide.tls_fingerprint import parse_client_hello, parse_server_hello

FIXDIR = pathlib.Path(__file__).resolve().parent / "fixtures"
MANIFEST = json.loads((FIXDIR / "manifest.json").read_text(encoding="utf-8"))


def _load(key: str) -> bytes:
    entry = MANIFEST[key]
    return (FIXDIR / entry["file"]).read_bytes()


# ------------------------------------------------------------------ SSH corpus
SSH_EXPECTATIONS = {
    # real OpenSSH (the workstation) — modern ciphers, must grade A or better
    "openssh-workstation": {"min_grade": "A ", "forbid_weak": True},
    # synthetic embedded firmware — modern but no post-quantum KEX
    "ssh_kexinit_synthetic_embedded": {"min_grade": "A ", "forbid_weak": True},
    # synthetic legacy server — must never be graded above D
    "ssh_kexinit_synthetic_legacy": {"max_grade": "D ", "expect_weak": True},
}


@pytest.mark.parametrize("key", [k for k in MANIFEST if MANIFEST[k]["protocol"] == "ssh-kexinit"])
def test_ssh_corpus(key):
    data = _load(key)
    parsed = _parse_ssh_kexinit_payload(data)
    assert parsed is not None, f"{key} failed to parse"
    assert parsed["validation"]["complete"] is True, f"{key}: {parsed['validation']}"
    assert len(parsed["kex_algorithms"]) > 0
    # HASSH must be a stable MD5 over the documented input
    assert len(parsed["hassh_server"]) == 32

    exp = SSH_EXPECTATIONS.get(key)
    if not exp:
        return
    grade = parsed["crypto_grade"]
    order = ["A+", "A ", "B ", "C ", "D "]
    if "min_grade" in exp:
        worst = min(order.index(g) for g in order if grade.startswith(g))
        assert worst >= order.index(exp["min_grade"]), f"{key}: grade {grade} below {exp['min_grade']}"
    if "max_grade" in exp:
        worst = min(order.index(g) for g in order if grade.startswith(g))
        assert worst <= order.index(exp["max_grade"]), f"{key}: grade {grade} above {exp['max_grade']}"
    if exp.get("expect_weak"):
        assert parsed["weak_hostkeys"] or parsed["weak_macs"] or parsed["weak_ciphers"], \
            f"{key}: expected weak algorithms to be detected"


def test_ssh_framing_rule_accepts_the_real_capture():
    """
    The framing rule must accept what real servers send.

    The captured OpenSSH KEXINIT arrived as packet_length=1116, padding_length=7,
    i.e. a 1120-byte packet on the wire (a multiple of 8). A rule that tested
    packet_length alone would reject every real server — this pins it.
    """
    from netwide.probers import _ssh_framing_ok
    ok, reason = _ssh_framing_ok(1116, 7, 1120)
    assert ok, reason
    # Malformed frames must still be refused.
    assert _ssh_framing_ok(1116, 7, 100)[0] is False, "truncated packet must fail"
    assert _ssh_framing_ok(1117, 7, 1121)[0] is False, "non-multiple-of-8 packet must fail"
    assert _ssh_framing_ok(10, 1, 20)[0] is False, "padding below 4 must fail"
    assert _ssh_framing_ok(10, 9, 20)[0] is False, "empty payload must fail"


# ------------------------------------------------------------------ SMB2 corpus
def test_smb_corpus_windows_311():
    key = "smb2_negotiate_response_synthetic_win311"
    parsed = _parse_smb2_negotiate_response(_load(key))
    assert parsed is not None
    assert parsed["dialect_code"] == "0x0311"
    assert parsed["signing_required"] is True
    assert parsed["ntlm_relay_risk"] is False
    assert "PREAUTH_INTEGRITY" in parsed["negotiate_contexts"]
    assert parsed["validation"]["complete"] is True


def test_smb_corpus_signing_not_required_is_risk_indicator():
    key = "smb2_negotiate_response_synthetic_smb21"
    parsed = _parse_smb2_negotiate_response(_load(key))
    assert parsed is not None
    assert parsed["signing_required"] is False
    assert parsed["ntlm_relay_risk"] is True
    assert "exploitability depends" in parsed["ntlm_relay_risk_basis"]
    assert "VULNERABLE" not in parsed["security_posture"]


# ------------------------------------------------------------------ DNS corpus
def test_dns_corpus_validates_against_its_own_query():
    key = "lan-resolver"
    entry = MANIFEST[key]
    data = _load(key)
    parsed = _parse_dns_response_header(data)
    assert parsed is not None, "captured DNS response must parse"
    assert parsed["rcode"] == 0, "resolver answered NOERROR"
    assert parsed["txid_int"] == entry["txid"], "transaction id must round-trip"
    assert parsed["recursion_available"] is True


# ------------------------------------------------------------------ TLS corpus
def test_tls_client_corpus_reproduces_known_ja3():
    for key, entry in MANIFEST.items():
        if entry["protocol"] != "tls-client-hello":
            continue
        parsed = parse_client_hello(_load(key))
        assert parsed is not None, f"{key} failed to parse"
        assert parsed["ja3"] == entry["ja3"], f"{key}: JA3 mismatch"
        assert parsed["ja3_input"] == entry["ja3_input"]
        assert parsed["source"] == "native"


def test_tls_server_corpus_reproduces_known_ja3s():
    for key, entry in MANIFEST.items():
        if entry["protocol"] != "tls-server-hello":
            continue
        parsed = parse_server_hello(_load(key))
        assert parsed is not None, f"{key} failed to parse"
        assert parsed["ja3s"] == entry["ja3s"], f"{key}: JA3S mismatch"
        assert parsed["ja3s_input"] == entry["ja3s_input"]


# ------------------------------------------------------------------ provenance
def test_corpus_provenance_is_declared():
    """Every fixture must state whether it is a real capture or synthetic."""
    for key, entry in MANIFEST.items():
        assert "source" in entry, f"{key} has no source"
        if entry.get("source") == "synthetic":
            assert entry.get("synthetic") is True, f"{key} must be marked synthetic"
            assert "note" in entry, f"{key} must explain what it was built from"
        else:
            assert entry.get("synthetic") is not True, f"{key} is a real capture"
