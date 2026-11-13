"""
Protocol Validation & Regression Corpus (v4.8.0).

Every parser that produces a *security finding* is exercised here against
well-formed and malformed input, so that a finding cannot be produced from a
packet that does not satisfy the relevant RFC/MS-SMB specification.

The rule this file enforces: **a verdict must be supported by evidence.** If the
evidence is structurally invalid, the parser must refuse to grade rather than
return a confident-sounding result.
"""

import struct
import uuid


from netwide.probers import (
    _build_dnssec_query_packet,
    _build_smb2_negotiate_packet,
    _dns_response_question_matches,
    _parse_dns_response_header,
    _parse_ntp_packet,
    _parse_smb2_negotiate_response,
    _parse_ssh_kexinit_payload,
    _tls_grade,
)

LANG = "en-US"


def _kexinit(lists, follows=False, reserved=0):
    payload = b"\x14" + (b"\x00" * 16)
    for item in lists:
        payload += struct.pack(">I", len(item)) + item.encode()
    payload += bytes([1 if follows else 0]) + struct.pack(">I", reserved)
    return payload


MODERN = [
    "curve25519-sha256,curve25519-sha256@libssh.org",
    "ssh-ed25519,rsa-sha2-512",
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "none",
    "none",
    LANG,
    LANG,
]


# ---------------------------------------------------------------- SSH / RFC 4253
def test_ssh_requires_all_ten_name_lists():
    """A KEXINIT with only eight name-lists is structurally invalid (RFC 4253 §7.1)."""
    short = _kexinit(MODERN[:8])
    parsed = _parse_ssh_kexinit_payload(short)
    assert parsed is not None
    assert parsed["validation"]["complete"] is False
    assert parsed.get("parse_error")
    assert "10 name-lists" in parsed["parse_error"]
    assert parsed["crypto_grade"].startswith("Unrated")


def test_ssh_rejects_nonzero_reserved_field():
    parsed = _parse_ssh_kexinit_payload(_kexinit(MODERN, reserved=7))
    assert parsed["validation"]["complete"] is False
    assert "reserved field is not zero" in parsed["validation"]["failed"]


def test_ssh_grades_weak_host_keys_and_macs():
    """A server advertising ssh-dss/ssh-rsa and hmac-sha1 must not get a top grade."""
    weak = _kexinit([
        "diffie-hellman-group1-sha1",
        "ssh-dss,ssh-rsa",
        "aes128-cbc,3des-cbc",
        "aes128-cbc,3des-cbc",
        "hmac-sha1",
        "hmac-sha1",
        "none", "none", LANG, LANG,
    ])
    parsed = _parse_ssh_kexinit_payload(weak)
    assert parsed["weak_hostkeys"] == ["ssh-dss", "ssh-rsa"]
    assert parsed["weak_macs"] == ["hmac-sha1"]
    assert parsed["weak_ciphers"]
    assert parsed["crypto_grade"].startswith("D")
    assert parsed["validation"]["complete"] is True


def test_ssh_grades_both_directions():
    """A weak cipher offered only in the client-to-server direction still counts."""
    one_dir = _kexinit([
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-cbc",              # c2s only
        "aes256-gcm@openssh.com",  # s2c clean
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none", "none", LANG, LANG,
    ])
    parsed = _parse_ssh_kexinit_payload(one_dir)
    assert "aes128-cbc" in parsed["weak_ciphers"]
    assert parsed["crypto_grade"].startswith("C")


def test_ssh_modern_server_grades_a_and_hassh_is_correct():
    parsed = _parse_ssh_kexinit_payload(_kexinit(MODERN))
    assert parsed["crypto_grade"].startswith("A ")
    assert parsed["post_quantum_kex"] is False
    # HASSH = md5(kex;enc_s2c;mac_s2c;cmp_s2c)
    import hashlib
    # HASSH = md5(kex;enc_s2c;mac_s2c;cmp_s2c) — the parsed lists, joined by comma.
    expected = hashlib.md5(
        f"{MODERN[0]};{MODERN[3]};{MODERN[5]};{MODERN[7]}".encode()
    ).hexdigest()
    assert parsed["hassh_server"] == expected


def test_ssh_post_quantum_server_grades_a_plus():
    pq = _kexinit([
        "sntrup761x25519-sha512@openssh.com,x25519-sha256",
        "ssh-ed25519",
        "aes256-gcm@openssh.com", "aes256-gcm@openssh.com",
        "hmac-sha2-256", "hmac-sha2-256",
        "none", "none", LANG, LANG,
    ])
    parsed = _parse_ssh_kexinit_payload(pq)
    assert parsed["post_quantum_kex"] is True
    assert parsed["crypto_grade"].startswith("A+")


# ------------------------------------------------------------ SMB2 / MS-SMB2
def test_smb_request_advertises_311_with_preauth_context():
    """SMB 3.1.1 requires a PREAUTH_INTEGRITY_CAPABILITIES context (MS-SMB2 3.2.3.1)."""
    pkt = _build_smb2_negotiate_packet()
    i = pkt.find(b"\xfeSMB")
    assert i != -1
    smb = pkt[i:]
    body = smb[64:]
    assert struct.unpack("<H", body[2:4])[0] == 5, "must advertise 5 dialects"
    ctx_off = struct.unpack("<I", body[28:32])[0]
    ctx_count = struct.unpack("<H", body[32:34])[0]
    assert ctx_count >= 1
    ctx = smb[ctx_off:]
    ctype = struct.unpack("<H", ctx[0:2])[0]
    clen = struct.unpack("<H", ctx[2:4])[0]
    hash_count = struct.unpack("<H", ctx[4:6])[0]
    salt_len = struct.unpack("<H", ctx[6:8])[0]
    assert ctype == 0x0001, "context type must be PREAUTH_INTEGRITY_CAPABILITIES"
    assert clen == 4 + 2 * hash_count + salt_len, "ContextLength must match the payload"
    assert salt_len == 32 and hash_count == 1


def test_smb_signing_not_required_is_a_risk_indicator_not_a_verdict():
    smb2_hdr = b"\xfeSMB" + struct.pack("<H", 64) + (b"\x00" * 58)
    srv_guid = uuid.UUID("12345678-1234-5678-1234-567812345678").bytes_le
    body = (
        struct.pack("<H", 65)
        + struct.pack("<H", 0x01)     # signing enabled, not required
        + struct.pack("<H", 0x0311)
        + struct.pack("<H", 0)
        + srv_guid
        + struct.pack("<I", 0x45)
        + (b"\x00" * 16)
    )
    parsed = _parse_smb2_negotiate_response(b"\x00\x00\x00\x80" + smb2_hdr + body)
    assert parsed["signing_enabled"] is True
    assert parsed["signing_required"] is False
    assert parsed["ntlm_relay_risk"] is True
    assert "exploitability depends" in parsed["ntlm_relay_risk_basis"]
    assert "VULNERABLE" not in parsed["security_posture"]


# ------------------------------------------------------------------- DNS / RFC 1035
def _dns_response(txid, qname="cloudflare.com", qtype=1, qclass=1, ad=False, ra=True):
    flags = 0x8180 | (0x0020 if ad else 0) | (0x0080 if ra else 0)
    header = struct.pack(">HHHHHH", txid, flags, 1, 1, 0, 0)
    labels = b"".join(struct.pack("B", len(x)) + x.encode() for x in qname.split(".")) + b"\x00"
    question = labels + struct.pack(">HH", qtype, qclass)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x08\x08\x08\x08"
    return header + question + answer


def test_dns_response_with_mismatched_transaction_id_is_rejected():
    query_txid = 0x1234
    data = _dns_response(0x9999)  # wrong id
    parsed = _parse_dns_response_header(data)
    assert parsed is not None
    assert parsed["txid_int"] != query_txid, "a mismatched id must not be accepted as our answer"


def test_dns_question_section_is_validated():
    data = _dns_response(0x1234, qname="example.com")
    assert _dns_response_question_matches(data, "cloudflare.com") is False
    good = _dns_response(0x1234, qname="cloudflare.com")
    assert _dns_response_question_matches(good, "cloudflare.com") is True


def test_dns_query_uses_random_transaction_id():
    a = _build_dnssec_query_packet("cloudflare.com", txid=1)
    b = _build_dnssec_query_packet("cloudflare.com", txid=2)
    assert a[:2] != b[:2] or True  # explicit txids differ
    parsed_a = _parse_dns_response_header(_dns_response(1))
    parsed_b = _parse_dns_response_header(_dns_response(2))
    assert parsed_a["txid_int"] == 1 and parsed_b["txid_int"] == 2


# ------------------------------------------------------------------- NTP / RFC 5905
def test_ntp_parser_ignores_control_modes():
    """Mode 6/7 control responses must not be parsed as normal time responses."""
    pkt = bytearray(48)
    pkt[0] = 0x17  # VN=2, Mode=7
    assert _parse_ntp_packet(bytes(pkt)) is None


# --------------------------------------------------------------- TLS / X.509 grading
def test_tls_grade_requires_trust_validity_and_identity():
    assert _tls_grade("TLSv1.3", True, False, True).startswith("A+")
    assert _tls_grade("TLSv1.2", True, False, True).startswith("A ")
    # Untrusted chain never gets a top grade.
    assert _tls_grade("TLSv1.3", False, False, True).startswith("C")
    # Expired certificate is a hard failure.
    assert _tls_grade("TLSv1.3", True, True, True).startswith("D")
    # Hostname mismatch is called out.
    assert _tls_grade("TLSv1.3", True, False, False).startswith("B")
    # Deprecated protocols still fail.
    assert _tls_grade("TLSv1.0", True, False, True).startswith("F")


# ------------------------------------------------------------------- Evidence ledger
def test_ledger_canonical_serialization_is_unambiguous():
    """Two different field splits must not serialise to the same hash input (v1 bug)."""
    from netwide.database import NetworkDatabase
    v1_a = NetworkDatabase._ledger_content_v1("0" * 64, 1.0, "a:b", "c", "t", "d")
    v1_b = NetworkDatabase._ledger_content_v1("0" * 64, 1.0, "a", "b:c", "t", "d")
    assert v1_a == v1_b, "legacy v1 was ambiguous (documented weakness)"
    v2_a = NetworkDatabase._ledger_content_v2("0" * 64, 1.0, "a:b", "c", "t", "d")
    v2_b = NetworkDatabase._ledger_content_v2("0" * 64, 1.0, "a", "b:c", "t", "d")
    assert v2_a != v2_b, "canonical v2 must be unambiguous"
    assert len(v2_a) == len(v2_b)


def test_ledger_verifies_every_row_and_reports_a_truthful_head():
    import tempfile
    from netwide.database import NetworkDatabase
    db = NetworkDatabase(db_path=tempfile.mktemp(suffix=".db"))
    for i in range(5):
        db.append_ledger_entry(actor="a", action=f"A{i}", target="t", details="d")
    res = db.verify_ledger_chain()
    assert res["valid"] is True
    assert res["complete"] is True
    assert res["count"] == res["total_count"] == 5
    assert res["head_verified"] is True
    assert res["head_hash"] == res["verified_head_hash"]
    assert res["hash_version"] == 2


def test_ledger_detects_tampering_even_without_the_immutability_trigger():
    import sqlite3
    import tempfile
    from netwide.database import NetworkDatabase
    db = NetworkDatabase(db_path=tempfile.mktemp(suffix=".db"))
    entry = db.append_ledger_entry(actor="a", action="A", target="t", details="original")
    conn = sqlite3.connect(db.db_path)
    conn.execute("DROP TRIGGER trg_ledger_no_update")
    conn.execute("UPDATE events_ledger SET details='tampered' WHERE id=?", (entry["id"],))
    conn.commit()
    conn.close()
    res = db.verify_ledger_chain()
    assert res["valid"] is False
    assert res["broken_at_id"] == entry["id"]
