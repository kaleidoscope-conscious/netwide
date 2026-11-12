"""
Unit tests for Netwide network probers, Wake-on-LAN, and XML parsers.
"""

import struct
import uuid

from netwide.probers import (
    HostQuarantineManager,
    _build_dnssec_query_packet,
    _build_smb2_negotiate_packet,
    _kasa_xor_decrypt,
    _kasa_xor_encrypt,
    _parse_dns_response_header,
    _parse_ntp_packet,
    _parse_smb2_negotiate_response,
    _parse_ssh_kexinit_payload,
    _strip_xml_ns,
    audit_ipv6_posture,
    audit_local_workstation_sockets,
    calculate_subnet_cidr,
    detect_active_interface,
    probe_domain_and_wan_target,
    probe_homekit_and_matter,
    send_port_knock_sequence,
    send_wake_on_lan,
)


def test_detect_active_interface():
    net = detect_active_interface()
    assert net.interface != ""
    assert net.ip != ""
    assert net.cidr != ""
    assert net.gateway_ip != ""


def test_strip_xml_ns():
    tag = "{urn:schemas-upnp-org:device-1-0}device"
    assert _strip_xml_ns(tag) == "device"
    assert _strip_xml_ns("plainTag") == "plainTag"


def test_send_wake_on_lan_invalid_mac():
    ok, msg = send_wake_on_lan("INVALID")
    assert not ok
    assert "Invalid" in msg or "invalid" in msg.lower()


def test_send_wake_on_lan_valid_mac():
    ok, msg = send_wake_on_lan("AA:BB:CC:DD:EE:FF")
    assert ok
    assert "Transmitted" in msg


def test_kasa_xor_cipher():
    payload = '{"system":{"get_sysinfo":{}}}'
    encrypted = _kasa_xor_encrypt(payload)
    assert len(encrypted) == len(payload) + 4
    decrypted = _kasa_xor_decrypt(encrypted)
    assert decrypted == payload


def test_homekit_and_matter_prober():
    mdns = [
        {"service_type": "_hap._tcp", "port": 51827, "txt": {"md": "Eve Energy", "ci": "7", "pv": "1.1", "s#": "12"}},
    ]
    res = probe_homekit_and_matter("192.168.12.77", [51827], mdns)
    assert res is not None
    assert res["ecosystem"] == "Apple HomeKit (HAP)"
    assert res["category_name"] == "Smart Outlet / Plug"
    assert res["model"] == "Eve Energy"
    assert res["hap_port"] == 51827


def test_quarantine_engine_lifecycle():
    mgr = HostQuarantineManager()
    assert not mgr.is_quarantined("192.0.2.123")
    entry = mgr.engage("192.0.2.123", "AA:BB:CC:DD:EE:FF", reason="Unit Test")
    assert entry["ip"] == "192.0.2.123"
    assert mgr.is_quarantined("192.0.2.123")
    released = mgr.release("192.0.2.123")
    assert released is True
    assert not mgr.is_quarantined("192.0.2.123")


def test_parse_ssh_kexinit_payload_and_hassh():
    def _nl(items):
        b = ",".join(items).encode("ascii")
        return struct.pack(">I", len(b)) + b

    # Msg 20 (SSH_MSG_KEXINIT) + 16-byte cookie + 10 algorithm name-lists
    payload = (
        b"\x14"
        + (b"\xaa" * 16)
        + _nl(["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"])
        + _nl(["ssh-ed25519", "rsa-sha2-512"])
        + _nl(["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"])
        + _nl(["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"])
        + _nl(["umac-128-etm@openssh.com"])
        + _nl(["umac-128-etm@openssh.com"])
        + _nl(["none", "zlib@openssh.com"])
        + _nl(["none", "zlib@openssh.com"])
        + _nl([])
        + _nl([])
    )
    res = _parse_ssh_kexinit_payload(payload)
    assert res is not None
    assert len(res["hassh_server"]) == 32
    assert res["post_quantum_kex"] is True
    assert "A+" in res["crypto_grade"]
    assert res["weak_kex"] == []
    assert res["weak_ciphers"] == []


def test_smb2_negotiate_packet_and_response_parser():
    req = _build_smb2_negotiate_packet()
    assert b"\xfeSMB" in req
    assert len(req) > 68

    # Construct synthetic SMB2 NEGOTIATE response with dialect 0x0311 (SMB 3.1.1) and signing enabled but NOT required (sec_mode=1)
    smb2_hdr = b"\xfeSMB" + struct.pack("<H", 64) + (b"\x00" * 58)
    srv_guid = uuid.UUID("12345678-1234-5678-1234-567812345678").bytes_le
    body = (
        struct.pack("<H", 65)        # StructureSize = 65
        + struct.pack("<H", 0x01)    # SecurityMode = Signing Enabled (0x01), Signing Required = False
        + struct.pack("<H", 0x0311)  # DialectRevision = SMB 3.1.1
        + struct.pack("<H", 0)       # NegotiateContextCount
        + srv_guid                   # ServerGuid (16 bytes)
        + struct.pack("<I", 0x45)    # Capabilities: DFS (0x01) | LARGE_MTU (0x04) | ENCRYPTION (0x40)
        + (b"\x00" * 16)
    )
    parsed = _parse_smb2_negotiate_response(b"\x00\x00\x00\x80" + smb2_hdr + body)
    assert parsed is not None
    assert parsed["dialect_name"] == "SMB 3.1.1"
    assert parsed["signing_enabled"] is True
    assert parsed["signing_required"] is False
    assert parsed["ntlm_relay_vulnerable"] is True
    assert "ENCRYPTION" in parsed["capabilities"]
    assert parsed["server_guid"] == "12345678-1234-5678-1234-567812345678"


def test_gateway_arp_spoofing_watchdog():
    mgr = HostQuarantineManager()
    mgr.lock_gateway_mac("192.168.12.1", "18:A5:FF:0C:62:3A")
    ok_check = mgr.verify_gateway_mac("192.168.12.1", "18:A5:FF:0C:62:3A")
    assert ok_check["arp_spoof_detected"] is False

    spoof_check = mgr.verify_gateway_mac("192.168.12.1", "DE:AD:BE:EF:00:01")
    assert spoof_check["arp_spoof_detected"] is True
    assert spoof_check["spoof_detected"] is True
    assert "18:A5:FF:0C:62:3A" in spoof_check["alert"]


def test_dnssec_query_builder_and_response_parser():
    pkt = _build_dnssec_query_packet("cloudflare.com", qtype=1, qclass=1, enable_do=True, txid=0x4E51)
    assert len(pkt) > 28
    assert b"cloudflare" in pkt

    # Construct synthetic DNS response header: QR=1, RD=1, RA=1, AD=1 (0x81A0), RCODE=0 (NOERROR), QD=1, AN=2
    syn_resp = struct.pack(">HHHHHH", 0x4E51, 0x81A0, 1, 2, 0, 1)
    parsed = _parse_dns_response_header(syn_resp)
    assert parsed is not None
    assert parsed["rcode_name"] == "NOERROR"
    assert parsed["recursion_available"] is True
    assert parsed["dnssec_ad_verified"] is True
    assert parsed["answer_count"] == 2


def test_ntp_packet_parser_and_ipv6_posture():
    # Construct synthetic 48-byte RFC 5905 NTPv4 Server (0x24 = LI 0, VN 4, Mode 4), Stratum 1, RefID='GPS\x00'
    ntp_pkt = struct.pack("!BBBbII4s", 0x24, 1, 6, -20, 655, 1310, b"GPS\x00") + (b"\x00" * 32)
    parsed = _parse_ntp_packet(ntp_pkt)
    assert parsed is not None
    assert parsed["ntp_version"] == 4
    assert parsed["stratum"] == 1
    assert parsed["ref_id"] == "GPS"

    v6 = audit_ipv6_posture("wlo1")
    assert "ipv6_enabled" in v6
    assert "security_grade" in v6

    knock = send_port_knock_sequence("127.0.0.1", [7000, 8000], protocol="udp", delay_ms=5, verify_port=8765)
    assert knock["ok"] is True
    assert len(knock["steps"]) == 2


def test_subnet_cidr_calculator_and_local_sockets():
    c24 = calculate_subnet_cidr("192.168.12.225/24")
    assert c24["ok"] is True
    assert c24["cidr"] == "192.168.12.0/24"
    assert c24["network_address"] == "192.168.12.0"
    assert c24["broadcast_address"] == "192.168.12.255"
    assert c24["first_usable"] == "192.168.12.1"
    assert c24["last_usable"] == "192.168.12.254"
    assert c24["usable_hosts"] == 254
    assert c24["ip_class"] == "Class C"

    c_v6 = calculate_subnet_cidr("fe80::1/64")
    assert c_v6["ok"] is True
    assert c_v6["ip_version"] == 6

    c_bad = calculate_subnet_cidr("not-an-ip/99")
    assert c_bad["ok"] is False

    socks = audit_local_workstation_sockets()
    assert socks["ok"] is True
    assert isinstance(socks["listening_sockets"], list)
    assert isinstance(socks["interface_counters"], list)

    dom = probe_domain_and_wan_target("127.0.0.1")
    assert dom["ok"] is True
    assert "security_grade" in dom





