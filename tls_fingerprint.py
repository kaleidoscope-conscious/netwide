"""
Native TLS client/server fingerprinting (JA3 and JA3S).

Why this exists
---------------
JA3 was previously extracted through tshark's dissector field
``tls.handshake.ja3``. That is a *capability* dependency: if the installed
tshark does not expose the field, no JA3 is produced at all — and "no JA3 on the
wire" became indistinguishable from "this host cannot compute JA3".

This module computes the fingerprints directly from the handshake bytes, so the
value is produced whenever the bytes exist — no dissector field required.

References
----------
* JA3 (Salesforce): MD5 over "SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"
* JA3S (Salesforce): MD5 over "SSLVersion,Cipher,Extensions" from the ServerHello
* GREASE values (RFC 8701) are excluded from every list.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Optional

# RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Extension types whose payload carries a named-group list (JA3 "EllipticCurves")
CURVE_EXTENSIONS = {0x000A, 0x001A, 0x001B}
# Extension types whose payload carries point formats (JA3 "EllipticCurvePointFormats")
POINT_FORMAT_EXTENSIONS = {0x000B}


def _is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def _hex4(value: int) -> str:
    return f"{value:04X}"


def _hex2(value: int) -> str:
    return f"{value:02X}"


def _strip_grease(values: List[int]) -> List[int]:
    return [v for v in values if not _is_grease(v)]


def parse_client_hello(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse a TLS ClientHello (possibly wrapped in one or more TLS records) and
    return the fields JA3 needs.
    """
    try:
        handshake = _extract_handshake(data, want_type=0x01)
        if handshake is None:
            return None
        # The handshake buffer starts with the message type (1 byte) and the
        # 3-byte length; the ClientHello body begins after those four bytes.
        offset = 4

        client_version = struct.unpack(">H", handshake[offset : offset + 2])[0]
        offset += 2
        offset += 32  # random

        if offset >= len(handshake):
            return None
        session_id_len = handshake[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(handshake):
            return None
        cipher_len = struct.unpack(">H", handshake[offset : offset + 2])[0]
        offset += 2
        cipher_bytes = handshake[offset : offset + cipher_len]
        offset += cipher_len
        ciphers = [struct.unpack(">H", cipher_bytes[i : i + 2])[0] for i in range(0, len(cipher_bytes) - 1, 2)]

        if offset >= len(handshake):
            return None
        comp_len = handshake[offset]
        offset += 1 + comp_len

        extensions: List[int] = []
        curves: List[int] = []
        point_formats: List[int] = []
        sni = ""
        alpn: List[str] = []
        sig_algs: List[str] = []

        if offset + 2 <= len(handshake):
            ext_total = struct.unpack(">H", handshake[offset : offset + 2])[0]
            offset += 2
            ext_end = min(len(handshake), offset + ext_total)
            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack(">HH", handshake[offset : offset + 4])
                offset += 4
                ext_data = handshake[offset : offset + ext_len]
                offset += ext_len
                if _is_grease(ext_type):
                    continue
                extensions.append(ext_type)

                if ext_type in CURVE_EXTENSIONS and len(ext_data) >= 2:
                    list_len = struct.unpack(">H", ext_data[0:2])[0]
                    body = ext_data[2 : 2 + list_len]
                    for i in range(0, len(body) - 1, 2):
                        grp = struct.unpack(">H", body[i : i + 2])[0]
                        if not _is_grease(grp):
                            curves.append(grp)
                elif ext_type in POINT_FORMAT_EXTENSIONS and len(ext_data) >= 1:
                    list_len = ext_data[0]
                    for i in range(1, 1 + list_len):
                        point_formats.append(ext_data[i])
                elif ext_type == 0x0000 and len(ext_data) >= 5:  # server_name
                    # ServerNameList: uint16 list length, then entries of
                    # [uint8 name_type=0][uint16 name length][hostname]
                    name_list_len = struct.unpack(">H", ext_data[0:2])[0]
                    entry = ext_data[2 : 2 + name_list_len]
                    if len(entry) >= 3 and entry[0] == 0:
                        host_len = struct.unpack(">H", entry[1:3])[0]
                        sni = entry[3 : 3 + host_len].decode("ascii", errors="ignore")
                elif ext_type == 0x0010 and len(ext_data) >= 3:  # ALPN
                    list_len = struct.unpack(">H", ext_data[0:2])[0]
                    body = ext_data[2 : 2 + list_len]
                    i = 0
                    while i < len(body):
                        n = body[i]
                        alpn.append(body[i + 1 : i + 1 + n].decode("ascii", errors="ignore"))
                        i += 1 + n
                elif ext_type == 0x000D and len(ext_data) >= 2:  # signature_algorithms
                    list_len = struct.unpack(">H", ext_data[0:2])[0]
                    body = ext_data[2 : 2 + list_len]
                    for i in range(0, len(body) - 1, 2):
                        sig_algs.append(_hex4(struct.unpack(">H", body[i : i + 2])[0]))

        # JA3 string format (Salesforce reference / tshark): decimal values,
        # dash-separated inside each list, comma-separated between lists.
        version_str = str(client_version)
        cipher_str = "-".join(str(c) for c in _strip_grease(ciphers))
        ext_str = "-".join(str(e) for e in extensions)
        curve_str = "-".join(str(c) for c in curves)
        point_str = "-".join(str(p) for p in point_formats)

        ja3_input = f"{version_str},{cipher_str},{ext_str},{curve_str},{point_str}"
        ja3 = hashlib.md5(ja3_input.encode("utf-8")).hexdigest()

        return {
            "ja3": ja3,
            "ja3_input": ja3_input,
            "client_version": version_str,
            "cipher_suites": [_hex4(c) for c in ciphers],
            "extensions": [_hex4(e) for e in extensions],
            "supported_groups": [_hex4(c) for c in curves],
            "ec_point_formats": [_hex2(p) for p in point_formats],
            "cipher_suites_decimal": [str(c) for c in _strip_grease(ciphers)],
            "sni": sni,
            "alpn": alpn,
            "signature_algorithms": sig_algs,
            "source": "native",
        }
    except Exception:
        return None


def parse_server_hello(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse a TLS ServerHello and compute JA3S."""
    try:
        handshake = _extract_handshake(data, want_type=0x02)
        if handshake is None:
            return None
        # Skip message type (1) + length (3) before the ServerHello body.
        offset = 4
        server_version = struct.unpack(">H", handshake[offset : offset + 2])[0]
        offset += 2
        offset += 32  # random
        if offset >= len(handshake):
            return None
        session_id_len = handshake[offset]
        offset += 1 + session_id_len
        if offset + 3 > len(handshake):
            return None
        cipher = struct.unpack(">H", handshake[offset : offset + 2])[0]
        offset += 2
        compression = handshake[offset]
        offset += 1

        extensions: List[int] = []
        if offset + 2 <= len(handshake):
            ext_total = struct.unpack(">H", handshake[offset : offset + 2])[0]
            offset += 2
            ext_end = min(len(handshake), offset + ext_total)
            while offset + 4 <= ext_end:
                ext_type, ext_len = struct.unpack(">HH", handshake[offset : offset + 4])
                offset += 4 + ext_len
                if not _is_grease(ext_type):
                    extensions.append(ext_type)

        version_str = str(server_version)
        ja3s_input = f"{version_str},{cipher},{'-'.join(str(e) for e in extensions)}"
        return {
            "ja3s": hashlib.md5(ja3s_input.encode("utf-8")).hexdigest(),
            "ja3s_input": ja3s_input,
            "server_version": version_str,
            "cipher_suite": _hex4(cipher),
            "extensions": [_hex4(e) for e in extensions],
            "compression_method": _hex2(compression),
            "source": "native",
        }
    except Exception:
        return None


def _extract_handshake(data: bytes, want_type: int) -> Optional[bytes]:
    """
    Pull a handshake message out of TLS record(s).

    Accepts either a raw handshake message or one or more TLS records
    (content type 0x16). Returns the handshake body (type + length + payload).
    """
    if not data:
        return None
    # Already a bare handshake message?
    if data[0] == want_type and len(data) >= 4:
        length = int.from_bytes(data[1:4], "big")
        if 4 + length <= len(data):
            return data[: 4 + length]
        return None

    offset = 0
    while offset + 5 <= len(data):
        content_type = data[offset]
        rec_len = struct.unpack(">H", data[offset + 3 : offset + 5])[0]
        payload = data[offset + 5 : offset + 5 + rec_len]
        offset += 5 + rec_len
        if content_type != 0x16:
            continue
        if len(payload) >= 4 and payload[0] == want_type:
            length = int.from_bytes(payload[1:4], "big")
            return payload[: 4 + length] if 4 + length <= len(payload) else payload
        # Multiple handshake messages in one record: scan for the wanted type.
        pos = 0
        while pos + 4 <= len(payload):
            msg_type = payload[pos]
            msg_len = int.from_bytes(payload[pos + 1 : pos + 4], "big")
            if msg_type == want_type:
                return payload[pos : pos + 4 + msg_len]
            pos += 4 + msg_len
    return None


def fingerprint_handshake(client_bytes: bytes, server_bytes: bytes = b"") -> Dict[str, Any]:
    """Convenience wrapper returning whatever could be derived from the bytes."""
    out: Dict[str, Any] = {}
    client = parse_client_hello(client_bytes)
    if client:
        out.update(client)
    if server_bytes:
        server = parse_server_hello(server_bytes)
        if server:
            out.update(server)
    out["ja4_supported"] = False
    out["ja4_note"] = "JA4 is not emitted: an incorrect fingerprint is worse than none."
    return out

def capture_handshake_bytes(ip: str, port: int = 443, timeout: float = 3.0,
                            server_name: str = "") -> Dict[str, bytes]:
    """
    Perform a TLS handshake and capture the raw handshake bytes.

    The client and server hello messages are captured through in-memory BIOs, so
    the fingerprints are derived from the bytes actually exchanged — no dissector
    field, no packet capture, no extra dependency. Returns
    {"client": b"..." , "server": b"...", "cipher": "...", "tls_version": "..."}.
    """
    import socket
    import ssl as _ssl

    incoming = _ssl.MemoryBIO()
    outgoing = _ssl.MemoryBIO()
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass

    client_bytes = b""
    server_bytes = b""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sslobj = ctx.wrap_bio(incoming, outgoing, server_hostname=(server_name or ip))

        # Drive the handshake manually so both directions can be captured.
        last_error = ""
        for _ in range(12):
            try:
                sslobj.do_handshake()
                break
            except _ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    client_bytes += pending
                    try:
                        sock.sendall(pending)
                    except Exception:
                        break
                try:
                    data = sock.recv(16384)
                except Exception:
                    break
                if not data:
                    break
                server_bytes += data
                incoming.write(data)
            except _ssl.SSLWantWriteError:
                pending = outgoing.read()
                if pending:
                    client_bytes += pending
                    try:
                        sock.sendall(pending)
                    except Exception:
                        break
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                break

        try:
            pending = outgoing.read()
            if pending:
                client_bytes += pending
        except Exception:
            pass

        cipher = ""
        version = ""
        try:
            # SSLObject (BIO based) exposes .cipher(), not .getcipher()
            info = sslobj.cipher()
            if info:
                cipher = f"{info[0]} ({info[1]})"
        except Exception:
            pass
        try:
            ver = sslobj.version()
            if ver:
                version = ver
        except Exception:
            pass
        return {"client": client_bytes, "server": server_bytes, "cipher": cipher,
                "tls_version": version, "error": last_error}
    except Exception:
        return {"client": b"", "server": b"", "cipher": "", "tls_version": ""}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fingerprint_endpoint(ip: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """Capture a handshake and return whatever fingerprints can be derived."""
    captured = capture_handshake_bytes(ip, port, timeout)
    out: Dict[str, Any] = {
        "ja3_source": "native",
        "tls_version": captured.get("tls_version", ""),
        "tls_cipher": captured.get("cipher", ""),
    }
    if captured.get("error"):
        out["ja3_capture_error"] = captured["error"][:120]
    if captured.get("client"):
        client = parse_client_hello(captured["client"])
        if client:
            out.update(client)
    if captured.get("server"):
        server = parse_server_hello(captured["server"])
        if server:
            out.update(server)
    return out
