#!/usr/bin/env python3
"""
Build the protocol capture corpus used by the regression suite.

Real captures (harvested from live systems) live in tests/fixtures/*.bin and are
described by tests/fixtures/manifest.json. Fixtures that could not be harvested
are generated here from the specifications and are explicitly marked
"synthetic": true so no test can mistake a synthetic fixture for a real one.

    python3 scripts/build_capture_corpus.py
"""
import json

import pathlib
import struct
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
FIX.mkdir(parents=True, exist_ok=True)

manifest = {}
mpath = FIX / "manifest.json"
if mpath.exists():
    manifest = json.loads(mpath.read_text(encoding="utf-8"))


def save(key: str, data: bytes, meta: dict) -> None:
    name = f"{key}.bin"
    (FIX / name).write_bytes(data)
    manifest[key] = {"file": name, "bytes": len(data), **meta}
    print(f"  {key:34} {len(data):6} bytes  [{meta.get('protocol')}]")


# ---------------------------------------------------------------- synthetic SMB2
def smb2_negotiate_response(dialect: int = 0x0311, sec_mode: int = 0x03,
                             caps: int = 0x45, contexts: bool = True) -> bytes:
    """Windows-style SMB2 NEGOTIATE response (MS-SMB2 3.2.3.2)."""
    body = (
        struct.pack("<H", 65)              # StructureSize
        + struct.pack("<H", sec_mode)       # SecurityMode
        + struct.pack("<H", dialect)       # DialectRevision
        + struct.pack("<H", 1 if contexts else 0)  # NegotiateContextCount
        + uuid.UUID("00000000-0000-0000-0000-000000000000").bytes_le  # ServerGuid
        + struct.pack("<I", caps)          # Capabilities
        + struct.pack("<I", 0)             # NegotiateContextOffset (filled below)
        + struct.pack("<H", 0)             # Reserved2
    )
    # The fixed structure is 34 bytes; dialects fill it out to the 64-byte
    # StructureSize, followed by one padding byte (MS-SMB2 3.2.3.2).
    dialects = b"".join(struct.pack("<H", d) for d in (0x0202, 0x0210, 0x0300, 0x0302, 0x0311) * 3)
    pad = b"\x00"
    ctx = b""
    if contexts:
        ctx_body = (
            struct.pack("<H", 1)             # HashAlgorithmCount
            + struct.pack("<H", 32)          # SaltLength
            + struct.pack("<H", 0x0001)      # SHA-512
            + (b"\x11" * 32)                # Salt
        )
        ctx = struct.pack("<H", 0x0001) + struct.pack("<H", len(ctx_body)) + ctx_body
    body = body + dialects
    ctx_offset = 64 + len(body) + len(pad)
    body = body[:28] + struct.pack("<I", ctx_offset) + body[32:]
    smb2_header = (
        b"\xfeSMB"                       # ProtocolId
        + struct.pack("<H", 64)          # StructureSize = 64
        + struct.pack("<H", 0)           # CreditCharge
        + struct.pack("<I", 0)           # Status
        + struct.pack("<H", 0)           # Command = NEGOTIATE
        + struct.pack("<H", 31)          # CreditRequest
        + struct.pack("<I", 0)           # Flags
        + struct.pack("<I", 0)           # NextCommand
        + struct.pack("<Q", 1)           # MessageId
        + struct.pack("<I", 0)           # Reserved / ProcessId
        + struct.pack("<I", 0)           # TreeId
        + struct.pack("<Q", 0)           # SessionId
        + (b"\x00" * 16)                 # Signature
    )
    payload = smb2_header + body + pad + ctx
    netbios = b"\x00" + struct.pack(">I", len(payload))[1:]
    return netbios + payload


# ------------------------------------------------- synthetic embedded SSH KEXINIT
def ssh_kexinit(kex, hostkeys, enc, mac, comp, langs="en-US") -> bytes:
    """Build an RFC 4253 SSH_MSG_KEXINIT payload (embedded-firmware style)."""
    payload = b"\x14" + (b"\x00" * 16)
    # RFC 4253 defines exactly ten name-lists.
    for item in (kex, hostkeys, enc, enc, mac, mac, comp, comp, langs, langs):
        payload += struct.pack(">I", len(item)) + item.encode()
    payload += b"\x00" + struct.pack(">I", 0)
    return payload


def main() -> None:
    print("building capture corpus:")

    # --- synthetic SMB2 3.1.1 response with preauth-integrity context ---
    save("smb2_negotiate_response_synthetic_win311", smb2_negotiate_response(),
         {"protocol": "smb2-negotiate-response", "source": "synthetic", "synthetic": True,
          "note": "Constructed from MS-SMB2 3.2.3.2 (Windows-style 3.1.1 with preauth context)."})

    # --- synthetic SMB2 2.1 response, signing enabled but not required ---
    save("smb2_negotiate_response_synthetic_smb21", smb2_negotiate_response(
        dialect=0x0210, sec_mode=0x01, caps=0x05, contexts=False),
        {"protocol": "smb2-negotiate-response", "source": "synthetic", "synthetic": True,
         "note": "SMB 2.1, signing enabled but not required -> relay risk indicator."})

    # --- synthetic embedded-firmware SSH (Dropbear-style algorithm set) ---
    save("ssh_kexinit_synthetic_embedded",
         ssh_kexinit(
             kex="curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
             hostkeys="ssh-ed25519,rsa-sha2-256",
             enc="aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com",
             mac="hmac-sha2-256,hmac-sha2-512",
             comp="none,zlib@openssh.com"),
         {"protocol": "ssh-kexinit", "source": "synthetic", "synthetic": True,
          "note": "Embedded firmware style algorithm set (no PQ KEX, no CBC)."})

    # --- synthetic legacy SSH (SHA-1 host key + CBC) ---
    save("ssh_kexinit_synthetic_legacy",
         ssh_kexinit(
             kex="diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
             hostkeys="ssh-rsa,ssh-dss",
             enc="aes128-cbc,3des-cbc",
             mac="hmac-sha1,hmac-md5",
             comp="none"),
         {"protocol": "ssh-kexinit", "source": "synthetic", "synthetic": True,
          "note": "Legacy server: SHA-1 host key + CBC + SHA-1 MAC (must never grade above D)."})

    (FIX / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\ncorpus: {len(manifest)} fixtures in {FIX}")


if __name__ == "__main__":
    main()
