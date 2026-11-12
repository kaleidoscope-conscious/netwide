"""
NetPulse License Authority — asymmetric (Ed25519) license signing.

Why this exists
---------------
License keys are HMAC-signed payloads. A shared-secret HMAC can only be
verified by the node that minted it, so a key bought by a customer could not
be activated on the customer's own machine. Ed25519 fixes that properly:

  * The **private key** stays on the operator's machine (never in the repo).
  * The **public key** ships inside the product. A public key cannot sign, so
    shipping it grants no ability to forge licenses.

Key resolution order
--------------------
1. ``NETPULSE_LICENSE_PRIVATE_KEY`` (env, hex-encoded raw 32-byte seed)
2. ``~/.config/netpulse/authority_ed25519.key`` (operator-only file, mode 600)
3. None -> the node falls back to legacy HMAC signing (node-local keys only)

The embedded public key is a constant so every NetPulse install can verify
operator-signed licenses offline. It can be overridden with
``NETPULSE_LICENSE_PUBLIC_KEY`` (used by the test-suite and by operators who
rotate keys).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional, Tuple

# Public key of the license authority. Safe to ship: it can only verify.
EMBEDDED_PUBLIC_KEY_B64 = "pw5EEm.yK4uc1yAHyIMsGAlw1B2m9F8ZTci_1vSaN9s"

_PRIVATE_KEY_ENV = "NETPULSE_LICENSE_PRIVATE_KEY"
_PUBLIC_KEY_ENV = "NETPULSE_LICENSE_PUBLIC_KEY"
_PRIVATE_KEY_PATH = Path(
    os.environ.get(
        "NETPULSE_LICENSE_KEY_PATH",
        str(Path(os.path.expanduser("~")) / ".config" / "netpulse" / "authority_ed25519.key"),
    )
)


def _crypto():
    """Import the crypto backend lazily so the module imports without the dep."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
        return Ed25519PrivateKey, Ed25519PublicKey
    except Exception as exc:  # pragma: no cover - dependency missing
        raise RuntimeError(
            "The 'cryptography' package is required for NetPulse license signing. "
            "Install it with: pip install cryptography"
        ) from exc


def _b64url_encode(raw: bytes) -> str:
    """Same safe alphabet as billing.py ("._" instead of "+/") so keys never contain "-"."""
    import base64
    return base64.b64encode(raw, altchars=b"._").decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    import base64
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.b64decode((text + pad).encode("ascii"), altchars=b"._")


def public_key_b64() -> str:
    """The public key this build trusts (env override > embedded constant)."""
    override = os.environ.get(_PUBLIC_KEY_ENV, "").strip()
    return override or EMBEDDED_PUBLIC_KEY_B64


def private_key_path() -> Path:
    """Resolve the private key path at call time so env overrides always apply."""
    env_path = os.environ.get("NETPULSE_LICENSE_KEY_PATH", "").strip()
    return Path(env_path) if env_path else _PRIVATE_KEY_PATH


def load_private_key():
    """Load the operator's Ed25519 private key, or None when unavailable."""
    hex_seed = os.environ.get(_PRIVATE_KEY_ENV, "").strip()
    seed: Optional[bytes] = None
    if hex_seed:
        try:
            seed = bytes.fromhex(hex_seed)
        except ValueError:
            seed = None
    if seed is None:
        path = private_key_path()
        if path.exists():
            try:
                seed = bytes.fromhex(path.read_text(encoding="utf-8").strip())
            except ValueError:
                seed = None
    if not seed or len(seed) != 32:
        return None
    Ed25519PrivateKey, _ = _crypto()
    return Ed25519PrivateKey.from_private_bytes(seed)


def generate_keypair() -> Tuple[str, str]:
    """Create a fresh keypair. Returns (public_b64, private_hex)."""
    Ed25519PrivateKey, _ = _crypto()
    from cryptography.hazmat.primitives import serialization

    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url_encode(raw_pub), raw_priv.hex()


def save_private_key(private_hex: str) -> Path:
    """Persist the private key with owner-only permissions. Never in the repo."""
    path = private_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(private_hex.strip(), encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def sign_payload(payload_b64: str) -> Optional[str]:
    """Sign a base64url payload with the operator private key (None if absent)."""
    priv = load_private_key()
    if priv is None:
        return None
    sig = priv.sign(payload_b64.encode("ascii"))
    return _b64url_encode(sig)


def verify_payload(payload_b64: str, sig_b64: str) -> bool:
    """Verify an Ed25519 signature against the trusted public key."""
    pub = public_key_b64().strip()
    if not pub or pub == EMBEDDED_PUBLIC_KEY_B64 and not pub:
        return False
    _, Ed25519PublicKey = _crypto()
    try:
        raw_pub = _b64url_decode(pub)
        raw_sig = _b64url_decode(sig_b64)
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(raw_sig, payload_b64.encode("ascii"))
        return True
    except Exception:
        return False
