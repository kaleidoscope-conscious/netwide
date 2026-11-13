#!/usr/bin/env python3
"""
Google Play Developer API v3 Automated App Bundle (.aab) Uploader for Netwide.
Implements the full Google Play Android Publisher v3 workflow:
  1. Offline AAB structural & cryptographic signature verification (jarsigner + BundleConfig.pb)
  2. OAuth2 Service Account JWT assertion (RS256 via openssl) -> Access Token exchange
  3. POST /androidpublisher/v3/applications/{packageName}/edits (create edit transaction)
  4. POST /upload/androidpublisher/v3/applications/{packageName}/edits/{editId}/bundles (upload .aab)
  5. PUT  /androidpublisher/v3/applications/{packageName}/edits/{editId}/tracks/{track} (assign release)
  6. POST /androidpublisher/v3/applications/{packageName}/edits/{editId}:commit (publish to track)
"""

from __future__ import annotations

import pathlib

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict

DEFAULT_AAB = Path(str(pathlib.Path(__file__).resolve().parents[1] / "static/Netwide-Mobile-PlayStore.aab"))
DEFAULT_PACKAGE = "com.netwide.mobile"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
PUBLISHER_SCOPE = "https://www.googleapis.com/auth/androidpublisher"
API_BASE = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications"
UPLOAD_BASE = "https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def verify_aab_bundle(aab_path: Path) -> Dict[str, Any]:
    if not aab_path.exists():
        raise FileNotFoundError(f"AAB bundle not found at {aab_path}")

    required_entries = {
        "BundleConfig.pb",
        "base/manifest/AndroidManifest.xml",
        "base/dex/classes.dex",
        "base/resources.pb",
        "base/assets/mobile.html",
    }
    with zipfile.ZipFile(aab_path, "r") as zf:
        names = set(zf.namelist())
        dir_entries = [n for n in names if n.endswith("/")]
        if dir_entries:
            raise ValueError(f"AAB contains prohibited directory entries: {dir_entries}")
        missing = required_entries - names
        if missing:
            raise ValueError(f"AAB is missing required entries: {sorted(missing)}")
        has_sig = any(n.startswith("META-INF/") and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC")) for n in names)
        if not has_sig:
            raise ValueError("AAB is not signed (missing META-INF/*.RSA certificate)")

    proc = subprocess.run(
        ["jarsigner", "-verify", str(aab_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or "jar verified" not in proc.stdout:
        raise RuntimeError(f"jarsigner verification failed: {proc.stdout} {proc.stderr}")

    sha256_hex = hashlib.sha256(aab_path.read_bytes()).hexdigest()
    return {
        "ok": True,
        "path": str(aab_path),
        "size_bytes": aab_path.stat().st_size,
        "sha256": sha256_hex,
        "entries_count": len(names),
    }


def mint_service_account_access_token(sa_json_path: Path) -> str:
    sa = json.loads(sa_json_path.read_text(encoding="utf-8"))
    client_email = sa["client_email"]
    private_key_pem = sa["private_key"]
    now = int(time.time())

    header_b64 = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf-8"))
    claims_b64 = _b64url(
        json.dumps(
            {
                "iss": client_email,
                "scope": PUBLISHER_SCOPE,
                "aud": OAUTH_TOKEN_URL,
                "iat": now,
                "exp": now + 3600,
            }
        ).encode("utf-8")
    )
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")

    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as kf:
        kf.write(private_key_pem)
        key_path = kf.name

    try:
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input,
            capture_output=True,
            check=True,
        )
        sig_b64 = _b64url(proc.stdout)
    finally:
        if os.path.exists(key_path):
            os.unlink(key_path)

    jwt_assertion = f"{header_b64}.{claims_b64}.{sig_b64}"
    body = (
        f"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={jwt_assertion}"
    ).encode("utf-8")
    req = urllib.request.Request(
        OAUTH_TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return str(payload["access_token"])


def _api_json(
    method: str,
    url: str,
    token: str,
    payload: Dict[str, Any] | None = None,
    raw_bytes: bytes | None = None,
    content_type: str = "application/json",
) -> Dict[str, Any]:
    data = raw_bytes if raw_bytes is not None else (json.dumps(payload or {}).encode("utf-8") if method in ("POST", "PUT") else None)
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        text = resp.read().decode("utf-8")
        return json.loads(text) if text else {}


def upload_aab_to_play_store(
    aab_path: Path,
    sa_json_path: Path,
    package_name: str,
    track: str,
    release_name: str,
    release_notes: str,
) -> Dict[str, Any]:
    token = mint_service_account_access_token(sa_json_path)

    # 1. Insert new Edit session
    edit = _api_json("POST", f"{API_BASE}/{package_name}/edits", token, {})
    edit_id = edit["id"]
    print(f"[1/4] Created Google Play Edit Session: {edit_id}")

    # 2. Upload AAB binary
    aab_bytes = aab_path.read_bytes()
    bundle_resp = _api_json(
        "POST",
        f"{UPLOAD_BASE}/{package_name}/edits/{edit_id}/bundles?uploadType=media",
        token,
        raw_bytes=aab_bytes,
        content_type="application/octet-stream",
    )
    version_code = bundle_resp["versionCode"]
    print(f"[2/4] Uploaded AAB Bundle (versionCode={version_code}, sha256={bundle_resp.get('sha256')})")

    # 3. Assign bundle to release track
    track_body = {
        "track": track,
        "releases": [
            {
                "name": release_name,
                "versionCodes": [str(version_code)],
                "status": "completed",
                "releaseNotes": [{"language": "en-US", "text": release_notes}],
            }
        ],
    }
    _api_json(
        "PUT",
        f"{API_BASE}/{package_name}/edits/{edit_id}/tracks/{track}",
        token,
        payload=track_body,
    )
    print(f"[3/4] Assigned versionCode {version_code} to '{track}' track")

    # 4. Commit edit
    commit_resp = _api_json(
        "POST",
        f"{API_BASE}/{package_name}/edits/{edit_id}:commit",
        token,
        payload={},
    )
    print(f"[4/4] Committed Google Play release! Edit ID {commit_resp.get('id')} is now live on '{track}'.")
    return {
        "ok": True,
        "package_name": package_name,
        "edit_id": edit_id,
        "version_code": version_code,
        "track": track,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload Netwide .aab bundle to Google Play Console API v3")
    parser.add_argument("--aab", type=Path, default=DEFAULT_AAB, help="Path to signed .aab file")
    parser.add_argument("--package", default=DEFAULT_PACKAGE, help="Android applicationId (default: com.netwide.mobile)")
    parser.add_argument("--track", choices=["internal", "alpha", "beta", "production"], default="internal")
    parser.add_argument("--service-account", type=Path, default=Path(os.environ.get("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON", "")))
    parser.add_argument("--release-name", default="v4.8.0 ")
    parser.add_argument(
        "--release-notes",
        default="Netwide v4.8.0: 8-Stage Hidden Wi-Fi De-Cloaker, Walk-Around RF Geiger Counter, 3-Axis Magnetometer, TLS JA3 DPI & Smart LAN Control.",
    )
    parser.add_argument("--verify-only", action="store_true", help="Verify .aab bundle integrity without calling Google Play API")
    args = parser.parse_args()

    info = verify_aab_bundle(args.aab)
    print(f"✔ Verified AAB Bundle: {info['path']} ({info['size_bytes']} bytes, sha256={info['sha256'][:16]}...)")

    if args.verify_only or not str(args.service_account) or str(args.service_account) == "." or not args.service_account.exists():
        if not args.verify_only:
            print(
                "\n[READY FOR GOOGLE PLAY UPLOAD]\n"
                "  • Option A (Web UI): Drag & drop /home/jg/Desktop/Netwide-Mobile-PlayStore.aab into https://play.google.com/console\n"
                "  • Option B (Automated API): Provide your Google Play Service Account JSON key:\n"
                f"      python3 {__file__} --service-account /path/to/play-service-account.json --track {args.track}"
            )
        return 0

    try:
        upload_aab_to_play_store(
            aab_path=args.aab,
            sa_json_path=args.service_account,
            package_name=args.package,
            track=args.track,
            release_name=args.release_name,
            release_notes=args.release_notes,
        )
    except urllib.error.HTTPError as exc:
        err_txt = exc.read().decode("utf-8", errors="replace")
        print(f"Google Play API HTTP {exc.code}: {err_txt}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
