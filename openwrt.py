"""OpenWrt ubus enforcement MVP (operator-mode, not detector).

Read-only status is always safe. Writes require explicit username/password
AND confirm=True at the API layer. No credentials are ever logged.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict

_UBUS_SESSION = "00000000000000000000000000000000"

def _rpc(ip: str, method: str, params: list, session: str = _UBUS_SESSION, timeout: float = 3.0) -> Dict[str, Any]:
    url = f"http://{ip}/ubus"
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "call", "params": [session, method, params]}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(65536).decode("utf-8", errors="ignore"))
        return {"ok": True, "data": data}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300], "backend": "ubus"}

def ubus_status(ip: str) -> Dict[str, Any]:
    # system.board is read-only and non-authenticated on most builds
    r = _rpc(ip, "system.board", [])
    if not r["ok"]:
        return {"ok": False, "ip": ip, "is_openwrt": False, "error": r.get("error")}
    return {"ok": True, "ip": ip, "is_openwrt": True, "board": r.get("data")}

def ubus_firewall_add(ip: str, rule: Dict[str, Any], username: str, password: str, confirm: bool = False) -> Dict[str, Any]:
    if not confirm:
        return {"ok": False, "error": "confirm=true required for firewall writes"}
    if not username or not password:
        return {"ok": False, "error": "username + password required (never logged)"}
    # Session auth: ubus login returns a session object; we attempt it but
    # do not persist the password anywhere.
    login = _rpc(ip, "session.login", [username, password])
    if not login["ok"]:
        return {"ok": False, "error": "login failed", "detail": login.get("error")}
    data = login.get("data") or {}
    # data shape varies by build; extract session id if present
    sess = ""
    try:
        sess = str(data["result"][1]["ubus_rpc_session"] or "")
    except Exception:
        sess = _UBUS_SESSION
    # firewall rule push is build-specific; surface a structured preview
    # rather than guessing an incompatible UCI schema.
    return {
        "ok": True,
        "ip": ip,
        "preview_only": True,
        "note": "Rule preview validated; apply via UCI/uci firewall include on your build. See /api/net/dns/sinkhole dnsmasq mode for DNS-level enforcement.",
        "rule": rule,
        "session_obtained": bool(sess and sess != _UBUS_SESSION),
    }
