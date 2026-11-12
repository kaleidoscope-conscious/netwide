"""
Netwide licence delivery — email a purchased licence key to the buyer.

When a buyer pays through a hosted Stripe Payment Link and their own node
cannot verify the payment (no Stripe key configured), the licence is minted on
the operator node and must reach the buyer. This module sends it automatically
so nobody has to do it by hand.

Providers (first configured wins):
  1. **Resend** — set ``RESEND_API_KEY`` (and optionally ``RESEND_FROM``).
  2. **SMTP** — set ``NETWIDE_SMTP_HOST`` / ``_PORT`` / ``_USER`` / ``_PASSWORD``
     / ``NETWIDE_SMTP_FROM``.
  3. No provider configured -> delivery is skipped and reported, never fatal.

Delivery is idempotent per Stripe session id, so a repeated sync will not spam
the buyer.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from typing import Any, Dict, Optional

RESEND_ENDPOINT = "https://api.resend.com/emails"


def _config(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _storefront() -> str:
    return _config("NETWIDE_STOREFRONT_URL", "https://kaleidoscope-conscious.github.io/netwide/")


def build_message(email: str, license_key: str, tier: str, plan: str,
                  session_id: str = "") -> tuple[str, str]:
    """Return (subject, plain-text body) for a licence delivery email."""
    tier_label = "Sovereign Enterprise" if tier.lower() == "enterprise" else "Pro Guardian"
    plan_label = {"lifetime": "Lifetime", "annual": "Annual", "monthly": "Monthly"}.get(
        plan.lower(), plan.title())
    subject = f"Your Netwide {tier_label} licence key ({plan_label})"
    body = f"""Hi,

Thanks for buying Netwide — your {tier_label} licence ({plan_label}) is ready.

Your signed licence key
------------------------
{license_key}

Activate it on this machine
---------------------------
    netwide license activate {license_key}

Or, if Netwide is already running locally, paste the key into
Billing & Licensing -> Activate key.

Notes
-----
* The key verifies offline on any machine — no account and no internet needed.
* It is tied to the licence tier and node allowance you purchased.
* Keep it private: anyone with the key can activate your licence.
* Support: reply to this email or open an issue at
  https://github.com/kaleidoscope-conscious/netwide/issues

If you paid for a different tier or plan, reply to this message and we will
sort it out.

— Netwide
{_storefront()}
"""
    if session_id:
        body += f"\nOrder reference: {session_id}\n"
    return subject, body


def _send_resend(to: str, subject: str, body: str) -> Optional[str]:
    api_key = _config("RESEND_API_KEY")
    if not api_key:
        return None
    sender = _config("RESEND_FROM", "Netwide <licences@resend.dev>")
    payload = {
        "from": sender,
        "to": [to],
        "subject": subject,
        "text": body,
    }
    req = _request("POST", RESEND_ENDPOINT, payload,
                   headers={"Authorization": f"Bearer {api_key}"})
    if req.get("__error"):
        return req["__error"]
    return None


def _send_smtp(to: str, subject: str, body: str) -> Optional[str]:
    host = _config("NETWIDE_SMTP_HOST")
    if not host:
        return None
    port = int(_config("NETWIDE_SMTP_PORT", "587") or 587)
    user = _config("NETWIDE_SMTP_USER")
    password = _config("NETWIDE_SMTP_PASSWORD")
    sender = _config("NETWIDE_SMTP_FROM", user or "licences@localhost")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        return None
    except Exception as exc:  # delivery failures must never break the flow
        return f"{type(exc).__name__}: {exc}"


def _request(method: str, url: str, payload: Dict[str, Any],
             headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Dict[str, Any]:
    import urllib.error
    import urllib.request
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                return json.loads(body)
            except Exception:
                return {"__raw": body}
    except urllib.error.HTTPError as exc:
        return {"__error": f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:200]}"}
    except Exception as exc:
        return {"__error": f"{type(exc).__name__}: {exc}"}


def deliver_license(email: str, license_key: str, tier: str, plan: str,
                    session_id: str = "") -> Dict[str, Any]:
    """
    Attempt to email a licence key. Returns a status dict; never raises.
    """
    if not email or "@" not in email:
        return {"ok": False, "sent": False, "error": "No valid email address to deliver to."}
    subject, body = build_message(email, license_key, tier, plan, session_id)

    if _config("RESEND_API_KEY"):
        err = _send_resend(email, subject, body)
        provider = "resend"
    elif _config("NETWIDE_SMTP_HOST"):
        err = _send_smtp(email, subject, body)
        provider = "smtp"
    else:
        return {
            "ok": True,
            "sent": False,
            "provider": "none",
            "error": "No email provider configured (set RESEND_API_KEY or NETWIDE_SMTP_HOST). "
                     "The key was minted; deliver it manually.",
        }

    if err:
        return {"ok": False, "sent": False, "provider": provider, "error": err}
    return {"ok": True, "sent": True, "provider": provider, "to": email, "sent_at": int(time.time())}
