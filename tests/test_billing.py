"""
Unit tests for NetPulse Cryptographic License Engine, 3-Tier Entitlements & Stripe Webhook HMAC verification.
"""

import hashlib
import hmac
import json
import os
import tempfile

from netpulse.billing import SubscriptionManager


def test_mint_and_verify_license_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "sub_test.db")
        mgr = SubscriptionManager(db_path=db_path)

        # Starts on free tier
        st0 = mgr.get_subscription_status()
        assert st0["tier"] == "free"
        assert st0["is_paid"] is False

        # Check Pro feature is gated on free tier
        ok_pro, err_pro = mgr.check_feature_access("roku_control")
        assert ok_pro is False
        assert err_pro is not None
        assert err_pro["upgrade_required"] is True
        assert err_pro["required_tier"] == "pro"

        # Mint a Pro Guardian key
        minted_pro = mgr.mint_license_key(tier="pro", plan="monthly", email="user@example.com")
        assert minted_pro["ok"] is True
        assert minted_pro["license_key"].startswith("NP1-PRO-")

        ver_pro = mgr.verify_license_key(minted_pro["license_key"])
        assert ver_pro["valid"] is True
        assert ver_pro["tier"] == "pro"

        # Activate Pro key -> Pro feature allowed, Enterprise feature still gated
        act_pro = mgr.activate_license_key(minted_pro["license_key"])
        assert act_pro["ok"] is True
        assert mgr.check_feature_access("roku_control")[0] is True
        assert mgr.check_feature_access("quarantine")[0] is False

        # Mint & activate Sovereign Enterprise Lifetime key -> all features allowed
        minted_ent = mgr.mint_license_key(tier="enterprise", plan="lifetime", email="founder@netpulse.io")
        assert minted_ent["expires_at"] == 0
        mgr.activate_license_key(minted_ent["license_key"])
        assert mgr.check_feature_access("quarantine")[0] is True
        assert mgr.check_feature_access("forensic_export")[0] is True
        assert mgr.check_feature_access("unrecognized_bogus_feature")[0] is False

        # Revoke the Enterprise key -> automatically invalidates and reverts to free
        rev = mgr.revoke_license(minted_ent["jti"])
        assert rev["ok"] is True
        assert mgr.verify_license_key(minted_ent["license_key"])["valid"] is False
        assert mgr.get_subscription_status()["tier"] == "free"


def test_tampered_license_key_rejected():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "sub_tamper.db")
        mgr = SubscriptionManager(db_path=db_path)

        minted = mgr.mint_license_key(tier="pro", plan="annual", email="sec@netpulse.io")
        key = minted["license_key"]
        # Tamper with signature
        tampered = key[:-2] + ("AA" if not key.endswith("AA") else "BB")
        ver = mgr.verify_license_key(tampered)
        assert ver["valid"] is False


def test_stripe_webhook_hmac_verification():
    import time as _time

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "sub_wh.db")
        mgr = SubscriptionManager(db_path=db_path)
        wh_secret = "whsec_test_secret_12345"
        mgr.configure_stripe_keys(secret_key="sk_test_123", webhook_secret=wh_secret)

        payload_dict = {
            "id": "evt_test_wh_1",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_999",
                    "payment_status": "paid",
                    "customer": "cus_test_888",
                    "customer_email": "stripe_buyer@netpulse.io",
                    "metadata": {
                        "netpulse_tier": "enterprise",
                        "netpulse_plan": "annual",
                    },
                }
            },
        }
        raw_body = json.dumps(payload_dict).encode("utf-8")
        # Live timestamp (the 5-minute anti-replay tolerance window rejects stale ones)
        t_str = str(int(_time.time()))
        sig = hmac.new(
            wh_secret.encode("utf-8"),
            f"{t_str}.".encode("utf-8") + raw_body,
            hashlib.sha256,
        ).hexdigest()
        sig_header = f"t={t_str},v1={sig}"

        res = mgr.handle_stripe_webhook(raw_body, sig_header)
        assert res["ok"] is True
        assert res["minted"]["tier"] == "enterprise"
        assert mgr.get_subscription_status()["tier"] == "enterprise"

        # Idempotency: a duplicate delivery of the same event must NOT re-mint
        # (and must report the duplicate nature).
        res_dup = mgr.handle_stripe_webhook(raw_body, sig_header)
        assert res_dup["ok"] is True
        assert res_dup.get("duplicate") is True
        assert mgr.get_subscription_status()["tier"] == "enterprise"

        # Fail-closed: an unsigned payload (with no sig header) must be rejected,
        # and the rejection must not have altered the active subscription state.
        res_unsigned = mgr.handle_stripe_webhook(raw_body, "")
        assert res_unsigned["ok"] is False
        assert "signature" in res_unsigned["error"].lower()
        assert mgr.get_subscription_status()["tier"] == "enterprise"

        # Webhook rejection on unpaid or missing payment_status
        unpaid_payload = {
            "id": "evt_unpaid_1",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_unpaid",
                    "payment_status": "unpaid",
                    "customer": "cus_test_unpaid",
                    "metadata": {"netpulse_tier": "enterprise"},
                }
            },
        }
        raw_unpaid = json.dumps(unpaid_payload).encode("utf-8")
        sig_unpaid = hmac.new(
            wh_secret.encode("utf-8"),
            f"{t_str}.".encode("utf-8") + raw_unpaid,
            hashlib.sha256,
        ).hexdigest()
        res_unpaid = mgr.handle_stripe_webhook(raw_unpaid, f"t={t_str},v1={sig_unpaid}")
        assert res_unpaid["ok"] is False
        assert "payment_status must be 'paid'" in res_unpaid["error"]


def test_operator_signed_license_verifies_on_a_customer_node():
    """Ed25519 license authority: a key minted by the operator verifies anywhere."""
    import os as _os
    import tempfile as _tempfile
    from netpulse import license_authority as _authority
    from netpulse.billing import SubscriptionManager as _SM

    key_path = _tempfile.mktemp(suffix=".authority.key")
    public, private_hex = _authority.generate_keypair()
    _os.environ["NETPULSE_LICENSE_KEY_PATH"] = key_path
    _os.environ["NETPULSE_LICENSE_PUBLIC_KEY"] = public
    try:
        with open(key_path, "w", encoding="utf-8") as fh:
            fh.write(private_hex)

        operator = _SM(db_path=_tempfile.mktemp(suffix=".db"))
        minted = operator.mint_license_key(tier="enterprise", plan="lifetime", email="buyer@example.com")
        key = minted["license_key"]
        assert key.startswith("NP1-ENTERPRISE-")
        assert operator.verify_license_key(key).get("valid") is True

        # Customer machine: no private key, only the shipped public key.
        _os.remove(key_path)
        customer = _SM(db_path=_tempfile.mktemp(suffix=".db"))
        assert _authority.load_private_key() is None
        verified = customer.verify_license_key(key)
        assert verified.get("valid") is True, verified.get("error")
        assert verified.get("tier") == "enterprise"

        activated = customer.activate_license_key(key)
        assert activated.get("ok") is True
        assert customer.get_subscription_status().get("tier") == "enterprise"
    finally:
        _os.environ.pop("NETPULSE_LICENSE_KEY_PATH", None)
        _os.environ.pop("NETPULSE_LICENSE_PUBLIC_KEY", None)
        if _os.path.exists(key_path):
            _os.remove(key_path)


def test_license_signature_scheme_is_recorded_in_payload():
    """The payload declares its signature scheme so verifiers pick the right path."""
    import json as _json
    import tempfile as _tempfile
    from netpulse.billing import _b64url_decode
    from netpulse.billing import SubscriptionManager as _SM

    mgr = _SM(db_path=_tempfile.mktemp(suffix=".db"))
    minted = mgr.mint_license_key(tier="pro", plan="monthly", email="probe@example.com")
    parts = minted["license_key"].split("-")
    assert len(parts) == 4, "license key must stay dash-safe for parsing"
    payload = _json.loads(_b64url_decode(parts[2]).decode("utf-8"))
    assert payload.get("sk") in ("ed25519", "hmac")
    assert payload.get("jti") and payload.get("tier") == "pro"
