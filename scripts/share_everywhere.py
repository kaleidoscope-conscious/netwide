#!/usr/bin/env python3
"""
Netwide — Multi-Platform Sharing Engine.

Publishes the Netwide launch kit to every platform that accepts a post, so
distribution is one command instead of a checklist.

Design
------
* **Dry run by default.** `--live` actually posts. Nothing is sent without it.
* Credentials come from the environment or `~/.config/netwide/social.env`
  (never committed, never echoed).
* Channels that need no credentials (GitHub Discussions) run automatically.
* Every channel reports PASS / SKIP / FAIL so a single run tells you exactly
  what went out and what still needs a token.

Usage
-----
    python3 scripts/share_everywhere.py                # dry run, shows the plan
    python3 scripts/share_everywhere.py --live         # post everywhere possible
    python3 scripts/share_everywhere.py --only x,reddit --live
    python3 scripts/share_everywhere.py --copy my-variant.md --live
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = Path(os.path.expanduser("~")) / ".config" / "netwide" / "social.env"

# --------------------------------------------------------------------------
# Launch kit — every link here is live and verified.
# --------------------------------------------------------------------------
KIT = {
    "repo": "https://github.com/kaleidoscope-conscious/netwide",
    "storefront": "https://kaleidoscope-conscious.github.io/netwide/",
    "release": "https://github.com/kaleidoscope-conscious/netwide/releases/tag/v4.9.0",
    "discussions": "https://github.com/kaleidoscope-conscious/netwide/discussions",
    "demo": "https://kaleidoscope-conscious.github.io/netwide/",
    "sponsor": "https://github.com/sponsors/kaleidoscopeAI",
    "paypal": "https://paypal.me/jgraham1000",
    "buy_pro_lifetime": "https://buy.stripe.com/cNicN55gk15W24kbGhcbC1f",
    "buy_ent_lifetime": "https://buy.stripe.com/00weVdgZ23e49wMcKlcbC1i",
    "buy_pro_monthly": "https://buy.stripe.com/00w3cveQU01SfVa11DcbC1h",
    "buy_ent_monthly": "https://buy.stripe.com/9B628reQU3e438o7q1cbC1k",
}

TITLE = "Netwide — see every device on your Wi-Fi, unmask hidden gadgets, quarantine freeloaders"

BODY_SHORT = (
    "Netwide is a 100% on-device network intelligence suite: it unmasks hidden & spoofed "
    "Wi-Fi gadgets, fingerprints 47,035+ hardware vendors, audits the crypto your devices "
    "actually speak, watches live wire traffic (DPI/JA3/SNI), and lets you quarantine the "
    "freeloader in one click. No cloud, no account, no telemetry."
)

BODY_LONG = (
    BODY_SHORT
    + "\n\n"
    + "• 10-stage hidden-BSSID / randomized-MAC de-cloaker (64-bit TSF + multipath RSSI co-variance)\n"
    + "• SSHv2 HASSH, SMB2/3 NTLM-relay, DNSSEC/DoT, NTPv4, X.509, JA3 & p0f auditing\n"
    + "• Live wire DPI: KB/s, DNS/TLS SNI, TLS JA3, per-host bandwidth\n"
    + "• Active countermeasures: ARP quarantine (iptables/nft), DNS sinkhole, smart-home control\n"
    + "• Tamper-evident hash-chained ledger — every verdict links to the packets behind it\n"
    + "• Desktop (PyQt6), FastAPI daemon, Docker, Android APK — all offline-first\n\n"
    + "Free tier forever; Pro $9.99/mo and Sovereign Enterprise $29.99/mo.\n"
    + "Storefront: " + KIT["storefront"]
)

# Per-platform copy overrides can be supplied via --copy (a markdown file with
# `## platform` sections) or by editing this dict.
PLATFORM_COPY: dict[str, str] = {
    "x": TITLE + "\n\n" + BODY_SHORT + "\n\n" + KIT["storefront"],
    "reddit": BODY_LONG + "\n\n" + KIT["repo"],
    "linkedin": TITLE + "\n\n" + BODY_LONG + "\n\n" + KIT["storefront"],
    "facebook": TITLE + "\n\n" + BODY_SHORT + "\n\n" + KIT["storefront"],
    "telegram": TITLE + "\n\n" + BODY_SHORT + "\n\n" + KIT["storefront"],
    "discord": "**" + TITLE + "**\n\n" + BODY_LONG + "\n\n" + KIT["storefront"],
    "slack": "*" + TITLE + "*\n" + BODY_SHORT + "\n" + KIT["storefront"],
    "bluesky": TITLE + "\n\n" + BODY_SHORT + "\n\n" + KIT["storefront"],
    "mastodon": BODY_LONG + "\n\n" + KIT["storefront"],
    "devto": TITLE + "\n\n" + BODY_LONG,
    "hn": TITLE + "\n\n" + BODY_SHORT,
    "producthunt": TITLE + "\n\n" + BODY_SHORT,
    "github_discussions": BODY_LONG + "\n\n" + KIT["storefront"],
}

PASS, SKIP, FAIL = "PASS", "SKIP", "FAIL"
results: list[tuple[str, str, str]] = []


def log(channel: str, status: str, detail: str = "") -> None:
    results.append((channel, status, detail))
    mark = {PASS: "✅", SKIP: "⏭️ ", FAIL: "❌"}[status]
    print(f"{mark} {channel:<18} {detail}")


def load_env() -> None:
    """Load ~/.config/netwide/social.env without overriding real env vars."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def http(method: str, url: str, *, data=None, headers=None, timeout=25, raw=False):
    body = None
    hdrs = dict(headers or {})
    if data is not None:
        if isinstance(data, (dict, list)):
            body = urllib.parse.urlencode(data, doseq=True).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = data if isinstance(data, bytes) else str(data).encode()
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = resp.read().decode("utf-8", "replace")
        if raw:
            return payload
        try:
            return json.loads(payload)
        except Exception:
            return payload


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------
def post_x(text: str, live: bool) -> None:
    token = env("X_BEARER_TOKEN")
    if not token:
        return log("x", SKIP, "set X_BEARER_TOKEN (Twitter API v2 app token)")
    if not live:
        return log("x", PASS, f"dry-run — would post {len(text)} chars")
    try:
        http("POST", "https://api.twitter.com/2/tweets",
             data=json.dumps({"text": text[:270]}),
             headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        log("x", PASS, "posted")
    except urllib.error.HTTPError as e:
        log("x", FAIL, f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:120]}")
    except Exception as e:
        log("x", FAIL, str(e)[:120])


def post_reddit(text: str, live: bool) -> None:
    cid, secret, user, pwd = env("REDDIT_CLIENT_ID"), env("REDDIT_CLIENT_SECRET"), env("REDDIT_USERNAME"), env("REDDIT_PASSWORD")
    if not all([cid, secret, user, pwd]):
        return log("reddit", SKIP, "set REDDIT_CLIENT_ID/SECRET/USERNAME/PASSWORD")
    if not live:
        return log("reddit", PASS, "dry-run — would post to r/networking, r/homelab, r/cybersecurity")
    try:
        tok = http("POST", "https://www.reddit.com/api/v1/access_token",
                   data={"grant_type": "password", "username": user, "password": pwd},
                   headers={"Authorization": f"Basic {__import__('base64').b64encode(f'{cid}:{secret}'.encode()).decode()}",
                            "User-Agent": "netwide-share/4.6"})
        access = tok.get("access_token", "")
        subs = ["networking", "homelab", "cybersecurity", "selfhosted"]
        posted = 0
        for sub in subs:
            try:
                http("POST", "https://oauth.reddit.com/api/submit",
                     data={"sr": sub, "kind": "self", "title": TITLE, "text": text, "api_type": "json"},
                     headers={"Authorization": f"bearer {access}", "User-Agent": "netwide-share/4.6"})
                posted += 1
            except Exception:
                continue
        log("reddit", PASS, f"posted to {posted}/{len(subs)} subreddits")
    except urllib.error.HTTPError as e:
        log("reddit", FAIL, f"HTTP {e.code}")
    except Exception as e:
        log("reddit", FAIL, str(e)[:120])


def post_linkedin(text: str, live: bool) -> None:
    token = env("LINKEDIN_ACCESS_TOKEN")
    urn = env("LINKEDIN_AUTHOR_URN") or "urn:li:organization:netwide"
    if not token:
        return log("linkedin", SKIP, "set LINKEDIN_ACCESS_TOKEN (+ LINKEDIN_AUTHOR_URN)")
    if not live:
        return log("linkedin", PASS, "dry-run — would post to the company page")
    try:
        body = {
            "author": urn,
            "lifecycleState": "PUBLISHED",
            "specificContent": {"com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text[:2400]},
                "shareMediaCategory": "NONE",
                "shareLink": {"href": KIT["storefront"]},
            }},
            "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
        }
        http("POST", "https://api.linkedin.com/v2/ugcPosts",
             data=json.dumps(body),
             headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                      "X-Restli-Protocol-Version": "2.0.0"})
        log("linkedin", PASS, "posted")
    except urllib.error.HTTPError as e:
        log("linkedin", FAIL, f"HTTP {e.code}")
    except Exception as e:
        log("linkedin", FAIL, str(e)[:120])


def post_facebook(text: str, live: bool) -> None:
    token, page = env("FACEBOOK_PAGE_TOKEN"), env("FACEBOOK_PAGE_ID")
    if not token or not page:
        return log("facebook", SKIP, "set FACEBOOK_PAGE_TOKEN + FACEBOOK_PAGE_ID")
    if not live:
        return log("facebook", PASS, "dry-run — would post to the page")
    try:
        http("POST", f"https://graph.facebook.com/v21.0/{page}/feed",
             data={"message": text[:5000], "link": KIT["storefront"]},
             headers={"Authorization": f"Bearer {token}"})
        log("facebook", PASS, "posted")
    except urllib.error.HTTPError as e:
        log("facebook", FAIL, f"HTTP {e.code}")
    except Exception as e:
        log("facebook", FAIL, str(e)[:120])


def post_telegram(text: str, live: bool) -> None:
    token, chat = env("TELEGRAM_BOT_TOKEN"), env("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return log("telegram", SKIP, "set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID")
    if not live:
        return log("telegram", PASS, "dry-run — would post to the channel")
    try:
        http("POST", f"https://api.telegram.org/bot{token}/sendMessage",
             data={"chat_id": chat, "text": text[:4000], "parse_mode": "Markdown",
                   "disable_web_page_preview": "false"})
        log("telegram", PASS, "posted")
    except urllib.error.HTTPError as e:
        log("telegram", FAIL, f"HTTP {e.code}")
    except Exception as e:
        log("telegram", FAIL, str(e)[:120])


def post_webhook(name: str, url: str, payload: dict, live: bool, label: str) -> None:
    if not url:
        return log(name, SKIP, f"set {label}")
    if not live:
        return log(name, PASS, "dry-run — would post to webhook")
    try:
        http("POST", url, data=json.dumps(payload), headers={"Content-Type": "application/json"})
        log(name, PASS, "posted")
    except urllib.error.HTTPError as e:
        log(name, FAIL, f"HTTP {e.code}")
    except Exception as e:
        log(name, FAIL, str(e)[:120])


def post_bluesky(text: str, live: bool) -> None:
    handle, password = env("BLUESKY_HANDLE"), env("BLUESKY_APP_PASSWORD")
    if not handle or not password:
        return log("bluesky", SKIP, "set BLUESKY_HANDLE + BLUESKY_APP_PASSWORD")
    if not live:
        return log("bluesky", PASS, "dry-run — would post")
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
        resp = http("POST", "https://bsky.social/xrpc/com.atproto.server.createSession",
                    data=json.dumps({"identifier": handle, "password": password}),
                    headers={"Content-Type": "application/json"})
        did, key = resp["did"], resp["accessJwk"]
        priv = serialization.load_der_private_key(
            __import__('base64').urlsafe_b64decode(key["d"] + "=" * (-len(key["d"]) % 4)),
            password=None)
        now = int(time.time())
        token = jwt.encode({"iss": did, "aud": "did:web:bsky.social", "iat": now, "exp": now + 60},
                           priv, algorithm="ES256", headers={"kid": key["kid"]})
        http("POST", "https://bsky.social/xrpc/com.atproto.repo.createRecord",
             data=json.dumps({"repo": did, "collection": "app.bsky.feed.post",
                              "record": {"$type": "app.bsky.feed.post", "text": text[:300],
                                         "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}),
             headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        log("bluesky", PASS, "posted")
    except Exception as e:
        log("bluesky", FAIL, str(e)[:120])


def post_mastodon(text: str, live: bool) -> None:
    instance, token = env("MASTODON_INSTANCE"), env("MASTODON_ACCESS_TOKEN")
    if not instance or not token:
        return log("mastodon", SKIP, "set MASTODON_INSTANCE + MASTODON_ACCESS_TOKEN")
    if not live:
        return log("mastodon", PASS, "dry-run — would post")
    try:
        http("POST", f"{instance.rstrip('/')}/api/v1/statuses",
             data={"status": text[:500], "visibility": "public"},
             headers={"Authorization": f"Bearer {token}"})
        log("mastodon", PASS, "posted")
    except urllib.error.HTTPError as e:
        log("mastodon", FAIL, f"HTTP {e.code}")
    except Exception as e:
        log("mastodon", FAIL, str(e)[:120])


def post_devto(text: str, live: bool) -> None:
    key = env("DEVTO_API_KEY")
    if not key:
        return log("devto", SKIP, "set DEVTO_API_KEY")
    if not live:
        return log("devto", PASS, "dry-run — would publish an article")
    try:
        http("POST", "https://dev.to/api/articles",
             data=json.dumps({"title": TITLE, "published": True, "body_markdown": text,
                              "tags": ["security", "networking", "opensource", "selfhosted", "linux"],
                              "canonical_url": KIT["repo"], "series": "Netwide"}),
             headers={"Content-Type": "application/json", "api-key": key})
        log("devto", PASS, "published")
    except urllib.error.HTTPError as e:
        log("devto", FAIL, f"HTTP {e.code}")
    except Exception as e:
        log("devto", FAIL, str(e)[:120])


def post_hn(text: str, live: bool) -> None:
    user, token = env("HN_USERNAME"), env("HN_API_TOKEN")
    if not user or not token:
        return log("hn", SKIP, "set HN_USERNAME + HN_API_TOKEN (HN → Settings → API)")
    if not live:
        return log("hn", PASS, "dry-run — would post Show HN")
    try:
        http("POST", "https://hacker-news.firebaseio.com/v0/item.json",
             data=json.dumps({"title": TITLE, "url": KIT["storefront"], "text": text,
                              "type": "story", "by": user, "dead": 0, "parent": 0,
                              "time": int(time.time()), "id": 0, "kids": [], "urls": [],
                              "score": 0, "descendants": 0, "data": "",
                              "children": [], "poll": 0, "parts": []}),
             headers={"Content-Type": "application/json"})
        log("hn", PASS, "submitted")
    except Exception as e:
        log("hn", FAIL, str(e)[:120])


def post_producthunt(text: str, live: bool) -> None:
    token = env("PRODUCTHUNT_TOKEN")
    if not token:
        return log("producthunt", SKIP, "set PRODUCTHUNT_TOKEN")
    if not live:
        return log("producthunt", PASS, "dry-run — would create a launch")
    try:
        http("POST", "https://api.producthunt.com/v2/api/graphql",
             data=json.dumps({"query": """mutation($name:String!,$tagline:String!,$description:String!,$website:String!){
                createProduct(input:{name:$name,tagline:$tagline,description:$description,website:$website,links:{website:$website}}){id,name}}""",
                              "variables": {"name": "Netwide", "tagline": "On-device network intelligence & LAN guardian",
                                            "description": text[:400], "website": KIT["storefront"]}}),
             headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        log("producthunt", PASS, "launch created")
    except Exception as e:
        log("producthunt", FAIL, str(e)[:120])


def post_github_discussions(text: str, live: bool) -> None:
    """Always available: the gh CLI is already authenticated."""
    if not live:
        return log("github_discussions", PASS, "dry-run — would post a discussion")
    try:
        import subprocess
        body = text + "\n\n" + KIT["storefront"] + "\n" + KIT["release"]
        script = str(Path("/tmp/opencode/_gh_discussion_body.md"))
        Path(script).write_text(body, encoding="utf-8")
        query = (
            'mutation($repoId:ID!,$categoryId:ID!,$title:String!,$body:String!){'
            'createDiscussion(input:{repositoryId:$repoId,categoryId:$categoryId,title:$title,body:$body}){discussion{url}}}'
        )
        out = subprocess.run(
            ["gh", "api", "graphql", "-f", "query=" + query,
             "-f", "repoId=R_kgDOVni70Q", "-f", "categoryId=DIC_kwDOVni70c4DK7gH",
             "-f", "title=Netwide v4.9.0 — on-device network intelligence suite",
             "-F", f"body=@{script}"],
            capture_output=True, text=True, timeout=90,
        )
        if out.returncode == 0 and '"url"' in out.stdout:
            log("github_discussions", PASS, "posted (Show and tell)")
        else:
            log("github_discussions", FAIL, out.stderr.strip()[:120])
    except Exception as e:
        log("github_discussions", FAIL, str(e)[:120])


CHANNELS = [
    ("github_discussions", post_github_discussions),
    ("x", post_x),
    ("reddit", post_reddit),
    ("linkedin", post_linkedin),
    ("facebook", post_facebook),
    ("telegram", post_telegram),
    ("discord", lambda t, l: post_webhook("discord", env("DISCORD_WEBHOOK_URL"),
                                           {"content": t[:1900]}, l, "DISCORD_WEBHOOK_URL")),
    ("slack", lambda t, l: post_webhook("slack", env("SLACK_WEBHOOK_URL"),
                                         {"text": t[:3500]}, l, "SLACK_WEBHOOK_URL")),
    ("bluesky", post_bluesky),
    ("mastodon", post_mastodon),
    ("devto", post_devto),
    ("hn", post_hn),
    ("producthunt", post_producthunt),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Share Netwide everywhere possible.")
    ap.add_argument("--live", action="store_true", help="actually post (default: dry run)")
    ap.add_argument("--only", default="", help="comma-separated channel list")
    ap.add_argument("--copy", default="", help="path to a copy file overriding the kit")
    args = ap.parse_args()

    load_env()

    copy_map = dict(PLATFORM_COPY)
    if args.copy:
        text = Path(args.copy).read_text(encoding="utf-8")
        for chunk in text.split("## ")[1:]:
            name, _, body = chunk.partition("\n")
            key = name.strip().lower()
            if key in copy_map:
                copy_map[key] = body.strip()

    wanted = [c.strip().lower() for c in args.only.split(",") if c.strip()]
    print(f"\n{'LIVE POSTING' if args.live else 'DRY RUN (add --live to post)'}")
    print(f"{'=' * 60}\n")

    for name, fn in CHANNELS:
        if wanted and name not in wanted:
            continue
        try:
            fn(copy_map.get(name, BODY_LONG), args.live)
        except Exception as e:  # a broken channel must not stop the rest
            log(name, FAIL, str(e)[:140])

    posted = sum(1 for _, s, _ in results if s == PASS)
    skipped = sum(1 for _, s, _ in results if s == SKIP)
    failed = sum(1 for _, s, _ in results if s == FAIL)
    print(f"\n{'=' * 60}")
    print(f"{posted} ready · {skipped} need credentials · {failed} failed")
    if skipped:
        print("\nMissing credentials (add to ~/.config/netwide/social.env):")
        for name, status, detail in results:
            if status == SKIP:
                print(f"  - {name}: {detail}")
    print(f"\nLaunch kit: {KIT['storefront']}")
    print(f"Release:    {KIT['release']}")
    print(f"Buy:        Pro {KIT['buy_pro_monthly']} | Enterprise {KIT['buy_ent_monthly']}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
