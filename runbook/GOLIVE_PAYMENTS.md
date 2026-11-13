# Netwide — Payments Go-Live Runbook

Everything below is verified against the shipped code. The system is fully
wired to accept payments the moment real credentials are provided.

## Account decision (2026-11-12)

Netwide launches on the existing live Stripe account **goeckoh**
(`acct_1SQ0CYI8vHeVjmon`). Rationale: it is already live-mode verified with
payout infrastructure; a dedicated account requires a new identity/bank
verification. Migrate later by re-pointing keys — licenses mint per-session
and stay valid.

**Coexistence rules with the existing goeckoh webhook**
(`goeckoh-backend.fly.dev/webhook/stripe`):
- Keep it — it serves the goeckoh products (DSP/Viterbi, mesh router,
  Wi-Fi CSI SDK, spore executor). Do NOT archive those 4 products.
- Archive ONLY the 20+ stale "Continuous Test Verification Link" products
  (reversible). This is authorized.
- Netwide sessions carry `metadata[netwide_plan]` — any backend that
  fetches the session and filters on unknown metadata will ignore them.
  Netwide-side minting is authoritative via checkout-return verification,
  so the shared webhook cannot mint Netwide licenses for goeckoh buyers
  or vice versa.
- Add a dedicated Netwide webhook endpoint once a stable public URL exists
  (Stripe allows multiple endpoints per account).

**No products needed for Netwide** — prices are created on-the-fly
(`price_data`) at checkout time. Tiers ship in `billing.py`.

## What's already live (no action needed)

| Channel | Status |
|---|---|
| **PayPal one-time donations** | ✅ LIVE — `paypal.me/jgraham1000` (repo FUNDING.yml + README badge) |
| Checkout endpoint | ✅ Graceful `stripe_not_configured` error until keys are set |
| License activation on checkout return | ✅ Auto-verify via `?stripe_session_id=…` → mints NP1 key |
| Stripe webhook handling | ✅ Fail-closed, replay-protected, idempotent |
| Admin-gated key storage | ✅ `/api/subscription/stripe-config` (admin token required) |

## 1. Product license payments (Stripe) — the money-maker

The engine creates prices on-the-fly (`price_data`), so **no Stripe product
setup is required**. Tiers ship pre-configured in `billing.py`:

| Tier | Monthly | Annual | Lifetime |
|---|---|---|---|
| Pro Guardian | $9.99 | $99.00 | $69.00 |
| Sovereign Enterprise | $29.99 | $299.00 | $149.00 |

### Steps (≈30 min)

1. **Create / activate a Stripe account** → https://dashboard.stripe.com/register
   (business details + bank account for payouts)
2. **Copy live API keys** → Stripe Dashboard → Developers → API keys
   (`sk_live_…` secret, `pk_live_…` publishable)
3. **Paste into Netwide**: open the Workbench → Subscription modal
   (💎 Storefront → license modal) → **Billing Settings** →
   enter `sk_live_…`, `pk_live_…`, and your admin master token
   (`~/.config/netwide/admin.token`) → Save.
   Keys are stored in the local DB config; env vars (`STRIPE_SECRET_KEY`,
   `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET`) override if present.
4. **First sale**: buy your own Founder's Lifetime ($149) — you receive a
   real NP1-ENTERPRISE key; refund yourself from Stripe afterwards.
5. **(Optional) Webhook** for asynchronous reliability:
   - Expose the daemon publicly (see §3), then in Stripe →
     Developers → Webhooks → Add endpoint → `https://<public-url>/api/subscription/webhook`
     (events: `checkout.session.completed`, `customer.subscription.deleted`)
   - Paste the `whsec_…` signing secret into Billing Settings.

## 2. GitHub Sponsors — recurring donations

`kaleidoscopeAI` is **not yet a Sponsors creator** (profile redirects to the
user page). To join:

1. https://github.com/sponsors/accounts → **Get started**
2. Complete Stripe Connect onboarding (bank + tax identity — required by law)
3. Set up tiers (e.g. $3 / $9 / $29) — they appear in the repo's
   "Sponsor this project" sidebar automatically (FUNDING.yml already lists you).

## 3. Selling to buyers outside your LAN

The daemon listens on `127.0.0.1:8765`. `cloudflared` is installed at
`~/.local/bin/cloudflared`.

- **Test tunnel (ephemeral URL, changes each run):**
  `~/.local/bin/cloudflared tunnel --url http://127.0.0.1:8765`
- **Production:** named Cloudflare Tunnel on a domain you own → stable URL
  → register the Netwide webhook endpoint
  (`/api/subscription/webhook`; events: `checkout.session.completed`,
  `customer.subscription.deleted`).
- Note: a public URL exposes the whole API surface. Admin endpoints are
  token-protected; `/api/state` is not — use a temporary URL for test
  checkouts, and the named tunnel only as long as needed.

## 4. After pasting keys — verify in one command

```
curl -s -X POST http://127.0.0.1:8765/api/subscription/status -H 'Content-Type: application/json' -d '{}' | grep -o '"stripe_configured":[a-z]*'
```
(or check the Billing Settings panel — it shows `stripe_configured: true`).

## 4b. Business Control Room (operator dashboard)

Open **`http://127.0.0.1:8765/admin`** (or the **📊 Business** button in the
desktop toolbar) to see everything commercial in one place: paid customers,
active licenses, lifetime revenue / MRR / ARR estimates, leads & trials,
Stripe status, a 30-day mint chart, and a recent-licenses table.
Auto-refreshes every 15 s; remote access prompts for the Sovereign Admin
token (`X-Admin-Token`). Data API: `GET /api/admin/business`.

## 4c. Webhook — proven end-to-end (2026-11-12)

The full signed webhook path was verified against the live goeckoh account
using a temporary webhook endpoint (created → used → deleted; stored
`whsec_` cleared after the proof):

- ✅ Valid `Stripe-Signature` accepted (HMAC-SHA256, 5-min anti-replay window)
- ✅ Tampered payload rejected
- ✅ Signed **unpaid** session → refused to mint (fail-closed)
- ✅ Signed **paid** event → license minted + activated
- ✅ Replayed event id → idempotent short-circuit (no double mint)
- ✅ Engine-level coverage in CI: `test_stripe_webhook_hmac_verification`

When a stable public URL exists (named Cloudflare tunnel on your domain),
register the production endpoint with events `checkout.session.completed`
and `customer.subscription.deleted`, then paste its `whsec_…` via the
Billing Settings or `POST /api/subscription/stripe-config`. Note: partial
config saves are safe — empty fields never overwrite stored keys.

## 4d. License Authority — Ed25519 (2026-11-12)

License keys are now signed **asymmetrically** so a key bought by a customer
verifies on *their* machine, not only on the operator's node.

| Piece | Where | Notes |
|---|---|---|
| Private key | `~/.config/netwide/authority_ed25519.key` (mode 600) | Never in the repo |
| Public key | `netwide/license_authority.py` (`EMBEDDED_PUBLIC_KEY_B64`) | Ships with the app — can only verify |
| Test override | `NETWIDE_LICENSE_PUBLIC_KEY` / `NETWIDE_LICENSE_KEY_PATH` | Used by the test suite |

Commands:
```
netwide authority show     # public key + private key presence
netwide authority init     # generate a new keypair (backup the old private key first)
```

Key rotation invalidates previously issued licenses — re-issue for existing
customers if you rotate.

Legacy node-local HMAC keys still verify on the node that minted them
(`sk: "hmac"` payloads); operator-signed keys carry `sk: "ed25519"`.

## 4e. How a purchase actually completes

Three paths, all real payments — **no free self-minting**:

1. **In-app (automated, recommended)** — the buyer's own node calls
   `POST /api/subscription/checkout` → Stripe Checkout → on payment Stripe
   returns to `http://127.0.0.1:8765/?stripe_session_id=cs_...` → the node
   verifies with Stripe and mints + activates the license.
2. **Web-first (hosted)** — the public storefront falls back to a Stripe
   Payment Link (`buy.stripe.com/...`) when no local node is detected. After
   payment the buyer returns to the storefront with `?session_id=...` and the
   page activates the license on any running local node.
3. **Concierge (any device, no node running)** — run on the operator node:
   ```
   netwide license verify --session cs_live_...
   ```
   This verifies the payment with Stripe, mints an Ed25519-signed key and
   activates it locally. Deliver the printed `Signed Key` to the customer;
   they run `netwide license activate NP1-...` on their node.

The operator node also **auto-syncs paid sessions every 5 minutes**
(`sync_paid_sessions`), so web purchases appear in the Business Control Room
even when no webhook endpoint is reachable.

## 4f. Operator console (private)

| Console | URL | Data API |
|---|---|---|
| Business Control Room | `http://127.0.0.1:8765/admin` | `/api/admin/business` |
| Watchtower (live telemetry) | `http://127.0.0.1:8765/watchtower` | `/api/admin/watchtower` |

- Pages **and** APIs require the Sovereign Admin token; loopback is allowed for
  reads, but from any other host they answer **403**.
- Page assets live **outside the repo**: `~/.config/netwide/operator/`
  (`NETWIDE_OPERATOR_DIR` overrides). The in-repo `operator/` folder is only a
  fallback for fresh installs. They are never published to the storefront.
- Desktop launchers: `Netwide-Business.desktop`, `Netwide-Watchtower.desktop`.

## 4g. Privileged actions

Minting, revoking, and Stripe configuration always require the Sovereign Admin
Master Token. The operator node opts into loopback admin with
`NETWIDE_ALLOW_LOOPBACK_ADMIN=1` (set in the systemd unit); a customer node
without that variable cannot self-issue licenses.

## 4h. Identity & asset paths (post-rebrand, 2026-11-12)

| Thing | Path / URL |
| :--- | :--- |
| Product name | **Netwide** (was NetPulse) |
| Python package / CLI | `netwide` — `pip install netwide`, `netwide <cmd>` |
| Repo | https://github.com/kaleidoscope-conscious/netwide |
| Storefront (Pages) | https://kaleidoscope-conscious.github.io/netwide/ |
| Container | `ghcr.io/kaleidoscope-conscious/netwide` |
| Working dir | `/home/jg/netwide` |
| Config dir | `~/.config/netwide/` (legacy `~/.config/netpulse/` still read) |
| DB | `netwide_intel.db` (legacy file still honoured) |
| Service | `netwide-guardian.service` |
| Launchers | `~/.local/bin/netwide`, `Netwide*.desktop` |

Old `netpulse` URLs still **301-redirect** to the new ones.

### Renaming the GitHub *organisation* (optional)
GitHub silently refuses organisation renames through the API (it returns 200 and
keeps the old login), so it must be done in the browser:
**Org → Settings → Profile → Rename organization** (requires 2FA).
Candidates that are free: `netwide-hq`, `netwidehq`, `netwide-labs`.
After renaming, re-point the Pages URL, OG tags, sitemap, promo gist and the
share engine — `scripts/flip_to_netwide.py` already performs the in-tree sweep.

### Backing up the licence authority key
```bash
netwide authority backup      # writes ~/.config/netwide/backups/authority_ed25519-<stamp>.key (mode 600)
netwide authority show        # prints the public key + private key fingerprint
```
**Losing the private key means every licence ever issued stops verifying.**
Keep at least one offline copy (password manager / encrypted drive). Never commit
it, never paste it into chat.

## 4i. Automatic licence delivery (email)

When a buyer pays through a hosted Payment Link and their own node cannot
verify the payment (no Stripe key on their machine), the licence is minted on
the operator node and **emailed to them automatically** — no manual step.

Configure one provider (first match wins):

```bash
# Option A — Resend (simplest)
export RESEND_API_KEY=re_xxxxxxxx
export RESEND_FROM="Netwide <licences@yourdomain.com>"

# Option B — plain SMTP
export NETWIDE_SMTP_HOST=smtp.yourdomain.com
export NETWIDE_SMTP_PORT=587
export NETWIDE_SMTP_USER=licences@yourdomain.com
export NETWIDE_SMTP_PASSWORD=...
export NETWIDE_SMTP_FROM=licences@yourdomain.com
```

Put these in the systemd unit as `Environment=` lines (do not commit secrets).

STARTTLS and SMTP AUTH are **negotiated, not assumed**: if the relay does not
offer STARTTLS the delivery is refused with a clear message rather than sending
credentials in the clear. Only for a trusted local relay, set
`NETWIDE_SMTP_INSECURE=1` to allow plain delivery.

### Granting the operator scopes (one command)

```bash
bash scripts/grant_scopes.sh
```
Requests `admin:org, read:packages, write:packages, delete:packages, delete_repo`
and opens the device flow. These are needed to publish a **public** GHCR image,
delete the orphaned pre-rename image, and remove leftover scratch repositories.

Behaviour:
- The 5-minute paid-session sync mints the licence **and** emails the key.
- Delivery is **idempotent per Stripe session id** — a repeated sync never
  re-emails the same buyer.
- With no provider configured the sync still mints the key and reports
  `sent: false` — it never fails the sync.
- Manual re-send for a specific order:
  ```bash
  netwide license deliver --session cs_live_... --email buyer@example.com
  ```
  This verifies the payment with Stripe, mints the key, and emails it.

## 4j. Protocol Verification hardening (v4.8.0, 2026-11-12)

An independent source-level audit of the protocol engines was carried out and every
claim was **reproduced against the running code** before acting. The fixes below
landed in v4.8.0; the rule now enforced across the product is:

> **A verdict must be supported by evidence. If the evidence is structurally
> invalid, the parser refuses to grade rather than returning a confident answer.**

### What changed

| Subsystem | Before | Now |
| :--- | :--- | :--- |
| **SSH (RFC 4253)** | Only 8 of 10 name-lists accepted; host keys and MACs never graded; only `enc_s2c` graded; no trailing-field check | All 10 lists + `first_kex_packet_follows`/reserved validated; host keys, MACs and **both directions** graded; packet framing checked (§6) |
| **SMB2 (MS-SMB2)** | Advertised 3.1.1 with **no** negotiate context (servers may reject); "NTLM Relay Vulnerable" asserted | Real `PREAUTH_INTEGRITY_CAPABILITIES` context with computed `ContextLength`; response contexts parsed; relay reported as a **risk indicator** |
| **DNSSEC (RFC 4035)** | Fixed transaction id, response never matched to the query; AD treated as proof | Random transaction id; transaction id **and** question section validated; AD reported as *resolver-reported*, not independently verified |
| **DNS-over-TLS (RFC 7858)** | Only a TLS handshake — never a DNS query | Real length-prefixed DoT exchange, response validated, **certificate chain trust measured** |
| **NTP (RFC 5905)** | Mode 6 responsiveness labelled as CVE-2013-5211 amplification | Mode 6 (control responsiveness) and Mode 7 (MONLIST — the real amplification vector) probed **separately**, amplification ratio **measured on the wire** |
| **TLS / X.509** | TLS 1.3 with an untrusted cert graded **A+**; expiry/hostname ignored; version detection broken on OpenSSL 3.x | Grade depends on chain trust, expiry and identity; expired/untrusted can never score highly; **OpenSSL 3.x parsing fixed** (the TLS audit had been silently inert on modern systems) |
| **Evidence ledger** | Ambiguous colon serialization; verification limited to the first 10,000 rows; head hash from the fetched prefix | Canonical **length-prefixed** serialization (v2) with legacy v1 rows still verifiable; **whole chain verified by default** with `complete` / `head_verified` reported |

### Regression corpus

`tests/test_protocol_validation.py` — 16 cases covering well-formed **and
malformed** input for every parser above, including the canonical-serialization
ambiguity case and a tamper test that drops the ledger's immutability trigger
before modifying a row (the chain is still detected as broken).

### Honest-wording rules now enforced

- "AD=1" is always described as **resolver-reported**, never as independent validation.
- "Signing not required" is a **hardening gap / relay risk indicator**, never a verdict.
- Mode 6 exposure is **not** called amplification; only a measured Mode 7 ratio is.
- A certificate finding states whether the chain was trusted, expired, or mismatched.

## 5. Prettier org handle (optional polish)

`netwide` is globally taken (EGYM, 2011). **`netwide-hq`** is verified
available. Rename via API (needs `admin:org`) or UI:
`github.com/organizations/kaleidoscope-conscious/settings` → rename →
all repo URLs redirect automatically.
