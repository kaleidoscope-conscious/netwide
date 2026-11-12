# NetPulse — Payments Go-Live Runbook

Everything below is verified against the shipped code. The system is fully
wired to accept payments the moment real credentials are provided.

## Account decision (2026-11-12)

NetPulse launches on the existing live Stripe account **goeckoh**
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
- NetPulse sessions carry `metadata[netpulse_plan]` — any backend that
  fetches the session and filters on unknown metadata will ignore them.
  NetPulse-side minting is authoritative via checkout-return verification,
  so the shared webhook cannot mint NetPulse licenses for goeckoh buyers
  or vice versa.
- Add a dedicated NetPulse webhook endpoint once a stable public URL exists
  (Stripe allows multiple endpoints per account).

**No products needed for NetPulse** — prices are created on-the-fly
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
3. **Paste into NetPulse**: open the Workbench → Subscription modal
   (💎 Storefront → license modal) → **Billing Settings** →
   enter `sk_live_…`, `pk_live_…`, and your admin master token
   (`~/.config/netpulse/admin.token`) → Save.
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
  → register the NetPulse webhook endpoint
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

## 5. Prettier org handle (optional polish)

`netpulse` is globally taken (EGYM, 2011). **`netpulse-hq`** is verified
available. Rename via API (needs `admin:org`) or UI:
`github.com/organizations/kaleidoscope-conscious/settings` → rename →
all repo URLs redirect automatically.
