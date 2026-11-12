# NetPulse — Payments Go-Live Runbook

Everything below is verified against the shipped code. The system is fully
wired to accept payments the moment real credentials are provided.

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

The daemon listens on `127.0.0.1:8765`. For public buyers:

- **Quick (no account):** `cloudflared tunnel --url http://127.0.0.1:8765`
  → share the printed `https://<random>.trycloudflare.com` URL.
- **Stable (recommended):** named Cloudflare Tunnel on your own domain
  (`netpulse.io` style), or any reverse proxy with TLS.
- The static storefront on GitHub Pages can then point its
  "Claim License" buttons at the public URL.

## 4. Prettier org handle (optional polish)

`netpulse` is globally taken (EGYM, 2011). **`netpulse-hq`** is verified
available. Rename via API (needs `admin:org`) or UI:
`github.com/organizations/kaleidoscope-conscious/settings` → rename →
all repo URLs redirect automatically.
