# Netwide License

**Netwide v4.9.0 — source-available, with a free Community Edition and paid
Pro Guardian / Sovereign Enterprise tiers.**

> This file states the licensing position of the code in this repository so that
> users, packagers, and platforms (F-Droid, Flathub, distro repos, awesome
> lists) know exactly what they may do with it. It is a plain-language summary,
> not legal advice — the operator should have counsel review the commercial
> terms before scaling sales.

---

## 1. Definitions

- **"Software"** — the Netwide source code, artwork, documentation, and build
  tooling in this repository, including the daemon (`server.py`), the CLI
  (`cli.py`), the desktop app (`desktop.py`), the Android app (`android/`), and
  the web interfaces in `static/`.
- **"Community Edition"** — the Software running with a `free` tier licence.
- **"Paid Tiers"** — `pro` (Pro Guardian) and `enterprise` (Sovereign
  Enterprise), unlocked by a signed `NP1-*` licence key.
- **"Operator"** — the person or entity distributing the Software and issuing
  licence keys.

## 2. Community Edition — free use

You may, without charge:

- Download, install, run, and study the Software for **personal, household,
  educational, research, or internal security-testing purposes**.
- Inspect, modify, and redistribute **your own copies** of the Software,
  including modifications, provided you do not distribute them as a competing
  product, do not remove attribution, and do not misrepresent them as
  official releases.
- Use it on networks you own or are **authorised to test**.

You may **not**:

- Use the Community Edition of the Software to build or operate a commercial
  product, service, or managed offering for third parties (that requires a
  licence from the Operator — see §4).
- Sell, sublicense, or distribute the Software itself as your own product.
- Use the Operator's licence authority to issue keys you have not paid for.

## 3. Paid Tiers

Pro Guardian and Sovereign Enterprise require a licence key issued by the
Operator (signed with the Operator's Ed25519 licence authority). Keys are
non-transferable beyond the licensed email/node budget and are subject to the
refund terms published at the storefront.

The Paid Tiers add features, not different code: the underlying Software is
the same, and the Community Edition remains fully usable.

## 4. Commercial use of the Paid Tiers

If you want to use Netwide in a commercial context — including managed
deployments for clients, MSP/MSP-style service work, integration into a
product you sell, or use across multiple sites — you need a written licence
from the Operator. Contact details are on the storefront and in
`.github/FUNDING.yml`.

## 5. Attribution

If you publicly redistribute the Software or a derivative, please keep the
Netwide attribution in the About/README. The name "Netwide" and the project
logo are trademarks of the Operator and may not be used to endorse a product
that is not the Software.

## 6. No warranty; limitation of liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. TO THE MAXIMUM EXTENT
PERMITTED BY LAW, THE OPERATOR IS NOT LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY ARISING FROM THE SOFTWARE OR ITS USE, INCLUDING ANY LIABILITY
ARISING FROM NETWORK ENFORCEMENT ACTIONS (QUARANTINE, FIREWALL RULES, DNS
SINKHOLING) APPLIED TO YOUR NETWORK.

**Operate defensive tools on networks you are authorised to test.** Misuse may
violate applicable law.

## 7. Security disclosures

Report vulnerabilities privately — see `SECURITY.md`. Do not disclose
exploitable findings publicly until a fix has shipped.

## 8. Changes

The Operator may update these terms in a new release. Terms are pinned to the
release tag you obtained the Software from; the version in this file applies
to v4.9.0.
