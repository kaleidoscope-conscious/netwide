# Contributing to NetPulse

Thanks for looking. NetPulse is a **100% on-device** network intelligence suite: everything it
learns stays on the machine it runs on. Contributions that preserve that property are always
welcome.

## The one rule

**No cloud dependency, no telemetry, no account.** A PR that sends data off-box (other than
the operator's own Stripe webhook flow) will not be merged.

## Quick start

```bash
git clone https://github.com/kaleidoscope-conscious/netpulse.git && cd netpulse
./install.sh
python3 -m pytest tests/ -q     # 139 tests, ~45s
python3 -m pyflakes .            # must be clean
```

Both commands must pass before you open a PR — CI runs exactly these.

## Where things live

| Path | What |
| :--- | :--- |
| `server.py` | FastAPI daemon, all HTTP/WS routes, admin gating |
| `billing.py` | Licence engine, Stripe checkout/webhooks, entitlements |
| `license_authority.py` | Ed25519 signing/verification for licences |
| `fingerprint.py` | Hardware fingerprinting + threat generation |
| `probers.py` | Active protocol probers/controllers |
| `intel_hypotheses.py` | Threat-field hypotheses, BLE/tether classification |
| `database.py` | SQLite schema + persistence |
| `static/` | Workbench, mobile PWA, storefront, launch hub |
| `operator/` | Private operator console pages (Business, Watchtower) |
| `tests/` | Pytest suite (isolated temp DB — never touches your data) |

## Style

- Python 3.10+, `snake_case`, type hints on public functions, docstrings that explain *why*.
- Keep pyflakes clean. No new runtime dependencies without discussion — the install must stay
  one command and lightweight.
- Every protocol parser must be **fail-closed**: a malformed or truncated handshake must raise
  an error, never silently succeed.
- Never log or store raw credentials, session tokens, or full packet payloads outside the
  local database.

## Adding a prober

1. Add a pure parse function in `probers.py` that takes bytes and returns a dict — no I/O.
2. Register it in the prober table with the ports it touches.
3. Add a test in `tests/` with a captured handshake fixture and a malformed-input case.
4. Surface the finding in `fingerprint.py` only when it is actionable.

## Tests

Every PR needs a test. Use the existing isolated sandbox:

```python
from netpulse.billing import SubscriptionManager
mgr = SubscriptionManager(db_path=tempfile.mktemp(suffix=".db"))
```

`tests/conftest.py` points `NETPULSE_DB_PATH` at a temp file, so the suite never touches a real
database. Do not remove that.

## Reporting bugs

Open an issue with: version, platform, what you expected, what happened, and the output of
`netpulse audit` if it is a detection issue. Security bugs → see `SECURITY.md`.

## Pull requests

- One logical change per PR.
- Describe the *why* in the body — the diff already shows the *what*.
- Update `docs/` and `runbook/` if you change behaviour operators rely on.
- By contributing you agree that your work is licensed under the repository licence.

## Code of conduct

Be decent. See `CODE_OF_CONDUCT.md`.
