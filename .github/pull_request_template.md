## What does this change?

<!-- One or two sentences. The diff shows the what; explain the why. -->

## Why

<!-- Problem, motivation, or the request it fulfils. Link the issue if there is one. -->

## How it was verified

- [ ] `python3 -m pytest tests/ -q` passes
- [ ] `python3 -m pyflakes .` is clean
- [ ] Tested on: <!-- Linux version / Docker / Android -->
- [ ] Still **100% on-device** — no new network calls, no telemetry, no cloud dependency

## Checklist

- [ ] Tests added for new behaviour (including malformed-input cases)
- [ ] Public functions have type hints and a docstring explaining *why*
- [ ] No new runtime dependency without discussion
- [ ] Docs updated (`docs/`, `runbook/`) if behaviour changed
- [ ] No secrets, keys, licences, or real network data in the diff
