#!/usr/bin/env python3
"""
Finish the Netwide rebrand: rename the GitHub repository and repoint every URL.

The repository rename is the one step that needs the `admin:org` scope
(renaming an org-owned repository is an org administration operation).

    gh auth refresh -h github.com -s admin:org
    python3 scripts/flip_to_netwide.py

What it does:
  1. Renames  <org>/netpulse  ->  <org>/netwide
  2. Rewrites every repo/Pages URL in the working tree
  3. Updates the local git remote
  4. Commits and pushes
  5. Prints the follow-ups (Pages URL, release, links)

Safe to re-run: it detects an already-renamed repo and skips that step.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP_DIRS = {"build", "dist", ".git", "__pycache__", "node_modules"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".apk", ".aab", ".db",
                   ".gz", ".zip", ".whl", ".idsig", ".svg"}
OLD_NAME = "netpulse"
NEW_NAME = "netwide"


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if proc.stdout.strip():
        print(proc.stdout.strip()[:400])
    if proc.returncode != 0 and check:
        print(f"  ! {proc.stderr.strip()[:300]}")
    return proc


def detect_owner() -> str:
    out = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
                         cwd=str(ROOT), capture_output=True, text=True)
    if out.returncode != 0:
        print("! Could not determine the repository owner — is `gh` authenticated?")
        sys.exit(1)
    return out.stdout.strip().split("/")[0]


def main() -> int:
    owner = detect_owner()
    old_repo = f"{owner}/{OLD_NAME}"
    new_repo = f"{owner}/{NEW_NAME}"

    print(f"\nNetwide repo flip: {old_repo} -> {new_repo}\n")

    # 0. Optionally rename the organisation as well (browser-only in the UI, but
    #    attempted here first — GitHub sometimes accepts it for org owners).
    new_org = os.environ.get("NETWIDE_NEW_ORG", "").strip()
    if new_org:
        res = run(["gh", "api", "-X", "PATCH", f"orgs/{owner}", "-f", f"login={new_org}"])
        probe = subprocess.run(["gh", "api", f"orgs/{new_org}", "--jq", ".login"],
                               cwd=str(ROOT), capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() == new_org:
            print(f"  -> organisation renamed to {new_org}")
            owner = new_org
        else:
            print(f"  ! organisation rename to {new_org} was refused by the API — "
                  "rename it in the UI (Settings -> Profile) and re-run this script.")

    # 1. Rename the repository (needs admin:org for org-owned repos)
    check = subprocess.run(["gh", "api", f"repos/{old_repo}", "--jq", ".name"],
                           cwd=str(ROOT), capture_output=True, text=True)
    if check.returncode == 0:
        # PATCH, not PUT: GitHub rejects PUT for organisation-owned repo renames.
        res = run(["gh", "api", "-X", "PATCH", f"repos/{old_repo}", "-f", f"name={NEW_NAME}"])
        if res.returncode != 0:
            print("\n! Rename refused. If you renamed an organisation-owned repo, refresh the token first:\n"
                  "    gh auth refresh -h github.com -s admin:org\n")
            return 1
        print(f"  -> renamed to {new_repo}")
    else:
        # Already renamed (or renamed by hand) — verify and continue.
        probe = subprocess.run(["gh", "api", f"repos/{new_repo}", "--jq", ".name"],
                               cwd=str(ROOT), capture_output=True, text=True)
        if probe.returncode != 0:
            print(f"! Neither {old_repo} nor {new_repo} is reachable — check the owner name.")
            return 1
        print(f"  -> repository is already {new_repo}; skipping rename")

    # 2. Rewrite URLs in the working tree
    changed = 0
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(p in SKIP_DIRS for p in path.parts):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES or path.name.endswith(".db"):
            continue
        try:
            src = path.read_text(encoding="utf-8")
        except Exception:
            continue
        out = src.replace(f"{owner}/{OLD_NAME}", f"{owner}/{NEW_NAME}")
        out = out.replace(f"github.io/{OLD_NAME}", f"github.io/{NEW_NAME}")
        if new_org:
            out = out.replace(f"{owner}", new_org)
        if out != src:
            path.write_text(out, encoding="utf-8")
            changed += 1
    print(f"  -> rewrote URLs in {changed} files")

    # 3. Local remote
    run(["git", "remote", "set-url", "origin", f"https://github.com/{new_repo}.git"])

    # 4. Commit + push
    run(["git", "add", "-A"])
    run(["git", "commit", "-m", "chore: complete Netwide rebrand — repository and URL rename"])
    run(["git", "push"])

    print("\nDone. Remaining manual steps:")
    print(f"  1. GitHub Pages URL becomes https://{owner}.github.io/{NEW_NAME}/ "
          "(update Pages settings if you set a custom domain)")
    print(f"  2. Publish the rebrand release:  gh release create v4.9.0 --repo {new_repo} ...")
    print("  3. Update the promo gist and any social posts that point at the old URLs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
