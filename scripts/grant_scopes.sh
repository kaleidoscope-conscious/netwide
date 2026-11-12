#!/usr/bin/env bash
# Grant the GitHub scopes Netwide's operator tooling needs.
#
#   bash scripts/grant_scopes.sh
#
# Why each scope:
#   admin:org      -> rename the organisation / manage org-level settings
#   read:packages  -> read GHCR package metadata (required by the API)
#   write:packages -> publish the container image
#   delete:packages-> remove the orphaned pre-rename 'netpulse' image
#   delete_repo    -> delete the leftover scratch repository
#
# The browser opens automatically; paste the one-time code and press Enter.
set -euo pipefail

SCOPES="admin:org,read:packages,write:packages,delete:packages,delete_repo"

echo "Requesting scopes: $SCOPES"
echo
gh auth refresh -h github.com -s "$SCOPES"

echo
echo "Current scopes:"
gh auth status 2>&1 | grep -o "Token scopes:.*" || true
