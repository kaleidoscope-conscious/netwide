#!/usr/bin/env bash
# Grant the GitHub scopes Netwide's operator tooling needs.
#
#   bash scripts/grant_scopes.sh
#
# Why each scope:
#   admin:org       -> rename the organisation / manage org-level settings
#   read:packages   -> read GHCR package metadata (the API checks it explicitly)
#   write:packages  -> publish the container image
#   delete:packages -> remove the orphaned pre-rename 'netpulse' image
#   delete_repo     -> delete leftover scratch repositories
#
# The browser opens automatically; paste the one-time code and press Enter.
set -uo pipefail

REQUIRED="admin:org read:packages write:packages delete:packages delete_repo"
SCOPES="admin:org,read:packages,write:packages,delete:packages,delete_repo"

echo "Requesting: $SCOPES"
echo
gh auth refresh -h github.com -s "$SCOPES"
rc=$?

echo
GRANTED="$(gh auth status 2>&1 | grep -o "Token scopes:.*" || echo '')"
echo "Granted now: $GRANTED"

missing=""
for want in $REQUIRED; do
  case "$GRANTED" in
    *"$want"*) ;;
    *) missing="$missing $want" ;;
  esac
done

if [ -n "$missing" ]; then
  echo
  echo "MISSING:$missing"
  echo "GitHub did not grant every scope. If the org rename or package"
  echo "visibility is still refused, re-run this script, or set the scopes"
  echo "manually at: https://github.com/settings/tokens"
  exit 1
fi

echo
echo "All required scopes granted."
echo "Next: tell the agent, and it will publish the container publicly,"
echo "delete the orphaned image, and remove the scratch repository."
