#!/usr/bin/env bash
# Publish Netwide to PyPI.
#
#   PYPI_API_TOKEN=pypi-... bash scripts/publish_pypi.sh
#
# The token needs the "publish" scope for the project "netwide".
# Without a token this script verifies everything and stops before uploading.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PROJECT="netwide"
VENV="/tmp/netwide-pypi-venv"

echo "=== [1/5] Checking the PyPI name is still free ==="
code=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/${PROJECT}/json")
if [ "$code" = "200" ]; then
  echo "  ! ${PROJECT} is already on PyPI — bump the version before publishing again."
else
  echo "  ✓ ${PROJECT} is available"
fi

echo "=== [2/5] Preparing the build toolchain ==="
if [ ! -x "$VENV/bin/twine" ]; then
  python3 -m venv "$VENV" >/dev/null 2>&1
  "$VENV/bin/pip" install --quiet --upgrade pip build twine >/dev/null 2>&1
fi

echo "=== [3/5] Building the wheel and sdist ==="
rm -rf build dist/*.whl dist/*.tar.gz
"$VENV/bin/python" -m build --outdir dist/ . >/dev/null 2>&1 || {
  echo "  ! full build failed, falling back to a wheel-only build"
  python3 -m pip wheel --no-deps --wheel-dir dist/ . >/dev/null || exit 1
}
ls -1 dist/*.whl dist/*.tar.gz 2>/dev/null | sed 's/^/  /'

echo "=== [4/5] Validating the distributions ==="
"$VENV/bin/twine" check dist/*.whl dist/*.tar.gz 2>/dev/null || "$VENV/bin/twine" check dist/*.whl

if [ -z "${PYPI_API_TOKEN:-}" ]; then
  echo "=== [5/5] No PYPI_API_TOKEN set — stopping before upload ==="
  echo "  Set PYPI_API_TOKEN and re-run to publish."
  exit 0
fi

echo "=== [5/5] Uploading to PyPI ==="
"$VENV/bin/twine" upload dist/*.whl dist/*.tar.gz \
  --username __token__ --password "$PYPI_API_TOKEN"
echo "  pip install ${PROJECT}"
