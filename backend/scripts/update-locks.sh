#!/usr/bin/env sh
set -eu

backend_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$backend_dir"

# Resolve for the oldest supported interpreter regardless of which Python runs
# this script; otherwise uv drops markers such as python_full_version < '3.12'
# and the locks break Python 3.11 installs. Keep the arguments identical to
# update-locks.ps1 so the recorded lock headers match.
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required. Install it with: python -m pip install uv" >&2
  exit 1
fi

uv pip compile --universal --generate-hashes --python-version 3.11 requirements.in -o requirements.lock
uv pip compile --universal --generate-hashes --python-version 3.11 requirements-memory.in -o requirements-memory.lock
uv pip compile --universal --generate-hashes --python-version 3.11 requirements-dev.in -o requirements-dev.lock
