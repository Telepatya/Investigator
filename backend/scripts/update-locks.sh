#!/usr/bin/env sh
set -eu

backend_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$backend_dir"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required. Install it with: python -m pip install uv" >&2
  exit 1
fi

uv pip compile --universal --generate-hashes requirements.in -o requirements.lock
uv pip compile --universal --generate-hashes requirements-memory.in -o requirements-memory.lock
uv pip compile --universal --generate-hashes requirements-dev.in -o requirements-dev.lock
