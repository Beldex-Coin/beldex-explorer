#!/usr/bin/env bash
# Run the mainnet explorer backend in development.
# Usage: ./run-mainnet.sh [port]
set -euo pipefail
cd "$(dirname "$0")"

# macOS (Apple Silicon): let ctypes find Homebrew's arm64 libsodium.
if [[ "$(uname)" == "Darwin" && -d /opt/homebrew/lib ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

# Use the active environment, then the project's venv, then system Python.
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  python="$VIRTUAL_ENV/bin/python"
elif [[ -x .venv/bin/python ]]; then
  python="$PWD/.venv/bin/python"
else
  python=python3
fi

if ! "$python" -c 'import flask' >/dev/null 2>&1; then
  echo "Flask is unavailable for $python. Install the project dependencies:" >&2
  if [[ "$python" == python3 ]]; then
    echo "  python3 -m venv .venv" >&2
    echo "  .venv/bin/python -m pip install -r requirements.txt" >&2
  else
    printf '  "%s" -m pip install -r requirements.txt\n' "$python" >&2
  fi
  exit 1
fi

export FLASK_APP=mainnet
exec "$python" -m flask run --port "${1:-5000}"
