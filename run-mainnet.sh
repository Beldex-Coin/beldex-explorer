#!/usr/bin/env bash
# Run the mainnet explorer backend in development.
# Usage: ./run-mainnet.sh [port]
set -euo pipefail
cd "$(dirname "$0")"

# macOS (Apple Silicon): let ctypes find Homebrew's arm64 libsodium.
if [[ "$(uname)" == "Darwin" && -d /opt/homebrew/lib ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
fi

# Use the venv if present and not already active.
if [[ -z "${VIRTUAL_ENV:-}" && -f .venv/bin/activate ]]; then
  source .venv/bin/activate
fi

export FLASK_APP=mainnet
exec flask run --port "${1:-5000}"
