#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install ./shared ./server
if [[ ! -f .env ]]; then
    (umask 077; .venv/bin/python tools/generate_secrets.py --write)
fi
printf '\nSetup complete. Start the server: bash scripts/run.sh\n'
