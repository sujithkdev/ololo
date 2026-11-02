#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ ! -f .env || ! -x .venv/bin/python ]]; then
    printf 'Run bash scripts/setup.sh first.\n' >&2
    exit 1
fi
# This is your locally generated, trusted shell-compatible environment file.
set -a
source .env
set +a
export EDR_DATA_DIR="${EDR_DATA_DIR:-$ROOT/data}"
export EDR_LOG_DIR="${EDR_LOG_DIR:-$ROOT/logs}"
export EDR_HOST="${EDR_HOST:-127.0.0.1}"
exec .venv/bin/python -m behedr_server "$@"
