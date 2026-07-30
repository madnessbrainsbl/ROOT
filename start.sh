#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
port="${1:-8080}"
python3 scripts/sync_zerodays.py
exec python3 serve.py "$port"
