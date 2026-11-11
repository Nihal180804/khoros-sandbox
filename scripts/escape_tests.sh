#!/usr/bin/env bash
# Thin wrapper: the suite itself lives in escape_tests.py.
# Requires the API server to be running (make server).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 scripts/escape_tests.py "$@"
