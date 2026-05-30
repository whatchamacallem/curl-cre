#!/usr/bin/env bash
# run_sweep.sh <N> — delegates to run_sweep.py.
# Run from the repo root: bash cyber/run_sweep.sh <N>

set -euo pipefail

CYBER="$(cd "$(dirname "$0")" && pwd)"

if [[ $# -ne 1 ]] || ! [[ $1 =~ ^[0-9]+$ ]]; then
    echo "Usage: bash cyber/run_sweep.sh <N>" >&2
    exit 1
fi

exec python3 "$CYBER/run_sweep.py" "$1"
