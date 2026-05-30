#!/usr/bin/env bash

set -euo pipefail
CYBER="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$CYBER/sweep"

echo "[clean_sweep] sweep state cleared"
