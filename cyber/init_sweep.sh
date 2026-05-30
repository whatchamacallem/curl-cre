#!/usr/bin/env bash
# init_sweep.sh — one-time setup for the vulnerability sweep.
# Safe to re-run: will not overwrite an existing queue.txt.
# Run from the repo root: bash cyber/init_sweep.sh [<single-file>]
#
# With a single-file argument (e.g. lib/cookie.c), queue.txt is populated
# with only that file so the pipeline can be tested before a full sweep.

set -euo pipefail
CYBER="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$CYBER")"
STATE="$CYBER/sweep"

mkdir -p "$STATE/status"
mkdir -p "$STATE/confirmed"

if [[ -f "$STATE/queue.txt" ]]; then
    echo "queue.txt already exists ($(wc -l < "$STATE/queue.txt") entries remaining). Not overwriting."
    echo "Delete cyber/sweep/queue.txt and re-run to start over."
    exit 0
fi

touch "$STATE/hits.md"

if [[ $# -eq 1 ]]; then
    # Test mode: queue exactly one file
    echo "$1" > "$STATE/queue.txt"
    echo "Initialized sweep (test mode): 1 file queued — $1"
else
    find "$REPO/lib" "$REPO/src" -maxdepth 1 -name "*.c" | sort > "$STATE/queue.txt"
    COUNT=$(wc -l < "$STATE/queue.txt")
    echo "Initialized sweep: $COUNT files queued in cyber/sweep/queue.txt"
fi
