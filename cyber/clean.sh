#!/usr/bin/env bash
# clean.sh — remove all build intermediates tracked by .gitignore.
#
# Uses `git clean -Xdf` which deletes only files/dirs that match
# .gitignore patterns — tracked source files are never touched.
#
# Scope: the cyber/ directory only (not the repo root or build-asan/).
# To also wipe the libcurl ASan build:
#   rm -rf ../build-asan
#
# Usage:
#   cd /home/t/curl/cyber && ./clean.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[clean] removing ignored intermediates in ${SCRIPT_DIR}..."
git -C "${SCRIPT_DIR}" clean -Xdf

echo "[clean] done"
