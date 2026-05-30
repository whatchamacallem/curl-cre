#!/usr/bin/env bash
# run.sh — run the cyber harness smoke tests.
#
# Usage:
#   cd /home/t/curl/cyber && ./run.sh
#   CYBER_DEBUG=0 ./run.sh      # suppress per-call trace

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASAN_RT="/usr/lib/llvm-19/lib/clang/19/lib/linux/libclang_rt.asan-x86_64.so"

if [[ ! -f "${ASAN_RT}" ]]; then
    echo "ERROR: ASan runtime not found at ${ASAN_RT}" >&2
    echo "       Install with: sudo apt-get install clang-19" >&2
    exit 1
fi

echo "[run] LD_PRELOAD=${ASAN_RT}"

ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=0 \
LD_PRELOAD="${ASAN_RT}" \
    python3 "${SCRIPT_DIR}/run.py" "$@"
