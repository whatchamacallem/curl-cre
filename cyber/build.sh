#!/usr/bin/env bash
# build.sh — build everything needed to run the cyber harness:
#   1. libcurl (ASan/UBSan static build) in build/curl-asan/
#   2. cyber Python C extension in build/lib.<platform>/
#
# Run from the cyber/ directory:
#   cd /home/t/curl/cyber && ./build.sh
#
# Override compiler or build dir:
#   CC=clang-19 CURL_BUILD=build/curl-asan ./build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CC="${CC:-clang-19}"
CURL_BUILD="${CURL_BUILD:-${SCRIPT_DIR}/build/curl-asan}"

# ── 1. build libcurl under ASan ──────────────────────────────────────────────
echo "[build] step 1: cmake configure libcurl → ${CURL_BUILD}"
mkdir -p "${CURL_BUILD}"
cmake -S "${REPO_ROOT}" -B "${CURL_BUILD}" \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_BUILD_TYPE=Debug \
    "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
    "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined" \
    "-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address,undefined" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCURL_DISABLE_LDAP=ON \
    -DCURL_USE_LIBPSL=OFF \
    -DENABLE_DEBUG=ON

echo "[build] step 1: make -j$(nproc)"
make -C "${CURL_BUILD}" clean
make -C "${CURL_BUILD}" -j"$(nproc)"

# Debug cmake builds name the archive libcurl-d.a; provide a plain alias.
if [[ -f "${CURL_BUILD}/lib/libcurl-d.a" && ! -f "${CURL_BUILD}/lib/libcurl.a" ]]; then
    echo "[build] symlinking libcurl-d.a → libcurl.a"
    ln -sf libcurl-d.a "${CURL_BUILD}/lib/libcurl.a"
fi

# ── 2. build cyber Python extension ─────────────────────────────────────────
echo "[build] step 2: build cyber extension"
cd "${SCRIPT_DIR}"
# Pass CURL_BUILD explicitly so build.py uses the same tree we just built.
CURL_BUILD="${CURL_BUILD}" CC="${CC}" \
    python3 build.py build_ext --force 2>&1

echo "[build] done — extension at:"
find "${SCRIPT_DIR}/build" -name 'cyber*.so' 2>/dev/null
