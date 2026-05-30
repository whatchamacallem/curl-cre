"""
build.py — build cyber.c against the ASan libcurl build.

The extension is placed in build/lib.<platform>/ (not inplace) so the
source tree stays clean.  build.sh handles invoking this correctly;
run.sh looks for the .so there.

Usage (via build.sh):
    cd cyber
    CURL_BUILD=build/curl-asan python3 build.py build_ext
"""

import os
from setuptools import setup, Extension

# cyber/ lives one level below the repo root; include/ is at the repo root.
CYBER_DIR  = os.path.dirname(os.path.realpath(__file__))
REPO_ROOT  = os.path.dirname(CYBER_DIR)

CURL_BUILD = os.environ.get("CURL_BUILD", os.path.join(CYBER_DIR, "build", "curl-asan"))

# Normalise: if caller passes a relative path, make it absolute so
# distutils does not get confused when it changes directory internally.
CURL_BUILD = os.path.realpath(CURL_BUILD)

CURL_INC = os.path.join(REPO_ROOT, "include")  # always the repo include/
CURL_LIB = os.path.join(CURL_BUILD, "lib")

ext = Extension(
    "cyberext",
    sources=["cyber.c"],
    include_dirs=[CURL_INC],
    library_dirs=[CURL_LIB],
    # libcurl-d.a is a static archive; we must also pull in its deps:
    # OpenSSL, zlib, zstd (all were enabled in the ASan cmake build).
    libraries=["curl", "ssl", "crypto", "z", "zstd"],
    extra_compile_args=[
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
    ],
    extra_link_args=[
        "-fsanitize=address,undefined",
        f"-Wl,-rpath,{CURL_LIB}",
    ],
    # Force clang so that ASan runtime matches the libcurl build.
    # Override via CC environment variable if needed.
)

# Honour CC env var so callers can pin to clang-19 etc.
cc = os.environ.get("CC", "clang-19")
os.environ["CC"] = cc

setup(
    name="cyberext",
    version="0.1",
    ext_modules=[ext],
)
