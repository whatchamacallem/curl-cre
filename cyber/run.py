#!/usr/bin/env python3
# run.py — load the cyberext extension and run a harness script.
# Usage: run.py [harness.py]
#   No argument: runs a minimal smoke test to verify the extension works.
#   With argument: executes that script with cyber and utility on sys.path.
import os
import sys
import pathlib

os.environ.setdefault("CYBER_DEBUG", "1")

print(f"[run] CYBER_DEBUG={os.environ['CYBER_DEBUG']}")
print(f"[run] LD_PRELOAD={os.environ.get('LD_PRELOAD', '(not set)')}")

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import cyber

if len(sys.argv) == 1:
    r = cyber.fetch("http://x.test/", cyber.response(200, body=b"hello"))
    if r["exit_code"] != 0:
        print(f"FAIL: {r['error']}", file=sys.stderr)
        sys.exit(1)
    print("OK")
    sys.exit(0)

harness = pathlib.Path(sys.argv[1]).resolve()
if not harness.exists():
    print(f"harness not found: {harness}", file=sys.stderr)
    sys.exit(1)

exec(compile(harness.read_text(), str(harness), "exec"), {"__file__": str(harness)})
