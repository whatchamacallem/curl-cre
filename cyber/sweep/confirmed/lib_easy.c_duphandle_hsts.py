"""
Reproduce and verify-fix for: curl_easy_duphandle HSTS-bypass (easy.c ~line 1046)

curl_easy_duphandle() populates the clone's HSTS table only via
Curl_hsts_loadfile() and Curl_hsts_loadcb().  Runtime-learned entries
(received via Strict-Transport-Security response headers) live only in
data->hsts and are never copied, so the clone's HSTS enforcement is
incomplete.

cyber.dupfetch() wires this up directly:
  - parent handle receives an STS header → entry added to data->hsts
  - curl_easy_duphandle() is called (the bug site)
  - clone handle fetches the same origin over plain HTTP
  - hsts_enforced=False means the clone accepted plain HTTP → bypass confirmed
  - hsts_enforced=True means the clone blocked the plain-HTTP request → fix verified
"""

import os
import sys
import cyber
from utility import raw_response

# DEBUGBUILD: allow Strict-Transport-Security over plain HTTP so the parent
# fetch (http://x.test/) teaches the HSTS entry we then test on the clone.
os.environ.setdefault("CURL_HSTS_HTTP", "1")

PARENT_URL = "http://x.test/"
CLONE_URL  = "http://x.test/secret"

parent_resp = raw_response(
    200,
    header_lines=[
        b"Strict-Transport-Security: max-age=31536000; includeSubDomains",
        b"Content-Type: text/plain",
    ],
    body=b"parent received STS policy",
)

clone_resp = raw_response(
    200,
    header_lines=[b"Content-Type: text/plain"],
    body=b"secret data - should be blocked by HSTS on a correct clone",
)

result = cyber.dupfetch(PARENT_URL, parent_resp, CLONE_URL, clone_resp)

parent = result["parent"]
clone  = result["clone"]
enforced = result["hsts_enforced"]

print(f"parent exit_code : {parent['exit_code']} ({parent['error']})")
print(f"clone  exit_code : {clone['exit_code']}  ({clone['error']})")
print(f"hsts_enforced    : {enforced}")

if enforced:
    print("PASS: clone correctly blocked plain-HTTP request for STS-pinned origin")
    print("      (fix verified — duphandle now copies runtime HSTS entries)")
else:
    print("FAIL: clone accepted plain HTTP for STS-pinned origin")
    print("      (bug present — duphandle does not copy runtime HSTS entries)")
    sys.exit(1)
