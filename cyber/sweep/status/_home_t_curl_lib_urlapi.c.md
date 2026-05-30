# /home/t/curl/lib/urlapi.c

## Scanner findings

FINDING
file: /home/t/curl/lib/urlapi.c
function: Curl_url_same_origin
line: ~1240 (the `curl_strequal(base->port, href->port)` call inside the `if(href->host)` block)
class: null_mistake
condition: Any HTTP/2 PUSH_PROMISE is received where either the base URL, the pushed URL, or both have no explicit port number (the common case — e.g. `https://example.com/page` uses no explicit `:443`). In that situation `u->port` is NULL after URL parsing (see `parse_port`: the field is only assigned when a `:NNN` suffix is found in the hostname). `Curl_url_same_origin` then calls `curl_strequal(base->port, href->port)` with one or both arguments NULL.
reachability: HTTP/2 servers may send PUSH_PROMISE frames whose `:authority` pseudo-header resolves to a CURLU with a NULL port. libcurl validates push-stream origin by calling `Curl_url_same_origin`. A crafted server (or MITM) can supply a PUSH_PROMISE whose authority has no explicit port while the connection itself was established without an explicit port, reliably landing in this code with two NULL port pointers.
defence_gap: The developer was aware of the NULL problem for other optional fields — the zone-ID comparison immediately above reads `base->zoneid ? base->zoneid : ""` — but the port comparison omits any such guard. `curl_strequal` delegates to `Curl_strcasecompare` / `strcasecmp`; neither handles NULL arguments. There is no prior check that forces either `base->port` or `href->port` to be non-NULL before the call; the only earlier guards in the function are for `base->scheme`, `base->host`, and `href->host`, not for port.
craft: Connect libcurl (as client) to an HTTP/2 server over TLS without specifying an explicit port (e.g. `https://example.com/`). Have the server send a PUSH_PROMISE with `:authority: example.com` and `:path: /pushed` (no port in the authority). libcurl parses the pushed URL into a CURLU with `port == NULL`, while the base connection CURLU also has `port == NULL`. `Curl_url_same_origin` reaches `curl_strequal(NULL, NULL)` → NULL dereference / crash.


## Test harnesses

Now I have all the information needed to assess the finding.

**FINDING 1 — null_mistake in `Curl_url_same_origin` / `curl_strequal(base->port, href->port)`**

**REJECTED.**

The scanner's key claim — "`curl_strequal` delegates to `Curl_strcasecompare`/`strcasecmp`; neither handles NULL arguments" — is factually wrong. Reading `lib/strequal.c:76-84`:

```c
int curl_strequal(const char *s1, const char *s2)
{
  if(s1 && s2)
    return casecompare(s1, s2);

  /* if both pointers are NULL then treat them as equal */
  return NULL == s1 && NULL == s2;
}
```

`curl_strequal` was explicitly written to be NULL-safe. When both `base->port` and `href->port` are NULL (the common no-explicit-port case), the call returns `1` (equal) without dereferencing anything, and `Curl_url_same_origin` proceeds normally to `return TRUE`. When exactly one is NULL and the other is a non-empty string it returns `0`, entering the port-mismatch block which itself guards with `base->port && href->port` before touching either pointer.

There is a real HTTP/1.1-reachable call path at `lib/http.c:1243` (`Curl_url_same_origin(u, data->state.uh)` in the redirect+digest cleanup branch), but because `curl_strequal` is NULL-safe that path also produces no memory-safety violation. No harness is warranted.

