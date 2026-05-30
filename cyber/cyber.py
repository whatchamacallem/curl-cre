"""
cyber.py — thin Python wrapper around the cyberext C extension.

Typical usage:

    import cyber

    r = cyber.fetch("http://x.test/", cyber.response(200, body=b"hello"))
    print(r)   # {'body': b'hello', 'exit_code': 0, 'error': 'No error'}
"""

import importlib.util
import pathlib

# Load the compiled C extension by absolute path so callers can do
# "import cyber" from any working directory.
so = next(
    (p for p in pathlib.Path(__file__).parent.glob("build/lib.*/*.so")
     if "cyberext" in p.name),
    None,
)
if so is None:
    raise ImportError("cyberext C extension not found — run build.sh first")

spec = importlib.util.spec_from_file_location("cyberext", so)
cyberext = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cyberext)
del spec, so


def dupfetch(
    parent_url: str, parent_resp: bytes,
    clone_url: str,  clone_resp: bytes,
) -> dict:
    """Run parent_url, duphandle, then run clone_url on the clone.

    Returns
    -------
    dict with keys:
        parent        : dict  – result of the parent fetch (body/exit_code/error)
        clone         : dict  – result of the clone fetch
        hsts_enforced : bool  – True if clone blocked the plain-HTTP request,
                                False if the HSTS-bypass bug is present
    """
    return cyberext.dupfetch(parent_url, parent_resp, clone_url, clone_resp)


def fetch(url: str, response: bytes) -> dict:
    """Drive libcurl with a fully crafted server response.

    Parameters
    ----------
    url      : str   – URL passed to curl (host/port are ignored; only the
                       path + scheme matter for curl's internal state machine)
    response : bytes – raw bytes that the fake server returns

    Returns
    -------
    dict with keys:
        body      : bytes  – data curl handed to its write callback
        exit_code : int    – CURLcode (0 == CURLE_OK)
        error     : str    – curl_easy_strerror() text
    """
    return cyberext.fetch(url, response)


def response(
    status: int = 200,
    headers: dict | None = None,
    body: bytes = b"",
    http_version: str = "1.1",
) -> bytes:
    """Build a minimal valid HTTP/1.1 response.

    Parameters
    ----------
    status       : int  – HTTP status code (default 200)
    headers      : dict – additional headers (Content-Length is added
                          automatically)
    body         : bytes – response body
    http_version : str  – e.g. "1.1" or "1.0"

    Returns
    -------
    bytes – the complete raw HTTP response suitable for passing to fetch()
    """
    status_texts = {
        100: "Continue",
        200: "OK",
        201: "Created",
        204: "No Content",
        206: "Partial Content",
        301: "Moved Permanently",
        302: "Found",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }
    reason = status_texts.get(status, "Unknown")

    lines = [f"HTTP/{http_version} {status} {reason}"]
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")

    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")

    lines.append("")   # blank line separating headers from body
    lines.append("")   # will join with \r\n, producing trailing \r\n

    header_bytes = "\r\n".join(lines).encode()
    return header_bytes + body
