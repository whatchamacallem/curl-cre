"""
utility.py — reusable builders and helpers for cyber vulnerability tests.

All response constructors return raw bytes suitable for cyber.fetch().
They intentionally bypass cyber.response() so they can inject malformed
or boundary-condition values that the high-level helper would sanitize.
"""

from __future__ import annotations

import struct


# ── status-line text map (shared with cyber.py) ─────────────────────────────

STATUS_TEXT: dict[int, str] = {
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


# ── low-level raw response builder ──────────────────────────────────────────

def raw_response(
    status: int = 200,
    *,
    header_lines: list[bytes] | None = None,
    body: bytes = b"",
    http_version: str = "1.1",
    add_content_length: bool = True,
    add_connection_close: bool = True,
) -> bytes:
    """Build a raw HTTP response with full control over every header byte.

    Unlike cyber.response(), this function:
    - accepts pre-encoded header_lines (bytes) so callers can inject
      NULs, bare CRs, duplicate headers, etc.
    - can suppress the automatic Content-Length header
    - never coerces or validates header values

    Parameters
    ----------
    status              : HTTP status code
    header_lines        : list of raw bytes, each a complete "Name: Value"
                          line WITHOUT a trailing CRLF — the function adds
                          CRLF between every line.  Pass [] or None for no
                          extra headers.
    body                : response body bytes
    http_version        : "1.1" or "1.0"
    add_content_length  : if True, prepend a correct Content-Length header
                          before header_lines (set False to omit or inject
                          a custom one via header_lines)
    add_connection_close: if True, append "Connection: close"

    Returns
    -------
    bytes — the complete raw HTTP response
    """
    reason = STATUS_TEXT.get(status, "Unknown")
    parts: list[bytes] = []

    parts.append(f"HTTP/{http_version} {status} {reason}\r\n".encode())

    if add_content_length:
        parts.append(f"Content-Length: {len(body)}\r\n".encode())

    if add_connection_close:
        parts.append(b"Connection: close\r\n")

    for line in (header_lines or []):
        parts.append(line if line.endswith(b"\r\n") else line + b"\r\n")

    parts.append(b"\r\n")   # end of headers
    parts.append(body)
    return b"".join(parts)


# ── chunked response builder ─────────────────────────────────────────────────

def chunked_response(
    chunks: list[tuple[str | int, bytes]],
    *,
    extra_headers: list[bytes] | None = None,
    status: int = 200,
    http_version: str = "1.1",
    trailing_crlf: bool = True,
) -> bytes:
    """Build a Transfer-Encoding: chunked HTTP response.

    Each element of *chunks* is a (size_field, data) pair where:
    - size_field is the hex string (or int) that appears in the chunk header
    - data       is the actual bytes sent as the chunk body

    The declared size and the actual data length are kept independent so
    callers can inject mismatches, SIZE_MAX values, etc.

    A zero-length terminator chunk ("0\\r\\n\\r\\n") is appended unless the
    last element of chunks already has size_field == "0" or 0.

    Parameters
    ----------
    chunks          : list of (size_field, data) pairs
    extra_headers   : additional raw header lines (bytes, no trailing CRLF)
    status          : HTTP status code
    http_version    : "1.1" or "1.0"
    trailing_crlf   : if True, append \\r\\n after each chunk's data

    Returns
    -------
    bytes — the complete raw HTTP response
    """
    reason = STATUS_TEXT.get(status, "Unknown")
    parts: list[bytes] = [
        f"HTTP/{http_version} {status} {reason}\r\n".encode(),
        b"Transfer-Encoding: chunked\r\n",
        b"Connection: close\r\n",
    ]
    for line in (extra_headers or []):
        parts.append(line if line.endswith(b"\r\n") else line + b"\r\n")
    parts.append(b"\r\n")

    for size_field, data in chunks:
        hex_size = (
            format(size_field, "x") if isinstance(size_field, int) else size_field
        )
        parts.append(f"{hex_size}\r\n".encode())
        parts.append(data)
        if trailing_crlf:
            parts.append(b"\r\n")

    # terminator — only add if the caller hasn't already included one
    last_size = chunks[-1][0] if chunks else None
    needs_terminator = last_size not in (0, "0", "00")
    if needs_terminator:
        parts.append(b"0\r\n\r\n")

    return b"".join(parts)


# ── redirect response builder ────────────────────────────────────────────────

def redirect_response(
    location: bytes | str,
    *,
    status: int = 301,
    body: bytes = b"",
    http_version: str = "1.1",
    raw_location: bool = False,
) -> bytes:
    """Build a redirect response with a crafted Location header.

    Parameters
    ----------
    location     : the Location value; bytes are used verbatim (no encoding),
                   str is encoded to UTF-8
    status       : redirect status code (301, 302, …)
    body         : optional body bytes
    http_version : "1.1" or "1.0"
    raw_location : if True, the entire "Location: <value>" line is taken
                   from *location* verbatim (useful for injecting NULs or
                   missing colons).  If False (default), the function
                   constructs "Location: <value>".

    Returns
    -------
    bytes — complete raw HTTP response
    """
    if raw_location:
        loc_line = location if isinstance(location, bytes) else location.encode()
    else:
        loc_val = location if isinstance(location, bytes) else location.encode()
        loc_line = b"Location: " + loc_val

    return raw_response(
        status,
        header_lines=[loc_line],
        body=body,
        http_version=http_version,
        add_content_length=True,
    )


# ── WebSocket helpers ────────────────────────────────────────────────────────

def ws_upgrade_response(extra_headers: list[bytes] | None = None) -> bytes:
    """Build the server-side 101 Switching Protocols handshake response.

    The Sec-WebSocket-Accept value is a placeholder — libcurl's WS
    client validates it, so use a valid-looking (but fake) value.  Under
    the fuzzing harness this causes curl to proceed far enough to read
    the subsequent frame bytes.
    """
    # A real accept value requires SHA-1(key + GUID); curl checks it.
    # We use the pre-computed accept for the canonical test key
    # "dGhlIHNhbXBsZSBub25jZQ==" → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    lines: list[bytes] = [
        b"HTTP/1.1 101 Switching Protocols\r\n",
        b"Upgrade: websocket\r\n",
        b"Connection: Upgrade\r\n",
        b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
    ]
    for h in (extra_headers or []):
        lines.append(h if h.endswith(b"\r\n") else h + b"\r\n")
    lines.append(b"\r\n")
    return b"".join(lines)


def ws_frame(
    payload: bytes,
    *,
    opcode: int = 0x2,          # 0x2 = binary
    fin: bool = True,
    masked: bool = False,       # server→client frames must NOT be masked
    declared_len: int | None = None,  # override the length field
) -> bytes:
    """Build a single WebSocket frame.

    Parameters
    ----------
    payload      : the frame payload bytes
    opcode       : 4-bit opcode (0x1=text, 0x2=binary, 0x8=close, …)
    fin          : set the FIN bit
    masked       : set the MASK bit (server frames should be 0)
    declared_len : if given, write this value into the length field
                   instead of len(payload) — allows size mismatch attacks

    Returns
    -------
    bytes — the raw WS frame (header + payload)
    """
    first_byte = (0x80 if fin else 0x00) | (opcode & 0x0F)
    actual_len = len(payload) if declared_len is None else declared_len
    mask_bit = 0x80 if masked else 0x00

    if actual_len <= 125:
        header = bytes([first_byte, mask_bit | actual_len])
    elif actual_len <= 0xFFFF:
        header = bytes([first_byte, mask_bit | 126]) + struct.pack(">H", actual_len)
    else:
        header = bytes([first_byte, mask_bit | 127]) + struct.pack(">Q", actual_len)

    if masked:
        mask_key = b"\x37\xfa\x21\x3d"
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return header + mask_key + masked_payload

    return header + payload


def ws_fetch_url() -> str:
    """Return the WebSocket URL used by all WS tests."""
    return "ws://x.test/"


# ── result analysis ──────────────────────────────────────────────────────────

# CURLcode values we treat as "curl noticed the problem cleanly"
_CLEAN_ERROR_CODES: frozenset[int] = frozenset({
    1,   # CURLE_UNSUPPORTED_PROTOCOL
    3,   # CURLE_URL_MALFORMAT
    5,   # CURLE_COULDNT_RESOLVE_PROXY
    6,   # CURLE_COULDNT_RESOLVE_HOST
    7,   # CURLE_COULDNT_CONNECT
    8,   # CURLE_WEIRD_SERVER_REPLY — curl detected a malformed response
    18,  # CURLE_PARTIAL_FILE
    22,  # CURLE_HTTP_RETURNED_ERROR
    26,  # CURLE_READ_ERROR
    28,  # CURLE_OPERATION_TIMEDOUT
    35,  # CURLE_SSL_CONNECT_ERROR
    43,  # CURLE_BAD_FUNCTION_ARGUMENT — invalid input caught before transfer
    47,  # CURLE_TOO_MANY_REDIRECTS
    52,  # CURLE_GOT_EMPTY_REPLY  (common when we drop the conn abruptly)
    56,  # CURLE_RECV_ERROR
    61,  # CURLE_BAD_CONTENT_ENCODING — malformed compressed body detected
})


def classify(r: dict) -> str:
    """Return a short label describing the fetch outcome.

    Labels
    ------
    "ok"           — CURLcode 0, curl accepted the response
    "clean_error"  — curl returned a non-zero code we recognise as safe
    "unknown_error"— curl returned a non-zero code we don't recognise
                     (worth investigating)

    Note: an ASan/UBSan hit will abort the process before this function
    is ever called, so there is no "crash" label — absence of a crash is
    the pass condition for all vulnerability tests.
    """
    rc = r["exit_code"]
    if rc == 0:
        return "ok"
    if rc in _CLEAN_ERROR_CODES:
        return "clean_error"
    return "unknown_error"


def survived(r: dict) -> bool:
    """Return True if libcurl returned at all (i.e. did not crash/abort).

    This is the primary pass condition for every vulnerability test:
    we reached this line, so ASan/UBSan did not terminate the process.
    """
    return True   # reaching here means no abort — always True by definition


def ok_or_safe(r: dict) -> bool:
    """Return True if the result is 'ok' or a recognised clean error."""
    return classify(r) in ("ok", "clean_error")
