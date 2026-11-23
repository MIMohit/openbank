"""Byte-exact HTTP/1.1 client over a raw TCP socket.

`send()` writes exactly the bytes it is given and parses the response without any help
from `http.client` (which would reject or rewrite the odd requests we send). It handles
the three framing modes a server may use:
  * Content-Length
  * Transfer-Encoding: chunked
  * connection close (read until EOF)
and enforces connect/read timeouts.
"""
from __future__ import annotations

import socket
import time
from typing import List, Optional

from .model import RawRequest, RawResponse, Header


class RawHTTPError(Exception):
    pass


def send_request(host: str, port: int, req: RawRequest, *,
                 timeout: float = 10.0) -> RawResponse:
    """Serialise `req` and send it. Convenience wrapper over `send`."""
    return send(host, port, req.to_bytes(), timeout=timeout)


def send(host: str, port: int, raw: bytes, *, timeout: float = 10.0) -> RawResponse:
    """Send `raw` bytes to host:port over TCP/1.1 and parse the response.

    On a transport error or timeout, returns a RawResponse with status=0 and `.error`
    set, rather than raising — the runner records this per case and moves on.
    """
    start = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(raw)
        # NOTE: we deliberately do NOT shutdown(SHUT_WR) here. A half-close before the
        # response makes some servers (e.g. nginx) reset the connection and return zero
        # bytes. Our requests are self-delimiting (GET/DELETE have no body; bodies carry
        # Content-Length), so the server knows the request ended at the header terminator.
        data = _read_response_bytes(sock, timeout=timeout, deadline=start + timeout)
        return _parse_response(data)
    except socket.timeout:
        return RawResponse(status=0, reason="timeout", http_version="",
                           headers=[], body=b"", framing="none", error="timeout")
    except OSError as e:
        return RawResponse(status=0, reason="transport-error", http_version="",
                           headers=[], body=b"", framing="none", error=str(e))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _read_response_bytes(sock: socket.socket, *, timeout: float, deadline: float) -> bytes:
    """Read a full HTTP response, honouring Content-Length / chunked / close framing."""
    buf = bytearray()
    header_end = -1

    # 1. Read until we have the full header block.
    while header_end == -1:
        _check_deadline(deadline)
        chunk = sock.recv(65536)
        if not chunk:
            # Connection closed before headers completed.
            return bytes(buf)
        buf += chunk
        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1:
            header_end_lf = buf.find(b"\n\n")
            if header_end_lf != -1:
                header_end = header_end_lf  # tolerate LF-only servers (rare)

    head = bytes(buf[:header_end])
    header_sep_len = 4 if buf[header_end:header_end + 4] == b"\r\n\r\n" else 2
    body_start = header_end + header_sep_len
    status, _reason, _ver, headers = _parse_head(head)

    # 2. Decide framing.
    te = _find_header(headers, "transfer-encoding")
    cl = _find_header(headers, "content-length")
    status_no_body = status in (204, 304) or (100 <= status < 200)

    if te and "chunked" in te.lower():
        body = _read_chunked(sock, buf, body_start, deadline=deadline)
    elif cl is not None:
        try:
            length = int(cl.strip())
        except ValueError:
            length = 0
        body = _read_fixed(sock, buf, body_start, length, deadline=deadline)
    elif status_no_body:
        body = bytes(buf[body_start:])
    else:
        # No length and not chunked: read until the server closes the connection.
        body = _read_until_close(sock, buf, body_start, deadline=deadline)
    return head + (b"\r\n\r\n") + body


def _read_fixed(sock, buf: bytearray, body_start: int, length: int, *, deadline: float) -> bytes:
    body = bytearray(buf[body_start:])
    while len(body) < length:
        _check_deadline(deadline)
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return bytes(body[:length])


def _read_until_close(sock, buf: bytearray, body_start: int, *, deadline: float) -> bytes:
    body = bytearray(buf[body_start:])
    while True:
        try:
            _check_deadline(deadline)
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        body += chunk
    return bytes(body)


def _read_chunked(sock, buf: bytearray, body_start: int, *, deadline: float) -> bytes:
    """Decode a chunked body, reading more from the socket as needed."""
    data = bytearray(buf[body_start:])
    out = bytearray()
    pos = 0

    def ensure(n: int) -> bool:
        nonlocal data
        while len(data) - pos < n:
            _check_deadline(deadline)
            chunk = sock.recv(65536)
            if not chunk:
                return False
            data.extend(chunk)
        return True

    def read_line() -> Optional[bytes]:
        nonlocal data
        while True:
            idx = data.find(b"\r\n", pos)
            if idx != -1:
                return data[pos:idx]
            _check_deadline(deadline)
            chunk = sock.recv(65536)
            if not chunk:
                return None
            data.extend(chunk)

    while True:
        line = read_line()
        if line is None:
            break
        pos += len(line) + 2  # consume size line + CRLF
        size_token = line.split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            break
        if size == 0:
            break  # last chunk (ignore trailers)
        if not ensure(size + 2):
            out += data[pos:pos + size]
            break
        out += data[pos:pos + size]
        pos += size + 2  # chunk data + trailing CRLF
    return bytes(out)


def _check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise socket.timeout("read deadline exceeded")


# ---- response head parsing ----

def _find_header(headers: List[Header], name: str) -> Optional[str]:
    lname = name.lower()
    for n, v in headers:
        if n.lower() == lname:
            return v
    return None


def _parse_head(head: bytes):
    lines = head.split(b"\r\n")
    if len(lines) == 1 and b"\n" in head:
        lines = head.split(b"\n")
    status_line = lines[0].decode("latin-1") if lines else ""
    parts = status_line.split(" ", 2)
    http_version = parts[0] if len(parts) > 0 else ""
    try:
        status = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        status = 0
    reason = parts[2] if len(parts) > 2 else ""
    headers: List[Header] = []
    for line in lines[1:]:
        if not line:
            continue
        s = line.decode("latin-1")
        cidx = s.find(":")
        if cidx == -1:
            continue
        name = s[:cidx]
        value = s[cidx + 1 :].strip()
        headers.append((name, value))
    return status, reason, http_version, headers


def _parse_response(raw: bytes) -> RawResponse:
    header_end = raw.find(b"\r\n\r\n")
    sep = 4
    if header_end == -1:
        header_end = raw.find(b"\n\n")
        sep = 2
    if header_end == -1:
        head = raw
        body = b""
    else:
        head = raw[:header_end]
        body = raw[header_end + sep :]
    status, reason, http_version, headers = _parse_head(head)
    te = _find_header(headers, "transfer-encoding")
    cl = _find_header(headers, "content-length")
    if te and "chunked" in te.lower():
        framing = "chunked"
    elif cl is not None:
        framing = "content-length"
    elif status:
        framing = "close"
    else:
        framing = "none"
    return RawResponse(status=status, reason=reason, http_version=http_version,
                       headers=headers, body=body, framing=framing)
