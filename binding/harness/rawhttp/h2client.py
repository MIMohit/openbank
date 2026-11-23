"""Optional HTTP/2 -> HTTP/1 primitive support via the `h2` library.

This exists for the H2->H1 downgrade primitives (a gateway speaks H2 to the client and
H1 to the backend; pseudo-headers like :path and :method, and header-name casing, can be
smuggled). It is OPTIONAL per the task. If the `h2` package is not installed, importing
this module raises ImportError and the runner records the H2 path as skipped.

Scope note: this sends H2 over cleartext (h2c prior-knowledge) because the harness is
TLS-free (CONTRACT §1). Many gateways only negotiate H2 over TLS/ALPN, so H2 coverage is
best-effort; the runner marks per-topology whether the gateway accepted h2c.
"""
from __future__ import annotations

import socket
import time
from typing import List, Tuple, Optional

from .model import RawResponse, Header

try:
    import h2.connection  # type: ignore
    import h2.config      # type: ignore
    import h2.events      # type: ignore
    _H2_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when h2 missing
    _H2_AVAILABLE = False


def h2_available() -> bool:
    return _H2_AVAILABLE


def send_h2(host: str, port: int, *,
            method: str,
            path: str,
            authority: str,
            extra_headers: Optional[List[Tuple[str, str]]] = None,
            body: bytes = b"",
            scheme: str = "http",
            timeout: float = 10.0) -> RawResponse:
    """Send a single H2 request (prior-knowledge h2c) and return the response.

    Pseudo-headers (:method, :path, :scheme, :authority) are supplied explicitly so the
    caller can create H2/H1 differentials (e.g. a :path that an H1 backend re-serialises
    differently). `extra_headers` may contain regular header name/value pairs.
    """
    if not _H2_AVAILABLE:
        raise ImportError("the 'h2' package is not installed; H2 primitives are skipped")

    deadline = time.monotonic() + timeout
    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()

    hdrs: List[Tuple[str, str]] = [
        (":method", method),
        (":path", path),
        (":scheme", scheme),
        (":authority", authority),
    ]
    if extra_headers:
        hdrs.extend(extra_headers)

    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(conn.data_to_send())
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, hdrs, end_stream=(len(body) == 0))
        if body:
            conn.send_data(stream_id, body, end_stream=True)
        sock.sendall(conn.data_to_send())

        resp_headers: List[Header] = []
        resp_body = bytearray()
        status = 0
        done = False
        while not done:
            if time.monotonic() > deadline:
                raise socket.timeout("h2 read deadline exceeded")
            chunk = sock.recv(65536)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    for name, value in ev.headers:
                        if name == ":status":
                            try:
                                status = int(value)
                            except ValueError:
                                status = 0
                        elif not name.startswith(":"):
                            resp_headers.append((name, value))
                elif isinstance(ev, h2.events.DataReceived):
                    resp_body += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    done = True
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
        return RawResponse(status=status, reason="", http_version="HTTP/2",
                           headers=resp_headers, body=bytes(resp_body),
                           framing="h2")
    except socket.timeout:
        return RawResponse(status=0, reason="timeout", http_version="HTTP/2",
                           headers=[], body=b"", framing="h2", error="timeout")
    except OSError as e:
        return RawResponse(status=0, reason="transport-error", http_version="HTTP/2",
                           headers=[], body=b"", framing="h2", error=str(e))
    finally:
        try:
            sock.close()
        except OSError:
            pass
