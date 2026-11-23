"""W18 ablation: RFC 9530 Content-Digest body check as an in-path hop (the half of +digest that needs the body).

Placement: gateway -> digest_gate (:8081) -> executor:8080. The edge verifier binds the Content-Digest
HEADER to the proof (bind.py, +digest); this hop checks that the BODY it forwards matches that header.
Behaviour per connection (the gateway speaks HTTP/1.0 or 1.1 with Content-Length; nginx de-chunks and
buffers request bodies by default):
  * read the request head; reject 400 if Transfer-Encoding is present, Content-Length is missing on a
    request with a body, Content-Length is duplicated/invalid, or Content-Digest is missing/duplicated;
  * read exactly Content-Length body bytes; reject 400 unless the sha-256 member equals SHA-256(body);
  * otherwise relay the EXACT received bytes to the executor and relay the response back unchanged.
Rejections are logged to LOG_PATH (default /logs/digest_gate.jsonl) with the request's DPoP jti.
Env: GATE_PORT (8081), UPSTREAM (executor:8080), LOG_PATH.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import socketserver
import sys
import threading
from datetime import datetime, timezone

from .bind import body_matches

UP_HOST, _, UP_PORT = os.environ.get("UPSTREAM", "executor:8080").partition(":")
LOG = os.environ.get("LOG_PATH", "/logs/digest_gate.jsonl")
_lock = threading.Lock()


def _log(rec: dict) -> None:
    rec["ts"] = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    line = json.dumps(rec, separators=(",", ":"))
    with _lock:
        try:
            with open(LOG, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def _jti(headers: list[tuple[str, str]]) -> str | None:
    for k, v in headers:
        if k.lower() == "dpop":
            try:
                p = v.strip().split(".")[1]
                return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("jti")
            except Exception:
                return None
    return None


class Gate(socketserver.BaseRequestHandler):
    def _reject(self, why: str, jti, line: str) -> None:
        body = json.dumps({"error": "digest_gate", "reason": why}).encode()
        self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        _log({"decision": "deny", "reason": why, "jti": jti, "request_line": line})

    def handle(self) -> None:
        s = self.request
        s.settimeout(15)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 1 << 20:
                return
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        line = lines[0]
        headers = [(l.split(":", 1)[0].strip(), l.split(":", 1)[1].strip()) for l in lines[1:] if ":" in l]
        jti = _jti(headers)
        lower = [k.lower() for k, _ in headers]
        if "transfer-encoding" in lower:
            return self._reject("transfer_encoding", jti, line)
        cls = [v for k, v in headers if k.lower() == "content-length"]
        if len(cls) > 1 or (cls and not cls[0].isdigit()):
            return self._reject("content_length_invalid", jti, line)
        n = int(cls[0]) if cls else 0
        body = rest
        while len(body) < n:
            chunk = s.recv(65536)
            if not chunk:
                break
            body += chunk
        if len(body) < n:
            return self._reject("short_body", jti, line)
        extra, body = body[n:], body[:n]
        if extra:
            return self._reject("trailing_bytes", jti, line)
        cds = [v for k, v in headers if k.lower() == "content-digest"]
        if len(cds) != 1:
            return self._reject("digest_header_missing" if not cds else "digest_header_multiple", jti, line)
        if not body_matches(cds[0], body):
            return self._reject("body_digest_mismatch", jti, line)
        up = socket.create_connection((UP_HOST, int(UP_PORT or 8080)), timeout=15)
        try:
            up.sendall(head + b"\r\n\r\n" + body)
            while True:
                chunk = up.recv(65536)
                if not chunk:
                    break
                s.sendall(chunk)
        finally:
            up.close()


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    port = int(os.environ.get("GATE_PORT", "8081"))
    print(f"digest_gate on :{port} -> {UP_HOST}:{UP_PORT}", file=sys.stderr, flush=True)
    Server(("0.0.0.0", port), Gate).serve_forever()


if __name__ == "__main__":
    main()
