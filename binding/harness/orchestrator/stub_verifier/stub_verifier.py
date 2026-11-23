"""STUB verifier (W6). NOT the reference verifier.

Stands in for bh-verifier:latest (W3) until that image exists, so gateway and
orchestrator wiring can be tested. It implements the three adapters of
CONTRACT section 4, extracts the view each adapter would see, logs it in the
verifier.jsonl schema, and ALWAYS ALLOWS. It does no cryptographic checks.
Every log line carries "stub": true and reason "STUB-ALWAYS-ALLOW" so its output
can never be mistaken for a real verifier decision.

Stdlib only; runs on python:3.12-slim with this file bind-mounted.
"""
import base64
import datetime as dt
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.environ.get("LOG_PATH", "/logs/verifier.jsonl")
CANON = os.environ.get("HTU_CANON", "rfc3986")
_lock = threading.Lock()


def _b64url_json(seg: str):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode()))


def proof_claims(dpop: str | None) -> dict:
    """Decode the DPoP payload WITHOUT verifying it (stub only)."""
    if not dpop:
        return {}
    try:
        return _b64url_json(dpop.split(".")[1])
    except Exception:
        return {}


def log(rec: dict) -> None:
    line = json.dumps(rec, separators=(",", ":"))
    print(line, flush=True)
    try:
        with _lock, open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:  # logs dir not mounted
        print(f"stub_verifier: cannot write {LOG_PATH}: {exc}", file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "bh-stub-verifier"

    def log_message(self, fmt, *args):  # silence default access log
        pass

    def __getattr__(self, name):
        # Accept every method token (GET, POST, PATCH, FOO, ...).
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def _reply(self, status: int, headers: dict | None = None, body: bytes = b"") -> None:
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        path = self.path
        h = self.headers
        if path == "/health" or path.startswith("/health?"):
            return self._reply(200, {"Content-Type": "application/json"}, b'{"status":"ok","stub":true}')
        if path.startswith("/authz/envoy"):
            adapter = "envoy"
            view_method = self.command
            view_uri = path[len("/authz/envoy"):] or "/"
            view_host = h.get("Host")
            view_proto = h.get("X-Forwarded-Proto", "http")
        elif path.startswith("/authz/fwd"):
            adapter = "fwd"
            view_method = h.get("X-Forwarded-Method")
            view_uri = h.get("X-Forwarded-Uri")
            view_host = h.get("X-Forwarded-Host")
            view_proto = h.get("X-Forwarded-Proto", "http")
        elif path.startswith("/authz/orig"):
            adapter = "orig"
            view_method = h.get("X-Original-Method")
            view_uri = h.get("X-Original-URI")
            view_host = h.get("X-Original-Host")
            view_proto = h.get("X-Original-Proto", "http")
        else:
            return self._reply(404, {"Content-Type": "application/json"}, b'{"error":"unknown adapter"}')
        claims = proof_claims(h.get("DPoP"))
        log({
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "adapter": adapter,
            "jti": claims.get("jti"),
            "view_method": view_method,
            "view_uri": view_uri,
            "view_host": view_host,
            "view_proto": view_proto,
            "htm": claims.get("htm"),
            "htu": claims.get("htu"),
            "canon_mode": CANON,
            "decision": "allow",
            "reason": "STUB-ALWAYS-ALLOW",
            "sub": "stub",
            "jkt": "stub",
            "has_authorization": h.get("Authorization") is not None,
            "has_dpop": h.get("DPoP") is not None,
            "stub": True,
        })
        return self._reply(200, {"X-Verified-Sub": "stub", "X-Verified-Jkt": "stub"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9100"))
    print(f"bh STUB verifier (always allow) listening on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
