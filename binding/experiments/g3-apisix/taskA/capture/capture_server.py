#!/usr/bin/env python3
"""Capture server: logs the EXACT raw request-target and all headers it receives.
ROLE=verifier  -> answers /authz/fwd and /authz/orig with 200 + X-Verified-Sub (so APISIX proxies upstream)
ROLE=upstream  -> answers anything with 200, logging the raw path APISIX forwarded.
Every request is appended as one JSON line to /logs/<ROLE>.jsonl and echoed to stdout.
Uses http.server, whose self.path is the raw request-target (percent-encoding preserved).
"""
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

ROLE = os.environ.get("ROLE", "upstream")
PORT = int(os.environ.get("PORT", "8080"))
LOG = os.environ.get("LOG_PATH", f"/logs/{ROLE}.jsonl")

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _log(self):
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "role": ROLE,
            "command": self.command,
            "raw_path": self.path,                       # exact request-target bytes
            "request_line": f"{self.command} {self.path} {self.request_version}",
            "headers": {k.lower(): v for k, v in self.headers.items()},
        }
        line = json.dumps(rec)
        try:
            with open(LOG, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            sys.stderr.write(f"logwrite-failed: {e}\n")
        print(line, flush=True)

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self._log()
        if ROLE == "verifier":
            body = b'{"decision":"allow"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Verified-Sub", "alice")
            self.send_header("X-Verified-Jkt", "testjkt")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        else:
            body = json.dumps({"role": ROLE, "raw_path": self.path, "op": "echo"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _handle
    def do_OPTIONS(self): self._handle()
    def log_message(self, *a): pass

if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    srv.daemon_threads = True
    print(f"capture[{ROLE}] on :{PORT} log={LOG}", flush=True)
    srv.serve_forever()
