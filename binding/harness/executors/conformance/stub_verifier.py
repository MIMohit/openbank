#!/usr/bin/env python3
"""Stub of the W3 verifier's /authz/orig adapter, for executor conformance ONLY.

It does no cryptography. It records the view each executor sends (X-Original-Method / -URI / -Host
plus whether Authorization and DPoP were forwarded) and decides:
  deny (401) if the unverified DPoP jti starts with "deny-", otherwise allow (200).

  python stub_verifier.py --port 19100 --log ./stub/verifier_stub.jsonl
"""
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def jti_of(dpop):
    try:
        seg = dpop.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("jti")
    except Exception:
        return None


class H(BaseHTTPRequestHandler):
    log_path = None

    def handle_one(self):
        jti = jti_of(self.headers.get("DPoP") or "")
        rec = {"path": self.path, "method": self.command, "jti": jti,
               "x_original_method": self.headers.get("X-Original-Method"),
               "x_original_uri": self.headers.get("X-Original-URI"),
               "x_original_host": self.headers.get("X-Original-Host"),
               "authorization": bool(self.headers.get("Authorization")),
               "dpop": bool(self.headers.get("DPoP"))}
        with open(self.log_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        deny = isinstance(jti, str) and jti.startswith("deny-")
        self.send_response(401 if deny else 200)
        if not deny:
            self.send_header("X-Verified-Sub", "stub")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = handle_one

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=19100)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    H.log_path = a.log
    ThreadingHTTPServer(("0.0.0.0", a.port), H).serve_forever()
