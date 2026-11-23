"""STUB echo executor (W6). NOT a framework executor.

Stands in for bh-exec-<fw>:latest (W4/W5) so gateway and orchestrator wiring can
be tested before the real executors exist. It matches the bench API of CONTRACT
section 3 with plain regexes on the raw path (no decoding, no normalisation, no
method override), honours VERIFY_MODE=origin-raw|origin-routed, and logs one
executor.jsonl line per request with "stub": true. Its routing behaviour says
nothing about any real framework and must never be used as a measurement.

Stdlib only; runs on python:3.12-slim with this file bind-mounted.
"""
import base64
import datetime as dt
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = os.environ.get("LOG_PATH", "/logs/executor.jsonl")
FRAMEWORK = os.environ.get("FRAMEWORK_TAG", "stub")
VERIFY_MODE = os.environ.get("VERIFY_MODE", "off")
VERIFIER = os.environ.get("VERIFIER_URL", "http://verifier:9100/authz/orig")
_lock = threading.Lock()

TRUST_PREFIXES = ("x-forwarded-", "x-original-", "x-verified-", "x-client-cert",
                  "client-cert", "x-forwarded-client-cert", "x-auth-")

# (method, regex, route_template, op_id or dispatcher)
ROUTES = [
    ("GET", r"/api/v1/accounts", "/api/v1/accounts", "listAccounts"),
    ("GET", r"/api/v1/accounts/(?P<id>[^/]+)", "/api/v1/accounts/{id}", "getAccount"),
    ("PUT", r"/api/v1/accounts/(?P<id>[^/]+)", "/api/v1/accounts/{id}", "updateAccount"),
    ("DELETE", r"/api/v1/accounts/(?P<id>[^/]+)", "/api/v1/accounts/{id}", "deleteAccount"),
    ("POST", r"/api/v1/accounts/(?P<id>[^/]+)/actions", "/api/v1/accounts/{id}/actions", "accountAction"),
    ("POST", r"/api/v1/transfers", "/api/v1/transfers", "createTransfer"),
    ("POST", r"/api/v1/graphql", "/api/v1/graphql", "graphql"),
    ("GET", r"/api/v1/me", "/api/v1/me", "me"),
    ("GET", r"/api/v1/admin/users", "/api/v1/admin/users", "adminListUsers"),
    ("DELETE", r"/api/v1/admin/users/(?P<id>[^/]+)", "/api/v1/admin/users/{id}", "adminDeleteUser"),
    ("GET", r"/api/v1/health", "/api/v1/health", "health"),
    ("GET", r"/api/v1/public/(?P<file>[^/]+)", "/api/v1/public/{file}", "publicFile"),
    ("GET", r"/api/v2/accounts/(?P<id>[^/]+)", "/api/v2/accounts/{id}", "getAccountV2"),
]
ROUTES = [(m, re.compile(rx + r"\Z"), t, o) for m, rx, t, o in ROUTES]


def jti_of(dpop):
    if not dpop:
        return None
    try:
        seg = dpop.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode())).get("jti")
    except Exception:
        return None


def log(rec):
    line = json.dumps(rec, separators=(",", ":"))
    print(line, flush=True)
    try:
        with _lock, open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(f"stub_executor: cannot write {LOG_PATH}: {exc}", file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "bh-stub-executor"

    def log_message(self, fmt, *args):
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._handle
        raise AttributeError(name)

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        raw_target = self.path
        path, _, query = raw_target.partition("?")
        method = self.command
        op_id, template, params = "NOT_FOUND", None, {}
        for m, rx, t, o in ROUTES:
            mt = rx.match(path)
            if mt and m == method:
                op_id, template, params = o, t, mt.groupdict()
                break
        if op_id == "accountAction":
            q = dict(p.partition("=")[::2] for p in query.split("&") if p)
            op_id = "accountAction." + (q.get("op") if q.get("op") in ("freeze", "close") else "unknown")
        elif op_id == "graphql":
            try:
                name = json.loads(body or b"{}").get("operationName")
            except Exception:
                name = None
            op_id = {"getProfile": "graphql.getProfile", "deleteProfile": "graphql.deleteProfile"}.get(name, "graphql.unknown")

        denied = False
        if VERIFY_MODE in ("origin-raw", "origin-routed") and op_id != "health":
            if VERIFY_MODE == "origin-raw":
                vm, vu = method, raw_target
            else:
                vm = method
                vu = template.format(**params) if template else path
            hdrs = {"X-Original-Method": vm, "X-Original-URI": vu,
                    "X-Original-Host": self.headers.get("Host", "")}
            for k in ("Authorization", "DPoP"):
                if self.headers.get(k) is not None:
                    hdrs[k] = self.headers.get(k)
            try:
                with urllib.request.urlopen(urllib.request.Request(VERIFIER, headers=hdrs), timeout=3) as r:
                    denied = not (200 <= r.status < 300)
            except urllib.error.HTTPError:
                denied = True
            except Exception as exc:
                print(f"stub_executor: verifier call failed: {exc}", file=sys.stderr, flush=True)
                denied = True

        status = 401 if denied else (404 if op_id == "NOT_FOUND" else 200)
        trust = {k.lower(): v for k, v in self.headers.items() if k.lower().startswith(TRUST_PREFIXES)}
        log({
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(), "framework": FRAMEWORK,
            "jti": jti_of(self.headers.get("DPoP")), "op_id": op_id, "route_template": template,
            "raw_method": method, "effective_method": method, "raw_target": raw_target,
            "path_params": params, "query": query, "trust_headers": trust,
            "denied": denied, "status": status, "stub": True,
        })
        out = json.dumps({"op_id": op_id, "framework": FRAMEWORK, "method": method,
                          "path_params": params, "stub": True}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"bh STUB executor ({FRAMEWORK}, VERIFY_MODE={VERIFY_MODE}) on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
