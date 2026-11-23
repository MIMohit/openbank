"""HTTP service for the reference verifier (CONTRACT section 4). Stdlib only (+ core deps).

  ANY /authz/fwd            view from X-Forwarded-{Method,Proto,Host,Uri}   (Traefik, APISIX, Caddy)
  ANY /authz/orig           view from X-Original-{Method,URI,Host,Proto}    (NGINX, HAProxy, Kong, executors)
  ANY /authz/envoy/{rest}   Envoy ext_authz HTTP service, path_prefix=/authz/envoy:
                            method = request method, URI = raw target minus the prefix
  GET /health

Env: PORT (9100), LOG_PATH (/logs/verifier.jsonl), HTU_CANON, JTI_CACHE, IAT_WINDOW, VIEW_MAC,
VIEW_MAC_KEY, AS_PUB_JWK, VIEW_DUP=first|last|reject (which copy of a duplicated view header
is used; default first), LOG_STDOUT=on|off.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import Config, Decision, View, header_values, verify

ENVOY_PREFIX = "/authz/envoy"


class JsonlLog:
    def __init__(self, path: str | None, stdout: bool = True):
        self.path, self.stdout, self.lock = path, stdout, threading.Lock()
        self.fh = None
        if path:
            try:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                self.fh = open(path, "a", buffering=1)
            except OSError as e:
                print(f"verifier: cannot open log {path}: {e}", file=sys.stderr)

    def write(self, rec: dict) -> None:
        line = json.dumps(rec, separators=(",", ":"))
        with self.lock:
            if self.fh:
                self.fh.write(line + "\n")
            if self.stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "bh-verifier/1.0"
    config: Config
    log: JsonlLog
    view_dup: str = "first"

    def log_message(self, fmt, *args):  # silence default stderr access log
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._dispatch
        raise AttributeError(name)

    # -- view extraction ---------------------------------------------------
    def _one(self, name: str, default=None):
        vals = header_values(self.headers, name)
        if not vals:
            return default, False
        if len(vals) > 1:
            if self.view_dup == "reject":
                return None, True
            return (vals[-1] if self.view_dup == "last" else vals[0]).strip(), True
        return vals[0].strip(), False

    def _view(self, adapter: str, target: str) -> tuple[View, bool]:
        dup = False
        if adapter == "fwd":
            (m, d1), (p, d2), (h, d3), (u, d4) = (self._one("x-forwarded-method"), self._one("x-forwarded-proto", "http"),
                                                  self._one("x-forwarded-host"), self._one("x-forwarded-uri"))
            dup = any((d1, d2, d3, d4))
            return View(m, u, h, p or "http"), dup
        if adapter == "orig":
            (m, d1), (u, d2), (h, d3), (p, d4) = (self._one("x-original-method"), self._one("x-original-uri"),
                                                  self._one("x-original-host"), self._one("x-original-proto", "http"))
            if h is None and not d3:
                h, d3 = self._one("host")
            dup = any((d1, d2, d3, d4))
            return View(m, u, h, p or "http"), dup
        # envoy: the check request carries the original method, :authority and path (+prefix)
        rest = target[len(ENVOY_PREFIX):] or "/"
        if rest.startswith("?"):
            rest = "/" + rest
        h, d1 = self._one("host")
        p, d2 = self._one("x-forwarded-proto", "http")
        return View(self.command, rest, h, p or "http"), d1 or d2

    # -- dispatch ------------------------------------------------------------
    def _send(self, status: int, body: dict, headers: dict | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _dispatch(self):
        t0 = time.perf_counter()
        n = int(self.headers.get("Content-Length") or 0)
        if n > 0:
            self.rfile.read(min(n, 1 << 20))
        target = self.path
        path_only = target.split("?", 1)[0]
        if path_only == "/health":
            return self._send(200, {"status": "ok", "canon": self.config.canon})
        if path_only == "/authz/fwd":
            adapter = "fwd"
        elif path_only == "/authz/orig":
            adapter = "orig"
        elif target == ENVOY_PREFIX or target.startswith(ENVOY_PREFIX + "/") or target.startswith(ENVOY_PREFIX + "?"):
            adapter = "envoy"
        else:
            return self._send(404, {"error": "not_found"})
        view, dup = self._view(adapter, target)
        dec: Decision = verify(view, self.headers, self.config)
        if dec.allow:
            self._send(200, {"decision": "allow", "sub": dec.sub, "jkt": dec.jkt}, dec.response_headers)
        else:
            self._send(401, {"decision": "deny", "reason": dec.reason, "error": dec.error},
                       {"WWW-Authenticate": dec.www_authenticate()})
        self.log.write({
            "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "adapter": adapter, "jti": dec.jti, "view_method": view.method, "view_uri": view.uri,
            "view_host": view.host, "view_proto": view.proto, "view_dup": dup, "htm": dec.htm, "htu": dec.htu,
            "canon_mode": self.config.canon, "decision": "allow" if dec.allow else "deny",
            "reason": dec.reason, "sub": dec.sub, "jkt": dec.jkt, "status": dec.status,
            "latency_us": int((time.perf_counter() - t0) * 1e6),
        })


def make_server(config: Config, port: int = 9100, host: str = "0.0.0.0", log_path: str | None = None,
                log_stdout: bool = True, view_dup: str = "first") -> ThreadingHTTPServer:
    if view_dup not in ("first", "last", "reject"):
        raise ValueError("VIEW_DUP must be first|last|reject")
    handler = type("BoundHandler", (Handler,), {"config": config, "log": JsonlLog(log_path, log_stdout),
                                                 "view_dup": view_dup})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv


def main() -> None:
    cfg = Config.from_env()
    port = int(os.environ.get("PORT", "9100"))
    srv = make_server(cfg, port, log_path=os.environ.get("LOG_PATH", "/logs/verifier.jsonl"),
                      log_stdout=os.environ.get("LOG_STDOUT", "on").lower() != "off",
                      view_dup=os.environ.get("VIEW_DUP", "first"))
    print(f"bh-verifier listening on :{port} canon={cfg.canon} jti_cache={cfg.jti_cache} "
          f"iat_window={cfg.iat_window} view_mac={cfg.view_mac}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
