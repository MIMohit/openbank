"""PDP HTTP service (W12, E4): the verifier's adapters + a path-based ownership/role policy.

It exposes exactly the verifier's adapter surface (CONTRACT §4) so it is a drop-in replacement
for the ``verifier`` service in a topology (set ``verifier.image: bh-pdp:latest``):

  ANY /authz/fwd            view from X-Forwarded-{Method,Proto,Host,Uri}
  ANY /authz/orig           view from X-Original-{Method,URI,Host,Proto}
  ANY /authz/envoy/{rest}   Envoy ext_authz, path_prefix=/authz/envoy
  GET /health

For every request it (1) runs the REAL verifier core (RFC 9449 §4.3 proof checks, imported
from ``verifier.core``) on the view, then (2) if the proof is valid, applies the path policy
(``pdp.policy``) to the SAME view the verifier saw. Overall decision = proof-valid AND
policy-allow. The decision, the view, and the matched rule are logged.

It writes TWO logs:
  * ``/logs/verifier.jsonl`` — the standard verifier record (CONTRACT §4), with ``decision``
    reflecting proof∧policy, so the binding oracle (``oracle.correlate``) reads it unchanged.
  * ``/logs/pdp.jsonl`` — the PDP record: the separate proof decision, the policy decision,
    the matched rule id, the matched (post-normalisation) path.

Env: PORT (9100), LOG_PATH (/logs/verifier.jsonl), PDP_LOG_PATH (/logs/pdp.jsonl),
POLICY=allowlist|blocklist (default allowlist), POLICY_NORMALIZE=off|rfc3986 (default off),
plus every verifier var (HTU_CANON, JTI_CACHE, IAT_WINDOW, VIEW_MAC, VIEW_MAC_KEY, AS_PUB_JWK,
VIEW_DUP, LOG_STDOUT).
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

from verifier.core import Config, Decision, View, header_values, verify
from pdp import policy as policymod

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
                print(f"pdp: cannot open log {path}: {e}", file=sys.stderr)

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
    server_version = "bh-pdp/1.0"
    config: Config
    vlog: JsonlLog
    plog: JsonlLog
    view_dup: str = "first"
    policy_name: str = "allowlist"
    normalize: str = "off"

    def log_message(self, fmt, *args):
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._dispatch
        raise AttributeError(name)

    # -- view extraction (mirrors verifier.server._view exactly) -----------------
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
        if adapter == "fwd":
            (m, d1), (p, d2), (h, d3), (u, d4) = (self._one("x-forwarded-method"),
                                                  self._one("x-forwarded-proto", "http"),
                                                  self._one("x-forwarded-host"),
                                                  self._one("x-forwarded-uri"))
            return View(m, u, h, p or "http"), any((d1, d2, d3, d4))
        if adapter == "orig":
            (m, d1), (u, d2), (h, d3), (p, d4) = (self._one("x-original-method"),
                                                  self._one("x-original-uri"),
                                                  self._one("x-original-host"),
                                                  self._one("x-original-proto", "http"))
            if h is None and not d3:
                h, d3 = self._one("host")
            return View(m, u, h, p or "http"), any((d1, d2, d3, d4))
        rest = target[len(ENVOY_PREFIX):] or "/"
        if rest.startswith("?"):
            rest = "/" + rest
        h, d1 = self._one("host")
        p, d2 = self._one("x-forwarded-proto", "http")
        return View(self.command, rest, h, p or "http"), d1 or d2

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
            return self._send(200, {"status": "ok", "canon": self.config.canon,
                                    "policy": self.policy_name, "normalize": self.normalize})
        if path_only == "/authz/fwd":
            adapter = "fwd"
        elif path_only == "/authz/orig":
            adapter = "orig"
        elif target == ENVOY_PREFIX or target.startswith(ENVOY_PREFIX + "/") or target.startswith(ENVOY_PREFIX + "?"):
            adapter = "envoy"
        else:
            return self._send(404, {"error": "not_found"})

        view, dup = self._view(adapter, target)
        # (1) real verifier core
        dec: Decision = verify(view, self.headers, self.config)
        # (2) path policy, only meaningful when the proof is valid
        pol = None
        allow = dec.allow
        reason = dec.reason
        if dec.allow:
            pol = policymod.decide(view.uri or "", self.policy_name, self.normalize)
            allow = pol.effect == "allow"
            reason = "ok" if allow else f"policy_deny:{pol.rule_id}"

        if allow:
            self._send(200, {"decision": "allow", "sub": dec.sub, "jkt": dec.jkt,
                             "rule": pol.rule_id if pol else None}, dec.response_headers)
        else:
            err = dec.error if not dec.allow else "insufficient_scope"
            wa = dec.www_authenticate() if not dec.allow else \
                f'DPoP error="insufficient_scope"'
            self._send(401, {"decision": "deny", "reason": reason, "error": err},
                       {"WWW-Authenticate": wa})

        ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        # verifier-format record (oracle reads this)
        self.vlog.write({
            "ts": ts, "adapter": adapter, "jti": dec.jti, "view_method": view.method,
            "view_uri": view.uri, "view_host": view.host, "view_proto": view.proto,
            "view_dup": dup, "htm": dec.htm, "htu": dec.htu, "canon_mode": self.config.canon,
            "decision": "allow" if allow else "deny", "reason": reason,
            "sub": dec.sub, "jkt": dec.jkt, "status": 200 if allow else 401,
            "latency_us": int((time.perf_counter() - t0) * 1e6),
        })
        # pdp record (policy detail)
        self.plog.write({
            "ts": ts, "adapter": adapter, "jti": dec.jti, "sub": dec.sub,
            "view_method": view.method, "view_uri": view.uri,
            "proof_decision": "allow" if dec.allow else "deny",
            "proof_reason": dec.reason,
            "policy": self.policy_name, "normalize": self.normalize,
            "policy_decision": (pol.effect if pol else None),
            "matched_rule": (pol.rule_id if pol else None),
            "matched_path": (pol.matched_path if pol else None),
            "overall": "allow" if allow else "deny",
        })


def make_server(config: Config, port: int = 9100, host: str = "0.0.0.0",
                log_path: str | None = None, pdp_log_path: str | None = None,
                log_stdout: bool = True, view_dup: str = "first",
                policy_name: str = "allowlist", normalize: str = "off") -> ThreadingHTTPServer:
    if view_dup not in ("first", "last", "reject"):
        raise ValueError("VIEW_DUP must be first|last|reject")
    if policy_name not in policymod.POLICIES:
        raise ValueError(f"POLICY must be one of {list(policymod.POLICIES)}")
    if normalize not in ("off", "rfc3986"):
        raise ValueError("POLICY_NORMALIZE must be off|rfc3986")
    handler = type("BoundHandler", (Handler,),
                   {"config": config, "vlog": JsonlLog(log_path, log_stdout),
                    "plog": JsonlLog(pdp_log_path, log_stdout), "view_dup": view_dup,
                    "policy_name": policy_name, "normalize": normalize})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv


def main() -> None:
    cfg = Config.from_env()
    port = int(os.environ.get("PORT", "9100"))
    srv = make_server(
        cfg, port,
        log_path=os.environ.get("LOG_PATH", "/logs/verifier.jsonl"),
        pdp_log_path=os.environ.get("PDP_LOG_PATH", "/logs/pdp.jsonl"),
        log_stdout=os.environ.get("LOG_STDOUT", "on").lower() != "off",
        view_dup=os.environ.get("VIEW_DUP", "first"),
        policy_name=os.environ.get("POLICY", "allowlist"),
        normalize=os.environ.get("POLICY_NORMALIZE", "off"))
    print(f"bh-pdp listening on :{port} canon={cfg.canon} policy={os.environ.get('POLICY','allowlist')} "
          f"normalize={os.environ.get('POLICY_NORMALIZE','off')}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
