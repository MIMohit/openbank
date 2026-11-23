"""W22 real-app PDP: the reference verifier's proof check + a FILE-CONFIGURED path policy.

Same idea and adapter surface as binding/harness/pdp (W12/E4), but the policy rules come
from a JSON file (POLICY_FILE) so each real application can carry a policy written in the
style its own docs / common gateway guides recommend (per-tenant prefix allow-list, or
admin/other-tenant deny blocklist). The RFC 9449 proof check is the REAL verifier core,
IMPORTED from `verifier.core` (not reimplemented) — this script is bind-mounted into the
stock `bh-verifier:latest` image, whose `verifier` package it imports unchanged.

Decision = proof-valid AND policy-allow. On allow: 200 + X-Verified-Sub/Jkt. On deny: 401.
Writes /logs/verifier.jsonl (standard verifier record, so the probe harness reads `decision`)
and /logs/pdp.jsonl (policy detail: proof vs policy sub-decisions, matched rule).

Policy file schema:
  {"default":"deny"|"allow",
   "normalize":"off"|"rfc3986",
   "rules":[{"id":..,"style":"prefix"|"exact"|"regex"|"suffix","pattern":..,"effect":"allow"|"deny","note":..}]}
Rules are evaluated top-to-bottom; the FIRST matching rule's effect wins; else `default`.
`normalize=rfc3986` runs the verifier canonicaliser (remove_dot_segments, %-decode unreserved;
no slash-collapse, no case-fold, no ;/.json strip) on the view path before matching.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/app")  # where the verifier package lives in bh-verifier:latest
from verifier.core import Config, Decision, View, verify  # noqa: E402
from verifier import canon  # noqa: E402

ENVOY_PREFIX = "/authz/envoy"


def load_policy(path: str) -> dict:
    p = json.load(open(path))
    p.setdefault("default", "deny")
    p.setdefault("normalize", "off")
    p.setdefault("rules", [])
    return p


def rule_matches(style: str, pattern: str, path: str) -> bool:
    if style == "prefix":
        return path == pattern or path.startswith(pattern.rstrip("/") + "/") or path.startswith(pattern)
    if style == "exact":
        return path == pattern
    if style == "suffix":
        return path.endswith(pattern)
    if style == "regex":
        return re.search(pattern, path) is not None
    raise ValueError(f"unknown rule style {style!r}")


def policy_decide(policy: dict, raw_path: str):
    path = raw_path
    if policy["normalize"] == "rfc3986":
        try:
            path = canon.canon_path(raw_path)  # rfc3986 path normalisation (no query/fragment)
        except Exception:  # noqa: BLE001
            path = raw_path
    for r in policy["rules"]:
        if rule_matches(r["style"], r["pattern"], path):
            return r["effect"], r["id"], path, r.get("style")
    return policy["default"], "<default>", path, "default"


class Log:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.fh = open(path, "a", buffering=1) if path else None

    def write(self, rec):
        line = json.dumps(rec, separators=(",", ":"))
        with self.lock:
            if self.fh:
                self.fh.write(line + "\n")
            sys.stdout.write(line + "\n")
            sys.stdout.flush()


def _now():
    return datetime.now(timezone.utc).isoformat()


class Handler(BaseHTTPRequestHandler):
    config: Config = None
    policy: dict = None
    vlog: Log = None
    plog: Log = None

    def log_message(self, *a):
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._dispatch
        raise AttributeError(name)

    def _one(self, name, default=None):
        v = self.headers.get(name)
        return v if v is not None else default

    def _view(self, adapter, target):
        if adapter == "fwd":
            return View(self._one("X-Forwarded-Method"), self._one("X-Forwarded-Uri"),
                        self._one("X-Forwarded-Host"), self._one("X-Forwarded-Proto") or "http")
        if adapter == "orig":
            return View(self._one("X-Original-Method"), self._one("X-Original-URI"),
                        self._one("X-Original-Host"), self._one("X-Original-Proto") or "http")
        rest = target[len(ENVOY_PREFIX):] or "/"
        return View(self.command, rest, self._one("X-Forwarded-Host") or self._one("Host"),
                    self._one("X-Forwarded-Proto") or "http")

    def _send(self, status, body, headers=None):
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
        target = self.path
        path_only = target.split("?", 1)[0]
        if path_only == "/health":
            return self._send(200, {"status": "ok"})
        if path_only == "/authz/fwd":
            view = self._view("fwd", target)
        elif path_only == "/authz/orig":
            view = self._view("orig", target)
        elif target == ENVOY_PREFIX or target.startswith(ENVOY_PREFIX + "/") or target.startswith(ENVOY_PREFIX + "?"):
            view = self._view("envoy", target)
        else:
            return self._send(404, {"error": "no such adapter"})

        dec: Decision = verify(view, self.headers, self.config)
        pol = None
        if dec.allow:
            effect, rid, mpath, style = policy_decide(self.policy, view.uri or "")
            pol = (effect, rid, mpath, style)
            allow = effect == "allow"
            reason = "ok" if allow else f"policy_deny:{rid}"
        else:
            allow = False
            reason = dec.reason

        if allow:
            self._send(200, {"decision": "allow", "sub": dec.sub, "jkt": dec.jkt},
                       {"X-Verified-Sub": dec.sub or "", "X-Verified-Jkt": dec.jkt or ""})
        else:
            err = dec.error if (not dec.allow and dec.error) else "invalid_dpop_proof"
            self._send(401, {"decision": "deny", "reason": reason},
                       {"WWW-Authenticate": f'DPoP error="{err}"'})

        self.vlog.write({
            "ts": _now(), "adapter": path_only, "jti": dec.jti,
            "view_method": view.method, "view_uri": view.uri, "view_host": view.host,
            "htm": dec.htm, "htu": dec.htu, "canon_mode": self.config.canon,
            "decision": "allow" if allow else "deny", "reason": reason,
            "sub": dec.sub, "jkt": dec.jkt})
        self.plog.write({
            "ts": _now(), "jti": dec.jti, "view_uri": view.uri,
            "proof_decision": "allow" if dec.allow else "deny", "proof_reason": dec.reason,
            "policy": os.environ.get("POLICY_NAME", "file"), "normalize": self.policy["normalize"],
            "policy_decision": (pol[0] if pol else None), "matched_rule": (pol[1] if pol else None),
            "matched_path": (pol[2] if pol else None), "matched_style": (pol[3] if pol else None),
            "decision": "allow" if allow else "deny"})


def main():
    cfg = Config.from_env(os.environ)
    policy = load_policy(os.environ["POLICY_FILE"])
    Handler.config = cfg
    Handler.policy = policy
    Handler.vlog = Log(os.environ.get("LOG_PATH", "/logs/verifier.jsonl"))
    Handler.plog = Log(os.environ.get("PDP_LOG_PATH", "/logs/pdp.jsonl"))
    port = int(os.environ.get("PORT", "9100"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"w22-pdp on :{port} canon={cfg.canon} default={policy['default']} "
          f"normalize={policy['normalize']} rules={len(policy['rules'])}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
