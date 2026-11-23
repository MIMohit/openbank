"""Shared executor helpers (jti extraction, verifier call, JSONL log)."""
import base64
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import quote

FRAMEWORK = os.environ.get("FRAMEWORK_TAG", "django")
VERIFY_MODE = os.environ.get("VERIFY_MODE", "off").lower()
VERIFIER_URL = os.environ.get("VERIFIER_URL", "http://verifier:9100/authz/orig")
LOG_PATH = os.environ.get("LOG_PATH", "/logs/executor.jsonl")
TRUST_PREFIXES = ("x-forwarded-", "x-original-", "x-verified-", "x-client-cert",
                  "client-cert", "x-forwarded-client-cert", "x-auth-")
if VERIFY_MODE not in ("off", "origin-raw", "origin-routed"):
    sys.exit(f"bad VERIFY_MODE={VERIFY_MODE}")
_lock = threading.Lock()


def jti_from_dpop(value):
    if not value:
        return None
    try:
        parts = value.strip().split(".")
        if len(parts) != 3:
            return None
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
        jti = claims.get("jti") if isinstance(claims, dict) else None
        return jti if isinstance(jti, str) else None
    except Exception:
        return None


def canonical_path(template, params):
    out = template
    for k, v in params.items():
        out = out.replace("{" + k + "}", quote(str(v), safe="-._~!$&'()*+,;=:@"))
    return out


def write_log(rec):
    line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
    with _lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def call_verifier(method, uri, host, authorization, dpop):
    req = urllib.request.Request(VERIFIER_URL, method="GET")
    req.add_header("X-Original-Method", method)
    req.add_header("X-Original-URI", uri)
    req.add_header("X-Original-Host", host)
    if authorization is not None:
        req.add_header("Authorization", authorization)
    if dpop is not None:
        req.add_header("DPoP", dpop)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False  # HTTPError (deny) or unreachable: fail closed
