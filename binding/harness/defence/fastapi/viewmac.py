"""Defence D-B, executor side: view-binding MAC check (CONTRACT sections 8 and 10).

Standalone (stdlib only) so it can be copied into an executor image. The verifier, on allow,
emits

    X-Verified-View: v1;<b64url(HMAC-SHA256(K, jti \\n UPPER(view_method) \\n canon(view_path) \\n jkt))>

where canon is the RFC 3986-normalised PATH only (CONTRACT section 10). The executor recomputes
the MAC over ITS OWN view, i.e. the method it dispatched on (after method override) and the
route template it matched with the path parameters substituted, and rejects on any mismatch.

check() is the framework-neutral core. fastapi_dependency() adapts it to FastAPI/Starlette.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import string
from dataclasses import dataclass
from urllib.parse import quote

HEADER = "x-verified-view"
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_PCT = re.compile(r"%([0-9A-Fa-f]{2})")
_ABS = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_URI = re.compile(r"^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$", re.S)
_VALUE = re.compile(r"^v1;[A-Za-z0-9_-]{43}$")
# Same encoder as the executors' VERIFY_MODE=origin-routed (D-A): unreserved + sub-delims + ':' '@'
SEGMENT_SAFE = "-._~!$&'()*+,;=:@"


# ----------------------------------------------------------------------------- canonicalisation
def remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4 (identical to verifier/canon.py)."""
    inp, out = path, []
    while inp:
        if inp.startswith("../"):
            inp = inp[3:]
        elif inp.startswith("./"):
            inp = inp[2:]
        elif inp.startswith("/./"):
            inp = "/" + inp[3:]
        elif inp == "/.":
            inp = "/"
        elif inp.startswith("/../"):
            inp = "/" + inp[4:]
            if out:
                out.pop()
        elif inp == "/..":
            inp = "/"
            if out:
                out.pop()
        elif inp in (".", ".."):
            inp = ""
        else:
            i = inp.find("/", 1)
            seg, inp = (inp, "") if i == -1 else (inp[:i], inp[i:])
            out.append(seg)
    return "".join(out)


def normalise_pct(s: str) -> str:
    def rep(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()
    return _PCT.sub(rep, s)


def canon_path(uri: str) -> str:
    """RFC 3986-normalised path, query and fragment dropped (= verifier.canon.canon_path)."""
    if not uri.startswith("/") and _ABS.match(uri):
        path = _URI.match(uri).group(5)
    else:
        path = re.split(r"[?#]", uri, maxsplit=1)[0]
    p = remove_dot_segments(normalise_pct(path))
    return p or "/"


def substitute(template: str, params: dict) -> str:
    out = template
    for k, v in params.items():
        out = out.replace("{" + k + "}", quote(str(v), safe=SEGMENT_SAFE))
    return out


# ----------------------------------------------------------------------------- JOSE bits
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_json(seg: str):
    return json.loads(base64.urlsafe_b64decode((seg + "=" * (-len(seg) % 4)).encode("ascii")))


def thumbprint(jwk: dict) -> str | None:
    """RFC 7638 SHA-256 thumbprint; None for unsupported/invalid keys."""
    if not isinstance(jwk, dict):
        return None
    kty = jwk.get("kty")
    members = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n"), "OKP": ("crv", "kty", "x")}.get(kty)
    if members is None or not all(isinstance(jwk.get(m), str) for m in members):
        return None
    req = {m: jwk[m] for m in members}
    return _b64u(hashlib.sha256(json.dumps(req, separators=(",", ":"), sort_keys=True).encode()).digest())


def dpop_binding(dpop: str) -> tuple[str, str] | None:
    """(jti, jkt) from a DPoP proof, parsed WITHOUT signature verification (the verifier did that;
    the MAC makes any substitution of the proof detectable)."""
    try:
        parts = dpop.strip().split(".")
        if len(parts) != 3:
            return None
        hdr, claims = _b64u_json(parts[0]), _b64u_json(parts[1])
        jti = claims.get("jti") if isinstance(claims, dict) else None
        jkt = thumbprint(hdr.get("jwk")) if isinstance(hdr, dict) else None
        if not isinstance(jti, str) or jkt is None:
            return None
        return jti, jkt
    except Exception:
        return None


def mac(key: bytes, jti: str, method: str, path: str, jkt: str) -> str:
    msg = "\n".join([jti, method.upper(), canon_path(path), jkt]).encode()
    return "v1;" + _b64u(hmac.new(key, msg, hashlib.sha256).digest())


# ----------------------------------------------------------------------------- the check
@dataclass
class Result:
    ok: bool
    reason: str
    path: str | None = None   # executor's canonical view path (for logs)


def check(key: bytes, view_values: list[str], dpop_values: list[str], method: str,
          template: str, params: dict) -> Result:
    """view_values/dpop_values: every value received for X-Verified-View / DPoP, in order."""
    if not key:
        raise ValueError("DEFENCE=db requires a non-empty VIEW_MAC_KEY")
    if len(view_values) == 0:
        return Result(False, "view_mac_missing")
    if len(view_values) > 1:
        return Result(False, "view_mac_multiple")
    got = view_values[0].strip(" \t")
    if not _VALUE.match(got):
        return Result(False, "view_mac_malformed")
    if len(dpop_values) != 1:
        return Result(False, "view_mac_no_dpop")
    binding = dpop_binding(dpop_values[0])
    if binding is None:
        return Result(False, "view_mac_no_dpop")
    if any(str(v) in (".", "..") for v in params.values()):
        return Result(False, "view_param_dot_segment")
    path = canon_path(substitute(template, params))
    want = mac(key, binding[0], method, path, binding[1])
    if not hmac.compare_digest(want.encode(), got.encode()):
        return Result(False, "view_mac_mismatch", path)
    return Result(True, "ok", path)


# ----------------------------------------------------------------------------- FastAPI adapter
def route_template(scope: dict) -> str | None:
    """Full matched template, including any Mount prefix (Starlette appends each Mount's matched
    prefix to scope['root_path']; scope['app_root_path'] is the server-level root_path)."""
    route = scope.get("route")
    fmt = getattr(route, "path_format", None)
    if fmt is None:
        return None
    mount_prefix = scope.get("root_path", "")[len(scope.get("app_root_path", "")):]
    return mount_prefix + fmt


def fastapi_dependency(key: bytes):
    """FastAPI dependency: `Depends(fastapi_dependency(key))` on a router/app. It runs after
    routing (so scope['route'] and path_params are set) and after any ASGI method-override
    middleware (which rewrites scope['method'])."""
    if not key:
        raise ValueError("DEFENCE=db requires a non-empty VIEW_MAC_KEY")
    from fastapi import HTTPException, Request

    async def _dep(request):
        scope = request.scope
        template = route_template(scope)
        headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope["headers"]]
        res = check(key, [v for k, v in headers if k == HEADER], [v for k, v in headers if k == "dpop"],
                    scope["method"], template or "", dict(request.path_params)) if template else \
            Result(False, "view_route_unknown")
        scope.setdefault("state", {})["viewmac"] = res
        if not res.ok:
            raise HTTPException(status_code=401, detail={"error": "view_binding", "reason": res.reason},
                                headers={"WWW-Authenticate": 'DPoP error="invalid_token"'})
    _dep.__annotations__ = {"request": Request}  # real class: this module uses postponed annotations
    return _dep
