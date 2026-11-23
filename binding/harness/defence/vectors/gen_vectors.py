"""Generate defence/vectors.json from the REFERENCE VERIFIER's implementation.

Every MAC, canonical path and thumbprint below comes from verifier.core.view_mac,
verifier.canon.canon_path and verifier.jose.thumbprint; nothing is imported from the
defence/ implementations, so the vectors are an independent oracle for all four languages.

Run (from binding/harness):
    PYTHONPATH=. verifier/.venv/bin/python defence/vectors/gen_vectors.py > defence/vectors.json
"""
from __future__ import annotations

import base64
import json
import re
import sys
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from verifier import canon as vcanon
from verifier import core as vcore
from verifier import jose as vjose


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ec_jwk(priv) -> dict:
    n = priv.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}


def rsa_jwk(priv) -> dict:
    n = priv.public_key().public_numbers()
    return {"kty": "RSA", "e": b64u(n.e.to_bytes(3, "big")), "n": b64u(n.n.to_bytes(256, "big"))}


def proof(priv, jti: str, htm: str, htu: str) -> str:
    h = {"typ": "dpop+jwt", "alg": "ES256", "jwk": ec_jwk(priv)}
    c = {"jti": jti, "htm": htm, "htu": htu, "iat": 1795000000, "ath": "x" * 43}
    si = b64u(json.dumps(h, separators=(",", ":")).encode()) + "." + b64u(json.dumps(c, separators=(",", ":")).encode())
    r, s = decode_dss_signature(priv.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
    return si + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def substitute(template: str, params: dict) -> str:
    # The executors' D-A encoder (python quote safe="-._~!$&'()*+,;=:@", mirrored in all 8 executors)
    out = template
    for k, v in params.items():
        out = out.replace("{" + k + "}", quote(str(v), safe="-._~!$&'()*+,;=:@"))
    return out


KEY = "w11-test-view-mac-key"
alice = ec.generate_private_key(ec.SECP256R1())
mallory = ec.generate_private_key(ec.SECP256R1())
JTI = "6f1c2b9e-0d3a-4c55-9a43-2f5d6e7a8b90"
JKT = vjose.thumbprint(ec_jwk(alice))
DPOP = proof(alice, JTI, "GET", "http://api.bench.test/api/v1/accounts/acc-alice-1")
DPOP_OTHER_JTI = proof(alice, "11111111-2222-4333-8444-555555555555", "GET", "http://api.bench.test/x")
DPOP_OTHER_KEY = proof(mallory, JTI, "GET", "http://api.bench.test/x")


def vmac(view_method, view_uri, jti=JTI, jkt=JKT, key=KEY):
    return vcore.view_mac(key.encode(), jti, view_method, view_uri, jkt)


def expect(key, view_values, dpop_values, method, template, params):
    """Expected executor decision, from the verifier's primitives."""
    if not view_values:
        return False, "view_mac_missing", None
    if len(view_values) > 1:
        return False, "view_mac_multiple", None
    got = view_values[0].strip(" \t")
    if not re.fullmatch(r"v1;[A-Za-z0-9_-]{43}", got):
        return False, "view_mac_malformed", None
    if len(dpop_values) != 1:
        return False, "view_mac_no_dpop", None
    try:
        p = dpop_values[0].split(".")
        hdr = json.loads(vjose.b64u_decode(p[0]))
        claims = json.loads(vjose.b64u_decode(p[1]))
        jti, jkt = claims["jti"], vjose.thumbprint(hdr["jwk"])
        assert isinstance(jti, str) and len(p) == 3
    except Exception:
        return False, "view_mac_no_dpop", None
    if any(str(v) in (".", "..") for v in params.values()):
        return False, "view_param_dot_segment", None
    path = vcanon.canon_path(substitute(template, params))
    want = vcore.view_mac(key.encode(), jti, method, path, jkt)
    return (want == got, "ok" if want == got else "view_mac_mismatch", path)


CASES = []


def case(name, note, method, template, params, *, view=None, views=None, dpops=None, key=KEY):
    """view = (verifier view method, verifier view URI) -> X-Verified-View emitted by the verifier."""
    if views is None:
        views = [vmac(*view)] if view else []
    dpops = [DPOP] if dpops is None else dpops
    ok, reason, path = expect(key, views, dpops, method, template, params)
    CASES.append({"name": name, "note": note, "key": key,
                  "verifier_view": {"method": view[0], "uri": view[1]} if view else None,
                  "headers": {"x-verified-view": views, "dpop": dpops},
                  "method": method, "template": template, "params": params,
                  "expect": {"ok": ok, "reason": reason, "path": path}})


A = "/api/v1/accounts/{id}"
case("benign_get", "same view on both sides", "GET", A, {"id": "acc-alice-1"}, view=("GET", "/api/v1/accounts/acc-alice-1"))
case("benign_query_ignored", "query is outside the MAC (path only)", "GET", "/api/v1/accounts", {}, view=("GET", "/api/v1/accounts?limit=5"))
case("view_absolute_form", "absolute-form view URI", "GET", "/api/v1/me", {}, view=("GET", "http://api.bench.test/api/v1/me"))
case("view_lowercase_method", "view method is upper-cased in the MAC", "GET", "/api/v1/me", {}, view=("get", "/api/v1/me"))
case("view_pct_unreserved", "%2D decodes to '-' under RFC 3986 normalisation", "GET", A, {"id": "acc-alice-1"}, view=("GET", "/api/v1/accounts/acc%2Dalice-1"))
case("view_dot_segments", "benign dot-segments removed on the verifier side", "GET", "/api/v1/accounts", {}, view=("GET", "/api/v1/x/../accounts"))
case("param_space", "decoded param re-encoded as %20", "GET", A, {"id": "a b"}, view=("GET", "/api/v1/accounts/a%20b"))
case("param_utf8_lowerhex", "lower-case hex upper-cased by the verifier canon", "GET", A, {"id": "ü"}, view=("GET", "/api/v1/accounts/%c3%bc"))
case("param_encoded_slash", "decoded '/' in a param re-encoded as %2F", "GET", "/api/v1/public/{file}", {"file": "a/b"}, view=("GET", "/api/v1/public/a%2Fb"))
case("param_subdelims_literal", "sub-delims and ':' '@' stay literal", "GET", A, {"id": "a:b@c;d=e"}, view=("GET", "/api/v1/accounts/a:b@c;d=e"))
case("param_percent", "a literal '%' in a decoded param becomes %25", "GET", A, {"id": "100%"}, view=("GET", "/api/v1/accounts/100%25"))
case("prefix_mount_v2", "sub-router prefix is part of the template", "GET", "/api/v2/accounts/{id}", {"id": "acc-alice-1"}, view=("GET", "/api/v2/accounts/acc-alice-1"))
case("g1_query_dispatch_not_covered", "G1: op=freeze vs op=close is NOT covered by D-B (path-only MAC)", "POST", "/api/v1/accounts/{id}/actions", {"id": "acc-alice-1"}, view=("POST", "/api/v1/accounts/acc-alice-1/actions?op=freeze"))
case("g1_method_override", "G1: verifier saw POST, executor dispatched DELETE after override", "DELETE", A, {"id": "acc-alice-1"}, view=("POST", "/api/v1/accounts/acc-alice-1"))
case("g2_route_differs", "G2: verifier view publicFile, router matched adminListUsers", "GET", "/api/v1/admin/users", {}, view=("GET", "/api/v1/public/..%2Fadmin/users"))
case("g2_trailing_slash", "G2: trailing-slash tolerant router", "GET", "/api/v1/accounts", {}, view=("GET", "/api/v1/accounts/"))
case("g2_case_insensitive_router", "G2: case-insensitive router", "GET", "/api/v1/accounts", {}, view=("GET", "/API/v1/accounts"))
case("g2_semicolon_param", "G2: router strips ;matrix params, verifier keeps them", "GET", A, {"id": "acc-alice-1"}, view=("GET", "/api/v1/accounts/acc-alice-1;x=1"))
case("g2_other_id", "different {id}", "GET", A, {"id": "acc-bob-1"}, view=("GET", "/api/v1/accounts/acc-alice-1"))
case("param_dot_dot", "a decoded '..' param would collapse under canon: fail closed", "GET", "/api/v1/public/{file}", {"file": ".."}, view=("GET", "/api/v1/public/%2E%2E"))
case("param_dot", "a decoded '.' param: fail closed", "GET", "/api/v1/public/{file}", {"file": "."}, view=("GET", "/api/v1/public/%2E"))
case("missing_header", "no X-Verified-View (verifier bypassed)", "GET", "/api/v1/me", {})
case("g3_duplicate_header", "G3: client-injected copy plus the gateway's", "GET", "/api/v1/me", {},
     views=[vmac("GET", "/api/v1/health"), vmac("GET", "/api/v1/me")], view=None)
case("malformed_version", "unknown version prefix", "GET", "/api/v1/me", {}, views=["v2;" + vmac("GET", "/api/v1/me")[3:]])
case("malformed_padding", "padded base64url", "GET", "/api/v1/me", {}, views=[vmac("GET", "/api/v1/me") + "="])
case("ows_trimmed", "surrounding OWS is ignored", "GET", "/api/v1/me", {}, views=[" " + vmac("GET", "/api/v1/me") + " "])
case("wrong_key", "MAC forged with another key", "GET", "/api/v1/me", {}, views=[vmac("GET", "/api/v1/me", key="attacker-key")])
case("dpop_swapped_jti", "DPoP header replaced by a proof with another jti", "GET", "/api/v1/me", {}, view=("GET", "/api/v1/me"), dpops=[DPOP_OTHER_JTI])
case("dpop_swapped_key", "DPoP header replaced by a proof with another key", "GET", "/api/v1/me", {}, view=("GET", "/api/v1/me"), dpops=[DPOP_OTHER_KEY])
case("dpop_missing", "no DPoP header", "GET", "/api/v1/me", {}, view=("GET", "/api/v1/me"), dpops=[])
case("dpop_multiple", "two DPoP headers", "GET", "/api/v1/me", {}, view=("GET", "/api/v1/me"), dpops=[DPOP, DPOP])
case("dpop_garbage", "unparseable DPoP header", "GET", "/api/v1/me", {}, view=("GET", "/api/v1/me"), dpops=["not.a.jwt"])
# fix the None view for header-only cases
for c in CASES:
    if c["name"] == "g3_duplicate_header":
        c["verifier_view"] = None

CANON = ["/api/v1/accounts", "/api/v1/accounts?x=1#f", "", "/", "/a/./b/../c", "/a/%2e%2E/b", "/a%2fb", "/a%2Fb",
         "/%7Euser/%41%42", "/a//b", "/a/b/..", "/..", "http://API.bench.test:80/x/../y?q", "https://h", "/a;b=c/d",
         "/%c3%bc", "/a%2", "/a/%2E", "/A/B"]
TP = [ec_jwk(alice), ec_jwk(mallory), rsa_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
      {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]
MACS = [("k", "j", "get", "/api/v1/me", "t"), (KEY, JTI, "DELETE", "/api/v1/accounts/acc-alice-1", JKT),
        (KEY, JTI, "POST", "/api/v1/x/../transfers?y=1", JKT), ("été", "jüti", "PUT", "/a%2fb", "jkt")]
SUBST = [("/api/v1/accounts/{id}", {"id": v}) for v in
         ["acc-alice-1", "a b", "a/b", "100%", "ü", "a:b@c;d=e!$&'()*+,", "a?b#c", "~-._", "\"<>\\^`{|}"]]

out = {
    "generator": "defence/vectors/gen_vectors.py (reference: verifier.core.view_mac, verifier.canon.canon_path, verifier.jose.thumbprint)",
    "contract": "CONTRACT section 8 + section 10: X-Verified-View: v1;b64url(HMAC-SHA256(key, jti\\nUPPER(method)\\ncanon_path\\njkt)); key = UTF-8 bytes of VIEW_MAC_KEY",
    "canon_path": [{"in": u, "out": vcanon.canon_path(u)} for u in CANON],
    "thumbprint": [{"jwk": j, "jkt": vjose.thumbprint(j)} for j in TP],
    "mac": [{"key": k, "jti": j, "method": m, "uri": u, "jkt": t, "out": vcore.view_mac(k.encode(), j, m, u, t)} for k, j, m, u, t in MACS],
    "substitute": [{"template": t, "params": p, "out": substitute(t, p)} for t, p in SUBST],
    "check": CASES,
}
json.dump(out, sys.stdout, indent=1, ensure_ascii=False)
sys.stdout.write("\n")
