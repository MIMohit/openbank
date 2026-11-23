"""W23: unit tests for the D-A/D-B public<->internal path map and the catch-all / %2F encoder seams.

The verifier side (the proof htu for D-A, X-Verified-View for D-B) is always in public-path space.
These tests assert the executor-side recomputed path, after mapping its internal routed view to
public space, equals what the verifier MAC'd/checked. A request is ACCEPTED iff the two match.
"""
import hashlib
import hmac
import json

import viewmac as vm

KEY = b"bh-test-view-mac-key"

# Rewrite rules mirroring the FRR scenarios (one rewrite per deployment).
STRIP = [("/svc/api", "/api")]          # S1 strip-prefix: public /svc/api -> internal /api
VERS = [("/api/latest", "/api/v1")]     # S2 version rewrite: public /api/latest -> internal /api/v1


def _verifier_view_mac(public_path, jti="j1", method="GET", jkt="k1", key=KEY):
    """What the edge verifier emits: MAC over canon(PUBLIC path)."""
    return vm.mac(key, jti, method, public_path, jkt)


def _dpop_for(jti, jkt):
    # minimal real proof whose header jwk thumbprints to `jkt` is overkill here; the check reads
    # jti/jkt from the proof, so build one with a known EC jwk and use its real thumbprint.
    hdr = {"typ": "dpop+jwt", "alg": "ES256",
           "jwk": {"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                   "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}
    claims = {"jti": jti, "htm": "GET", "htu": "http://api.bench.test/x", "iat": 0}

    def b64(d):
        import base64
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return b64(hdr) + "." + b64(claims) + ".sig", vm.thumbprint(hdr["jwk"])


def _run(public_path, template, params, rules, wildcards=frozenset(), method="GET"):
    dpop, jkt = _dpop_for("j1", None)
    jkt = vm.thumbprint({"kty": "EC", "crv": "P-256",
                         "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                         "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"})
    view = _verifier_view_mac(public_path, jti="j1", method=method, jkt=jkt)
    return vm.check(KEY, [view], [dpop], method, template, params, pathmap=rules, wildcards=wildcards)


# --------------------------------------------------------- path map closes the rewrite false reject
def test_strip_prefix_accepts():
    # client sent /svc/api/v1/accounts/acc-alice-1 (public); gateway stripped to /api/...; executor
    # matched /api/v1/accounts/{id}. With the map it reconstructs the public path and the MAC matches.
    r = _run("/svc/api/v1/accounts/acc-alice-1", "/api/v1/accounts/{id}", {"id": "acc-alice-1"}, STRIP)
    assert r.ok, r.reason


def test_version_rewrite_accepts():
    r = _run("/api/latest/accounts/acc-alice-1", "/api/v1/accounts/{id}", {"id": "acc-alice-1"}, VERS)
    assert r.ok, r.reason


def test_no_map_rewrite_still_rejects():
    # same strip-prefix traffic but with an EMPTY map -> internal != public -> mismatch (the status quo).
    r = _run("/svc/api/v1/accounts/acc-alice-1", "/api/v1/accounts/{id}", {"id": "acc-alice-1"}, [])
    assert not r.ok and r.reason == "view_mac_mismatch"


# --------------------------------------------------------- catch-all seam (multi-segment wildcard)
def test_catchall_wildcard_accepts():
    # verifier sees /api/v1/files/reports/logo.png (literal slashes). executor matched
    # /api/v1/files/{path} with path="reports/logo.png": wildcard keeps '/' literal -> matches.
    r = _run("/api/v1/files/reports/logo.png", "/api/v1/files/{path}",
             {"path": "reports/logo.png"}, [], wildcards=frozenset({"path"}))
    assert r.ok, r.reason


def test_catchall_without_wildcard_flag_rejects():
    # the pre-W23 behaviour: '/' escaped to %2F inside the single param -> mismatch.
    r = _run("/api/v1/files/reports/logo.png", "/api/v1/files/{path}",
             {"path": "reports/logo.png"}, [], wildcards=frozenset())
    assert not r.ok and r.reason == "view_mac_mismatch"


def test_catchall_dot_segment_rejected_per_segment():
    r = _run("/api/v1/files/reports/../x", "/api/v1/files/{path}",
             {"path": "reports/../x"}, [], wildcards=frozenset({"path"}))
    assert not r.ok and r.reason == "view_param_dot_segment"


# --------------------------------------------------------- %2F-in-id seam
def test_encoded_slash_in_id_matches_verifier():
    # verifier keeps %2F literal in the public path. A route value that still holds the literal
    # "%2F" (Kestrel) must not be double-encoded to %252F.
    r = _run("/api/v1/accounts/acc%2Fx", "/api/v1/accounts/{id}", {"id": "acc%2Fx"}, [])
    assert r.ok, r.reason


def test_decoded_slash_in_id_matches_verifier():
    # a value that was decoded to '/' (Express) encodes to %2F -> matches the verifier's %2F.
    r = _run("/api/v1/accounts/acc%2Fx", "/api/v1/accounts/{id}", {"id": "acc/x"}, [])
    assert r.ok, r.reason


# --------------------------------------------------------- helpers in isolation
def test_to_public_identity_and_longest_match():
    rules = vm.load_rules  # not called; inline pairs
    pairs = sorted([("/svc/api", "/api"), ("/svc/api/v1", "/api/v1")], key=lambda p: len(p[1]), reverse=True)
    assert vm.to_public("/api/v1/accounts/x", pairs) == "/svc/api/v1/accounts/x"  # longest internal wins
    assert vm.to_public("/other/x", pairs) == "/other/x"  # no rule -> identity


def test_pct25_collapse_only_on_double_encoding():
    assert vm._encode_value("acc%2Fx") == "acc%2Fx"       # literal %2F preserved, not %252F
    assert vm._encode_value("a/b") == "a%2Fb"             # real slash in a non-wildcard id -> %2F
    assert vm._encode_value("a/b", wildcard=True) == "a/b"  # wildcard keeps the slash
    assert vm._encode_value("100%") == "100%25"           # lone percent still encodes
