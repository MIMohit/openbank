"""End-to-end unit tests for the PDP HTTP service (pdp.server).

Starts the real server (verifier core + path policy) on an ephemeral port, mints a REAL
alice DPoP proof with the harness minter, and drives the three adapters over loopback.
Asserts the combined proof∧policy decision and that the matched rule / view are logged.
Run from binding/harness:  PYTHONPATH=. python -m pytest pdp/tests/test_server.py -q
"""
import json
import os
import threading
import urllib.request
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parents[2]
os.environ.setdefault("AS_PUB_JWK", str(HARNESS / "keys" / "as_pub.jwk"))

from verifier.core import Config
from pdp.server import make_server
from runner.minter_adapter import get_minter

ORIGIN = "http://api.bench.test"


@pytest.fixture(scope="module")
def minter():
    return get_minter(prefer="auto")


def _start(policy="allowlist", normalize="off"):
    cfg = Config.from_env()
    srv = make_server(cfg, port=0, log_path=None, pdp_log_path=None, log_stdout=False,
                      policy_name=policy, normalize=normalize)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def _orig(port, method, uri, authz, dpop):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/authz/orig", method="POST")
    req.add_header("X-Original-Method", method)
    req.add_header("X-Original-URI", uri)
    req.add_header("X-Original-Host", "api.bench.test")
    req.add_header("Authorization", authz)
    req.add_header("DPoP", dpop)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_allow_own_resource(minter):
    srv, port = _start("allowlist")
    try:
        path = "/api/v1/accounts/acc-alice-1"
        authz, dpop, _ = minter.mint("alice", "GET", ORIGIN + path)
        status, body = _orig(port, "GET", path, authz, dpop)
        assert status == 200 and body["decision"] == "allow"
        assert body["rule"] == "allow-v1-own"
    finally:
        srv.shutdown()


def test_policy_denies_admin_even_with_valid_proof(minter):
    """A valid proof for the admin path: the RFC 9449 check passes, the path policy denies."""
    srv, port = _start("allowlist")
    try:
        path = "/api/v1/admin/users"
        authz, dpop, _ = minter.mint("alice", "GET", ORIGIN + path)
        status, body = _orig(port, "GET", path, authz, dpop)
        assert status == 401 and body["decision"] == "deny"
        assert body["reason"].startswith("policy_deny")
    finally:
        srv.shutdown()


def test_dotseg_view_allowed_by_allowlist(minter):
    """The PDP-side half of the authorization-soundness violation: a `/../` path whose proof
    is valid (htu == the raw view) and whose string prefix is alice's own, so the raw-view
    allow-list rule fires. The backend-side routing to bob is measured in the live matrix."""
    srv, port = _start("allowlist", normalize="off")
    try:
        path = "/api/v1/accounts/acc-alice-1/../acc-bob-1"
        authz, dpop, _ = minter.mint("alice", "GET", ORIGIN + path)
        status, body = _orig(port, "GET", path, authz, dpop)
        assert status == 200 and body["decision"] == "allow"
        assert body["rule"] == "allow-v1-own"
    finally:
        srv.shutdown()


def test_normalising_pdp_closes_dotseg(minter):
    """With POLICY_NORMALIZE=rfc3986 the PDP resolves `/../` before matching, so the same
    path now denies (default-deny allow-list) — the documented mitigation."""
    srv, port = _start("allowlist", normalize="rfc3986")
    try:
        path = "/api/v1/accounts/acc-alice-1/../acc-bob-1"
        authz, dpop, _ = minter.mint("alice", "GET", ORIGIN + path)
        status, body = _orig(port, "GET", path, authz, dpop)
        assert status == 401 and body["decision"] == "deny"
    finally:
        srv.shutdown()


def test_invalid_proof_denied(minter):
    """htu mismatch: proof minted for a different path -> RFC 9449 htu check fails -> deny,
    regardless of policy."""
    srv, port = _start("allowlist")
    try:
        authz, dpop, _ = minter.mint("alice", "GET", ORIGIN + "/api/v1/me")
        status, body = _orig(port, "GET", "/api/v1/accounts/acc-alice-1", authz, dpop)
        assert status == 401 and body["decision"] == "deny"
    finally:
        srv.shutdown()
