"""
Unit tests for the Device simulator: key generation, JKT computation, DPoP proof signing.
"""
import sys
import hashlib
import json
import base64
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from client_sim.device import Device, _b64url


def _parse_dpop(proof: str) -> tuple[dict, dict]:
    parts = proof.split(".")
    def b64decode(s):
        s += "=="
        return json.loads(base64.urlsafe_b64decode(s))
    return b64decode(parts[0]), b64decode(parts[1])


def test_device_creates_keypair():
    d = Device()
    assert d.jkt
    assert len(d.jkt) > 10
    assert d.device_fp


def test_deterministic_key_with_seed():
    d1 = Device(seed=99)
    d2 = Device(seed=99)
    assert d1.jkt == d2.jkt


def test_different_seeds_give_different_keys():
    d1 = Device(seed=1)
    d2 = Device(seed=2)
    assert d1.jkt != d2.jkt


def test_dpop_proof_structure():
    d = Device()
    proof = d.sign_dpop_proof("GET", "http://host/path", access_token="at123")
    hdr, payload = _parse_dpop(proof)
    assert hdr["typ"] == "dpop+jwt"
    assert hdr["alg"] == "ES256"
    assert "jwk" in hdr
    assert payload["htm"] == "GET"
    assert payload["htu"] == "http://host/path"
    assert "jti" in payload
    assert "iat" in payload
    assert "ath" in payload


def test_dpop_ath_correct():
    d = Device()
    at = "some_access_token"
    proof = d.sign_dpop_proof("GET", "http://h/p", access_token=at)
    _, payload = _parse_dpop(proof)
    expected_ath = _b64url(hashlib.sha256(at.encode()).digest())
    assert payload["ath"] == expected_ath


def test_jkt_thumbprint_matches_jwk():
    d = Device()
    jwk = d.jwk_public
    # Manual thumbprint
    required = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    expected = _b64url(hashlib.sha256(canonical).digest())
    assert d.jkt == expected


def test_unique_jti_per_proof():
    d = Device()
    jtis = set()
    for _ in range(10):
        proof = d.sign_dpop_proof("GET", "http://h/p", access_token="at")
        _, payload = _parse_dpop(proof)
        jtis.add(payload["jti"])
    assert len(jtis) == 10


def test_no_private_key_in_proof():
    d = Device()
    proof = d.sign_dpop_proof("GET", "http://h/p")
    hdr, _ = _parse_dpop(proof)
    jwk = hdr["jwk"]
    assert "d" not in jwk, "Private key must not appear in DPoP proof"
