"""
Unit tests for DPoP proof verification (Stage 2).
Tests: valid proof, jti replay, iat skew, cnf.jkt mismatch, htm/htu mismatch, ath mismatch.
"""
import sys
import time
import uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi import HTTPException

# Patch config before import
import os
os.environ.setdefault("ZT_MODE", "P")
os.environ.setdefault("KEYCLOAK_URL", "http://keycloak:8080")

from client_sim.device import Device
from app.dpop_verify import verify_dpop_proof, _jti_cache

METHOD = "GET"
URL = "http://controller:9000/accounts"
SEED = 1


@pytest.fixture(autouse=True)
def clear_jti_cache():
    _jti_cache.clear()
    yield
    _jti_cache.clear()


def make_device() -> Device:
    return Device(device_id="test_device", seed=SEED)


def test_valid_dpop_proof():
    d = make_device()
    at = "fake_access_token_xyz"
    proof = d.sign_dpop_proof(method=METHOD, url=URL, access_token=at)
    result = verify_dpop_proof(
        dpop_header=proof,
        method=METHOD,
        url=URL,
        raw_access_token=at,
        cnf_jkt=d.jkt,
    )
    assert result["htm"] == METHOD
    assert result["htu"] == URL


def test_jti_replay_rejected():
    d = make_device()
    at = "fake_at"
    jti = str(uuid.uuid4())
    proof1 = d.sign_dpop_proof(method=METHOD, url=URL, access_token=at, override_jti=jti)
    # First use: OK
    verify_dpop_proof(proof1, METHOD, URL, at, d.jkt)
    # Second use (replay): must fail
    proof2 = d.sign_dpop_proof(method=METHOD, url=URL, access_token=at, override_jti=jti)
    with pytest.raises(HTTPException) as exc_info:
        verify_dpop_proof(proof2, METHOD, URL, at, d.jkt)
    assert exc_info.value.status_code == 401
    assert "replay" in exc_info.value.detail.lower()


def test_iat_too_old():
    d = make_device()
    at = "fake_at"
    old_iat = time.time() - 999  # way outside 60s skew
    proof = d.sign_dpop_proof(method=METHOD, url=URL, access_token=at, override_iat=old_iat)
    with pytest.raises(HTTPException) as exc_info:
        verify_dpop_proof(proof, METHOD, URL, at, d.jkt)
    assert exc_info.value.status_code == 401
    assert "skew" in exc_info.value.detail.lower()


def test_cnf_jkt_mismatch():
    d1 = make_device()
    d2 = Device(device_id="other", seed=2)
    at = "fake_at"
    proof = d1.sign_dpop_proof(method=METHOD, url=URL, access_token=at)
    # d2's jkt does not match d1's proof key
    with pytest.raises(HTTPException) as exc_info:
        verify_dpop_proof(proof, METHOD, URL, at, d2.jkt)
    assert exc_info.value.status_code == 401
    assert "jkt" in exc_info.value.detail.lower()


def test_htm_mismatch():
    d = make_device()
    at = "fake_at"
    proof = d.sign_dpop_proof(method="POST", url=URL, access_token=at)
    with pytest.raises(HTTPException) as exc_info:
        verify_dpop_proof(proof, "GET", URL, at, d.jkt)
    assert exc_info.value.status_code == 401
    assert "htm" in exc_info.value.detail.lower()


def test_ath_mismatch():
    d = make_device()
    proof = d.sign_dpop_proof(method=METHOD, url=URL, access_token="real_token")
    # Verify with a different token → ath won't match
    with pytest.raises(HTTPException) as exc_info:
        verify_dpop_proof(proof, METHOD, URL, "different_token", d.jkt)
    assert exc_info.value.status_code == 401
    assert "ath" in exc_info.value.detail.lower()


def test_missing_dpop_header():
    with pytest.raises(HTTPException):
        verify_dpop_proof("", METHOD, URL, "at", "jkt")
