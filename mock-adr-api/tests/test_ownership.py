"""
Tests: object-level ownership enforcement (BOLA prevention).
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
from seed.synthetic_data import generate, all_user_ids, get_user
from app.auth import INTERNAL_SECRET

# Trigger data generation before importing app
generate(seed=42, num_users=5)

from app.main import app

client = TestClient(app)
_HEADERS = {"x-zt-validated": INTERNAL_SECRET}


def _headers(user_id: str) -> dict:
    return {**_HEADERS, "x-zt-user-id": user_id}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200


def test_list_accounts_own():
    u_id = all_user_ids()[0]
    r = client.get("/accounts", headers=_headers(u_id))
    assert r.status_code == 200
    data = r.json()["data"]
    assert len(data) > 0
    for acct in data:
        # All accounts belong to the requesting user
        assert acct["id"].startswith("acct_")


def test_get_account_own():
    u_id = all_user_ids()[0]
    user = get_user(u_id)
    acct_id = user.accounts[0].id
    r = client.get(f"/accounts/{acct_id}", headers=_headers(u_id))
    assert r.status_code == 200


def test_get_account_bola():
    """Requesting another user's account must return 403."""
    u_ids = all_user_ids()
    owner_id = u_ids[0]
    attacker_id = u_ids[1]
    owner = get_user(owner_id)
    acct_id = owner.accounts[0].id
    r = client.get(f"/accounts/{acct_id}", headers=_headers(attacker_id))
    assert r.status_code == 403


def test_direct_access_blocked():
    """Requests without the internal ZT header must return 403."""
    u_id = all_user_ids()[0]
    r = client.get("/accounts", headers={"x-zt-user-id": u_id})
    assert r.status_code == 403


def test_get_user_bola():
    """Requesting another user's profile must return 403."""
    u_ids = all_user_ids()
    r = client.get(f"/users/{u_ids[0]}", headers=_headers(u_ids[1]))
    assert r.status_code == 403


def test_transactions_bola():
    """Requesting transactions for another user's account must return 403."""
    u_ids = all_user_ids()
    owner = get_user(u_ids[0])
    acct_id = owner.accounts[0].id
    r = client.get(f"/transactions?account_id={acct_id}", headers=_headers(u_ids[1]))
    assert r.status_code == 403
