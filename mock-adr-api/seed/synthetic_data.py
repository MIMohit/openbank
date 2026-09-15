"""
Synthetic data generator for the mock ADR API.
Deterministic — always produces the same dataset for a given seed.
No real PII, no real bank data.
"""
from __future__ import annotations

import os
import random
import uuid
from dataclasses import dataclass, field
from typing import List, Dict


SEED = int(os.getenv("MOCK_ADR_SEED", "42"))
NUM_USERS = int(os.getenv("MOCK_ADR_NUM_USERS", "100"))
ACCOUNTS_PER_USER = 3
TRANSACTIONS_PER_ACCOUNT = 200


@dataclass
class Transaction:
    id: str
    account_id: str
    owner_user_id: str
    amount: float
    currency: str
    description: str
    date: str
    type: str  # debit | credit


@dataclass
class Account:
    id: str
    owner_user_id: str
    bsb: str
    account_number: str
    account_name: str
    balance: float
    currency: str
    type: str  # transaction | savings
    transactions: List[Transaction] = field(default_factory=list)


@dataclass
class Connection:
    id: str
    user_id: str
    institution: str
    status: str  # active | inactive


@dataclass
class User:
    id: str
    name: str
    email: str
    accounts: List[Account] = field(default_factory=list)
    connections: List[Connection] = field(default_factory=list)


@dataclass
class Consent:
    id: str
    user_id: str
    client_id: str
    scopes: List[str]
    accounts: List[str]  # account IDs covered
    status: str  # active | revoked
    expires_at: str


_DB: Dict[str, object] = {}
_USERS: Dict[str, User] = {}
_ACCOUNTS: Dict[str, Account] = {}
_TRANSACTIONS: Dict[str, Transaction] = {}
_CONSENTS: Dict[str, Consent] = {}


def _stable_id(prefix: str, *parts) -> str:
    """Create a deterministic UUID from parts."""
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    return f"{prefix}_{uuid.uuid5(ns, '_'.join(str(p) for p in parts))}"


def generate(seed: int = SEED, num_users: int = NUM_USERS) -> None:
    """Generate and store synthetic data in module-level dicts."""
    global _USERS, _ACCOUNTS, _TRANSACTIONS, _CONSENTS
    rng = random.Random(seed)

    institution_names = ["MockBank", "SynthBank", "TestCredit", "FakeFinance"]
    account_types = ["transaction", "savings"]
    tx_types = ["debit", "credit"]
    descriptions = [
        "Grocery shopping", "Salary deposit", "Rent payment", "Utility bill",
        "Online purchase", "ATM withdrawal", "Transfer", "Insurance premium",
        "Subscription fee", "Tax payment",
    ]

    for u_idx in range(num_users):
        user_id = _stable_id("u", seed, u_idx)
        user = User(
            id=user_id,
            name=f"User_{u_idx:04d}",
            email=f"user{u_idx:04d}@synthetic.local",
        )

        # Add connection
        conn = Connection(
            id=_stable_id("conn", seed, u_idx),
            user_id=user_id,
            institution=rng.choice(institution_names),
            status="active",
        )
        user.connections.append(conn)

        # Add accounts
        for a_idx in range(ACCOUNTS_PER_USER):
            acct_id = _stable_id("acct", seed, u_idx, a_idx)
            acct = Account(
                id=acct_id,
                owner_user_id=user_id,
                bsb=f"{rng.randint(100,999)}-{rng.randint(100,999)}",
                account_number=f"{rng.randint(10000000,99999999)}",
                account_name=f"Account_{u_idx:04d}_{a_idx}",
                balance=round(rng.uniform(0, 50000), 2),
                currency="AUD",
                type=account_types[a_idx % 2],
            )

            # Add transactions
            for t_idx in range(TRANSACTIONS_PER_ACCOUNT):
                tx = Transaction(
                    id=_stable_id("tx", seed, u_idx, a_idx, t_idx),
                    account_id=acct_id,
                    owner_user_id=user_id,
                    amount=round(rng.uniform(0.01, 5000), 2),
                    currency="AUD",
                    description=rng.choice(descriptions),
                    date=f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
                    type=rng.choice(tx_types),
                )
                acct.transactions.append(tx)
                _TRANSACTIONS[tx.id] = tx

            user.accounts.append(acct)
            _ACCOUNTS[acct_id] = acct

        # Add a default consent for self
        consent = Consent(
            id=_stable_id("consent", seed, u_idx),
            user_id=user_id,
            client_id="zt-client",
            scopes=["accounts:read", "transactions:read"],
            accounts=[a.id for a in user.accounts],
            status="active",
            expires_at="2030-01-01T00:00:00Z",
        )
        _CONSENTS[consent.id] = consent

        _USERS[user_id] = user

    # Generate one extra cross-user consent for BFLA/BOLA testing
    if num_users >= 2:
        u_ids = list(_USERS.keys())
        bola_consent = Consent(
            id=_stable_id("consent_bola", seed),
            user_id=u_ids[0],
            client_id="zt-client",
            scopes=["accounts:read"],
            accounts=[_USERS[u_ids[0]].accounts[0].id],  # only own first account
            status="active",
            expires_at="2030-01-01T00:00:00Z",
        )
        _CONSENTS[bola_consent.id] = bola_consent


def get_users() -> Dict[str, User]:
    return _USERS


def get_accounts() -> Dict[str, Account]:
    return _ACCOUNTS


def get_transactions() -> Dict[str, Transaction]:
    return _TRANSACTIONS


def get_consents() -> Dict[str, Consent]:
    return _CONSENTS


def get_user(user_id: str) -> User | None:
    return _USERS.get(user_id)


def get_account(account_id: str) -> Account | None:
    return _ACCOUNTS.get(account_id)


def get_transaction(tx_id: str) -> Transaction | None:
    return _TRANSACTIONS.get(tx_id)


def get_consent_for_user(user_id: str) -> List[Consent]:
    return [c for c in _CONSENTS.values() if c.user_id == user_id]


def all_user_ids() -> List[str]:
    return list(_USERS.keys())
