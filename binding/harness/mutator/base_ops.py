"""Canonical bench-API operations (CONTRACT §3) as byte-exact base requests.

Each base op is the *legitimate* request a client would make, for which a valid DPoP
proof exists (the A_leak model, CONTRACT §6). The mutator transforms these; the runner
mints a proof bound to the base op's canonical (htm, htu) and injects it.

Auth headers are present as placeholders so that (a) header-oriented mutations can see a
realistic request and (b) the runner can swap in a fresh token/proof per case without
re-parsing. Placeholders: AT_PLACEHOLDER and PROOF_PLACEHOLDER.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from rawhttp.model import RawRequest

PUBLIC_ORIGIN = "http://api.bench.test"
HOST = "api.bench.test"

# The runner replaces these placeholders with a freshly minted Authorization header value
# ("DPoP <access-token>") and DPoP proof. AUTHZ_PLACEHOLDER is the FULL header value.
AUTHZ_PLACEHOLDER = "@@AUTHZ@@"
PROOF_PLACEHOLDER = "@@PROOF@@"

# Owners (CONTRACT §2): alice owns acc-alice-1, bob owns acc-bob-1.
ACC_ALICE = "acc-alice-1"
ACC_BOB = "acc-bob-1"
ADMIN_USER = "u-1"


@dataclass
class BaseOp:
    op_id: str
    method: str          # canonical (effective) method
    path: str            # canonical path WITHOUT query (this is the htu path)
    query: str = ""      # canonical query string (no leading '?')
    body: bytes = b""
    content_type: Optional[str] = None
    client: str = "alice"
    tags: Set[str] = field(default_factory=set)

    @property
    def htu(self) -> str:
        return PUBLIC_ORIGIN + self.path

    @property
    def htm(self) -> str:
        return self.method

    @property
    def target(self) -> str:
        return self.path + (("?" + self.query) if self.query else "")

    def canonical_request(self) -> RawRequest:
        """Build the byte-exact canonical request with auth placeholders."""
        headers = [
            ("Host", HOST),
            ("Authorization", AUTHZ_PLACEHOLDER),
            ("DPoP", PROOF_PLACEHOLDER),
            ("Accept", "application/json"),
            ("User-Agent", "bind-harness/1.0"),
        ]
        body = self.body or b""
        if self.content_type is not None:
            headers.append(("Content-Type", self.content_type))
        if body:
            headers.append(("Content-Length", str(len(body))))
        headers.append(("Connection", "close"))
        return RawRequest(method=self.method, target=self.target, version="HTTP/1.1",
                          headers=headers, body=body)


def _json_body(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


GRAPHQL_BODY = _json_body({
    "operationName": "getProfile",
    "query": "query getProfile { profile { id email } }",
    "variables": {},
})

BASE_OPS: List[BaseOp] = [
    BaseOp("listAccounts", "GET", "/api/v1/accounts",
           tags={"read", "collection"}),
    BaseOp("getAccount", "GET", f"/api/v1/accounts/{ACC_ALICE}",
           tags={"read", "with_id", "account", "v1"}),
    BaseOp("updateAccount", "PUT", f"/api/v1/accounts/{ACC_ALICE}",
           body=_json_body({"nickname": "primary"}),
           content_type="application/json",
           tags={"write", "with_id", "account", "with_body", "v1"}),
    BaseOp("deleteAccount", "DELETE", f"/api/v1/accounts/{ACC_ALICE}",
           tags={"write", "with_id", "account", "v1"}),
    BaseOp("accountAction.freeze", "POST", f"/api/v1/accounts/{ACC_ALICE}/actions",
           query="op=freeze", body=_json_body({"reason": "user-request"}),
           content_type="application/json",
           tags={"write", "with_id", "action", "has_query", "with_body"}),
    BaseOp("createTransfer", "POST", "/api/v1/transfers",
           body=_json_body({"from": ACC_ALICE, "to": ACC_BOB, "amount": 1}),
           content_type="application/json",
           tags={"write", "with_body", "transfer"}),
    BaseOp("graphql.getProfile", "POST", "/api/v1/graphql",
           body=GRAPHQL_BODY, content_type="application/json",
           tags={"write", "graphql", "with_body"}),
    BaseOp("me", "GET", "/api/v1/me", tags={"read"}),
    BaseOp("adminListUsers", "GET", "/api/v1/admin/users",
           tags={"read", "admin", "collection"}),
    BaseOp("adminDeleteUser", "DELETE", f"/api/v1/admin/users/{ADMIN_USER}",
           tags={"write", "with_id", "admin"}),
    BaseOp("health", "GET", "/api/v1/health", tags={"read", "public"}),
    BaseOp("publicFile", "GET", "/api/v1/public/logo.png",
           tags={"read", "public", "with_file"}),
    BaseOp("getAccountV2", "GET", f"/api/v2/accounts/{ACC_ALICE}",
           tags={"read", "with_id", "account", "v2"}),
]

BASE_OPS_BY_ID: Dict[str, BaseOp] = {op.op_id: op for op in BASE_OPS}
