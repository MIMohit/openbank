"""W15 ext-routes: register the v2 base ops and custom primitives into the mutator at runtime.

We do NOT edit binding/harness/mutator/ (owned by W7). Instead we append to the live
BASE_OPS / BASE_OPS_BY_ID dicts and build a primitive list = W7's catalogue + a few targeted
custom primitives. `from mutator.base_ops import BASE_OPS_BY_ID` in runner.run_matrix binds the
same dict object, so appending here is visible to the runner for proof minting.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[3] / "harness"
sys.path.insert(0, str(HARNESS))

import mutator.base_ops as bo          # noqa: E402
from mutator.base_ops import BaseOp     # noqa: E402
from mutator.catalogue import Primitive, load_catalogue  # noqa: E402

ACC_ALICE = "acc-alice-1"
ACC_BOB = "acc-bob-1"

# ─── v2 base ops (A_leak: a leaked valid proof exists for each of these canonical requests) ───
NEW_OPS = [
    # POST sharing the /accounts/{id} path with GET/PUT/DELETE.
    BaseOp("postAccount", "POST", f"/api/v1/accounts/{ACC_ALICE}",
           body=b'{"nickname":"x"}', content_type="application/json",
           tags={"write", "with_id", "account", "v1", "v2route", "shared_post"}),
    # Nested same-method route.
    BaseOp("getStatements", "GET", f"/api/v1/accounts/{ACC_ALICE}/statements",
           tags={"read", "with_id", "account", "nested", "v2route"}),
    # Deeper nested DELETE.
    BaseOp("deleteStatement", "DELETE", f"/api/v1/accounts/{ACC_ALICE}/statements/stmt-1",
           tags={"write", "with_id", "account", "nested", "v2route"}),
    # Catch-all; a two-segment canonical so a leading './' normalises back to the htu.
    BaseOp("catchAllFile", "GET", "/api/v1/files/reports/logo.png",
           tags={"read", "public", "catchall", "v2route", "with_file"}),
]

# ─── custom targeted primitives (nested-route substitution via a kept '#') ───
CUSTOM_PRIMS = [
    Primitive(
        id="x-frag-statements", group="G2", cls="fragment-route-substitution",
        description="Append '#/statements' to a /accounts/{id} target. A proxy that forwards the raw "
                    "'#' and a server that keeps it in the path re-route the request to the nested "
                    "GET /accounts/{id}/statements (id='..#'), while the verifier (RFC 3986) drops the "
                    "fragment and binds the original path.",
        source="RFC 3986 §3.5 fragment; RFC 9449 §4.3 (fragment excluded from htu); extends W9 RC6.",
        transform=[{"fn": "set_fragment", "args": {"value": "/statements"}}],
        applies_to={"op_ids": ["getAccount", "updateAccount", "deleteAccount"]},
    ),
    Primitive(
        id="x-frag-statements-sid", group="G2", cls="fragment-route-substitution",
        description="Append '#/statements/s-evil' to a /accounts/{id} target to reach the deeper nested "
                    "route (e.g. DELETE /accounts/{id}/statements/{sid}) while the verifier binds the path.",
        source="RFC 3986 §3.5 fragment; RFC 9449 §4.3; extends W9 RC6.",
        transform=[{"fn": "set_fragment", "args": {"value": "/statements/s-evil"}}],
        applies_to={"op_ids": ["getAccount", "updateAccount", "deleteAccount"]},
    ),
]


def register():
    """Idempotently append the v2 base ops to the shared mutator dicts."""
    for op in NEW_OPS:
        if op.op_id not in bo.BASE_OPS_BY_ID:
            bo.BASE_OPS.append(op)
            bo.BASE_OPS_BY_ID[op.op_id] = op


def primitives():
    return load_catalogue() + CUSTOM_PRIMS
