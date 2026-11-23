"""Helpers to build synthetic runner/verifier/executor records for oracle tests."""
from __future__ import annotations

from typing import List, Optional


def runner_rec(case_id, base_op_id, jti, *, base_method="GET",
               base_path="/api/v1/accounts/acc-alice-1", primitive_ids=None,
               client="alice", status=200):
    return {
        "case_id": case_id, "base_op_id": base_op_id, "base_method": base_method,
        "base_path": base_path, "primitive_ids": primitive_ids or [], "client": client,
        "jti": jti, "status": status,
    }


def verifier_rec(jti, *, adapter="orig", decision="allow", reason="ok",
                 view_method="GET", view_uri="http://api.bench.test/api/v1/accounts/acc-alice-1",
                 sub="alice", jkt="jkt-alice"):
    return {
        "jti": jti, "adapter": adapter, "view_method": view_method, "view_uri": view_uri,
        "decision": decision, "reason": reason, "sub": sub, "jkt": jkt,
    }


def executor_rec(jti, op_id, *, route_template=None, raw_method="GET",
                 effective_method="GET", raw_target="/api/v1/accounts/acc-alice-1",
                 path_params=None, query="", trust_headers=None, denied=False, status=200,
                 framework="fastapi"):
    return {
        "ts": "2026-01-01T00:00:00Z", "framework": framework, "jti": jti, "op_id": op_id,
        "route_template": route_template, "raw_method": raw_method,
        "effective_method": effective_method, "raw_target": raw_target,
        "path_params": path_params or {}, "query": query,
        "trust_headers": trust_headers or {}, "denied": denied, "status": status,
    }


def ground_truth_rec(base_op_id, op_id, *, base_method="GET",
                     base_path="/api/v1/accounts/acc-alice-1", path_params=None, status=200):
    return {
        "base_op_id": base_op_id, "base_method": base_method, "base_path": base_path,
        "op_id": op_id, "path_params": path_params or {}, "status": status,
    }


def topo(**kw):
    base = {"id": "envoy-default-edge-fastapi-ovoff", "gateway": "envoy",
            "profile": "default", "placement": "edge", "framework": "fastapi",
            "override": "off", "verifier": {"canon": "rfc3986", "view_mac": "off"}}
    base.update(kw)
    return base
