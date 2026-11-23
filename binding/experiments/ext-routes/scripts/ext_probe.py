"""Targeted probes for the ext-routes G2 differentials, against a LIVE topology.
Adapted from W9 kill/scripts/probe_fragment.py; registers the v2 base ops.

    cd binding/harness && orchestrator/.venv/bin/python \
        ../experiments/ext-routes/scripts/ext_probe.py <topology-id>

Two questions:
  (1) fragment nested-route substitution: can a proof for a /accounts/{id} op be steered to
      the nested statements route, and can it cross owners?
  (2) catch-all {path:path}: can a dot-segment / encoded-slash differential (verifier removes
      dot segments per RFC 3986 §5.2.4; router keeps them) reach a DIFFERENT op or escape /files?

Writes experiments/ext-routes/ddmin/probe__<id>.jsonl.
"""
import json
import os
import sys
import time

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
K = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
sys.path.insert(0, SCRIPTS)
import ext_base  # noqa: E402
ext_base.register()
from mutator.base_ops import BASE_OPS_BY_ID, AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER  # noqa: E402
from rawhttp.client import send  # noqa: E402
from runner.minter_adapter import get_minter  # noqa: E402

PROBES = [
    # (1) fragment nested-route substitution
    ("getAccount", "/api/v1/accounts/acc-alice-1#frag"),                          # control: RC6 suffix
    ("getAccount", "/api/v1/accounts/acc-alice-1#/statements"),                   # -> getStatements?
    ("deleteAccount", "/api/v1/accounts/acc-alice-1#/statements/s-evil"),         # -> deleteStatement?
    ("getAccount", "/api/v1/accounts/acc-bob-1#/statements"),                     # cross-owner attempt (proof is alice's acc)
    ("getAccount", "/api/v1/accounts/acc-alice-1#/../acc-bob-1/statements"),      # owner via fragment dot-seg
    # (2) catch-all {path:path} dot-segment / encoded-slash escape
    ("catchAllFile", "/api/v1/files/reports/logo.png"),                           # control canonical
    ("catchAllFile", "/api/v1/files/reports/./logo.png"),                         # dot-seg kept
    ("catchAllFile", "/api/v1/files/../accounts/acc-bob-1"),                      # escape /files to another route?
    ("catchAllFile", "/api/v1/files/..%2f..%2faccounts%2facc-bob-1"),            # encoded escape
    ("catchAllFile", "/api/v1/files/reports/..%2f..%2f..%2fadmin%2fusers"),       # reach admin?
    ("catchAllFile", "/api/v1/files/%2e%2e/accounts/acc-bob-1"),                  # encoded-dot escape
]


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def main():
    tid = sys.argv[1]
    yml = os.path.join(K, "topologies", f"{tid}.yaml")
    import yaml
    port = int(yaml.safe_load(open(yml))["host_port"])
    logs = os.path.join(HARNESS, "logs", tid)
    m = get_minter(prefer="w3")
    os.makedirs(os.path.join(K, "ddmin"), exist_ok=True)
    out = open(os.path.join(K, "ddmin", f"probe__{tid}.jsonl"), "w")
    print(f"# probes against {tid} (port {port})")
    for base, target in PROBES:
        op = BASE_OPS_BY_ID[base]
        req = op.canonical_request()
        req.target = target
        authz, proof, jti = m.mint(client="alice", htm=op.htm, htu=op.htu)
        raw = req.to_bytes().replace(AUTHZ_PLACEHOLDER.encode(), authz.encode()).replace(PROOF_PLACEHOLDER.encode(), proof.encode())
        r = send("127.0.0.1", port, raw, timeout=10)
        time.sleep(0.3)
        v = next((x for x in jl(os.path.join(logs, "verifier.jsonl")) if x.get("jti") == jti), {})
        e = next((x for x in jl(os.path.join(logs, "executor.jsonl")) if x.get("jti") == jti), {})
        rec = {"base_op": base, "target": target, "status": r.status, "verifier": v.get("decision"),
               "view_uri": v.get("view_uri"), "exec_op": e.get("op_id"),
               "route_template": e.get("route_template"), "path_params": e.get("path_params")}
        out.write(json.dumps(rec) + "\n")
        print(f'{base:13} {target:52.52} {r.status} V={str(rec["verifier"]):5} X={rec["exec_op"]} {rec["route_template"]} {rec["path_params"]}')


if __name__ == "__main__":
    main()
