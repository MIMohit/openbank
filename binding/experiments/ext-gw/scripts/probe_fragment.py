"""Targeted probes: can the '#' differential (RC6) reach a different op or a chosen resource?
Run against a LIVE topology (e.g. w9-nginx-default-edge-fastapi-ovoff):

    cd binding/harness && orchestrator/.venv/bin/python ../experiments/kill/scripts/probe_fragment.py <topology-id>

Each probe: proof minted for the base op's canonical (htm, htu); the raw target is replaced.
Writes experiments/kill/ddmin/probe_fragment__<id>.jsonl.
"""
import json, os, sys, time

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
K = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, HARNESS)
from mutator.base_ops import BASE_OPS_BY_ID, AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER  # noqa: E402
from rawhttp.client import send  # noqa: E402
from runner.minter_adapter import get_minter  # noqa: E402

PROBES = [
    ("getAccount", "/api/v1/accounts/acc-alice-1#frag"),                      # control (RC6)
    ("getAccount", "/api/v1/accounts/acc-alice-1#/../../admin/users"),
    ("getAccount", "/api/v1/accounts/acc-alice-1#/actions"),
    ("getAccount", "/api/v1/accounts/acc-alice-1#%2F..%2Facc-bob-1"),
    ("listAccounts", "/api/v1/accounts#/acc-bob-1"),
    ("publicFile", "/api/v1/public/logo.png#/../../accounts/acc-bob-1"),
    ("adminListUsers", "/api/v1/admin/users#/u-1"),
    ("deleteAccount", "/api/v1/accounts/acc-alice-1#/../acc-bob-1"),
    ("getAccountV2", "/api/v2/accounts/acc-alice-1#frag"),
]


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def main():
    tid = sys.argv[1]
    yml = os.path.join(K, "topologies", f"{tid}.yaml")
    port = int(next(l.split(":")[1] for l in open(yml) if l.startswith("host_port")))
    logs = os.path.join(HARNESS, "logs", tid)
    m = get_minter(prefer="w3")
    out = open(os.path.join(K, "ddmin", f"probe_fragment__{tid}.jsonl"), "w")
    for base, target in PROBES:
        op = BASE_OPS_BY_ID[base]
        req = op.canonical_request(); req.target = target
        authz, proof, jti = m.mint(client="alice", htm=op.htm, htu=op.htu)
        raw = req.to_bytes().replace(AUTHZ_PLACEHOLDER.encode(), authz.encode()).replace(PROOF_PLACEHOLDER.encode(), proof.encode())
        r = send("127.0.0.1", port, raw, timeout=10); time.sleep(0.3)
        v = next((x for x in jl(os.path.join(logs, "verifier.jsonl")) if x.get("jti") == jti), {})
        e = next((x for x in jl(os.path.join(logs, "executor.jsonl")) if x.get("jti") == jti), {})
        rec = {"base_op": base, "target": target, "status": r.status, "verifier": v.get("decision"),
               "view_uri": v.get("view_uri"), "exec_op": e.get("op_id"), "path_params": e.get("path_params"),
               "resp_body": r.body[:200].decode("utf-8", "replace")}
        out.write(json.dumps(rec) + "\n")
        print(f'{base:15} {target:55} {r.status} V={rec["verifier"]} X={rec["exec_op"]} {rec["path_params"]}')


if __name__ == "__main__":
    main()
