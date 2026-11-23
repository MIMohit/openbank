"""ddmin a hit's request delta against a LIVE topology (it must already be up).

    cd binding/harness && orchestrator/.venv/bin/python ../experiments/kill/scripts/ddmin_hit.py \
        <topology-id> <case-id> [<case-id> ...]

Depth-1 cases carry one primitive, so primitive-level ddmin is trivial. This minimises the
request *delta* relative to the canonical base request, with oracle.minimise.ddmin over units:
  - each character of the differing middle of the request target (after common prefix/suffix),
  - each header line that the mutation added or changed,
  - each character of the differing middle of the body (Content-Length recomputed),
  - the request method, if changed (one unit).
test(units) = rebuild canonical + kept units, mint a fresh proof for the base op, send raw,
read harness/logs/<id>/{verifier,executor}.jsonl by jti; True iff verifier allow and the
executor ran the SAME (op_id, path_params) as the original hit with status < 400.
Writes experiments/kill/ddmin/<id>__<case>.json.
"""
import base64, json, os, sys, time

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
K = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, HARNESS)
from mutator import compose  # noqa: E402
from mutator.base_ops import BASE_OPS_BY_ID, AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER  # noqa: E402
from rawhttp.model import RawRequest  # noqa: E402
from rawhttp.client import send  # noqa: E402
from runner.minter_adapter import get_minter  # noqa: E402
from oracle.minimise import ddmin  # noqa: E402

MINTER = get_minter(prefer="w3")


def mid(a, b):
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    j = 0
    while j < min(len(a), len(b)) - i and a[-1 - j] == b[-1 - j]:
        j += 1
    return i, j  # common prefix len, common suffix len


def build(canon, mut, units):
    r = canon.copy()
    keep = set(units)
    # method
    if ("m",) in keep:
        r.method = mut.method
    # target: canonical prefix + kept chars of mutated middle + canonical suffix
    p, s = mid(canon.target, mut.target)
    mmid = mut.target[p:len(mut.target) - s]
    r.target = canon.target[:p] + "".join(ch for k, ch in enumerate(mmid) if ("t", k) in keep) + canon.target[len(canon.target) - s:]
    # headers: canonical, then replace/add kept mutated header lines
    hs = list(canon.headers)
    for k, (n, v) in enumerate(mut.headers):
        if ("h", k) in keep:
            idx = next((i for i, (cn, _) in enumerate(hs) if cn == n and (cn, _) not in mut.headers), None)
            if idx is not None:
                hs[idx] = (n, v)
            else:
                hs.append((n, v))
    r.headers = hs
    pb, sb = mid(canon.body, mut.body)
    bmid = mut.body[pb:len(mut.body) - sb]
    r.body = canon.body[:pb] + bytes(b for k, b in enumerate(bmid) if ("b", k) in keep) + canon.body[len(canon.body) - sb:]
    if any(n.lower() == "content-length" for n, _ in r.headers):
        r.headers = [(n, str(len(r.body)) if n.lower() == "content-length" else v) for n, v in r.headers]
    return r


def units_of(canon, mut):
    u = []
    if mut.method != canon.method:
        u.append(("m",))
    p, s = mid(canon.target, mut.target)
    u += [("t", k) for k in range(len(mut.target) - p - s)]
    u += [("h", k) for k, h in enumerate(mut.headers) if h not in canon.headers and h[0] != "Content-Length"]
    pb, sb = mid(canon.body, mut.body)
    u += [("b", k) for k in range(len(mut.body) - pb - sb)]
    return u


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def main():
    tid, case_ids = sys.argv[1], sys.argv[2:]
    yml = os.path.join(K, "topologies", f"{tid}.yaml")
    port = int(next(l.split(":")[1] for l in open(yml) if l.startswith("host_port")))
    logs = os.path.join(HARNESS, "logs", tid)
    hits = {h["case_id"]: h for h in jl(os.path.join(K, "runs", tid, "hits.jsonl"))}
    cases = {c.case_id: c for c in compose.generate(depth=1)}
    os.makedirs(os.path.join(K, "ddmin"), exist_ok=True)
    for cid in case_ids:
        h = hits[cid]; c = cases[cid]
        op = BASE_OPS_BY_ID[c.base_op_id]
        canon = op.canonical_request()
        mut = RawRequest.from_b64(json.loads(c.to_json())["raw_request_b64"])
        trials = []

        def test(units):
            req = build(canon, mut, units)
            authz, proof, jti = MINTER.mint(client="alice", htm=op.htm, htu=op.htu)
            raw = req.to_bytes().replace(AUTHZ_PLACEHOLDER.encode(), authz.encode()).replace(PROOF_PLACEHOLDER.encode(), proof.encode())
            resp = send("127.0.0.1", port, raw, timeout=10)
            time.sleep(0.3)
            v = [x for x in jl(os.path.join(logs, "verifier.jsonl")) if x.get("jti") == jti]
            e = [x for x in jl(os.path.join(logs, "executor.jsonl")) if x.get("jti") == jti]
            ok = any(x["decision"] == "allow" for x in v) and any(
                x["op_id"] == h["exec_op_id"] and (x.get("path_params") or {}) == h["exec_path_params"]
                and (x.get("status") or 999) < 400 for x in e)
            trials.append({"n_units": len(units), "status": resp.status, "hit": ok})
            return ok

        full = units_of(canon, mut)
        minimal = ddmin(full, test)
        mreq = build(canon, mut, minimal)
        out = {"topology": tid, "case_id": cid, "primitive_ids": h["primitive_ids"],
               "exec_op_id": h["exec_op_id"], "exec_path_params": h["exec_path_params"],
               "full_units": len(full), "minimal_units": len(minimal), "still_hit": test(minimal),
               "canonical_request": canon.to_bytes().decode("latin-1"),
               "minimal_request": mreq.to_bytes().decode("latin-1"), "trials": trials}
        p = os.path.join(K, "ddmin", f"{tid}__{cid.replace(':', '_')}.json")
        json.dump(out, open(p, "w"), indent=1)
        print(f"{cid}: {len(full)} -> {len(minimal)} units, still_hit={out['still_hit']}")
        print("  " + mreq.to_bytes().decode("latin-1").split("\r\n")[0])


if __name__ == "__main__":
    main()
