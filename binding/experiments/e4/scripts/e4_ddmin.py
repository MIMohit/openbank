"""e4_ddmin.py — ddmin-minimise an E4 authorization-soundness hit against a LIVE topology.

Each E4 vector carries a single parsing primitive, so primitive-level ddmin is trivial. This
minimises the request *delta* that turns a correctly-DENIED forbidden request into an
ALLOWED-but-forbidden one: the canonical reference is the matching ``direct-*`` control (the
plain forbidden request, e.g. ``GET /api/v1/accounts/acc-bob-1`` or ``/api/v1/admin/users``,
which the PDP denies), and the mutated request is the hit vector. ddmin (oracle.minimise.ddmin)
runs over:
  * each char of the differing middle of the request target (common prefix/suffix removed),
  * the request method, if the vector changed it,
  * each header line the vector added.
test(units) = rebuild canonical+kept units, mint a FRESH alice proof bound to the rebuilt htu
(so the DPoP check always passes — this is the A_client threat), send the exact bytes raw, read
harness/logs/<id>/{verifier,executor}.jsonl by jti; True iff the verifier/PDP ALLOWED (decision
allow, sub alice) AND the executor ran the SAME forbidden (op_id, path_params) with status<400.
Writes experiments/e4/ddmin/<id>__<vector>.json.

    cd binding/harness && orchestrator/.venv/bin/python \
        ../experiments/e4/scripts/e4_ddmin.py <topology-id> <vector_id>[:<canonical_vector>] ...
The topology must already be up (host_port from its YAML).  Run from binding/harness.
"""
from __future__ import annotations
import base64, json, os, sys, time
from pathlib import Path

HARNESS = str(Path(__file__).resolve().parents[3] / "harness")
E4 = Path(__file__).resolve().parents[1]
sys.path.insert(0, HARNESS)
sys.path.insert(0, str(E4 / "scripts"))

import yaml
from rawhttp.client import send as raw_send
from mutator.base_ops import AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER
from runner.minter_adapter import get_minter
from oracle.minimise import ddmin
from e4_oracle import forbidden_reason

MINTER = get_minter(prefer="auto")
ORIGIN = "http://api.bench.test"

# default canonical control (plain forbidden request) for each hit vector
DEFAULT_CANON = {
    "bob": "direct-bob-get",       # GET /api/v1/accounts/acc-bob-1
    "admin-list": "direct-admin-list",
    "admin-del": "direct-admin-del",
    "bob-getv2": "direct-bob-getv2",
}


def load_cases():
    return {json.loads(l)["vector_id"]: json.loads(l)
            for l in open(E4 / "cases.jsonl") if l.strip()}


def raw_of(case):
    return base64.b64decode(case["raw_request_b64"])


def target_of(raw: bytes) -> str:
    return raw.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin-1")


def method_of(raw: bytes) -> str:
    return raw.split(b" ", 1)[0].decode("latin-1")


def headers_of(raw: bytes):
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]
    out = []
    for h in head:
        if b":" in h:
            n, v = h.split(b":", 1)
            out.append((n.decode("latin-1").strip(), v.decode("latin-1").strip()))
    return out


def mid(a: str, b: str):
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    j = 0
    while j < min(len(a), len(b)) - i and a[-1 - j] == b[-1 - j]:
        j += 1
    return i, j


def pick_canon(vec_id, case, cases):
    # explicit override after ':'; else by forbidden kind / op
    k = case.get("forbidden_kind")
    op = case.get("forbidden_op")
    if k == "admin":
        cid = "direct-admin-del" if "del" in op.lower() or op == "adminDeleteUser" else "direct-admin-list"
    elif "getv2" in vec_id or op == "getAccountV2":
        cid = "direct-bob-getv2"
    else:
        cid = "direct-bob-get"
    return cases[cid]


def build(canon_t, mut_t, canon_m, mut_m, canon_h, mut_h, units):
    keep = set(units)
    p, s = mid(canon_t, mut_t)
    mmid = mut_t[p:len(mut_t) - s]
    target = canon_t[:p] + "".join(ch for k, ch in enumerate(mmid) if ("t", k) in keep) + canon_t[len(canon_t) - s:]
    method = mut_m if ("m",) in keep else canon_m
    hs = list(canon_h)
    for k, (n, v) in enumerate(mut_h):
        if ("h", k) in keep and (n, v) not in canon_h:
            hs.append((n, v))
    return method, target, hs


def to_bytes(method, target, headers):
    lines = [f"{method} {target} HTTP/1.1"]
    lines += [f"{n}: {v}" for n, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def units_of(canon_t, mut_t, canon_m, mut_m, canon_h, mut_h):
    u = []
    if mut_m != canon_m:
        u.append(("m",))
    p, s = mid(canon_t, mut_t)
    u += [("t", k) for k in range(len(mut_t) - p - s)]
    u += [("h", k) for k, h in enumerate(mut_h) if h not in canon_h]
    return u


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def main():
    tid = sys.argv[1]
    specs = sys.argv[2:]
    yml = E4 / "topologies" / f"{tid}.yaml"
    topo = yaml.safe_load(open(yml))
    port = int(topo["host_port"])
    logs = os.path.join(HARNESS, "logs", tid)
    cases = load_cases()
    (E4 / "ddmin").mkdir(exist_ok=True)

    for spec in specs:
        vec_id = spec.split(":")[0]
        case = cases[vec_id]
        canon = cases[spec.split(":")[1]] if ":" in spec else pick_canon(vec_id, case, cases)
        craw, mraw = raw_of(canon), raw_of(case)
        canon_t, mut_t = target_of(craw), target_of(mraw)
        canon_m, mut_m = method_of(craw), method_of(mraw)
        # drop the auth placeholder headers; they are re-added per trial by injection
        canon_h = [h for h in headers_of(craw) if h[0] not in ("Authorization", "DPoP")]
        mut_h = [h for h in headers_of(mraw) if h[0] not in ("Authorization", "DPoP")]
        # expected forbidden execution = what the full mutation produces
        trials = []

        def test(units):
            method, target, headers = build(canon_t, mut_t, canon_m, mut_m, canon_h, mut_h, units)
            headers = headers + [("Authorization", AUTHZ_PLACEHOLDER), ("DPoP", PROOF_PLACEHOLDER)]
            htu = ORIGIN + target
            authz, proof, jti = MINTER.mint(client="alice", htm=method, htu=htu)
            raw = to_bytes(method, target, headers)
            raw = raw.replace(AUTHZ_PLACEHOLDER.encode(), authz.encode()).replace(
                PROOF_PLACEHOLDER.encode(), proof.encode())
            resp = raw_send("127.0.0.1", port, raw, timeout=10)
            time.sleep(0.3)
            v = [x for x in jl(os.path.join(logs, "verifier.jsonl")) if x.get("jti") == jti]
            e = [x for x in jl(os.path.join(logs, "executor.jsonl")) if x.get("jti") == jti]
            allowed = any(x.get("decision") == "allow" and
                          (x.get("sub") in (None, "alice") or str(x.get("sub", "")).endswith("alice"))
                          for x in v)
            hit = False
            for x in e:
                if int(x.get("status", 999)) >= 400 or x.get("denied"):
                    continue
                fb, kind, _ = forbidden_reason(x.get("op_id"), x.get("path_params") or {})
                if fb and kind == case.get("forbidden_kind"):
                    hit = True
            ok = allowed and hit
            trials.append({"n_units": len(units), "status": resp.status, "allowed": allowed, "hit": ok})
            return ok

        full = units_of(canon_t, mut_t, canon_m, mut_m, canon_h, mut_h)
        # sanity: canonical (no units) must NOT hit; full must hit
        base_hit = test([])
        full_hit = test(full)
        minimal = ddmin(full, test) if full_hit else full
        mmethod, mtarget, mheaders = build(canon_t, mut_t, canon_m, mut_m, canon_h, mut_h, minimal)
        out = {
            "topology": tid, "vector_id": vec_id, "canonical_vector": canon["vector_id"],
            "primitive_ids": case.get("primitive_ids"),
            "forbidden_op": case.get("forbidden_op"), "forbidden_kind": case.get("forbidden_kind"),
            "canonical_target": canon_t, "mutated_target": mut_t,
            "full_units": len(full), "minimal_units": len(minimal),
            "canonical_denied_ok": not base_hit, "full_hit": full_hit,
            "minimal_target": mtarget, "minimal_method": mmethod,
            "minimal_request_line": f"{mmethod} {mtarget}",
            "still_hit": test(minimal), "trials": trials,
        }
        p = E4 / "ddmin" / f"{tid}__{vec_id}.json"
        json.dump(out, open(p, "w"), indent=1)
        print(f"{tid} {vec_id}: {len(full)}->{len(minimal)} units  base_denied={not base_hit} "
              f"still_hit={out['still_hit']}  minimal='{mmethod} {mtarget}'")


if __name__ == "__main__":
    main()
