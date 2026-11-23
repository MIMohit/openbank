"""W18 A1 runner: like runner.run_matrix (raw TCP, exact bytes, one fresh token+proof per case), but the
proof is minted by minter_ablate.mint_bound for the binding variant:
  --bind full          standard RFC 9449 proof (htm, htu without query, ath)        [also no-htm/no-htu/no-ath]
  --bind query         htu claim includes the base op's canonical query
  --bind digest        proof carries cdig = Content-Digest(canonical body); a 'Content-Digest: <cd>' header
                       line is inserted right after the DPoP header line (the legitimate client's header,
                       which the A_leak attacker replays unchanged with the leaked proof)
  --bind query-digest  both
The A_leak model is unchanged: the proof (and digest header) are for the BASE op's canonical request;
primitives then mutate the request. Records go to runner.jsonl in run_matrix's format (+ "bind").
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
A = HERE.parent
HARNESS = A.parents[1] / "harness"
os.environ.setdefault("BH_KEYS_DIR", str(HARNESS / "keys"))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(A))
import ab_base  # noqa: E402  (puts harness on sys.path, registers v2 ops)

ab_base.register()
import yaml  # noqa: E402
from minter_ablate.dpop import mint_bound  # noqa: E402
from mutator.base_ops import AUTHZ_PLACEHOLDER, BASE_OPS_BY_ID, PROOF_PLACEHOLDER  # noqa: E402
from rawhttp.client import send as raw_send  # noqa: E402
from runner.run_matrix import parse_resp_op_id  # noqa: E402


def build(case: dict, bind: str) -> tuple[bytes, str, str, str | None]:
    op = BASE_OPS_BY_ID[case["base_op_id"]]
    bq, bd = "query" in bind, "digest" in bind
    authz, proof, jti, cd = mint_bound(case.get("client", "alice"), op.htm, op.htu, query=op.query,
                                       body=op.body, bind_query=bq, bind_digest=bd)
    raw = base64.b64decode(case["raw_request_b64"])
    raw = raw.replace(AUTHZ_PLACEHOLDER.encode(), authz.encode())
    pv = proof + (f"\r\nContent-Digest: {cd}" if bd else "")
    raw = raw.replace(PROOF_PLACEHOLDER.encode(), pv.encode())
    return raw, jti, op.htu + ("?" + op.query if bq and op.query else ""), cd


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--topology")
    g.add_argument("--host-port", type=int)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bind", default="full", choices=["full", "query", "digest", "query-digest"])
    ap.add_argument("--direct", action="store_true")
    ap.add_argument("--topology-id")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()
    if args.topology:
        t = yaml.safe_load(open(args.topology))
        tid, port = t["id"], int(t["host_port"])
    else:
        tid, port = args.topology_id or f"adhoc-{args.host_port}", args.host_port
    cases = [json.loads(l) for l in open(args.cases) if l.strip()]
    if args.direct:
        cases = [c for c in cases if c.get("depth", 0) == 0]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    n = err = 0
    with open(args.out, "w") as out:
        for c in cases:
            op = BASE_OPS_BY_ID[c["base_op_id"]]
            raw, jti, htu, cd = build(c, args.bind)
            r = raw_send("127.0.0.1", port, raw, timeout=args.timeout)
            out.write(json.dumps({
                "ts": dt.datetime.now(dt.timezone.utc).isoformat(), "case_id": c["case_id"],
                "base_op_id": c["base_op_id"], "base_method": c["base_method"], "base_path": c["base_path"],
                "primitive_ids": c.get("primitive_ids", []), "depth": c.get("depth", 0),
                "groups": c.get("groups", []), "client": c.get("client", "alice"), "jti": jti,
                "mode": "direct" if args.direct else "gateway", "topology": tid, "host": "127.0.0.1",
                "host_port": port, "htm": op.htm, "htu": htu, "minter": "w18-ablate", "bind": args.bind,
                "content_digest": cd, "sent_bytes_len": len(raw), "status": r.status,
                "resp_framing": r.framing, "resp_body_len": len(r.body),
                "resp_body_sha256": hashlib.sha256(r.body).hexdigest(),
                "resp_op_id": parse_resp_op_id(r.body), "error": r.error}) + "\n")
            n += 1
            err += 1 if r.error else 0
    sys.stderr.write(f"[ab_run_matrix] {tid} bind={args.bind}: sent={n} errors={err}\n")


if __name__ == "__main__":
    main()
