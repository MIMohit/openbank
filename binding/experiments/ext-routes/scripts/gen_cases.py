"""Generate depth-1 ext-routes cases JSONL (baseline + one primitive per compatible op).

Mirrors mutator.compose.build_case but over the v2-augmented op set and the catalogue+custom
primitive list from ext_base. Usage (from experiments/ext-routes):
    harness/orchestrator/.venv/bin/python scripts/gen_cases.py --out cases.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ext_base  # noqa: E402

ext_base.register()
from mutator import compose, transforms  # noqa: E402
import mutator.base_ops as bo  # noqa: E402

# Focus: shared-path ops, the new routes, and a catch-all control.
OP_SET = ["getAccount", "updateAccount", "deleteAccount", "publicFile",
          "postAccount", "getStatements", "deleteStatement", "catchAllFile"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--client", default="alice")
    args = ap.parse_args()

    prims = ext_base.primitives()
    ops = [bo.BASE_OPS_BY_ID[o] for o in OP_SET]
    cases = []
    for op in ops:
        # baseline (depth-0)
        req = op.canonical_request()
        cases.append(compose.Case(
            case_id=compose._case_id(op.op_id, ["baseline"], args.client),
            base_op_id=op.op_id, base_method=op.method, base_path=op.path,
            primitive_ids=[], client=args.client, raw_request_b64=req.to_b64(), depth=0, groups=[]))
        # depth-1: each compatible primitive
        for p in prims:
            if p.compatible_with(op):
                cases.append(compose.build_case(op, [p], args.client))

    with open(args.out, "w") as f:
        for c in cases:
            f.write(c.to_json() + "\n")
    by_depth = {}
    for c in cases:
        by_depth[c.depth] = by_depth.get(c.depth, 0) + 1
    sys.stderr.write(f"[gen_cases] wrote {len(cases)} cases to {args.out}; by depth {by_depth}\n")


if __name__ == "__main__":
    main()
