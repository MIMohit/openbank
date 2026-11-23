"""W18 A1 case set: the kill-style exhaustive depth-1 A_leak set over ALL base ops (v1 kill ops + the
four v2 ops), primitives = W7 catalogue + W15 custom fragment primitives. Baselines included.
Usage (from experiments/ablation):  ../../harness/orchestrator/.venv/bin/python scripts/gen_cases.py --out cases.jsonl
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ab_base  # noqa: E402

ab_base.register()
from mutator import compose  # noqa: E402
import mutator.base_ops as bo  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--client", default="alice")
    args = ap.parse_args()
    prims = ab_base.primitives()
    cases = []
    for op in bo.BASE_OPS:
        req = op.canonical_request()
        cases.append(compose.Case(
            case_id=compose._case_id(op.op_id, ["baseline"], args.client),
            base_op_id=op.op_id, base_method=op.method, base_path=op.path,
            primitive_ids=[], client=args.client, raw_request_b64=req.to_b64(), depth=0, groups=[]))
        for p in prims:
            if p.compatible_with(op):
                cases.append(compose.build_case(op, [p], args.client))
    with open(args.out, "w") as f:
        for c in cases:
            f.write(c.to_json() + "\n")
    sys.stderr.write(f"[gen_cases] {len(cases)} cases, {len(bo.BASE_OPS)} base ops, {len(prims)} primitives; "
                     f"per op {dict(Counter(c.base_op_id for c in cases))}\n")


if __name__ == "__main__":
    main()
