"""build_groundtruth.py — derive op(π) per base op from a DIRECT executor run.

The oracle (oracle_spec §2) needs, per base op `b` in framework `F`, the pair
`(op_id, path_params)` the executor returns for the canonical request sent **directly**
(no gateway, `VERIFY_MODE=off`). `run_matrix --direct` produces that run's `runner.jsonl`
(carrying `base_op_id` + `jti`) and the executor container writes `executor.jsonl`
(carrying `op_id` + `path_params`, keyed by the same `jti`). This tool joins them on `jti`
and emits `groundtruth/<framework>.jsonl` in the shape `load_ground_truth` expects:

    {"base_op_id", "base_method", "base_path", "op_id", "path_params", "status"}

Usage:
    python -m runner.build_groundtruth \
        --runner logs/groundtruth-fastapi/runner.jsonl \
        --executor logs/groundtruth-fastapi/executor.jsonl \
        --framework fastapi \
        --out logs/groundtruth/fastapi.jsonl

If one base op produced several executor records for its jti (should not happen in a
direct run), the first non-NOT_FOUND record wins and a warning is printed to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional


def _read_jsonl(path: str) -> List[dict]:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def build(runner_recs: List[dict], exec_recs: List[dict]) -> Dict[str, dict]:
    """Return {base_op_id: ground-truth dict}. Only baseline (depth-0) runner records
    define ground truth; a direct run that sent the whole matrix is filtered to depth 0."""
    exec_by_jti: Dict[Optional[str], List[dict]] = {}
    for x in exec_recs:
        exec_by_jti.setdefault(x.get("jti"), []).append(x)

    gt: Dict[str, dict] = {}
    for r in runner_recs:
        # Ground truth is the canonical (unmutated) request only.
        if r.get("depth", len(r.get("primitive_ids", []))) != 0:
            continue
        base = r.get("base_op_id")
        jti = r.get("jti")
        xs = exec_by_jti.get(jti, [])
        if not xs:
            sys.stderr.write(f"[build_groundtruth] no executor record for base={base} jti={jti}\n")
            continue
        chosen = next((x for x in xs if x.get("op_id") != "NOT_FOUND"), xs[0])
        if len(xs) > 1:
            sys.stderr.write(f"[build_groundtruth] {len(xs)} executor records for base={base}; "
                             f"chose op_id={chosen.get('op_id')}\n")
        gt[base] = {
            "base_op_id": base,
            "base_method": r.get("base_method"),
            "base_path": r.get("base_path"),
            "op_id": chosen.get("op_id"),
            "path_params": chosen.get("path_params", {}),
            "status": chosen.get("status", 200),
        }
    return gt


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build groundtruth/<framework>.jsonl from a direct run.")
    ap.add_argument("--runner", required=True, help="direct-run runner.jsonl")
    ap.add_argument("--executor", required=True, help="direct-run executor.jsonl")
    ap.add_argument("--framework", required=True, help="framework tag (e.g. fastapi)")
    ap.add_argument("--out", default=None, help="output path (default logs/groundtruth/<fw>.jsonl)")
    args = ap.parse_args(argv)

    runner_recs = _read_jsonl(args.runner)
    exec_recs = _read_jsonl(args.executor)
    gt = build(runner_recs, exec_recs)

    harness_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = args.out or os.path.join(harness_dir, "logs", "groundtruth", f"{args.framework}.jsonl")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        for base in sorted(gt):
            f.write(json.dumps(gt[base], sort_keys=True) + "\n")
    sys.stderr.write(f"[build_groundtruth] wrote {len(gt)} base ops to {out}\n")


if __name__ == "__main__":
    main()
