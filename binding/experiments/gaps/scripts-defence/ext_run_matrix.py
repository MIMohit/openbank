"""W15 ext-routes runner: register v2 base ops, then drive runner.run_matrix over a cases file.

This is a thin wrapper so the v2 base ops are present in BASE_OPS_BY_ID (for proof minting)
without editing W7's mutator. Usage:

  # through a running gateway topology (reads host_port from the YAML):
  ext_run_matrix.py --topology <yaml> --cases cases.jsonl --out runner.jsonl
  # direct to an executor (ground-truth baseline only):
  ext_run_matrix.py --host-port 29001 --direct --cases cases.jsonl --topology-id gt-x --out runner.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ext_base  # noqa: E402

ext_base.register()

import yaml  # noqa: E402
from runner import run_matrix  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--topology")
    g.add_argument("--host-port", type=int)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--direct", action="store_true", help="ground-truth baseline-only direct run")
    ap.add_argument("--topology-id", default=None)
    ap.add_argument("--minter", default="w3")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    if args.topology:
        t = yaml.safe_load(open(args.topology))
        tid, port = t["id"], int(t["host_port"])
    else:
        port = args.host_port
        tid = args.topology_id or f"adhoc-{port}"

    cases = [json.loads(l) for l in open(args.cases) if l.strip()]
    if args.direct:
        cases = [c for c in cases if c.get("depth", len(c.get("primitive_ids", []))) == 0]
    mode = "direct" if args.direct else "gateway"
    counts = run_matrix.run(cases, host=args.host, port=port, mode=mode, topology_id=tid,
                            out_path=args.out, minter_prefer=args.minter, timeout=args.timeout)
    sys.stderr.write(f"[ext_run_matrix] {tid}/{mode}: {counts}\n")


if __name__ == "__main__":
    main()
