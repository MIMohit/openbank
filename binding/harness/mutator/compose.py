"""Deterministic, seeded case generation (CONTRACT §6).

Produces `Case` records:
  {case_id, base_op_id, base_method, base_path, primitive_ids[], client, raw_request_b64}

- Depth-1: every primitive applied to every COMPATIBLE base op (full cross product).
- Depth-2: a deterministic seeded sample of compatible primitive *pairs* per base op.
  The full depth-2 product is huge; we sample so the matrix is tractable while staying
  reproducible for a given (seed, k). Composition is order-sensitive, so a pair is applied
  in a fixed (group-then-id) order.

Output: JSONL, one Case per line, to stdout or --out.

CLI:
  python -m mutator.compose --depth 2 --seed 1337 --pairs-per-op 40 --out cases.jsonl
  python -m mutator.compose --only-op getAccount --depth 1
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import itertools
import json
import random
import sys
from dataclasses import dataclass
from typing import List, Optional

from .base_ops import BASE_OPS, BASE_OPS_BY_ID, BaseOp
from .catalogue import Primitive, load_catalogue
from . import transforms


@dataclass
class Case:
    case_id: str
    base_op_id: str
    base_method: str
    base_path: str
    primitive_ids: List[str]
    client: str
    raw_request_b64: str
    # extra metadata (not required by the contract schema but useful downstream)
    depth: int = 1
    groups: Optional[List[str]] = None

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), separators=(",", ":"))


def _case_id(base_op_id: str, primitive_ids: List[str], client: str) -> str:
    h = hashlib.sha1(("|".join([base_op_id, client] + primitive_ids)).encode()).hexdigest()[:12]
    return f"{base_op_id}:{'+'.join(primitive_ids)}:{client}:{h}"


def _sort_key(prims: List[Primitive]):
    # deterministic composition order: by group then id
    return sorted(prims, key=lambda p: (p.group, p.id))


def build_case(op: BaseOp, prims: List[Primitive], client: str) -> Case:
    ordered = _sort_key(prims)
    req = op.canonical_request()
    for p in ordered:
        req = transforms.apply_steps(req, p.transform)
    pids = [p.id for p in ordered]
    return Case(
        case_id=_case_id(op.op_id, pids, client),
        base_op_id=op.op_id,
        base_method=op.method,
        base_path=op.path,
        primitive_ids=pids,
        client=client,
        raw_request_b64=req.to_b64(),
        depth=len(pids),
        groups=sorted({p.group for p in ordered}),
    )


def generate(
    *,
    depth: int = 1,
    seed: int = 1337,
    pairs_per_op: int = 40,
    only_op: Optional[str] = None,
    client: str = "alice",
    include_baseline: bool = True,
) -> List[Case]:
    prims = load_catalogue()
    ops = BASE_OPS if only_op is None else [BASE_OPS_BY_ID[only_op]]
    cases: List[Case] = []

    # Baseline (depth-0): the unmutated canonical request. Lets the oracle confirm the
    # honest path reaches op(pi) under each topology.
    if include_baseline:
        for op in ops:
            req = op.canonical_request()
            cases.append(Case(
                case_id=_case_id(op.op_id, ["baseline"], client),
                base_op_id=op.op_id, base_method=op.method, base_path=op.path,
                primitive_ids=[], client=client, raw_request_b64=req.to_b64(),
                depth=0, groups=[],
            ))

    # Depth-1: full cross product of compatible (op, primitive).
    for op in ops:
        compat = [p for p in prims if p.compatible_with(op)]
        for p in compat:
            cases.append(build_case(op, [p], client))

    # Depth-2: deterministic seeded sample of compatible primitive pairs per op.
    if depth >= 2:
        for op in ops:
            compat = [p for p in prims if p.compatible_with(op)]
            all_pairs = list(itertools.combinations(compat, 2))
            # Seed per-op so adding ops doesn't perturb earlier ops' samples.
            rng = random.Random(f"{seed}:{op.op_id}")
            rng.shuffle(all_pairs)
            chosen = all_pairs[: pairs_per_op]
            # stable output order
            chosen.sort(key=lambda pr: (pr[0].group, pr[0].id, pr[1].group, pr[1].id))
            for a, b in chosen:
                cases.append(build_case(op, [a, b], client))

    return cases


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compose mutation cases (CONTRACT §6).")
    ap.add_argument("--depth", type=int, default=1, choices=[1, 2],
                    help="max composition depth (1 or 2).")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--pairs-per-op", type=int, default=40,
                    help="depth-2 pairs sampled per base op.")
    ap.add_argument("--only-op", default=None, help="restrict to one base op id.")
    ap.add_argument("--client", default="alice", choices=["alice", "bob"])
    ap.add_argument("--no-baseline", action="store_true")
    ap.add_argument("--out", default=None, help="output JSONL path (default stdout).")
    ap.add_argument("--stats", action="store_true", help="print a summary to stderr.")
    args = ap.parse_args(argv)

    cases = generate(depth=args.depth, seed=args.seed, pairs_per_op=args.pairs_per_op,
                     only_op=args.only_op, client=args.client,
                     include_baseline=not args.no_baseline)

    out = open(args.out, "w") if args.out else sys.stdout
    try:
        for c in cases:
            out.write(c.to_json() + "\n")
    finally:
        if args.out:
            out.close()

    if args.stats:
        by_depth = {}
        for c in cases:
            by_depth[c.depth] = by_depth.get(c.depth, 0) + 1
        sys.stderr.write(f"generated {len(cases)} cases; by depth: {dict(sorted(by_depth.items()))}\n")


if __name__ == "__main__":
    main()
