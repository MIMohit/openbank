#!/usr/bin/env python3
"""Draw the seeded hand-validation sample of flagged operations and dump spec context for review.

Population: strong-tier flags in the chosen (one-per-API) set (see summarize.py).
Design: stratified by mechanism with a fixed allocation summing to 100 (ALLOC below), seed 20261123.
Strata smaller than their allocation are taken whole.
Stratification is used because M1 (AWS-style query-in-path) is ~95% of all flags; a uniform
sample would be almost entirely AWS and say nothing about the other detectors. The overall
precision is re-weighted by stratum size in precision.py.
Writes e1/out/validation_sample.csv (one row per sampled op, with the spec text needed to judge it).
"""
import csv
import json
import os
import random
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from analyze import Loader, Resolver, norm_path  # noqa: E402

OUT = os.path.join(HERE, "out")
ROOT = os.path.join(HERE, "..", "data", "openapi-directory", "APIs")
SEED = 20261123
ALLOC = {"M1-query-in-path": 30, "M2-dispatch-param": 30, "M3-header-dispatch": 0,
         "M4-body-discriminator": 37, "M5-rpc-endpoint": 3}
MECHS = ["M1-query-in-path", "M2-dispatch-param", "M3-header-dispatch", "M4-body-discriminator", "M5-rpc-endpoint"]


def clip(s, n=400):
    s = " ".join(str(s or "").split())
    return s[:n]


def context(f):
    raw = open(os.path.join(ROOT, f["file"]), "rb").read()
    try:
        doc = yaml.load(raw, Loader=Loader)
    except yaml.YAMLError:
        doc = yaml.load(raw.replace(b"\t", b"    "), Loader=Loader)
    R = Resolver(doc)
    item = R.get(doc["paths"][f["raw_path"]])
    op = item[f["method"].lower()]
    ctx = {"summary": clip(op.get("summary")), "description": clip(op.get("description"), 500)}
    params = []
    for p in (item.get("parameters", []) or []) + (op.get("parameters", []) or []):
        p = R.get(p)
        if isinstance(p, dict) and p.get("in") in ("query", "header", "formData"):
            sch = R.get(p.get("schema", {})) if "schema" in p else p
            params.append(f"{p.get('in')}:{p.get('name')} req={p.get('required')} enum={json.dumps(sch.get('enum'), default=str)[:150] if isinstance(sch, dict) else None} desc={clip(p.get('description'), 160)}")
    ctx["params"] = " || ".join(params)[:900]
    if f["mech"] == "M1-query-in-path":
        sib = []
        for rp, it in doc["paths"].items():
            b, q = norm_path(rp)
            it = R.get(it)
            if b == f["norm_path"] and isinstance(it, dict) and f["method"].lower() in it:
                o = it[f["method"].lower()]
                sib.append(f"{rp} => {o.get('operationId', '')}")
        ctx["siblings"] = " || ".join(sib[:12]) + (f" || ... ({len(sib)} total)" if len(sib) > 12 else "")
    else:
        ctx["siblings"] = ""
    return ctx


def main():
    chosen = {r["file"] for r in csv.DictReader(open(os.path.join(OUT, "e1_api_level.csv")))}
    flags = [f for f in csv.DictReader(open(os.path.join(OUT, "e1_flags.csv")))
             if f["tier"] == "strong" and f["file"] in chosen]
    rng = random.Random(SEED)
    rows = []
    sizes = {}
    for m in MECHS:
        pop = [f for f in flags if f["mech"] == m]
        sizes[m] = len(pop)
        pick = rng.sample(pop, min(ALLOC[m], len(pop)))
        for f in pick:
            c = context(f)
            rows.append(dict(sample_id=f"S{len(rows)+1:03d}", stratum=m, stratum_size=len(pop), file=f["file"],
                             method=f["method"], raw_path=f["raw_path"], sub=f["sub"], evidence=f["evidence"],
                             opid=f["opid"], **c))
    with open(os.path.join(OUT, "validation_sample.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(json.dumps(sizes), len(rows))


if __name__ == "__main__":
    main()
