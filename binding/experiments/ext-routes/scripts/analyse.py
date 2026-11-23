"""Aggregate the ext-routes runs. Run from binding/experiments/ext-routes:
    harness/orchestrator/.venv/bin/python scripts/analyse.py   (or python3)

Reads runs/<id>/hits.jsonl + groundtruth/*.jsonl; writes analysis/: hits_all.jsonl,
signatures.csv, hits_per_topology.csv, resolution.csv, and prints a markdown digest.
Pure function of the files.
"""
import collections
import csv
import json
import os

K = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(K, "analysis")
os.makedirs(OUT, exist_ok=True)


def jl(p):
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


def parse_id(tid):
    # w15r-<gw>-<profile>-edge-<fw>-ov<x>
    p = tid.split("-")
    # fw may contain '-', e.g. go-chi -> p[4]='go', p[5]='chi', ov at end
    gw, prof, placement = p[1], p[2], p[3]
    ov = p[-1][2:]
    fw = "-".join(p[4:-1])
    return dict(gateway=gw, profile=prof, placement=placement, framework=fw, override=ov)


topos = [l.strip() for l in open(os.path.join(K, "topologies.txt")) if l.strip()]
present = [t for t in topos if os.path.exists(os.path.join(K, "runs", t, "hits.jsonl"))]
missing = [t for t in topos if t not in present]

GT = {}
for f in os.listdir(os.path.join(K, "groundtruth")):
    if f.endswith(".jsonl"):
        GT[f[:-6]] = {r["base_op_id"]: r for r in jl(os.path.join(K, "groundtruth", f))}

hits = []
for t in present:
    meta = parse_id(t)
    for h in jl(os.path.join(K, "runs", t, "hits.jsonl")):
        h.update(meta)
        h["topology"] = t
        # The oracle derives `class` from the primitive id's first token (pid.split("-")[0]),
        # so our custom primitive `x-frag-statements[-sid]` is labelled "x" instead of "g2".
        # It is a fragment interpretation-differential (RFC 3986 §3.5) -> G2. Correct the label
        # here for aggregation; the raw runs/*/hits.jsonl keep the oracle's literal output. (W15)
        h["class"] = sorted({"g2" if c == "x" else c for c in h["class"]})
        hits.append(h)

with open(os.path.join(OUT, "hits_all.jsonl"), "w") as f:
    for h in hits:
        f.write(json.dumps(h, sort_keys=True) + "\n")


def pdelta(h):
    b, e = h.get("base_path_params") or {}, h.get("exec_path_params") or {}
    return ";".join(f"{k}:{b.get(k)}->{e.get(k)}" for k in sorted(set(b) | set(e)) if b.get(k) != e.get(k))


def prim_group(pids):
    """Map the primitive id(s) to a coarse mechanism bucket."""
    s = "+".join(pids)
    if any(p.startswith("g1-hdr-") or p.startswith("g1-qmethod") or p.startswith("g1-fmethod") for p in pids):
        return "method-override (G1)"
    if any(p.startswith("g1-op") or p.startswith("g1-gql") or p.startswith("g1-ct") for p in pids):
        return "app-dispatch (G1)"
    if any(p.startswith("x-frag-statements") for p in pids):
        return "fragment-route-substitution (G2)"
    if any("fragment" in p for p in pids):
        return "fragment (G2)"
    if any("dot" in p or "encslash" in p or "pct2f" in p for p in pids):
        return "dot-segment/encoded-slash (G2)"
    return "other (" + s + ")"


# ---------- signatures
sig = collections.defaultdict(list)
for h in hits:
    key = ("+".join(h["primitive_ids"]), h["base_op_id"], h["exec_op_id"],
           "+".join(sorted(h["deviation_kinds"])), pdelta(h), "+".join(sorted(h["class"])))
    sig[key].append(h)

rows = []
for key, hs in sorted(sig.items()):
    prims, base, exe, dev, pd, cls = key
    rows.append(dict(
        primitives=prims, base_op=base, exec_op=exe, deviation=dev, param_delta=pd, prim_class=cls,
        bucket=prim_group(prims.split("+")),
        n_topologies=len({h["topology"] for h in hs}),
        gateways="|".join(sorted({h["gateway"] for h in hs})),
        frameworks="|".join(sorted({h["framework"] for h in hs})),
        overrides="|".join(sorted({h["override"] for h in hs})),
        severity="|".join(sorted({h["severity"] for h in hs})),
        example_topology=sorted({h["topology"] for h in hs})[0]))
with open(os.path.join(OUT, "signatures.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["none"])
    w.writeheader()
    w.writerows(rows)

# ---------- per-topology counts
cnt = collections.Counter(h["topology"] for h in hits)
bycls = collections.Counter((h["topology"], "+".join(sorted(h["class"]))) for h in hits)
with open(os.path.join(OUT, "hits_per_topology.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["topology", "gateway", "framework", "override", "hits", "g1", "g2", "g3", "S1", "S2", "S3"])
    for t in present:
        m = parse_id(t)
        sev = collections.Counter(h["severity"] for h in hits if h["topology"] == t)
        g1 = sum(v for (tt, c), v in bycls.items() if tt == t and "g1" in c)
        g2 = sum(v for (tt, c), v in bycls.items() if tt == t and "g2" in c)
        g3 = sum(v for (tt, c), v in bycls.items() if tt == t and "g3" in c)
        w.writerow([t, m["gateway"], m["framework"], m["override"], cnt.get(t, 0), g1, g2, g3,
                    sev.get("S1", 0), sev.get("S2", 0), sev.get("S3", 0)])

# ---------- resolution per (topology, base op)
res_rows = []
for t in present:
    m = parse_id(t)
    gt = GT.get(f'{m["framework"]}-ov{m["override"]}', {})
    d = os.path.join(K, "runs", t)
    vby = collections.defaultdict(list)
    for v in jl(os.path.join(d, "verifier.jsonl")):
        vby[v.get("jti")].append(v)
    xby = collections.defaultdict(list)
    for x in jl(os.path.join(d, "executor.jsonl")):
        xby[x.get("jti")].append(x)
    ops = collections.defaultdict(set)
    for r in jl(os.path.join(d, "runner.jsonl")):
        b = r["base_op_id"]
        g = gt.get(b)
        if g:
            ops[b].add((g["op_id"], json.dumps(g["path_params"], sort_keys=True)))
        if not any(v.get("decision") == "allow" for v in vby.get(r["jti"], [])):
            continue
        for x in xby.get(r["jti"], []):
            if x.get("op_id") not in (None, "NOT_FOUND") and (x.get("status") or 999) < 400 and not x.get("denied"):
                ops[b].add((x["op_id"], json.dumps(x.get("path_params") or {}, sort_keys=True)))
    for b, s in sorted(ops.items()):
        res_rows.append(dict(topology=t, **m, base_op=b, res_hat=len(s),
                             executed="; ".join(sorted(f"{o}{p if p != '{}' else ''}" for o, p in s))))
with open(os.path.join(OUT, "resolution.csv"), "w", newline="") as f:
    if res_rows:
        w = csv.DictWriter(f, fieldnames=list(res_rows[0].keys()))
        w.writeheader()
        w.writerows(res_rows)

# ---------- digest
print(f"# ext-routes digest: {len(present)}/{len(topos)} runs present; missing {missing}")
print(f"raw hits: {len(hits)}; signatures: {len(rows)}")
print("res_hat dist:", dict(sorted(collections.Counter(r["res_hat"] for r in res_rows).items())))
print("\n## buckets (G1 by-design vs G2/G3):")
bk = collections.Counter(prim_group(h["primitive_ids"]) for h in hits)
for b, n in bk.most_common():
    print(f"  {n:>4}  {b}")
print("\n## G2/G3 signatures (candidate independent classes):")
for r in rows:
    if "g2" in r["prim_class"] or "g3" in r["prim_class"]:
        print(f'  {r["n_topologies"]:>2}x | {r["bucket"]:<34} | {r["base_op"]}->{r["exec_op"]} [{r["deviation"]}] '
              f'{r["param_delta"]} | gw={r["gateways"]} fw={r["frameworks"]} ov={r["overrides"]} sev={r["severity"]}')
