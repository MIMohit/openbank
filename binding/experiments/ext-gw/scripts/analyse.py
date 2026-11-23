"""Aggregate the 48 kill-experiment runs.

    python3 scripts/analyse.py            (from binding/experiments/kill)

Reads runs/<id>/{hits,runner,verifier,executor}.jsonl, groundtruth/*.jsonl and the
framework-only map groundtruth/raw/<fw>-ov<x>/{runner,executor}.all.jsonl.
Writes analysis/: hits_all.jsonl, pivot_*.csv, signatures.csv, resolution.csv,
direct_map.csv, and prints a markdown digest to stdout. Pure function of the files.
"""
import collections, csv, glob, json, os, sys

K = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(K, "analysis")
os.makedirs(OUT, exist_ok=True)


def jl(p):
    if not os.path.exists(p):
        return []
    return [json.loads(l) for l in open(p) if l.strip()]


def parse_id(tid):
    # w13-<gw>-<profile>-edge-<fw>-ov<x>; <fw> may contain '-' (go-chi).
    s = tid[4:] if tid.startswith("w13-") else tid
    gw, rest = s.split("-", 1)
    profile, rest = rest.split("-", 1)
    placement, rest = rest.split("-", 1)
    fw, ovtok = rest.rsplit("-", 1)
    return dict(gateway=gw, profile=profile, placement=placement, framework=fw, override=ovtok[2:])


topos = [l.strip() for l in open(os.path.join(K, "topologies.txt")) if l.strip()]
present = [t for t in topos if os.path.exists(os.path.join(K, "runs", t, "hits.jsonl"))]
missing = [t for t in topos if t not in present]

# ---------- ground truth + framework-only map
GT = {}
for f in glob.glob(os.path.join(K, "groundtruth", "*.jsonl")):
    key = os.path.basename(f)[:-6]
    GT[key] = {r["base_op_id"]: r for r in jl(f)}

DIRECT = {}  # (fw, ov) -> {(base, prims): exec record}
for d in glob.glob(os.path.join(K, "groundtruth", "raw", "*")):
    fw, ov = os.path.basename(d).rsplit("-ov", 1)
    run = jl(os.path.join(d, "runner.all.jsonl"))
    ex = collections.defaultdict(list)
    for r in jl(os.path.join(d, "executor.all.jsonl")):
        ex[r.get("jti")].append(r)
    m = {}
    for r in run:
        xs = ex.get(r["jti"], [])
        m[(r["base_op_id"], tuple(r["primitive_ids"]))] = (xs[0] if xs else {"op_id": None, "status": r["status"], "path_params": None})
    DIRECT[(fw, ov)] = m

# ---------- hits
hits = []
for t in present:
    meta = parse_id(t)
    for h in jl(os.path.join(K, "runs", t, "hits.jsonl")):
        h.update(meta)
        h["topology"] = t
        hits.append(h)
with open(os.path.join(OUT, "hits_all.jsonl"), "w") as f:
    for h in hits:
        f.write(json.dumps(h, sort_keys=True) + "\n")


def pdelta(h):
    b, e = h.get("base_path_params") or {}, h.get("exec_path_params") or {}
    return ";".join(f"{k}:{b.get(k)}->{e.get(k)}" for k in sorted(set(b) | set(e)) if b.get(k) != e.get(k))


# ---------- cross-topology root-cause signatures
sig = collections.defaultdict(list)
for h in hits:
    key = ("+".join(h["primitive_ids"]), h["base_op_id"], h["exec_op_id"], "+".join(h["deviation_kinds"]),
           pdelta(h), "+".join(h["class"]))
    sig[key].append(h)

rows = []
for key, hs in sorted(sig.items()):
    prims, base, exe, dev, pd, cls = key
    tset = sorted({h["topology"] for h in hs})
    gws = sorted({h["gateway"] for h in hs}); fws = sorted({h["framework"] for h in hs})
    profs = sorted({h["profile"] for h in hs}); ovs = sorted({h["override"] for h in hs})
    # framework-only map: does the framework alone execute the same thing for this case?
    dm = []
    for fw in ["fastapi", "express", "django", "go-chi", "spring", "aspnet", "rails", "laravel"]:
        for ov in ["off", "on"]:
            x = DIRECT.get((fw, ov), {}).get((base, tuple(prims.split("+"))))
            ep = hs[0].get("exec_path_params") or {}
            if x and x.get("op_id") == exe and (x.get("status") or 999) < 400 and (x.get("path_params") or {}) == ep:
                dm.append(f"{fw}/{ov}")
    rows.append(dict(primitives=prims, base_op=base, exec_op=exe, deviation=dev, param_delta=pd, prim_class=cls,
                     n_topologies=len(tset), gateways="|".join(gws), profiles="|".join(profs),
                     frameworks="|".join(fws), overrides="|".join(ovs), severity="|".join(sorted({h["severity"] for h in hs})),
                     direct_map="|".join(dm), example_topology=tset[0],
                     example_case=sorted(h["case_id"] for h in hs if h["topology"] == tset[0])[0],
                     view=f'{hs[0]["view_method"]} {hs[0]["view_uri"]}', raw=f'{hs[0]["raw_method"]} {hs[0]["raw_target"]}'))
with open(os.path.join(OUT, "signatures.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["none"])
    w.writeheader(); w.writerows(rows)

# ---------- pivots
def pivot(name, rowkey, colkey):
    c = collections.Counter((rowkey(h), colkey(h)) for h in hits)
    rk = sorted({r for r, _ in c} | set()); ck = sorted({k for _, k in c})
    with open(os.path.join(OUT, f"pivot_{name}.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["row"] + ck)
        for r in rk:
            w.writerow([r] + [c.get((r, k), 0) for k in ck])
    return c

# full per-topology table (includes zero-hit topologies)
cnt = collections.Counter(h["topology"] for h in hits)
bycls = collections.Counter((h["topology"], "+".join(h["class"])) for h in hits)
with open(os.path.join(OUT, "hits_per_topology.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["topology", "gateway", "profile", "framework", "override", "hits", "g1", "g2", "g3", "S1", "S2", "S3"])
    for t in present:
        m = parse_id(t)
        sev = collections.Counter(h["severity"] for h in hits if h["topology"] == t)
        w.writerow([t, m["gateway"], m["profile"], m["framework"], m["override"], cnt.get(t, 0),
                    bycls.get((t, "g1"), 0), bycls.get((t, "g2"), 0), bycls.get((t, "g3"), 0),
                    sev.get("S1", 0), sev.get("S2", 0), sev.get("S3", 0)])

# ---------- resolution per (topology, base op), recomputed from raw logs (oracle_spec §4)
res_rows = []
for t in present:
    m = parse_id(t)
    gt = GT[f'{m["framework"]}-ov{m["override"]}']
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
        g = gt[b]
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
    w = csv.DictWriter(f, fieldnames=list(res_rows[0].keys())); w.writeheader(); w.writerows(res_rows)

# ---------- digest
print(f"# digest: {len(present)} runs present, {len(missing)} missing {missing}")
print(f"raw hits: {len(hits)}; cross-topology signatures: {len(rows)}")
print("res_hat distribution:", dict(sorted(collections.Counter(r["res_hat"] for r in res_rows).items())))
pv = pivot("gw_fw", lambda h: f'{h["gateway"]}/{h["profile"]}', lambda h: f'{h["framework"]}/ov{h["override"]}')
for r in rows:
    print(f'{r["n_topologies"]:>2} | {r["prim_class"]} | {r["primitives"]} | {r["base_op"]} -> {r["exec_op"]} '
          f'[{r["deviation"]}] {r["param_delta"]} | gw={r["gateways"]} prof={r["profiles"]} fw={r["frameworks"]} '
          f'ov={r["overrides"]} | direct={r["direct_map"]}')
