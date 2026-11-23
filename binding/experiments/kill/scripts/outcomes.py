"""Per-case outcome classes for every topology (for skepticism / null-result analysis).
outcome: gw_reject (no verifier record, no executor record), deny, allow_sound (exec op==gt),
allow_notfound, allow_4xx, allow_hit, allow_notexec. Writes analysis/outcomes_by_primitive.csv."""
import collections, csv, glob, json, os
K = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def jl(p): return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []
GT = {os.path.basename(f)[:-6]: {r["base_op_id"]: r for r in jl(f)} for f in glob.glob(f"{K}/groundtruth/*.jsonl")}
rows = collections.Counter()
for d in sorted(glob.glob(f"{K}/runs/w9-*")):
    tid = os.path.basename(d); p = tid.split("-"); gw, prof, fw, ov = p[1], p[2], p[4], p[5][2:]
    gt = GT[f"{fw}-ov{ov}"]
    V = collections.defaultdict(list); X = collections.defaultdict(list)
    for v in jl(f"{d}/verifier.jsonl"): V[v.get("jti")].append(v)
    for x in jl(f"{d}/executor.jsonl"): X[x.get("jti")].append(x)
    for r in jl(f"{d}/runner.jsonl"):
        vs, xs = V.get(r["jti"], []), X.get(r["jti"], [])
        allow = any(v["decision"] == "allow" for v in vs)
        if not vs: o = "gw_reject" if not xs else "B0_bypass"
        elif not allow: o = "deny"
        elif not xs: o = "allow_notexec"
        else:
            x = xs[0]; g = gt[r["base_op_id"]]
            if x["op_id"] == "NOT_FOUND": o = "allow_notfound"
            elif (x.get("status") or 999) >= 400: o = "allow_4xx"
            elif x["op_id"] == g["op_id"] and (x.get("path_params") or {}) == g["path_params"]: o = "allow_sound"
            else: o = "allow_hit"
        prim = "+".join(r["primitive_ids"]) or "baseline"
        rows[(prim, gw, prof, o)] += 1
os.makedirs(f"{K}/analysis", exist_ok=True)
with open(f"{K}/analysis/outcomes_by_primitive.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["primitive", "gateway", "profile", "outcome", "cases"])
    for k, n in sorted(rows.items()): w.writerow([*k, n])
# compact: per gateway/profile, G2 primitives outcome totals
agg = collections.Counter()
for (prim, gw, prof, o), n in rows.items(): agg[(prim.split("-")[0], gw, prof, o)] += n
for k in sorted(agg): print(k, agg[k])
