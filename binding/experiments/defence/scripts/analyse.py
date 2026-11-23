"""E7/E8 analysis over runs/<cfg>/<id>/ -> analysis/*.csv + analysis/e7_tables.md"""
import csv, collections, glob, json, os
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CFG_ORDER = ["bedge", "borigin", "bstrict", "bopt", "da", "db", "dc"]
CFG_NAME = {"bedge": "B-edge", "borigin": "B-origin", "bstrict": "B-strict", "bopt": "B-optional",
            "da": "D-A", "db": "D-B", "dc": "D-C"}
CLASSES = ["G1-query", "G1-query(frag-in-query)", "G1-body", "G1-override", "G2-#", "G2-%2f", "G2-dot"]

def jl(p): return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []
def by_jti(rs):
    d = collections.defaultdict(list)
    for r in rs: d[r.get("jti")].append(r)
    return d

def outcome(r, V, X, hit):
    if hit: return "HIT"
    if r.get("status", 0) == 0: return "transport_error"
    if any(v.get("decision") == "deny" for v in V): return "verifier_deny:" + next(v["reason"] for v in V if v.get("decision") == "deny")
    if not X: return f"gateway_reject_{r.get('status')}"
    x = X[0]
    if x.get("denied"): return "executor_deny"
    if x.get("op_id") == "NOT_FOUND" or x.get("status", 0) == 404: return "not_found"
    if x.get("op_id") == r.get("base_op_id"): return "bound_op"
    if x.get("status", 0) >= 400: return f"exec_{x.get('status')}"
    return "other:" + str(x.get("op_id"))

def aleak():
    src = json.load(open(os.path.join(D, "cases", "sources.json")))
    rows = []
    for s in src:
        meta = {m["case_id"]: m for m in jl(os.path.join(D, "cases", f"{s}.meta.jsonl"))}
        for cfg in CFG_ORDER:
            d = os.path.join(D, "runs", cfg, f"w17-{cfg}-{s}")
            if not os.path.exists(os.path.join(d, "runner.jsonl")): continue
            R, V, X = jl(f"{d}/runner.jsonl"), by_jti(jl(f"{d}/verifier.jsonl")), by_jti(jl(f"{d}/executor.jsonl"))
            H = {h["case_id"]: h for h in jl(f"{d}/hits.jsonl")}
            for r in R:
                m = meta[r["case_id"]]; x = (X.get(r["jti"]) or [{}])[0]
                rows.append({"cfg": cfg, "source": s, "case_id": r["case_id"], "kind": m["kind"], "class": m["class"] or "",
                             "base_op": r["base_op_id"], "status": r.get("status"), "exec_op": x.get("op_id"),
                             "hit": r["case_id"] in H, "new_hit": r["case_id"] in H and m["kind"] != "hit",
                             "outcome": outcome(r, V.get(r["jti"], []), X.get(r["jti"], []), r["case_id"] in H)})
    with open(os.path.join(D, "analysis", "e7_aleak_long.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    return rows

def e4():
    reps = {"rc1": 9, "rc2": 9, "rc3": 11, "rc4": 2, "rc5": 3, "rc6": 3, "rc7": 15}  # e4 REPORT §7 confirmed vectors
    out = []
    for cfg in CFG_ORDER:
        for d in sorted(glob.glob(os.path.join(D, "runs", cfg, f"w17-{cfg}-e4rc*"))):
            rc = os.path.basename(d).split("-")[2][2:]
            oc = list(csv.DictReader(open(f"{d}/outcomes.csv"))) if os.path.exists(f"{d}/outcomes.csv") else []
            viol = jl(f"{d}/violations.jsonl")
            legit = [o for o in oc if (o["vector_id"] or "").startswith("legit-")]
            out.append({"cfg": cfg, "rc": rc.upper(), "topology": os.path.basename(d), "orig_confirmed": reps[rc],
                        "violations": len(viol), "vectors": ",".join(sorted({v["vector_id"] for v in viol})),
                        "legit_total": len(legit), "legit_ok": sum(o["outcome"] == "allowed_sound" for o in legit),
                        "outcomes": json.dumps(collections.Counter(o["outcome"] for o in oc))})
    with open(os.path.join(D, "analysis", "e4_by_cfg.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0])); w.writeheader(); w.writerows(out)
    return out

def md(rows, e4rows):
    L = []
    # witnesses per class (per source, counted under B-edge = denominators are the source witness counts)
    wit = collections.Counter((r["class"]) for r in rows if r["cfg"] == "bedge" and r["kind"] == "hit")
    rem = collections.Counter((r["cfg"], r["class"]) for r in rows if r["hit"] and r["kind"] == "hit")
    new = collections.Counter((r["cfg"]) for r in rows if r["new_hit"])
    cfgs = [c for c in CFG_ORDER if any(r["cfg"] == c for r in rows)]
    L.append("| class (witnesses) | " + " | ".join(CFG_NAME[c] for c in cfgs) + " |")
    L.append("|---|" + "---|" * len(cfgs))
    for k in CLASSES:
        if not wit[k]: continue
        L.append(f"| {k} ({wit[k]}) | " + " | ".join(str(rem[(c, k)]) for c in cfgs) + " |")
    L.append(f"| **all ({sum(wit.values())})** | " + " | ".join(f"**{sum(rem[(c, k)] for k in CLASSES)}**" for c in cfgs) + " |")
    L.append("| hits on baseline (depth-0) cases | " + " | ".join(str(new[c]) for c in cfgs) + " |")
    base_fail = collections.Counter(r["cfg"] for r in rows if r["kind"] == "baseline" and not (r["status"] == 200 and r["exec_op"] == r["base_op"]))
    base_n = collections.Counter(r["cfg"] for r in rows if r["kind"] == "baseline")
    L.append("| baseline cases NOT executed as op(π) | " + " | ".join(f"{base_fail[c]}/{base_n[c]}" for c in cfgs) + " |")
    L.append("")
    # how non-hits were stopped
    L.append("| how witnesses were stopped | " + " | ".join(CFG_NAME[c] for c in cfgs) + " |")
    L.append("|---|" + "---|" * len(cfgs))
    oc = collections.Counter((r["cfg"], r["outcome"].split(":")[0]) for r in rows if r["kind"] == "hit")
    for o in sorted({k[1] for k in oc}):
        L.append(f"| {o} | " + " | ".join(str(oc[(c, o)]) for c in cfgs) + " |")
    L.append("")
    if e4rows:
        e4cfgs = [c for c in CFG_ORDER if any(r["cfg"] == c for r in e4rows)]
        L.append("| E4 class (orig. confirmed) | " + " | ".join(CFG_NAME[c] for c in e4cfgs) + " |")
        L.append("|---|" + "---|" * len(e4cfgs))
        cell = {(r["cfg"], r["rc"]): r for r in e4rows}
        for rc in sorted({r["rc"] for r in e4rows}):
            o = next(r for r in e4rows if r["rc"] == rc)["orig_confirmed"]
            L.append(f"| {rc} ({o}) | " + " | ".join(
                (str(cell[(c, rc)]["violations"]) if (c, rc) in cell else "n/a") for c in e4cfgs) + " |")
        L.append("| legit-* vectors executed / total | " + " | ".join(
            f"{sum(int(r['legit_ok']) for r in e4rows if r['cfg']==c)}/{sum(int(r['legit_total']) for r in e4rows if r['cfg']==c)}" for c in e4cfgs) + " |")
    open(os.path.join(D, "analysis", "e7_tables.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))

if __name__ == "__main__":
    rows = aleak()
    try: e4rows = e4()
    except (StopIteration, IndexError, FileNotFoundError): e4rows = []
    md(rows, e4rows)
